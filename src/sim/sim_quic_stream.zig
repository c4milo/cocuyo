//! The twin's request transport over TCP, as DoH over HTTP/2 runs (docs/design.md §24, request
//! rules 14 to 16): the items of the twin's QUIC (`sim_quic.zig`), each output framed by a
//! two-octet length on the stream, and the stream's octets read back into whole frames, whatever
//! chunks they came in. What a frame holds is what a datagram of the twin's QUIC holds, so the
//! twin's servers answer both alike.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const quic = @import("sim_quic.zig");

const Connection = quic.Connection;

/// The octets a frame's length takes, as a DNS message's does over TCP (RFC 7766 §8).
pub const prefix_bytes = core.constants.tcp_prefix_bytes;

/// One frame at its longest: its length, then a datagram's worth of items.
pub const frame_bytes_max = prefix_bytes + constants.quic_datagram_bytes_max;

/// Writes `items` as one frame into `out`, and returns its length.
pub fn frame(items: []const u8, out: []u8) usize {
    assert(items.len <= constants.quic_datagram_bytes_max);
    assert(out.len >= prefix_bytes + items.len);
    std.mem.writeInt(u16, out[0..prefix_bytes], @intCast(items.len), .big);
    @memcpy(out[prefix_bytes..][0..items.len], items);
    return prefix_bytes + items.len;
}

/// The items of the first whole frame of `bytes`, and the octets it takes; null when no whole
/// frame is there yet.
pub fn unframe(bytes: []const u8) ?struct { items: []const u8, len: usize } {
    if (bytes.len < prefix_bytes) return null;
    const len: usize = std.mem.readInt(u16, bytes[0..prefix_bytes], .big);
    if (prefix_bytes + len > bytes.len) return null;
    return .{ .items = bytes[prefix_bytes..][0..len], .len = prefix_bytes + len };
}

pub const Stream = struct {
    pub const enabled = true;
    pub const http3 = false;
    /// A stream of octets, over TCP (docs/design.md §24, the request interface).
    pub const socket = .stream;
    pub const output_bytes_max = frame_bytes_max;
    pub const request_bytes_max = Connection.request_bytes_max;
    pub const Error = Connection.Error;
    pub const Context = Connection.Context;
    pub const Ticket = Connection.Ticket;
    pub const Answered = Connection.Answered;
    pub const Next = Connection.Next;
    pub const Expiry = Connection.Expiry;

    inner: Connection = .{},
    /// The stream's octets not yet read as whole frames: less than one frame once `next` has read
    /// what it can, and one of the engine's chunks at most after it.
    partial: [constants.quic_stream_partial_bytes_max]u8 = undefined,
    partial_len: usize = 0,

    pub fn start(self: *Stream, context: anytype) Error!void {
        self.partial_len = 0;
        return self.inner.start(context);
    }

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return Connection.lifetime_ns(ticket);
    }

    /// Keeps a chunk of the stream for `next` to read. A chunk that leaves no room fails the
    /// connection, as a frame longer than the engine can hold fails a TCP connection.
    pub fn receive(self: *Stream, bytes: []const u8, now_ns: u64) Error!void {
        _ = now_ns;
        if (self.partial_len + bytes.len > self.partial.len) return error.Failed;
        @memcpy(self.partial[self.partial_len..][0..bytes.len], bytes);
        self.partial_len += bytes.len;
    }

    /// What the stream's frames did, one thing at a time, as `Connection.next` reads a datagram's
    /// items: the frame it holds is read to its end before the next whole one is taken.
    pub fn next(self: *Stream, out: []u8) ?Next {
        var frames: usize = 0;
        while (frames <= self.partial.len / prefix_bytes) : (frames += 1) {
            if (self.inner.next(out)) |said| return said;
            const whole = unframe(self.partial[0..self.partial_len]) orelse return null;
            self.inner.receive(whole.items, 0) catch return .closed;
            std.mem.copyForwards(u8, self.partial[0 .. self.partial_len - whole.len], self.partial[whole.len..self.partial_len]);
            self.partial_len -= whole.len;
        }
        return null;
    }

    pub fn request(self: *Stream, bytes: []u8, len: usize) Error!?u64 {
        return self.inner.request(bytes, len);
    }

    pub fn cancel(self: *Stream, stream: u64) void {
        self.inner.cancel(stream);
    }

    /// The next frame it owes: a datagram's worth of items, after their length.
    pub fn output(self: *Stream, out: []u8, now_ns: u64) usize {
        assert(out.len >= frame_bytes_max);
        var items: [constants.quic_datagram_bytes_max]u8 = undefined;
        const len = self.inner.output(&items, now_ns);
        if (len == 0) return 0;
        return frame(items[0..len], out);
    }

    pub fn deadline(self: *const Stream) ?u64 {
        return self.inner.deadline();
    }

    pub fn expire(self: *Stream, now_ns: u64) void {
        self.inner.expire(now_ns);
    }

    pub fn idle_left_ns(self: *const Stream, now_ns: u64) u64 {
        return self.inner.idle_left_ns(now_ns);
    }

    pub fn close(self: *Stream) void {
        self.inner.close();
    }

    pub fn wipe(self: *Stream) void {
        self.inner.wipe();
        self.partial_len = 0;
    }
};

// Tests.

const testing = std.testing;

test "a frame reads back whole, and not before its last octet has come" {
    var out: [frame_bytes_max]u8 = undefined;
    const len = frame("items", &out);
    const whole = unframe(out[0..len]).?;
    try testing.expectEqualStrings("items", whole.items);
    try testing.expectEqual(len, whole.len);
    try testing.expect(unframe(out[0 .. len - 1]) == null);
    try testing.expect(unframe(out[0..1]) == null);
}

test "the server's frames are read whatever the chunks they came in" {
    var stream: Stream = .{};
    try stream.start(.{ .alpn = "h2", .ticket = @as(?Stream.Ticket, null) });
    var items: [64]u8 = undefined;
    var items_len = quic.write_item(.{ .kind = .done, .bytes = "h2" }, &items);
    items_len += quic.write_item(.{ .kind = .ticket }, items[items_len..]);
    var framed: [frame_bytes_max]u8 = undefined;
    const framed_len = frame(items[0..items_len], &framed);
    var answer: [16]u8 = undefined;
    // Octet by octet: nothing is read until the frame is whole.
    for (framed[0 .. framed_len - 1]) |octet| {
        try stream.receive(&.{octet}, 0);
        try testing.expect(stream.next(&answer) == null);
    }
    try stream.receive(framed[framed_len - 1 ..], 0);
    try testing.expectEqualStrings("h2", stream.next(&answer).?.up);
    try testing.expect(stream.next(&answer).? == .ticket);
    try testing.expect(stream.next(&answer) == null);
}

test "what it owes goes out as one frame, holding the hello" {
    var stream: Stream = .{};
    try stream.start(.{ .alpn = "h2", .ticket = @as(?Stream.Ticket, null) });
    var out: [frame_bytes_max]u8 = undefined;
    const len = stream.output(&out, 0);
    const whole = unframe(out[0..len]).?;
    try testing.expectEqual(len, whole.len);
    const hello = quic.read_item(whole.items).?.item;
    try testing.expectEqual(quic.Kind.hello, hello.kind);
    try testing.expectEqualStrings("h2", hello.bytes);
    try testing.expectEqual(@as(usize, 0), stream.output(&out, 0));
}
