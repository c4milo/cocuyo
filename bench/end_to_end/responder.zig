//! The in-process responder both stacks are measured against: a thread on a loopback datagram
//! socket that answers every query with one A record for whatever name it asked, so what is
//! measured is the two stacks and the kernel between them, and nothing of a network.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const constants = @import("constants.zig");
const udp = @import("udp.zig");

const header_bytes = cocuyo.constants.header_bytes;
const question_fixed_bytes = cocuyo.constants.question_fixed_bytes;

pub const Responder = struct {
    socket: udp.Socket,
    port: u16,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Set by the thread once it is in its receive loop. `start` waits for it, because a spawn
    /// returns before the thread runs: a row that began first had its earliest queries wait in
    /// the socket's buffer until the thread got there, and that start-up delay landed in the
    /// latencies of the first row alone.
    serving: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// How many queries were answered. Atomic because a row that gives up reads it while this
    /// thread still runs: it is what tells a query c-ares never sent from a reply it never took.
    answered: std.atomic.Value(u64) = .init(0),

    pub fn start(self: *Responder) !void {
        self.socket = try udp.open(0);
        self.port = udp.port_of(self.socket);
        self.serving.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
        while (!self.serving.load(.acquire)) std.atomic.spinLoopHint();
    }

    /// Stops the thread with a datagram to its own socket, joins it and closes the socket.
    pub fn stop(self: *Responder) void {
        self.stopping.store(true, .seq_cst);
        const to = udp.loopback(self.port);
        udp.send(self.socket, "stop", &to) catch {};
        if (self.thread) |thread| thread.join();
        self.thread = null;
        udp.close(self.socket);
    }

    fn serve(self: *Responder) void {
        var query: [constants.datagram_bytes_max]u8 = undefined;
        var reply: [constants.datagram_bytes_max]u8 = undefined;
        var from: udp.Address = undefined;
        self.serving.store(true, .release);
        while (!self.stopping.load(.seq_cst)) {
            const bytes = udp.receive(self.socket, &query, &from) orelse continue;
            const len = build_reply(bytes, &reply) orelse continue;
            udp.send(self.socket, reply[0..len], &from) catch continue;
            _ = self.answered.fetchAdd(1, .monotonic);
        }
    }
};

/// The reply to `query`: its header with QR and RA set and the counts of one answer, its
/// question as it came, and one A record owned by the question's name. Null for a datagram that
/// is not a query, which is dropped.
pub fn build_reply(query: []const u8, reply: []u8) ?usize {
    const question_len = question_length(query) orelse return null;
    const copied = header_bytes + question_len;
    @memcpy(reply[0..copied], query[0..copied]);
    reply[2] |= constants.flag_response_octet;
    reply[3] = (reply[3] & constants.rcode_clear_mask) | constants.flag_recursion_available_octet;
    // qdcount stays one; ancount is one; nothing in the other two sections.
    reply[6] = 0;
    reply[7] = 1;
    @memset(reply[8..header_bytes], 0);
    var at = copied;
    at += write(reply[at..], &constants.record_head);
    at += write(reply[at..], &ttl_octets());
    at += write(reply[at..], &constants.record_rdlength);
    at += write(reply[at..], &constants.answer_v4);
    assert(at <= reply.len);
    return at;
}

fn write(out: []u8, bytes: []const u8) usize {
    @memcpy(out[0..bytes.len], bytes);
    return bytes.len;
}

fn ttl_octets() [4]u8 {
    var octets: [4]u8 = undefined;
    std.mem.writeInt(u32, &octets, constants.answer_ttl_seconds, .big);
    return octets;
}

/// The octets of the question section after the header: the name's labels to the root, then
/// the type and class. Null when the datagram is too short to hold one question.
fn question_length(query: []const u8) ?usize {
    if (query.len < header_bytes) return null;
    var at: usize = header_bytes;
    var labels: usize = 0;
    while (labels < cocuyo.constants.labels_max) : (labels += 1) {
        if (at >= query.len) return null;
        const label_len = query[at];
        if (label_len == 0) break;
        at += 1 + label_len;
    }
    at += 1 + question_fixed_bytes;
    if (at > query.len) return null;
    return at - header_bytes;
}
