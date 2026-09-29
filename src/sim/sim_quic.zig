//! The twin's QUIC (docs/design.md §24, the request interface): a connection with the functions
//! the engine asks of colibri, whose datagrams carry items in the clear, and the server side a
//! scripted server answers it with. An item is one octet naming what happened, the stream it
//! happened on, and the octets it carries. The replay spells the model's QUIC steps with them
//! (spec/tla/engine/EngineRequest.tla, `QuicStep`), and a scripted server answers a hello with
//! them.
//!
//! What the twin cannot show is colibri's and chapulin's to show: packets, loss and its recovery,
//! flow control, the ciphers and the certificate checks. The engine runs over colibri on the twin
//! for those (§24).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

const header_bytes = constants.quic_item_header_bytes;

/// What one item says.
pub const Kind = enum(u8) {
    // The client's.
    hello,
    hello_resumed,
    flight_answer,
    finished,
    ack,
    request,
    stop_sending,
    close,
    // The server's.
    flight,
    done,
    refused,
    ticket,
    ping,
    answer,
    reset,
    closed,
    // The server's: a GOAWAY, which no DoQ server sends (RFC 9250), for the engine's drain
    // (docs/design.md §24, request rule 13).
    goaway,
};

pub const Item = struct { kind: Kind, stream: u32 = 0, bytes: []const u8 = &.{} };

/// Writes one item into `out` and returns its octets.
pub fn write_item(item: Item, out: []u8) usize {
    assert(item.bytes.len <= std.math.maxInt(u16));
    assert(out.len >= header_bytes + item.bytes.len);
    out[0] = @intFromEnum(item.kind);
    std.mem.writeInt(u32, out[constants.quic_item_stream_at..][0..@sizeOf(u32)], item.stream, .big);
    std.mem.writeInt(u16, out[constants.quic_item_length_at..][0..@sizeOf(u16)], @intCast(item.bytes.len), .big);
    @memcpy(out[header_bytes..][0..item.bytes.len], item.bytes);
    return header_bytes + item.bytes.len;
}

pub const Read = struct { item: Item, len: usize };

/// The first item of `bytes`, and its octets, or null when it is not a whole item of a kind the
/// twin knows.
pub fn read_item(bytes: []const u8) ?Read {
    if (bytes.len < header_bytes) return null;
    const kind = std.enums.fromInt(Kind, bytes[0]) orelse return null;
    const length = std.mem.readInt(u16, bytes[constants.quic_item_length_at..][0..@sizeOf(u16)], .big);
    if (bytes.len < header_bytes + length) return null;
    const stream = std.mem.readInt(u32, bytes[constants.quic_item_stream_at..][0..@sizeOf(u32)], .big);
    return .{ .item = .{ .kind = kind, .stream = stream, .bytes = bytes[header_bytes..][0..length] }, .len = header_bytes + length };
}

const peer_module = @import("sim_quic_peer.zig");

/// The client: a connection with the functions the engine asks of one (docs/design.md §24).
pub const Connection = struct {
    pub const enabled = true;
    pub const output_bytes_max = constants.quic_datagram_bytes_max;
    pub const request_bytes_max = core.constants.query_bytes_max;
    pub const Error = error{Failed};
    /// What the engine hands every connection it starts: nothing, for the twin.
    pub const Context = struct {};
    /// A ticket the server gave. The twin's carries nothing: it only has to be kept and spent.
    pub const Ticket = struct {};
    pub const Answered = struct { stream: u64, len: usize };
    pub const Next = union(enum) { up: []const u8, refused, answered: Answered, reset: u64, closed, goaway, ticket: Ticket };
    /// What an expiry does, as the replay or a test sets it: the connection resends what the
    /// server has not acknowledged, or gives up.
    pub const Expiry = enum { retransmit, timeout };

    const State = enum { idle, handshaking, up, closing, dead };

    state: State = .idle,
    /// The items it has to send, oldest first, and whether it owes the server a datagram.
    pending: [constants.quic_pending_bytes_max]u8 = undefined,
    pending_len: usize = 0,
    owes: bool = false,
    /// The datagram last received, and how far `next` has read it.
    inbound: [output_bytes_max]u8 = undefined,
    inbound_len: usize = 0,
    inbound_at: usize = 0,
    next_stream: u64 = 0,
    /// The connection's QUIC timer, and what its expiry does: set by the replay and by tests.
    due_ns: ?u64 = null,
    expiry: Expiry = .retransmit,
    timed_out: bool = false,
    /// How long before the idle timeout it negotiated: never near, unless a test says so.
    idle_left: u64 = std.math.maxInt(u64),

    /// Stages the hello, a resumed one when the engine hands over a ticket, offering the ALPN the
    /// engine names.
    pub fn start(self: *Connection, context: anytype) Error!void {
        assert(self.state == .idle);
        self.* = .{ .state = .handshaking };
        self.add(.{ .kind = if (context.ticket != null) .hello_resumed else .hello, .bytes = context.alpn });
    }

    /// The twin's tickets never lapse on their own, so the engine's seven-day cap is what ends one.
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        _ = ticket;
        return std.math.maxInt(u64);
    }

    /// Keeps one datagram for `next` to read.
    pub fn receive(self: *Connection, bytes: []const u8, now_ns: u64) Error!void {
        _ = now_ns;
        assert(self.state != .idle);
        if (bytes.len > self.inbound.len) return self.fail();
        @memcpy(self.inbound[0..bytes.len], bytes);
        self.inbound_len = bytes.len;
        self.inbound_at = 0;
    }

    /// What the datagram, or the expiry, did, one thing at a time. An answer's octets go into
    /// `out`, as many as fit, and it says how many there were.
    pub fn next(self: *Connection, out: []u8) ?Next {
        if (self.timed_out) {
            self.timed_out = false;
            self.state = .dead;
            return .closed;
        }
        // A closing connection reads nothing more (docs/design.md §24, request rule 9).
        if (self.state == .closing) return null;
        var items: usize = 0;
        while (items < constants.quic_items_per_datagram_max) : (items += 1) {
            if (self.inbound_at >= self.inbound_len) break;
            const read = read_item(self.inbound[self.inbound_at..self.inbound_len]) orelse {
                self.inbound_at = self.inbound_len;
                return self.lost();
            };
            self.inbound_at += read.len;
            if (self.hear(read.item, out)) |said| return said;
        }
        return null;
    }

    fn hear(self: *Connection, item: Item, out: []u8) ?Next {
        switch (item.kind) {
            .flight => self.add(.{ .kind = .flight_answer }),
            .ping => self.owes = true,
            .done => {
                if (self.state != .handshaking) return self.lost();
                self.state = .up;
                self.add(.{ .kind = .finished });
                return .{ .up = item.bytes };
            },
            .refused => {
                self.state = .dead;
                return .refused;
            },
            .ticket => {
                self.owes = true;
                return .{ .ticket = .{} };
            },
            .answer => {
                self.owes = true;
                const copied = @min(item.bytes.len, out.len);
                @memcpy(out[0..copied], item.bytes[0..copied]);
                return .{ .answered = .{ .stream = item.stream, .len = item.bytes.len } };
            },
            .reset => {
                self.owes = true;
                return .{ .reset = item.stream };
            },
            .goaway => {
                self.owes = true;
                return .goaway;
            },
            .closed => return self.lost(),
            // A client's item from the server is a protocol error.
            else => return self.lost(),
        }
        return null;
    }

    /// Opens a stream carrying `bytes[0..len]`, then FIN. Null when the items it holds leave no
    /// room, which the engine reads as the server's credit run out.
    pub fn request(self: *Connection, bytes: []u8, len: usize) Error!?u64 {
        assert(self.state == .up);
        assert(len <= bytes.len);
        const room = self.pending.len - self.pending_len;
        if (room < header_bytes + len + constants.quic_pending_reserve_bytes) return null;
        const stream = self.next_stream;
        self.next_stream += constants.quic_stream_step;
        self.add(.{ .kind = .request, .stream = @intCast(stream), .bytes = bytes[0..len] });
        return stream;
    }

    /// STOP_SENDING, and the engine's side of the stream reset.
    pub fn cancel(self: *Connection, stream: u64) void {
        self.add(.{ .kind = .stop_sending, .stream = @intCast(stream) });
    }

    /// The next datagram it owes, as many whole items as fit, or nothing. One owed with nothing
    /// staged carries an acknowledgement.
    pub fn output(self: *Connection, out: []u8, now_ns: u64) usize {
        _ = now_ns;
        if (!self.owes) return 0;
        if (self.pending_len == 0) self.add(.{ .kind = .ack });
        var len: usize = 0;
        var items: usize = 0;
        while (items < constants.quic_items_per_datagram_max and len < self.pending_len) : (items += 1) {
            const read = read_item(self.pending[len..self.pending_len]).?;
            if (len + read.len > out.len) break;
            len += read.len;
        }
        assert(len > 0);
        @memcpy(out[0..len], self.pending[0..len]);
        std.mem.copyForwards(u8, self.pending[0 .. self.pending_len - len], self.pending[len..self.pending_len]);
        self.pending_len -= len;
        self.owes = self.pending_len > 0;
        return len;
    }

    pub fn deadline(self: *const Connection) ?u64 {
        return self.due_ns;
    }

    pub fn expire(self: *Connection, now_ns: u64) void {
        _ = now_ns;
        self.due_ns = null;
        switch (self.expiry) {
            .retransmit => self.owes = true,
            .timeout => self.timed_out = true,
        }
    }

    pub fn idle_left_ns(self: *const Connection, now_ns: u64) u64 {
        _ = now_ns;
        return self.idle_left;
    }

    /// The CONNECTION_CLOSE of an idle close.
    pub fn close(self: *Connection) void {
        assert(self.state == .handshaking or self.state == .up);
        self.add(.{ .kind = .close });
        self.state = .closing;
    }

    pub fn wipe(self: *Connection) void {
        self.* = .{};
    }

    fn add(self: *Connection, item: Item) void {
        assert(self.pending_len + header_bytes + item.bytes.len <= self.pending.len);
        self.pending_len += write_item(item, self.pending[self.pending_len..]);
        self.owes = true;
    }

    fn lost(self: *Connection) Next {
        self.state = .dead;
        return .closed;
    }

    fn fail(self: *Connection) Error {
        self.state = .dead;
        return Error.Failed;
    }
};

/// How a scripted server's QUIC behaves, and one connection's server side (`sim_quic_peer.zig`).
pub const Behaviour = peer_module.Behaviour;
pub const Peer = peer_module.Peer;

// Tests.

const testing = std.testing;

const Context = struct { alpn: []const u8 = "doq", ticket: ?Connection.Ticket = null };

fn datagram_of(items: []const Item, out: []u8) []const u8 {
    var len: usize = 0;
    for (items) |item| len += write_item(item, out[len..]);
    return out[0..len];
}

test "an item reads back as written, and a short or unknown one does not read" {
    var out: [64]u8 = undefined;
    const len = write_item(.{ .kind = .answer, .stream = 8, .bytes = "abc" }, &out);
    const read = read_item(out[0..len]).?;
    try testing.expectEqual(Kind.answer, read.item.kind);
    try testing.expectEqual(@as(u32, 8), read.item.stream);
    try testing.expectEqualStrings("abc", read.item.bytes);
    try testing.expectEqual(@as(?Read, null), read_item(out[0 .. len - 1]));
    out[0] = 0xff;
    try testing.expectEqual(@as(?Read, null), read_item(out[0..len]));
}

test "a hello, a flight, and the handshake's end on the offered protocol, then a ticket" {
    var client: Connection = .{};
    try client.start(Context{});
    var out: [Connection.output_bytes_max]u8 = undefined;
    var peer: Peer = .{};
    const behaviour: Behaviour = .{ .flights = 1, .tickets = true };
    const hello = read_item(out[0..client.output(&out, 0)]).?.item;
    try testing.expectEqual(Kind.flight, peer.hear(&behaviour, hello).steps.first);
    var scratch: [Connection.output_bytes_max]u8 = undefined;
    try client.receive(datagram_of(&.{.{ .kind = .flight }}, &scratch), 0);
    try testing.expectEqual(@as(?Connection.Next, null), client.next(&.{}));
    const heard = peer.hear(&behaviour, read_item(out[0..client.output(&out, 0)]).?.item);
    try testing.expectEqual(Kind.done, heard.steps.first);
    try testing.expectEqual(@as(?Kind, .ticket), heard.steps.second);
    try client.receive(datagram_of(&.{ .{ .kind = .done, .bytes = peer.negotiated(&behaviour) }, .{ .kind = .ticket } }, &scratch), 0);
    try testing.expectEqualStrings("doq", client.next(&.{}).?.up);
    try testing.expect(client.next(&.{}).? == .ticket);
    try testing.expectEqual(@as(?Connection.Next, null), client.next(&.{}));
}

test "a stream carries its request to the server, and its answer back by the stream" {
    var client: Connection = .{ .state = .up };
    var bytes = [_]u8{ 0, 2, 'h', 'i' };
    const stream = (try client.request(&bytes, bytes.len)).?;
    try testing.expectEqual(@as(u64, 0), stream);
    try testing.expectEqual(@as(u64, constants.quic_stream_step), (try client.request(&bytes, bytes.len)).?);
    var out: [Connection.output_bytes_max]u8 = undefined;
    var peer: Peer = .{ .up = true };
    const sent = out[0..client.output(&out, 0)];
    const heard = peer.hear(&.{}, read_item(sent).?.item);
    try testing.expectEqualSlices(u8, &bytes, heard.request.bytes);
    var scratch: [Connection.output_bytes_max]u8 = undefined;
    try client.receive(datagram_of(&.{.{ .kind = .answer, .stream = 4, .bytes = "answer" }}, &scratch), 0);
    var answer: [3]u8 = undefined;
    const answered = client.next(&answer).?.answered;
    try testing.expectEqual(@as(u64, 4), answered.stream);
    // The answer says how long it was, past the buffer it was handed.
    try testing.expectEqual(@as(usize, 6), answered.len);
    try testing.expectEqualStrings("ans", &answer);
}

test "a refused handshake, a close, an unknown item and an expiry each end the connection" {
    var scratch: [Connection.output_bytes_max]u8 = undefined;
    var refused: Connection = .{ .state = .handshaking };
    try refused.receive(datagram_of(&.{.{ .kind = .refused }}, &scratch), 0);
    try testing.expect(refused.next(&.{}).? == .refused);
    var closed: Connection = .{ .state = .up };
    try closed.receive(datagram_of(&.{.{ .kind = .closed }}, &scratch), 0);
    try testing.expect(closed.next(&.{}).? == .closed);
    var confused: Connection = .{ .state = .up };
    try confused.receive(datagram_of(&.{.{ .kind = .hello }}, &scratch), 0);
    try testing.expect(confused.next(&.{}).? == .closed);
    var timed: Connection = .{ .state = .up, .due_ns = 5, .expiry = .timeout };
    timed.expire(5);
    try testing.expect(timed.next(&.{}).? == .closed);
    var resending: Connection = .{ .state = .up, .due_ns = 5 };
    resending.expire(5);
    try testing.expectEqual(@as(?Connection.Next, null), resending.next(&.{}));
    try testing.expect(resending.output(&scratch, 5) > 0);
}
