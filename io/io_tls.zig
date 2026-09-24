//! The engine's TLS, over a session type (docs/design.md §21: the session seam and the TLS rules).
//! A connection to a TLS server handshakes between its connect and its first query (rule 1).
//! The records the session makes are sealed as it makes them and wait in the connection's
//! records buffer with the queries sealed after them, going out in the order they were sealed
//! (rule 2); a send lends the buffer to the loop until its final event (rule 3). Records received
//! go to the session whole (rule 7). An idle connection says `close_notify` before it closes
//! (rule 5), and a resumed handshake that fails is answered by a full one (rule 8).
//!
//! Free functions over the engine, split out of `io_tcp.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const tcp = @import("io_tcp.zig");
const queue_module = @import("io_tcp_queue.zig");
const ring = @import("io_tcp_queue_ring.zig");

/// No TLS: the engine's default. It holds nothing, and `init` refuses a TLS configuration, so
/// none of its functions is ever called.
pub const None = struct {
    pub const enabled = false;
    pub const out_bytes_max = 0;
    pub const Error = error{Failed};
    pub const Context = struct {};
    pub const Ticket = struct {};
    pub const Handshake = enum { going, done };
    pub const Opened = union(enum) { data: usize, nothing, closed };

    pub fn start(_: *None, _: anytype) Error!void {
        unreachable;
    }
    pub fn lifetime_ns(_: *const Ticket) u64 {
        unreachable;
    }
    pub fn take_out(_: *None, _: []u8) usize {
        unreachable;
    }
    pub fn handshake(_: *None, _: []const u8) Error!Handshake {
        unreachable;
    }
    pub fn seal(_: *None, _: []const u8) Error!void {
        unreachable;
    }
    pub fn open(_: *None, _: []const u8, _: []u8) Error!Opened {
        unreachable;
    }
    pub fn take_ticket(_: *None) ?Ticket {
        unreachable;
    }
    pub fn close(_: *None) void {
        unreachable;
    }
    pub fn wipe(_: *None) void {}
};

/// One connection's TLS: its session, the record it is reading, and the records sealed and not
/// yet gone. With `None` the buffers hold nothing.
pub fn State(comptime Session: type) type {
    const in_bytes = if (Session.enabled) constants.tls_record_in_bytes else 0;
    const out_bytes = if (Session.enabled) constants.tls_records_out_bytes else 0;
    return struct {
        session: Session = .{},
        /// The ticket this opening resumes with, spent from its server's (rule 8).
        ticket: ?Session.Ticket = null,
        record_in: [in_bytes]u8 = undefined,
        record_in_used: usize = 0,
        /// Sealed records, oldest first, from `out_head` to `out_tail`: the head entry's are the
        /// ones in flight.
        out: [out_bytes]u8 = undefined,
        out_head: u16 = 0,
        out_tail: u16 = 0,
    };
}

/// A ticket a server's session gave, and when (rule 8).
pub fn Kept(comptime Session: type) type {
    return struct { ticket: Session.Ticket, since_ns: u64 };
}

/// Whether the engine's connections speak TLS: every server does, or none (§21).
pub fn speaks(self: anytype) bool {
    return self.config.uses_tls();
}

// Tickets (rule 8).

/// Keeps the newest ticket a session of `server`'s was given.
fn keep(self: anytype, server: u8, ticket: anytype, now_ns: u64) void {
    self.tls_tickets[server] = .{ .ticket = ticket, .since_ns = now_ns };
}

/// Spends `server`'s ticket on the opening in slot `at`, unless it has lapsed: at its own
/// lifetime, or seven days after it came, whichever is sooner (RFC 9846 §4.7.1). A ticket is used
/// once, since reuse lets an observer link two connections (§C.4).
pub fn spend(self: anytype, at: u8, server: u8, now_ns: u64) void {
    const Session = @TypeOf(self.*).Tls;
    const connection = &self.connections[at];
    connection.tls.ticket = null;
    const kept = self.tls_tickets[server] orelse return;
    self.tls_tickets[server] = null;
    const age_ns = now_ns -| kept.since_ns;
    const lifetime_ns = @min(Session.lifetime_ns(&kept.ticket), constants.tls_ticket_age_ns_max);
    if (age_ns >= lifetime_ns) return;
    connection.tls.ticket = kept.ticket;
}

// The handshake (rules 1 and 4).

/// A connection to a TLS server came up: the session starts, with the ticket its opening spent,
/// and its first flight goes (rule 1). A session that cannot start fails the connection.
pub fn begin(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    const server = &self.config.servers[connection.server];
    assert(connection.state == .handshaking);
    connection.tls.session.start(.{
        .tls = &server.tls.?,
        .ticket = connection.tls.ticket,
        .context = &self.tls_context,
    }) catch return tcp.fail(self, at, now_ns);
    _ = make_records(self, at, now_ns);
}

/// Bytes of a TLS connection's stream: kept until they make whole records, and each whole record
/// handed to the session (rule 7).
pub fn take(self: anytype, at: u8, bytes: []const u8, now_ns: u64) void {
    const state = &self.connections[at].tls;
    if (state.record_in_used + bytes.len > state.record_in.len) return tcp.fail(self, at, now_ns);
    @memcpy(state.record_in[state.record_in_used..][0..bytes.len], bytes);
    state.record_in_used += bytes.len;
    var records: usize = 0;
    while (records < constants.tls_records_per_chunk_max) : (records += 1) {
        const whole = record_len(state.record_in[0..state.record_in_used]) catch return tcp.fail(self, at, now_ns);
        if (whole == 0) return;
        if (!hear(self, at, state.record_in[0..whole], now_ns)) return;
        std.mem.copyForwards(u8, state.record_in[0 .. state.record_in_used - whole], state.record_in[whole..state.record_in_used]);
        state.record_in_used -= whole;
    }
}

/// The octets of the first whole record, zero while it has not all arrived. A record longer than
/// TLS allows can never be whole, and ends the connection (RFC 9846 §5.2).
fn record_len(bytes: []const u8) error{Overflow}!usize {
    const header = constants.tls_record_header_bytes;
    if (bytes.len < header) return 0;
    const body = std.mem.readInt(u16, bytes[constants.tls_record_length_at..][0..@sizeOf(u16)], .big);
    // "The length MUST NOT exceed 2^14 + 256 bytes" (RFC 9846 §5.2).
    if (body > constants.tls_record_body_bytes_max) return error.Overflow;
    if (bytes.len < header + body) return 0;
    return header + body;
}

/// One whole record, as the connection's stage reads it. False when the connection is no longer
/// the one that read it, and the rest of the chunk is not its to read.
fn hear(self: anytype, at: u8, record: []const u8, now_ns: u64) bool {
    return switch (self.connections[at].state) {
        .handshaking => shake(self, at, record, now_ns),
        .up => open(self, at, record, now_ns),
        // A closing connection said its last, and reads nothing more.
        else => true,
    };
}

fn shake(self: anytype, at: u8, record: []const u8, now_ns: u64) bool {
    const connection = &self.connections[at];
    const step = connection.tls.session.handshake(record) catch {
        // A resumed handshake that fails is not the server's failure (rule 8).
        if (connection.tls.ticket != null) tcp.retry_full(self, at, now_ns) else tcp.fail(self, at, now_ns);
        return false;
    };
    if (!make_records(self, at, now_ns)) return false;
    if (step == .done) {
        connection.state = .up;
        tcp.tell_all(self, at, now_ns, true);
    }
    return true;
}

/// A record once up: an answer's octets go to the connection's framing, a ticket is kept, and
/// what the session answered of its own accord goes out (rule 2). The peer's close or a record
/// the session refuses fails the connection.
fn open(self: anytype, at: u8, record: []const u8, now_ns: u64) bool {
    const connection = &self.connections[at];
    const opened = connection.tls.session.open(record, connection.frame[connection.used..]) catch {
        tcp.fail(self, at, now_ns);
        return false;
    };
    if (connection.tls.session.take_ticket()) |ticket| keep(self, connection.server, ticket, now_ns);
    if (!make_records(self, at, now_ns)) return false;
    switch (opened) {
        .data => |count| {
            connection.used += count;
            tcp.deliver(self, at, now_ns);
        },
        .nothing => {},
        .closed => {
            tcp.fail(self, at, now_ns);
            return false;
        },
    }
    return true;
}

// Sealing (rules 2 and 3).

/// Collects what the session made as one entry of its own records, sealed now: after what is
/// sealed already and ahead of every query that is not (rule 2). False when the connection
/// failed: no room was left, or the loop refused the send.
pub fn make_records(self: anytype, at: u8, now_ns: u64) bool {
    const connection = &self.connections[at];
    const end = take_out(self, at) orelse {
        tcp.fail(self, at, now_ns);
        return false;
    };
    if (end == connection.tls.out_tail) return true;
    connection.tls.out_tail = end;
    const queue = &connection.queue;
    // Behind an entry of the session's own records that has not started, they join it: the two
    // go out together, in the order they were made (rule 2).
    if (queue.sealed > 1 and !queue.at(queue.sealed - 1).is_query()) {
        queue.slot_at(queue.sealed - 1).end = end;
        return true;
    }
    queue.insert_sealed(.{ .slot = ring.records, .end = end });
    queue_module.pump(self, at, now_ns);
    return self.connections[at].state != .closed;
}

/// Seals the head's query as it goes (rule 2). False when the connection failed.
pub fn seal(self: anytype, at: u8, slot: u16, now_ns: u64) bool {
    const connection = &self.connections[at];
    assert(connection.queue.sealed == 0);
    const query = self.send_buffers[slot][0..self.send_lengths[slot]];
    connection.tls.session.seal(query) catch {
        tcp.fail(self, at, now_ns);
        return false;
    };
    const end = take_out(self, at) orelse {
        tcp.fail(self, at, now_ns);
        return false;
    };
    assert(end > connection.tls.out_tail);
    connection.tls.out_tail = end;
    connection.queue.first_pointer().end = end;
    connection.queue.sealed = 1;
    return true;
}

/// Moves what the session made to the end of the records buffer, and returns where it ends.
/// Null when it could not fit: sealed bytes the loop holds are never moved (rule 3), so the room
/// is what is left behind them, or the whole buffer once nothing is in flight.
fn take_out(self: anytype, at: u8) ?u16 {
    const Session = @TypeOf(self.*).Tls;
    const connection = &self.connections[at];
    const state = &connection.tls;
    if (!connection.sending and state.out_head > 0) {
        const kept = state.out_tail - state.out_head;
        std.mem.copyForwards(u8, state.out[0..kept], state.out[state.out_head..state.out_tail]);
        connection.queue.shift_ends(state.out_head);
        state.out_head = 0;
        state.out_tail = kept;
    }
    const room = state.out[state.out_tail..];
    if (room.len < Session.out_bytes_max) return null;
    const made = state.session.take_out(room);
    return state.out_tail + @as(u16, @intCast(made));
}

/// What is left to send of the head, whose sealed records end at `end`.
pub fn pending(self: anytype, at: u8, end: u16) []const u8 {
    const connection = &self.connections[at];
    const from = connection.tls.out_head + connection.sent_bytes;
    assert(from < end);
    return connection.tls.out[from..end];
}

/// The head's records went whole: the buffer up to `end` is free again.
pub fn sent_through(self: anytype, at: u8, end: u16) void {
    const state = &self.connections[at].tls;
    assert(end <= state.out_tail);
    state.out_head = end;
    if (state.out_head == state.out_tail) {
        state.out_head = 0;
        state.out_tail = 0;
    }
}

// Closing (rule 5).

/// An idle connection that is up says `close_notify`, and closes once that has gone.
pub fn close(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(connection.state == .up and connection.users == 0);
    connection.state = .closing;
    connection.tls.session.close();
    _ = make_records(self, at, now_ns);
}

/// Everything of a connection's TLS but what outlives it: the session's secrets wiped.
pub fn reset(connection: anytype) void {
    connection.tls.session.wipe();
    connection.tls = .{};
}

comptime {
    // A sealed entry's end fits the queue's u16.
    assert(constants.tls_records_out_bytes <= std.math.maxInt(u16));
}

// Tests.

const testing = std.testing;

test "a record is whole once its body has come, and one longer than TLS allows never is" {
    const header = constants.tls_record_header_bytes;
    var bytes: [header + 3]u8 = .{ 23, 3, 3, 0, 3, 'a', 'b', 'c' };
    try testing.expectEqual(@as(usize, 0), try record_len(bytes[0 .. header - 1]));
    try testing.expectEqual(@as(usize, 0), try record_len(bytes[0 .. header + 2]));
    try testing.expectEqual(@as(usize, header + 3), try record_len(&bytes));
    // "The length MUST NOT exceed 2^14 + 256 bytes" (RFC 9846 §5.2): one octet over is refused
    // at the header, before its body could fill the buffer.
    std.mem.writeInt(u16, bytes[constants.tls_record_length_at..][0..@sizeOf(u16)], constants.tls_record_body_bytes_max + 1, .big);
    try testing.expectError(error.Overflow, record_len(bytes[0..header]));
    std.mem.writeInt(u16, bytes[constants.tls_record_length_at..][0..@sizeOf(u16)], constants.tls_record_body_bytes_max, .big);
    try testing.expectEqual(@as(usize, 0), try record_len(bytes[0..header]));
}
