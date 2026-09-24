//! The twin's TLS (docs/design.md §21, the session seam): a session with the functions the
//! engine asks of chapulin, whose records carry their plaintext unsealed, and the server side a
//! scripted server answers it with. A record keeps a real record's header (RFC 9846 §5.1), so
//! the engine frames the twin's records as it frames chapulin's. A handshake step is one octet in
//! a handshake record. The replay spells the model's TLS steps with them (spec/Spec/Engine.lean,
//! `TlsStep`), and a scripted server answers a hello with them.
//!
//! What the twin cannot show is chapulin's to show: the ciphers, the certificate and pin checks,
//! and the binding of a ticket.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

const header_bytes = constants.tls_record_header_bytes;

/// One octet in a handshake record: what one side says to the other.
pub const Step = enum(u8) {
    // The client's.
    hello,
    hello_resumed,
    flight_answer,
    finished,
    rekey_answer,
    // The server's.
    flight,
    done,
    refused,
    rekey,
    ticket,
};

/// Writes one record into `out` and returns its octets.
pub fn write_record(content: u8, payload: []const u8, out: []u8) usize {
    assert(payload.len <= constants.tls_payload_bytes_max);
    assert(out.len >= header_bytes + payload.len);
    out[0] = content;
    std.mem.writeInt(u16, out[constants.tls_record_version_at..][0..@sizeOf(u16)], constants.tls_legacy_version, .big);
    std.mem.writeInt(u16, out[constants.tls_record_length_at..][0..@sizeOf(u16)], @intCast(payload.len), .big);
    @memcpy(out[header_bytes..][0..payload.len], payload);
    return header_bytes + payload.len;
}

/// Writes one handshake step as its own record.
pub fn write_step(step: Step, out: []u8) usize {
    return write_record(constants.tls_content_handshake, &.{@intFromEnum(step)}, out);
}

/// The step a whole record holds, or null when it is not one handshake step.
pub fn step_of(record: []const u8) ?Step {
    if (record.len != header_bytes + 1 or record[0] != constants.tls_content_handshake) return null;
    return std.enums.fromInt(Step, record[header_bytes]);
}

/// The octets of the first whole record in `bytes`, or null while it has not all arrived.
pub fn record_len(bytes: []const u8) ?usize {
    if (bytes.len < header_bytes) return null;
    const length = std.mem.readInt(u16, bytes[constants.tls_record_length_at..][0..@sizeOf(u16)], .big);
    if (bytes.len < header_bytes + length) return null;
    return header_bytes + length;
}

/// The client: a session with the functions the engine asks of one (docs/design.md §21).
pub const Session = struct {
    pub const enabled = true;
    /// The most one call makes before the engine takes it out.
    pub const out_bytes_max = constants.tls_out_bytes_max;
    pub const Error = error{Failed};
    /// What the engine hands every session it starts: nothing, for the twin.
    pub const Context = struct {};
    /// A ticket the server gave. The twin's carries nothing: it only has to be kept and spent.
    pub const Ticket = struct {};
    pub const Handshake = enum { going, done };
    pub const Opened = union(enum) { data: usize, nothing, closed };

    const State = enum { idle, handshaking, up, dead };

    state: State = .idle,
    out: [constants.tls_out_bytes_max]u8 = undefined,
    out_len: usize = 0,
    ticket: ?Ticket = null,

    /// Stages the hello: a resumed one when the engine hands over a ticket.
    pub fn start(self: *Session, context: anytype) Error!void {
        assert(self.state == .idle);
        self.* = .{ .state = .handshaking };
        self.make(if (context.ticket != null) .hello_resumed else .hello);
    }

    /// How long a ticket may be used for, in nanoseconds: the twin's never lapse on their own,
    /// so the engine's seven-day cap is what ends one.
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        _ = ticket;
        return std.math.maxInt(u64);
    }

    /// Hands over what the session made since the last call, in the order it made it.
    pub fn take_out(self: *Session, out: []u8) usize {
        assert(out.len >= self.out_len);
        const made = self.out_len;
        @memcpy(out[0..made], self.out[0..made]);
        self.out_len = 0;
        return made;
    }

    /// One whole record while the handshake runs.
    pub fn handshake(self: *Session, record: []const u8) Error!Handshake {
        assert(self.state == .handshaking);
        const step = step_of(record) orelse return self.fail();
        switch (step) {
            .flight => {
                self.make(.flight_answer);
                return .going;
            },
            .done => {
                self.make(.finished);
                self.state = .up;
                return .done;
            },
            else => return self.fail(),
        }
    }

    /// The records of one query.
    pub fn seal(self: *Session, plaintext: []const u8) Error!void {
        assert(self.state == .up);
        assert(self.out_len + header_bytes + plaintext.len <= self.out.len);
        self.out_len += write_record(constants.tls_content_application, plaintext, self.out[self.out_len..]);
    }

    /// One whole record once up: what it held, into `plaintext` when it is data.
    pub fn open(self: *Session, record: []const u8, plaintext: []u8) Error!Opened {
        assert(self.state == .up);
        if (record.len < header_bytes) return self.fail();
        switch (record[0]) {
            constants.tls_content_application => {
                const payload = record[header_bytes..];
                if (payload.len > plaintext.len) return self.fail();
                @memcpy(plaintext[0..payload.len], payload);
                return .{ .data = payload.len };
            },
            constants.tls_content_alert => {
                self.state = .dead;
                return .closed;
            },
            else => return self.post_handshake(record),
        }
    }

    fn post_handshake(self: *Session, record: []const u8) Error!Opened {
        const step = step_of(record) orelse return self.fail();
        switch (step) {
            .rekey => self.make(.rekey_answer),
            .ticket => self.ticket = .{},
            else => return self.fail(),
        }
        return .nothing;
    }

    /// The ticket the server gave, once.
    pub fn take_ticket(self: *Session) ?Ticket {
        const ticket = self.ticket;
        self.ticket = null;
        return ticket;
    }

    /// The `close_notify` of an idle close (RFC 9846 §6.1).
    pub fn close(self: *Session) void {
        assert(self.state == .up);
        self.out_len += write_record(constants.tls_content_alert, &constants.tls_close_notify, self.out[self.out_len..]);
        self.state = .dead;
    }

    pub fn wipe(self: *Session) void {
        self.* = .{};
    }

    fn make(self: *Session, step: Step) void {
        assert(self.out_len + header_bytes + 1 <= self.out.len);
        self.out_len += write_step(step, self.out[self.out_len..]);
    }

    fn fail(self: *Session) Error {
        self.state = .dead;
        return Error.Failed;
    }
};

/// How a scripted server's TLS behaves (sim_server.zig's `Script`).
pub const Behaviour = struct {
    /// Flights it asks the client to answer before the handshake ends.
    flights: u8 = 0,
    /// Refuses every handshake, as a server whose certificate does not verify is refused.
    refuse: bool = false,
    /// Declines every ticket, which fails a resumed handshake.
    decline_tickets: bool = false,
    /// Gives a ticket when a handshake ends.
    tickets: bool = false,
};

/// One connection's server side.
pub const Peer = struct {
    flights_left: u8 = 0,
    up: bool = false,

    /// What the server does with one whole record: steps to write back, or a query stream's
    /// bytes to answer, or the client's close.
    pub const Heard = union(enum) {
        steps: struct { first: Step, second: ?Step = null },
        data: []const u8,
        nothing,
        close,
    };

    pub fn hear(self: *Peer, behaviour: *const Behaviour, record: []const u8) Heard {
        if (record.len >= header_bytes and record[0] == constants.tls_content_application) {
            if (!self.up) return .close;
            return .{ .data = record[header_bytes..] };
        }
        const step = step_of(record) orelse return .close;
        return switch (step) {
            .hello => self.begin(behaviour, false),
            .hello_resumed => self.begin(behaviour, true),
            .flight_answer => self.next(behaviour),
            .finished, .rekey_answer => .nothing,
            else => .close,
        };
    }

    fn begin(self: *Peer, behaviour: *const Behaviour, resumed: bool) Heard {
        if (behaviour.refuse or (resumed and behaviour.decline_tickets)) return .{ .steps = .{ .first = .refused } };
        self.flights_left = behaviour.flights;
        return self.next(behaviour);
    }

    fn next(self: *Peer, behaviour: *const Behaviour) Heard {
        if (self.flights_left > 0) {
            self.flights_left -= 1;
            return .{ .steps = .{ .first = .flight } };
        }
        self.up = true;
        return .{ .steps = .{ .first = .done, .second = if (behaviour.tickets) .ticket else null } };
    }
};

// Tests.

const testing = std.testing;

fn take_step(session: *Session) !Step {
    var out: [constants.tls_out_bytes_max]u8 = undefined;
    const made = session.take_out(&out);
    return step_of(out[0..made]) orelse error.NotAStep;
}

fn step_record(step: Step, out: []u8) []const u8 {
    return out[0..write_step(step, out)];
}

test "a hello, a flight and the handshake's end, with a ticket after it" {
    var session: Session = .{};
    try session.start(.{ .ticket = @as(?Session.Ticket, null) });
    try testing.expectEqual(Step.hello, try take_step(&session));
    var record: [constants.tls_out_bytes_max]u8 = undefined;
    try testing.expectEqual(Session.Handshake.going, try session.handshake(step_record(.flight, &record)));
    try testing.expectEqual(Step.flight_answer, try take_step(&session));
    try testing.expectEqual(Session.Handshake.done, try session.handshake(step_record(.done, &record)));
    try testing.expectEqual(Step.finished, try take_step(&session));
    try testing.expectEqual(Session.Opened.nothing, try session.open(step_record(.ticket, &record), &.{}));
    try testing.expect(session.take_ticket() != null);
    try testing.expect(session.take_ticket() == null);
}

test "a refused handshake fails, and a resumed hello says it resumes" {
    var session: Session = .{};
    try session.start(.{ .ticket = @as(?Session.Ticket, .{}) });
    try testing.expectEqual(Step.hello_resumed, try take_step(&session));
    var record: [constants.tls_out_bytes_max]u8 = undefined;
    try testing.expectError(Session.Error.Failed, session.handshake(step_record(.refused, &record)));
}

test "a sealed query opens on the other side as its plaintext, and a server walks its script" {
    var session: Session = .{};
    try session.start(.{ .ticket = @as(?Session.Ticket, null) });
    var out: [constants.tls_out_bytes_max]u8 = undefined;
    var peer: Peer = .{};
    const behaviour: Behaviour = .{ .flights = 1, .tickets = true };
    const hello = out[0..session.take_out(&out)];
    try testing.expectEqual(Step.flight, peer.hear(&behaviour, hello).steps.first);
    var record: [constants.tls_out_bytes_max]u8 = undefined;
    _ = try session.handshake(step_record(.flight, &record));
    const heard = peer.hear(&behaviour, out[0..session.take_out(&out)]);
    try testing.expectEqual(Step.done, heard.steps.first);
    try testing.expectEqual(@as(?Step, .ticket), heard.steps.second);
    _ = try session.handshake(step_record(.done, &record));
    _ = session.take_out(&out);
    try session.seal("query");
    const sealed = out[0..session.take_out(&out)];
    try testing.expectEqual(@as(?usize, sealed.len), record_len(sealed));
    try testing.expectEqualStrings("query", peer.hear(&behaviour, sealed).data);
}
