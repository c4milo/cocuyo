//! The engine over TLS on the twin (docs/design.md §21): a handshake between the connect and the
//! first query, flights answered, a refused handshake failed over, a ticket kept and spent, a
//! declined ticket answered by a full handshake, and an idle connection's `close_notify`. The
//! session is the twin's (`rotor.tls`), whose records carry their plaintext unsealed; what only
//! chapulin can show is chapulin's.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks the twin's TLS, with a connection slot for each server (TLS rule 6).
const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.servers,
    .tls = rotor.tls.Session,
});
const Rig = sim_test.RigOf(Resolver);

/// Both of the rig's servers known by a name, as a configuration names DoT servers.
fn encrypt(rig: anytype) !void {
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.tls = tls;
}

/// A rig whose servers speak TLS as `scripts` say, under a timeout long enough for any of them.
fn start(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script) !void {
    try encrypt(rig);
    try rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
}

test "a lookup over TLS handshakes, then is answered on the stream, and no UDP socket is opened" {
    var rig: Rig = .{};
    try start(&rig, 41, .{ .{}, .{} });
    try testing.expectEqual(@as(u8, 0), rig.engine.sockets.count);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.engine.connections[0].state == .up);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "flights before the handshake's end are answered, and both lookups wait for it" {
    var rig: Rig = .{};
    try start(&rig, 42, .{ .{ .tls = .{ .flights = 2 } }, .{} });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a refused handshake says its alert, fails the connection, and the next server answers" {
    var rig: Rig = .{};
    try start(&rig, 43, .{ .{ .tls = .{ .refuse = true } }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // The session's fatal alert reached the server that refused (RFC 9846 §6.2, TLS rule 4), and
    // the next server heard none.
    try testing.expectEqual(@as(u32, 1), rig.loop.network().alerts_heard[0]);
    try testing.expectEqual(@as(u32, 0), rig.loop.network().alerts_heard[1]);
    // The refused connection freed its slot, which the next server's took.
    try testing.expect(up_to(&rig, 1));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup every server refused over TLS ends in AllServersFailed, not Timeout" {
    // Strict mode's refusal is the server failing the lookup, as SERVFAIL is: the lookup did not
    // run out of time (docs/design.md §16 decision 25).
    var rig: Rig = .{};
    try start(&rig, 47, .{ .{ .tls = .{ .refuse = true } }, .{ .tls = .{ .refuse = true } } });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Whether a connection to `server` is up, in whichever slot.
fn up_to(rig: *const Rig, server: u8) bool {
    for (rig.engine.connections) |connection| {
        if (connection.server == server and connection.state == .up) return true;
    }
    return false;
}

/// Lets the idle close run: the clock moves past `tcp_idle_ns` with nothing due, twice, so the
/// timer the last lookup left is gone as well.
fn idle(rig: *Rig) !void {
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
}

test "an idle TLS connection says close_notify, and closes once it has gone" {
    var rig: Rig = .{};
    try start(&rig, 44, .{ .{}, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try idle(&rig);
    try testing.expect(rig.engine.connections[0].state == .closing);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].state == .closed);
    try rig.deinit();
}

test "a ticket is kept and spent, and a declined one is answered in full, counting no failure" {
    var rig: Rig = .{};
    try start(&rig, 45, .{ .{ .tls = .{ .tickets = true, .decline_tickets = true } }, .{} });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(rig.engine.tls_tickets[0] != null);
    try idle(&rig);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].state == .closed);
    // The next connection resumes, spending the ticket; the server declines it, and the
    // connection opens again in full before the lookup hears anything (TLS rule 8).
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(rig.engine.tls_tickets[0] == null);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a ticket seven days old is not spent: the opening handshakes in full" {
    var rig: Rig = .{};
    try start(&rig, 46, .{ .{}, .{} });
    // "Clients MUST NOT use tickets for longer than 7 days after issuance" (RFC 9846 §4.7.1).
    const week_ns = io.constants.tls_ticket_age_ns_max;
    rig.engine.tls_tickets[0] = .{ .ticket = .{}, .since_ns = 0 };
    io.tls.spend(&rig.engine, 0, 0, week_ns);
    try testing.expect(rig.engine.connections[0].tls.ticket == null);
    try testing.expect(rig.engine.tls_tickets[0] == null);
    // A nanosecond younger, it is spent.
    rig.engine.tls_tickets[0] = .{ .ticket = .{}, .since_ns = 0 };
    io.tls.spend(&rig.engine, 0, 0, week_ns - 1);
    try testing.expect(rig.engine.connections[0].tls.ticket != null);
    try rig.deinit();
}

/// Where the failing session fails. A TLS stack can fail to start or to seal, refuse a record, as
/// it refuses a forged one, or hear its peer close; the twin's session does none of these.
const Failure = enum { start, seal, open, closed };
const Plan = struct { at: Failure = .start, left: u8 = 0 };
threadlocal var failing: Plan = .{};

fn fails_now(at: Failure) bool {
    if (failing.at != at or failing.left == 0) return false;
    failing.left -= 1;
    return true;
}

/// The twin's session, failing where `failing` says and as often.
const Failing = struct {
    const Twin = rotor.tls.Session;
    pub const enabled = true;
    pub const out_bytes_max = Twin.out_bytes_max;
    pub const Error = Twin.Error;
    pub const Context = Twin.Context;
    pub const Ticket = Twin.Ticket;
    pub const Handshake = Twin.Handshake;
    pub const Opened = Twin.Opened;

    twin: Twin = .{},

    pub fn start(self: *Failing, context: anytype) Error!void {
        if (fails_now(.start)) return error.Failed;
        return self.twin.start(context);
    }
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return Twin.lifetime_ns(ticket);
    }
    pub fn take_out(self: *Failing, out: []u8) usize {
        return self.twin.take_out(out);
    }
    pub fn handshake(self: *Failing, record: []const u8) Error!Handshake {
        return self.twin.handshake(record);
    }
    pub fn seal(self: *Failing, plaintext: []const u8) Error!void {
        if (fails_now(.seal)) return error.Failed;
        return self.twin.seal(plaintext);
    }
    pub fn open(self: *Failing, record: []const u8, plaintext: []u8) Error!Opened {
        if (fails_now(.open)) return error.Failed;
        if (fails_now(.closed)) return .closed;
        return self.twin.open(record, plaintext);
    }
    pub fn take_ticket(self: *Failing) ?Ticket {
        return self.twin.take_ticket();
    }
    pub fn close(self: *Failing) void {
        self.twin.close();
    }
    pub fn wipe(self: *Failing) void {
        self.twin.wipe();
    }
};

const FailingRig = sim_test.RigOf(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.servers,
    .tls = Failing,
}));

/// The first server's session fails once, at `at`: its connection fails, the server is charged
/// with it, and the next server answers over TLS.
fn expect_fails_over(seed: u64, at: Failure) !void {
    failing = .{ .at = at, .left = 1 };
    defer failing = .{};
    var rig: FailingRig = .{};
    try encrypt(&rig);
    try rig.init(seed, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), failing.left);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // At once, and not once the first server's wait ran out.
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a session that cannot start, seal or open, or whose peer closes, fails over to the next server" {
    try expect_fails_over(48, .start);
    try expect_fails_over(49, .seal);
    try expect_fails_over(50, .open);
    try expect_fails_over(51, .closed);
}

/// The octet a test's buffer holds before a reset, which no reset writes.
const untouched: u8 = 0x5a;

test "a TLS reset empties the state and leaves the records' bytes, which the loop may hold" {
    var holder: struct { tls: io.tls.State(Failing) = .{} } = .{};
    holder.tls.ticket_since_ns = 9;
    holder.tls.record_in_used = 3;
    holder.tls.out_head = 1;
    holder.tls.out_tail = 2;
    @memset(&holder.tls.record_in, untouched);
    @memset(&holder.tls.out, untouched);
    io.tls.reset(&holder);
    try testing.expectEqual(@as(u64, 0), holder.tls.ticket_since_ns);
    try testing.expectEqual(@as(usize, 0), holder.tls.record_in_used);
    try testing.expectEqual(@as(u16, 0), holder.tls.out_head);
    try testing.expectEqual(@as(u16, 0), holder.tls.out_tail);
    for (holder.tls.record_in) |octet| try testing.expectEqual(untouched, octet);
    for (holder.tls.out) |octet| try testing.expectEqual(untouched, octet);
}
