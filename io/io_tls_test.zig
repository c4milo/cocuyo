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
const Engine = io.Engine(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.servers,
    .tls = rotor.tls.Session,
});
const Rig = sim_test.RigOf(Engine);

/// Both of the rig's servers known by a name, as a configuration names DoT servers.
fn encrypt(rig: *Rig) !void {
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

test "a refused handshake fails the connection, and the next server answers over TLS" {
    var rig: Rig = .{};
    try start(&rig, 43, .{ .{ .tls = .{ .refuse = true } }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
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
