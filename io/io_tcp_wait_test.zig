//! A lookup's wait for a connection slot, on the twin (docs/design.md §19 step 13, the stream's
//! rule 12; `io_tcp_wait.zig`). In the clear the connect of a lookup's last try hangs, and no
//! lookup is on its connection any more. The lookup at the next server closes that connection,
//! and waits for the cancelled connect's event. More tests over TLS of a slot that a send holds
//! are in `io_tls_failing_test.zig`.
//!
//! The tests over TLS here have a peer that stops reading, so a send to it never ends. The idle
//! close shuts a connection once it has closed for `tcp_idle_ns`. A `reinit`, a `deinit` and a
//! retry in full end a connection too. Each way cancels the send, and the slot frees at the
//! cancel's event (docs/design.md §16 decision 49). Split from `io_tcp_test.zig` by the
//! file-length rule. The rig is the one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;

/// Every query over TCP, one pass over the two servers, and a wait shorter than the hung connect.
const one_pass: cocuyo.Config = .{
    .servers = &.{},
    .use_tcp = true,
    .timeout_ns = fixtures.slow_connect_timeout_ns,
    .attempts = 1,
    .failover_retry_chance = 0,
};

/// The first server's connect hangs, and the second server answers.
const hung_first = [fixtures.servers]rotor.server.Script{ .{ .connect_delay_ns = fixtures.hung_connect_ns }, .{} };

/// Steps the rig until a lookup waits for a slot.
fn until_waiting(rig: anytype) !void {
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.tcp_waiters > 0) return;
        _ = try rig.step(fixtures.wait_ns);
    }
    return error.NoWait;
}

/// The error of a result, or null for an answer.
fn failure_of(result: anytype) ?cocuyo.Error {
    return if (result.outcome == .failure) result.outcome.failure.err else null;
}

test "a lookup at the next server closes the connect of its last try, and the next server answers it" {
    // One slot. The first server's connect hangs past the lookup's wait, and the lookup moves on.
    // The loop still holds that slot's connect (the stream's rule 10). No lookup is on that
    // connection and no slot is pending, so the lookup closes it, and waits for the slot. The
    // cancelled connect's event frees the slot, and the second server answers (rule 12).
    var rig: Rig = .{};
    try rig.init(120, hung_first, one_pass);
    try testing.expectEqual(@as(usize, 1), rig.engine.connections.len);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(result));
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    // The slot holds the second server's connection. The first server is charged with the wait
    // that ran out, and the second with nothing. The answer came before a second wait had passed.
    try testing.expectEqual(@as(u8, 1), rig.engine.connections[0].server);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    try testing.expect(rig.loop.now() < 2 * fixtures.slow_connect_timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup whose admission the loop refuses waits for the next drive, which admits it" {
    // As above, but the loop refuses each submission when the cancelled connect's event comes. The
    // drive's end finds the slot free and its connect refused, so the lookup waits on. A lookup
    // that starts later drives the engine. That drive's end admits the first lookup to the
    // connection that the second opened (the stream's rule 12).
    var rig: Rig = .{};
    try rig.init(122, hung_first, one_pass);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try until_waiting(&rig);
    rig.loop.refuse_submissions = true;
    _ = try rig.step(fixtures.wait_ns);
    rig.loop.refuse_submissions = false;
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .closed and !connection.borrowed());
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    try testing.expectEqual(@as(u16, 2), connection.users);
    // `until_result` takes each result, and the last `take` frees the slot of the second.
    for (0..2) |_| try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    try testing.expect(rig.loop.now() < 2 * fixtures.slow_connect_timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup whose admission the loop refuses until its deadline moves on there, and admits nobody later" {
    // As above, and the loop refuses each submission until the lookup's deadline. The lookup moves
    // on at its deadline, and ends in Timeout: no server answered or refused it. Then a later
    // lookup waits for nothing (the stream's rule 12).
    var rig: Rig = .{};
    try rig.init(123, hung_first, one_pass);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try until_waiting(&rig);
    rig.loop.refuse_submissions = true;
    const result = try rig.until_result();
    rig.loop.refuse_submissions = false;
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(result));
    try testing.expectEqual(@as(?cocuyo.Cause, null), result.outcome.failure.cause);
    try testing.expect(rig.loop.now() <= 2 * fixtures.slow_connect_timeout_ns);
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    // A wait for a slot that runs out counts against the server as a connect that runs out does
    // (docs/design.md §16 decision 46).
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(1));
    _ = rig.engine.take(rig.loop.now());
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup at the next server leaves alone a connect that a lookup is on, and is told at once" {
    // One slot, and the first server's connect hangs. A second lookup joins that connection while
    // it connects. The first lookup's wait runs out, and it moves to the second server. The slot
    // holds a lookup, and no slot is pending. So the first lookup is told at once that its
    // connection failed (the stream's rules 1 and 12).
    var rig: Rig = .{};
    try rig.init(124, hung_first, one_pass);
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.step(fixtures.slow_connect_timeout_ns / 2);
    const second = try rig.engine.start(question("two.example."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    try testing.expectEqual(@as(u16, 2), connection.users);
    const result = try rig.until_result();
    try testing.expectEqual(first, result.handle);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), failure_of(result));
    // No slot was free, and no server took part (docs/design.md §5, The cause of a failure).
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = .local } }), result.outcome.failure.cause);
    // The second lookup is still on the connection, whose connect is still in flight.
    try testing.expectEqual(@as(?u8, 0), rig.engine.tcp_connection[second.index]);
    try testing.expect(connection.state == .connecting and connection.server == 0);
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    _ = rig.engine.take(rig.loop.now());
    // Its wait runs out in turn. No lookup is on the connection then, so it closes the connect,
    // and the second server answers it.
    const next = try rig.until_result();
    try testing.expectEqual(second, next.handle);
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(next));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Two connection slots over the same two servers.
const TwoSlots = sim_test.RigOf(io.Resolver(.{
    .lookups = fixtures.lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.tcp_slots_pair,
}));

test "a lookup that waits while a slot is pending leaves alone a connect that no lookup is on" {
    // Two slots, and each server's connect hangs. One lookup asks each server in turn, and leaves a
    // connect in flight in each slot. The idle close closes the older one, and the loop holds that
    // slot until the connect's event. A lookup to that server waits for the slot. It does not close
    // the other connect, which no lookup is on either (the stream's rule 12).
    var rig: TwoSlots = .{};
    const hung: rotor.server.Script = .{ .connect_delay_ns = fixtures.hung_connect_ns };
    try rig.init(125, .{ hung, hung }, one_pass);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    // The first slot has been idle since the first wait ran out, and the second since the second
    // did. Half a wait past the idle close of the first, the second is not idle long enough.
    _ = try rig.step(rig.engine.tcp_idle_ns - fixtures.slow_connect_timeout_ns / 2);
    rig.engine.drive(rig.loop.now());
    try testing.expect(rig.engine.connections[0].state == .closed and rig.engine.connections[0].borrowed());
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    const other = &rig.engine.connections[1];
    try testing.expect(other.state == .connecting and other.server == 1 and other.borrowed());
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// One server and one connection slot over the twin's TLS, the least that TLS rule 6 allows.
const TlsEngine = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 1,
    .tls = rotor.tls.Session,
});
const TlsOneSlot = sim_test.RigOfServers(TlsEngine, 1);

/// The state of a connection slot of `TlsOneSlot`.
const State = @typeInfo(@FieldType(TlsEngine, "connections")).array.child.State;

/// A TLS rig of one server that speaks as `script` says, under a wait long enough for any step.
fn start_tls(rig: *TlsOneSlot, seed: u64, script: rotor.server.Script) !void {
    try tls_test.encrypt(rig);
    try rig.init(seed, .{script}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
}

/// Moves the twin's clock to `at`, each event before it applied, and drives the engine there, as
/// the next event of any kind would.
fn drive_at(rig: anytype, at: u64) !void {
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.loop.now() >= at) break;
        _ = try rig.step(at - rig.loop.now());
    }
    try testing.expectEqual(at, rig.loop.now());
    rig.engine.drive(rig.loop.now());
}

/// The peer of the first slot's connection stops reading, and keeps its side open.
fn stall_first(rig: anytype) void {
    rig.loop.network().stall(rig.engine.connections[0].descriptor.?);
}

/// The first slot's connection closes, and its last send is in flight. At the drive just before
/// the idle close's wait has passed since `since`, it still closes. At the first drive after it,
/// the slot frees at the cancel's event (docs/design.md §16 decision 49).
fn expect_shut_after_wait(rig: anytype, since: u64) !void {
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .closing and connection.sending);
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    try drive_at(rig, since + rig.engine.tcp_idle_ns - fixtures.half_step_ns);
    try testing.expectEqual(State.closing, connection.state);
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    try drive_at(rig, since + rig.engine.tcp_idle_ns);
    try expect_freed_at_cancel(rig);
}

/// The first slot is closed, and its records buffer is lent until the cancel's event. That event
/// frees the slot, and the drive's end admits the lookup that waits (docs/design.md §16 decision
/// 49).
fn expect_freed_at_cancel(rig: anytype) !void {
    const connection = &rig.engine.connections[0];
    try testing.expectEqual(State.closed, connection.state);
    try testing.expect(connection.borrowed());
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expectEqual(@as(?u16, null), connection.records_send);
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    try testing.expectEqual(State.connecting, connection.state);
}

/// One server and one slot over TLS. A lookup is answered, and its connection goes idle. The peer
/// stops reading. The idle close makes the session's `close_notify`, whose send never ends (TLS
/// rule 5).
fn stall_close_notify(rig: *TlsOneSlot, seed: u64) !void {
    try start_tls(rig, seed, .{});
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    stall_first(rig);
    try drive_at(rig, rig.loop.now() + fixtures.tcp_idle_jump_ns);
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .closing and connection.sending);
}

test "a second pass gets a slot whose alert never goes once the idle close's wait has passed" {
    // One server and one slot over TLS. The server refuses the handshake, and stops reading before
    // its refusal comes. So the alert's send takes nothing and never ends, and the connection stays
    // closing (TLS rules 4 and 5). The lookup's second pass waits for the slot (the stream's rule
    // 12). The wait counts from the instant the connection began to close, a step after its
    // connect.
    var rig: TlsOneSlot = .{};
    try start_tls(&rig, 126, .{ .tls = .{ .refuse = true }, .delay_ns_min = fixtures.slow_step_ns, .delay_ns_max = fixtures.slow_step_ns });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .handshaking and !connection.sending) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expect(connection.state == .handshaking and !connection.sending);
    stall_first(&rig);
    // The server refused the hello it read, and takes the next connection's handshake.
    rig.loop.network().scripts[0].tls.refuse = false;
    try until_waiting(&rig);
    const since = rig.loop.now();
    try expect_shut_after_wait(&rig, since);
    // The server answers the second pass on a new connection, before its deadline. It heard no
    // alert, since it had stopped reading.
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(result));
    try testing.expect(rig.loop.now() < since + rig.config.timeout_ns);
    try testing.expectEqual(@as(u32, 0), rig.loop.network().alerts_heard[0]);
    // A later lookup joins that connection, and the server answers it.
    _ = rig.engine.take(rig.loop.now());
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup gets a slot whose close_notify never goes once the idle close's wait has passed" {
    // A later lookup waits for the slot. The wait counts from the idle close's instant, and not
    // from the instant the connection went idle.
    var rig: TlsOneSlot = .{};
    try stall_close_notify(&rig, 127);
    const since = rig.loop.now();
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try expect_shut_after_wait(&rig, since);
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(result));
    try testing.expect(rig.loop.now() < since + rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a reinit cancels a close_notify that never goes, and a later lookup gets its slot" {
    // A reinit closes each connection, and keeps the mark of a send that reads the records buffer
    // (docs/design.md §16 decision 47). It cancels that send too. So the slot frees at the cancel's
    // event, and a later lookup that waits gets it (decision 49).
    var rig: TlsOneSlot = .{};
    try stall_close_notify(&rig, 128);
    try rig.engine.reinit(&rig.config, rig.cache_memory.slices(), 129, rig.loop.now());
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try expect_freed_at_cancel(&rig);
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a close of the engine cancels a close_notify that never goes, so the loop drains" {
    // `deinit` ends each operation of the engine, the send in flight among them. So the loop drains
    // before `close` (rotor decision 5, rule 7; docs/design.md §16 decision 49).
    var rig: TlsOneSlot = .{};
    try stall_close_notify(&rig, 130);
    rig.engine.deinit();
    try rig.loop.drain(&rig.events);
    try testing.expectEqual(@as(u32, 0), rig.loop.in_flight());
    rig.engine.close();
    rig.loop.deinit();
}

test "a resumed handshake that fails while its hello never goes connects again in full at the cancel" {
    // One server and one slot over TLS. The opening resumes with the server's ticket. The peer
    // stops reading before the hello goes, so the hello's send never ends. A refusal that the peer
    // sent before then fails the resumed handshake. The connection waits to connect again in full
    // (TLS rule 8). The retry cancels the send, so the connection connects again at the cancel's
    // event (docs/design.md §16 decision 49).
    var rig: TlsOneSlot = .{};
    try start_tls(&rig, 131, .{ .delay_ns_min = fixtures.slow_step_ns, .delay_ns_max = fixtures.slow_step_ns });
    rig.engine.tls_tickets[0] = .{ .ticket = .{}, .since_ns = rig.loop.now() };
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.tls.ticket != null);
    // The twin opens the stream as it takes the connect, whose event comes a step later.
    _ = try rig.step(fixtures.half_step_ns);
    try testing.expectEqual(State.connecting, connection.state);
    stall_first(&rig);
    _ = try rig.step(fixtures.slow_step_ns);
    try testing.expect(connection.state == .handshaking and connection.sending);
    var refusal: [rotor.constants.tls_record_header_bytes + 1]u8 = undefined;
    const refusal_len = rotor.tls.write_step(.refused, &refusal);
    try testing.expect(rig.loop.network().write_stream(connection.descriptor.?, refusal[0..refusal_len], rig.loop.now()));
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(connection.state == .reopening and connection.borrowed());
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expectEqual(@as(?u16, null), connection.records_send);
    try testing.expect(connection.state == .connecting and connection.tls.ticket == null);
    // The full handshake goes to a new stream, and the server answers. The declined ticket counts
    // no failure.
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
