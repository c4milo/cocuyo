//! A lookup's wait for a connection slot in the clear, on the twin (docs/design.md §19 step 13,
//! the stream's rule 12; `io_tcp_wait.zig`). The connect of a lookup's last try hangs, and no
//! lookup is on its connection any more. The lookup at the next server closes that connection,
//! and waits for the cancelled connect's event. The tests over TLS are in
//! `io_tls_failing_test.zig`. Split from `io_tcp_test.zig` by the file-length rule. The rig is the
//! one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
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
    try testing.expectEqual(@as(?cocuyo.Cause, .connect), result.outcome.failure.cause);
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
