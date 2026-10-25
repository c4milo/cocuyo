//! A query's send that never ends, on the twin (docs/design.md §5; §16 decision 52). The peer
//! stops reading before the query goes, so the send takes nothing and never ends. A deadline ends
//! `tcp_ready`, so the lookup moves on at its deadline, and leaves its connection (§19 step 13, the
//! stream's rule 3). The idle close then shuts the connection, and the shut cancels the send
//! (decision 49). Over TLS the slot frees at the cancel's event. Split from `io_tcp_test.zig` by
//! the file-length rule. The rigs are the ones `io_sim_test.zig` and `io_tcp_wait_test.zig` build.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const wait_test = @import("io_tcp_wait_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;
const failure_of = wait_test.failure_of;
const drive_at = wait_test.drive_at;
const State = wait_test.State;

/// One scripted server, and the engine of `Rig` over it.
const OneServer = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.lookups,
    .group_buffers = fixtures.group_buffers,
}), 1);

/// Two scripted servers, and an engine with a connection slot for each.
const TwoSlots = sim_test.RigOf(io.Resolver(.{
    .lookups = fixtures.lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.tcp_slots_pair,
}));

/// Every query over TCP, and one pass over the servers.
const one_pass: cocuyo.Config = .{
    .servers = &.{},
    .use_tcp = true,
    .attempts = 1,
    .failover_retry_chance = 0,
};

/// Starts a lookup, and stops the peer of its connection from reading before the query goes. The
/// connection comes up, and the query's send never ends. The lookup is in `tcp_ready`.
fn stall_the_query(rig: anytype) !cocuyo.Handle {
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    rig.loop.network().stall(connection.descriptor.?);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(connection.state == .up and connection.sending);
    try testing.expectEqual(cocuyo.resolver.State.tcp_ready, rig.engine.resolver.lookup_of(handle).state);
    return handle;
}

test "a lookup whose query's send never ends moves on at its deadline, and the next server answers" {
    // One connection slot. At its deadline the lookup asks the second server. The first server's
    // connection has no lookup on it then, so the lookup closes it to make room (the stream's rule
    // 1). That shut cancels the send. The held query goes once the cancel gives the buffer back.
    var rig: Rig = .{};
    try rig.init(140, .{ .{}, .{} }, one_pass);
    const handle = try stall_the_query(&rig);
    const deadline = rig.engine.resolver.lookup_of(handle).deadline_ns;
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(result));
    try testing.expect(rig.loop.now() >= deadline and rig.loop.now() < deadline + rig.config.timeout_ns);
    // The first server counts the try that ran out, and the second answered on the same slot.
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    try testing.expectEqual(@as(u8, 1), rig.engine.connections[0].server);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a send never ends, and the try at the next server waits for its buffer, as built" {
    // Two servers, a connection slot for each, and one pass. The peer of the first stops reading.
    // At the deadline the lookup asks the second server on a slot of its own, so nothing shuts the
    // first connection. The second connection comes up. The lookup's send buffer is still lent to
    // the send that never ends, so its query is held (the stream's rule 6). The idle close comes
    // after the second deadline. So the second server counts a failure that it did not earn, and
    // the lookup ends in Timeout. §17 question 70 asks the owner (docs/design.md §16 decision 52).
    var rig: TwoSlots = .{};
    try rig.init(143, .{ .{}, .{} }, one_pass);
    const handle = try stall_the_query(&rig);
    const first_deadline = rig.engine.resolver.lookup_of(handle).deadline_ns;
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(result));
    try testing.expect(rig.loop.now() > first_deadline and rig.loop.now() < first_deadline + rig.engine.tcp_idle_ns);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(1));
    const second = &rig.engine.connections[1];
    try testing.expect(second.server == 1 and second.state == .up and !second.sending);
    try testing.expect(rig.engine.connections[0].sending and rig.engine.send_in_flight[handle.index]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the other lookups on a connection whose send never ends keep their own deadlines" {
    // One server, one pass, and an answer a second after each query. The first lookup's query goes
    // whole. Then the peer stops reading, and two more lookups join the connection. The second's
    // query has started and never ends, and the third's waits in the queue. The first still gets
    // its answer. At their deadline the other two end in Timeout. The third's query leaves the
    // queue, and its buffer comes back at once. The second's query stays at the head, and its
    // buffer stays lent (docs/design.md §16 decision 52).
    var rig: OneServer = .{};
    try rig.init(144, .{.{ .delay_ns_min = fixtures.slow_step_ns, .delay_ns_max = fixtures.slow_step_ns }}, one_pass);
    const answered = try rig.engine.start(question("example.com."), rig.loop.now());
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.resolver.lookup_of(answered).state == .awaiting_tcp) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expectEqual(cocuyo.resolver.State.awaiting_tcp, rig.engine.resolver.lookup_of(answered).state);
    const connection = &rig.engine.connections[0];
    rig.loop.network().stall(connection.descriptor.?);
    const started = try rig.engine.start(question("example.net."), rig.loop.now());
    const queued = try rig.engine.start(question("example.org."), rig.loop.now());
    const first = try rig.until_result();
    try testing.expect(first.handle.index == answered.index and failure_of(first) == null);
    const deadline = rig.engine.resolver.lookup_of(started).deadline_ns;
    for (0..2) |_| {
        const result = try rig.until_result();
        try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(result));
    }
    try testing.expectEqual(deadline, rig.loop.now());
    try testing.expect(!rig.engine.send_in_flight[queued.index]);
    try testing.expect(rig.engine.send_in_flight[started.index]);
    try testing.expect(connection.users == 0 and connection.sending and connection.queue.count == 1);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup whose query's send never ends fails at its deadline, and the idle close cancels the send" {
    // One server and one pass. The deadline counts a failure of the server, takes no sample and
    // keeps no cause, so the lookup ends in Timeout (docs/design.md §16 decision 52). The
    // connection is idle from the deadline, with the send in flight. The idle close shuts it once
    // it has been idle for `tcp_idle_ns`, and the cancel's event gives the lookup's buffer back.
    var rig: OneServer = .{};
    try rig.init(141, .{.{}}, one_pass);
    const handle = try stall_the_query(&rig);
    const deadline = rig.engine.resolver.lookup_of(handle).deadline_ns;
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(result));
    try testing.expectEqual(@as(?cocuyo.Cause, null), result.outcome.failure.cause);
    try testing.expect(rig.loop.now() >= deadline and rig.loop.now() < deadline + fixtures.half_step_ns);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u64, 0), rig.engine.resolver.servers.samples(0));
    const connection = &rig.engine.connections[0];
    const since = connection.idle_since_ns;
    try testing.expect(connection.users == 0 and connection.state == .up and connection.sending);
    try testing.expect(rig.engine.send_in_flight[handle.index]);
    _ = rig.engine.take(rig.loop.now());
    try drive_at(&rig, since + rig.engine.tcp_idle_ns - fixtures.half_step_ns);
    try testing.expect(connection.state == .up and connection.sending);
    try drive_at(&rig, since + rig.engine.tcp_idle_ns);
    try testing.expect(connection.state == .closed and rig.engine.send_in_flight[handle.index]);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(!rig.engine.send_in_flight[handle.index]);
    // A later lookup opens the slot again, and the server answers it there.
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "over TLS a lookup whose send never ends frees the slot once the idle close has shut it" {
    // One server and one slot over TLS, and two passes. The peer stops reading during the
    // handshake, so the send at its end never ends. Each pass ends at its deadline. The second
    // pass joins the same connection, since it is up (the stream's rule 1). Then the connection is
    // idle. The idle close makes its `close_notify`, and shuts it once it has closed for
    // `tcp_idle_ns` (§21, TLS rule 5; docs/design.md §16 decision 49). A later lookup waits for
    // the slot, and gets it at the cancel's event.
    var rig: wait_test.TlsOneSlot = .{};
    try wait_test.start_tls(&rig, 142, .{ .delay_ns_min = fixtures.slow_step_ns, .delay_ns_max = fixtures.slow_step_ns });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .handshaking and !connection.sending) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    wait_test.stall_first(&rig);
    const lookup = rig.engine.resolver.lookup_of(handle);
    for (0..fixtures.until_rounds_max) |_| {
        if (lookup.state == .tcp_ready) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expect(lookup.state == .tcp_ready and connection.state == .up and connection.sending);
    const first_deadline = lookup.deadline_ns;
    for (0..fixtures.until_rounds_max) |_| {
        if (lookup.round == 1) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expectEqual(@as(u8, 1), lookup.round);
    try testing.expectEqual(first_deadline, rig.loop.now());
    try testing.expectEqual(@as(?u8, 0), rig.engine.tcp_connection[handle.index]);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(connection.users == 0 and connection.state == .up and connection.sending);
    try drive_at(&rig, connection.idle_since_ns + rig.engine.tcp_idle_ns);
    try testing.expectEqual(State.closing, connection.state);
    const since = rig.loop.now();
    _ = try rig.engine.start(question("example.net."), rig.loop.now());
    try wait_test.expect_shut_after_wait(&rig, since);
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
