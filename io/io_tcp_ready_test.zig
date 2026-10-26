//! A query's send that never ends, on the twin (docs/design.md §5; §16 decisions 52 and 53). The
//! peer stops reading before the query goes, so the send takes nothing and never ends. A deadline
//! ends `tcp_ready`, so the lookup moves on at its deadline, and leaves its connection (§19 step
//! 13, the stream's rule 3). When no lookup stays, the drive shuts the connection at once. The shut
//! cancels the send (decision 49). The cancel's event gives the send buffer back, and over TLS it
//! frees the slot. A send of the session's own records holds no lookup's buffer, so the idle close
//! ends that connection as before. Split from `io_tcp_test.zig` by the file-length rule. The rigs
//! are the ones `io_sim_test.zig`, `io_tls_test.zig` and `io_tcp_wait_test.zig` build.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
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

/// One pass over the servers, by datagram first.
const datagram_pass: cocuyo.Config = .{
    .servers = &.{},
    .attempts = 1,
    .failover_retry_chance = 0,
};

/// Starts a lookup, and stops the peer of its connection from reading before the query goes. The
/// connection comes up, and the query's send never ends. The lookup is in `tcp_ready`.
fn stall_the_query(rig: anytype) !cocuyo.Handle {
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try stall_when_connecting(rig, handle);
    return handle;
}

/// Steps the rig until the first slot connects, and stops its peer from reading before the query
/// goes. The connection comes up, and the query's send never ends. The lookup is in `tcp_ready`.
fn stall_when_connecting(rig: anytype, handle: cocuyo.Handle) !void {
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .connecting) break;
        _ = try rig.step(fixtures.wait_ns);
    }
    rig.loop.network().stall(connection.descriptor.?);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(connection.state == .up and connection.sending);
    try testing.expectEqual(cocuyo.resolver.State.tcp_ready, rig.engine.resolver.lookup_of(handle).state);
}

test "a lookup whose query's send never ends moves on at its deadline, and the next server answers" {
    // One connection slot. At its deadline the lookup asks the second server. No lookup stays on
    // the first server's connection, and the query's send is in flight. So the drive shuts it, and
    // the shut cancels the send (docs/design.md §16 decision 53). The lookup opens the slot again.
    // The held query goes once the cancel gives the buffer back.
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

test "a send never ends, and the try at the next server goes once the leave shuts the connection" {
    // Two servers, a connection slot for each, and one pass. The peer of the first stops reading.
    // At the deadline the lookup asks the second server. No lookup stays on the first connection,
    // so the drive shuts it, and the shut cancels the send. In the clear that slot is free at once,
    // and the lookup opens it again. The cancel's event gives the send buffer back. So the query
    // goes when the second connection comes up, and the second server answers it and counts no
    // failure (docs/design.md §16 decision 53). Until 2026-10-25 the lookup took the other slot,
    // and its query was held until the idle close, after the second deadline.
    var rig: TwoSlots = .{};
    try rig.init(143, .{ .{}, .{} }, one_pass);
    const handle = try stall_the_query(&rig);
    const first_deadline = rig.engine.resolver.lookup_of(handle).deadline_ns;
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(result));
    try testing.expect(rig.loop.now() > first_deadline and rig.loop.now() < first_deadline + rig.config.timeout_ns);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    const second = &rig.engine.connections[0];
    try testing.expect(second.server == 1 and second.state == .up and !second.sending);
    try testing.expect(rig.engine.connections[1].state == .closed and !rig.engine.send_in_flight[handle.index]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a send never ends after TC=1, and the datagram at the next server goes at the cancel's event" {
    // Two servers and one pass, by datagram first. The first answers with TC=1, so the lookup asks
    // it on a stream (RFC 7766 §5), and its peer stops reading before the query goes. At the
    // deadline the lookup asks the second server by datagram, and leaves the connection, which the
    // drive shuts. The datagram is held for the send buffer (the stream's rule 6). It goes at the
    // cancel's event, with no drive and no timer, and the second server answers it
    // (docs/design.md §16 decision 53).
    var rig: Rig = .{};
    try rig.init(146, .{ .{ .truncate_per_256 = fixtures.always }, .{} }, datagram_pass);
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try stall_when_connecting(&rig, handle);
    const deadline = rig.engine.resolver.lookup_of(handle).deadline_ns;
    try drive_at(&rig, deadline);
    try testing.expectEqual(cocuyo.resolver.State.query_ready, rig.engine.resolver.lookup_of(handle).state);
    try testing.expect(rig.engine.held[handle.index] != null);
    const result = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(result));
    try testing.expect(rig.loop.now() < deadline + rig.config.timeout_ns);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    try testing.expect(rig.engine.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a send never ends, and a new lookup in the same table slot sends at the cancel's event" {
    // One server and one pass, by datagram first. The server answers with TC=1, and the peer of the
    // stream stops reading before the query goes. At the deadline the lookup fails in Timeout, and
    // leaves the connection, which the drive shuts. A new lookup takes the same table slot before
    // the cancel's event. Its datagram is held for the slot's send buffer, and goes at that event
    // (docs/design.md §16 decision 53). The server no longer truncates, and answers it.
    var rig: OneServer = .{};
    try rig.init(147, .{.{ .truncate_per_256 = fixtures.always }}, datagram_pass);
    const first = try rig.engine.start(question("example.com."), rig.loop.now());
    try stall_when_connecting(&rig, first);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(try rig.until_result()));
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(rig.engine.send_in_flight[first.index]);
    rig.loop.network().scripts[0].truncate_per_256 = 0;
    const second = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(first.index, second.index);
    try testing.expect(rig.engine.held[second.index] != null);
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    try testing.expect(rig.engine.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the other lookups on a connection whose send never ends keep their own deadlines" {
    // One server, one pass, and an answer a second after each query. The first lookup's query goes
    // whole. Then the peer stops reading, and two more lookups join the connection. The second's
    // query has started and never ends, and the third's waits in the queue. The first still gets
    // its answer. At their deadline the other two end in Timeout. The third's query leaves the
    // queue, and its buffer comes back at once (docs/design.md §16 decision 52). The last to leave
    // finds the second's send in flight, so the drive shuts the connection. The second's buffer
    // comes back at the cancel's event (decision 53).
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
    try testing.expect(connection.state == .closed and connection.queue.count == 0);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(!rig.engine.send_in_flight[started.index]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup whose query's send never ends fails at its deadline, and its leave shuts the connection" {
    // One server and one pass. The deadline counts a failure of the server, takes no sample and
    // keeps no cause, so the lookup ends in Timeout (docs/design.md §16 decision 52). No lookup
    // stays on the connection, and the query's send is in flight. So the drive shuts it at once,
    // with no wait for the idle close. The cancel's event gives the lookup's buffer back on the
    // next loop step (decision 53).
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
    try testing.expect(connection.state == .closed and !connection.sending);
    try testing.expect(rig.engine.send_in_flight[handle.index]);
    _ = rig.engine.take(rig.loop.now());
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
    // pass joins the same connection, since it is up (the stream's rule 1). The send in flight is
    // the session's records, and no query's, so no leave shuts the connection (docs/design.md §16
    // decision 53). Then the connection is idle. The idle close makes its `close_notify`, and shuts
    // it once it has closed for `tcp_idle_ns` (§21, TLS rule 5; decision 49). A later lookup waits
    // for the slot, and gets it at the cancel's event.
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
    try testing.expect(!connection.queue.first().?.is_query());
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

test "over TLS a query's send never ends, and the leave shuts the connection with no close_notify" {
    // Two servers over TLS, a slot for each, and one pass. The peer of the first stops reading once
    // the connection is up, so the query's send never ends. At the deadline the lookup moves to the
    // second server. No lookup stays on the first connection, so the drive shuts it at once. It
    // does not close with a `close_notify` (§21, TLS rule 5). Its slot frees at the cancel's event
    // (TLS rule 3), and the second server answers (docs/design.md §16 decision 53).
    var rig: tls_test.Rig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(145, .{ .{}, .{} }, one_pass);
    rig.use_test_contexts();
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .up) break;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    wait_test.stall_first(&rig);
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.sending and connection.queue.first().?.is_query()) break;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    const lookup = rig.engine.resolver.lookup_of(handle);
    try testing.expect(lookup.state == .tcp_ready and connection.queue.first().?.is_query());
    try drive_at(&rig, lookup.deadline_ns);
    // A `close_notify` would keep the connection closing behind the send that never ends, and the
    // peer does not read it. So the closed state shows that none went (§21, TLS rule 5).
    try testing.expect(connection.state == .closed and connection.borrowed());
    try testing.expectEqual(@as(?u8, 1), rig.engine.tcp_connection[handle.index]);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(!connection.borrowed() and !rig.engine.send_in_flight[handle.index]);
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(try rig.until_result()));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
