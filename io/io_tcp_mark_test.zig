//! A connection that no lookup may join, on the twin (docs/design.md §16 decision 54;
//! `io_tcp_mark.zig`). The peer stops reading before the first lookup's query goes, so that send
//! never ends. A second lookup joins the connection later. At the first lookup's deadline it
//! leaves during its query's send, and the second stays, so the drive marks the connection. No
//! lookup joins it again. A new lookup to the same server opens a new connection, or waits for
//! the marked connection's slot. The last leave ends the marked connection at once. The rigs are
//! the ones `io_sim_test.zig`, `io_tls_test.zig` and `io_tcp_wait_test.zig` build.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const wait_test = @import("io_tcp_wait_test.zig");
const question = sim_test.question;
const failure_of = wait_test.failure_of;
const drive_at = wait_test.drive_at;

/// One server, and an engine with the one connection slot of the default in the clear.
const OneSlot = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.lookups,
    .group_buffers = fixtures.group_buffers,
}), 1);

/// One server, and an engine with two connection slots in the clear.
const TwoSlots = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.tcp_slots_pair,
}), 1);

/// One server over the twin's TLS, and an engine with two connection slots.
const TlsTwoSlots = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.tcp_slots_pair,
    .tls = rotor.tls.Session,
}), 1);

/// Every query on a stream, and one pass over the one server.
const one_pass: cocuyo.Config = .{
    .servers = &.{},
    .use_tcp = true,
    .attempts = 1,
    .failover_retry_chance = 0,
};

/// The two lookups of a marked connection: the one that left during its query's send, and the one
/// that stays.
const Marked = struct { left: cocuyo.Handle, stays: cocuyo.Handle };

/// One pass, under a wait long enough for a handshake whose server takes a second each flight.
const long_pass: cocuyo.Config = .{
    .servers = &.{},
    .use_tcp = true,
    .attempts = 1,
    .timeout_ns = fixtures.stream_timeout_ns,
    .timeout_ns_max = fixtures.stream_timeout_ns,
    .failover_retry_chance = 0,
};

/// Starts the rig over its one server, which speaks as `script` says, under `config`. Over TLS the
/// server is known by a name.
fn begin(rig: anytype, seed: u64, script: rotor.server.Script, config: cocuyo.Config) !void {
    const tls = comptime @TypeOf(rig.engine).Tls.enabled;
    if (tls) try tls_test.encrypt(rig);
    try rig.init(seed, .{script}, config);
    if (tls) rig.use_test_contexts();
}

/// Stops the peer of the first slot's connection from reading before the query of `handle` goes.
/// In the clear the peer stops while the connection connects. Over TLS it stops once the
/// handshake has ended, so the session's records go and the query's send never ends.
fn stall_query(rig: anytype, handle: cocuyo.Handle) !void {
    const connection = &rig.engine.connections[0];
    const tls = comptime @TypeOf(rig.engine).Tls.enabled;
    const stage: @TypeOf(connection.state) = if (tls) .up else .connecting;
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == stage) break;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    wait_test.stall_first(rig);
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.sending and connection.queue.first().?.is_query()) break;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    try testing.expect(connection.state == .up and connection.queue.first().?.slot == handle.index);
    try testing.expectEqual(cocuyo.resolver.State.tcp_ready, rig.engine.resolver.lookup_of(handle).state);
}

/// The first lookup's query's send never ends. A second later a second lookup joins the
/// connection, and its query waits behind. At the first deadline the first lookup ends in
/// `Timeout`, and its result waits to be taken. It left during its query's send, and the second
/// stays (docs/design.md §16 decision 54).
fn mark_first(rig: anytype) !Marked {
    const left = try rig.engine.start(question("example.com."), rig.loop.now());
    try stall_query(rig, left);
    const deadline = rig.engine.resolver.lookup_of(left).deadline_ns;
    // A second, half the default wait, is before the deadline (`timeout_ns_default`).
    try testing.expect(rig.loop.now() + fixtures.slow_step_ns < deadline);
    try drive_at(rig, rig.loop.now() + fixtures.slow_step_ns);
    const stays = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(?u8, 0), rig.engine.tcp_connection[stays.index]);
    try drive_at(rig, deadline);
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .up and connection.users == 1 and connection.sending);
    try testing.expect(rig.engine.send_in_flight[left.index]);
    try testing.expectEqual(cocuyo.resolver.State.tcp_ready, rig.engine.resolver.lookup_of(stays).state);
    return .{ .left = left, .stays = stays };
}

/// The next result is the first lookup's, which ran out at its deadline.
fn expect_left_timed_out(rig: anytype, marked: Marked) !void {
    const result = try rig.until_result();
    try testing.expectEqual(marked.left.index, result.handle.index);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(result));
}

/// A new lookup to the server opens a new connection in the free slot, and the server answers it
/// there before the deadline of the lookup that stays. That one then ends in `Timeout`, and its
/// leave shuts the marked connection (docs/design.md §16 decisions 53 and 54).
fn expect_new_connection(rig: anytype) !void {
    const marked = try mark_first(rig);
    const new = try rig.engine.start(question("example.org."), rig.loop.now());
    try expect_left_timed_out(rig, marked);
    const answered = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(answered));
    try testing.expectEqual(new.index, answered.handle.index);
    try testing.expect(rig.loop.now() < rig.engine.resolver.lookup_of(marked.stays).deadline_ns);
    const other = &rig.engine.connections[1];
    try testing.expect(other.state == .up and other.server == 0);
    const last = try rig.until_result();
    try testing.expectEqual(marked.stays.index, last.handle.index);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(last));
    try testing.expect(rig.engine.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
}

/// A new lookup to the server finds no free slot, and waits for the marked connection's slot. The
/// lookup that stays ends in `Timeout` at its deadline, and its leave shuts the connection. The
/// slot frees, at once in the clear and at the cancel's event over TLS. The drive's end admits the
/// new lookup, and the server answers it on a new connection (docs/design.md §16 decision 54).
fn expect_wait_for_slot(rig: anytype) !void {
    const marked = try mark_first(rig);
    const new = try rig.engine.start(question("example.org."), rig.loop.now());
    try expect_left_timed_out(rig, marked);
    const last = try rig.until_result();
    try testing.expectEqual(marked.stays.index, last.handle.index);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.Timeout), failure_of(last));
    const answered = try rig.until_result();
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(answered));
    try testing.expectEqual(new.index, answered.handle.index);
    try testing.expect(rig.engine.connections[0].state == .up and rig.engine.connections[0].server == 0);
    _ = rig.engine.take(rig.loop.now());
}

test "a lookup leaves during its send, another stays, and a new lookup opens a new connection" {
    var rig: TwoSlots = .{};
    try begin(&rig, 150, .{}, one_pass);
    try expect_new_connection(&rig);
    try rig.deinit();
}

test "over TLS a new lookup opens a new connection beside the marked one" {
    // TLS rule 6: each server has at most one connection that a lookup may join, and the marked
    // one is not. So the server has two connections for a time (docs/design.md §16 decision 54).
    var rig: TlsTwoSlots = .{};
    try begin(&rig, 151, .{}, one_pass);
    try expect_new_connection(&rig);
    try rig.deinit();
}

test "with each slot taken, a new lookup waits for the marked connection's slot" {
    // One slot, which the marked connection holds. No slot is free or pending, and no connect
    // that no lookup is on can be closed. So the lookup waits for that slot (decision 54).
    var rig: OneSlot = .{};
    try begin(&rig, 152, .{}, one_pass);
    try expect_wait_for_slot(&rig);
    try rig.deinit();
}

test "over TLS with each slot taken, a new lookup waits for the marked connection's slot" {
    // One server and one slot, the least that TLS rule 6 allows. The shut at the last leave makes
    // no `close_notify`, and the slot is pending until the cancel's event (decision 53).
    var rig: wait_test.TlsOneSlot = .{};
    try begin(&rig, 153, .{}, one_pass);
    try expect_wait_for_slot(&rig);
    try rig.deinit();
}

test "a lookup that leaves while another lookup's query is in flight marks nothing" {
    // The first lookup's query's send never ends, and the second's query waits behind it. The
    // caller cancels the second. Its query has not started, so it leaves the queue, and its buffer
    // comes back at once (the stream's rule 9). The first lookup stays, and its own deadline
    // bounds its send. So the connection is not marked, and a new lookup joins it
    // (docs/design.md §16 decision 54).
    var rig: TwoSlots = .{};
    try begin(&rig, 156, .{}, one_pass);
    const first = try rig.engine.start(question("example.com."), rig.loop.now());
    try stall_query(&rig, first);
    const second = try rig.engine.start(question("example.net."), rig.loop.now());
    try testing.expectEqual(@as(?u8, 0), rig.engine.tcp_connection[second.index]);
    rig.engine.cancel(second, rig.loop.now());
    try testing.expect(!rig.engine.send_in_flight[second.index]);
    const joins = try rig.engine.start(question("example.org."), rig.loop.now());
    try testing.expectEqual(@as(?u8, 0), rig.engine.tcp_connection[joins.index]);
    try testing.expectEqual(@as(u16, 2), rig.engine.connections[0].users);
    try testing.expect(rig.engine.connections[1].state == .closed);
    rig.engine.cancel(first, rig.loop.now());
    rig.engine.cancel(joins, rig.loop.now());
    for (0..3) |_| _ = try rig.until_result();
    try rig.deinit();
}

/// One event of the loop, applied: a step that delivers no more than that.
fn step_one(rig: anytype) !void {
    const count = try sim_test.tick_for(&rig.loop, rig.events[0..1], fixtures.wait_ns);
    if (count == 1) _ = rig.engine.apply(rig.events[0], rig.loop.now());
}

/// The server answers a second after each query.
const slow_answers: rotor.server.Script = .{ .delay_ns_min = fixtures.slow_step_ns, .delay_ns_max = fixtures.slow_step_ns };

/// Two lookups join the connection while it connects, and the first one's query goes whole. The
/// caller cancels the second while its query's send is in flight, and the first stays for its
/// answer. So the drive marks the connection. The second's send then ends, and the server answers
/// the first. Its leave is the last, with no query's send in flight. The connection is marked, so
/// the leave ends it at once, with no wait for the idle close (docs/design.md §16 decision 54).
/// Returns the connection.
fn answer_after_mark(rig: anytype) !*@TypeOf(rig.engine.connections[0]) {
    const stays = try rig.engine.start(question("example.com."), rig.loop.now());
    const left = try rig.engine.start(question("example.net."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.sending and connection.queue.first().?.slot == left.index) break;
        try step_one(rig);
    }
    try testing.expect(connection.sending and connection.queue.first().?.slot == left.index);
    rig.engine.cancel(left, rig.loop.now());
    try testing.expect(connection.state == .up and connection.users == 1 and connection.sending);
    const canceled = try rig.until_result();
    try testing.expectEqual(left.index, canceled.handle.index);
    const answered = try rig.until_result();
    try testing.expectEqual(stays.index, answered.handle.index);
    try testing.expectEqual(@as(?cocuyo.Error, null), failure_of(answered));
    try testing.expect(!rig.engine.send_in_flight[left.index]);
    return connection;
}

test "the last leave of a marked connection whose send ended shuts it at once" {
    var rig: OneSlot = .{};
    try begin(&rig, 154, slow_answers, long_pass);
    const connection = try answer_after_mark(&rig);
    try testing.expect(connection.state == .closed and !connection.borrowed());
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "over TLS the last leave of a marked connection whose send ended says close_notify at once" {
    // The peer reads, so the session says `close_notify` before the connection closes (RFC 9846
    // §6.1). It closes once that has gone (§21, TLS rule 5).
    var rig: wait_test.TlsOneSlot = .{};
    try begin(&rig, 155, slow_answers, long_pass);
    const connection = try answer_after_mark(&rig);
    try testing.expect(connection.state == .closing and connection.users == 0);
    const notify = rotor.constants.tls_close_notify;
    const sealed = connection.tls.out[0..connection.tls.out_tail];
    try testing.expectEqualSlices(u8, &notify, sealed[sealed.len - notify.len ..]);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(connection.state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
