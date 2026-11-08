//! The engine's part of the tries a lookup keeps open, on the twin (docs/design.md §5, Tries kept
//! open; §16 decision 66): a lookup stays on the connection of its open try past the deadline
//! that moved it on, a socket that drains stays open for an open try's answer, and a connection
//! the engine closes itself tells its keepers `local`. The rig is the one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");

const io = @import("io.zig");
const tcp = @import("io_tcp.zig");
const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;

/// The rig's engine with a connection slot for each server, so that the second server's
/// connection does not need the first's slot.
const TwoSlots = sim_test.RigOf(io.Resolver(.{ .lookups = fixtures.lookups, .group_buffers = fixtures.group_buffers, .tcp_connections = fixtures.servers }));

/// A wait the late answer comes after, and the answer's delay past it: the first server answers in
/// a second and a half, and the lookup's wait for it is one second.
const wait_ns: u64 = 1_000_000_000;
const late_ns: u64 = 1_500_000_000;
/// The first server answers late; the second never answers, so only the late answer can end it.
/// The first's connect is quick, so its query goes out before the deadline. The second accepts a
/// connection and drops each query, so the lookup waits on it while the late answer comes.
const late: rotor.server.Script = .{ .delay_ns_min = late_ns, .delay_ns_max = late_ns, .connect_delay_ns = connect_ns };
const late_then_down: [fixtures.servers]rotor.server.Script = .{ late, .{ .down = true } };
const late_then_dropping: [fixtures.servers]rotor.server.Script = .{ late, .{ .drop_per_256 = fixtures.always } };
const connect_ns: u64 = 1_000_000;
/// An idle wait far shorter than the late answer's delay.
const idle_ns: u64 = 100_000_000;
/// An answer later than the first pass over both servers: the second pass waits on it.
const later_ns: u64 = 2_500_000_000;
/// A step far shorter than a wait, so the test sees the lookup in its second pass.
const step_ns: u64 = 10_000_000;

test "a lookup that moved on over TCP takes the late answer on the connection it stayed on" {
    var rig: TwoSlots = .{};
    try rig.init(141, late_then_dropping, .{ .servers = &.{}, .use_tcp = true, .timeout_ns = wait_ns, .attempts = 1, .failover_retry_chance = 0 });
    // An idle close that forgot the keeper would end the first connection before the answer.
    rig.engine.tcp_idle_ns = idle_ns;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    // Before decision 66 the lookup left the first connection at its deadline and timed out on
    // the second server.
    try testing.expect(result.outcome == .answer);
    try testing.expect(rig.loop.now() >= late_ns);
    _ = rig.engine.take(rig.loop.now());
    // The lookup left each connection at its end: none keeps it.
    for (rig.engine.connections[0..]) |*connection| try testing.expectEqual(@as(u16, 0), connection.keepers);
    try rig.deinit();
}

test "a socket that drains stays open for the late answer to an open datagram try" {
    var rig: Rig = .{};
    // One query a port: the first query's socket drains from the end of the drive that sent it.
    try rig.init(142, late_then_down, .{ .servers = &.{}, .timeout_ns = wait_ns, .attempts = 1, .failover_retry_chance = 0, .udp_queries_per_port = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    // Before decision 66 the draining socket closed once the lookup waited on the second server,
    // and the answer came to no socket.
    try testing.expect(result.outcome == .answer);
    try testing.expect(rig.loop.now() >= late_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection that only keepers hold makes room, and its keepers hear local, no server's failure" {
    // The rig's engine has one connection slot. The first server takes the query and drops it, so
    // its connection holds a keeper once the lookup moves on. The second needs the one slot: the
    // first closes, and its keeper hears `local`.
    var rig: Rig = .{};
    try rig.init(143, .{ .{ .drop_per_256 = fixtures.always, .connect_delay_ns = connect_ns }, .{} }, .{ .servers = &.{}, .use_tcp = true, .timeout_ns = wait_ns, .attempts = 1, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    // The first server failed once, at its deadline. The close made for room is no second failure.
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a later pass over TCP waits on its open query, and takes its answer there" {
    var rig: TwoSlots = .{};
    // The first server answers after the first pass: one wait on it, and one on the second, which
    // drops each query. The second pass waits on the first query, and sends none.
    const slow: rotor.server.Script = .{ .delay_ns_min = later_ns, .delay_ns_max = later_ns, .connect_delay_ns = connect_ns };
    try rig.init(144, .{ slow, .{ .drop_per_256 = fixtures.always } }, .{ .servers = &.{}, .use_tcp = true, .timeout_ns = wait_ns, .attempts = 2, .failover_retry_chance = 0 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.resolver.lookup_of(handle).round == 1) break;
        _ = try rig.step(step_ns);
    }
    const lookup = rig.engine.resolver.lookup_of(handle);
    try testing.expectEqual(@as(u8, 1), lookup.round);
    try testing.expectEqual(@TypeOf(lookup.state).awaiting_tcp, lookup.state);
    // The pass sent nothing, so the drive saw no event for it yet: the lookup is still a keeper of
    // the connection its query is on, which stays open for the answer (the stream's rule 3).
    const at = rig.engine.kept.conns[handle.index][lookup.server_slot()] orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@TypeOf(rig.engine.connections[at].state).up, rig.engine.connections[at].state);
    try testing.expectEqual(@as(u16, 1), rig.engine.connections[at].keepers);
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a keeper hears closed when its connection fails for a reason that fits a closing connection" {
    var rig: TwoSlots = .{};
    try rig.init(145, late_then_dropping, .{ .servers = &.{}, .use_tcp = true, .timeout_ns = wait_ns, .attempts = 1, .failover_retry_chance = 0 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    // The deadline moves the lookup to the second server: it keeps the first connection.
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.kept.conns[handle.index][0] != null) break;
        _ = try rig.step(step_ns);
    }
    const at = rig.engine.kept.conns[handle.index][0] orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // The connection closes, and a send of its own records fails then, as
    // `io_tcp_queue.on_records_event` fails it: `handshake`, the reason a closing one gives. The
    // keeper's try went out while it was up, so it hears `closed` (the owner's ruling of
    // 2026-11-08). Before, the lookup halted at its assertion that an earlier connection closed.
    rig.engine.connections[at].state = .closing;
    tcp.fail(&rig.engine, at, .handshake, rig.loop.now());
    const lookup = rig.engine.resolver.lookup_of(handle);
    try testing.expectEqual(@as(?u8, null), lookup.earlier_try_at(0, .stream));
    // Its connection's failure is its server's: one more failure, and the cause.
    try testing.expectEqual(@as(u8, 2), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .closed } }), lookup.cause.get());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
