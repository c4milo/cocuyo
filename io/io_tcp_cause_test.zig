//! The cause that each failure of a stream gives a lookup, on the twin (docs/design.md §5, The
//! cause of a failure). Before the lookup hears that its connection is up, a connect refused is
//! `connect`. No slot that is free or frees with no lookup leaving it, and an engine with no TCP
//! connection, are `local`. After it, a failure is `closed`: a reset, the peer's close, or a send
//! that fails or that the loop refuses. Each cause names the server that gave it. The causes of a
//! TLS connection are in `io_tls_cause_test.zig`. Split from `io_tcp_test.zig` by the file-length
//! rule. The rig is the one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const tcp = @import("io_tcp.zig");
const queue_module = @import("io_tcp_queue.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;
const Streamless = @import("io_tcp_test.zig").Streamless;

/// The rig's engine over one scripted server, so that the first failure is the last one.
const OneServer = sim_test.RigOfServers(@FieldType(Rig, "engine"), 1);

/// Requires the next result to be `AllServersFailed`, its cause `reason` from `server`, and takes
/// it.
fn expect_all_failed(rig: anytype, server: u8, reason: cocuyo.Reason) !void {
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = server, .what = .{ .reason = reason } }), result.outcome.failure.cause);
    _ = rig.engine.take(rig.loop.now());
}

test "a lookup every server refused a connection ends in AllServersFailed, its cause the connect" {
    var rig: Rig = .{};
    try rig.init(116, .{ .{ .tcp = false }, .{ .tcp = false } }, .{ .servers = &.{}, .use_tcp = true, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    // The connection never came up.
    try expect_all_failed(&rig, 1, .connect);
    try rig.deinit();
}

test "a lookup whose every stream failed once up ends in AllServersFailed, its cause closed" {
    var rig: Rig = .{};
    try rig.init(118, .{ .{}, .{} }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    for (0..fixtures.servers) |server| {
        // The query is on its way out on the server's connection, which is up, and the peer
        // resets it.
        const at = try until_up(&rig, @intCast(server));
        const receive = tcp.user_data_of(&rig.engine, .tcp_receive, at);
        _ = rig.engine.apply(rotor.Event.failure(receive, .connection_reset), rig.loop.now());
    }
    try expect_all_failed(&rig, 1, .closed);
    try rig.deinit();
}

/// Steps the loop until a connection to `server` is up, and returns its slot.
fn until_up(rig: anytype, server: u8) !u8 {
    for (0..fixtures.until_rounds_max) |_| {
        if (up_to(rig, server)) |at| return at;
        _ = try rig.step(fixtures.wait_ns);
    }
    return error.TestUnexpectedResult;
}

/// The slot of the connection to `server` that is up, if one is.
fn up_to(rig: anytype, server: u8) ?u8 {
    for (rig.engine.connections, 0..) |connection, at| {
        if (connection.server == server and connection.state == .up) return @intCast(at);
    }
    return null;
}

test "a query send that fails on a connection that is up gives closed as the cause" {
    // The engine fails the connection, and does not report a failed send. A failed send is
    // silence, and this server took the connection (docs/design.md §5, The cause of a failure).
    var rig: OneServer = .{};
    try rig.init(117, .{.{}}, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    // The connect ends, the lookup hears that the connection is up, and its query goes out.
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].sending);
    // The twin's sends do not fail, so the query's is made to.
    const count = try sim_test.tick_for(&rig.loop, &rig.events, fixtures.wait_ns);
    const sent = @TypeOf(rig.engine).user_data(.tcp_send, handle.index);
    var failed = false;
    for (rig.events[0..count]) |*event| {
        if (event.user_data != sent) continue;
        event.* = rotor.Event.failure(sent, .connection_reset);
        failed = true;
    }
    try testing.expect(failed);
    for (rig.events[0..count]) |event| _ = rig.engine.apply(event, rig.loop.now());
    try expect_all_failed(&rig, 0, .closed);
    try rig.deinit();
}

test "a lookup that finds each slot held by a lookup fails over at once, its cause local" {
    // One slot, and two lookups on the first server's connection, which drops their queries. The
    // first whose wait runs out moves to the second server while the other is still on the
    // connection. No slot is free, and none frees with no lookup leaving it. So nothing reaches the
    // second server for that lookup (docs/design.md §19 step 13, the stream's rules 1 and 12).
    var rig: Rig = .{};
    try rig.init(119, .{ .{ .drop_per_256 = fixtures.always }, .{} }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1, .failover_retry_chance = 0 });
    try testing.expectEqual(@as(usize, 1), rig.engine.connections.len);
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(first, result.handle);
    const failure: ?cocuyo.Error = if (result.outcome == .failure) result.outcome.failure.err else null;
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), failure);
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = .local } }), result.outcome.failure.cause);
    _ = rig.engine.take(rig.loop.now());
    // The other lookup left the connection next, and the slot went to its connection to the
    // second server, which answers it.
    try testing.expect((try rig.until_result()).outcome == .answer);
    try testing.expectEqual(@as(u8, 1), rig.engine.connections[0].server);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an engine with no TCP connection fails each stream that a lookup asks for, its cause local" {
    // Each server truncates, and so each asks the lookup to ask again over a stream that an
    // engine of none cannot give.
    var rig: sim_test.RigOf(Streamless) = .{};
    const truncating: rotor.server.Script = .{ .truncate_per_256 = fixtures.always };
    try rig.init(120, .{ truncating, truncating }, .{ .servers = &.{}, .attempts = 1, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try expect_all_failed(&rig, 1, .local);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(1));
    try rig.deinit();
}

test "a lookup whose every stream the peer closed once up ends in AllServersFailed, its cause closed" {
    var rig: Rig = .{};
    try rig.init(121, .{ .{}, .{} }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    for (0..fixtures.servers) |server| {
        // Zero octets is the peer closing its side of a connection that is up.
        const at = try until_up(&rig, @intCast(server));
        const receive = tcp.user_data_of(&rig.engine, .tcp_receive, at);
        _ = rig.engine.apply(rotor.Event.success(receive, 0), rig.loop.now());
    }
    try expect_all_failed(&rig, 1, .closed);
    try rig.deinit();
}

test "a query's send that the loop refuses on a connection that is up gives closed as the cause" {
    // The connect ends, and the loop refuses what the connection asks of it then: its receive and
    // the query's send. The lookup heard that the connection was up, so the reason is `closed`
    // though no server took part (docs/design.md §5, The cause of a failure).
    var rig: OneServer = .{};
    try rig.init(122, .{.{}}, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    var connected = false;
    for (0..fixtures.until_rounds_max) |_| {
        const connect = tcp.user_data_of(&rig.engine, .tcp_connect, 0);
        const count = try sim_test.tick_for(&rig.loop, &rig.events, fixtures.wait_ns);
        for (rig.events[0..count]) |event| connected = connected or event.user_data == connect;
        rig.loop.refuse_submissions = connected;
        for (rig.events[0..count]) |event| _ = rig.engine.apply(event, rig.loop.now());
        rig.loop.refuse_submissions = false;
        if (connected) break;
    }
    try testing.expect(connected);
    try expect_all_failed(&rig, 0, .closed);
    try rig.deinit();
}

test "a lookup ready to send on a connection that it is no longer on is told closed" {
    // No drive leaves a lookup that heard its connection was up off that connection, so the slot
    // is cleared by hand (the stream's rule 3). The lookup heard that it was up, so the reason is
    // `closed` (docs/design.md §5, The cause of a failure).
    var rig: OneServer = .{};
    try rig.init(123, .{.{ .drop_per_256 = fixtures.always }}, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const at = try until_up(&rig, 0);
    try testing.expect(rig.engine.resolver.lookup_of(handle).is_on_stream());
    rig.engine.tcp_connection[handle.index] = null;
    rig.engine.connections[at].users -= 1;
    queue_module.send(&rig.engine, handle.index, "query", rig.loop.now());
    try expect_all_failed(&rig, 0, .closed);
    try rig.deinit();
}
