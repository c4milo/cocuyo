//! The engine at `servers_max` scripted servers on the twin (docs/design.md §19 step 13): the
//! first seven are down, and the eighth answers over UDP, over TCP and over TLS. The per-server
//! arrays and the receive index reach their last server only here. One drive also takes a lookup
//! through every try at eight servers, the most polls a run gives it. Split from
//! `io_sim_test.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

const servers_max = cocuyo.limits.servers_max;
const last: u8 = servers_max - 1;

/// Every server down but the last.
const scripts = blk: {
    var all: [servers_max]rotor.server.Script = @splat(.{ .down = true });
    all[last] = .{};
    break :blk all;
};

/// A lookup on `rig`, whose servers are named as `named` says: the last server answers it, after
/// each server before it failed it once.
fn expect_last_answers(rig: anytype, seed: u64, named: cocuyo.Config) !void {
    try rig.init(seed, scripts, named);
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    for (0..last) |server| try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(@intCast(server)));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(last));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// One try at each server, and a wait short enough that seven of them pass quickly.
const one_try: cocuyo.Config = .{ .servers = &.{}, .attempts = 1, .timeout_ns = fixtures.down_server_timeout_ns, .failover_retry_chance = 0 };

test "the last of eight servers answers over UDP, after the seven before it fail" {
    var rig: sim_test.RigOfServers(io.Resolver(.{ .lookups = fixtures.small_lookups, .group_buffers = fixtures.group_buffers }), servers_max) = .{};
    try expect_last_answers(&rig, 111, one_try);
}

test "the last of eight servers answers over TCP, after the seven before it fail" {
    var rig: sim_test.RigOfServers(io.Resolver(.{ .lookups = fixtures.small_lookups, .group_buffers = fixtures.group_buffers }), servers_max) = .{};
    var over_tcp = one_try;
    over_tcp.use_tcp = true;
    try expect_last_answers(&rig, 112, over_tcp);
}

test "the last of eight servers answers over TLS, after the seven before it fail" {
    // A connection slot for each server (TLS rule 6).
    var rig: sim_test.RigOfServers(io.Resolver(.{
        .lookups = fixtures.small_lookups,
        .group_buffers = fixtures.group_buffers,
        .tcp_connections = servers_max,
        .tls = rotor.tls.Session,
    }), servers_max) = .{};
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.tls = tls;
    var over_tls = one_try;
    over_tls.timeout_ns = fixtures.stream_timeout_ns;
    over_tls.timeout_ns_max = fixtures.stream_timeout_ns;
    try expect_last_answers(&rig, 113, over_tls);
}

/// The connections that are up.
fn up_count(rig: anytype) usize {
    var up: usize = 0;
    for (rig.engine.connections) |connection| {
        if (connection.state == .up) up += 1;
    }
    return up;
}

test "one drive takes a lookup through every try at eight servers when the loop refuses each send" {
    // `drive_polls_per_lookup_max` bounds the polls of one drive (the stream's rule 8). A try on a
    // connection that is up costs two polls: one for the connection, and one for the send. The
    // refused send fails the connection. A later try at that server costs one poll, since no slot
    // is free for a new connection. So eight servers and five passes cost 8 × 2 + 8 × 4 + 1 = 49
    // polls. By a read of the drive, this is the most that a run gives one lookup, 32 under the
    // bound.
    var rig: sim_test.RigOfServers(io.Resolver(.{
        .lookups = 1,
        .group_buffers = fixtures.group_buffers,
        .tcp_connections = servers_max,
    }), servers_max) = .{};
    const answering: [servers_max]rotor.server.Script = @splat(.{});
    try rig.init(114, answering, .{
        .servers = &.{},
        .attempts = cocuyo.limits.attempts_max,
        .use_tcp = true,
        .rotate = true,
        .failover_retry_chance = 0,
    });
    // Each lookup starts at the server the rotation chooses. They run until a connection to each
    // server is up.
    var buffer: [fixtures.name_text_bytes]u8 = undefined;
    for (0..fixtures.until_rounds_max) |round| {
        if (up_count(&rig) == servers_max) break;
        const text = try std.fmt.bufPrint(&buffer, "w{d}.example.", .{round});
        _ = try rig.engine.start(question(text), rig.loop.now());
        try testing.expect((try rig.until_result()).outcome == .answer);
        _ = rig.engine.take(rig.loop.now());
    }
    try testing.expectEqual(@as(usize, servers_max), up_count(&rig));
    // The loop refuses each send now, so each try fails at once, in the drive that `start` runs.
    rig.loop.refuse_submissions = true;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = rig.engine.take(rig.loop.now()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    rig.loop.refuse_submissions = false;
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
