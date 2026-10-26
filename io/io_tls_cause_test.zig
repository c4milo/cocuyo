//! The cause that each failure of a TLS connection gives a lookup, on the twin (docs/design.md §5,
//! The cause of a failure). While the handshake runs, a failure of the server or of the path is
//! `handshake`, and one that no server took part in is `local`. Each cause names the server that
//! gave it. The failures of a session are in `io_tls_failing_test.zig`. Split from
//! `io_tls_test.zig` by the file-length rule. The rig is the one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");
const tcp = @import("io_tcp.zig");
const constants = @import("constants.zig");
const limits = @import("limits.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const question = sim_test.question;

/// One server and one connection slot over the twin's TLS, so that the first failure is the last.
const OneServer = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 1,
    .tls = rotor.tls.Session,
}), 1);

/// Starts one lookup over TLS on one pass, and steps until its connection handshakes.
fn until_handshaking(rig: *OneServer, seed: u64, script: rotor.server.Script) !void {
    try tls_test.encrypt(rig);
    try rig.init(seed, .{script}, .{ .servers = &.{}, .attempts = 1, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.connections[0].state == .handshaking) return;
        _ = try rig.step(fixtures.wait_ns);
    }
    return error.NotHandshaking;
}

/// Requires the next result to be `AllServersFailed`, its cause `reason` from the one server.
fn expect_all_failed(rig: *OneServer, reason: cocuyo.Reason) !void {
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = reason } }), result.outcome.failure.cause);
    _ = rig.engine.take(rig.loop.now());
}

test "a peer that closes while the handshake runs gives the handshake as the cause" {
    var rig: OneServer = .{};
    try until_handshaking(&rig, 130, .{});
    // Zero octets is the peer closing its side.
    _ = rig.engine.apply(rotor.Event.success(tcp.user_data_of(&rig.engine, .tcp_receive, 0), 0), rig.loop.now());
    try expect_all_failed(&rig, .handshake);
    try rig.deinit();
}

test "a record longer than TLS allows while the handshake runs gives the handshake as the cause" {
    // "The length MUST NOT exceed 2^14 + 256 bytes" (RFC 9846 §5.2).
    var rig: OneServer = .{};
    try until_handshaking(&rig, 131, .{});
    var header: [constants.tls_record_header_bytes]u8 = .{ 22, 3, 3, 0, 0 };
    std.mem.writeInt(u16, header[constants.tls_record_length_at..][0..@sizeOf(u16)], limits.tls_record_body_bytes_max + 1, .big);
    io.tls.take(&rig.engine, 0, &header, rig.loop.now());
    try expect_all_failed(&rig, .handshake);
    try rig.deinit();
}

test "a send of the session's records that moves nothing while the handshake runs gives the handshake as the cause" {
    var rig: OneServer = .{};
    try until_handshaking(&rig, 132, .{});
    // The hello's send is in flight, and the twin's sends do not fail, so its end is made to move
    // nothing.
    const sent = tcp.user_data_of(&rig.engine, .tls_send, 0);
    var moved_nothing = false;
    for (0..fixtures.until_rounds_max) |_| {
        const count = try sim_test.tick_for(&rig.loop, &rig.events, fixtures.wait_ns);
        for (rig.events[0..count]) |*event| {
            if (event.user_data != sent) continue;
            event.* = rotor.Event.success(sent, 0);
            moved_nothing = true;
        }
        for (rig.events[0..count]) |event| _ = rig.engine.apply(event, rig.loop.now());
        if (moved_nothing) break;
    }
    try testing.expect(moved_nothing);
    try expect_all_failed(&rig, .handshake);
    try rig.deinit();
}

test "a send the loop refuses while the handshake runs gives local as the cause" {
    // No server took part: the loop refused the hello's send (docs/design.md §5, The cause of a
    // failure).
    var rig: OneServer = .{};
    try tls_test.encrypt(&rig);
    try rig.init(133, .{.{}}, .{ .servers = &.{}, .attempts = 1, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    // The connect ends, and the loop refuses what the handshake asks of it then.
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
    try expect_all_failed(&rig, .local);
    try rig.deinit();
}

test "a connection that cannot connect again after its resumed handshake failed gives local as the cause" {
    // A resumed handshake that fails is no failure of the server's, and the connection opens
    // again in full (TLS rule 8). The system refuses that socket: no server took part.
    var rig: OneServer = .{};
    try tls_test.encrypt(&rig);
    const declining: rotor.server.Script = .{ .tls = .{ .tickets = true, .decline_tickets = true } };
    try rig.init(134, .{declining}, .{ .servers = &.{}, .attempts = 1, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(rig.engine.tls_tickets[0] != null);
    // The connection closes idle, and the next lookup's connection resumes with the ticket.
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].state == .closed);
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(rig.engine.connections[0].tls.ticket != null);
    rig.loop.network().refuse_open = true;
    defer rig.loop.network().refuse_open = false;
    try expect_all_failed(&rig, .local);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try rig.deinit();
}
