//! The engine over DoQ on the twin when a server or the system fails it (docs/design.md §24,
//! request rules 2, 5, 7, 8, 9 and 11): each failure fails every request on the connection once,
//! counts against the server, and the lookup moves on (§16 decision 25).
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const request_test = @import("io_request_test.zig");
const question = sim_test.question;
const Rig = request_test.Rig;
const start = request_test.start;

/// A lookup the first server fails as `script` says, answered by the second, with the failure
/// counted against the first and its connection closed.
fn fails_over(seed: u64, script: rotor.server.Script) !void {
    var rig: Rig = .{};
    try start(&rig, seed, .{ script, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.engine.quic_connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// A lookup both servers fail as `script` says, which ends in AllServersFailed, not Timeout.
fn fails_all(seed: u64, first: rotor.server.Script, second: rotor.server.Script) !void {
    var rig: Rig = .{};
    try start(&rig, seed, .{ first, second });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a refused handshake fails the connection, and the next server answers" {
    try fails_over(71, .{ .quic = .{ .refuse = true } });
}

test "a handshake that ends on another protocol than doq is never up" {
    // "DoQ support is indicated by selecting the ... ALPN token "doq"" (RFC 9250 §4.1).
    try fails_over(72, .{ .quic = .{ .other_protocol = true } });
}

test "a stream the server resets fails its request, and a server's close every one on it" {
    try fails_over(73, .{ .quic = .{ .instead = .close } });
    try fails_all(74, .{ .quic = .{ .instead = .reset } }, .{ .quic = .{ .instead = .reset } });
}

test "an answer whose prefix or ID breaks RFC 9250 fails the connection" {
    // A FIN before the prefix's octets, and a message ID that is not 0, are protocol errors
    // (RFC 9250 §4.3.3).
    try fails_all(75, .{ .quic = .{ .malformed = .prefix } }, .{ .quic = .{ .malformed = .id } });
}

test "a datagram whose send fails fails the connection" {
    try fails_over(76, .{ .no_route = true });
}

test "a socket the system refuses fails the request, on every server" {
    var rig: Rig = .{};
    try start(&rig, 77, .{ .{}, .{} });
    rig.loop.network().refuse_open = true;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    try testing.expect(rig.engine.quic_connections[0].state == .closed);
    rig.loop.network().refuse_open = false;
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection whose QUIC timer gives up fails, when the engine's one timer comes" {
    var rig: Rig = .{};
    try start(&rig, 78, .{ .{ .down = true }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.quic_connections[0];
    try testing.expect(connection.state == .handshaking);
    connection.quic.due_ns = rig.loop.now() + fixtures.quic_timer_ns;
    connection.quic.expiry = .timeout;
    // The drive moves the engine's timer to the connection's deadline (request rule 11).
    rig.engine.drive(rig.loop.now());
    try testing.expectEqual(connection.quic.due_ns, rig.engine.timer_due_ns);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an idle connection near its negotiated timeout closes before a request, which opens anew" {
    var rig: Rig = .{};
    try start(&rig, 79, .{ .{}, .{} });
    try request_test.answer(&rig, "one.example.");
    const connection = &rig.engine.quic_connections[0];
    connection.quic.idle_left = 0;
    // RFC 9250 §4.4: "it SHOULD check whether the idle time is sufficiently lower than the idle
    // timer. ... If not, the client SHOULD establish a new connection".
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(connection.state == .closing);
    try testing.expectEqual(@as(u16, 1), connection.queue_len);
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u32, 2), connection.incarnation);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// An engine whose answer buffer holds less than an ordinary answer.
const Tiny = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_message_bytes = fixtures.tiny_message_bytes,
    .quic = rotor.quic.Connection,
});

test "an answer longer than the engine's buffer fails the connection" {
    var rig: sim_test.RigOf(Tiny) = .{};
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    try rig.init(80, .{ .{}, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    // A name long enough that its answer, prefix and all, passes the buffer's 64 octets.
    _ = try rig.engine.start(question("a-name-long-enough-to-overflow.example."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
