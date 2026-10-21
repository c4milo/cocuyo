//! The engine over DoQ on the twin when a server or the system fails it (docs/design.md §24,
//! request rules 2, 5, 7, 8, 9 and 11): each failure fails every request on the connection once,
//! counts against the server, and the lookup moves on (§16 decision 25). Each gives its reason,
//! which the cause keeps with its server (§5, The cause of a failure).
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
/// counted against the first and its connection closed. Then a lookup that both servers fail so,
/// whose cause is `reason` from the second.
fn fails_over(seed: u64, script: rotor.server.Script, reason: cocuyo.Reason) !void {
    var rig: Rig = .{};
    try start(&rig, seed, .{ script, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.engine.quic.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
    try fails_all(seed, script, script, reason);
}

/// A lookup both servers fail as `first` and `second` say, which ends in AllServersFailed, not
/// Timeout. The cause is `reason`, from the second server.
fn fails_all(seed: u64, first: rotor.server.Script, second: rotor.server.Script, reason: cocuyo.Reason) !void {
    var rig: Rig = .{};
    try start(&rig, seed, .{ first, second });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = reason } }), result.outcome.failure.cause);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a refused handshake fails the connection, and the next server answers" {
    try fails_over(71, .{ .quic = .{ .refuse = true } }, .handshake);
}

test "a handshake that ends on another protocol than doq is never up" {
    // "DoQ support is indicated by selecting the ... ALPN token "doq"" (RFC 9250 §4.1).
    try fails_over(72, .{ .quic = .{ .other_protocol = true } }, .handshake);
}

test "a stream the server resets fails its request, and a server's close every one on it" {
    try fails_over(73, .{ .quic = .{ .instead = .close } }, .closed);
    try fails_all(74, .{ .quic = .{ .instead = .reset } }, .{ .quic = .{ .instead = .reset } }, .reset);
}

test "an answer whose prefix or ID breaks RFC 9250 fails the connection" {
    // A FIN before the prefix's octets, and a message ID that is not 0, are protocol errors
    // (RFC 9250 §4.3.3) on a connection that is up.
    try fails_all(75, .{ .quic = .{ .malformed = .prefix } }, .{ .quic = .{ .malformed = .id } }, .closed);
}

test "a datagram whose send fails fails the connection" {
    // The first datagram goes before the handshake ends.
    try fails_over(76, .{ .no_route = true }, .handshake);
}

test "a socket the system refuses fails the request, on every server" {
    var rig: Rig = .{};
    try start(&rig, 77, .{ .{}, .{} });
    rig.loop.network().refuse_open = true;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    // No server took part (docs/design.md §5, The cause of a failure).
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = .local } }), result.outcome.failure.cause);
    try testing.expect(rig.engine.quic.connections[0].state == .closed);
    rig.loop.network().refuse_open = false;
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection whose QUIC timer gives up fails, when the engine's one timer comes" {
    var rig: Rig = .{};
    try start(&rig, 78, .{ .{ .down = true }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.quic.connections[0];
    try testing.expect(connection.state == .handshaking);
    connection.transport.due_ns = rig.loop.now() + fixtures.quic_timer_ns;
    connection.transport.expiry = .timeout;
    // The drive moves the engine's timer to the connection's deadline (request rule 11).
    rig.engine.drive(rig.loop.now());
    try testing.expectEqual(connection.transport.due_ns, rig.engine.timer_due_ns);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // The connection gave up before its handshake ended, and the lookup kept that cause.
    const cause = rig.engine.resolver.lookup_of(result.handle).cause.get();
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .handshake } }), cause);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an idle connection near its negotiated timeout closes before a request, which opens anew" {
    var rig: Rig = .{};
    try start(&rig, 79, .{ .{}, .{} });
    try request_test.answer(&rig, "one.example.");
    const connection = &rig.engine.quic.connections[0];
    connection.transport.idle_left = 0;
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
    .group_buffers = fixtures.group_buffers,
    .tcp_message_bytes = fixtures.tiny_message_bytes,
    .quic = rotor.quic.Connection,
});

/// How a lookup of `text` fails on the tiny engine, and its cause, over DoQ servers that send no
/// cookie. Both are null when it is answered with one address.
const Seen = struct { err: ?cocuyo.Error, cause: ?cocuyo.Cause = null };

fn tiny_failure(seed: u64, text: []const u8) !Seen {
    var rig: sim_test.RigOf(Tiny) = .{};
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    const bare: rotor.server.Script = .{ .cookies = false };
    try rig.init(seed, .{ bare, bare }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    _ = try rig.engine.start(question(text), rig.loop.now());
    const result = try rig.until_result();
    const failure: Seen = switch (result.outcome) {
        .answer => |answer| .{ .err = if (answer.addresses.len == 1) null else error.NoData },
        .failure => |failure| .{ .err = failure.err, .cause = failure.cause },
    };
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
    return failure;
}

test "an answer longer than the engine's buffer fails the connection" {
    // A name long enough that its answer passes the 64 octets a message may be.
    const failure = try tiny_failure(80, "a-name-long-enough-to-overflow.example.");
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), failure.err);
    // The connection was up, and the answer is the server's (RFC 9250 §4.2).
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 1, .what = .{ .reason = .closed } }), failure.cause);
}

test "an answer of tcp_message_bytes is taken over DoQ, and one an octet longer is not" {
    // The header, the question, an A record and a bare OPT record are 43 octets and the name
    // (`fixtures.tiny_name_fits`): a name of 21 octets makes a message of 64, which the buffer
    // holds beside its prefix (RFC 9250 §4.2), and a name of 22 one of 65.
    try testing.expectEqual(@as(?cocuyo.Error, null), (try tiny_failure(81, fixtures.tiny_name_fits)).err);
    const longer = try tiny_failure(82, fixtures.tiny_name_over);
    try testing.expectEqual(@as(?cocuyo.Error, cocuyo.Error.AllServersFailed), longer.err);
}

test "a connection that cannot open again for the requests that waited gives local as the cause" {
    // An idle connection closes before a request (RFC 9250 §4.4), and the system refuses the
    // socket of the next one. No server took part (docs/design.md §5, The cause of a failure). One
    // server and one pass, so that this failure is the last.
    var rig: sim_test.RigOfServers(@FieldType(Rig, "engine"), 1) = .{};
    rig.servers[0].quic = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    try rig.init(83, .{.{}}, .{ .servers = &.{}, .attempts = 1, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns });
    rig.use_test_contexts();
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.quic.connections[0];
    connection.transport.idle_left = 0;
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(connection.state == .closing);
    rig.loop.network().refuse_open = true;
    const result = try rig.until_result();
    rig.loop.network().refuse_open = false;
    try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .local } }), result.outcome.failure.cause);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a receive that fails while the handshake runs gives the handshake as the cause" {
    var rig: Rig = .{};
    try start(&rig, 84, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.quic.connections[0];
    try testing.expect(connection.state == .handshaking);
    // The loop ends the receive in an error before the server's first datagram comes.
    rig.loop.cancel(connection.receive orelse return error.NoReceive);
    _ = try rig.step(fixtures.wait_ns);
    const cause = rig.engine.resolver.lookup_of(handle).cause.get();
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .handshake } }), cause);
    // The next server answers.
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a datagram the transport refuses while the handshake runs gives the handshake as the cause" {
    var rig: Rig = .{};
    try start(&rig, 85, .{ .{}, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.quic.connections[0];
    try testing.expect(connection.state == .handshaking);
    // The server's first datagram breaks the protocol, as the twin's transport says it does.
    connection.transport.refuses_datagrams = true;
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    const cause = rig.engine.resolver.lookup_of(handle).cause.get();
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .handshake } }), cause);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a stream that the transport cannot open on a connection that is up gives closed as the cause" {
    var rig: Rig = .{};
    try start(&rig, 86, .{ .{}, .{} });
    try request_test.answer(&rig, "one.example.");
    const connection = &rig.engine.quic.connections[0];
    try testing.expect(connection.state == .up);
    connection.transport.refuses_requests = true;
    const handle = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(connection.state == .closed);
    const cause = rig.engine.resolver.lookup_of(handle).cause.get();
    try testing.expectEqual(@as(?cocuyo.Cause, .{ .server_index = 0, .what = .{ .reason = .closed } }), cause);
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
