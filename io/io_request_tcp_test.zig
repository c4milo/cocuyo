//! The engine over DoH on HTTP/2 on the twin (docs/design.md §24, DoH over HTTP/2, request rules 14
//! to 16): the connect before the handshake, the requests that wait for both, a stream answered, a
//! refused connect failed over, a send that goes short, the server's end of the stream, the idle
//! close, and a connection opened again while the connect of an earlier one is in flight. The
//! connection is the twin's over TCP (`rotor.quic.Stream`), whose frames carry the twin's QUIC
//! items in the clear.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks the twin's QUIC over TCP, and keeps no TCP connection of RFC 7766's: DoH
/// needs none.
pub const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .h2 = rotor.quic.Stream,
});
pub const Rig = sim_test.RigOf(Resolver);

/// A template that names no port, so the connection goes to TCP's 443, where the twin's servers
/// take DoH over HTTP/2 (RFC 9110 §4.2.2).
const template = "https://dns.example/dns-query{?dns}";

/// A rig whose servers speak DoH as `scripts` say, under a timeout long enough for any of them.
/// A send buffer of `send_bytes`, when it is not zero, makes the twin's sends go short.
fn start(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script, send_bytes: u32) !void {
    for (&rig.servers) |*server| server.https = .{ .template = template };
    try rig.init(seed, scripts, .{
        .servers = &.{},
        .timeout_ns = fixtures.stream_timeout_ns,
        .failover_retry_chance = 0,
        .socket_send_bytes = send_bytes,
    });
}

/// Lets the idle close run, as `io_request_test.zig`'s `idle` does for DoQ.
fn idle(rig: *Rig) !void {
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
}

/// The server side of the twin's connection to server `server`, if one is open.
fn peer_of(rig: *Rig, server: u8) ?*rotor.quic.Peer {
    for (&rig.loop.network().quic_peers) |*entry| {
        if (entry.open and entry.server == server) return &entry.peer;
    }
    return null;
}

test "a lookup over DoH on HTTP/2 connects, handshakes on h2, and is answered on its stream" {
    var rig: Rig = .{};
    try start(&rig, 91, .{ .{}, .{} }, 0);
    try testing.expectEqual(@as(u8, 0), rig.engine.sockets.count);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.h2.connections[0];
    try testing.expect(connection.state == .connecting);
    // Nothing is armed or sent before the connect has succeeded (request rule 14).
    try testing.expect(connection.receive == null and !rig.engine.h2.sends[0].lent);
    try testing.expectEqual(@as(u16, 443), connection.port);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(connection.state == .up);
    const peer = peer_of(&rig, 0).?;
    try testing.expectEqualStrings("h2", peer.offered[0..peer.offered_len]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "requests taken while the connection connects wait for it and its handshake, then each is answered" {
    var rig: Rig = .{};
    try start(&rig, 92, .{ .{ .quic = .{ .flights = 1 } }, .{} }, 0);
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expectEqual(@as(u16, 2), rig.engine.h2.connections[0].queue_len);
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection whose server negotiates another protocol than h2 is never up" {
    // "HTTP/2 connections over TLS MUST use protocol negotiation in TLS" (RFC 9113 §3.3).
    var rig: Rig = .{};
    try start(&rig, 98, .{ .{ .quic = .{ .other_protocol = true } }, .{} }, 0);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.engine.h2.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connect the server refuses fails the request once, and the next server answers" {
    var rig: Rig = .{};
    try start(&rig, 93, .{ .{ .tcp = false }, .{} }, 0);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.engine.h2.connections[0].state == .closed);
    try testing.expect(!rig.engine.h2.sends[0].connecting);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "sends that go short send their rest first, and the lookup is answered" {
    // A send buffer shorter than the hello makes every send of it go short (request rule 15).
    var rig: Rig = .{};
    try start(&rig, 94, .{ .{}, .{} }, fixtures.short_send_bytes);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the server's end of the stream fails the request once, and the next server answers" {
    var rig: Rig = .{};
    try start(&rig, 95, .{ .{ .quic = .{ .instead = .end_stream } }, .{} }, 0);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.engine.h2.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an idle connection says its close, and its socket closes once that has gone" {
    var rig: Rig = .{};
    try start(&rig, 96, .{ .{}, .{} }, 0);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try idle(&rig);
    try testing.expect(rig.engine.h2.connections[0].state == .closing);
    try testing.expect(peer_of(&rig, 0).?.closed);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.h2.connections[0].state == .closed);
    try rig.deinit();
}

test "a connection idle while it connects closes with nothing sent, and one opened again waits for the old connect" {
    // The connect takes longer than the idle wait: the lookup is cancelled while it is in flight,
    // the connection closes at once, and the next lookup's connection waits for the old connect to
    // give its address back before it connects (request rules 14 and 16).
    var rig: Rig = .{};
    try start(&rig, 97, .{ .{ .connect_delay_ns = fixtures.idle_connect_ns }, .{} }, 0);
    rig.engine.h2.idle_ns = fixtures.short_idle_ns;
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    rig.engine.cancel(first, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    _ = try rig.step(fixtures.short_idle_ns);
    rig.engine.drive(rig.loop.now());
    const connection = &rig.engine.h2.connections[0];
    try testing.expect(connection.state == .closed);
    try testing.expect(rig.engine.h2.sends[0].connecting);
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect(connection.state == .reopening);
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u32, 2), connection.incarnation);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
