//! The engine over DoQ on the twin (docs/design.md §24, the request rules): a handshake before
//! the first stream, the requests that wait for it, a stream answered, a refused handshake and a
//! protocol the engine refuses failed over, a ticket kept and spent, and the idle close. The
//! connection is the twin's (`rotor.quic`), whose datagrams carry items in the clear; what only
//! colibri can show is colibri's, over the twin as well.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks the twin's QUIC.
pub const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .quic = rotor.quic.Connection,
});
pub const Rig = sim_test.RigOf(Resolver);

/// A rig whose servers speak DoQ as `scripts` say, under a timeout long enough for any of them.
pub fn start(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script) !void {
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    try rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
}

/// The server side of the twin's connection to server `server`, if one was opened.
pub fn peer_of(rig: *Rig, server: u8) ?*rotor.quic.Peer {
    for (&rig.loop.network().quic_peers) |*entry| {
        if (entry.open and entry.server == server) return &entry.peer;
    }
    return null;
}

test "a lookup over DoQ handshakes, then is answered on its stream, and no plain socket is opened" {
    var rig: Rig = .{};
    try start(&rig, 61, .{ .{}, .{} });
    try testing.expectEqual(@as(u8, 0), rig.engine.sockets.count);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.engine.quic_connections[0].state == .up);
    try testing.expect(!rig.engine.requests[result.handle.index].live);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "requests taken while the handshake runs wait for its end, then each opens a stream" {
    var rig: Rig = .{};
    try start(&rig, 62, .{ .{ .quic = .{ .flights = 2 } }, .{} });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expectEqual(@as(u16, 2), rig.engine.quic_connections[0].queue_len);
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u64, 2 * rotor.constants.quic_stream_step), rig.engine.quic_connections[0].quic.next_stream);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup cancelled while its stream is open has the stream cancelled, and hears nothing" {
    // The server never answers, so the stream is open when the caller cancels the lookup, which
    // takes no new request: the drive cancels the stream it left (request rule 6).
    var rig: Rig = .{};
    try start(&rig, 68, .{ .{ .drop_per_256 = fixtures.always }, .{} });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.quic_connections[0];
    var rounds: usize = 0;
    while (connection.streams == 0 and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try rig.step(fixtures.wait_ns);
    }
    try testing.expectEqual(@as(u16, 1), connection.streams);
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expectEqual(@as(u16, 0), connection.users());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Canceled, result.outcome.failure.err);
    // The STOP_SENDING goes once the buffer is back from the datagram before it (rule 8).
    _ = try rig.step(fixtures.wait_ns);
    try testing.expectEqual(@as(u16, 1), peer_of(&rig, 0).?.cancels);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// Lets the idle close run: the clock moves past `quic_idle_ns` with nothing due, twice, so the
/// timer the last lookup left is gone as well.
pub fn idle(rig: *Rig) !void {
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
}

/// One lookup of `name`, answered, and its result taken.
pub fn answer(rig: *Rig, name: []const u8) !void {
    _ = try rig.engine.start(question(name), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
}

test "an idle connection says CONNECTION_CLOSE, and closes once it has gone" {
    var rig: Rig = .{};
    try start(&rig, 63, .{ .{}, .{} });
    try answer(&rig, "example.com.");
    try idle(&rig);
    try testing.expect(rig.engine.quic_connections[0].state == .closing);
    try testing.expect(peer_of(&rig, 0).?.closed);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic_connections[0].state == .closed);
    try rig.deinit();
}

test "a ticket the server gave is kept, and the next connection resumes with it" {
    var rig: Rig = .{};
    try start(&rig, 64, .{ .{ .quic = .{ .tickets = true } }, .{} });
    try answer(&rig, "one.example.");
    try testing.expect(rig.engine.quic_tickets[0] != null);
    try testing.expectEqual(@as(u16, 0), peer_of(&rig, 0).?.resumed);
    try idle(&rig);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic_connections[0].state == .closed);
    try answer(&rig, "two.example.");
    // The new connection spent the ticket, and its handshake gave another (request rule 10).
    try testing.expectEqual(@as(u16, 1), peer_of(&rig, 0).?.resumed);
    try testing.expect(rig.engine.quic_tickets[0] != null);
    try rig.deinit();
}

test "a request its lookup left is cancelled with STOP_SENDING, and the next server answers" {
    // The first server's handshake ends, and it never answers the stream: the lookup's deadline
    // moves it on, and the drive cancels the stream it left (request rule 6, RFC 9250 §4.3.1).
    var rig: Rig = .{};
    try start(&rig, 65, .{ .{ .drop_per_256 = fixtures.always }, .{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(u16, 1), peer_of(&rig, 0).?.cancels);
    try testing.expectEqual(@as(u16, 0), rig.engine.quic_connections[0].users());
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a closing connection reads nothing more, and a close the loop refused goes at the next drive" {
    var rig: Rig = .{};
    try start(&rig, 66, .{ .{}, .{} });
    try answer(&rig, "example.com.");
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    // The loop refuses the CONNECTION_CLOSE's send, so the connection stays closing (rule 8).
    rig.loop.refuse_submissions = true;
    rig.engine.drive(rig.loop.now());
    rig.loop.refuse_submissions = false;
    const connection = &rig.engine.quic_connections[0];
    try testing.expect(connection.state == .closing);
    try testing.expect(connection.made > 0);
    // A ticket the server sent before it heard the close arrives after it, and is not read
    // (request rule 9).
    const pending = rig.loop.network().queue_datagram().?;
    pending.socket = connection.descriptor.?;
    pending.from = rotor.Network.server_address(0);
    pending.due_ns = rig.loop.now();
    pending.len = @intCast(rotor.quic.write_item(.{ .kind = .ticket }, &pending.bytes));
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.quic_tickets[0] == null);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(connection.state == .closed);
    try rig.deinit();
}

/// An engine whose datagram group runs dry under its own answers.
const Starved = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.small_group_buffers,
    .quic = rotor.quic.Connection,
});

test "a receive that runs out of buffers is armed again, and fails nothing" {
    var rig: sim_test.RigOf(Starved) = .{};
    const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    for (&rig.servers) |*server| server.quic = quic;
    // Every answer comes at the same instant: more datagrams than the group has buffers.
    const script: rotor.server.Script = .{ .delay_ns_min = fixtures.slow_answer_ns, .delay_ns_max = fixtures.slow_answer_ns };
    try rig.init(67, .{ script, .{} }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." };
    for (names) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    for (names) |_| {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
