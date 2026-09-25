//! The engine over colibri on the twin (docs/design.md §24, colibri over the twin): colibri's client
//! in the engine, colibri's server behind each scripted server's QUIC port, both over the session
//! that encrypts nothing, and the scripted servers' answers on the streams. Real packets, streams,
//! flow control, loss and its recovery, on the twin's clock.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const cocuyo_quic = @import("cocuyo_quic");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine over colibri, with no TCP connection: DoQ needs none.
const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .quic = cocuyo_quic.Connection(.{ .streams = fixtures.small_lookups }),
});
const Rig = sim_test.RigOf(Resolver);

/// One scripted server's side: a colibri server for each connection the engine opens to it, each
/// on its own client socket, answering with the scripted server's answers.
const Side = struct {
    const Server = cocuyo_quic.server.Server(fixtures.small_lookups);
    const Entry = struct { socket: ?rotor.Descriptor = null, server: Server = .{} };

    index: u8,
    network: *rotor.Network,
    entries: [fixtures.quic_servers_per_side]Entry = @splat(.{}),
    draws: u64 = 0,
    /// Datagrams from the client dropped before any is heard, and whether the server selects
    /// another protocol than DoQ.
    drop_first: usize = 0,
    other_protocol: bool = false,
    hold: bool = false,

    fn responder(side: *Side) rotor.Responder {
        return .{ .context = side, .hear = hear, .deadline = deadline, .expire = expire };
    }

    fn hear(context: *anyopaque, socket: rotor.Descriptor, bytes: []const u8, now_ns: u64) void {
        const side: *Side = @ptrCast(@alignCast(context));
        if (side.drop_first > 0) {
            side.drop_first -= 1;
            return;
        }
        const entry = side.entry_of(socket) orelse return;
        entry.server.receive(bytes, now_ns, .{ .context = side, .answer = answer });
        side.pump(entry, now_ns);
    }

    /// The connection from `socket`, or a new one for a socket the side has not heard from.
    fn entry_of(side: *Side, socket: rotor.Descriptor) ?*Entry {
        for (&side.entries) |*entry| {
            if (entry.socket == socket) return entry;
        }
        for (&side.entries) |*entry| {
            if (entry.socket != null) continue;
            entry.* = .{ .socket = socket };
            entry.server.other_protocol = side.other_protocol;
            entry.server.hold = side.hold;
            return entry;
        }
        return null;
    }

    /// Sends what the server owes, each datagram after the scripted server's delay.
    fn pump(side: *Side, entry: *Entry, now_ns: u64) void {
        var datagram: [cocuyo_quic.constants.datagram_receive_bytes]u8 = undefined;
        var sent: usize = 0;
        while (sent < fixtures.quic_pump_max) : (sent += 1) {
            const len = entry.server.send(&datagram, now_ns);
            if (len == 0) return;
            const delay_ns = side.network.scripts[side.index].delay_ns_min;
            _ = side.network.reply(entry.socket.?, side.index, datagram[0..len], now_ns + delay_ns);
        }
    }

    fn answer(context: *anyopaque, query: []const u8, out: []u8) ?usize {
        const side: *Side = @ptrCast(@alignCast(context));
        side.draws += 1;
        const script = &side.network.scripts[side.index];
        const from = rotor.Network.server_quic_address(side.index);
        const answered = rotor.server.respond(script, &from, query, true, side.draws, out) orelse return null;
        return answered.len;
    }

    fn deadline(context: *anyopaque) ?u64 {
        const side: *Side = @ptrCast(@alignCast(context));
        var soonest: ?u64 = null;
        for (&side.entries) |*entry| {
            if (entry.socket == null) continue;
            const due = entry.server.deadline() orelse continue;
            soonest = if (soonest) |earlier| @min(earlier, due) else due;
        }
        return soonest;
    }

    fn expire(context: *anyopaque, now_ns: u64) void {
        const side: *Side = @ptrCast(@alignCast(context));
        for (&side.entries) |*entry| {
            if (entry.socket == null) continue;
            const due = entry.server.deadline() orelse continue;
            if (due > now_ns) continue;
            entry.server.expire(now_ns);
            side.pump(entry, now_ns);
        }
    }
};

/// A rig and a side for each of its scripted servers, on the heap: an engine over colibri holds a
/// connection of half a megabyte for each server it may ask.
const World = struct {
    rig: Rig = .{},
    sides: [fixtures.servers]Side = undefined,

    fn create(seed: u64, scripts: [fixtures.servers]rotor.server.Script) !*World {
        const world = try testing.allocator.create(World);
        errdefer testing.allocator.destroy(world);
        world.* = .{};
        const quic: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
        for (&world.rig.servers) |*server| server.quic = quic;
        try world.rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
        for (&world.sides, 0..) |*side, index| {
            side.* = .{ .index = @intCast(index), .network = world.rig.loop.network() };
            world.rig.loop.network().responders[index] = side.responder();
        }
        return world;
    }

    fn free(world: *World) void {
        testing.allocator.destroy(world);
    }
};

test "a lookup over DoQ is answered through colibri's client and colibri's server on the twin" {
    const world = try World.create(91, .{ .{}, .{} });
    defer world.free();
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(world.rig.engine.quic_connections[0].state == .up);
    try testing.expectEqual(@as(usize, 1), world.sides[0].entries[0].server.answered);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "lookups over DoQ share one connection to colibri's server, each on a stream of its own" {
    const world = try World.create(92, .{ .{}, .{} });
    defer world.free();
    const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." };
    for (names) |name| _ = try world.rig.engine.start(question(name), world.rig.loop.now());
    for (names) |_| {
        const result = try world.rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(usize, names.len), world.sides[0].entries[0].server.answered);
    try testing.expect(world.sides[0].entries[1].socket == null);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "a colibri server that selects another protocol than doq is refused, and the next answers" {
    // "DoQ support is indicated by selecting the ... ALPN token "doq"" (RFC 9250 §4.1).
    const world = try World.create(93, .{ .{}, .{} });
    defer world.free();
    world.sides[0].other_protocol = true;
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), world.rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(usize, 0), world.sides[0].entries[0].server.answered);
    try testing.expectEqual(@as(usize, 1), world.sides[1].entries[0].server.answered);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "colibri resends the client's first datagrams when they are lost, through the engine's timer" {
    const world = try World.create(94, .{ .{}, .{} });
    defer world.free();
    world.sides[0].drop_first = fixtures.quic_datagrams_lost;
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    // The first server answered after all: the loss cost time, not the server.
    try testing.expectEqual(@as(u8, 0), world.rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(usize, 1), world.sides[0].entries[0].server.answered);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "an idle connection to colibri's server closes with CONNECTION_CLOSE, which the server hears" {
    const world = try World.create(95, .{ .{}, .{} });
    defer world.free();
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    _ = try world.rig.until_result();
    _ = world.rig.engine.take(world.rig.loop.now());
    // colibri's own timers wake the loop meanwhile, so the clock is stepped until the idle close
    // has come and gone.
    const connection = &world.rig.engine.quic_connections[0];
    var rounds: usize = 0;
    while (connection.state != .closed and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.tcp_idle_jump_ns);
        world.rig.engine.drive(world.rig.loop.now());
    }
    try testing.expect(connection.state == .closed);
    const server = &world.sides[0].entries[0].server.connection;
    try testing.expect(server.termination.state != .active);
    try world.rig.deinit();
}

test "streams the engine cancels are drained, and give their places in colibri's table back" {
    // Each lookup is cancelled once its stream is open, and the server's answer, already on its
    // way, arrives on a cancelled stream. colibri holds 128 streams of a connection at once, so
    // more cancelled streams than that, kept, would leave no place for the last lookup's.
    const world = try World.create(96, .{ .{}, .{} });
    defer world.free();
    const engine = &world.rig.engine;
    var cancelled: usize = 0;
    while (cancelled < fixtures.quic_cancelled_streams) : (cancelled += 1) {
        const handle = try engine.start(question("example.com."), world.rig.loop.now());
        var rounds: usize = 0;
        while (engine.quic_connections[0].streams == 0 and rounds < fixtures.until_rounds_max) : (rounds += 1) {
            _ = try world.rig.step(fixtures.wait_ns);
        }
        try testing.expectEqual(@as(u16, 1), engine.quic_connections[0].streams);
        engine.cancel(handle, world.rig.loop.now());
        _ = try world.rig.until_result();
        _ = engine.take(world.rig.loop.now());
        // The server's answer arrives on the cancelled stream, and is drained.
        _ = try world.rig.step(fixtures.wait_ns);
    }
    _ = try engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "a lookup cancelled while colibri's server holds its query sends STOP_SENDING, which ends it" {
    // "If a DoQ client wishes to cancel an outstanding request, it MUST issue a QUIC
    // STOP_SENDING" (RFC 9250 §4.3.1). The server holds the query, so only the client's
    // STOP_SENDING ends its side of the stream: colibri resets it in answer.
    const world = try World.create(97, .{ .{}, .{} });
    defer world.free();
    world.sides[0].hold = true;
    const engine = &world.rig.engine;
    const handle = try engine.start(question("example.com."), world.rig.loop.now());
    var rounds: usize = 0;
    while (engine.quic_connections[0].streams == 0 and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.wait_ns);
    }
    engine.cancel(handle, world.rig.loop.now());
    _ = try world.rig.until_result();
    _ = engine.take(world.rig.loop.now());
    _ = try world.rig.step(fixtures.wait_ns);
    const server = &world.sides[0].entries[0].server;
    const id = cocuyo_quic.server.StreamId.of(.client, .bidirectional, 0);
    const state = switch (server.connection.streams.lookup(id)) {
        .live => |stream| stream.sending.state,
        .closed, .unopened => return error.StreamGone,
    };
    try testing.expect(state == .reset_sent or state == .reset_recvd);
    try world.rig.deinit();
}

test "a request taken while an idle close is held back reopens the connection, though colibri's period ended" {
    // The loop refuses the idle close's CONNECTION_CLOSE, which is made and kept (request rule 8),
    // and colibri's closing period ends while it waits. That end is the engine's own close, not the
    // connection failing: the request taken meanwhile waits, and opens the connection again once
    // the close has gone (request rule 9).
    const world = try World.create(98, .{ .{}, .{} });
    defer world.free();
    const engine = &world.rig.engine;
    const connection = &engine.quic_connections[0];
    _ = try engine.start(question("one.example."), world.rig.loop.now());
    _ = try world.rig.until_result();
    _ = engine.take(world.rig.loop.now());
    var rounds: usize = 0;
    while (world.rig.loop.now() < connection.idle_since_ns + engine.quic_idle_ns and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.tcp_idle_jump_ns);
    }
    try testing.expect(connection.state == .up);
    world.rig.loop.refuse_submissions = true;
    engine.drive(world.rig.loop.now());
    try testing.expect(connection.state == .closing and connection.made > 0);
    _ = try engine.start(question("two.example."), world.rig.loop.now());
    try testing.expectEqual(@as(u16, 1), connection.queue_len);
    rounds = 0;
    while (connection.quic.connection.termination.state != .closed and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.wait_ns);
    }
    try testing.expect(connection.state == .closing);
    world.rig.loop.refuse_submissions = false;
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u32, 2), connection.incarnation);
    _ = engine.take(world.rig.loop.now());
    try world.rig.deinit();
}
