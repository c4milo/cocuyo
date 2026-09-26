//! The engine over DoH on HTTP/2 through colibri's client and colibri's server, on the twin
//! (docs/design.md §24, DoH over HTTP/2): the plain record provider on both sides, the server a
//! stream responder on each scripted server's HTTPS port. An answer and its `Age`, the responses
//! that fail over, an interim response, more lookups than answer buffers, a GOAWAY that drains the
//! connection, a request cancelled, and the idle close.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const cocuyo_h2 = @import("cocuyo_h2");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks DoH over colibri's HTTP/2, with fewer answer buffers on a connection than
/// lookups.
const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .h2 = cocuyo_h2.Connection(.{ .answers = fixtures.doh_answers }),
});
const Rig = sim_test.RigOf(Resolver);
const Server = cocuyo_h2.server.Server;

/// No port, so the connection goes to TCP's 443, where the twin takes DoH over HTTP/2.
const template = "https://dns.example/dns-query{?dns}";

/// A scripted server's HTTPS port as colibri's HTTP/2 server: a server for each connection, by the
/// client's socket, answering as the scripted server would, after its delay.
const Side = struct {
    const Entry = struct { socket: ?rotor.Descriptor = null, server: Server = .{} };

    index: u8,
    network: *rotor.Network,
    entries: [fixtures.quic_servers_per_side]Entry = @splat(.{}),
    script: cocuyo_h2.server.Script = .{},
    draws: u64 = 0,

    fn responder(side: *Side) rotor.StreamResponder {
        return .{ .context = side, .opened = opened, .hear = hear };
    }

    /// A new connection, maybe on a socket an old one used: a new server for it.
    fn opened(context: *anyopaque, socket: rotor.Descriptor) void {
        const side: *Side = @ptrCast(@alignCast(context));
        for (&side.entries) |*entry| {
            if (entry.socket == socket) entry.socket = null;
        }
    }

    fn hear(context: *anyopaque, socket: rotor.Descriptor, bytes: []const u8, now_ns: u64) void {
        const side: *Side = @ptrCast(@alignCast(context));
        const entry = side.entry_of(socket) orelse return;
        entry.server.receive(bytes, .{ .context = side, .answer = answer });
        var out: [cocuyo_h2.constants.output_bytes_max]u8 = undefined;
        for (0..fixtures.quic_pump_max) |_| {
            const len = entry.server.send(&out);
            if (len == 0) return;
            const delay_ns = side.network.scripts[side.index].delay_ns_min;
            _ = side.network.write_stream(socket, out[0..len], now_ns + delay_ns);
        }
    }

    /// The connection from `socket`, or a new one for a socket the side has not heard from.
    fn entry_of(side: *Side, socket: rotor.Descriptor) ?*Entry {
        for (&side.entries) |*entry| if (entry.socket == socket) return entry;
        for (&side.entries) |*entry| {
            if (entry.socket != null or entry.server.answered > 0) continue;
            entry.socket = socket;
            entry.server.init(side.script);
            return entry;
        }
        return null;
    }

    fn answer(context: *anyopaque, query: []const u8, out: []u8) ?usize {
        const side: *Side = @ptrCast(@alignCast(context));
        side.draws += 1;
        const script = &side.network.scripts[side.index];
        const from = rotor.Network.server_address(side.index);
        const answered = rotor.server.respond(script, &from, query, true, side.draws, out) orelse return null;
        return answered.len;
    }
};

/// A rig and a side for each scripted server, on the heap: an engine over colibri's HTTP/2 holds a
/// connection of a few hundred kilobytes for each server it may ask.
const World = struct {
    rig: Rig = .{},
    sides: [fixtures.servers]Side = undefined,

    fn create(seed: u64, scripts: [fixtures.servers]rotor.server.Script) !*World {
        const world = try testing.allocator.create(World);
        errdefer testing.allocator.destroy(world);
        world.* = .{};
        for (&world.rig.servers) |*server| server.https = .{ .template = template };
        try world.rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
        for (&world.sides, 0..) |*side, index| {
            side.* = .{ .index = @intCast(index), .network = world.rig.loop.network() };
            world.rig.loop.network().stream_responders[index] = side.responder();
        }
        return world;
    }

    fn free(world: *World) void {
        testing.allocator.destroy(world);
    }

    /// One lookup of `name`, whose result is taken.
    fn resolve(world: *World, name: []const u8) !Resolver.Result {
        _ = try world.rig.engine.start(question(name), world.rig.loop.now());
        const result = try world.rig.until_result();
        _ = world.rig.engine.take(world.rig.loop.now());
        return result;
    }
};

test "a lookup over DoH on HTTP/2 is answered through colibri's client and colibri's server on the twin" {
    const world = try World.create(111, .{ .{}, .{} });
    defer world.free();
    const result = try world.resolve("example.com.");
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(world.rig.engine.h2.connections[0].state == .up);
    try testing.expectEqual(@as(usize, 1), world.sides[0].entries[0].server.answered);
    try world.rig.deinit();
}

test "the Age colibri's server writes lowers the answer's TTLs" {
    const world = try World.create(112, .{ .{ .ttl_seconds = 600 }, .{} });
    defer world.free();
    world.sides[0].script.age = "250";
    const result = try world.resolve("example.com.");
    try testing.expectEqual(@as(u32, 350), result.outcome.answer.ttl_seconds);
    try world.rig.deinit();
}

/// A lookup whose first server's responses are as `script` says: it fails over, counted once.
fn expect_failed_over(seed: u64, script: cocuyo_h2.server.Script) !void {
    const world = try World.create(seed, .{ .{}, .{} });
    defer world.free();
    world.sides[0].script = script;
    const result = try world.resolve("example.com.");
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), world.rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(usize, 1), world.sides[1].entries[0].server.answered);
    try world.rig.deinit();
}

test "a 404, a coded answer, another media type or another protocol from colibri's server fails over" {
    try expect_failed_over(113, .{ .status = 404 });
    try expect_failed_over(114, .{ .content_encoding = "gzip" });
    try expect_failed_over(115, .{ .content_type = "text/html" });
    try expect_failed_over(116, .{ .other_protocol = true });
}

test "an interim response before the answer changes nothing" {
    const world = try World.create(117, .{ .{}, .{} });
    defer world.free();
    world.sides[0].script.interim = true;
    const result = try world.resolve("example.com.");
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), world.rig.engine.resolver.servers.failures(0));
    try world.rig.deinit();
}

test "more lookups than a connection has answer buffers are all answered on it, in turn" {
    const world = try World.create(118, .{ .{}, .{} });
    defer world.free();
    const names = [fixtures.small_lookups][]const u8{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." };
    for (names) |name| _ = try world.rig.engine.start(question(name), world.rig.loop.now());
    for (names) |_| {
        const result = try world.rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    _ = world.rig.engine.take(world.rig.loop.now());
    try testing.expectEqual(@as(usize, names.len), world.sides[0].entries[0].server.answered);
    try testing.expectEqual(@as(u8, 0), world.rig.engine.resolver.servers.failures(0));
    try world.rig.deinit();
}

test "a server's GOAWAY drains the connection, and the next lookup opens a new one" {
    const world = try World.create(119, .{ .{}, .{} });
    defer world.free();
    world.sides[0].script.goaway = true;
    try testing.expect((try world.resolve("one.example.")).outcome == .answer);
    try testing.expect((try world.resolve("two.example.")).outcome == .answer);
    // The first connection drained and closed once its stream was answered; the second answers.
    try testing.expectEqual(@as(usize, 1), world.sides[0].entries[1].server.answered);
    try testing.expectEqual(@as(u8, 0), world.rig.engine.resolver.servers.failures(0));
    try world.rig.deinit();
}

test "a request its lookup left is cancelled with RST_STREAM, and the next server answers" {
    // The first server holds the request, so the lookup's deadline moves it on (request rule 6).
    const world = try World.create(120, .{ .{}, .{} });
    defer world.free();
    world.sides[0].script.hold = true;
    const result = try world.resolve("example.com.");
    try testing.expect(result.outcome == .answer);
    _ = try world.rig.step(fixtures.wait_ns);
    try testing.expectEqual(@as(usize, 1), world.sides[0].entries[0].server.cancels);
    try world.rig.deinit();
}

test "an idle connection says GOAWAY and close_notify, and its socket closes once they have gone" {
    const world = try World.create(121, .{ .{}, .{} });
    defer world.free();
    _ = try world.resolve("example.com.");
    const connection = &world.rig.engine.h2.connections[0];
    _ = try world.rig.step(fixtures.tcp_idle_jump_ns);
    _ = try world.rig.step(fixtures.tcp_idle_jump_ns);
    world.rig.engine.drive(world.rig.loop.now());
    // The GOAWAY and the `close_notify` go in two sends, and the socket closes after the second.
    for (0..fixtures.until_rounds_max) |_| {
        if (connection.state == .closed) break;
        _ = try world.rig.step(fixtures.wait_ns);
    }
    const server = &world.sides[0].entries[0].server;
    try testing.expect(server.client_goaway and server.client_closed);
    try testing.expect(connection.state == .closed);
    try world.rig.deinit();
}
