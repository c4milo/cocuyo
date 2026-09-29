//! The engine over `cocuyo_doh` on the twin (docs/design.md §24, DoH over colibri's client, beyond
//! the model): colibri's channel against colibri's server, which answers over TLS on each scripted
//! server's HTTPS port, or over QUIC on its QUIC port. Where no QUIC server listens, the channel
//! opens TCP once its fallback delay has passed: a lookup answered over HTTP/2, one over HTTP/1.1
//! from a server that selects no protocol, and a channel that goes idle and shuts down. Where one
//! does, a lookup is answered over HTTP/3. The engine's own rig is the `io` module's, whose tests
//! link no chapulin, so this file holds a small one.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const cocuyo_doh = @import("io_doh_channel.zig");
const identity = @import("io_doh_channel_identity.zig");
const server_module = @import("io_doh_channel_server.zig");
const quic_server = @import("io_doh_channel_server_quic.zig");
const colibri_server = @import("server");

const lookups = 4;
const group_buffers = 16;
const Resolver = io.Resolver(.{
    .lookups = lookups,
    .cache_slots = lookups,
    .group_buffers = group_buffers,
    .tcp_connections = 0,
    .doh = cocuyo_doh.Channel(.{}),
});

/// The twin's first two scripted servers, each known by a template with no port, so the channel's
/// connections go to 443 (RFC 9110 §4.2.2).
const servers = 2;
const template = "https://dns.example/dns-query{?dns}";
/// A template on the twin's QUIC port, where a QUIC responder listens (`sim.Network.responders`).
const quic_template = "https://dns.example:853/dns-query{?dns}";
/// The port the QUIC server sees each datagram come from. Test-only.
const client_port = 50_000;
const anchors = [_]@TypeOf(identity.anchor){identity.anchor};
/// A lookup's deadline, long past the fallback delay and a handshake after it.
const timeout_s = 25;
const timeout_ns = timeout_s * std.time.ns_per_s;
/// The events one tick delivers at most, the waits a lookup takes at most, and a wait's length.
const events_max = 32;
const rounds_max = 512;
const wait_s = 60;
const wait_ns = wait_s * std.time.ns_per_s;
/// The connections a scripted server takes over a test, and the records it sends for one read.
const connections_per_side = 2;
const sends_per_hear_max = 64;

/// A scripted server's HTTPS port as colibri's server over TLS: a server for each connection, by
/// the client's socket, answering as the scripted server would, after its delay.
const Side = struct {
    const Entry = struct { socket: ?rotor.Descriptor = null, server: server_module.Server = .{} };

    index: u8,
    network: *rotor.Network,
    script: server_module.Script = .{},
    entries: [connections_per_side]Entry = @splat(.{}),
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
        entry.server.receive(bytes, .{ .context = side, .answer = answer }, now_ns);
        var out: [cocuyo_doh.constants.output_bytes_max]u8 = undefined;
        for (0..sends_per_hear_max) |_| {
            const len = entry.server.send(&out, now_ns);
            if (len == 0) return;
            const delay_ns = side.network.scripts[side.index].delay_ns_min;
            _ = side.network.write_stream(socket, out[0..len], now_ns + delay_ns);
        }
    }

    /// The connection from `socket`, or a new one for a socket the side has not heard from.
    fn entry_of(side: *Side, socket: rotor.Descriptor) ?*Side.Entry {
        for (&side.entries) |*entry| if (entry.socket == socket) return entry;
        for (&side.entries) |*entry| {
            if (entry.socket != null) continue;
            entry.server.init(side.script, identity.unix_seconds) catch return null;
            entry.socket = socket;
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

/// A scripted server's QUIC port as colibri's server over QUIC: one endpoint takes every connection
/// there, from the socket that last spoke, and answers as the scripted server would, after its
/// delay.
const QuicSide = struct {
    index: u8,
    network: *rotor.Network,
    server: quic_server.QuicServer = .{},
    socket: ?rotor.Descriptor = null,
    draws: u64 = 0,

    fn responder(side: *QuicSide) rotor.Responder {
        return .{ .context = side, .hear = hear, .deadline = deadline, .expire = expire };
    }

    fn hear(context: *anyopaque, socket: rotor.Descriptor, bytes: []const u8, now_ns: u64) void {
        const side: *QuicSide = @ptrCast(@alignCast(context));
        side.socket = socket;
        const from = colibri_server.quic_connection.PeerAddress.of(rotor.Network.server_address(side.index).bytes[0..cocuyo.constants.address_v4_bytes], client_port);
        side.server.receive(bytes, from, .{ .context = side, .answer = answer }, now_ns);
        side.pump(now_ns);
    }

    fn deadline(context: *anyopaque) ?u64 {
        const side: *QuicSide = @ptrCast(@alignCast(context));
        return side.server.deadline();
    }

    fn expire(context: *anyopaque, now_ns: u64) void {
        const side: *QuicSide = @ptrCast(@alignCast(context));
        side.server.expire(now_ns);
        side.pump(now_ns);
    }

    /// Sends what the server owes, each datagram after the scripted server's delay.
    fn pump(side: *QuicSide, now_ns: u64) void {
        const socket = side.socket orelse return;
        var out: [cocuyo_doh.constants.datagram_bytes]u8 = undefined;
        for (0..sends_per_hear_max) |_| {
            const octets = side.server.send(&out, now_ns) orelse return;
            const delay_ns = side.network.scripts[side.index].delay_ns_min;
            _ = side.network.reply(socket, side.index, octets, now_ns + delay_ns);
        }
    }

    fn answer(context: *anyopaque, query: []const u8, out: []u8) ?usize {
        const side: *QuicSide = @ptrCast(@alignCast(context));
        side.draws += 1;
        const script = &side.network.scripts[side.index];
        const from = rotor.Network.server_quic_address(side.index);
        const answered = rotor.server.respond(script, &from, query, true, side.draws, out) orelse return null;
        return answered.len;
    }
};

/// The twin, the engine over it and a side for each scripted server, on the heap: an engine holds
/// a channel of over a megabyte for each server it may ask.
const World = struct {
    loop: rotor.Loop = undefined,
    memory: [0]u8 align(rotor.memory_alignment) = undefined,
    servers: [servers]cocuyo.Server = undefined,
    config: cocuyo.Config = undefined,
    engine: Resolver = undefined,
    events: [events_max]rotor.Event = undefined,
    sides: [servers]Side = undefined,
    quic_sides: [servers]QuicSide = undefined,

    fn create(seed: u64, script: server_module.Script) !*World {
        return create_over(seed, script, false);
    }

    /// A world whose servers answer over QUIC as well, on the twin's QUIC port, which their
    /// template names.
    fn create_quic(seed: u64, script: server_module.Script) !*World {
        return create_over(seed, script, true);
    }

    fn create_over(seed: u64, script: server_module.Script, quic: bool) !*World {
        const world = try testing.allocator.create(World);
        errdefer testing.allocator.destroy(world);
        world.* = .{};
        try world.loop.init(&world.memory, .{ .operations = Resolver.loop_operations });
        world.loop.seed(seed);
        world.loop.network().server_count = servers;
        for (&world.servers, 0..) |*server, index| {
            const address = rotor.Network.server_address(@intCast(index));
            server.* = .{
                .endpoint = .{ .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*), .port = address.port },
                .https = .{ .template = if (quic) quic_template else template },
            };
        }
        world.config = .{ .servers = &world.servers, .timeout_ns = timeout_ns, .failover_retry_chance = 0 };
        try world.engine.init(&world.loop, &world.config, seed, world.loop.now());
        world.engine.doh.context = .init(&anchors, @splat(@truncate(seed)), identity.unix_seconds, world.loop.now());
        for (&world.sides, &world.quic_sides, 0..) |*side, *quic_side, index| {
            side.* = .{ .index = @intCast(index), .network = world.loop.network(), .script = script };
            world.loop.network().stream_responders[index] = side.responder();
            if (!quic) continue;
            quic_side.* = .{ .index = @intCast(index), .network = world.loop.network() };
            try quic_side.server.init(script, identity.unix_seconds, world.loop.now());
            world.loop.network().responders[index] = quic_side.responder();
        }
        return world;
    }

    /// Ends the engine, drains the loop, and gives the memory back.
    fn destroy(world: *World) !void {
        defer testing.allocator.destroy(world);
        world.engine.deinit();
        try world.loop.drain(&world.events);
        world.engine.close();
        world.loop.deinit();
    }

    /// One wait of up to `wait_ns`, in ticks of rotor's longest, every event applied.
    fn step(world: *World) !void {
        var left: u64 = wait_ns;
        for (0..wait_ns / rotor.constants.wait_ns_max + 1) |_| {
            const slice = @min(left, rotor.constants.wait_ns_max);
            const count = try world.loop.tick(&world.events, slice);
            left -= slice;
            for (world.events[0..count]) |event| _ = world.engine.apply(event, world.loop.now());
            if (count > 0 or left == 0) return;
        }
    }

    /// One lookup of `name`, whose result is taken.
    fn resolve(world: *World, name: []const u8) !Resolver.Result {
        _ = try world.engine.start(try cocuyo.Question.from_text(name, .a), world.loop.now());
        for (0..rounds_max) |_| {
            if (world.engine.take(world.loop.now())) |result| {
                _ = world.engine.take(world.loop.now());
                return result;
            }
            try world.step();
        }
        return error.NoResult;
    }
};

test "a lookup through colibri's channel is answered over HTTP/2 once QUIC's datagrams go unanswered" {
    const world = try World.create(141, .{});
    const result = try world.resolve("example.com.");
    try testing.expect(result.outcome == .answer);
    // Rule 18: QUIC went first, and its fallback delay passed before TCP carried the request.
    const side = &world.sides[0];
    try testing.expectEqual(@as(usize, 1), side.entries[0].server.answered);
    try testing.expectEqual(.h2, side.entries[0].server.connection.protocol().?);
    try testing.expect(world.loop.now() >= cocuyo_doh.constants.fallback_delay_ns);
    const links = &world.engine.doh.slots[0].links;
    try testing.expect(links[@intFromEnum(Resolver.Doh.Link.tcp)].state == .running);
    try world.destroy();
}

test "a server that selects no protocol answers the engine over HTTP/1.1" {
    // Rule 20: whatever version the channel comes up on carries the GET alike.
    const world = try World.create(142, .{ .alpn = &.{} });
    const result = try world.resolve("example.com.");
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(.h11, world.sides[0].entries[0].server.connection.protocol().?);
    try world.destroy();
}

test "a channel with no request on it shuts down, closes its links, and says closed" {
    // Rule 24, over colibri's channel: the TCP link's connection ends with a GOAWAY and a
    // close_notify, QUIC's once its closing period has run, and the slot is free.
    const world = try World.create(143, .{});
    const result = try world.resolve("example.com.");
    try testing.expect(result.outcome == .answer);
    const slot = &world.engine.doh.slots[0];
    for (0..rounds_max) |_| {
        if (slot.state == .closed) break;
        try world.step();
    }
    try testing.expect(slot.state == .closed);
    for (&slot.links) |*link| try testing.expect(link.state == .down);
    try world.destroy();
}

test "a lookup through colibri's channel is answered over HTTP/3 by colibri's server over QUIC" {
    // Rule 18: QUIC first, and no TCP when its handshake ends before the fallback delay.
    const world = try World.create_quic(144, .{});
    const result = try world.resolve("example.com.");
    try testing.expect(result.outcome == .answer);
    try testing.expectEqual(@as(usize, 1), world.quic_sides[0].server.answered);
    const slot = &world.engine.doh.slots[0];
    try testing.expectEqual(.h3, slot.channel.connected().?.protocol);
    try testing.expect(slot.links[@intFromEnum(Resolver.Doh.Link.quic)].state == .running);
    try testing.expect(slot.links[@intFromEnum(Resolver.Doh.Link.tcp)].state == .down);
    try world.destroy();
}
