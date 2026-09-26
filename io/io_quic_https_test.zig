//! The engine over colibri's HTTP/3 on the twin (docs/design.md §24, DoH over HTTP/3): colibri's
//! `h3` client in the engine, colibri's `h3` server behind each scripted server's QUIC port, both
//! over the session that encrypts nothing. Real packets, streams, QPACK and flow control, on the
//! twin's clock.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const cocuyo_quic = @import("cocuyo_quic");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const quic_test = @import("io_quic_test.zig");
const question = sim_test.question;

/// An engine that speaks DoH over colibri, with fewer answer buffers on a connection than lookups.
const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
    .quic = cocuyo_quic.Connection(.{ .streams = fixtures.small_lookups, .http3 = true, .answers = fixtures.doh_answers }),
});
const Rig = sim_test.RigOf(Resolver);
const Side = quic_test.SideOf(cocuyo_quic.server_h3.Server(fixtures.small_lookups));
const World = quic_test.WorldOf(Rig, Side);

/// The twin's scripted servers take QUIC on 853, so the template names it.
const template = "https://dns.example:853/dns-query{?dns}";

test "a lookup over DoH is answered through colibri's HTTP/3 client and server on the twin" {
    const world = try World.create_https(101, .{ .{}, .{} }, template);
    defer world.free();
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(world.rig.engine.quic.connections[0].state == .up);
    try testing.expectEqual(@as(usize, 1), world.sides[0].entries[0].server.answered);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "the Age colibri's server writes lowers the answer's TTLs" {
    const world = try World.create_https(102, .{ .{ .ttl_seconds = 600 }, .{} }, template);
    defer world.free();
    world.sides[0].script.age = "250";
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(u32, 350), result.outcome.answer.ttl_seconds);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

/// A lookup whose first server's responses are as `script` says: it fails over, counted once.
fn expect_failed_over(seed: u64, script: @FieldType(Side, "script")) !void {
    const world = try World.create_https(seed, .{ .{}, .{} }, template);
    defer world.free();
    world.sides[0].script = script;
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), world.rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(usize, 1), world.sides[1].entries[0].server.answered);
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "a 404, a coded answer or another media type from colibri's server fails over" {
    try expect_failed_over(103, .{ .status = "404" });
    try expect_failed_over(104, .{ .content_encoding = "gzip" });
    try expect_failed_over(105, .{ .content_type = "text/html" });
    try expect_failed_over(106, .{ .other_protocol = true });
}

test "an interim response before the answer changes nothing" {
    const world = try World.create_https(107, .{ .{}, .{} }, template);
    defer world.free();
    world.sides[0].script.interim = true;
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), world.rig.engine.resolver.servers.failures(0));
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "more lookups than a connection has answer buffers are all answered on it, in turn" {
    // Two rounds of as many lookups as the engine holds, which is as many request slots as the
    // connection has: the first round's slots come back once the server has each GET.
    const world = try World.create_https(108, .{ .{}, .{} }, template);
    defer world.free();
    // Names of their own, so no round is answered from the cache.
    const rounds = [_][fixtures.small_lookups][]const u8{
        .{ "a.example.", "b.example.", "c.example.", "d.example.", "e.example.", "f.example." },
        .{ "g.example.", "h.example.", "i.example.", "j.example.", "k.example.", "l.example." },
    };
    for (rounds) |names| {
        for (names) |name| _ = try world.rig.engine.start(question(name), world.rig.loop.now());
        for (names) |_| {
            const result = try world.rig.until_result();
            try testing.expect(result.outcome == .answer);
        }
        // The last result's lookup is the caller's until the next `take`.
        _ = world.rig.engine.take(world.rig.loop.now());
        _ = try world.rig.step(fixtures.wait_ns);
    }
    try testing.expectEqual(@as(usize, rounds.len * fixtures.small_lookups), world.sides[0].entries[0].server.answered);
    try testing.expect(world.sides[0].entries[1].socket == null);
    try testing.expectEqual(@as(u8, 0), world.rig.engine.resolver.servers.failures(0));
    _ = world.rig.engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "lookups cancelled over DoH give their answer buffers and their slots back" {
    // More cancelled lookups than the connection has buffers or request slots: kept, they would
    // leave none.
    const world = try World.create_https(109, .{ .{}, .{} }, template);
    defer world.free();
    const engine = &world.rig.engine;
    var cancelled: usize = 0;
    while (cancelled < fixtures.small_lookups + 1) : (cancelled += 1) {
        const handle = try engine.start(question("example.com."), world.rig.loop.now());
        var rounds: usize = 0;
        while (engine.quic.connections[0].streams == 0 and rounds < fixtures.until_rounds_max) : (rounds += 1) {
            _ = try world.rig.step(fixtures.wait_ns);
        }
        try testing.expectEqual(@as(u16, 1), engine.quic.connections[0].streams);
        engine.cancel(handle, world.rig.loop.now());
        _ = try world.rig.until_result();
        _ = engine.take(world.rig.loop.now());
        _ = try world.rig.step(fixtures.wait_ns);
    }
    _ = try engine.start(question("example.com."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "a GOAWAY closes the connection once the answer it came with is read, and the next opens anew" {
    // colibri's server sends GOAWAY with its answer, in one datagram, and `h3` reads the control
    // stream first: the answer is still the lookup's.
    const world = try World.create_https(110, .{ .{}, .{} }, template);
    defer world.free();
    world.sides[0].script.goaway = true;
    const engine = &world.rig.engine;
    _ = try engine.start(question("one.example."), world.rig.loop.now());
    const first = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), first.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), engine.resolver.servers.failures(0));
    _ = engine.take(world.rig.loop.now());
    var rounds: usize = 0;
    while (engine.quic.connections[0].state != .closed and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.wait_ns);
    }
    try testing.expect(engine.quic.connections[0].state == .closed);
    _ = try engine.start(question("two.example."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u32, 2), engine.quic.connections[0].incarnation);
    _ = engine.take(world.rig.loop.now());
    try world.rig.deinit();
}

test "an idle DoH connection closes with CONNECTION_CLOSE, which colibri's server hears" {
    const world = try World.create_https(111, .{ .{}, .{} }, template);
    defer world.free();
    _ = try world.rig.engine.start(question("example.com."), world.rig.loop.now());
    _ = try world.rig.until_result();
    _ = world.rig.engine.take(world.rig.loop.now());
    const connection = &world.rig.engine.quic.connections[0];
    var rounds: usize = 0;
    while (connection.state != .closed and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.tcp_idle_jump_ns);
        world.rig.engine.drive(world.rig.loop.now());
    }
    try testing.expect(connection.state == .closed);
    try testing.expect(world.sides[0].entries[0].server.connection.termination.state != .active);
    // H3_NO_ERROR, which colibri gives the first time it is asked (RFC 9114 §8.1).
    try testing.expectEqual(@as(?u64, cocuyo_quic.constants.h3_no_error), world.sides[0].entries[0].server.close_code);
    try world.rig.deinit();
}

test "a DoH request's bytes outlive its answer, and colibri sends them again until the server has them" {
    // As over DoQ: the server's acknowledgement of the first GET is lost and its response arrives,
    // so colibri sends the GET again at its probe timeout, reading the bytes the answer has not
    // freed (RFC 9000 §13.3).
    const world = try World.create_https(112, .{ .{}, .{} }, template);
    defer world.free();
    world.sides[0].answers_unacknowledged = 1;
    const engine = &world.rig.engine;
    _ = try engine.start(question("one.example."), world.rig.loop.now());
    _ = try world.rig.until_result();
    _ = engine.take(world.rig.loop.now());
    try testing.expect(world.sides[0].acks_lost > 0);
    const client = &engine.quic.connections[0].transport.connection;
    const first = cocuyo_quic.server.StreamId.of(.client, .bidirectional, 0);
    var rounds: usize = 0;
    while (client.streams.lookup(first) != .closed and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try world.rig.step(fixtures.wait_ns);
    }
    try testing.expect(client.streams.lookup(first) == .closed);
    _ = try engine.start(question("two.example."), world.rig.loop.now());
    const result = try world.rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(usize, 2), world.sides[0].entries[0].server.answered);
    _ = engine.take(world.rig.loop.now());
    try world.rig.deinit();
}
