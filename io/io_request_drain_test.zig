//! A GOAWAY drains the engine's connection (docs/design.md §24, request rule 13), on the twin: its
//! streams go on until each is answered, a request taken meanwhile waits, and once no stream is left
//! the connection closes and opens again for it. A failure while it drains fails the requests on its
//! streams alone.
const std = @import("std");
const testing = std.testing;
const rotor = @import("rotor");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const request_test = @import("io_request_test.zig");
const question = sim_test.question;
const Rig = request_test.Rig;

/// Starts a lookup for each name, then steps until the server's GOAWAY, which it sends once it took
/// the first, and ahead of any answer: the connection drains the streams of all of them.
fn drain_first(rig: *Rig, asked: []const []const u8) !void {
    for (asked) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    var rounds: usize = 0;
    while (rig.engine.quic_connections[0].state != .draining and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try rig.step(fixtures.quic_timer_ns);
    }
    try testing.expect(rig.engine.quic_connections[0].state == .draining);
}

const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example." };

test "a request taken while its connection drains waits, and opens the next connection" {
    var rig: Rig = .{};
    try request_test.start(&rig, 131, .{ .{ .quic = .{ .goaway = true } }, .{} });
    try drain_first(&rig, &names);
    const connection = &rig.engine.quic_connections[0];
    _ = try rig.engine.start(question("e.example."), rig.loop.now());
    try testing.expectEqual(@as(u16, 1), connection.queue_len);
    var answered: usize = 0;
    while (answered < names.len + 1) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    // Nothing the GOAWAY did counts against the server (request rule 13).
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    try testing.expect(connection.incarnation >= 2);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection that fails while it drains fails its streams' requests, and opens again for what waits" {
    var rig: Rig = .{};
    try request_test.start(&rig, 132, .{ .{ .quic = .{ .goaway = true } }, .{} });
    try drain_first(&rig, &names);
    const connection = &rig.engine.quic_connections[0];
    const waiting = try rig.engine.start(question("e.example."), rig.loop.now());
    // The connection's QUIC timer gives up while it drains (request rule 11).
    connection.quic.due_ns = rig.loop.now() + fixtures.quic_timer_ns;
    connection.quic.expiry = .timeout;
    rig.engine.drive(rig.loop.now());
    var rounds: usize = 0;
    while (connection.incarnation < 2 and rounds < fixtures.until_rounds_max) : (rounds += 1) {
        _ = try rig.step(fixtures.quic_timer_ns);
    }
    // It opened again for the request that waits, which never went to the one that failed.
    try testing.expectEqual(@as(u32, 2), connection.incarnation);
    var answered: usize = 0;
    while (answered < names.len + 1) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
        if (result.handle.index == waiting.index) try testing.expectEqual(@as(u32, 2), connection.incarnation);
    }
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a draining connection whose last streams are cancelled closes, and opens again for what waits" {
    // The cancels, and not an answer, end its last stream (request rules 6 and 13).
    var rig: Rig = .{};
    try request_test.start(&rig, 133, .{ .{ .quic = .{ .goaway = true } }, .{} });
    try drain_first(&rig, &names);
    const waiting = try rig.engine.start(question("e.example."), rig.loop.now());
    for (rig.engine.handles, 0..) |handle, index| {
        // The answered request, and the waiting one, are not cancelled.
        if (index == waiting.index or !rig.engine.requests[index].live) continue;
        rig.engine.cancel(handle, rig.loop.now());
    }
    try testing.expect(rig.engine.quic_connections[0].state == .closing);
    var rounds: usize = 0;
    while (rounds < fixtures.until_rounds_max) : (rounds += 1) {
        const result = try rig.until_result();
        if (result.handle.index != waiting.index) continue;
        try testing.expect(result.outcome == .answer);
        break;
    }
    try testing.expect(rig.engine.quic_connections[0].incarnation >= 2);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
