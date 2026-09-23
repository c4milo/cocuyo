//! What a consumer does to the engine besides asking it questions (docs/design.md §19 step 13):
//! cancelling everything at once, taking a new configuration, binding to a local address of its
//! own, and retiring a source port that has carried its share, or failing to. The rig is the one
//! `io_sim_test.zig` builds, since these drive the same engine over the same scripted servers.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;
const endpoint_of = sim_test.endpoint_of;

test "cancel_all ends every lookup, and the caller is told about each" {
    var rig: Rig = .{};
    try rig.init(21, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{} });
    var started: usize = 0;
    var buffer: [fixtures.name_text_bytes]u8 = undefined;
    while (started < fixtures.small_lookups) : (started += 1) {
        const text = try std.fmt.bufPrint(&buffer, "h{d}.example.", .{started});
        _ = try rig.engine.start(question(text), rig.loop.now());
    }
    rig.engine.cancel_all(rig.loop.now());
    var ended: usize = 0;
    while (ended < fixtures.small_lookups) : (ended += 1) {
        const result = try rig.until_result();
        try testing.expectEqual(cocuyo.Error.Canceled, result.outcome.failure.err);
    }
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(usize, 0), rig.engine.active());
    try rig.deinit();
}

test "reinit cancels what is in flight, empties the cache, and asks the new servers" {
    var rig: Rig = .{};
    try rig.init(22, .{ .{}, .{} }, .{ .servers = &.{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const first = try rig.until_result();
    try testing.expect(first.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    // A lookup is in flight when the configuration goes, so the caller ends it and takes what it
    // lost before it reinits: the engine must be idle.
    _ = try rig.engine.start(question("other.example."), rig.loop.now());
    rig.engine.cancel_all(rig.loop.now());
    const cancelled = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Canceled, cancelled.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(usize, 0), rig.engine.active());

    var servers = [_]cocuyo.Server{.{ .endpoint = endpoint_of(rotor.Network.server_address(1)) }};
    const replacement: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    try rig.engine.reinit(&replacement, 22, rig.loop.now());
    // The cache went with the servers that filled it, so the name is asked about again.
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    // Nothing is waiting to be taken, so the cache did not answer it: it goes to a server.
    try testing.expect(rig.engine.take(rig.loop.now()) == null);
    const answer = try rig.until_result();
    try testing.expect(answer.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    // The new cache is under the new table: the answer the new server gave is remembered.
    const again = try rig.engine.start(question("example.com."), rig.loop.now());
    const hit = rig.engine.take(rig.loop.now()).?;
    try testing.expectEqual(again, hit.handle);
    try rig.deinit();
}

test "a socket binds to the local address the caller named" {
    var rig: Rig = .{};
    const local = cocuyo.Address.from_v4(fixtures.local_octets);
    try rig.init(23, .{ .{}, .{} }, .{ .servers = &.{}, .local_address = local });
    const descriptor = rig.engine.sockets.descriptor_of(0);
    const bound = rig.loop.network().socket(descriptor).local;
    try testing.expectEqualSlices(u8, &fixtures.local_octets, bound.bytes[0..fixtures.local_octets.len]);
    // The port is still the seed's, which is the entropy of RFC 5452 §9.2.
    try testing.expect(bound.port >= cocuyo.constants.port_ephemeral_min);
    try rig.deinit();
}

test "a local address of another family is not bound to a socket of this one" {
    // An IPv6 address cannot name a local endpoint for an IPv4 socket, and binding it would be
    // asking the host for something that does not exist.
    var rig: Rig = .{};
    const local = cocuyo.Address.from_v6(fixtures.local_v6_octets);
    try rig.init(25, .{ .{}, .{} }, .{ .servers = &.{}, .local_address = local });
    const bound = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local;
    try testing.expectEqual(rotor.Address.Family.ipv4, bound.family);
    // Unspecified, and not the first four octets of an address that names another family.
    try testing.expectEqualSlices(u8, &fixtures.unspecified_v4, bound.bytes[0..fixtures.unspecified_v4.len]);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the sockets take the buffer sizes the caller asked for" {
    var rig: Rig = .{};
    try rig.init(26, .{ .{}, .{} }, .{
        .servers = &.{},
        .socket_receive_bytes = fixtures.socket_bytes_granted,
        .socket_send_bytes = fixtures.socket_bytes_granted,
    });
    const entry = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0));
    try testing.expectEqual(@as(u32, fixtures.socket_bytes_granted), entry.receive_buffer_bytes);
    try testing.expectEqual(@as(u32, fixtures.socket_bytes_granted), entry.send_buffer_bytes);
    try rig.deinit();
}

test "a size the kernel caps or refuses leaves the socket working with what it has" {
    // What a kernel grants is rarely what it was asked for: it may cap, and it may refuse. A
    // socket that did not take the size still resolves.
    var rig: Rig = .{};
    try rig.init(27, .{ .{}, .{} }, .{ .servers = &.{}, .socket_receive_bytes = fixtures.socket_bytes_capped });
    const capped = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).receive_buffer_bytes;
    try testing.expect(capped > 0 and capped < fixtures.socket_bytes_capped);
    try rig.deinit();

    var refused: Rig = .{};
    try refused.init(28, .{ .{}, .{} }, .{ .servers = &.{}, .socket_receive_bytes = fixtures.socket_bytes_refused });
    const entry = refused.loop.network().socket(refused.engine.sockets.descriptor_of(0));
    try testing.expectEqual(@as(u32, 0), entry.receive_buffer_bytes);
    _ = try refused.engine.start(question("example.com."), refused.loop.now());
    try testing.expect((try refused.until_result()).outcome == .answer);
    _ = refused.engine.take(refused.loop.now());
    try refused.deinit();
}

test "a source port that has carried its share is replaced once nothing waits on it" {
    var rig: Rig = .{};
    try rig.init(24, .{ .{}, .{} }, .{ .servers = &.{}, .udp_queries_per_port = 1 });
    const before = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    // The query has gone out, so the port has carried its share; the lookup is still waiting for
    // its answer, and a port is never taken from a query that is.
    _ = try rig.step(0);
    try testing.expect(rig.engine.sockets.is_retiring(0));
    try testing.expectEqual(before, rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port);
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    // The twin hands out descriptor numbers again once they are closed, so the port is what
    // says the socket is another one.
    try testing.expect(rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port != before);
    try testing.expect(!rig.engine.sockets.is_retiring(0));
    // The new port answers as the old one did.
    _ = try rig.engine.start(question("other.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a port that cannot be replaced leaves its server no socket, and a send to it fails over" {
    var rig: Rig = .{};
    try rig.init(25, .{ .{}, .{} }, .{ .servers = &.{}, .udp_queries_per_port = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expect(rig.engine.sockets.is_retiring(0));
    // No descriptor is left when the port comes to be replaced (docs/design.md §19 step 13, the
    // datagram's rule 4): the server has no socket, and the program goes on.
    rig.loop.network().refuse_open = true;
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(!rig.engine.sockets.is_open(0));
    // The next lookup asks server 0 first. Its send fails as any send fails, and server 1
    // answers it.
    _ = try rig.engine.start(question("other.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    // Descriptors come back, and the next drive gives the server a socket again.
    rig.loop.network().refuse_open = false;
    rig.engine.drive(rig.loop.now());
    try testing.expect(rig.engine.sockets.is_open(0));
    try rig.deinit();
}
