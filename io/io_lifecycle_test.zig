//! What a consumer does to the engine besides asking it questions (docs/design.md §19 step 13):
//! cancelling everything at once, taking a new configuration, binding to a local address of its
//! own, and retiring a source port that has carried its share, or failing to. Then the payload
//! sizes that `init` and `reinit` refuse (docs/design.md §19 step 13, the datagram's rule 7). Last,
//! a `reinit` keeps a slot whose records buffer a query's send over TLS reads (§21, TLS rule 3).
//! The rig is the one `io_sim_test.zig` builds, since these drive the same engine over the same
//! scripted servers.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const tcp_test = @import("io_tcp_test.zig");
const failing_test = @import("io_tls_failing_test.zig");
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
    try rig.engine.reinit(&replacement, rig.cache_memory.slices(), 22, rig.loop.now());
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

test "a source port that has carried its share is replaced at once, and the old one drains" {
    var rig: Rig = .{};
    try rig.init(24, .{ .{}, .{} }, .{ .servers = &.{}, .udp_queries_per_port = 1 });
    const before = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    // The query has gone out, so the port has carried its share, and a new one takes every
    // query from now on while the lookup still waits (docs/design.md §19 step 13, the datagram's
    // rule 4). The old socket drains: its answer comes back to it.
    _ = try rig.step(0);
    const after = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port;
    try testing.expect(after != before);
    try testing.expect(rig.engine.sockets.draining[0].open);
    try testing.expect(!rig.engine.sockets.items[0].retiring);
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    // Nothing is owed on the old socket any more, so it is gone.
    try testing.expect(!rig.engine.sockets.draining[0].open);
    // The new port answers as the old one did.
    _ = try rig.engine.start(question("other.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a port that cannot be replaced stays in use until one can be opened" {
    var rig: Rig = .{};
    try rig.init(25, .{ .{}, .{} }, .{ .servers = &.{}, .udp_queries_per_port = 1 });
    const before = rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port;
    // No descriptor is left when the port comes to be replaced: the old socket stays the one
    // queries leave from, and the program goes on (the datagram's rule 4).
    rig.loop.network().refuse_open = true;
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(rig.engine.sockets.items[0].retiring);
    try testing.expectEqual(before, rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port);
    // Descriptors come back, and the next drive replaces the port.
    rig.loop.network().refuse_open = false;
    rig.engine.drive(rig.loop.now());
    try testing.expect(!rig.engine.sockets.items[0].retiring);
    try testing.expect(rig.loop.network().socket(rig.engine.sockets.descriptor_of(0)).local.port != before);
    try rig.deinit();
}

test "a receive's generation and a socket's epoch wrap at the last of their thirty-two bits" {
    // The generation tells the receives apart, and the epoch the sockets (docs/design.md §19 step
    // 13, the datagram's rule 4). Each query here replaces its port. The first replacement arms
    // the largest generation, which fills the index above the server's octet, at the largest
    // epoch. The second wraps both to zero.
    var rig: Rig = .{};
    try rig.init(26, .{ .{}, .{} }, .{ .servers = &.{}, .udp_queries_per_port = 1 });
    rig.engine.sockets.next_generation = std.math.maxInt(u32) - 1;
    rig.engine.sockets.next_epoch = std.math.maxInt(u32) - 1;
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), rig.engine.sockets.items[0].armed_generation);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), rig.engine.sockets.items[0].epoch);
    // The next query leaves from that socket, and its answer comes back to that receive. A
    // receive that did not find its socket would drop the answer, and the lookup would wait out
    // its try and count a failure against the server.
    const sent_ns = rig.loop.now();
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    try testing.expect(rig.loop.now() - sent_ns < cocuyo.constants.timeout_ns_default);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(u32, 0), rig.engine.sockets.items[0].armed_generation);
    try testing.expectEqual(@as(u32, 0), rig.engine.sockets.items[0].epoch);
    try rig.deinit();
}

/// The sockets the twin holds open, whoever opened them.
fn open_sockets(loop: *rotor.Loop) usize {
    var count: usize = 0;
    for (loop.network().sockets) |socket| count += @intFromBool(socket.open);
    return count;
}

/// The payload size that the query of `handle`'s lookup advertises in its OPT record (RFC 6891
/// §6.1.2). A query over UDP starts at the first octet of its slot's buffer.
fn advertised(engine: anytype, handle: cocuyo.Handle) !u16 {
    const query = &engine.send_buffers[handle.index];
    var name: cocuyo.Name = cocuyo.Name.empty;
    _ = try cocuyo.wire.question.parse(query, &name);
    const opt = (try cocuyo.wire.response_opt.find(query, &name)) orelse return error.NoOpt;
    return opt.class;
}

/// A configuration of the rig's servers that advertises `payload_bytes`.
fn advertising(rig: *const Rig, payload_bytes: usize) cocuyo.Config {
    var config = rig.config;
    config.udp_payload_bytes = @intCast(payload_bytes);
    return config;
}

/// What a refused `reinit` keeps of the stream in the engine's first slot: its state, its socket,
/// its receive and its opening.
const Stream = struct { up: bool, descriptor: ?rotor.Descriptor, receive: ?rotor.Handle, receiving: bool, incarnation: u32 };

fn stream_of(engine: anytype) Stream {
    const connection = &engine.connections[0];
    return .{
        .up = connection.state == .up,
        .descriptor = connection.descriptor,
        .receive = connection.handle,
        .receiving = connection.receiving,
        .incarnation = connection.incarnation,
    };
}

test "init takes a payload at the room of a datagram buffer, and refuses one octet more" {
    // "The requestor SHOULD place a value in this field that it can actually receive" (RFC 6891
    // §6.2.3). The engine receives into a buffer of its datagram group (docs/design.md §19 step
    // 13, the datagram's rule 7).
    const room = io.constants.udp_payload_bytes_max;
    var refused: Rig = .{};
    @memset(std.mem.asBytes(&refused.engine), fixtures.memory_mark);
    const past: cocuyo.Config = .{ .servers = &.{}, .udp_payload_bytes = @intCast(room + 1) };
    try testing.expectError(error.UdpPayloadTooLarge, refused.init(51, .{ .{}, .{} }, past));
    // The check came first: the engine's memory is as it was, and no buffer or socket is taken.
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&refused.engine), fixtures.memory_mark));
    try testing.expectEqual(@as(u16, 0), refused.loop.groups[io.constants.group_id].count);
    try testing.expectEqual(@as(usize, 0), open_sockets(&refused.loop));
    refused.loop.deinit();

    var rig: Rig = .{};
    try rig.init(52, .{ .{}, .{} }, .{ .servers = &.{}, .udp_payload_bytes = @intCast(room) });
    // The room is what a buffer of the loop's group holds, under the options the engine gave it.
    const holds = rotor.datagram.payload_capacity(io.constants.buffer_bytes, rig.loop.group_options);
    try testing.expectEqual(room, holds);
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(u16, @intCast(room)), try advertised(&rig.engine, handle));
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "reinit refuses a payload one octet past the room, and the engine keeps what it held" {
    // The first server cuts each answer over UDP, so the lookup asks it again over a stream (RFC
    // 7766 §5). Then the stream stays up and idle beside the socket.
    var rig: Rig = .{};
    try rig.init(53, .{ .{ .truncate_per_256 = fixtures.always }, .{} }, .{ .servers = &.{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    const socket = rig.engine.sockets.items[0];
    const stream = stream_of(&rig.engine);
    try testing.expect(stream.up and stream.receiving);
    const sockets_open = open_sockets(&rig.loop);
    const past = advertising(&rig, io.constants.udp_payload_bytes_max + 1);
    var other: cocuyo.cache.Storage(fixtures.cache_least_slots) = undefined;
    @memset(std.mem.asBytes(&other), fixtures.memory_mark);
    const refused = rig.engine.reinit(&past, other.slices(), 54, rig.loop.now());
    try testing.expectError(error.UdpPayloadTooLarge, refused);
    // Nothing changed: the configuration, the cache over the memory it held, and the socket and
    // the stream, each with its receive. The memory of the call is the caller's, and the engine
    // never wrote it.
    try testing.expectEqual(@as(*const cocuyo.Config, &rig.config), rig.engine.config);
    try testing.expectEqual(@as([*]cocuyo.cache.Slot, &rig.cache_memory.slots), rig.engine.cache.?.slots.ptr);
    try testing.expectEqual(@as(u64, 53), rig.engine.cache.?.seed);
    try testing.expectEqual(socket, rig.engine.sockets.items[0]);
    try testing.expectEqual(stream, stream_of(&rig.engine));
    try testing.expectEqual(sockets_open, open_sockets(&rig.loop));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&other), fixtures.memory_mark));
    // The cache still holds the answer, so nothing goes out for it.
    const hit = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(hit, rig.engine.take(rig.loop.now()).?.handle);
    _ = rig.engine.take(rig.loop.now());

    // At the room the reinit takes the configuration, and its queries advertise the room.
    const at = advertising(&rig, io.constants.udp_payload_bytes_max);
    try rig.engine.reinit(&at, rig.cache_memory.slices(), 55, rig.loop.now());
    try testing.expectEqual(@as(*const cocuyo.Config, &at), rig.engine.config);
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(u16, @intCast(io.constants.udp_payload_bytes_max)), try advertised(&rig.engine, handle));
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// One server and one connection slot over the twin's TLS, the least that TLS rule 6 allows.
const OneSlotTlsRig = sim_test.RigOfServers(io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 1,
    .tls = rotor.tls.Session,
}), 1);

test "a reinit keeps a slot whose records a query's send reads until that send's event" {
    try expect_reinit_waits(true, 68);
    try expect_reinit_waits(false, 69);
}

/// A lookup's query over TLS is in flight when the caller cancels each lookup and calls `reinit`.
/// The new configuration speaks TLS when `tls` says so, and the clear otherwise. The loop holds the
/// send's event back. The slot stays closed and lent (§21, TLS rule 3), and a new lookup waits for
/// it (the stream's rule 12). The send's event frees the slot, whatever the engine speaks then.
fn expect_reinit_waits(tls: bool, seed: u64) !void {
    var rig: OneSlotTlsRig = .{};
    try tls_test.encrypt(&rig);
    try rig.init(seed, .{.{}}, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
    rig.use_test_contexts();
    const first = try rig.engine.start(question("example.com."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    try failing_test.until_query_in_flight(&rig);
    const lent = io.tls.pending(&rig.engine, 0, connection.queue.first().?.end);
    var sealed: [io.constants.tls_records_out_bytes]u8 = undefined;
    @memcpy(sealed[0..lent.len], lent);
    rig.engine.cancel_all(rig.loop.now());
    const cancelled = rig.engine.take(rig.loop.now()) orelse return error.NoResult;
    try testing.expectEqual(cocuyo.Error.Canceled, cancelled.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    var servers = rig.servers;
    if (!tls) servers[0].tls = null;
    const config: cocuyo.Config = .{ .servers = &servers, .use_tcp = !tls, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 };
    try rig.engine.reinit(&config, rig.cache_memory.slices(), seed + 1, rig.loop.now());
    try testing.expect(connection.state == .closed);
    try testing.expectEqual(@as(?u16, first.index), connection.records_send);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    const send = @TypeOf(rig.engine).user_data(.tcp_send, first.index);
    var held: ?rotor.Event = null;
    for (0..fixtures.until_rounds_max) |_| {
        if (held != null) break;
        try tcp_test.step_holding(&rig, send, &held);
    }
    // The octets the loop may still read are the ones it was lent, and the lookup still waits.
    try testing.expect(held != null and connection.state == .closed);
    try testing.expectEqualSlices(u8, sealed[0..lent.len], lent);
    try testing.expectEqual(@as(u16, 1), rig.engine.tcp_waiters);
    _ = rig.engine.apply(held.?, rig.loop.now());
    try testing.expect(connection.state == .connecting and connection.records_send == null);
    try testing.expectEqual(@as(u16, 0), rig.engine.tcp_waiters);
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
