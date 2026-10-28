//! A datagram at the room that a buffer of the engine's datagram group gives it (docs/design.md
//! §19 step 13, the datagram's rules 3 and 6). That room is `buffer_bytes_max`, 2,048 octets, less
//! rotor's prefix of 192 octets: 1,856 octets. The twin carries 1,232 octets at most, so each test
//! writes the completion of a receive itself, into a buffer of the group, as the kernel writes one.
//! Last, a receive that ends on the event that carries a datagram (rule 1). Split from
//! `io_sim_test.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;
const fixtures = @import("fixtures.zig");

const integer = cocuyo.wire.integer;
const u16_bytes = cocuyo.wire.constants.u16_bytes;

/// The octets of a datagram that fill a buffer of the group after rotor's prefix.
fn room(rig: anytype) usize {
    return rotor.datagram.payload_capacity(io.limits.buffer_bytes_max, rig.loop.group_options);
}

/// The scripted server's answer to the query of `handle`'s lookup, written into `out`. A Padding
/// option of zeros (RFC 7830 §3) grows its OPT record, the last record, until the message is
/// `total` octets.
fn padded_answer(rig: anytype, handle: cocuyo.Handle, total: usize, out: []u8) ![]const u8 {
    const server = rotor.Network.server_address(0);
    const query = &rig.engine.send_buffers[handle.index];
    const answer = rotor.server.respond(&.{}, &server, query, false, 0, out) orelse return error.NoAnswer;
    var name: cocuyo.Name = cocuyo.Name.empty;
    _ = try cocuyo.wire.question.parse(out[0..answer.len], &name);
    const opt = (try cocuyo.wire.response_opt.find(out[0..answer.len], &name)) orelse return error.NoOpt;
    try testing.expectEqual(answer.len, opt.end);
    const padding = total - answer.len - cocuyo.constants.opt_option_header_bytes;
    integer.write_u16(out, answer.len, cocuyo.wire.constants.padding_option_code);
    integer.write_u16(out, answer.len + u16_bytes, @intCast(padding));
    @memset(out[answer.len + cocuyo.constants.opt_option_header_bytes ..][0..padding], 0);
    const rdlength_at = opt.end - opt.rdata.len - u16_bytes;
    integer.write_u16(out, rdlength_at, @intCast(total - (opt.end - opt.rdata.len)));
    return out[0..total];
}

/// Hands the engine a completion of server `server`'s current receive, as the kernel writes one:
/// the octets that fit the room of a buffer, and the truncated flag when the datagram was longer.
fn deliver(rig: anytype, server: u8, datagram: []const u8) !void {
    try deliver_to(rig, server, rig.engine.sockets.items[server].armed_generation, datagram);
}

/// The same, on the receive of server `server`'s socket armed as `generation`: its current one,
/// or the one that drains.
fn deliver_to(rig: anytype, server: u8, generation: usize, datagram: []const u8) !void {
    const group = &rig.loop.groups[io.constants.group_id];
    const id = group.take() orelse return error.NoBuffer;
    const buffer = rig.loop.provided_buffer(io.constants.group_id, id);
    const peer = rotor.Network.server_address(server);
    const kept = datagram[0..@min(datagram.len, room(rig))];
    const len = rotor.buffers.write_delivery(buffer, rig.loop.group_options, &peer, kept);
    const metadata = buffer[rotor.constants.prefix_head_bytes..][0..@sizeOf(rotor.datagram.Received)];
    const received: *rotor.datagram.Received = @ptrCast(@alignCast(metadata));
    received.flags.truncated = datagram.len > kept.len;
    const index = @as(usize, server) | (generation << io.constants.receive_generation_shift);
    const event: rotor.Event = .{
        .user_data = @TypeOf(rig.engine).user_data(.udp_receive, index),
        .result = @intCast(len),
        .flags = .{ .buffer = true, .more = true, .buffer_id = id },
    };
    try testing.expect(rig.engine.apply(event, rig.loop.now()));
}

/// A lookup whose query went to server 0, which is down, so only the test answers it.
fn waiting(rig: anytype, seed: u64) !cocuyo.Handle {
    return waiting_under(rig, seed, .{ .servers = &.{} });
}

/// The same, under `config`.
fn waiting_under(rig: anytype, seed: u64, config: cocuyo.Config) !cocuyo.Handle {
    try rig.init(seed, .{ .{ .down = true }, .{ .down = true } }, config);
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(usize, 1), rig.engine.active());
    return handle;
}

test "a datagram that fills a buffer of the group to its last octet is read whole, and answers" {
    var rig: Rig = .{};
    const handle = try waiting(&rig, 31);
    // 2,048 octets, less rotor's prefix: the room a datagram has.
    try testing.expectEqual(@as(usize, 1856), room(&rig));
    var out: [io.limits.buffer_bytes_max]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig), &out);
    const free = rig.loop.groups[io.constants.group_id].free_count;
    try deliver(&rig, 0, answer);
    // The table read the datagram, and its buffer went back (rule 3).
    try testing.expectEqual(free, rig.loop.groups[io.constants.group_id].free_count);
    const result = rig.engine.take(rig.loop.now()) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(handle, result.handle);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a datagram one octet longer than the room is taken as truncated, and its lookup asks over TCP" {
    // The kernel keeps the octets that fit, and says that the datagram was truncated. Its header
    // and question are whole and pass the checks of a cut datagram, so the lookup asks the same
    // server over TCP, as for an answer with TC set (docs/design.md §7, A datagram that the buffer
    // cut).
    var rig: Rig = .{};
    const handle = try waiting(&rig, 32);
    // The UDP query went to a server that was down. It answers from now on, over TCP too.
    rig.loop.network().scripts[0] = .{};
    var out: [io.limits.buffer_bytes_max]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig) + 1, &out);
    const free = rig.loop.groups[io.constants.group_id].free_count;
    try deliver(&rig, 0, answer);
    try testing.expectEqual(free, rig.loop.groups[io.constants.group_id].free_count);
    try testing.expectEqual(cocuyo.resolver.State.connecting_tcp, rig.engine.resolver.lookup_of(handle).state);
    // A copy that comes once the lookup is on its way to a stream is ignored (rule 1 of §7, A
    // datagram that the buffer cut).
    try deliver(&rig, 0, answer);
    try testing.expectEqual(cocuyo.resolver.State.connecting_tcp, rig.engine.resolver.lookup_of(handle).state);
    const result = try rig.until_result();
    try testing.expectEqual(handle, result.handle);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    // The answer came over a connection to the server that sent the cut datagram.
    try testing.expect(rig.engine.connections[0].state == .up);
    try testing.expectEqual(@as(u8, 0), rig.engine.connections[0].server);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a cut datagram that fails a check of section 7 is ignored, and its lookup waits on" {
    // The same cut answer from the other server fails check 3. It is ignored, as each datagram
    // that fails a check is, and no connection opens (docs/design.md §7).
    var rig: Rig = .{};
    const handle = try waiting(&rig, 33);
    var out: [io.limits.buffer_bytes_max]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig) + 1, &out);
    const free = rig.loop.groups[io.constants.group_id].free_count;
    try deliver(&rig, 1, answer);
    try testing.expectEqual(free, rig.loop.groups[io.constants.group_id].free_count);
    try testing.expectEqual(cocuyo.resolver.State.awaiting_udp, rig.engine.resolver.lookup_of(handle).state);
    try testing.expect(rig.engine.take(rig.loop.now()) == null);
    try testing.expect(rig.engine.connections[0].state == .closed);
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a cut datagram on a draining socket moves its lookup to TCP, and the drive closes that socket" {
    // The query left a port that then carried its share, and that port drains (the datagram's
    // rule 4). The cut answer comes to that socket's receive. Its lookup moves to a stream, so
    // nothing is owed on the socket any more, and the drive closes it (rules 4 and 6).
    var rig: Rig = .{};
    const handle = try waiting_under(&rig, 36, .{ .servers = &.{}, .udp_queries_per_port = 1 });
    try testing.expect(rig.engine.sockets.draining[0].open);
    var out: [io.limits.buffer_bytes_max]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig) + 1, &out);
    try deliver_to(&rig, 0, rig.engine.sockets.draining[0].armed_generation, answer);
    try testing.expectEqual(cocuyo.resolver.State.connecting_tcp, rig.engine.resolver.lookup_of(handle).state);
    try testing.expect(!rig.engine.sockets.draining[0].open);
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// An engine that keeps no TCP connection, as one built for DoQ alone does.
const Streamless = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
});

test "on an engine of no TCP connection a cut datagram moves its lookup to the next server over UDP" {
    // The stream that the cut datagram asks for fails at once, and counts against the server. The
    // next server is asked over UDP: a retry that an off-path attacker can race (docs/design.md §7).
    var rig: sim_test.RigOf(Streamless) = .{};
    const handle = try waiting(&rig, 34);
    // The second server answers from now on.
    rig.loop.network().scripts[1] = .{};
    var out: [io.limits.buffer_bytes_max]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig) + 1, &out);
    try deliver(&rig, 0, answer);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.lookup_of(handle).server_slot());
    const result = try rig.until_result();
    try testing.expectEqual(handle, result.handle);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "under ignore_truncation a cut datagram is ignored, and its lookup waits on" {
    // That caller asked to read a truncated answer in place of TCP, and the cut left no whole
    // message to read (docs/design.md §7, A datagram that the buffer cut, rule 1).
    var rig: Rig = .{};
    const handle = try waiting_under(&rig, 35, .{ .servers = &.{}, .ignore_truncation = true });
    var out: [io.limits.buffer_bytes_max]u8 = undefined;
    const answer = try padded_answer(&rig, handle, room(&rig) + 1, &out);
    try deliver(&rig, 0, answer);
    try testing.expectEqual(cocuyo.resolver.State.awaiting_udp, rig.engine.resolver.lookup_of(handle).state);
    try testing.expect(rig.engine.connections[0].state == .closed);
    rig.engine.cancel(handle, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a receive that ends on a datagram has the datagram read, and is armed again" {
    // rotor's io_uring backend can end a multishot with the event that carries a datagram. Here
    // each receive ends on its first, so every answer comes on a final event (rules 1 and 3).
    var rig: Rig = .{};
    try rig.init(37, .{ .{}, .{} }, .{ .servers = &.{}, .failover_retry_chance = 0 });
    rig.loop.network().multishot_deliveries_max = 1;
    const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example." };
    for (names) |name| _ = try rig.engine.start(question(name), rig.loop.now());
    const armed = rig.engine.sockets.items[0].armed_generation;
    for (names) |_| {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expect(rig.engine.sockets.items[0].armed_generation >= armed + names.len);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
