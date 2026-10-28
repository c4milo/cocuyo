//! The framing of the stream path on the twin (docs/design.md §19 step 13, the stream's rule 11).
//! A frame holds a message at its longest and one chunk. Every whole message a chunk completes
//! goes to the table with it. A prefix is read once both its octets have come, and a prefix
//! longer than the connection assembles fails it. Split from `io_tcp_test.zig` by the file-length
//! rule. The rigs are the ones `io_sim_test.zig` and `io_tls_test.zig` build.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");
const tcp = @import("io_tcp.zig");
const frame = @import("io_tcp_frame.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const tls_test = @import("io_tls_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;
const endpoint_of = sim_test.endpoint_of;

const Tiny = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_message_bytes = fixtures.tiny_message_bytes,
});

test "a message longer than the connection can assemble ends the lookups on it" {
    var loop: rotor.Loop = undefined;
    var memory: [0]u8 align(rotor.memory_alignment) = undefined;
    try loop.init(&memory, .{ .operations = Tiny.loop_operations });
    loop.seed(19);
    loop.network().scripts[0] = .{ .truncate_per_256 = fixtures.always };
    loop.network().server_count = 1;
    const servers = [_]cocuyo.Server{.{ .endpoint = endpoint_of(rotor.Network.server_address(0)) }};
    const config: cocuyo.Config = .{ .servers = &servers, .timeout_ns = 1_000_000_000, .attempts = 1 };
    var engine: Tiny = undefined;
    var cache_memory: cocuyo.cache.Storage(fixtures.small_lookups) = .{};
    try engine.init(&loop, &config, cache_memory.slices(), 19, loop.now());
    _ = try engine.start(question("example.com."), loop.now());
    var events: [fixtures.events_max]rotor.Event = undefined;
    var rounds: usize = 0;
    var outcome: ?Tiny.Result = null;
    while (rounds < fixtures.until_rounds_max and outcome == null) : (rounds += 1) {
        outcome = engine.take(loop.now());
        if (outcome != null) break;
        const count = try sim_test.tick_for(&loop, &events, fixtures.wait_ns);
        for (events[0..count]) |event| _ = engine.apply(event, loop.now());
    }
    // The answer will not fit, so the connection is no good and the lookup ends without one.
    try testing.expect(outcome.?.outcome == .failure);
    _ = engine.take(loop.now());
    engine.deinit();
    try loop.drain(&events);
    engine.close();
    loop.deinit();
}

/// A lookup answered over a stream of the rig's first server, which leaves the connection up and
/// its frame empty: the socket the server writes to.
fn answered_stream(rig: *Rig, seed: u64) !rotor.Descriptor {
    try rig.init(seed, .{ .{}, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .up and connection.used == 0);
    return connection.descriptor.?;
}

test "a length prefix of 65534 or 65535 is waited for, and the connection stays up" {
    // The prefix's two octets and a message that long pass 65535 (RFC 1035 §4.2.2). Summed in
    // the `u16` the prefix reads as, they overflowed: a panic on two octets any server can write.
    for ([_]u16{ fixtures.message_bytes_unsummed, fixtures.message_bytes_unsummed + 1, cocuyo.limits.message_bytes_max }) |length| {
        var rig: Rig = .{};
        const socket = try answered_stream(&rig, 23);
        var prefix: [cocuyo.constants.tcp_prefix_bytes]u8 = undefined;
        std.mem.writeInt(u16, &prefix, length, .big);
        try testing.expect(rig.loop.network().write_stream(socket, &prefix, rig.loop.now()));
        _ = try rig.step(fixtures.channel_read_ns);
        const connection = &rig.engine.connections[0];
        try testing.expect(connection.state == .up);
        try testing.expectEqual(@as(usize, prefix.len), connection.used);
        try rig.deinit();
    }
}

test "a frame holds the longest message a prefix can say and a chunk after it, and hands them over" {
    // The twin's stream holds less than such a message, so the frame is filled by hand: the
    // prefix, then 65535 octets of zeros, which is nobody's answer. The chunk after it is empty
    // messages, each a prefix of zeros.
    var rig: Rig = .{};
    _ = try answered_stream(&rig, 24);
    const connection = &rig.engine.connections[0];
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    const longest = prefix + cocuyo.limits.message_bytes_max;
    try testing.expectEqual(longest + io.limits.tcp_chunk_bytes_max, connection.frame.len);
    @memset(&connection.frame, 0);
    std.mem.writeInt(u16, connection.frame[0..prefix], cocuyo.limits.message_bytes_max, .big);
    connection.used = connection.frame.len;
    try testing.expect(frame.deliver(&rig.engine, 0, rig.loop.now()));
    try testing.expectEqual(@as(usize, 0), connection.used);
    try testing.expect(connection.state == .up);
    try rig.deinit();
}

/// A lookup on a stream of the tiny engine whose server never answers, the connection up: the
/// server then writes one message of `length` octets of zeros, which is nobody's answer. Returns
/// the failures the server has once the engine has read it.
fn failures_after_message(seed: u64, length: usize) !u8 {
    var rig: sim_test.RigOf(Tiny) = .{};
    try rig.init(seed, .{ .{ .drop_per_256 = fixtures.always }, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(rig.engine.connections[0].state == .up);
    var bytes: [cocuyo.constants.tcp_prefix_bytes + fixtures.tiny_message_bytes + 1]u8 = @splat(0);
    const framed = bytes[0 .. cocuyo.constants.tcp_prefix_bytes + length];
    std.mem.writeInt(u16, framed[0..cocuyo.constants.tcp_prefix_bytes], @intCast(length), .big);
    const socket = rig.engine.connections[0].descriptor.?;
    try testing.expect(rig.loop.network().write_stream(socket, framed, rig.loop.now()));
    _ = try rig.step(fixtures.channel_read_ns);
    const failures = rig.engine.resolver.servers.failures(0);
    if (failures == 0) try testing.expectEqual(@as(usize, 0), rig.engine.connections[0].used);
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
    return failures;
}

test "a connection assembles a message of tcp_message_bytes, and fails on one an octet longer" {
    // `tcp_message_bytes` is the longest message, so the frame holds the prefix beside it.
    try testing.expectEqual(@as(u8, 0), try failures_after_message(25, fixtures.tiny_message_bytes));
    try testing.expectEqual(@as(u8, 1), try failures_after_message(26, fixtures.tiny_message_bytes + 1));
}

test "a chunk that ends a message and starts the next keeps the connection up" {
    // A server can answer two queries back to back, and the chunks of a stream do not stop where
    // its messages stop. One chunk holds a message of `tcp_message_bytes`, its prefix, and the
    // first octets of the next message (the stream's rule 11).
    var rig: sim_test.RigOf(Tiny) = .{};
    try rig.init(fixtures.one_chunk_seed, .{ .{ .drop_per_256 = fixtures.always }, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(fixtures.wait_ns);
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .up);
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    var bytes: [prefix + fixtures.tiny_message_bytes + fixtures.next_message_octets]u8 = @splat(0);
    std.mem.writeInt(u16, bytes[0..prefix], fixtures.tiny_message_bytes, .big);
    std.mem.writeInt(u16, bytes[prefix + fixtures.tiny_message_bytes ..][0..prefix], fixtures.next_message_bytes, .big);
    try testing.expect(rig.loop.network().write_stream(connection.descriptor.?, &bytes, rig.loop.now()));
    // The seed makes the twin give all of the octets as one chunk.
    const receive = tcp.user_data_of(&rig.engine, .tcp_receive, 0);
    const count = try sim_test.tick_for(&rig.loop, &rig.events, fixtures.channel_read_ns);
    for (rig.events[0..count]) |event| {
        if (event.user_data == receive) try testing.expectEqual(@as(u32, bytes.len), try event.outcome());
        _ = rig.engine.apply(event, rig.loop.now());
    }
    // The first message went to the table, and the start of the next is at the frame's head.
    try testing.expect(connection.state == .up);
    try testing.expectEqual(fixtures.next_message_octets, connection.used);
    try testing.expectEqual(fixtures.next_message_bytes, cocuyo.message_len(connection.frame[0..prefix]));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "every whole message one chunk carries is handed over with it, the last one too" {
    // A server that answers pipelined queries can fill one read with whole messages. Here the
    // lookup's answer is the last message of a full chunk. No chunk follows it, because the
    // server drops every query. The lookup has its answer before its deadline (the stream's
    // rule 11).
    var rig: Rig = .{};
    try rig.init(27, .{ .{ .drop_per_256 = fixtures.always }, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    try sim_test.until_sent(&rig);
    var answer: [io.limits.tcp_chunk_bytes_max]u8 = undefined;
    const answer_bytes = try sim_test.framed_answer(&rig.engine, handle, &answer);
    // The frame holds the chunk as `take_chunk` keeps it. Each message before the answer is a
    // header of zeros. Such a header is a query, and no lookup takes a query (docs/design.md §7,
    // check 4).
    const connection = &rig.engine.connections[0];
    const header = cocuyo.constants.header_bytes;
    const framed = cocuyo.constants.tcp_prefix_bytes + header;
    const others = (io.limits.tcp_chunk_bytes_max - answer_bytes) / framed;
    @memset(connection.frame[0 .. others * framed], 0);
    for (0..others) |other| cocuyo.wire.header.write_message_len(connection.frame[other * framed ..], @intCast(header));
    @memcpy(connection.frame[others * framed ..][0..answer_bytes], answer[0..answer_bytes]);
    connection.used = others * framed + answer_bytes;
    // `take_chunk` gives the frame to `deliver`, and `apply` then drives the engine, as after
    // each event.
    try testing.expect(frame.deliver(&rig.engine, 0, rig.loop.now()));
    rig.engine.drive(rig.loop.now());
    try testing.expectEqual(@as(usize, 0), connection.used);
    const result = try rig.until_result();
    try testing.expectEqual(handle, result.handle);
    try testing.expect(result.outcome == .answer);
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a frame over TLS of messages that are their prefix alone is handed over whole" {
    // Each message is at least its two-octet prefix, so the frame holds no more messages than
    // its length in prefixes. The frame over TLS is the longest, so it holds the most. No whole
    // message stays for a chunk that may not come (the stream's rule 11).
    var rig: tls_test.Rig = .{};
    try tls_test.up(&rig, 56);
    const connection = &rig.engine.connections[0];
    try testing.expectEqual(io.limits.tcp_messages_per_frame_max, connection.frame.len / cocuyo.constants.tcp_prefix_bytes);
    @memset(&connection.frame, 0);
    connection.used = connection.frame.len;
    try testing.expect(frame.deliver(&rig.engine, 0, rig.loop.now()));
    try testing.expectEqual(connection.frame.len % cocuyo.constants.tcp_prefix_bytes, connection.used);
    try testing.expect(connection.state == .up);
    try rig.deinit();
}

/// Octets of the stream that come after what the frame holds, as `take_chunk` copies a chunk.
fn arrive(connection: anytype, octets: []const u8) void {
    @memcpy(connection.frame[connection.used..][0..octets.len], octets);
    connection.used += octets.len;
}

test "a prefix split between two chunks is read once its second octet has come" {
    // A chunk can end after the first octet of a prefix. The octet after it in the frame is then
    // left from an earlier message, and is not read. Here it would make the prefix say more than
    // the connection assembles. A prefix that does say more fails the connection once it is
    // whole (the stream's rule 11). The server drops every query, so no answer comes between.
    var rig: sim_test.RigOf(Tiny) = .{};
    try rig.init(29, .{ .{ .drop_per_256 = fixtures.always }, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const handle = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(fixtures.wait_ns);
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.state == .up and connection.used == 0);
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    var sound: [prefix]u8 = undefined;
    std.mem.writeInt(u16, &sound, fixtures.next_message_bytes, .big);
    var long: [prefix]u8 = undefined;
    std.mem.writeInt(u16, &long, fixtures.tiny_message_bytes + 1, .big);
    // The first octet of a sound prefix, and after it in the frame the last octet of a long one.
    connection.frame[1] = long[1];
    arrive(connection, sound[0..1]);
    try testing.expect(frame.deliver(&rig.engine, 0, rig.loop.now()));
    try testing.expect(connection.state == .up and connection.used == 1);
    // The rest of that message, a message of zeros that is nobody's answer, and the first octet of
    // the long prefix.
    const zeros: [fixtures.next_message_bytes]u8 = @splat(0);
    arrive(connection, sound[1..]);
    arrive(connection, &zeros);
    arrive(connection, long[0..1]);
    try testing.expect(frame.deliver(&rig.engine, 0, rig.loop.now()));
    try testing.expect(connection.state == .up and connection.used == 1);
    // The last octet of the long prefix.
    arrive(connection, long[1..]);
    try testing.expect(!frame.deliver(&rig.engine, 0, rig.loop.now()));
    try testing.expect(connection.state == .closed);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    rig.engine.cancel(handle, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
