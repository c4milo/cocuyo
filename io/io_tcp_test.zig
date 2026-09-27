//! The stream path of the engine on the twin (docs/design.md §19 step 13): a truncated answer
//! asked again over TCP, the pipelining of one connection, a server that refuses one, the idle
//! close, and what a connection that comes up too late tells nobody. The rig is the one
//! `io_sim_test.zig` builds, since these drive the same engine over the same scripted servers.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");
const tcp = @import("io_tcp.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;
const endpoint_of = sim_test.endpoint_of;

const Tiny = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_message_bytes = fixtures.tiny_message_bytes,
});

const Dry = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_group_buffers = fixtures.tcp_group_buffers_small,
});

test "a truncated answer goes to the stream, and the stream answers it" {
    var rig: Rig = .{};
    try rig.init(11, .{ .{ .truncate_per_256 = fixtures.always }, .{} }, .{ .servers = &.{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    // The same server answered, over a connection this lookup opened (RFC 7766 §5).
    try testing.expectEqual(@as(u8, 0), result.outcome.answer.addresses[0].family.address_bytes() * 0);
    try testing.expect(rig.engine.connections[0].state == .up);
    try testing.expectEqual(@as(u16, 0), rig.engine.connections[0].users);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "two lookups that need the stream share one connection" {
    var rig: Rig = .{};
    // The other server is down, so a lookup that opened a connection of its own rather than
    // sharing would be refused one and fail over to nothing.
    try rig.init(12, .{ .{ .truncate_per_256 = fixtures.always }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 1_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expect(rig.engine.connections[0].state == .up);
    try testing.expectEqual(@as(usize, 1), rig.engine.connections.len);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a stream send that goes short sends the rest, and the next query waits its turn" {
    var rig: Rig = .{};
    // Every send moves five octets, so each query takes several, and the second lookup's query
    // is asked for while the first's is in flight (the stream's rule 9).
    try rig.init(18, .{ .{ .truncate_per_256 = fixtures.always }, .{ .down = true } }, .{
        .servers = &.{},
        .timeout_ns = 1_000_000_000,
        .attempts = 1,
        .socket_send_bytes = fixtures.socket_send_bytes_short,
    });
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    var answered: usize = 0;
    while (answered < 2) : (answered += 1) {
        const result = try rig.until_result();
        try testing.expect(result.outcome == .answer);
    }
    try testing.expectEqual(@as(u16, 0), rig.engine.connections[0].queue.count);
    try testing.expect(!rig.engine.connections[0].sending);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup that leaves its connection takes its waiting query out of the queue" {
    var rig: Rig = .{};
    try rig.init(19, .{ .{}, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    const second = try rig.engine.start(question("two.example."), rig.loop.now());
    // The connect ends, and both queries are asked for: the first goes, the second waits.
    _ = try rig.step(fixtures.wait_ns);
    const connection = &rig.engine.connections[0];
    try testing.expectEqual(@as(u16, 2), connection.queue.count);
    rig.engine.cancel(second, rig.loop.now());
    // The second's query had not started, so it leaves the queue and its buffer comes back.
    try testing.expectEqual(@as(u16, 1), connection.queue.count);
    try testing.expectEqual(first.index, connection.queue.first().?.slot);
    try testing.expect(!rig.engine.send_in_flight[second.index]);
    var ended: usize = 0;
    while (ended < 2) : (ended += 1) _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a server that refuses the connection costs it the lookup, and the next server answers" {
    var rig: Rig = .{};
    try rig.init(13, .{ .{ .truncate_per_256 = fixtures.always, .tcp = false }, .{} }, .{ .servers = &.{}, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.engine.connections[0].state == .closed);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// An engine that keeps no TCP connection, as one built for DoQ alone does (c4milo/cocuyo#14).
const Streamless = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = 0,
});

test "an engine with no TCP connection fails a lookup's stream over at once" {
    // The truncated answer asks for a stream, which an engine of none cannot give: the lookup is
    // told so, and the next server answers long before the first one's wait would have ended.
    var rig: sim_test.RigOf(Streamless) = .{};
    try rig.init(15, .{ .{ .truncate_per_256 = fixtures.always }, .{} }, .{ .servers = &.{}, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expect(rig.loop.now() < rig.config.timeout_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection nobody is using is closed once it has been idle long enough" {
    var rig: Rig = .{};
    try rig.init(14, .{ .{ .truncate_per_256 = fixtures.always }, .{} }, .{ .servers = &.{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(rig.engine.connections[0].state == .up);
    // The first tick stops at the timer the lookup left behind, which is what the deadline
    // bound of §11 keeps armed until something looks; the second moves the clock past the idle
    // time, with nothing due, and the drive after it closes the connection.
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
    try testing.expect(rig.engine.connections[0].state == .closed);
    try rig.deinit();
}

test "a connection with a lookup on it is not closed for having been idle" {
    // The answer takes longer than the idle time, so a close that ignored the lookups on a
    // connection would take this one's stream away mid-question.
    var rig: Rig = .{};
    const script: rotor.server.Script = .{
        .truncate_per_256 = fixtures.always,
        .delay_ns_min = fixtures.stream_delay_ns,
        .delay_ns_max = fixtures.stream_delay_ns,
    };
    try rig.init(16, .{ script, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() >= fixtures.stream_delay_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a stream answer comes from the server's own TCP port" {
    var rig: Rig = .{};
    rig.servers[0].tcp_port = rotor.constants.server_tcp_port;
    try rig.init(17, .{ .{ .truncate_per_256 = fixtures.always }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 1_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection that comes up after its lookup moved on tells nobody" {
    // The connect is slower than the lookup's wait, so by the time it is up the lookup has given
    // up on that server and is asking the next one. Telling it then would be telling it about a
    // stream it is not on.
    var rig: Rig = .{};
    const slow: rotor.server.Script = .{
        .truncate_per_256 = fixtures.always,
        .delay_ns_min = 1_000_000,
        .delay_ns_max = 1_000_000,
        .connect_delay_ns = fixtures.slow_connect_ns,
    };
    const next: rotor.server.Script = .{ .delay_ns_min = fixtures.slow_answer_ns, .delay_ns_max = fixtures.slow_answer_ns };
    try rig.init(18, .{ slow, next }, .{ .servers = &.{}, .timeout_ns = fixtures.slow_connect_timeout_ns, .attempts = 1, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    _ = rig.engine.take(rig.loop.now());
    // The connect lands after the answer, on a connection nobody is on.
    _ = try rig.step(fixtures.slow_connect_ns);
    try rig.deinit();
}

test "the stream receive is armed again after its group runs dry" {
    var loop: rotor.Loop = undefined;
    var memory: [0]u8 align(rotor.memory_alignment) = undefined;
    try loop.init(&memory, .{ .operations = Dry.loop_operations });
    loop.seed(20);
    loop.network().scripts[0] = .{ .truncate_per_256 = fixtures.always };
    loop.network().server_count = 1;
    const servers = [_]cocuyo.Server{.{ .endpoint = endpoint_of(rotor.Network.server_address(0)) }};
    const config: cocuyo.Config = .{ .servers = &servers, .timeout_ns = 5_000_000_000 };
    var engine: Dry = undefined;
    try engine.init(&loop, &config, 20, loop.now());
    var buffer: [fixtures.name_text_bytes]u8 = undefined;
    var started: usize = 0;
    while (started < fixtures.small_lookups) : (started += 1) {
        const text = try std.fmt.bufPrint(&buffer, "h{d}.example.", .{started});
        _ = try engine.start(question(text), loop.now());
    }
    var events: [fixtures.events_max]rotor.Event = undefined;
    var answered: usize = 0;
    var rounds: usize = 0;
    while (rounds < fixtures.until_rounds_max) : (rounds += 1) {
        while (engine.take(loop.now())) |result| {
            try testing.expect(result.outcome == .answer);
            answered += 1;
        }
        if (answered == fixtures.small_lookups) break;
        const count = try sim_test.tick_for(&loop, &events, fixtures.wait_ns);
        for (events[0..count]) |event| _ = engine.apply(event, loop.now());
    }
    try testing.expectEqual(@as(usize, fixtures.small_lookups), answered);
    _ = engine.take(loop.now());
    engine.deinit();
    try loop.drain(&events);
    engine.close();
    loop.deinit();
}

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
    try engine.init(&loop, &config, 19, loop.now());
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

/// Two lookups on one connection, its connect ended: the first's query is the send in flight,
/// and the second's waits behind it.
fn two_queued(rig: *Rig, seed: u64) ![fixtures.queued_lookups]cocuyo.Handle {
    try rig.init(seed, .{ .{}, .{ .down = true } }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    const second = try rig.engine.start(question("two.example."), rig.loop.now());
    _ = try rig.step(fixtures.wait_ns);
    const connection = &rig.engine.connections[0];
    try testing.expectEqual(@as(u16, fixtures.queued_lookups), connection.queue.count);
    try testing.expect(connection.sending);
    return .{ first, second };
}

/// The connection to the first server is gone: both lookups were told, and moved on to the next
/// server, whose connection took the slot with none of the first one's queries in it.
fn expect_failed_over(rig: *Rig) !void {
    const connection = &rig.engine.connections[0];
    try testing.expectEqual(@as(u8, 1), connection.server);
    try testing.expectEqual(@as(u16, 0), connection.queue.count);
}

test "a query send that fails ends its connection, and every query on it gives its buffer back" {
    var rig: Rig = .{};
    const handles = try two_queued(&rig, 21);
    // The twin's sends do not fail, so the first query's is made to: the stream is broken.
    const count = try sim_test.tick_for(&rig.loop, &rig.events, fixtures.wait_ns);
    const sent = @TypeOf(rig.engine).user_data(.tcp_send, handles[0].index);
    var failed = false;
    for (rig.events[0..count]) |*event| {
        if (event.user_data != sent) continue;
        event.* = rotor.Event.failure(sent, .connection_reset);
        failed = true;
    }
    try testing.expect(failed);
    for (rig.events[0..count]) |event| _ = rig.engine.apply(event, rig.loop.now());
    try expect_failed_over(&rig);
    try testing.expect(!rig.engine.send_in_flight[handles[0].index]);
    try testing.expect(!rig.engine.send_in_flight[handles[1].index]);
    var ended: usize = 0;
    while (ended < 2) : (ended += 1) _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a connection that fails mid-send keeps that send's buffer until its event, and not the rest" {
    var rig: Rig = .{};
    const handles = try two_queued(&rig, 22);
    // The peer resets the connection while the first query is on its way out.
    const receive = tcp.user_data_of(&rig.engine, .tcp_receive, 0);
    _ = rig.engine.apply(rotor.Event.failure(receive, .connection_reset), rig.loop.now());
    try expect_failed_over(&rig);
    // The loop still holds the first query's bytes; the second's are the engine's again.
    try testing.expect(rig.engine.send_in_flight[handles[0].index]);
    try testing.expect(!rig.engine.send_in_flight[handles[1].index]);
    // The send's event names a connection that is gone, and hands the buffer back all the same.
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(!rig.engine.send_in_flight[handles[0].index]);
    var ended: usize = 0;
    while (ended < 2) : (ended += 1) _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
