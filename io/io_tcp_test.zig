//! The stream path of the engine on the twin (docs/design.md §19 step 13): a truncated answer
//! asked again over TCP, the pipelining of one connection, a server that refuses one, the idle
//! close, and what a connection that comes up too late tells nobody. A send's buffer stays as it
//! was until the send's event, after its connection failed too. The rig is the one
//! `io_sim_test.zig` builds, since these drive the same engine over the same scripted servers.
//! The cause that each failure of a stream gives a lookup is in `io_tcp_cause_test.zig`.
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

const Dry = io.Resolver(.{
    .lookups = fixtures.small_lookups,
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

/// Both lookups that `two_queued` started end in `AllServersFailed`. The first server's
/// connection failed under them, and then the second server, which is down, refused theirs. Each
/// failure carries the last cause, the connect's (docs/design.md §5, The cause of a failure).
fn expect_both_failed(rig: *Rig) !void {
    for (0..fixtures.queued_lookups) |_| {
        const result = try rig.until_result();
        try testing.expectEqual(cocuyo.Error.AllServersFailed, result.outcome.failure.err);
        try testing.expectEqual(@as(?cocuyo.Cause, .connect), result.outcome.failure.cause);
    }
}

/// An engine that keeps no TCP connection, as one built for DoQ alone does (c4milo/cocuyo#14).
pub const Streamless = io.Resolver(.{
    .lookups = fixtures.small_lookups,
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
    try rig.init(16, .{ script, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() >= fixtures.stream_delay_ns);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// In the clear a query's send reads its lookup's own buffer (the stream's rule 6). The peer stops
/// reading before the query goes, so the send takes nothing and never ends. The caller cancels
/// the lookup, and the connection is idle with that send in flight (rule 9).
fn stall_a_query(rig: *Rig, seed: u64) !cocuyo.Handle {
    try rig.init(seed, .{ .{}, .{} }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    const connection = &rig.engine.connections[0];
    rig.loop.network().stall(connection.descriptor.?);
    _ = try rig.step(fixtures.wait_ns);
    try testing.expect(connection.state == .up and connection.sending);
    rig.engine.cancel(first, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try testing.expect(connection.users == 0 and rig.engine.send_in_flight[first.index]);
    return first;
}

/// The connection is closed, and the stalled send still holds the buffer. At the cancel's event the
/// buffer comes back. A later lookup opens the slot again, and the server answers it.
fn expect_buffer_at_cancel(rig: *Rig, first: cocuyo.Handle) !void {
    try testing.expect(rig.engine.connections[0].state == .closed and rig.engine.send_in_flight[first.index]);
    _ = try rig.step(fixtures.channel_read_ns);
    try testing.expect(!rig.engine.send_in_flight[first.index]);
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
}

test "the idle close cancels a send that never ends, and its buffer comes back at the cancel" {
    // The idle close shuts the connection, and the shut cancels the send (docs/design.md §16
    // decision 49).
    var rig: Rig = .{};
    const first = try stall_a_query(&rig, 24);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
    try expect_buffer_at_cancel(&rig, first);
    try rig.deinit();
}

test "a reinit cancels a send that never ends, and its buffer comes back at the cancel" {
    // A reinit drops the connection before the idle close, and cancels the send too (docs/design.md
    // §16 decision 49).
    var rig: Rig = .{};
    const first = try stall_a_query(&rig, 25);
    try rig.engine.reinit(&rig.config, rig.cache_memory.slices(), 26, rig.loop.now());
    try expect_buffer_at_cancel(&rig, first);
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
    var cache_memory: cocuyo.cache.Storage(fixtures.small_lookups) = .{};
    try engine.init(&loop, &config, cache_memory.slices(), 20, loop.now());
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
    try expect_both_failed(&rig);
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
    try expect_both_failed(&rig);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a new opening in the slot of a connection that failed mid-send writes none of that send's octets" {
    // In the clear a query's send reads its lookup's own buffer, which is lent until the send's
    // event (the stream's rule 6). The peer resets the connection while the first query is on its
    // way out, and both lookups move to the next server. Its connection opens in the same slot at
    // once, since the loop holds nothing of the slot's (rule 10). The first lookup's next query is
    // held until the send's event, so the octets the loop may still read stay as they were.
    var rig: Rig = .{};
    try rig.init(23, .{ .{}, .{} }, .{ .servers = &.{}, .use_tcp = true, .attempts = 1 });
    const first = try rig.engine.start(question("one.example."), rig.loop.now());
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    _ = try rig.step(fixtures.wait_ns);
    const connection = &rig.engine.connections[0];
    try testing.expect(connection.sending and connection.queue.first().?.slot == first.index);
    const length = rig.engine.send_lengths[first.index];
    var lent: [cocuyo.constants.query_bytes_max]u8 = undefined;
    @memcpy(lent[0..length], rig.engine.send_buffers[first.index][0..length]);
    const receive = tcp.user_data_of(&rig.engine, .tcp_receive, 0);
    _ = rig.engine.apply(rotor.Event.failure(receive, .connection_reset), rig.loop.now());
    try testing.expect(connection.state == .connecting and connection.server == 1);
    // The loop holds the send's event back, as a slow send's end comes late.
    const send = @TypeOf(rig.engine).user_data(.tcp_send, first.index);
    var held: ?rotor.Event = null;
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.held[first.index] != null) break;
        try step_holding(&rig, send, &held);
    }
    try testing.expect(held != null and rig.engine.held[first.index] != null);
    try testing.expect(connection.state == .up and rig.engine.send_in_flight[first.index]);
    try testing.expectEqualSlices(u8, lent[0..length], rig.engine.send_buffers[first.index][0..length]);
    // The send's event gives the buffer back, and the held query goes out on the new connection.
    _ = rig.engine.apply(held.?, rig.loop.now());
    try testing.expect(rig.engine.held[first.index] == null and connection.queue.contains(first.index));
    try testing.expect((try rig.until_result()).outcome == .answer);
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// One short wait of the rig, each event applied but the one whose `user_data` is `send`, which
/// `held` keeps.
pub fn step_holding(rig: anytype, send: u64, held: *?rotor.Event) !void {
    const count = try sim_test.tick_for(&rig.loop, &rig.events, fixtures.channel_read_ns);
    for (rig.events[0..count]) |event| {
        if (event.user_data == send) {
            held.* = event;
            continue;
        }
        _ = rig.engine.apply(event, rig.loop.now());
    }
}

/// The octet a test's buffer holds before a reset, which no reset writes.
const untouched: u8 = 0x5a;

test "a new opening resets the slot but what outlives it, and writes none of its frame, address or queue" {
    const Slot = tcp.Connection(fixtures.tiny_message_bytes, fixtures.small_lookups, io.tls.None);
    var slot: Slot = .{ .state = .up, .server = 1, .used = 3, .users = 2, .idle_since_ns = 42 };
    slot.incarnation = 5;
    slot.connect_in_flight = true;
    slot.records_send = 3;
    @memset(&slot.frame, untouched);
    @memset(std.mem.asBytes(&slot.address), untouched);
    @memset(std.mem.sliceAsBytes(&slot.queue.items), untouched);
    slot.queue.head = 1;
    slot.queue.count = 2;
    slot.restart();
    try testing.expectEqual(@as(u16, 0), slot.queue.head);
    try testing.expectEqual(@as(u16, 0), slot.queue.count);
    for (std.mem.sliceAsBytes(&slot.queue.items)) |octet| try testing.expectEqual(untouched, octet);
    try testing.expectEqual(Slot.State.closed, slot.state);
    try testing.expectEqual(@as(u8, 0), slot.server);
    try testing.expectEqual(@as(usize, 0), slot.used);
    try testing.expectEqual(@as(u16, 0), slot.users);
    try testing.expectEqual(@as(u64, 0), slot.idle_since_ns);
    // What outlives an opening: the stream's rules 2 and 10, and §21's TLS rule 3.
    try testing.expectEqual(@as(u32, 5), slot.incarnation);
    try testing.expect(slot.connect_in_flight);
    try testing.expectEqual(@as(?u16, 3), slot.records_send);
    for (slot.frame) |octet| try testing.expectEqual(untouched, octet);
    for (std.mem.asBytes(&slot.address)) |octet| try testing.expectEqual(untouched, octet);
}

test "a connection's incarnation wraps at the last of its thirty-two bits, and the opening before is nobody's" {
    // The incarnation tells the events of the slot's current opening from those of the openings
    // before it (docs/design.md §19 step 13, the stream's rule 2). An opening adds one, so the
    // first one here runs at the largest incarnation, and the second wraps it to zero.
    var rig: Rig = .{};
    try rig.init(13, .{ .{ .truncate_per_256 = fixtures.always }, .{} }, .{ .servers = &.{} });
    rig.engine.connections[0].incarnation = std.math.maxInt(u32) - 1;
    _ = try rig.engine.start(question("one.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
    // Its events carried the largest incarnation above the slot, and each was the connection's.
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), rig.engine.connections[0].incarnation);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    // The connection closes once idle, and the next lookup opens the slot again.
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    _ = try rig.step(fixtures.tcp_idle_jump_ns);
    rig.engine.drive(rig.loop.now());
    try testing.expect(rig.engine.connections[0].state == .closed);
    _ = try rig.engine.start(question("two.example."), rig.loop.now());
    try testing.expect((try rig.until_result()).outcome == .answer);
    try testing.expectEqual(@as(u32, 0), rig.engine.connections[0].incarnation);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    // An event of the opening before: the largest incarnation above the slot.
    const before: usize = @as(usize, std.math.maxInt(u32)) << io.constants.tcp_incarnation_shift;
    const event: rotor.Event = .{ .user_data = 0, .result = 0, .flags = .{} };
    try testing.expectEqual(@as(?u8, null), tcp.current_of(&rig.engine, before, event));
    try testing.expectEqual(@as(?u8, 0), tcp.current_of(&rig.engine, 0, event));
    // That incarnation above the last slot a connection may have is the largest index a
    // `user_data` holds.
    try testing.expectEqual(io.constants.index_mask, before | io.constants.tcp_slot_mask);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
