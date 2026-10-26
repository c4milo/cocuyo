//! The engine on the twin (docs/design.md §19 step 13's gate): lookups through the loop against
//! scripted servers, the cache in front, loss and delays and a server that is down, and one seed
//! giving one trace. Compiled only when `rotor` is the twin, which is what has scripts.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");

const options: io.Options = .{
    .lookups = fixtures.lookups,
    .group_buffers = fixtures.group_buffers,
};
const Resolver = io.Resolver(options);

/// Two scripted servers, which are the twin's first two, and the engine the tests use over them.
pub const Rig = RigOf(Resolver);

/// Waits up to `wait_ns` for events, in ticks of rotor's `wait_ns_max` at most, as a caller of
/// rotor must: a longer tick halts there, and the twin holds the same bound. A tick moves the
/// clock to the next event due within its wait, so this ends where one long wait would.
pub fn tick_for(loop: *rotor.Loop, events: []rotor.Event, wait_ns: u64) !u32 {
    const slices_max = wait_ns / rotor.constants.wait_ns_max + 1;
    var left = wait_ns;
    var slices: u64 = 0;
    while (slices < slices_max) : (slices += 1) {
        const slice = @min(left, rotor.constants.wait_ns_max);
        const count = try loop.tick(events, slice);
        left -= slice;
        if (count > 0 or left == 0) return count;
    }
    return 0;
}

/// Two scripted servers and an engine of type `EngineType` over them, with the memory of a
/// cache as large as the engine's table of lookups, which is the cache every rig's engine held
/// while its options sized both.
pub fn RigOf(comptime EngineType: type) type {
    return RigOfServers(EngineType, fixtures.servers);
}

/// The same rig over `server_count` scripted servers, the twin's first.
pub fn RigOfServers(comptime EngineType: type, comptime server_count: u8) type {
    return struct {
        const RigType = @This();
        const loop_options: rotor.Loop.Options = .{ .operations = EngineType.loop_operations };
        /// The engine's lookups, read from the table's slots it declares.
        pub const cache_slots = @typeInfo(@FieldType(EngineType, "slots")).array.len;

        loop: rotor.Loop = undefined,
        memory: [0]u8 align(rotor.memory_alignment) = undefined,
        cache_memory: cocuyo.cache.Storage(cache_slots) = .{},
        servers: [server_count]cocuyo.Server = servers_of(server_count),
        config: cocuyo.Config = undefined,
        engine: EngineType = undefined,
        events: [fixtures.events_max]rotor.Event = undefined,

        pub fn init(rig: *RigType, seed: u64, scripts: [server_count]rotor.server.Script, config: cocuyo.Config) !void {
            try rig.init_with(seed, scripts, config, rig.cache_memory.slices());
        }

        /// As `init`, with the cache memory the test names: the rig's whole, part of it, or
        /// none, which is an engine with no cache (docs/design.md §19 step 13).
        pub fn init_with(
            rig: *RigType,
            seed: u64,
            scripts: [server_count]rotor.server.Script,
            config: cocuyo.Config,
            cache_memory: ?cocuyo.cache.Slices,
        ) !void {
            try rig.loop.init(&rig.memory, loop_options);
            rig.loop.seed(seed);
            @memcpy(rig.loop.network().scripts[0..server_count], &scripts);
            rig.loop.network().server_count = server_count;
            rig.config = config;
            rig.config.servers = &rig.servers;
            try rig.engine.init(&rig.loop, &rig.config, cache_memory, seed, rig.loop.now());
        }

        /// A rig whose engine holds `config`, which other engines may hold too: a `Config` is read
        /// and never written (docs/design.md §24, a thread per core). Its servers are the twin's.
        pub fn init_on(rig: *RigType, seed: u64, scripts: [server_count]rotor.server.Script, config: *const cocuyo.Config) !void {
            try rig.loop.init(&rig.memory, loop_options);
            rig.loop.seed(seed);
            @memcpy(rig.loop.network().scripts[0..server_count], &scripts);
            rig.loop.network().server_count = server_count;
            try rig.engine.init(&rig.loop, config, rig.cache_memory.slices(), seed, rig.loop.now());
        }

        /// Hands the engine a test's context for each encrypted transport it speaks over one of
        /// the twin's types, as a consumer names its own after `init`: the engine has none until
        /// then (docs/design.md §16 decision 39). The twin's contexts are structs of no fields,
        /// since its sessions draw nothing, check no certificate and read no clock. A transport
        /// over any other type, as colibri's QUIC is, is its own test's to name. Test-only.
        pub fn use_test_contexts(rig: *RigType) void {
            use_empty_contexts(&rig.engine);
        }

        pub fn deinit(rig: *RigType) !void {
            rig.engine.deinit();
            try rig.loop.drain(&rig.events);
            rig.engine.close();
            rig.loop.deinit();
        }

        /// One wait of up to `wait_ns`, every event applied. How many were the engine's.
        pub fn step(rig: *RigType, wait_ns: u64) !u32 {
            const count = try tick_for(&rig.loop, &rig.events, wait_ns);
            var applied: u32 = 0;
            for (rig.events[0..count]) |event| {
                if (rig.engine.apply(event, rig.loop.now())) applied += 1;
            }
            return applied;
        }

        /// Runs until a result is ready, or the rounds run out.
        pub fn until_result(rig: *RigType) !EngineType.Result {
            var rounds: usize = 0;
            while (rounds < fixtures.until_rounds_max) : (rounds += 1) {
                if (rig.engine.take(rig.loop.now())) |result| return result;
                _ = try rig.step(fixtures.wait_ns);
            }
            return error.NoResult;
        }
    };
}

/// Names the empty context of each transport `engine` speaks whose context holds nothing, for
/// `use_test_contexts`. Test-only.
fn use_empty_contexts(engine: anytype) void {
    const Engine = @TypeOf(engine.*);
    if (comptime carries_nothing(Engine.Tls)) engine.use_tls(.{});
    if (comptime carries_nothing(Engine.Quic)) engine.use_quic(.{});
    if (comptime carries_nothing(Engine.Doh)) engine.use_doh(.{});
}

/// Whether `Transport` is one an engine speaks whose context is a struct of no fields, as each of
/// the twin's is.
fn carries_nothing(comptime Transport: type) bool {
    return Transport.enabled and @typeInfo(Transport.Context).@"struct".fields.len == 0;
}

/// The twin's first `count` servers, as a configuration names them.
fn servers_of(comptime count: u8) [count]cocuyo.Server {
    var servers: [count]cocuyo.Server = undefined;
    for (&servers, 0..) |*server, index| server.* = .{ .endpoint = endpoint_of(rotor.Network.server_address(index)) };
    return servers;
}

pub fn endpoint_of(address: rotor.Address) cocuyo.Endpoint {
    return .{ .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*), .port = address.port };
}

pub fn question(text: []const u8) cocuyo.Question {
    return cocuyo.Question.from_text(text, .a) catch unreachable;
}

/// Steps until the connection in the first slot is up and its queue has gone out. Then every
/// query on it is sent, and its lookup waits for the answer.
pub fn until_sent(rig: anytype) !void {
    var rounds: usize = 0;
    while (rounds < fixtures.until_rounds_max) : (rounds += 1) {
        const connection = &rig.engine.connections[0];
        if (connection.state == .up and connection.queue.count == 0 and !connection.sending) return;
        _ = try rig.step(fixtures.channel_read_ns);
    }
    return error.NotSent;
}

/// The answer a scripted server that drops nothing writes to the stream query of `handle`'s
/// lookup, framed by its length (RFC 1035 §4.2.2), into `out`. Returns the octets it took.
pub fn framed_answer(engine: anytype, handle: cocuyo.Handle, out: []u8) !usize {
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    const query = engine.send_buffers[handle.index][prefix..engine.send_lengths[handle.index]];
    const server = rotor.Network.server_address(0);
    const answer = rotor.server.respond(&.{}, &server, query, true, 0, out[prefix..]) orelse return error.NoAnswer;
    cocuyo.wire.header.write_message_len(out[0..prefix], @intCast(answer.len));
    return prefix + answer.len;
}

test "a lookup started on the engine is answered by the scripted server through the loop" {
    var rig: Rig = .{};
    try rig.init(1, .{ .{}, .{} }, .{ .servers = &.{} });
    const started = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(usize, 1), rig.engine.active());
    const result = try rig.until_result();
    try testing.expectEqual(started, result.handle);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(result.outcome.answer.addresses[0].family == .ipv4);
    try testing.expect(rig.loop.now() >= 1_000_000);
    try testing.expectEqual(@as(?Resolver.Result, null), rig.engine.take(rig.loop.now()));
    try testing.expectEqual(@as(usize, 0), rig.engine.active());
    try rig.deinit();
}

test "a lookup of a name of 255 octets is answered through the loop, over UDP and over a stream" {
    // Its answer's question ends past octet 255 of the message, where check 5's offsets, summed
    // in the octet a name's length is held in, overflowed (docs/design.md §7).
    const scripts = [_]rotor.server.Script{ .{}, .{ .truncate_per_256 = fixtures.always } };
    for (scripts, 0..) |script, case| {
        var rig: Rig = .{};
        try rig.init(fixtures.longest_name_seed + case, .{ script, .{ .down = true } }, .{ .servers = &.{} });
        const text_question = question(fixtures.longest_name_text);
        try testing.expectEqual(@as(usize, cocuyo.limits.name_bytes_max), text_question.name.len);
        _ = try rig.engine.start(text_question, rig.loop.now());
        const result = try rig.until_result();
        try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
        // A truncated answer sent the lookup to the stream, which answered it (RFC 7766 §5).
        try testing.expectEqual(case == 1, rig.engine.connections[0].state == .up);
        _ = rig.engine.take(rig.loop.now());
        try rig.deinit();
    }
}

test "a second start for the same name is a cache hit, and a negative answer is cached too" {
    var rig: Rig = .{};
    try rig.init(2, .{ .{}, .{} }, .{ .servers = &.{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const first = try rig.until_result();
    const address = first.outcome.answer.addresses[0];
    _ = rig.engine.take(rig.loop.now());
    // The cache answers it under the table (docs/design.md §20), so the result is there before
    // the loop turns: nothing was sent, because nothing could have been.
    const again = try rig.engine.start(question("EXAMPLE.com."), rig.loop.now());
    const hit = rig.engine.take(rig.loop.now()).?;
    try testing.expectEqual(again, hit.handle);
    try testing.expect(address.equal(&hit.outcome.answer.addresses[0]));

    // The scripted server holds addresses alone, so an MX question is NODATA, and NODATA is
    // cached for the SOA minimum, or not at all without one (§18): the engine puts it anyway
    // with the TTL the failure carries, which is zero here and so not cached.
    var mx = question("nodata.example.");
    mx.kind = .mx;
    _ = try rig.engine.start(mx, rig.loop.now());
    const nodata = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.NoData, nodata.outcome.failure.err);
    try testing.expectEqual(@as(u32, 0), nodata.outcome.failure.negative_ttl_seconds);
    _ = rig.engine.take(rig.loop.now());
    _ = try rig.engine.start(mx, rig.loop.now());
    _ = try rig.until_result();
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a server that is down costs a timeout, the other answers, and the failure is counted" {
    var rig: Rig = .{};
    try rig.init(3, .{ .{ .down = true }, .{} }, .{ .servers = &.{}, .timeout_ns = 1_000_000_000, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() >= 1_000_000_000);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    _ = rig.engine.take(rig.loop.now());
    // The next lookup asks the live server first and needs no timeout.
    const before = rig.loop.now();
    _ = try rig.engine.start(question("other.example."), rig.loop.now());
    _ = try rig.until_result();
    try testing.expect(rig.loop.now() - before < 1_000_000_000);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "cancel ends a lookup with Canceled, through take" {
    var rig: Rig = .{};
    try rig.init(4, .{ .{ .delay_ns_min = 1_000_000_000, .delay_ns_max = 1_000_000_000 }, .{} }, .{ .servers = &.{} });
    const started = try rig.engine.start(question("example.com."), rig.loop.now());
    rig.engine.cancel(started, rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Canceled, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(usize, 0), rig.engine.active());
    try rig.deinit();
}

test "the timer follows the table's soonest deadline" {
    var rig: Rig = .{};
    try rig.init(5, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    // A queued send is not a sent one: the wait, and the timer, start when it completes.
    try testing.expect(rig.engine.timer_handle == null);
    _ = try rig.step(0);
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(rig.engine.resolver.next_deadline_ns(), rig.engine.timer_due_ns);
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Timeout, result.outcome.failure.err);
    try testing.expectEqual(@as(u64, 4_000_000_000), rig.loop.now());
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "the end of a timer the engine has replaced is not taken for the current one's, across the wrap" {
    // The table's deadline is a bound that never moves earlier while lookups wait (§11), so the
    // engine replaces a timer rarely; when it does, the old one's canceled end arrives after the
    // new one is armed (rotor decision 5, rule 2). The generation in the `user_data` is what
    // tells them apart, and this hands the engine an end from the timer before the current one.
    // The generation starts one short of the last of its thirty-two bits. The first timer runs at
    // the largest generation, and the second wraps it to zero.
    var rig: Rig = .{};
    try rig.init(9, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    rig.engine.timer_generation = std.math.maxInt(u32) - 1;
    const started = try rig.engine.start(question("first.example."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), rig.engine.timer_generation);
    // That timer ends at the first server's deadline. The next one is armed for the second
    // server's once the query to it has gone.
    for (0..fixtures.until_rounds_max) |_| {
        if (rig.engine.timer_handle != null and rig.loop.now() >= 2_000_000_000) break;
        _ = try rig.step(2_000_000_000);
    }
    const armed = rig.engine.timer_handle;
    try testing.expect(armed != null);
    try testing.expectEqual(@as(?u64, 4_000_000_000), rig.engine.timer_due_ns);
    try testing.expectEqual(@as(u32, 0), rig.engine.timer_generation);

    const stale: rotor.Event = .{
        .user_data = Resolver.user_data(.timer, rig.engine.timer_generation -% 1),
        .result = 0,
        .flags = .{},
    };
    try testing.expect(rig.engine.apply(stale, rig.loop.now()));
    try testing.expectEqual(armed, rig.engine.timer_handle);
    try testing.expectEqual(@as(?u64, 4_000_000_000), rig.engine.timer_due_ns);

    rig.engine.cancel(started, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an event another component submitted is handed back untouched" {
    // A consumer's loop carries its own operations beside the resolver's, told apart by the tag
    // in the high bits of `user_data` (docs/design.md §24). This one is the resolver's own
    // current timer in every bit but the tag: taken for the resolver's, it would end that timer.
    var rig: Rig = .{};
    try rig.init(11, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    const started = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    const armed = rig.engine.timer_handle;
    try testing.expect(armed != null);
    const own = Resolver.user_data(.timer, rig.engine.timer_generation);
    const other_tag: u64 = Resolver.tag +% 1;
    const below_tag: u64 = (@as(u64, 1) << io.constants.tag_shift) - 1;
    const foreign: rotor.Event = .{ .user_data = (other_tag << io.constants.tag_shift) | (own & below_tag), .result = 0, .flags = .{} };
    try testing.expect(!rig.engine.apply(foreign, rig.loop.now()));
    try testing.expectEqual(armed, rig.engine.timer_handle);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    try testing.expectEqual(@as(usize, 1), rig.engine.active());

    rig.engine.cancel(started, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a timer that fires before the caller's clock reaches the deadline is armed again" {
    var rig: Rig = .{};
    try rig.init(10, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(u32, 1), try tick_for(&rig.loop, &rig.events, fixtures.wait_ns));
    try testing.expectEqual(@as(u64, 2_000_000_000), rig.loop.now());
    // The caller's clock is a nanosecond short of the deadline the loop's has reached: nothing
    // times out yet, and the timer must be armed again rather than left for dead.
    try testing.expect(rig.engine.apply(rig.events[0], rig.loop.now() - 1));
    try testing.expectEqual(@as(usize, 1), rig.engine.active());
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    try testing.expectEqual(cocuyo.Error.Timeout, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a lookup offered twice is on the ready list once" {
    // `start` offers the lookup and `cancel` settles it again before any poll, so the table is
    // asked to put one slot on its list twice (§11).
    var rig: Rig = .{};
    try rig.init(15, .{ .{}, .{} }, .{ .servers = &.{} });
    const started = try rig.engine.start(question("example.com."), rig.loop.now());
    rig.engine.cancel(started, rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Canceled, result.outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(?Resolver.Result, null), rig.engine.take(rig.loop.now()));
    try testing.expectEqual(@as(usize, 0), rig.engine.active());
    try rig.deinit();
}

/// Many lookups against lossy, slow servers: every one ends, and the trace is the seed's.
fn many(seed: u64) !u64 {
    var rig: Rig = .{};
    try rig.init(seed, fixtures.lossy_scripts, .{ .servers = &.{}, .timeout_ns = fixtures.lossy_timeout_ns });
    var buffer: [fixtures.name_text_bytes]u8 = undefined;
    var started: usize = 0;
    while (started < fixtures.many_lookups) : (started += 1) {
        const text = try std.fmt.bufPrint(&buffer, "h{d}.example.", .{started});
        _ = try rig.engine.start(question(text), rig.loop.now());
    }
    var trace: u64 = seed;
    var taken: usize = 0;
    var rounds: usize = 0;
    while (taken < fixtures.many_lookups and rounds < fixtures.rounds_max) : (rounds += 1) {
        while (rig.engine.take(rig.loop.now())) |result| {
            taken += 1;
            const code: u64 = switch (result.outcome) {
                .answer => |answer| answer.addresses[0].octets[cocuyo.constants.address_v4_bytes - 1],
                .failure => |failure| @intFromError(failure.err),
            };
            trace = cocuyo.core.mix.next(trace ^ result.handle.index ^ (code << fixtures.trace_code_shift) ^ rig.loop.now());
        }
        _ = try rig.step(fixtures.lossy_step_ns);
    }
    try testing.expectEqual(@as(usize, fixtures.many_lookups), taken);
    _ = rig.engine.take(rig.loop.now());
    try testing.expectEqual(@as(usize, 0), rig.engine.active());
    try rig.deinit();
    return trace;
}

test "many lookups in flight over lossy servers all end, and one seed gives one trace" {
    try testing.expectEqual(try many(21), try many(21));
    try testing.expect(try many(21) != try many(22));
}

test "a send that fails at the socket costs no timeout: the next server is asked at once" {
    var rig: Rig = .{};
    try rig.init(6, .{ .{ .no_route = true }, .{} }, .{ .servers = &.{}, .timeout_ns = 1_000_000_000, .failover_retry_chance = 0 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(rig.loop.now() < 1_000_000_000);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

const Small = io.Resolver(.{ .lookups = fixtures.small_lookups, .group_buffers = fixtures.small_group_buffers });

test "the receive is armed again after the group runs dry, and every answer still arrives" {
    var loop: rotor.Loop = undefined;
    var memory: [0]u8 align(rotor.memory_alignment) = undefined;
    try loop.init(&memory, .{ .operations = Small.loop_operations });
    loop.seed(8);
    loop.network().scripts[0] = .{ .delay_ns_min = 1000, .delay_ns_max = 1000 };
    loop.network().server_count = 1;
    const servers = [_]cocuyo.Server{.{ .endpoint = endpoint_of(rotor.Network.server_address(0)) }};
    const config: cocuyo.Config = .{ .servers = &servers };
    var engine: Small = undefined;
    var cache_memory: cocuyo.cache.Storage(fixtures.small_lookups) = .{};
    try engine.init(&loop, &config, cache_memory.slices(), 8, loop.now());
    var buffer: [fixtures.name_text_bytes]u8 = undefined;
    var started: usize = 0;
    while (started < fixtures.small_lookups) : (started += 1) {
        const text = try std.fmt.bufPrint(&buffer, "h{d}.example.", .{started});
        _ = try engine.start(question(text), loop.now());
    }
    var events: [fixtures.events_max]rotor.Event = undefined;
    var answers: usize = 0;
    var rounds: usize = 0;
    while (rounds < fixtures.until_rounds_max) : (rounds += 1) {
        while (engine.take(loop.now())) |result| {
            try testing.expect(result.outcome == .answer);
            answers += 1;
        }
        if (answers == fixtures.small_lookups) break;
        const count = try tick_for(&loop, &events, fixtures.wait_ns);
        for (events[0..count]) |event| _ = engine.apply(event, loop.now());
    }
    try testing.expectEqual(@as(usize, fixtures.small_lookups), answers);
    try testing.expect(loop.now() < fixtures.lossy_timeout_ns);
    _ = engine.take(loop.now());
    engine.deinit();
    try loop.drain(&events);
    engine.close();
    loop.deinit();
}

test "the buffer groups sit where the kernel can take them" {
    var rig: Rig = .{};
    try rig.init(1, .{ .{}, .{} }, .{ .servers = &.{} });
    defer rig.deinit() catch {};
    // `IORING_REGISTER_PBUF_RING` refuses a ring that is not page-aligned, and rotor asks the
    // caller for `group_alignment` so it never is. A field's alignment is only as good as the
    // placement of whatever holds it, and this is the check that it held (docs/design.md §19
    // step 13).
    // What is handed over, not what is declared: the declaration is what Linux did not honour.
    const udp_at = @intFromPtr(rig.engine.group.ring().ptr);
    const tcp_at = @intFromPtr(rig.engine.tcp_group.ring().ptr);
    try testing.expectEqual(@as(usize, 0), udp_at % rotor.buffers.group_alignment);
    try testing.expectEqual(@as(usize, 0), tcp_at % rotor.buffers.group_alignment);
}
