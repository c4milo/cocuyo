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
    .cache_slots = fixtures.cache_slots,
    .group_buffers = fixtures.group_buffers,
};
const Engine = io.Engine(options);

const loop_options: rotor.Loop.Options = .{ .operations = Engine.loop_operations };

/// Two scripted servers, which are the twin's first two, and an engine over them.
const Rig = struct {
    loop: rotor.Loop = undefined,
    memory: [0]u8 align(rotor.memory_alignment) = undefined,
    servers: [fixtures.servers]cocuyo.Server = .{
        .{ .endpoint = endpoint_of(rotor.Network.server_address(0)) },
        .{ .endpoint = endpoint_of(rotor.Network.server_address(1)) },
    },
    config: cocuyo.Config = undefined,
    engine: Engine = undefined,
    events: [fixtures.events_max]rotor.Event = undefined,

    fn init(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script, config: cocuyo.Config) !void {
        try rig.loop.init(&rig.memory, loop_options);
        rig.loop.seed(seed);
        rig.loop.network().scripts[0] = scripts[0];
        rig.loop.network().scripts[1] = scripts[1];
        rig.loop.network().server_count = fixtures.servers;
        rig.config = config;
        rig.config.servers = &rig.servers;
        try rig.engine.init(&rig.loop, &rig.config, seed, rig.loop.now());
    }

    fn deinit(rig: *Rig) !void {
        rig.engine.deinit();
        try rig.loop.drain(&rig.events);
        rig.engine.close();
        rig.loop.deinit();
    }

    /// One tick, every event applied. How many were the engine's.
    fn step(rig: *Rig, wait_ns: u64) !u32 {
        const count = try rig.loop.tick(&rig.events, wait_ns);
        var applied: u32 = 0;
        for (rig.events[0..count]) |event| {
            if (rig.engine.apply(event, rig.loop.now())) applied += 1;
        }
        return applied;
    }

    /// Runs until a result is ready, or the rounds run out.
    fn until_result(rig: *Rig) !Engine.Result {
        var rounds: usize = 0;
        while (rounds < fixtures.until_rounds_max) : (rounds += 1) {
            if (rig.engine.take(rig.loop.now())) |result| return result;
            _ = try rig.step(fixtures.wait_ns);
        }
        return error.NoResult;
    }
};

fn endpoint_of(address: rotor.Address) cocuyo.Endpoint {
    return .{ .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*), .port = address.port };
}

fn question(text: []const u8) cocuyo.Question {
    return cocuyo.Question.from_text(text, .a) catch unreachable;
}

test "a lookup started on the engine is answered by the scripted server through the loop" {
    var rig: Rig = .{};
    try rig.init(1, .{ .{}, .{} }, .{ .servers = &.{} });
    const started = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expect(started == .lookup);
    try testing.expectEqual(@as(usize, 1), rig.engine.active());
    const result = try rig.until_result();
    try testing.expectEqual(started.lookup, result.handle);
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expect(result.outcome.answer.addresses[0].family == .ipv4);
    try testing.expect(rig.loop.now() >= 1_000_000);
    try testing.expectEqual(@as(?Engine.Result, null), rig.engine.take(rig.loop.now()));
    try testing.expectEqual(@as(usize, 0), rig.engine.active());
    try rig.deinit();
}

test "a second start for the same name is a cache hit, and a negative answer is cached too" {
    var rig: Rig = .{};
    try rig.init(2, .{ .{}, .{} }, .{ .servers = &.{} });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const first = try rig.until_result();
    const address = first.outcome.answer.addresses[0];
    _ = rig.engine.take(rig.loop.now());
    const again = try rig.engine.start(question("EXAMPLE.com."), rig.loop.now());
    try testing.expect(again == .hit);
    try testing.expectEqual(cocuyo.cache.Outcome.answered, again.hit.outcome);
    try testing.expect(address.equal(&again.hit.answers.addresses()[0]));

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
    try testing.expect((try rig.engine.start(mx, rig.loop.now())) == .lookup);
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
    rig.engine.cancel(started.lookup, rig.loop.now());
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

test "a timer moved to a later deadline stays armed when the old timer's canceled end arrives" {
    var rig: Rig = .{};
    try rig.init(9, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    const first = try rig.engine.start(question("first.example."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    // A tick with nothing due moves the clock, so the second lookup's deadline is later.
    _ = try rig.step(1_000_000_000);
    const second = try rig.engine.start(question("second.example."), rig.loop.now());
    _ = try rig.step(0);
    // Cancelling the first moves the deadline to the second's: the old timer is cancelled and
    // a new one armed, and the old one's canceled end must not be taken for the new one's.
    rig.engine.cancel(first.lookup, rig.loop.now());
    try testing.expectEqual(@as(?u64, 3_000_000_000), rig.engine.timer_due_ns);
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(@as(u32, 1), try rig.step(0));
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(@as(u64, 1_000_000_000), rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    rig.engine.cancel(second.lookup, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    // No deadline is left, so no timer is: the drain ends now, not when a forgotten one fires.
    try rig.deinit();
    try testing.expectEqual(@as(u64, 1_000_000_000), rig.loop.now());
}

test "a timer that fires before the caller's clock reaches the deadline is armed again" {
    var rig: Rig = .{};
    try rig.init(10, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(u32, 1), try rig.loop.tick(&rig.events, fixtures.wait_ns));
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

const Small = io.Engine(.{ .lookups = fixtures.small_lookups, .cache_slots = fixtures.small_lookups, .group_buffers = fixtures.small_group_buffers });

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
    try engine.init(&loop, &config, 8, loop.now());
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
        const count = try loop.tick(&events, fixtures.wait_ns);
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
