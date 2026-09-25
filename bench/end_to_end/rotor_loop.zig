//! cocuyo's side of the comparison: the engine of docs/design.md §19 step 13 over rotor itself,
//! `io.Resolver` on a `rotor.Loop`, which is the batteries-included path a consumer would get. The
//! engine is not exported (step 13); the bench builds it privately against the real rotor.
//!
//! The loop is the consumer's: start lookups until `in_flight` are going, tick, hand every
//! event to the engine, take the results, until `total` have ended.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const harness = @import("../harness.zig");
const constants = @import("constants.zig");

/// One slot more than the most in flight: `take` frees the slot of the result taken before, so
/// the lookup started between two takes needs a slot of its own.
const Resolver = io.Resolver(.{
    .lookups = constants.in_flight_max + 1,
    .cache_slots = constants.in_flight_max + 1,
    .group_buffers = constants.group_buffers,
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };

var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;
var started_ns: [constants.in_flight_max + 1]u64 = @splat(0);

pub const Outcome = struct { elapsed_ns: u64, failures: u32 };

/// Runs `total` lookups of distinct names against the responder at `port`, `in_flight` at a
/// time, writing each lookup's latency into `latencies`, and returns the wall time of the run.
pub fn run(port: u16, in_flight: u32, total: u32, latencies: []u64) !Outcome {
    assert(in_flight >= 1 and in_flight <= constants.in_flight_max);
    assert(latencies.len >= total);
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = cocuyo.Address.from_v4(constants.loopback_v4), .port = port } }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    var events: [constants.events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, constants.engine_seed, harness.now_ns());
    defer {
        engine.deinit();
        loop.drain(&events) catch {};
        engine.close();
    }
    var driver: Driver = .{ .loop = &loop, .total = total, .in_flight = in_flight, .latencies = latencies };
    const begin = harness.now_ns();
    while (driver.done < total) {
        // Results first: `take` frees the slot the lookup before it used, and the start below
        // needs one. Starting first leaves this iteration with nothing outstanding, and the tick
        // under it then waits out `tick_wait_ns_max` before the next lookup goes out at all.
        driver.take_results();
        try driver.start_more();
        if (driver.done == total) break;
        const count = try loop.tick(&events, constants.tick_wait_ns_max);
        const now = harness.now_ns();
        for (events[0..count]) |event| _ = engine.apply(event, now);
    }
    return .{ .elapsed_ns = harness.now_ns() - begin, .failures = driver.failures };
}

const Driver = struct {
    loop: *rotor.Loop,
    total: u32,
    in_flight: u32,
    latencies: []u64,
    started: u32 = 0,
    done: u32 = 0,
    failures: u32 = 0,

    fn start_more(self: *Driver) !void {
        while (self.started - self.done < self.in_flight and self.started < self.total) {
            var text: [constants.name_bytes]u8 = undefined;
            const name = try std.fmt.bufPrint(&text, "h{d}.example.", .{self.started});
            const now = harness.now_ns();
            // The names are distinct, so the cache under the table never holds one and every
            // start is a query (docs/design.md §20).
            const handle = try engine.start(try cocuyo.Question.from_text(name, .a), now);
            started_ns[handle.index] = now;
            self.started += 1;
        }
    }

    fn take_results(self: *Driver) void {
        const now = harness.now_ns();
        while (engine.take(now)) |result| {
            self.latencies[self.done] = now - started_ns[result.handle.index];
            self.done += 1;
            if (result.outcome == .failure) self.failures += 1;
        }
    }
};
