//! cocuyo's side of the comparison: the engine of docs/design.md §19 step 13 over rotor itself,
//! `io.Resolver` on a `rotor.Loop`, which is the batteries-included path a consumer would get. The
//! engine is not exported (step 13); the bench builds it privately against the real rotor.
//!
//! The loop is the consumer's: take the results, start every lookup that is due while there is
//! room, tick until the next one is due or an event comes, hand every event to the engine, until
//! `total` have ended. The engine answers from its cache inside `start` (`io.zig`), so a result
//! is taken right after each start, and one taken there is a hit.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const schedule_module = @import("schedule.zig");
const kernel = @import("kernel.zig");
const Schedule = schedule_module.Schedule;
const Outcome = schedule_module.Outcome;
const Record = schedule_module.Record;
const Names = schedule_module.Names;

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
/// Which lookup of the row each of the engine's slots holds, by the slot's index.
var lookup_of: [constants.in_flight_max + 1]u32 = @splat(0);

/// Runs `total` lookups against the responder at `port`, each started when `schedule` says it is
/// due and asking the name `names` gives it, and writes each one's latency and lateness into
/// `record`. Repeated names are each asked once first, unmeasured, so the cache holds them.
pub fn run(port: u16, schedule: Schedule, total: u32, record: Record, names: Names) !Outcome {
    assert(schedule.in_flight >= 1 and schedule.in_flight <= constants.in_flight_max);
    assert(record.holds(total));
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
    switch (names) {
        .distinct => {},
        .repeated => |count| {
            assert(count <= total);
            var warm: Driver = .{ .schedule = .{ .period_ns = 0, .in_flight = constants.in_flight_max }, .total = count, .record = record, .names = .distinct, .begin_ns = harness.now_ns() };
            try run_row(&loop, &events, &warm);
        },
    }
    const kernel_before = kernel.read();
    var driver: Driver = .{ .schedule = schedule, .total = total, .record = record, .names = names, .begin_ns = harness.now_ns() };
    try run_row(&loop, &events, &driver);
    return .{
        .elapsed_ns = harness.now_ns() - driver.begin_ns,
        .failures = driver.failures,
        .in_flight_peak = driver.in_flight_peak,
        .hits = driver.hits,
        .kernel = kernel.since(kernel_before, kernel.read()),
    };
}

/// Drives the loop until every lookup of `driver` has ended.
fn run_row(loop: *rotor.Loop, events: []rotor.Event, driver: *Driver) !void {
    while (driver.done < driver.total) {
        // Results first: `take` frees the room a due lookup needs, so it goes out on this pass.
        // The wait below is read after both, so the other order costs a pass and never a wait.
        driver.take_results();
        try driver.start_due();
        if (driver.done == driver.total) break;
        const count = try loop.tick(events, driver.wait_ns());
        const now = harness.now_ns();
        for (events[0..count]) |event| _ = engine.apply(event, now);
    }
}

const Driver = struct {
    schedule: Schedule,
    total: u32,
    record: Record,
    names: Names,
    begin_ns: u64,
    started: u32 = 0,
    done: u32 = 0,
    failures: u32 = 0,
    in_flight_peak: u32 = 0,
    hits: u32 = 0,
    /// The lookup whose start just returned, while its result is looked for.
    starting: ?u32 = null,

    /// Starts every lookup that is due, while fewer than the schedule allows are out.
    fn start_due(self: *Driver) !void {
        while (self.started < self.total and self.started - self.done < self.schedule.in_flight) {
            const now = harness.now_ns();
            const due = self.schedule.due_ns(self.begin_ns, self.started);
            if (now < due) return;
            var text: [constants.name_bytes]u8 = undefined;
            const name = try std.fmt.bufPrint(&text, "h{d}.example.", .{self.names.number(self.started)});
            // The cache under the table answers a name it holds inside `start` (docs/design.md
            // §20), so its result is taken now, before a tick could wait for nothing.
            const handle = try engine.start(try cocuyo.Question.from_text(name, .a), now);
            lookup_of[handle.index] = self.started;
            self.record.late[self.started] = now - due;
            self.started += 1;
            self.in_flight_peak = @max(self.in_flight_peak, self.started - self.done);
            self.starting = self.started - 1;
            self.take_results();
            self.starting = null;
        }
    }

    fn take_results(self: *Driver) void {
        const now = harness.now_ns();
        while (engine.take(now)) |result| {
            const index = lookup_of[result.handle.index];
            assert(index < self.started);
            self.record.latencies[index] = now - self.schedule.due_ns(self.begin_ns, index);
            self.done += 1;
            if (result.outcome == .failure) self.failures += 1 else if (self.starting == index) self.hits += 1;
        }
    }

    /// How long the tick may wait: until the next lookup is due, or, with none left to start or
    /// no room for it, until an event comes.
    fn wait_ns(self: *const Driver) u64 {
        const room = self.started - self.done < self.schedule.in_flight;
        if (self.started == self.total or !room) return constants.tick_wait_ns_max;
        const wait = self.schedule.wait_ns(self.begin_ns, self.started, harness.now_ns());
        return @min(wait, constants.tick_wait_ns_max);
    }
};
