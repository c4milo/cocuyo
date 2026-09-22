//! The harness under `bench/bench.zig` and `bench/cares.zig`: how a case is timed, summarised
//! and printed. Two binaries share it so that a cocuyo row and a c-ares row are measured by the
//! same code in the same process, which is the only way a comparison between them means anything.
//!
//! The method is the plain one. A case runs `iterations` times back to back between two reads of
//! the monotonic clock, that is one sample, and there are `samples` of them after one untimed
//! warm-up. The table reports the fastest sample, the median and the ninetieth percentile, each
//! in nanoseconds per operation with three decimals from integer picosecond arithmetic: no
//! floating point takes part. The fastest sample is the cost of the operation with the least
//! interference; the median is what a caller sees; the gap between them is how noisy the machine
//! was.
//!
//! Three decimals are only as real as the clock's step divided by the iterations, so the header
//! prints the step. On macOS `CLOCK_MONOTONIC` steps a whole microsecond at a time, which is why
//! the clock read here is `CLOCK_UPTIME_RAW`, the 24 MHz timebase at 42 ns: a microsecond over
//! 200,000 iterations would quantise every figure at 5 ps and the shortest sample at 0.3%.
//!
//! Nothing here reads a fixture at comptime: a case copies its input into a `var` at setup, so the
//! optimizer sees a runtime value and cannot fold the operation away, and every result goes
//! through `std.mem.doNotOptimizeAway` for the same reason.
//!
//! This file lives outside `src/`, so it may read a clock. Nothing under `src/` may
//! (CLAUDE.md non-negotiable 4).
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

/// Samples per case. Odd, so the median is one sample rather than a mean of two; twenty-one puts
/// the ninetieth percentile at the nineteenth.
pub const samples = 21;

/// Picoseconds in a nanosecond, for the integer arithmetic that prints three decimals.
const ps_per_ns = 1000;

/// How long the harness spins before its first case. A run started straight after `zig build
/// test` measured its first two rows a quarter slower and with a ninetieth percentile far from
/// their medians, while the test binaries were still going away; a run started after another
/// bench run did not. One second of spinning on the clock lets that pass, and keeps the core at
/// its clock rather than letting a sleep drop it. 1 * 1_000_000_000.
const settle_ns = 1_000_000_000;

/// One case: a name, how many iterations make one sample, and the two functions.
pub const Case = struct {
    name: []const u8,
    /// Iterations per sample, chosen per case so one sample lasts milliseconds: long enough that
    /// the clock read and the loop vanish into it, short enough that twenty-one fit a run.
    iterations: u32,
    run: *const fn () void,
    /// Runs once before the warm-up. What a caller sets up once, a benchmark sets up once.
    setup: *const fn () void = &noop,
};

fn noop() void {}

/// Per-operation cost in picoseconds: the fastest sample, the median and the ninetieth percentile.
const Result = struct {
    min_ps: u64,
    median_ps: u64,
    p90_ps: u64,
};

/// The name column. A case name longer than this would push its numbers out of their columns,
/// so `run` checks the width against every case at comptime rather than discovering it in the
/// output.
const name_width = 60;

fn measure(case: Case) Result {
    assert(case.iterations >= 1);
    case.setup();
    _ = sample(case);
    var results: [samples]u64 = undefined;
    for (&results) |*result| result.* = sample(case);
    return summarise(&results);
}

/// The three figures of a row, from the samples. Sorts them, so the caller's array is not left in
/// the order it was measured.
fn summarise(results: *[samples]u64) Result {
    std.sort.insertion(u64, results, {}, std.sort.asc(u64));
    const median = results[samples / 2];
    assert(results[0] <= median);
    assert(median <= results[samples - 1]);
    return .{
        .min_ps = results[0],
        .median_ps = median,
        .p90_ps = results[samples * 9 / 10],
    };
}

/// One sample: `iterations` runs between two clock reads, as picoseconds per run.
fn sample(case: Case) u64 {
    const start = now_ns();
    var completed: u32 = 0;
    while (completed < case.iterations) : (completed += 1) case.run();
    const elapsed = now_ns() - start;
    assert(completed == case.iterations);
    return elapsed * ps_per_ns / case.iterations;
}

/// `ps` as nanoseconds with three decimals, right-aligned in twelve columns.
fn print_ns(ps: u64) void {
    std.debug.print("{d:>8}.{d:0>3} ", .{ ps / ps_per_ns, ps % ps_per_ns });
}

/// The timespec the host's monotonic clock fills, which the two platforms spell apart.
const Timespec = if (builtin.os.tag == .linux) std.os.linux.timespec else std.c.timespec;

/// The clock every sample reads. On Linux `CLOCK_MONOTONIC` steps a nanosecond; on Darwin it
/// steps a microsecond, and `CLOCK_UPTIME_RAW` is the one that steps at the timebase.
const clock = if (builtin.os.tag == .linux) std.os.linux.CLOCK.MONOTONIC else std.c.CLOCK.UPTIME_RAW;

/// The clock in nanoseconds. Its own read costs tens of nanoseconds, which is why a sample is
/// many iterations and never one.
pub fn now_ns() u64 {
    var value: Timespec = undefined;
    if (builtin.os.tag == .linux) {
        assert(std.os.linux.clock_gettime(clock, &value) == 0);
    } else {
        assert(std.c.clock_gettime(clock, &value) == 0);
    }
    const seconds: u64 = @intCast(value.sec);
    assert(value.nsec >= 0);
    return seconds * std.time.ns_per_s + @as(u64, @intCast(value.nsec));
}

/// The clock's step, as the host reports it, so the table says what its decimals are worth.
pub fn resolution_ns() u64 {
    var value: Timespec = undefined;
    if (builtin.os.tag == .linux) {
        assert(std.os.linux.clock_getres(clock, &value) == 0);
    } else {
        assert(std.c.clock_getres(clock, &value) == 0);
    }
    assert(value.nsec >= 0);
    return @as(u64, @intCast(value.sec)) * std.time.ns_per_s + @as(u64, @intCast(value.nsec));
}

/// Measures every case and prints the table, `title` first.
pub fn run(title: []const u8, comptime cases: []const Case) void {
    comptime {
        for (cases) |case| {
            if (case.name.len > name_width) @compileError("a case name is wider than the name column");
        }
    }
    std.debug.print(
        "{s}: {t}, {s}-{s}, {d} samples per case, clock {s} stepping {d} ns, ns per operation\n\n",
        .{
            title,
            builtin.mode,
            @tagName(builtin.cpu.arch),
            @tagName(builtin.os.tag),
            samples,
            @tagName(clock),
            resolution_ns(),
        },
    );
    std.debug.print("{s:<60} {s:>10} {s:>12} {s:>12} {s:>12}\n", .{
        "case", "iterations", "fastest", "median", "p90",
    });
    settle();
    for (cases) |case| {
        const result = measure(case);
        std.debug.print("{s:<60} {d:>10} ", .{ case.name, case.iterations });
        print_ns(result.min_ps);
        print_ns(result.median_ps);
        print_ns(result.p90_ps);
        std.debug.print("\n", .{});
    }
}

/// Spins for `settle_ns`, so the first case is measured on a machine that has stopped doing
/// whatever ran before the bench.
fn settle() void {
    const start = now_ns();
    var spins: u64 = 0;
    while (now_ns() - start < settle_ns) spins += 1;
    assert(now_ns() - start >= settle_ns);
    std.mem.doNotOptimizeAway(spins);
}

// Tests. The harness is measured against itself: `zig build test` compiles it, and these pin the
// arithmetic the table is printed from.

const testing = std.testing;

test "the clock moves forward, and steps finer than a microsecond" {
    const first = now_ns();
    const second = now_ns();
    try testing.expect(second >= first);
    // A microsecond step would quantise the shortest sample at a third of a percent and every
    // printed figure at five picoseconds; the clock chosen steps far finer than that.
    try testing.expect(resolution_ns() < std.time.ns_per_us);
}

test "a sample is picoseconds per run, not per sample" {
    const case: Case = .{ .name = "noop", .iterations = 1000, .run = &noop };
    const ps = sample(case);
    // A thousand empty calls take microseconds at most: far under a microsecond each.
    try testing.expect(ps < 1000 * ps_per_ns);
}

test "the three figures come from the sorted samples, through the harness's own summary" {
    // Twenty-one samples handed over in reverse: the fastest is 1, the eleventh is the median at
    // 11, and the nineteenth is the ninetieth percentile at 19. The test calls `summarise`
    // rather than repeating its arithmetic, so a change to that arithmetic is what fails it.
    var results: [samples]u64 = undefined;
    for (&results, 0..) |*result, index| result.* = samples - index;
    const result = summarise(&results);
    try testing.expectEqual(@as(u64, 1), result.min_ps);
    try testing.expectEqual(@as(u64, 11), result.median_ps);
    try testing.expectEqual(@as(u64, 19), result.p90_ps);
}
