//! One server's latency, which its wait is read from (docs/design.md §5, retry and timeout
//! policy): the samples of the time from a query's send to the response the lookup accepted for
//! it, kept in five windows, and the average the wait reads. Split from `servers.zig`, whose
//! `ServerState` holds one per server.
//!
//! The five windows and their spans are c-ares's, read from its features page. Which window the
//! wait reads, the shortest with `latency_samples_min` samples, is cocuyo's own choice, since the
//! page names the windows and not that rule. Nothing here reads a clock: every instant is the
//! caller's `now_ns`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

/// The samples one window holds: how many, their sum, and the instant of the first of them.
pub const Window = struct {
    /// When the window took its first sample since it last started. Nothing while `count` is
    /// zero.
    start_ns: u64 = 0,
    count: u64 = 0,
    sum_ns: u64 = 0,
};

/// The window that holds every sample since the table was built: the last, which has no span.
const since_built = constants.latency_windows - 1;

pub const Latency = struct {
    /// Shortest span first, as `constants.latency_window_spans_ns` lists them.
    windows: [constants.latency_windows]Window = @splat(.{}),

    /// One sample, `sample_ns` long, taken at `now_ns`, into every window. A window whose span has
    /// passed starts again with it. A sample longer than the longest wait a configuration may set
    /// counts as that wait, which bounds what one sample adds to a sum.
    pub fn record(self: *Latency, sample_ns: u64, now_ns: u64) void {
        const sample = @min(sample_ns, core.constants.timeout_ns_max);
        for (&self.windows, constants.latency_window_spans_ns) |*window, span_ns| {
            if (window.count > 0 and passed(window, span_ns, now_ns)) window.* = .{};
            if (window.count == 0) window.start_ns = now_ns;
            add(window, sample);
        }
        assert(self.samples() >= 1);
        assert(self.windows[0].count >= 1);
    }

    /// How many samples came since the table was built, or half of them once a sum would have
    /// passed 2^64.
    pub fn samples(self: *const Latency) u64 {
        return self.windows[since_built].count;
    }

    /// The average of the shortest window that holds `latency_samples_min` samples and whose span
    /// has not passed at `now_ns`; null while fewer samples than that came since the table was
    /// built. The window since then has no span, so it is read when no shorter one qualifies.
    pub fn average_ns(self: *const Latency, now_ns: u64) ?u64 {
        if (self.samples() < constants.latency_samples_min) return null;
        for (self.windows[0..since_built], constants.latency_window_spans_ns[0..since_built]) |*window, span_ns| {
            if (window.count < constants.latency_samples_min) continue;
            if (passed(window, span_ns, now_ns)) continue;
            return average(window);
        }
        return average(&self.windows[since_built]);
    }
};

/// Whether a window's span has passed at `now_ns`. A window with no span never passes.
fn passed(window: *const Window, span_ns: ?u64, now_ns: u64) bool {
    const span = span_ns orelse return false;
    assert(span >= 1);
    return now_ns -| window.start_ns >= span;
}

fn average(window: *const Window) u64 {
    assert(window.count >= constants.latency_samples_min);
    const mean = window.sum_ns / window.count;
    assert(mean <= core.constants.timeout_ns_max);
    return mean;
}

/// Adds one sample to a window. A sum that would pass 2^64 first halves the window's count and
/// its sum, which keeps the average: with no sample past `timeout_ns_max`, that takes over 600
/// million samples, so half of them is still a window of many. The count is halved up and the sum
/// down, so the average never rises past the longest sample.
fn add(window: *Window, sample_ns: u64) void {
    assert(sample_ns <= core.constants.timeout_ns_max);
    if (window.sum_ns > std.math.maxInt(u64) - sample_ns) {
        assert(window.count > 1);
        window.count -= window.count >> 1;
        window.sum_ns >>= 1;
    }
    window.count +|= 1;
    window.sum_ns += sample_ns;
    assert(window.count >= 1 and window.sum_ns >= sample_ns);
}

// Tests.

const testing = std.testing;

/// A millisecond and a second, in nanoseconds, for the tests.
const millisecond = 1_000_000;
const second = 1_000_000_000;

test "fewer than three samples give no average, and the third gives one" {
    var latency: Latency = .{};
    try testing.expectEqual(@as(?u64, null), latency.average_ns(0));
    latency.record(10 * millisecond, 1 * second);
    latency.record(20 * millisecond, 2 * second);
    try testing.expectEqual(@as(?u64, null), latency.average_ns(2 * second));
    latency.record(30 * millisecond, 3 * second);
    try testing.expectEqual(@as(?u64, 20 * millisecond), latency.average_ns(3 * second));
    try testing.expectEqual(@as(u64, 3), latency.samples());
}

test "the shortest window with three samples is read, and one whose span passed starts again" {
    var latency: Latency = .{};
    // Three samples of 40 ms, which every window holds.
    for (0..3) |index| latency.record(40 * millisecond, index * second);
    try testing.expectEqual(@as(?u64, 40 * millisecond), latency.average_ns(10 * second));
    // Seventy seconds on, the minute's span has passed: it starts again empty, with this sample
    // alone, too few to read, so the fifteen minutes are read, all four samples of them.
    latency.record(10 * millisecond, 70 * second);
    try testing.expectEqual(@as(?u64, 32_500_000), latency.average_ns(70 * second));
    // Two more, and the minute holds three.
    latency.record(10 * millisecond, 71 * second);
    latency.record(10 * millisecond, 72 * second);
    try testing.expectEqual(@as(?u64, 10 * millisecond), latency.average_ns(72 * second));
    try testing.expectEqual(@as(?u64, 10 * millisecond), latency.average_ns(129 * second));
    // Sixty seconds after its first sample, the minute's span has passed: it holds nothing the
    // wait reads, though no sample has come to start it again.
    try testing.expectEqual(@as(?u64, 25 * millisecond), latency.average_ns(130 * second));
    try testing.expectEqual(@as(u64, 6), latency.samples());
}

test "samples a day apart are read from the window that holds every one" {
    var latency: Latency = .{};
    const day = constants.latency_window_day_ns;
    latency.record(100 * millisecond, 0);
    latency.record(200 * millisecond, 2 * day);
    latency.record(300 * millisecond, 4 * day);
    // Each window with a span holds the last sample alone.
    for (latency.windows[0..since_built]) |window| try testing.expectEqual(@as(u64, 1), window.count);
    try testing.expectEqual(@as(?u64, 200 * millisecond), latency.average_ns(4 * day));
}

test "a sample longer than the longest wait counts as that wait" {
    var latency: Latency = .{};
    const hour = constants.latency_window_hour_ns;
    for (0..3) |index| latency.record(hour, hour + index * second);
    try testing.expectEqual(@as(?u64, core.constants.timeout_ns_max), latency.average_ns(hour + 3 * second));
}

test "a sum that would pass 2^64 is halved first, and the average stays at or under the samples" {
    var latency: Latency = .{};
    const longest = core.constants.timeout_ns_max;
    // As many samples of the longest wait as a sum can hold, and one more would pass 2^64.
    const many = std.math.maxInt(u64) / longest;
    for (&latency.windows) |*window| window.* = .{ .start_ns = 0, .count = many, .sum_ns = many * longest };
    latency.record(longest, 1);
    // 614,891,469 halved up is 307,445,735, and the sample makes one more. The sum, halved down
    // and with the sample, over that count is just under the longest wait, never over it.
    try testing.expectEqual(@as(u64, 307_445_736), latency.samples());
    try testing.expectEqual(@as(?u64, 29_999_999_951), latency.average_ns(1));
}
