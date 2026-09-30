//! The load a row of the end-to-end comparison offers (docs/design.md §11): lookup `index` is due
//! `index` periods after the row began, whether or not the stack has answered the ones before it,
//! and at most `in_flight` are out at once. A lookup's latency runs from when it was due to its
//! result, so a stall shows in every lookup it held back. A driver that starts a lookup only when
//! another ends sends nothing while the stack stalls, and its percentiles leave the stall out
//! (pepegrillo's method, step 1).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const kernel = @import("kernel.zig");

pub const Schedule = struct {
    /// Nanoseconds between two lookups' due times. Zero makes every lookup due when the row
    /// begins.
    period_ns: u64,
    /// The most lookups out at once. A lookup due while this many are out waits for one to end,
    /// and the wait is in its latency.
    in_flight: u32,

    /// `rate` lookups a second, with at most `constants.in_flight_max` out.
    pub fn of_rate(rate: u32) Schedule {
        assert(rate >= 1);
        assert(rate <= constants.ns_per_s);
        return .{ .period_ns = constants.ns_per_s / rate, .in_flight = constants.in_flight_max };
    }

    /// When lookup `index` is due, the row having begun at `begin_ns`.
    pub fn due_ns(self: Schedule, begin_ns: u64, index: u32) u64 {
        assert(self.in_flight >= 1);
        return begin_ns + @as(u64, index) * self.period_ns;
    }

    /// How long until lookup `index` is due: zero once it is.
    pub fn wait_ns(self: Schedule, begin_ns: u64, index: u32, now_ns: u64) u64 {
        return self.due_ns(begin_ns, index) -| now_ns;
    }
};

/// What a row did: its wall time from its beginning, the lookups that failed, the most that were
/// out at once, and what the kernel counted for the stack's process meanwhile.
pub const Outcome = struct {
    elapsed_ns: u64,
    failures: u32,
    in_flight_peak: u32,
    kernel: kernel.Counts,
};

/// Where a row writes each lookup's figures, at the lookup's index: its latency, from when it was
/// due to its result, and how late it went out. The lateness is the part of the latency the
/// driver spent before the stack had the lookup: the timer that woke it, or a wait for room.
pub const Record = struct {
    latencies: []u64,
    late: []u64,

    pub fn holds(self: Record, total: u32) bool {
        return self.latencies.len >= total and self.late.len >= total;
    }
};

const testing = std.testing;

test "a rate spaces the due times a period apart from the row's beginning" {
    const schedule = Schedule.of_rate(1_000);
    try testing.expectEqual(@as(u64, constants.ns_per_ms), schedule.period_ns);
    try testing.expectEqual(@as(u32, constants.in_flight_max), schedule.in_flight);
    try testing.expectEqual(@as(u64, 500), schedule.due_ns(500, 0));
    try testing.expectEqual(@as(u64, 500 + 3 * constants.ns_per_ms), schedule.due_ns(500, 3));
}

test "the wait runs to the due time and is zero once it has passed" {
    const schedule = Schedule.of_rate(1_000);
    try testing.expectEqual(@as(u64, constants.ns_per_ms - 10), schedule.wait_ns(0, 1, 10));
    try testing.expectEqual(@as(u64, 0), schedule.wait_ns(0, 1, constants.ns_per_ms));
    try testing.expectEqual(@as(u64, 0), schedule.wait_ns(0, 1, 2 * constants.ns_per_ms));
}

test "a period of zero makes every lookup due at once" {
    const schedule: Schedule = .{ .period_ns = 0, .in_flight = 1 };
    try testing.expectEqual(@as(u64, 7), schedule.due_ns(7, 19));
    try testing.expectEqual(@as(u64, 0), schedule.wait_ns(7, 19, 7));
}
