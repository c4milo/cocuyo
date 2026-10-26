//! The constants of the table that are no limit: the latency windows and their parameters, and the
//! silence of a cookie. Everything the codec and the types share lives in `core/constants.zig`,
//! and the limits are in `limits.zig` (docs/design.md §16 decision 56).
const std = @import("std");
const limits = @import("limits.zig");
const core = @import("core");

/// How long queries to a server carry no COOKIE option once it answered a client cookie without
/// one, having given no server cookie: five minutes, the period RFC 9018 §3 gives as an example
/// ("for a certain period (for example, five minutes)"). After it, a fresh client cookie again
/// (docs/design.md §19 step 10). Spelled in nanoseconds, as `core/constants.zig` says why:
/// 5 * 60 * 1_000_000_000.
pub const cookie_silence_ns: u64 = 300_000_000_000;

/// A server's wait, once it has been measured, is its average latency times this: 5, c-ares's,
/// read from its features page, not measured (docs/design.md §5).
pub const latency_wait_multiplier: u64 = 5;

/// The span of the shortest of the five windows a server's samples are kept in: a minute,
/// c-ares's, read from its features page, not measured (docs/design.md §5). 60 * 1_000_000_000.
pub const latency_window_minute_ns: u64 = 60_000_000_000;
/// The span of the second window: fifteen minutes, c-ares's, read from its features page, not
/// measured (docs/design.md §5). 15 * 60 * 1_000_000_000.
pub const latency_window_quarter_hour_ns: u64 = 900_000_000_000;
/// The span of the third window: an hour, c-ares's, read from its features page, not measured
/// (docs/design.md §5). 60 * 60 * 1_000_000_000.
pub const latency_window_hour_ns: u64 = 3_600_000_000_000;
/// The span of the fourth window: a day, c-ares's, read from its features page, not measured
/// (docs/design.md §5). The fifth has no span. 24 * 60 * 60 * 1_000_000_000.
pub const latency_window_day_ns: u64 = 86_400_000_000_000;

/// Every window's span, shortest first, which is the order the wait reads them in. The fifth,
/// null, has no span: it holds every sample since the table was built.
pub const latency_window_spans_ns = [_]?u64{
    latency_window_minute_ns,
    latency_window_quarter_hour_ns,
    latency_window_hour_ns,
    latency_window_day_ns,
    null,
};
pub const latency_windows = latency_window_spans_ns.len;

comptime {
    // Two entries per slot, at the largest table, must still be a count a power of two can cover.
    if (core.limits.lookup_slots_max * limits.keys_per_slot_min > 1 << 16) {
        @compileError("the key table cannot be indexed by a sixteen-bit slot");
    }
    // The wait reads the windows shortest first, and the last holds every sample.
    for (latency_window_spans_ns[1 .. latency_windows - 1], 0..) |span, index| {
        if (span.? <= latency_window_spans_ns[index].?) @compileError("the windows are out of order");
    }
    if (latency_window_spans_ns[latency_windows - 1] != null) @compileError("no window keeps every sample");
}

// The paths a consumer reached these limits by before they moved into the limits file. Each
// is an alias, and no limit of its own. They stay until the owner rules on them (docs/design.md
// §16 decision 56, §17 question 76).
pub const keys_per_slot_min = limits.keys_per_slot_min;
pub const transactions_per_server_max = limits.transactions_per_server_max;
pub const latency_samples_min = limits.latency_samples_min;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
