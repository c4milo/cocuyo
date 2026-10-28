//! The constants of the cache that are no limit: the place of the hash's fields, a unit and a
//! default (docs/design.md §18). The limits the cache holds are in `limits.zig` (§16 decision 56).
const std = @import("std");
const limits = @import("limits.zig");
const core = @import("core");

/// The TTL cap when the caller sets none: an hour, which is c-ares's default (§18), so a consumer
/// replacing it sees the same ceiling. RFC 8767 §4 asks for a cap and recommends seven days at
/// most, so an hour is inside it. It is `core`'s constant, under the name it has had here, since
/// `Config.cache_ttl_seconds_max` defaults to the same number (docs/design.md §16 decision 37).
pub const ttl_seconds_max_default = core.constants.cache_ttl_seconds_max_default;

/// The time the first resolution failure of a name is kept when the caller sets none:
/// `Cache.failure_seconds_min`. RFC 9520 §3.2 gives 5 seconds as its example of the initial time,
/// inside its bounds of 1 second and 5 minutes. It is `core`'s constant, since
/// `Config.cache_failure_seconds_min` defaults to the same number (docs/design.md §16 decision 60).
pub const failure_seconds_min_default = core.constants.cache_failure_seconds_min_default;

/// Where the type and the flag sit in the word the hash starts from: the flag's one bit at 40,
/// the type's sixteen at 48, so the two never overlap whatever the seed.
pub const hash_absolute_shift: u6 = 40;
pub const hash_kind_shift: u6 = 48;

/// Nanoseconds in a second, spelled out because nothing under `src/` may name `std.time`
/// (CLAUDE.md non-negotiable 4).
pub const ns_per_s: u64 = 1_000_000_000;

comptime {
    if (limits.slots_max * limits.keys_per_slot_min > 1 << 16) @compileError("the key index cannot be indexed by a u16");
    if (limits.slots_max >= 0xfffe) @compileError("a slot index would collide with a sentinel");
    if (failure_seconds_min_default < limits.failure_seconds_least) @compileError("the default failure time is under RFC 9520's least");
    if (failure_seconds_min_default > limits.failure_seconds_max) @compileError("the default failure time is over RFC 9520's most");
    if (limits.probe_max < 2) @compileError("a probe of one entry is a hash lookup with no chain");
}

// The paths a consumer reached these limits by before they moved into the limits file. Each
// is an alias, and no limit of its own. They stay until the owner rules on them (docs/design.md
// §16 decision 56, §17 question 76).
pub const slots_max = limits.slots_max;
pub const keys_per_slot_min = limits.keys_per_slot_min;
pub const probe_max = limits.probe_max;
pub const sweep_steps_max = limits.sweep_steps_max;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
