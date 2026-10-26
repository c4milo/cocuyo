//! The limits the cache holds (docs/design.md §16 decision 56, §18).
const std = @import("std");

/// The most slots one cache may hold. A slot is named by a `u16` in the insertion-order chain and
/// in the key index, with room left for the sentinels, and nobody has asked for more.
pub const slots_max: usize = 16384;

/// The key index holds at least this many entries per slot, so a bounded probe stays short.
pub const keys_per_slot_min: usize = 2;

/// The longest chain a `get` walks before calling it a miss and a `put` before refusing. A peer
/// that chooses the names a process resolves cannot choose where they land, because the hash is
/// keyed by the caller's seed; this bound is what makes a run of collisions cost a miss and never
/// a walk.
pub const probe_max: usize = 16;

/// The most steps one eviction sweep takes: one pass over every slot clears every visited bit,
/// and the next pass must then find an unvisited one.
pub fn sweep_steps_max(slot_count: usize) usize {
    return slot_count * 2;
}

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
