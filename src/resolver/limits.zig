//! The limits the table and the lookup hold (docs/design.md §16 decision 56). The limits more than
//! one module shares are in `core/limits.zig`; these are the table's own.
const std = @import("std");

/// The key table holds at least this many entries per slot. A load factor of one half is where
/// linear probing still finds an entry in a step or two, and the table is sized by the caller, so
/// the floor is checked rather than assumed (docs/design.md §11).
pub const keys_per_slot_min: usize = 2;

/// The transactions a lookup draws for one name on one server in one pass: the query, the
/// retry without EDNS0 after FORMERR (RFC 6891 §6.2.2) and the retry with the server cookie
/// after BADCOOKIE (RFC 7873 §5.3), which is the server's once, over UDP or over a stream. It
/// bounds a transaction's `number` (docs/design.md §22).
pub const transactions_per_server_max: usize = 3;

/// The samples a server needs since its table was built before its wait comes from them, and the
/// samples a window needs before the wait reads it: 3, c-ares's, read from its features page, not
/// measured. Until then the server waits `Config.timeout_ns` (docs/design.md §5).
pub const latency_samples_min: usize = 3;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
