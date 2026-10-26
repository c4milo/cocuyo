//! The limits of DoH that `cocuyo_doh` reads (docs/design.md §24, New limits; §16 decision 56).
const std = @import("std");

/// A DoH GET's `:path`, which an exchange holds in a buffer of this size (docs/design.md §24, New
/// limits). The bound is on the path alone, by the owner's ruling of 2026-10-14 (§17 question 41).
/// A channel's `start` expands its template with a `dns` value at its longest, 512 octets, and
/// refuses a template whose path then passes this bound. A test sends that GET over HTTP/2, with
/// an authority of 259 octets: a name of 253 octets and a port. colibri's server answers it.
pub const doh_request_bytes_max: usize = 1536;

/// RFC 9111 §1.2.2's 2^31, "infinity (over 68 years)".
pub const age_seconds_max: u32 = 2147483648;

/// The last code point of a plane that a template's `ucschar` may hold (`io_doh_template.zig`):
/// 0xFFFE and 0xFFFF of each plane are not characters (RFC 3987 §2.2).
pub const template_plane_offset_max: u21 = 0xFFFD;

/// The most digits of a template's `max-length` (`io_doh_template.zig`): `%x31-39 0*3DIGIT`, a
/// positive integer below 10,000 (RFC 6570 §2.4.1).
pub const template_max_length_digits_max: usize = 4;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
