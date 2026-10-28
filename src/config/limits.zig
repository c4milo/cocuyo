//! The limits the parsers hold: the shape of a `resolv.conf` and of a hosts file rather than
//! anything the protocol fixes (docs/design.md §16 decision 56). The keywords and the defaults are
//! in `constants.zig`.
const std = @import("std");

/// The most lines the parser reads from one file. A `resolv.conf` is a handful of lines; the bound
/// is what keeps a file the parser did not write from deciding how long it runs.
pub const lines_max: usize = 256;

/// The most option tokens one `options` line is read for. A line holds a handful; the bound is
/// what keeps a file the parser did not write from deciding how long it runs.
pub const options_max: usize = 16;

/// The hosts file (`hosts(5)`): the most lines read from one. What the table holds is bounded in
/// `core`, where the table lives.
pub const hosts_lines_max: usize = 4096;

/// The most `ndots:` reads: `resolv.conf(5)` caps it at 15, and a larger value reads as 15.
pub const ndots_limit: usize = 15;

/// The most `timeout:` reads, in seconds: `resolv.conf(5)` caps it at 30. That is also the most
/// `Config.timeout_ns_max` may be, so the parser can raise the cap to any timeout it reads.
pub const timeout_seconds_limit: u64 = 30;

/// The text fuzz target (`fuzz/fuzz.zig`, docs/design.md §13). The longest text it builds, which
/// holds the longest file it writes several times over; the most servers, search names and hosts
/// lines it writes whole, below every limit the parsers keep so that each must come back; the most
/// labels in a name, and the longest label it writes but for one of full length; and the most
/// comment or blank lines it puts between two lines that count.
pub const fuzz_text_bytes_max: usize = 2048;
pub const fuzz_entries_max: usize = 4;
pub const fuzz_labels_max: usize = 4;
pub const fuzz_label_bytes_max: usize = 12;
pub const fuzz_filler_lines_max: usize = 2;

/// The longest noise the target writes: longer than any address, name or pin it reads.
pub const fuzz_noise_bytes_max: usize = 96;

/// The most hexadecimal digits the text fuzz target writes in one IPv6 group
/// (`fuzz/fuzz_generate.zig`): the four RFC 4291 §2.2 allows.
pub const fuzz_hex_digits_max: usize = 4;

/// The most blanks the text fuzz target writes between two tokens
/// (`fuzz/fuzz_generate_files.zig`). Chosen, not measured.
pub const fuzz_blanks_max: usize = 3;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
