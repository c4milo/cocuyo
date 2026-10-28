//! The constants of the parsers that are no limit: the keywords and the options of a `resolv.conf`
//! and of a hosts file, a unit, and the default nameserver. The limits the parsers hold are in
//! `limits.zig` (docs/design.md §16 decision 56).
//!
//! `resolv.conf` has no RFC. Its keywords and its options are what the platform manual pages
//! document — `resolv.conf(5)` on Linux and on macOS — so this module cites a manual page where
//! the rest of cocuyo cites an RFC, and says so (CLAUDE.md non-negotiable 8).
const std = @import("std");
const limits = @import("limits.zig");
const core = @import("core");

/// The nameserver a `resolv.conf` with no `nameserver` line means: the local one. Every platform
/// stub does this, and a `Config` with no server at all would be a configuration no lookup could
/// use (docs/design.md §10).
pub const nameserver_default = [_]u8{ 127, 0, 0, 1 };

/// The keywords a line may start with that the parser reads (`resolv.conf(5)`). A line that
/// starts with any other is skipped.
pub const keyword_nameserver = "nameserver";
pub const keyword_search = "search";
pub const keyword_domain = "domain";
pub const keyword_options = "options";

/// What separates tokens on a line, and what starts a comment.
pub const token_separators = " \t\r";
pub const comment_starts = "#;";

/// The hosts file (`hosts(5)`): the character that starts a comment.
pub const hosts_comment_start: u8 = '#';

/// The `use-vc` option of `resolv.conf(5)`: every query over TCP.
pub const option_use_vc = "use-vc";

/// One second in nanoseconds, which a `timeout:` value is multiplied by. It is spelled out
/// because nothing under `src/` may name `std.time` (CLAUDE.md non-negotiable 4).
pub const ns_per_s: u64 = 1_000_000_000;

comptime {
    if (limits.timeout_seconds_limit * ns_per_s > core.limits.timeout_ns_max) {
        @compileError("a timeout the parser reads would not fit under any cap");
    }
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
