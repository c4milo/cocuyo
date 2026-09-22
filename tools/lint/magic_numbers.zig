//! magic-numbers: every limit is named in a `constants.zig` with a doc comment saying why that
//! number, and never written at the use site (CLAUDE.md non-negotiable 5). A wire format is where
//! this rule earns its keep: `255`, `63`, `0xC0` and `12` all mean something in RFC 1035, and a
//! reader who meets them inline has to know which. Named, they read as `name_bytes_max`,
//! `label_bytes_max`, `pointer_mask` and `header_bytes`, and a change to one looks like a diff
//! that changes a constant.
//!
//! The width of an octet is `@bitSizeOf(u8)`, never 8, so a shift by a whole octet names what it
//! shifts by.
//!
//! `constants.zig` is exempt, because it is the file the numbers belong in.
//!
//! The rule is pepegrillo's `magic_numbers`. This file holds cocuyo's configuration of it and the
//! fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const magic_numbers = lint.rules.magic_numbers;

pub const config: magic_numbers.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{"src"},
        .exclude_basenames = &.{"constants.zig"},
    },
};

const Rule = magic_numbers.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

test "magic-numbers flags a literal shift and a literal buffer length" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/wire/wire_name.zig",
        \\pub fn decode(octets: []const u8) u64 {
        \\    var value: u64 = 0;
        \\    for (octets) |octet| value = (value << 8) | octet;
        \\    var buffer: [16]u8 = @splat(0);
        \\    _ = &buffer;
        \\    return value;
        \\}
        \\
    );
    try testing.expect(findings.len >= 1);
}

test "magic-numbers exempts the file the numbers belong in" {
    try testing.expect(!config.scope.applies("src/core/constants.zig"));
    try testing.expect(!config.scope.applies("src/wire/constants.zig"));
    try testing.expect(config.scope.applies("src/wire/wire_name.zig"));
}
