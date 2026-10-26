//! magic-numbers: every limit is named in a `limits.zig` with a doc comment saying why that number,
//! and never written at the use site (CLAUDE.md non-negotiable 5). The protocol sizes and the
//! defaults are named in a `constants.zig` the same way (docs/design.md §16 decision 56). A wire
//! format is where this rule earns its keep: `255`, `63`, `0xC0` and `12` all mean something in
//! RFC 1035, and a reader who meets them inline has to know which. Named, they read as
//! `name_bytes_max`, `label_bytes_max`, `pointer_mask` and `header_bytes`, and a change to one
//! looks like a diff that changes a constant.
//!
//! The width of an octet is `@bitSizeOf(u8)`, never 8, so a shift by a whole octet names what it
//! shifts by.
//!
//! Three basenames are exempt. `limits.zig` is the file the limits belong in, and `constants.zig`
//! the file the protocol sizes and the defaults belong in. `fixtures.zig` holds hand-written wire
//! messages for the tests of its module: it is all numbers, the numbers are the format, and naming
//! each octet of a message would say less than the octets do. Each exemption is by basename, so
//! every module gets one of each and no other file gets any.
//!
//! This rule takes a number named in any `const`, wherever it is. That a limit is named in a limits
//! file, and in no constants file or other file, is the typed-constants rule's check
//! (`typed_constants.zig`).
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
        .include_directories = &.{ "src", "io" },
        .exclude_basenames = &.{ "limits.zig", "constants.zig", "fixtures.zig" },
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

test "magic-numbers exempts the limits, the constants and the corpus, and nothing else" {
    try testing.expect(!config.scope.applies("src/core/limits.zig"));
    try testing.expect(!config.scope.applies("io/limits.zig"));
    try testing.expect(config.scope.applies("io/io_quic_limits.zig"));
    try testing.expect(!config.scope.applies("src/core/constants.zig"));
    try testing.expect(!config.scope.applies("src/wire/constants.zig"));
    try testing.expect(!config.scope.applies("src/wire/fixtures.zig"));
    try testing.expect(config.scope.applies("src/wire/name.zig"));
    try testing.expect(config.scope.applies("src/wire/fixtures_extra.zig"));
}
