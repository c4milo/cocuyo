//! relative-import: a file imports the module name build/modules.zig declares, never a path that
//! climbs out of its own module (CLAUDE.md, Layout). The module graph of docs/design.md §2 is
//! enforced by the build, and a relative import is how a file escapes it: `@import("../core/
//! name.zig")` from `src/resolver/` would give the state machine a second copy of `core` that the
//! graph never granted.
//!
//! Inside one module a relative import is how files are assembled, so only a path that leaves the
//! module, or an absolute one, is a finding.
//!
//! The rule is pepegrillo's `relative_import`. This file holds cocuyo's configuration of it and
//! the fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const relative_import = lint.rules.relative_import;

pub const config: relative_import.Config = .{
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{ "src", "io" } },
    .mode = .leaves_subsystem,
    .message = "@import(\"{[path]s}\") reaches out of the module by path;" ++
        " import the module name build/modules.zig declares",
};

const Rule = relative_import.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

/// The arena owns the findings, so the caller holds it: a helper that freed its own arena would
/// return a slice into memory it had just released.
fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const lint.report.Finding {
    return harness.run(arena, Rule, path, source);
}

test "relative-import flags a path that climbs out of the module" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "src/resolver/lookup.zig",
        \\const name = @import("../core/name.zig");
        \\comptime {
        \\    _ = name;
        \\}
        \\
    ), &.{
        "@import(\"../core/name.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
    });
}

test "relative-import passes a file assembling its own module" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "src/wire/wire.zig",
        \\pub const name_codec = @import("wire_name.zig");
        \\
    ), &.{});
}
