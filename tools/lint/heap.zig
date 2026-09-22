//! heap: cocuyo allocates nothing (CLAUDE.md non-negotiable 2). The caller hands the library its
//! memory at init, so no file under `src/` names an allocator — not `std.heap`, not a parameter
//! whose type holds the segment `Allocator`, not the testing allocator.
//!
//! The rule is pepegrillo's `forbidden_references`. This file holds cocuyo's configuration of it
//! and the fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const forbidden_references = lint.rules.forbidden_references;

/// Every chain that names an allocator a file did not receive. `std.testing` is listed member by
/// member, because the rest of it is what every test uses.
const forbidden_prefixes = [_][]const u8{
    "std.heap",
    "std.testing.allocator",
    "std.testing.allocator_instance",
    "std.testing.failing_allocator",
    "std.testing.FailingAllocator",
};

const reason = "cocuyo allocates nothing; the caller owns every buffer (non-negotiable 2)";

/// The configuration. It reads `src/` alone: developer tooling under `tools/` allocates freely,
/// and nothing under `tools/` is linked into the library.
pub const config: forbidden_references.Config = .{
    .name = "heap",
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{"src"} },
    .prefixes = &forbidden_prefixes,
    .parameter_check = .{ .type_segment = "Allocator", .description = "an allocator parameter" },
    .reason = reason,
};

const Rule = forbidden_references.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, path, source);
    try harness.expect_messages(findings, expected);
}

test "heap flags std.heap and an allocator parameter under src" {
    try expect_findings("src/wire/wire.zig",
        \\const std = @import("std");
        \\pub fn build(allocator: std.mem.Allocator) void {
        \\    _ = allocator;
        \\    _ = std.heap.page_allocator;
        \\}
        \\
    , &.{
        "build takes an allocator parameter: " ++ reason,
        "reference to std.heap.page_allocator: " ++ reason,
    });
}

test "heap reads no file outside src" {
    try expect_findings("tools/lint/heap.zig",
        \\const std = @import("std");
        \\pub fn run(allocator: std.mem.Allocator) void {
        \\    _ = allocator;
        \\}
        \\
    , &.{});
}
