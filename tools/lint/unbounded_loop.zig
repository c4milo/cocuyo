//! unbounded-loop: every loop and every queue is bounded (CLAUDE.md non-negotiable 5). cocuyo
//! parses hostile input, so a loop whose trip count comes from the message is the bug that turns a
//! malformed datagram into a hang: a compression pointer chain, a record walk, a CNAME chain.
//!
//! Two shapes are findings. First, `while (true)` with no `break`, or with a `break` that no named
//! limit governs. Second, a condition that reads a length — a call or field named `len`,
//! `remaining`, `count` and the rest of `length_reader_names` — against an integer literal while
//! the loop names no limit.
//!
//! A limit is a chain holding the segment `constants`, or one whose last segment ends in `_max`:
//! `compression_hops_max`, `constants.records_max`.
//!
//! The rule is pepegrillo's `unbounded_loop`. This file holds cocuyo's configuration of it and the
//! fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const unbounded_loop = lint.rules.unbounded_loop;

/// The last name of a length read. A call or a field with one of these names, compared against an
/// integer literal, is the shape of the second check.
const length_reader_names = [_][]const u8{
    "remaining",
    "len",
    "size",
    "count",
    "bytes_remaining",
    "bytes_left",
};

pub const config: unbounded_loop.Config = .{
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{"src"} },
    .forever = .unless_bounded_break,
    .length_read = true,
    .bound = .{ .segments = &.{"constants"}, .last_segment_suffixes = &.{"_max"} },
    .length_reader_names = &length_reader_names,
    .messages = .{
        .forever_without_break = "while (true) has no break; nothing ends the loop" ++
            " (non-negotiable 5)",
        .forever_without_bound = "while (true) breaks on no named limit;" ++
            " bound it with a constants.zig value (non-negotiable 5)",
        .length_read = "the condition reads {[read]s} against a literal" ++
            " and the loop names no limit (non-negotiable 5)",
    },
};

const Rule = unbounded_loop.Rule(config);
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

test "unbounded-loop flags a forever loop that no limit ends" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "src/wire/wire_name.zig",
        \\pub fn decode() void {
        \\    while (true) {}
        \\}
        \\
    ), &.{"while (true) has no break; nothing ends the loop (non-negotiable 5)"});
}

test "unbounded-loop passes a hop loop bounded by a named limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "src/wire/wire_name.zig",
        \\const constants = @import("constants.zig");
        \\pub fn decode(message: []const u8) void {
        \\    var hops: u32 = 0;
        \\    while (true) {
        \\        if (hops == constants.compression_hops_max) break;
        \\        hops += 1;
        \\        _ = message;
        \\    }
        \\}
        \\
    ), &.{});
}
