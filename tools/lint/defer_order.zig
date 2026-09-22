//! defer-order: a `defer` or an `errdefer` registered under a statement that can fail. That
//! statement returns before the cleanup is registered, so whatever the block acquired above it is
//! never released.
//!
//! cocuyo allocates nothing, so what leaks here is not memory: it is a socket the engine opened,
//! a buffer group a loop still holds, or a lookup's slot. `io/` is where those live, and `src/`
//! is where an ordering mistake would be hardest to see, since nothing there owns anything the
//! operating system counts.
//!
//! The rule passes a `defer` that names something the statement above it produced, which is the
//! ordinary `const socket = try open(...); defer close(socket);`. What it reports is a cleanup
//! for something acquired further up, registered under a statement that can return first.
//!
//! The rule is pepegrillo's `defer_order`. This file holds cocuyo's configuration of it and the
//! fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const defer_order = lint.rules.defer_order;

pub const config: defer_order.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{ "src", "io", "examples", "bench", "tools", "build" },
    },
    .message = "a defer under a statement that can fail; what the block took above it" ++
        " is never released when that statement returns",
};

const Rule = defer_order.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const lint.report.Finding {
    return harness.run(arena, Rule, path, source);
}

test "defer-order flags a cleanup for something taken further up" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "io/io.zig",
        \\pub fn open(loop: *Loop) !void {
        \\    const socket = try first();
        \\    try second(socket);
        \\    defer close_all();
        \\}
        \\
    ), &.{
        "a defer under a statement that can fail; what the block took above it" ++
            " is never released when that statement returns",
    });
}

test "defer-order passes a cleanup for what the statement above it produced" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "io/io.zig",
        \\pub fn open() !void {
        \\    const socket = try first();
        \\    defer close(socket);
        \\}
        \\
    ), &.{});
}
