//! unreleased-acquire: a socket taken with `try` that nothing releases, where a statement under it
//! can still fail. When that statement returns, the descriptor is lost. `defer-order` reads the
//! caller of a cleanup; this one reads the function that takes the thing.
//!
//! cocuyo allocates nothing, so the only handles in the tree are the ones the operating system
//! counts, and every one of them is opened by a call named `open_something`: `open_datagram` and
//! `open_socket` of rotor's synchronous surface, and the `open_bound` and `open_one` of `io/` that
//! wrap them. Each is released by `close_now`, which the rule's default release names already
//! cover. Nothing else in the tree acquires: the caller hands cocuyo its memory, and a lookup's
//! slot is taken and freed through the table rather than by a call of this shape.
//!
//! The rule is pepegrillo's `unreleased_acquire`. This file holds cocuyo's configuration of it and
//! the fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const unreleased_acquire = lint.rules.unreleased_acquire;

pub const config: unreleased_acquire.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{ "src", "io", "examples", "bench" },
    },
    .acquire_prefixes = &.{"open_"},
    .message = "{[acquired]s} is opened here and a statement under it can fail," ++
        " and nothing releases {[acquired]s}",
};

const Rule = unreleased_acquire.Rule(config);
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

test "unreleased-acquire flags a socket nothing releases" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "io/io_udp.zig",
        \\pub fn open(family: Family) !void {
        \\    const socket = try open_datagram(family);
        \\    try arm(socket);
        \\}
        \\
    ), &.{
        "socket is opened here and a statement under it can fail," ++
            " and nothing releases socket",
    });
}

test "unreleased-acquire passes a socket a defer closes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try findings_of(arena_state.allocator(), "io/io_udp.zig",
        \\pub fn open(family: Family) !void {
        \\    const socket = try open_datagram(family);
        \\    defer close_now(socket);
        \\    try arm(socket);
        \\}
        \\
    ), &.{});
}
