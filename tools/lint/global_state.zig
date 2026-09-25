//! global-state: a container-level `var` under `src/` or `io/` is `threadlocal`. An image runs one
//! loop on each core and one resolver on each loop, and nothing is shared between cores
//! (docs/design.md §24, §16 decision 28). A `var` every thread shares is state two cores race on,
//! so the rule refuses it: hand the state in, or make it the thread's own.
//!
//! The rule is pepegrillo's `global_state`. This file holds cocuyo's configuration of it and the
//! fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const global_state = lint.rules.global_state;

pub const config: global_state.Config = .{
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{ "src", "io" } },
};

const Rule = global_state.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape of the configuration.

const testing = std.testing;
const harness = lint.harness;

test "global-state flags a var every thread shares, and passes a thread's own" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try harness.expect_messages(try harness.run(arena, Rule, "src/resolver/table.zig", "var shared: u32 = 0;"), &.{
        "var shared is state every thread shares: make it threadlocal, or hand it in",
    });
    try harness.expect_messages(try harness.run(arena, Rule, "io/io.zig", "threadlocal var mine: u32 = 0;"), &.{});
}

test "global-state reads src/ and io/, and leaves the tools and the examples alone" {
    try testing.expect(config.scope.applies("src/core/core.zig"));
    try testing.expect(config.scope.applies("io/io.zig"));
    try testing.expect(!config.scope.applies("examples/dot_rotor.zig"));
    try testing.expect(!config.scope.applies("tools/mutations.zig"));
}
