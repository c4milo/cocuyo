//! `zig build orders`: the check that no order of a validating table's replies changes a verdict,
//! over a range of seeds (tools/orders.zig, c4milo/cocuyo#61). build.zig stays short (CLAUDE.md,
//! Layout), so the wiring is here.
const std = @import("std");
const modules = @import("modules.zig");

const root = "tools/orders.zig";

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
) void {
    const tests = b.addTest(.{ .name = "orders_tool", .root_module = tool_module(b, target, graph) });
    const run_tests = &b.addRunArtifact(tests).step;
    test_step.dependOn(run_tests);
    tool_test_step.dependOn(run_tests);

    // ReleaseSafe, so a long range runs fast with every check and assertion still on.
    const exe = b.addExecutable(.{ .name = "orders", .root_module = tool_module(b, target, modules.add_private(b, target, .ReleaseSafe)) });
    test_step.dependOn(&exe.step);
    const range = b.addRunArtifact(exe);
    if (b.args) |arguments| range.addArgs(arguments);
    b.step("orders", "Run the order check over a range of seeds: -- [<count> [<first>]]").dependOn(&range.step);
}

fn tool_module(b: *std.Build, target: std.Build.ResolvedTarget, graph: modules.Graph) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = graph.core.optimize orelse .Debug,
    });
    module.addImport("sim", graph.sim);
    return module;
}
