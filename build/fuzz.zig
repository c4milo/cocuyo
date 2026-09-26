//! `zig build fuzz` and `zig build fuzz-gate`: the two fuzz targets run outside the test runner,
//! one seed or a range of them (tools/fuzz.zig, docs/design.md §13). build.zig stays short
//! (CLAUDE.md, Layout), so the wiring is here.
const std = @import("std");
const modules = @import("modules.zig");

const root = "tools/fuzz.zig";

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
) void {
    const tests = b.addTest(.{ .name = "fuzz_tool", .root_module = tool_module(b, target, graph) });
    const run_tests = &b.addRunArtifact(tests).step;
    test_step.dependOn(run_tests);
    tool_test_step.dependOn(run_tests);

    // ReleaseSafe, so a long range runs fast with every check and assertion still on.
    const exe = b.addExecutable(.{ .name = "fuzz", .root_module = tool_module(b, target, modules.add_private(b, target, .ReleaseSafe)) });
    test_step.dependOn(&exe.step);
    const one = b.addRunArtifact(exe);
    if (b.args) |arguments| one.addArgs(arguments);
    b.step("fuzz", "Run one fuzz seed and print what it built: -- [--text] --seed <hex>").dependOn(&one.step);
    const range = b.addRunArtifact(exe);
    range.addArg("--gate");
    if (b.args) |arguments| range.addArgs(arguments);
    b.step("fuzz-gate", "Run a range of fuzz seeds: -- [--text] [<count> [<first>]]").dependOn(&range.step);
}

fn tool_module(b: *std.Build, target: std.Build.ResolvedTarget, graph: modules.Graph) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = graph.core.optimize orelse .Debug,
    });
    module.addImport("wire", graph.wire);
    module.addImport("config", graph.config);
    return module;
}
