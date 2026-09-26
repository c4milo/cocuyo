//! `zig build dnslib-check -- <directory>`: the codec against dnslib's reading of responses real
//! servers sent (`tools/dnslib/check.zig`). The directory is fetched by `tools/dnslib/run.sh`, so
//! the step runs only when asked. `zig build test` runs the check's own tests, which need no
//! network. build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
const std = @import("std");
const modules = @import("modules.zig");

const root = "tools/dnslib/check.zig";

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
) void {
    const tests = b.addTest(.{ .name = "dnslib_check", .root_module = check_module(b, target, graph) });
    const run_tests = &b.addRunArtifact(tests).step;
    test_step.dependOn(run_tests);
    tool_test_step.dependOn(run_tests);

    const exe = b.addExecutable(.{ .name = "dnslib-check", .root_module = check_module(b, target, graph) });
    // Compiled by the gate, so a check that stopped compiling fails it.
    test_step.dependOn(&exe.step);
    const run = b.addRunArtifact(exe);
    run.has_side_effects = true;
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step("dnslib-check", "Compare the codec's reading of dnslib's captured responses with dnslib's");
    step.dependOn(&run.step);
}

fn check_module(b: *std.Build, target: std.Build.ResolvedTarget, graph: modules.Graph) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = .Debug,
    });
    module.addImport("core", graph.core);
    module.addImport("wire", graph.wire);
    return module;
}
