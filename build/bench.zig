//! `zig build bench`: the microbenchmarks of docs/design.md §15 step 7. build.zig stays short
//! (CLAUDE.md, Layout), so the wiring is here.
//!
//! A measurement is built ReleaseSafe whatever `-Drelease` says, and so is the library it
//! measures: the bench gets a module graph of its own at ReleaseSafe, because a ReleaseSafe bench
//! over a Debug library would measure a build nobody ships. `zig build test` compiles the bench
//! without running it, so a bench that stopped compiling fails the gate, and runs the harness's
//! own tests in Debug, where the assertions on its arithmetic are what a test is for.
const std = @import("std");
const modules = @import("modules.zig");

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
) void {
    const graph = modules.add_private(b, target, .ReleaseSafe);
    const module = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("wire", graph.wire);
    const exe = b.addExecutable(.{ .name = "bench", .root_module = module });
    test_step.dependOn(&exe.step);

    const run = b.addRunArtifact(exe);
    const step = b.step("bench", "Measure query build, response parse and datagram match");
    step.dependOn(&run.step);

    // The harness's own tests, in Debug, with the graph `zig build test` already has.
    const debug_graph = modules.add_private(b, target, .Debug);
    const test_module = b.createModule(.{
        .root_source_file = b.path("bench/bench.zig"),
        .target = target,
        .optimize = .Debug,
    });
    test_module.addImport("cocuyo", debug_graph.cocuyo);
    test_module.addImport("wire", debug_graph.wire);
    const tests = b.addTest(.{ .name = "bench", .root_module = test_module });
    const run_tests = &b.addRunArtifact(tests).step;
    test_step.dependOn(run_tests);
    tool_test_step.dependOn(run_tests);
}
