//! `zig build spec`: the Lean model of `Lookup` under spec/, its proofs, and the replay that ties
//! the model to the Zig code (spec/README.md). build.zig stays short (CLAUDE.md, Layout), so the
//! wiring is here.
//!
//! Lean is a tool the gate must not require, as c-ares is for `bench-cares`. So `zig build test`
//! compiles the replay and runs its own tests, which replay the committed slice of the model's
//! transcript in `tools/spec_replay/lookup_gate.txt`, and needs nothing but Zig. `zig build spec`
//! needs `lake` on the path, at the version spec/lean-toolchain pins. It builds the proofs, which
//! includes the module that pins the axioms each one rests on, requires the committed slice to be
//! the one the model writes, and then replays the whole transcript, ReleaseSafe.
const std = @import("std");
const modules = @import("modules.zig");

/// The CNAME hops the model walks with. It must be core's `cname_hops_max`: the transcript's first
/// line records it, and the replay refuses a transcript written for another.
const cname_hops_max = "8";

/// The committed slice `zig build test` replays, and `zig build spec` checks.
const gate_transcript = "tools/spec_replay/lookup_gate.txt";

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
) void {
    const debug_graph = modules.add_private(b, target, .Debug);
    const tests = b.addTest(.{
        .name = "spec_replay",
        .root_module = replay_module(b, target, .Debug, debug_graph),
    });
    const run_tests = &b.addRunArtifact(tests).step;
    test_step.dependOn(run_tests);
    tool_test_step.dependOn(run_tests);

    const graph = modules.add_private(b, target, .ReleaseSafe);
    const exe = b.addExecutable(.{
        .name = "spec-replay",
        .root_module = replay_module(b, target, .ReleaseSafe, graph),
    });
    // Compiled by the gate, so a replay that stopped compiling fails it.
    test_step.dependOn(&exe.step);

    // `lake exe` builds what it runs first, the proofs and the axiom pins with it. The two runs
    // go one after the other, so two builds never race over spec/.lake.
    const check = lake(b, &.{ "exe", "cocuyo-spec", "check", cname_hops_max });
    check.addFileArg(b.path(gate_transcript));
    const transcript = lake(b, &.{ "exe", "cocuyo-spec", "all", cname_hops_max });
    transcript.step.dependOn(&check.step);
    const replay = b.addRunArtifact(exe);
    replay.addFileArg(transcript.captureStdOut(.{}));
    const step = b.step("spec", "Build the Lean proofs of the lookup and replay the model against it");
    step.dependOn(&replay.step);
}

fn replay_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("tools/spec_replay/replay.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("core", graph.core);
    module.addImport("wire", graph.wire);
    module.addImport("resolver", graph.resolver);
    return module;
}

/// A `lake` command run in spec/. It always runs: lake knows what it has built, and the build
/// graph here does not see the Lean sources.
fn lake(b: *std.Build, arguments: []const []const u8) *std.Build.Step.Run {
    const run = b.addSystemCommand(&.{"lake"});
    run.addArgs(arguments);
    run.setCwd(b.path("spec"));
    run.has_side_effects = true;
    return run;
}
