//! `zig build spec`: the Lean models under spec/lean/, the lookup's proofs, and the replays that
//! tie the models to the Zig code (spec/README.md). build.zig stays short (CLAUDE.md, Layout), so
//! the wiring is here.
//!
//! Lean is a tool the gate must not require, as c-ares is for `bench-cares`. So `zig build test`
//! compiles the replay and runs its own tests, which replay the committed slice of the model's
//! transcript in `tools/spec_replay/lookup_gate.txt`, and needs nothing but Zig. `zig build spec`
//! needs `lake` on the path, at the version spec/lean/lean-toolchain pins. pepegrillo's `lean` tool
//! builds the proofs first (`tools/lean.zig`), which includes the module that pins the axioms each
//! one rests on. Then the step requires the committed slices to be the ones the models write, and
//! replays the whole transcripts, ReleaseSafe.
const std = @import("std");
const modules = @import("modules.zig");

/// The CNAME hops the model walks with. It must be core's `cname_hops_max`: the transcript's first
/// line records it, and the replay refuses a transcript written for another.
const cname_hops_max = "8";

/// The committed slices `zig build test` replays, and `zig build spec` checks.
const gate_transcript = "tools/spec_replay/lookup_gate.txt";
const engine_gate_transcript = "tools/spec_replay/engine_gate.txt";
const walk_gate_transcript = "tools/spec_replay/walk_gate.txt";

/// The replays' roots: the lookup's, and the engine's.
const lookup_root = "tools/spec_replay/replay.zig";
const engine_root = "tools/spec_replay/engine_replay.zig";
const walk_root = "tools/spec_replay/walk_replay.zig";

/// The engine walks `zig build spec` has the model write: the seed, the walks per
/// configuration, and the most events in one walk.
const engine_walks = .{ "1", "2000", "200" };

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
    lean_tool: *std.Build.Step.Compile,
) void {
    const debug_graph = modules.add_private(b, target, .Debug);
    for ([_][]const u8{ lookup_root, engine_root, walk_root }) |root| {
        const tests = b.addTest(.{
            .name = std.fs.path.stem(root),
            .root_module = replay_module(b, target, .Debug, debug_graph, root),
        });
        const run_tests = &b.addRunArtifact(tests).step;
        test_step.dependOn(run_tests);
        tool_test_step.dependOn(run_tests);
    }

    const graph = modules.add_private(b, target, .ReleaseSafe);
    const exe = b.addExecutable(.{
        .name = "spec-replay",
        .root_module = replay_module(b, target, .ReleaseSafe, graph, lookup_root),
    });
    const engine_exe = b.addExecutable(.{
        .name = "spec-engine-replay",
        .root_module = replay_module(b, target, .ReleaseSafe, graph, engine_root),
    });
    const walk_exe = b.addExecutable(.{
        .name = "spec-walk-replay",
        .root_module = replay_module(b, target, .ReleaseSafe, graph, walk_root),
    });
    // Compiled by the gate, so a replay that stopped compiling fails it.
    test_step.dependOn(&exe.step);
    test_step.dependOn(&engine_exe.step);
    test_step.dependOn(&walk_exe.step);

    // The proofs and the axiom pins first, through pepegrillo's `lean` tool from the repository's
    // root. Every lake run after it goes one after the other, so two never race over
    // spec/lean/.lake.
    const proofs = b.addRunArtifact(lean_tool);
    proofs.setCwd(b.path("."));
    proofs.has_side_effects = true;
    const check = lake(b, &.{ "exe", "cocuyo-spec", "check", cname_hops_max });
    check.step.dependOn(&proofs.step);
    check.addFileArg(b.path(gate_transcript));
    check.addFileArg(b.path(engine_gate_transcript));
    check.addFileArg(b.path(walk_gate_transcript));
    const transcript = lake(b, &.{ "exe", "cocuyo-spec", "all", cname_hops_max });
    transcript.step.dependOn(&check.step);
    const replay = b.addRunArtifact(exe);
    replay.addFileArg(transcript.captureStdOut(.{}));
    const engine_transcript = lake(b, &(.{ "exe", "cocuyo-spec", "engine-walks" } ++ engine_walks));
    engine_transcript.step.dependOn(&transcript.step);
    const engine_replay = b.addRunArtifact(engine_exe);
    engine_replay.addFileArg(engine_transcript.captureStdOut(.{}));
    const walk_transcript = lake(b, &.{ "exe", "cocuyo-spec", "walks" });
    walk_transcript.step.dependOn(&engine_transcript.step);
    const walk_replay = b.addRunArtifact(walk_exe);
    walk_replay.addFileArg(walk_transcript.captureStdOut(.{}));
    const step = b.step("spec", "Build the Lean proofs and models, and replay the models against the code");
    step.dependOn(&replay.step);
    step.dependOn(&engine_replay.step);
    step.dependOn(&walk_replay.step);
}

fn replay_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    root: []const u8,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("core", graph.core);
    module.addImport("wire", graph.wire);
    module.addImport("resolver", graph.resolver);
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("io", graph.io);
    module.addImport("rotor", graph.sim);
    return module;
}

/// A `lake` command run in spec/lean/. It always runs: lake knows what it has built, and the build
/// graph here does not see the Lean sources.
fn lake(b: *std.Build, arguments: []const []const u8) *std.Build.Step.Run {
    const run = b.addSystemCommand(&.{"lake"});
    run.addArgs(arguments);
    run.setCwd(b.path("spec/lean"));
    run.has_side_effects = true;
    return run;
}
