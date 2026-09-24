//! `zig build spec`: the Lean models under spec/lean/, the lookup's proofs, the engine model's walks
//! under spec/tla/engine/, and the replays that tie the models to the Zig code (spec/README.md).
//! build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
//!
//! Lean and TLC are tools the gate must not require, as c-ares is for `bench-cares`. So `zig build
//! test` compiles the replays and runs their own tests, which replay the committed slices of the
//! models' transcripts in `tools/spec_replay/`, and needs nothing but Zig. `zig build spec` needs
//! `lake` on the path, at the version spec/lean/lean-toolchain pins, and Java for TLC. pepegrillo's
//! `lean` tool builds the proofs first (`tools/lean.zig`), which includes the module that pins the
//! axioms each one rests on. Then the step requires the committed slices to be the ones the models
//! write, and replays the whole transcripts, ReleaseSafe.
//!
//! `zig build spec-lean` is the Lean half alone, which needs no Java, and `zig build spec-engine`
//! the engine's part alone, which needs Java and not Lean. With
//! `-Dengine-walks=<file>` it replays walks written before instead of having TLC write them, which
//! is how a mutation of the engine is measured.
const std = @import("std");
const modules = @import("modules.zig");

/// The CNAME hops the model walks with. It must be core's `cname_hops_max`: the transcript's first
/// line records it, and the replay refuses a transcript written for another.
const cname_hops_max = "8";

/// The committed slices `zig build test` replays, and `zig build spec` checks.
const gate_transcript = "tools/spec_replay/lookup_gate.txt";
const engine_gate_transcript = "tools/spec_replay/engine_gate.txt";
const engine_picks_transcript = "tools/spec_replay/engine_picks.txt";
const walk_gate_transcript = "tools/spec_replay/walk_gate.txt";

/// The replays' roots: the lookup's, and the engine's.
const lookup_root = "tools/spec_replay/replay.zig";
const engine_root = "tools/spec_replay/engine_replay.zig";
const walk_root = "tools/spec_replay/walk_replay.zig";

/// The engine walks `zig build spec` has TLC write (`tools/tla_walks.zig`): the seed, the walks
/// per configuration, and the states in one walk, which is one more than its events.
const engine_walks = .{ "1", "2000", "201" };
/// The committed engine walks: the same seed, ten walks per configuration, forty events each.
const engine_gate_walks = .{ "1", "10", "41" };
/// The full run's walks the committed ones keep as well, by their place in the run, counted from 1
/// in the configurations' order: each is where the full run caught a mutation of the engine that
/// the short walks miss (docs/mutations.md, the engine replay on TLC's walks).
const engine_picks = .{ "51", "79", "359", "4011", "8095", "8279", "8573" };

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    test_step: *std.Build.Step,
    tool_test_step: *std.Build.Step,
    lean_tool: *std.Build.Step.Compile,
    tla_tool: *std.Build.Step.Compile,
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
    check.addFileArg(b.path(walk_gate_transcript));
    const transcript = lake(b, &.{ "exe", "cocuyo-spec", "all", cname_hops_max });
    transcript.step.dependOn(&check.step);
    const replay = b.addRunArtifact(exe);
    replay.addFileArg(transcript.captureStdOut(.{}));
    const walk_transcript = lake(b, &.{ "exe", "cocuyo-spec", "walks" });
    walk_transcript.step.dependOn(&transcript.step);
    const walk_replay = b.addRunArtifact(walk_exe);
    walk_replay.addFileArg(walk_transcript.captureStdOut(.{}));
    // The Lean half alone, which needs no Java: the Lean model's mutations are measured on it.
    const lean_step = b.step("spec-lean", "Build the Lean proofs and models, and replay the lookup and the walks against the code");
    lean_step.dependOn(&replay.step);
    lean_step.dependOn(&walk_replay.step);
    const step = b.step("spec", "Build the Lean proofs and models, have TLC walk the engine's, and replay them against the code");
    step.dependOn(lean_step);
    step.dependOn(add_engine(b, tla_tool, engine_exe));
    add_mutations(b);
}

/// `zig build spec-engine`: the committed engine walks, the short ones and the picked ones,
/// required to be the ones TLC writes, then TLC's full run replayed against the engine, or the
/// walks `-Dengine-walks` names.
fn add_engine(b: *std.Build, tla_tool: *std.Build.Step.Compile, engine_exe: *std.Build.Step.Compile) *std.Build.Step {
    const step = b.step("spec-engine", "Have TLC walk the engine model, and replay the walks against the engine");
    const engine_replay = b.addRunArtifact(engine_exe);
    if (b.option([]const u8, "engine-walks", "Replay these engine walks instead of having TLC write them")) |path| {
        engine_replay.addFileArg(.{ .cwd_relative = path });
    } else {
        const gate = tla_walks(b, tla_tool, &engine_gate_walks);
        const full = tla_walks(b, tla_tool, &engine_walks);
        // One after the other: on a machine without TLC's jar each would fetch it to one place.
        full.step.dependOn(&gate.step);
        full.addArg("--pick");
        const picked = full.addOutputFileArg("engine_picks.txt");
        full.addArgs(&engine_picks);
        engine_replay.addFileArg(full.captureStdOut(.{}));
        engine_replay.step.dependOn(same(b, engine_gate_transcript, gate.captureStdOut(.{})));
        engine_replay.step.dependOn(same(b, engine_picks_transcript, picked));
    }
    step.dependOn(&engine_replay.step);
    return step;
}

/// `zig build mutations -- <set>`: the mutations of `tools/mutations/<set>.zon` run again, each
/// against the check it names: the committed walks and TLC's full run, which the tool has TLC
/// write the first time a mutation needs it unless `--walks <file>` names one, or a build step. It
/// edits the tree while it runs, and puts each file back.
fn add_mutations(b: *std.Build) void {
    const tool = b.addExecutable(.{ .name = "mutations", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/mutations.zig"),
        .target = b.graph.host,
    }) });
    const run = b.addRunArtifact(tool);
    run.setCwd(b.path("."));
    run.has_side_effects = true;
    const arguments = b.args orelse &.{};
    // The set comes first, then the walks the build knows, then what else the caller named.
    if (arguments.len > 0) run.addArg(arguments[0]);
    run.addArgs(&.{ "--short", engine_gate_transcript, "--picked", engine_picks_transcript, "--full" });
    run.addArgs(&engine_walks);
    run.addArg("--full-out");
    _ = run.addOutputFileArg("engine_walks.txt");
    if (arguments.len > 1) run.addArgs(arguments[1..]);
    const step = b.step("mutations", "Break the code each way a set of tools/mutations/ says, and require each caught");
    step.dependOn(&run.step);
}

/// Requires the committed walks at `committed` to be the ones TLC wrote, and shows how they differ.
fn same(b: *std.Build, committed: []const u8, written: std.Build.LazyPath) *std.Build.Step {
    const diff = b.addSystemCommand(&.{ "diff", "-u" });
    diff.addFileArg(b.path(committed));
    diff.addFileArg(written);
    return &diff.step;
}

/// The engine model's walks, which the `tla` tool has TLC write from the repository's root. They
/// are TLC's to write each time: the build graph does not see the model's sources.
fn tla_walks(b: *std.Build, tla_tool: *std.Build.Step.Compile, arguments: []const []const u8) *std.Build.Step.Run {
    const run = b.addRunArtifact(tla_tool);
    run.setCwd(b.path("."));
    run.addArg("walks");
    run.addArgs(arguments);
    run.has_side_effects = true;
    return run;
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
