//! `zig build bench`: the microbenchmarks of docs/design.md §15 step 7, and `zig build bench-cares`:
//! the comparison against c-ares. build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
//!
//! The comparison links a library the gate must not require, so nothing of it runs under
//! `zig build test`: `bench-cares` compiles the comparison's own tests and runs them, then runs the
//! comparison, and a machine without c-ares simply cannot run that step. The library is found under
//! `-Dcares=<prefix>`, a Homebrew prefix by default, and the version measured is the one the
//! binary prints, read from the library itself.
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
    rotor: ?*std.Build.Dependency,
    sanitize_thread: bool,
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

    add_cares(b, target, graph, debug_graph, rotor, sanitize_thread);
    add_log(b, target, graph, test_step);
}

/// `zig build bench-log -- <dataset.csv>`: the cache and its policy models over a real DNS log
/// (docs/design.md §18). The log is not in the tree, so the gate compiles the replay and never
/// runs it; its tests run with the harness's.
fn add_log(b: *std.Build, target: std.Build.ResolvedTarget, graph: modules.Graph, test_step: *std.Build.Step) void {
    const module = b.createModule(.{
        .root_source_file = b.path("bench/log_replay.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    module.addImport("cocuyo", graph.cocuyo);
    const exe = b.addExecutable(.{ .name = "bench-log", .root_module = module });
    test_step.dependOn(&exe.step);
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step("bench-log", "Replay a real DNS log through the cache and its models: -- <dataset.csv>");
    step.dependOn(&run.step);
}

/// Where a Homebrew c-ares lives on Apple Silicon. Any prefix with `include/ares.h` and
/// `lib/libcares` will do; this is the one the measurements in docs/design.md §11 were made with.
const cares_prefix_default = "/opt/homebrew/opt/c-ares";

/// `zig build bench-cares`: the comparison, ReleaseSafe for cocuyo, the installed build for c-ares.
/// Its tests run first, in Debug, so the two sides are shown to be looking at the same bytes
/// before either is timed.
fn add_cares(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    graph: modules.Graph,
    debug_graph: modules.Graph,
    rotor: ?*std.Build.Dependency,
    sanitize_thread: bool,
) void {
    const prefix = b.option(
        []const u8,
        "cares",
        "The c-ares install prefix for bench-cares (default " ++ cares_prefix_default ++ ")",
    ) orelse cares_prefix_default;
    // The comparison's driver shares state between two threads, ours and c-ares's, and every race
    // it has had lived there. ThreadSanitizer sees an access to shared state that nothing orders,
    // whether or not the bad interleaving happened in the run. Off by default: Zig 0.16 cannot
    // build its runtime for arm64 macOS, and CI turns it on for Linux. Only the driver's module is
    // instrumented; the engine and rotor under it are not, and hold no state two threads share,
    // which the two-engine example shows under the sanitizer (`build/examples.zig`).

    const test_module = cares_module(b, target, .Debug, prefix, debug_graph, rotor);
    test_module.sanitize_thread = sanitize_thread;
    // Zig 0.16's own x86_64 backend, the default for Debug there, instruments nothing and says
    // nothing about it; LLVM does the instrumenting. The control is built the same way, so it
    // fails wherever the tests would be blind.
    const use_llvm: ?bool = if (sanitize_thread) true else null;
    const tests = b.addTest(.{ .name = "cares", .root_module = test_module, .use_llvm = use_llvm });
    const run_tests = b.addRunArtifact(tests);
    if (sanitize_thread) run_tests.step.dependOn(sanitizer_control(b, target, use_llvm));

    const test_cares = b.step("test-cares", "Run the comparison's own tests alone");
    test_cares.dependOn(&run_tests.step);

    const module = cares_module(b, target, .ReleaseSafe, prefix, graph, rotor);
    const exe = b.addExecutable(.{ .name = "bench-cares", .root_module = module });
    const run = b.addRunArtifact(exe);
    run.step.dependOn(&run_tests.step);

    const step = b.step("bench-cares", "Measure query build and response parse against c-ares");
    step.dependOn(&run.step);
}

/// ThreadSanitizer's exit status when it has reported a race.
const sanitizer_reported_exit = 66;

/// A planted race the sanitizer must report before its silence over the tests means anything,
/// as the lint's canary does for the lint (docs/mutations.md T1).
pub fn sanitizer_control(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    use_llvm: ?bool,
) *std.Build.Step {
    const module = b.createModule(.{
        .root_source_file = b.path("bench/end_to_end/race_control.zig"),
        .target = target,
        .optimize = .Debug,
        .link_libc = true,
        .sanitize_thread = true,
    });
    const exe = b.addExecutable(.{ .name = "race-control", .root_module = module, .use_llvm = use_llvm });
    const run = b.addRunArtifact(exe);
    run.setEnvironmentVariable("TSAN_OPTIONS", "halt_on_error=1");
    run.expectExitCode(sanitizer_reported_exit);
    return &run.step;
}

/// The comparison's module. Its end-to-end run drives the engine of docs/design.md §19 step 13
/// over rotor itself, so the engine is built here, privately, against the real rotor: the one
/// place in the tree that binds the two, and not a library (step 13).
fn cares_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    prefix: []const u8,
    graph: modules.Graph,
    rotor: ?*std.Build.Dependency,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("bench/cares.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("wire", graph.wire);
    if (rotor) |dependency| {
        const engine = b.createModule(.{
            .root_source_file = b.path(modules.roots.io),
            .target = target,
            .optimize = optimize,
        });
        engine.addImport("cocuyo", graph.cocuyo);
        engine.addImport("rotor", dependency.module("rotor"));
        module.addImport("rotor", dependency.module("rotor"));
        module.addImport("io", engine);
    }
    module.addIncludePath(.{ .cwd_relative = b.fmt("{s}/include", .{prefix}) });
    module.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/lib", .{prefix}) });
    module.linkSystemLibrary("cares", .{});
    return module;
}
