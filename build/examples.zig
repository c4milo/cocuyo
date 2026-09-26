//! The worked examples. build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
//!
//! `zig build test` compiles every example it can without running it. An example that stopped
//! compiling would otherwise rot quietly, and an example that does not compile is worse than no
//! example: it is documentation that lies.
//!
//! Two of them are driven by rotor, an event loop of its own. rotor is a dependency of those
//! examples and of nothing else: not of the library, not of the tests. It is lazy, so a build that
//! does not ask for them never resolves it, and cocuyo's own graph never names it (`zig build
//! graph-check`). rotor exports one module and chooses its own backend by host, so nothing here
//! knows whether an example ends up on io_uring or on kqueue.
const std = @import("std");
const modules = @import("modules.zig");
const bench = @import("bench.zig");

const Example = struct {
    /// The step and binary name: `zig build example-<name>`.
    name: []const u8,
    root: []const u8,
    summary: []const u8,
};

const examples = [_]Example{
    .{
        .name = "udp-blocking",
        .root = "examples/udp_blocking.zig",
        .summary = "One lookup over a UDP socket, on std.Io: -- <name>",
    },
};

/// The rotor example, added only when rotor resolved and the target has a backend.
const rotor_example: Example = .{
    .name = "udp-rotor",
    .root = "examples/udp_rotor.zig",
    .summary = "One lookup over rotor's completion-based loop: -- <name>",
};

/// Two engines on two threads, each on its own rotor loop (docs/design.md §24 step 6). It runs the
/// engine, which is not a module of the library a consumer binds rotor into here, so it is built
/// privately against rotor, as `build/dot.zig` builds it.
const threads_example: Example = .{
    .name = "threads-rotor",
    .root = "examples/threads_rotor.zig",
    .summary = "Two engines on two threads, each on its own rotor loop, resolving at once",
};

pub fn add(
    b: *std.Build,
    graph: modules.Graph,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
    sanitize_thread: bool,
) void {
    // Built for another target with `-Dtarget`, an example cannot run where it was built, and
    // `tools/search_order/run.sh` runs it in a container instead: this puts it in the prefix.
    const install = b.step("examples", "Install the worked examples into the prefix's bin/");
    for (examples) |example| {
        _ = add_one(b, graph.cocuyo, target, optimize, test_step, install, example);
    }
    add_rotor(b, graph, target, optimize, test_step, install, rotor);
    add_threads(b, graph, target, optimize, test_step, install, rotor, sanitize_thread);
}

fn add_one(
    b: *std.Build,
    cocuyo: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    install: *std.Build.Step,
    example: Example,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path(example.root),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("cocuyo", cocuyo);
    const exe = b.addExecutable(.{ .name = example.name, .root_module = module });
    test_step.dependOn(&exe.step);
    install.dependOn(&b.addInstallArtifact(exe, .{}).step);

    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step(b.fmt("example-{s}", .{example.name}), example.summary);
    step.dependOn(&run.step);
    return module;
}

/// rotor exports one module and picks its own backend by host, so this adds the example only
/// where rotor has a backend to pick: Linux and Darwin. Elsewhere there is no example rather than
/// an example that does not compile.
fn add_rotor(
    b: *std.Build,
    graph: modules.Graph,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    install: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
) void {
    const dependency = rotor orelse return;
    switch (target.result.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .visionos => {},
        else => return,
    }
    const module = add_one(b, graph.cocuyo, target, optimize, test_step, install, rotor_example);
    module.addImport("rotor", dependency.module("rotor"));
}

/// The two-engine example, where rotor has a backend. Under `-Dsanitize-thread` it is built in
/// Debug from a graph whose every module is instrumented, with LLVM, since Zig 0.16's own x86_64
/// backend instruments nothing, and it runs only after the planted race of the comparison's
/// control is reported, so the sanitizer's silence over it means something.
fn add_threads(
    b: *std.Build,
    graph: modules.Graph,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    install: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
    sanitize_thread: bool,
) void {
    const dependency = rotor orelse return;
    switch (target.result.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .visionos => {},
        else => return,
    }
    const used = if (sanitize_thread) modules.add_sanitized(b, target) else graph;
    const mode: std.builtin.OptimizeMode = if (sanitize_thread) .Debug else optimize;
    const engine = b.createModule(.{ .root_source_file = b.path(modules.roots.io), .target = target, .optimize = mode });
    engine.addImport("cocuyo", used.cocuyo);
    engine.addImport("rotor", dependency.module("rotor"));
    engine.sanitize_thread = sanitize_thread;
    const module = b.createModule(.{ .root_source_file = b.path(threads_example.root), .target = target, .optimize = mode });
    module.addImport("cocuyo", used.cocuyo);
    module.addImport("rotor", dependency.module("rotor"));
    module.addImport("io", engine);
    // The responder's socket is libc's, as the bench's is.
    module.link_libc = true;
    module.sanitize_thread = sanitize_thread;
    const use_llvm: ?bool = if (sanitize_thread) true else null;
    const exe = b.addExecutable(.{ .name = threads_example.name, .root_module = module, .use_llvm = use_llvm });
    test_step.dependOn(&exe.step);
    install.dependOn(&b.addInstallArtifact(exe, .{}).step);
    const run = b.addRunArtifact(exe);
    if (sanitize_thread) {
        run.setEnvironmentVariable("TSAN_OPTIONS", "halt_on_error=1");
        run.step.dependOn(bench.sanitizer_control(b, target, use_llvm));
    }
    const step = b.step(b.fmt("example-{s}", .{threads_example.name}), threads_example.summary);
    step.dependOn(&run.step);
}
