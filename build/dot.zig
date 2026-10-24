//! DNS over TLS through colibri (docs/design.md §21 step 5): the session over colibri's
//! `tls.record.Client`, whose module carries chapulin's record-mode object (§16 decision 32).
//! colibri is a lazy dependency, so a project that depends on cocuyo never fetches it for this.
//!
//! colibri builds the object `RAND=session TRUST=webpki TRANSPORT=tcp-nonblocking`. On x86-64 and
//! arm64 it is chapulin's host object. A session runs AES only where the program states its CPU and
//! its thread's timing mode (colibri's decision 97, as amended for chapulin 0.2.0). The session
//! states what its context carries, which the consumer fills (docs/design.md §16 decision 48).
//! colibri compares the object's build record with the headers it translated at each
//! configuration. So an object built another way stops the program there, and does not lay its
//! sessions out otherwise unnoticed.
//!
//! The session is `chapulin`, a module the build registers (§16 decision 38, as amended for §17
//! question 64). Its tests and the example use that module, with colibri and rotor bound here as a
//! consumer binds them.
const std = @import("std");
const modules = @import("modules.zig");

/// `zig build test-chapulin`, the session's own tests, which need no network; and, where stdx
/// resolved, `zig build example-dot-rotor`, lookups over DNS over TLS. The gate runs the tests and
/// builds the example, so a colibri that breaks the session fails it. Nothing until colibri and
/// rotor are fetched, which the build runner does the first time it sees them requested. The
/// session's `io` is the registered engine, whose `rotor` the tests need bound too.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    lazy: modules.Lazy,
) void {
    const resolved = lazy.colibri orelse return;
    const loop = lazy.rotor orelse return;
    const session = bind(graph, resolved, loop);
    const tests = b.addTest(.{ .name = "chapulin", .root_module = session });
    const run = &b.addRunArtifact(tests).step;
    b.step("test-chapulin", "Run the DoT session's tests, over colibri's tls").dependOn(run);
    test_step.dependOn(run);
    const platform = lazy.platform orelse return;
    test_step.dependOn(add_example(b, target, optimize, graph, loop, platform));
}

/// The engine over the real rotor with chapulin's session: the registered `cocuyo_rotor` and
/// `chapulin`, which `bind` bound as a consumer binds them. Returns the example's build, which the
/// gate depends on.
fn add_example(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    rotor: *std.Build.Dependency,
    platform: *std.Build.Module,
) *std.Build.Step {
    const module = b.createModule(.{
        .root_source_file = b.path("examples/dot_rotor.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("rotor", rotor.module("rotor"));
    module.addImport("io", graph.cocuyo_rotor);
    module.addImport("chapulin", graph.chapulin);
    // The probe the word `cpu` states the CPU from (`examples/cpu_text.zig`).
    module.addImport("platform", platform);
    const exe = b.addExecutable(.{ .name = "dot-rotor", .root_module = module });
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step("example-dot-rotor", "Lookups over DNS over TLS: -- [cpu] <name>[/TYPE][+...][,...] <address>[:<port>] <auth name | pin-sha256:<pin>,...> <root.der>...");
    step.dependOn(&run.step);
    return &exe.step;
}

/// Binds rotor and colibri where a consumer that speaks DoT binds them, as
/// `test/consumer/build.zig` does: rotor's `rotor` into `cocuyo_rotor`, the session's `io`, and
/// colibri's `tls` and `tls_provider` into `chapulin`. colibri's `tls` module carries the objects:
/// a second object of the same build would define every public name twice (§16 decision 32).
/// Returns the session's module, which the build registers with the rest of its imports bound.
///
/// This is the only place where the root build binds a `rotor` into `cocuyo_rotor`. `addImport`
/// replaces a binding without a word, so a second binding would change the engine of the session
/// and of the example. The first assertion stops a binding made before this one.
fn bind(graph: modules.Graph, colibri: *std.Build.Dependency, rotor: *std.Build.Dependency) *std.Build.Module {
    std.debug.assert(graph.cocuyo_rotor.import_table.get("rotor") == null);
    graph.cocuyo_rotor.addImport("rotor", rotor.module("rotor"));
    std.debug.assert(graph.cocuyo_rotor.import_table.get("rotor").? == rotor.module("rotor"));
    graph.chapulin.addImport("tls", colibri.module("tls"));
    graph.chapulin.addImport("tls_provider", colibri.module("tls_provider"));
    return graph.chapulin;
}
