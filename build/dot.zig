//! DNS over TLS through colibri (docs/design.md §21 step 5): the session over colibri's
//! `tls.record.Client`, whose module carries chapulin's record-mode object (§16 decision 32).
//! colibri is a lazy dependency, so a project that depends on cocuyo never fetches it for this.
//!
//! colibri builds the object `RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking`, with AES-GCM on
//! the AES instructions where the target has them and ChaCha20-Poly1305 alone elsewhere (its
//! decision 97). It compares the object's build record with the headers it translated whenever a
//! configuration is made, so an object built another way stops the program there, rather than lay
//! its sessions out otherwise unnoticed.
const std = @import("std");
const modules = @import("modules.zig");

/// `zig build test-chapulin`, the session's own tests, which need no network; and, where rotor
/// resolved, `zig build example-dot-rotor`, lookups over DNS over TLS. The gate runs the tests and
/// builds the example, so a colibri that breaks the session fails it. Nothing until colibri is
/// fetched, which the build runner does the first time it sees it requested.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
    colibri: ?*std.Build.Dependency,
) void {
    const resolved = colibri orelse return;
    const session = session_module(b, target, optimize, graph, resolved, graph.io);
    const tests = b.addTest(.{ .name = "chapulin", .root_module = session });
    const run = &b.addRunArtifact(tests).step;
    b.step("test-chapulin", "Run the DoT session's tests, over colibri's tls").dependOn(run);
    test_step.dependOn(run);
    if (rotor) |loop| test_step.dependOn(add_example(b, target, optimize, graph, resolved, loop));
}

/// The engine over the real rotor with chapulin's session, built here privately, as the bench
/// builds its own: the engine is not exported (docs/design.md §19 step 13). Returns the example's
/// build, which the gate depends on.
fn add_example(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    colibri: *std.Build.Dependency,
    rotor: *std.Build.Dependency,
) *std.Build.Step {
    const engine = b.createModule(.{
        .root_source_file = b.path(modules.roots.io),
        .target = target,
        .optimize = optimize,
    });
    engine.addImport("cocuyo", graph.cocuyo);
    engine.addImport("rotor", rotor.module("rotor"));
    const session = session_module(b, target, optimize, graph, colibri, engine);
    const module = b.createModule(.{
        .root_source_file = b.path("examples/dot_rotor.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("rotor", rotor.module("rotor"));
    module.addImport("io", engine);
    module.addImport("chapulin", session);
    const exe = b.addExecutable(.{ .name = "dot-rotor", .root_module = module });
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step("example-dot-rotor", "Lookups over DNS over TLS: -- <name>[/TYPE][+...][,...] <address>[:<port>] <auth name | pin-sha256:<pin>,...> <root.der>...");
    step.dependOn(&run.step);
    return &exe.step;
}

/// chapulin's session: `io/io_chapulin.zig` over colibri's `tls`, whose module carries the object,
/// and libc, which the object needs. It reads the engine's constants through `engine`, the engine
/// module it is built for.
pub fn session_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    colibri: *std.Build.Dependency,
    engine: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("io/io_chapulin.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("io", engine);
    module.addImport("chapulin_hooks", graph.chapulin_hooks);
    // The module carries the objects: a second object of the same build would define every public
    // name twice (§16 decision 32).
    module.addImport("tls", colibri.module("tls"));
    module.addImport("tls_provider", colibri.module("tls_provider"));
    return module;
}
