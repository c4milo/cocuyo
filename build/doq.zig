//! DNS over QUIC through colibri (docs/design.md §24, chapulin under colibri): the session over
//! colibri's `tls.quic.Client`, whose module carries chapulin's QUIC object (§16 decision 32).
//! colibri is a lazy dependency, so the build adds nothing until it is fetched, and neither the
//! gate's library tests nor a consumer needs chapulin. DoH goes through colibri's channel since
//! decision 33, and `build/doh.zig` builds its example.
const std = @import("std");
const modules = @import("modules.zig");

/// `zig build test-chapulin-quic`, the session's own tests; and, where rotor resolved, `zig build
/// example-doq-rotor`, lookups over DNS over QUIC. The gate runs the tests and builds the example,
/// so a colibri that breaks the session fails it.
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
    const session = session_module(b, target, optimize, graph, resolved);
    const tests = b.addTest(.{ .name = "chapulin_quic", .root_module = session });
    const run_tests = &b.addRunArtifact(tests).step;
    b.step("test-chapulin-quic", "Run the DoQ session's tests, over colibri's tls").dependOn(run_tests);
    test_step.dependOn(run_tests);
    const dependency = rotor orelse return;
    const engine = b.createModule(.{ .root_source_file = b.path(modules.roots.io), .target = target, .optimize = optimize });
    engine.addImport("cocuyo", graph.cocuyo);
    engine.addImport("rotor", dependency.module("rotor"));
    const module = b.createModule(.{
        .root_source_file = b.path("examples/doq_rotor.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("rotor", dependency.module("rotor"));
    module.addImport("io", engine);
    module.addImport("cocuyo_quic", graph.io_quic);
    module.addImport("chapulin_quic", session);
    const exe = b.addExecutable(.{ .name = "doq-rotor", .root_module = module });
    test_step.dependOn(&exe.step);
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const example = b.step("example-doq-rotor", "Lookups over DNS over QUIC: -- <name>[/TYPE][+...][,...] <address>[:<port>] <auth name | pin-sha256:<pin>,...> <root.der>...");
    example.dependOn(&run.step);
}

/// chapulin's QUIC session: `io/io_chapulin_quic.zig` over colibri's `tls`, whose module carries
/// the object, and libc, which the object needs.
fn session_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    colibri: *std.Build.Dependency,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("io/io_chapulin_quic.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("quic", colibri.module("quic"));
    module.addImport("tls", colibri.module("tls"));
    module.addImport("cocuyo_quic", graph.io_quic);
    module.addImport("chapulin_hooks", graph.chapulin_hooks);
    return module;
}
