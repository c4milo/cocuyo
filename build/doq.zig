//! DNS over QUIC through colibri (docs/design.md §24, chapulin under colibri): the session over
//! colibri's `tls.quic.Client`, whose module carries chapulin's QUIC object (§16 decision 32).
//! colibri is a lazy dependency, so the build adds nothing until it is fetched, and neither the
//! gate's library tests nor a consumer needs chapulin. DoH goes through colibri's channel since
//! decision 33, and `build/doh.zig` builds its example.
//!
//! The session is `chapulin_quic`, a module the build registers (§16 decision 38, as amended). Its
//! tests and the example use that module, with colibri bound into it here as a consumer binds it.
const std = @import("std");
const modules = @import("modules.zig");
const crypto_context = @import("crypto_context.zig");

/// `zig build test-chapulin-quic`, the session's own tests, where stdx resolved, since they make
/// their context through `crypto_context`; and, where rotor resolved too, `zig build
/// example-doq-rotor`, lookups over DNS over QUIC. The gate runs the tests and builds the example,
/// so a colibri that breaks the session fails it.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    lazy: modules.Lazy,
) void {
    const resolved = lazy.colibri orelse return;
    const stdx = lazy.stdx orelse return;
    const session = bind(graph, resolved);
    const tests = b.addTest(.{ .name = "chapulin_quic", .root_module = crypto_context.test_module(b, session, stdx) });
    const run_tests = &b.addRunArtifact(tests).step;
    b.step("test-chapulin-quic", "Run the DoQ session's tests, over colibri's tls").dependOn(run_tests);
    test_step.dependOn(run_tests);
    const dependency = lazy.rotor orelse return;
    const engine = b.createModule(.{ .root_source_file = b.path(modules.roots.io), .target = target, .optimize = optimize });
    engine.addImport("cocuyo", graph.cocuyo);
    modules.add_internal(engine, graph);
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
    module.addImport("cocuyo_quic", graph.cocuyo_quic);
    module.addImport("chapulin_quic", session);
    // The verifier the word `dnssec` validates over (`examples/trust_text.zig`).
    module.addImport("cocuyo_dnssec", graph.cocuyo_dnssec);
    // The CPU's features the example detects, and the context of colibri's TLS
    // (`examples/cpu_text.zig`).
    module.addImport("stdx", stdx);
    const exe = b.addExecutable(.{ .name = "doq-rotor", .root_module = module });
    test_step.dependOn(&exe.step);
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const example = b.step("example-doq-rotor", "Lookups over DNS over QUIC: -- [dnssec <anchors>] <name>[/TYPE][+...][,...] <address>[:<port>] <auth name | pin-sha256:<pin>,...> <root.der>...");
    example.dependOn(&run.step);
}

/// Binds colibri where a consumer that speaks DoQ binds it, as `test/consumer/build.zig` does: its
/// one module, `colibri`, into `cocuyo_quic` and into `chapulin_quic` (colibri decision 170).
/// Returns the session's module, which the build registers with the rest of its imports bound.
fn bind(graph: modules.Graph, colibri: *std.Build.Dependency) *std.Build.Module {
    const root = colibri.module("colibri");
    graph.cocuyo_quic.addImport("colibri", root);
    graph.chapulin_quic.addImport("colibri", root);
    return graph.chapulin_quic;
}
