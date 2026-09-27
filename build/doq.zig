//! DNS over QUIC and DoH on HTTP/3 through colibri (docs/design.md §24, chapulin under colibri):
//! the session over colibri's `tls.quic.Client`, whose module carries chapulin's QUIC object (§16
//! decision 32). colibri is a lazy dependency, so the build adds nothing until it is fetched, and
//! neither the gate's library tests nor a consumer needs chapulin.
const std = @import("std");
const modules = @import("modules.zig");

/// `zig build test-chapulin-quic`, the session's own tests; and, where rotor resolved, `zig build
/// example-doq-rotor` and `zig build example-doh-rotor`, lookups over DNS over QUIC and over DoH on
/// HTTP/3.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    rotor: ?*std.Build.Dependency,
    colibri: ?*std.Build.Dependency,
) void {
    const resolved = colibri orelse return;
    const session = session_module(b, target, optimize, graph, resolved);
    const tests = b.addTest(.{ .name = "chapulin_quic", .root_module = session });
    const step = b.step("test-chapulin-quic", "Run the DoQ session's tests, over colibri's tls");
    step.dependOn(&b.addRunArtifact(tests).step);
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
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const example = b.step("example-doq-rotor", "Lookups over DNS over QUIC: -- <name>[/TYPE][+...][,...] <address>[:<port>] <auth name | pin-sha256:<pin>,...> <root.der>...");
    example.dependOn(&run.step);
    // DoH over HTTP/3 is the same program, handed a URI template where DoQ takes a name.
    const doh = b.step("example-doh-rotor", "Lookups over DoH on HTTP/3: -- <name>[/TYPE][+...][,...] <address> <URI template> <root.der>...");
    doh.dependOn(&run.step);
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
