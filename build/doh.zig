//! DoH over colibri's client (docs/design.md §24, DoH over colibri's client): `cocuyo_doh`, colibri's
//! `client.Channel` under the engine's DoH interface. colibri is a lazy dependency, requested only by
//! cocuyo's root build, so the build adds nothing here until it is fetched. The channel's TLS is
//! colibri's `tls`, whose module carries chapulin's objects, so the tests link libc, as the sessions'
//! do (`build/doq.zig`).
const std = @import("std");
const modules = @import("modules.zig");

/// Binds colibri's `client` and `tls` into the tests' module, and its `server`, which the tests
/// answer with, and adds `zig build test-cocuyo_doh`: the type against colibri's server in memory,
/// and the engine over it on the twin. Where rotor resolved, it adds `zig build example-doh-rotor`
/// as well, lookups over DoH through the channel. The gate runs the tests and builds the example,
/// so a colibri that breaks the type fails it. Null `colibri` is the build before the fetch.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    test_step: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
    colibri: ?*std.Build.Dependency,
) void {
    const dependency = colibri orelse return;
    const module = graph.io_doh_channel;
    module.addImport("client", dependency.module("client"));
    module.addImport("tls", dependency.module("tls"));
    module.addImport("server", dependency.module("server"));
    module.addImport("io", graph.io);
    module.addImport("rotor", graph.sim);
    module.link_libc = true;
    const tests = b.addTest(.{ .name = "cocuyo_doh", .root_module = module });
    const run = &b.addRunArtifact(tests).step;
    test_step.dependOn(run);
    b.step("test-cocuyo_doh", "Run cocuyo_doh's tests, over colibri's client and server").dependOn(run);
    if (rotor) |loop| test_step.dependOn(add_example(b, target, optimize, graph, dependency, loop));
}

/// The engine over the real rotor with `cocuyo_doh`, both built here privately, as the bench builds
/// its own: the engine is not exported (docs/design.md §19 step 13). Returns the example's build,
/// which the gate depends on.
fn add_example(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    colibri: *std.Build.Dependency,
    rotor: *std.Build.Dependency,
) *std.Build.Step {
    const engine = b.createModule(.{ .root_source_file = b.path(modules.roots.io), .target = target, .optimize = optimize });
    engine.addImport("cocuyo", graph.cocuyo);
    engine.addImport("rotor", rotor.module("rotor"));
    const doh = b.createModule(.{
        .root_source_file = b.path(modules.roots.io_doh_channel),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    doh.addImport("cocuyo", graph.cocuyo);
    doh.addImport("doh", graph.doh);
    doh.addImport("chapulin_hooks", graph.chapulin_hooks);
    doh.addImport("client", colibri.module("client"));
    doh.addImport("tls", colibri.module("tls"));
    const module = b.createModule(.{
        .root_source_file = b.path("examples/doh_rotor.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("rotor", rotor.module("rotor"));
    module.addImport("io", engine);
    module.addImport("cocuyo_doh", doh);
    module.addImport("tls", colibri.module("tls"));
    const exe = b.addExecutable(.{ .name = "doh-rotor", .root_module = module });
    const run = b.addRunArtifact(exe);
    if (b.args) |arguments| run.addArgs(arguments);
    const step = b.step("example-doh-rotor", "Lookups over DoH through colibri's channel: -- <name>[/TYPE][+...][,...] <address> <URI template> <root.der>...");
    step.dependOn(&run.step);
    return &exe.step;
}
