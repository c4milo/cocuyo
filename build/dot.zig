//! DNS over TLS through chapulin (docs/design.md §21 step 5), built only when `-Dchapulin` names a
//! chapulin checkout: its record-mode object and its headers, read in place, as colibri's driver
//! links chapulin. Nothing of chapulin is vendored. Without the option the build adds nothing,
//! so neither the gate nor a consumer needs chapulin.
//!
//! The checkout's object is made by
//!
//!     make RAND=extern TRUST=webpki TRANSPORT=record lib && cp bin/chapulin.o bin/chapulin-record.o
const std = @import("std");
const modules = @import("modules.zig");

/// The object a checkout carries for this build, under its `bin/`.
const object = "bin/chapulin-record.o";

/// `zig build test-chapulin`, the session's own tests, which need no network; and, where rotor
/// resolved, `zig build example-dot-rotor`, one lookup over DNS over TLS.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    checkout: ?[]const u8,
    rotor: ?*std.Build.Dependency,
) void {
    const path = checkout orelse return;
    const session = session_module(b, target, optimize, graph, path, graph.io);
    const tests = b.addTest(.{ .name = "chapulin", .root_module = session });
    const step = b.step("test-chapulin", "Run the DoT session's tests over the -Dchapulin checkout");
    step.dependOn(&b.addRunArtifact(tests).step);
    if (rotor) |dependency| add_example(b, target, optimize, graph, path, dependency);
}

/// The engine over the real rotor with chapulin's session, built here privately, as the bench
/// builds its own: the engine is not exported (docs/design.md §19 step 13).
fn add_example(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    checkout: []const u8,
    rotor: *std.Build.Dependency,
) void {
    const engine = b.createModule(.{
        .root_source_file = b.path(modules.roots.io),
        .target = target,
        .optimize = optimize,
    });
    engine.addImport("cocuyo", graph.cocuyo);
    engine.addImport("rotor", rotor.module("rotor"));
    const session = session_module(b, target, optimize, graph, checkout, engine);
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
    const step = b.step("example-dot-rotor", "One lookup over DNS over TLS: -- <name> <address> <auth name> <root.der>...");
    step.dependOn(&run.step);
}

/// chapulin's session: `io/io_chapulin.zig`, the checkout's headers and its object, and libc,
/// which chapulin's object needs. It reads the engine's constants through `engine`, the engine
/// module it is built for.
pub fn session_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    checkout: []const u8,
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
    module.addIncludePath(.{ .cwd_relative = checkout });
    module.addObjectFile(.{ .cwd_relative = b.fmt("{s}/{s}", .{ checkout, object }) });
    return module;
}
