//! DNS over TLS through chapulin (docs/design.md §21 step 5), over chapulin's Zig API: the module
//! of the `chapulin` dependency, which carries its record-mode object (chapulin's docs/zig.md).
//! chapulin is a lazy dependency that only cocuyo's own build requests, so a project that depends
//! on cocuyo never fetches it (c4milo/cocuyo#30).
//!
//! The object is built `RAND=extern TRUST=webpki TRANSPORT=tcp-nonblocking`. It keeps chapulin's
//! default multiply, every widening product in 16x16 pieces, which claims nothing about the CPU.
//! `CH_NATIVE_MUL128` among the options would state that "the 64x64->128 multiply runs in constant
//! time" instead: chapulin measured the client's side of a handshake 1.5 to 1.9 times faster with
//! it on an Apple M1 Pro (bench/notes-primitives.md there). cocuyo makes that statement for no
//! part, so it keeps the default.
//!
//! Every session compares the object's build record with the headers its module was translated
//! from when it starts: an object built another way stops the program there, rather than lay its
//! sessions out otherwise unnoticed.
const std = @import("std");
const modules = @import("modules.zig");

/// `zig build test-chapulin`, the session's own tests, which need no network; and, where rotor
/// resolved, `zig build example-dot-rotor`, lookups over DNS over TLS. Nothing until chapulin is
/// fetched, which the build runner does the first time it sees it requested.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    rotor: ?*std.Build.Dependency,
) void {
    const dependency = b.lazyDependency("chapulin", .{
        .target = target,
        .RAND = .@"extern",
        .TRANSPORT = .@"tcp-nonblocking",
        .TRUST = .webpki,
    }) orelse return;
    const chapulin = dependency.module("chapulin");
    const session = session_module(b, target, optimize, graph, chapulin, graph.io);
    const tests = b.addTest(.{ .name = "chapulin", .root_module = session });
    const step = b.step("test-chapulin", "Run the DoT session's tests, over chapulin's record-mode object");
    step.dependOn(&b.addRunArtifact(tests).step);
    if (rotor) |loop| add_example(b, target, optimize, graph, chapulin, loop);
}

/// The engine over the real rotor with chapulin's session, built here privately, as the bench
/// builds its own: the engine is not exported (docs/design.md §19 step 13).
fn add_example(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    chapulin: *std.Build.Module,
    rotor: *std.Build.Dependency,
) void {
    const engine = b.createModule(.{
        .root_source_file = b.path(modules.roots.io),
        .target = target,
        .optimize = optimize,
    });
    engine.addImport("cocuyo", graph.cocuyo);
    engine.addImport("rotor", rotor.module("rotor"));
    const session = session_module(b, target, optimize, graph, chapulin, engine);
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
}

/// chapulin's session: `io/io_chapulin.zig` over chapulin's module, which carries the object, and
/// libc, which the object needs. It reads the engine's constants through `engine`, the engine
/// module it is built for.
pub fn session_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    chapulin: *std.Build.Module,
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
    // The module carries the object: a second object of the same build would define every public
    // name twice (chapulin's docs/zig.md).
    module.addImport("chapulin", chapulin);
    return module;
}
