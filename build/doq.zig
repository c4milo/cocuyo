//! DNS over QUIC through colibri and chapulin (docs/design.md §24, chapulin under colibri), built
//! only when `-Dchapulin` names a chapulin checkout that holds `bin/chapulin-quic-nonblocking.o`,
//! made by
//!
//!     make RAND=extern TRUST=webpki TRANSPORT=quic-nonblocking lib && cp bin/chapulin.o bin/chapulin-quic-nonblocking.o
//!
//! beside the DoT object `build/dot.zig` names, and when colibri resolved. Its headers are read
//! from the checkout in place. Without the option the build adds nothing, so neither the gate nor
//! a consumer needs chapulin.
const std = @import("std");
const modules = @import("modules.zig");

/// The object a checkout carries for this build, under its `bin/`.
const object = "bin/chapulin-quic-nonblocking.o";

/// `zig build test-chapulin-quic`, the session's own tests; and, where rotor resolved, `zig build
/// example-doq-rotor` and `zig build example-doh-rotor`, lookups over DNS over QUIC and over DoH on
/// HTTP/3.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    checkout: ?[]const u8,
    rotor: ?*std.Build.Dependency,
    colibri: ?*std.Build.Dependency,
) void {
    const path = checkout orelse return;
    const quic = (colibri orelse return).module("quic");
    const session = session_module(b, target, optimize, graph, path, quic);
    const tests = b.addTest(.{ .name = "chapulin_quic", .root_module = session });
    const step = b.step("test-chapulin-quic", "Run the DoQ session's tests over the -Dchapulin checkout");
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
    const example = b.step("example-doq-rotor", "Lookups over DNS over QUIC: -- <name>[,<name>...] <address> <auth name> <root.der>...");
    example.dependOn(&run.step);
    // DoH over HTTP/3 is the same program, handed a URI template where DoQ takes a name.
    const doh = b.step("example-doh-rotor", "Lookups over DoH on HTTP/3: -- <name>[,<name>...] <address> <URI template> <root.der>...");
    doh.dependOn(&run.step);
}

/// chapulin's QUIC session: `io/io_chapulin_quic.zig`, the checkout's headers and its object, and
/// libc, which chapulin's object needs.
fn session_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    graph: modules.Graph,
    checkout: []const u8,
    quic: *std.Build.Module,
) *std.Build.Module {
    const module = b.createModule(.{
        .root_source_file = b.path("io/io_chapulin_quic.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("quic", quic);
    module.addImport("cocuyo_quic", graph.io_quic);
    module.addImport("chapulin_hooks", graph.chapulin_hooks);
    module.addIncludePath(.{ .cwd_relative = checkout });
    module.addObjectFile(.{ .cwd_relative = b.fmt("{s}/{s}", .{ checkout, object }) });
    return module;
}
