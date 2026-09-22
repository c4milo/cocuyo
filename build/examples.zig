//! The worked examples. build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
//!
//! `zig build test` compiles every example it can without running it. An example that stopped
//! compiling would otherwise rot quietly, and an example that does not compile is worse than no
//! example: it is documentation that lies.
//!
//! One of them is driven by rotor, an event loop of its own. rotor is a dependency of that example
//! and of nothing else: not of the library, not of the tests. It is lazy, so a build that does not
//! ask for the example never resolves it, and cocuyo's own graph never names it
//! (`zig build graph-check`). rotor exports one module and chooses its own backend by host, so
//! nothing here knows whether the example ends up on io_uring or on kqueue.
const std = @import("std");

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

pub fn add(
    b: *std.Build,
    cocuyo: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
) void {
    for (examples) |example| {
        _ = add_one(b, cocuyo, target, optimize, test_step, example);
    }
    add_rotor(b, cocuyo, target, optimize, test_step, rotor);
}

fn add_one(
    b: *std.Build,
    cocuyo: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
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
    cocuyo: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
) void {
    const dependency = rotor orelse return;
    switch (target.result.os.tag) {
        .linux, .macos, .ios, .tvos, .watchos, .visionos => {},
        else => return,
    }
    const module = add_one(b, cocuyo, target, optimize, test_step, rotor_example);
    module.addImport("rotor", dependency.module("rotor"));
}
