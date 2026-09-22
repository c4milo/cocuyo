//! The worked examples. build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
//!
//! `zig build test` compiles every example without running it. An example that stopped compiling
//! would otherwise rot quietly, and an example that does not compile is worse than no example: it
//! is documentation that lies.
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
        .summary = "One lookup over a blocking UDP socket: -- <name>",
    },
};

pub fn add(
    b: *std.Build,
    cocuyo: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
) void {
    for (examples) |example| {
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
    }
}
