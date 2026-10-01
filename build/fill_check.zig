//! `zig build fill-check`: the library's hot paths call no fill, `memset` or `bzero`, beyond the
//! ones `tools/fill_check/fill_check.zig` names as known (c4milo/cocuyo#35), and nor do the
//! engine's over rotor, and the benchmark programs' own `memset` calls none. The probe is compiled
//! ReleaseSafe, stripped, for each target the library ships to, and the tool reads the assembly.
//! A cross compile needs no machine of the target's, so every host checks both.
const std = @import("std");
const modules = @import("modules.zig");

/// The targets the library ships to, by the names the tool knows their assembly by.
const targets = [_]struct { name: []const u8, query: std.Target.Query }{
    .{ .name = "x86_64-linux-gnu", .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu } },
    .{ .name = "aarch64-macos", .query = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
};

pub fn add(b: *std.Build, tool: *std.Build.Module) *std.Build.Step {
    const check = b.addExecutable(.{ .name = "fill_check", .root_module = tool });
    const step = b.step("fill-check", "Require the hot paths' ReleaseSafe code to call no memset or bzero beyond the fills known");
    for (targets) |entry| {
        const target = b.resolveTargetQuery(entry.query);
        const graph = modules.add_private(b, target, .ReleaseSafe);
        const probe = b.createModule(.{
            .root_source_file = b.path("tools/fill_check/fill_probe.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        probe.addImport("cocuyo", graph.cocuyo);
        probe.addImport("bench_memset", b.createModule(.{
            .root_source_file = b.path("bench/memset.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
            .strip = true,
        }));
        // The engine over rotor itself, built for this target and ReleaseSafe, which rotor's build
        // spells `release`: a rotor asked for no mode builds Debug. rotor is lazy, and the build
        // runs again once it has fetched it, so the first pass adds nothing for the target.
        const rotor = b.lazyDependency("rotor", .{ .target = target, .release = true }) orelse continue;
        const engine = b.createModule(.{
            .root_source_file = b.path(modules.roots.io),
            .target = target,
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        engine.addImport("cocuyo", graph.cocuyo);
        engine.addImport("rotor", rotor.module("rotor"));
        probe.addImport("io", engine);
        probe.addImport("rotor", rotor.module("rotor"));
        const object = b.addObject(.{ .name = "fill_probe", .root_module = probe });
        const run = b.addRunArtifact(check);
        if (modules.require_release_rotor(b, rotor, "the fill check")) |fail| run.step.dependOn(fail);
        run.addArg(entry.name);
        // No `expectExitCode(0)`: it checks the output, and Zig 0.16 prints a checked step's
        // stderr as a failed command even when it passed. A step fails on any other exit anyway.
        run.addFileArg(object.getEmittedAsm());
        step.dependOn(&run.step);
    }
    return step;
}
