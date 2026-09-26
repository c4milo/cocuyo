//! `zig build readme-check`: the README's Zig code, built and run (tools/readme_check.zig).
//! build.zig stays short (CLAUDE.md, Layout), so the wiring is here.
const std = @import("std");

/// Where the package the tool writes lives, and where its nested build keeps its cache and its
/// output: under this build's cache, so nothing it writes lands in the tree.
const package_dir = ".zig-cache/readme-check/package";
const nested_cache = ".zig-cache/readme-check/cache";

pub fn add(b: *std.Build, tool: *std.Build.Module) *std.Build.Step {
    const check = b.addExecutable(.{ .name = "readme_check", .root_module = tool });
    const run = b.addRunArtifact(check);
    run.addArg(b.graph.zig_exe);
    run.addFileArg(b.path("README.md"));
    run.addFileArg(b.path("build.zig.zon"));
    run.addArg(b.pathFromRoot(package_dir));
    run.addArg(b.pathFromRoot(nested_cache));
    // The README's code reads the whole public surface, so the check runs every time rather than
    // naming each file it depends on.
    run.has_side_effects = true;

    const step = b.step("readme-check", "Build every Zig block of the README against the library, and run the quick start");
    step.dependOn(&run.step);
    return step;
}
