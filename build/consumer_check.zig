//! `zig build consumer-check`: the check of docs/design.md §20. build.zig stays short
//! (CLAUDE.md, Layout), so the wiring is here and the check itself is tools/consumer_check.zig.
const std = @import("std");

/// Where the nested build keeps its cache and its output: under this build's cache, so the
/// fixture's own directory holds sources and nothing else. The fixture lives outside every
/// directory the lint and the format check read, because a nested build materialises whatever
/// packages the machine already holds into a `zig-pkg/` beside it, and those are not ours to
/// score.
const nested_cache = ".zig-cache/consumer";

pub fn add(b: *std.Build, tool: *std.Build.Module) *std.Build.Step {
    const check = b.addExecutable(.{ .name = "consumer_check", .root_module = tool });
    const run = b.addRunArtifact(check);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg(b.path("test/consumer"));
    run.addArg(b.pathFromRoot(nested_cache));
    // The dependent build reads the manifest and the surface, so re-run when either moves.
    run.addFileInput(b.path("build.zig.zon"));
    run.addFileInput(b.path("build/modules.zig"));
    run.addFileInput(b.path("src/cocuyo.zig"));
    run.addFileInput(b.path("test/consumer/build.zig"));

    const step = b.step("consumer-check", "Require that a package depending on cocuyo builds, and cannot reach inside");
    step.dependOn(&run.step);
    return step;
}
