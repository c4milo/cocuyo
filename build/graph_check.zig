//! `zig build graph-check`: the check of docs/design.md §15 step 0. build.zig stays short
//! (CLAUDE.md, Layout), so the wiring is here and the check itself is tools/graph_check.zig.
const std = @import("std");

pub fn add(b: *std.Build, tool: *std.Build.Module) *std.Build.Step {
    const check = b.addExecutable(.{ .name = "graph_check", .root_module = tool });
    const run = b.addRunArtifact(check);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg(b.path("src"));
    run.addDirectoryArg(b.path("tools/fixtures"));
    // Re-run the check when the graph it checks changes, not only when the tool does.
    run.addFileInput(b.path("build/modules.zig"));

    const step = b.step("graph-check", "Require that a resolver module cannot import the parser");
    step.dependOn(&run.step);
    return step;
}
