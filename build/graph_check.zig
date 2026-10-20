//! `zig build graph-check`: the check of docs/design.md §15 step 0, and the packages the library
//! and the engine must not reach (§2). build.zig stays short (CLAUDE.md, Layout), so the wiring is
//! here. The first check is tools/graph_check.zig, and the second is
//! build/graph_check_packages.zig.
const std = @import("std");
const modules = @import("modules.zig");
const packages_check = @import("graph_check_packages.zig");

pub const Packages = packages_check.Packages;

pub fn add(b: *std.Build, tool: *std.Build.Module, packages: Packages) *std.Build.Step {
    const check = b.addExecutable(.{ .name = "graph_check", .root_module = tool });
    const run = b.addRunArtifact(check);
    run.addArg(b.graph.zig_exe);
    run.addDirectoryArg(b.path("tools/fixtures"));
    // The roots of `resolver`'s imports, in the order the tool lists them.
    run.addFileArg(b.path(modules.roots.core));
    run.addFileArg(b.path(modules.roots.wire));
    // Re-run the check when the graph it checks changes, not only when the tool does.
    run.addFileInput(b.path("build/modules.zig"));

    const step = b.step("graph-check", "Require that a resolver module cannot import the parser, that no module in src/ reaches stdx or colibri, and that none in io/ reaches stdx but through colibri");
    step.dependOn(&run.step);
    step.dependOn(packages_check.add(b, packages));
    return step;
}
