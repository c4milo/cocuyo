//! `zig build coverage`: line coverage of the library and the engine. kcov runs every module's unit
//! tests, built with LLVM for their line tables, then merges what each recorded, and
//! tools/coverage.zig reads the merge into `zig-out/coverage/`: a table, the README's badge, and
//! kcov's own HTML under `html/`.
//!
//! kcov traces a process with ptrace and reads its DWARF, so it runs on Linux, and the step needs it
//! on the path or where `-Dkcov` names it. CI's `coverage` job builds it from a pinned release. On
//! another host, `zig build coverage-binaries -Dtarget=<arch>-linux-gnu` installs the test binaries
//! alone, for kcov in a Linux container to run.
const std = @import("std");

pub const Tests = struct { name: []const u8, module: *std.Build.Module };

pub fn add(b: *std.Build, tests: []const Tests, report_tool: *std.Build.Module) void {
    const kcov = b.option([]const u8, "kcov", "The kcov `zig build coverage` runs") orelse "kcov";
    const include = b.fmt("--include-path={s},{s}", .{ b.pathFromRoot("src"), b.pathFromRoot("io") });
    const merge = b.addSystemCommand(&.{ kcov, "--merge" });
    const merged = merge.addOutputDirectoryArg("merged");
    const binaries = b.step("coverage-binaries", "Install every module's test binary, built with LLVM, for kcov on another host");
    for (tests) |entry| {
        const compiled = b.addTest(.{ .name = entry.name, .root_module = entry.module, .use_llvm = true });
        const run = b.addSystemCommand(&.{ kcov, include });
        merge.addDirectoryArg(run.addOutputDirectoryArg(entry.name));
        run.addArtifactArg(compiled);
        binaries.dependOn(&b.addInstallArtifact(compiled, .{ .dest_dir = .{ .override = .{ .custom = "coverage-binaries" } } }).step);
    }

    const report = b.addRunArtifact(b.addExecutable(.{ .name = "coverage", .root_module = report_tool }));
    report.addFileArg(merged.path(b, "kcov-merged/cobertura.xml"));
    report.addArg(b.pathFromRoot("."));
    const written = report.addOutputDirectoryArg("report");
    const step = b.step("coverage", "Measure line coverage of the library and the engine with kcov (Linux)");
    step.dependOn(&b.addInstallDirectory(.{ .source_dir = written, .install_dir = .prefix, .install_subdir = "coverage" }).step);
    step.dependOn(&b.addInstallDirectory(.{ .source_dir = merged.path(b, "kcov-merged"), .install_dir = .prefix, .install_subdir = "coverage/html" }).step);
}
