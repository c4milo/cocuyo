//! `zig build coverage`: line coverage of the library and the engine. kcov runs every module's unit
//! tests, built with LLVM for their line tables, then merges what each recorded, and
//! tools/coverage.zig reads the merge into `zig-out/coverage/`: a table, the README's badge, and
//! kcov's own HTML under `html/`.
//!
//! kcov traces a process with ptrace and reads its DWARF, so it runs on Linux, and the step needs it
//! on the path or where `-Dkcov` names it. CI's `coverage` job builds it from a pinned release. On
//! another host, `zig build coverage-binaries -Dtarget=<arch>-linux-gnu` installs the test binaries
//! alone, for kcov in a Linux container to run.
//!
//! The report refuses a total under its floor and a report whose paths missed the tree. Its own
//! tests cannot show that `main` does either, so the gate runs it over two reports written here,
//! which need no kcov, and requires each refused with its reason.
const std = @import("std");

pub const Tests = struct { name: []const u8, module: *std.Build.Module };

/// A file of each part of the tree the report has a row for (tools/coverage.zig, `areas`).
const one_file_an_area = [_][]const u8{ "src/core/name.zig", "src/wire/wire.zig", "src/resolver/lookup.zig", "src/config/resolv_conf.zig", "src/cache/cache.zig", "io/io.zig", "src/sim/sim.zig" };

pub fn add(b: *std.Build, tests: []const Tests, report_tool: *std.Build.Module, test_step: *std.Build.Step) void {
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

    const report_exe = b.addExecutable(.{ .name = "coverage", .root_module = report_tool });
    test_step.dependOn(refused(b, report_exe, "unrun", unrun_report(b), "under the floor"));
    test_step.dependOn(refused(b, report_exe, "empty", "<coverage>\n</coverage>\n", "no line of an area"));
    const report = b.addRunArtifact(report_exe);
    report.addFileArg(merged.path(b, "kcov-merged/cobertura.xml"));
    report.addArg(b.pathFromRoot("."));
    const written = report.addOutputDirectoryArg("report");
    const step = b.step("coverage", "Measure line coverage of the library and the engine with kcov (Linux)");
    step.dependOn(&b.addInstallDirectory(.{ .source_dir = written, .install_dir = .prefix, .install_subdir = "coverage" }).step);
    step.dependOn(&b.addInstallDirectory(.{ .source_dir = merged.path(b, "kcov-merged"), .install_dir = .prefix, .install_subdir = "coverage/html" }).step);
}

/// The report run over `xml`, required to exit 1 and to say `reason`.
fn refused(b: *std.Build, report_exe: *std.Build.Step.Compile, name: []const u8, xml: []const u8, reason: []const u8) *std.Build.Step {
    const run = b.addRunArtifact(report_exe);
    run.addFileArg(b.addWriteFiles().add(b.fmt("{s}.xml", .{name}), xml));
    run.addArg(b.pathFromRoot("."));
    _ = run.addOutputDirectoryArg(name);
    run.expectExitCode(1);
    run.addCheck(.{ .expect_stderr_match = reason });
    return &run.step;
}

/// A report with the first line of one file in each part, none of them run: 0%, under any floor.
fn unrun_report(b: *std.Build) []const u8 {
    var xml: std.ArrayList(u8) = .empty;
    xml.appendSlice(b.allocator, b.fmt("<coverage>\n<source>{s}/</source>\n", .{b.pathFromRoot(".")})) catch @panic("OOM");
    for (one_file_an_area) |file| {
        xml.appendSlice(b.allocator, b.fmt("<class filename=\"{s}\">\n<line number=\"1\" hits=\"0\"/>\n</class>\n", .{file})) catch @panic("OOM");
    }
    xml.appendSlice(b.allocator, "</coverage>\n") catch @panic("OOM");
    return xml.items;
}
