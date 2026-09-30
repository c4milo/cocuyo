//! `zig build instructions` and `zig build instructions-rewrite`: pepegrillo's `instructions` tool
//! over `bench/count.zig` (tools/instructions.zig). The program is built ReleaseSafe, cocuyo's only
//! mode, for the host's architecture at its baseline CPU, so every runner of one architecture
//! counts the same code: the baseline records the target and not the CPU (pepegrillo's README,
//! "Instruction counts"). The gate builds the program and the tool; counting needs valgrind, which
//! CI's Linux job installs.
const std = @import("std");
const modules = @import("modules.zig");

pub fn add(b: *std.Build, tool: *std.Build.Module, test_step: *std.Build.Step) void {
    const target = b.resolveTargetQuery(.{ .cpu_model = .baseline });
    const graph = modules.add_private(b, target, .ReleaseSafe);
    const program_module = b.createModule(.{
        .root_source_file = b.path("bench/count.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    program_module.addImport("cocuyo", graph.cocuyo);
    program_module.addImport("wire", graph.wire);
    const program = b.addExecutable(.{ .name = "count", .root_module = program_module });
    const instructions = b.addExecutable(.{ .name = "instructions", .root_module = tool });
    test_step.dependOn(&program.step);
    test_step.dependOn(&instructions.step);

    // The baseline is a file the build does not track, so both steps run every time.
    const check = b.addRunArtifact(instructions);
    check.addArtifactArg(program);
    check.setCwd(b.path("."));
    check.has_side_effects = true;
    b.step("instructions", "Hold each benchmark case to the instructions one operation takes (Linux, valgrind)").dependOn(&check.step);
    const rewrite = b.addRunArtifact(instructions);
    rewrite.addArg("--rewrite");
    rewrite.addArtifactArg(program);
    rewrite.setCwd(b.path("."));
    rewrite.has_side_effects = true;
    b.step("instructions-rewrite", "Write each case's instruction count anew to bench/instructions.zon (Linux, valgrind)").dependOn(&rewrite.step);
}
