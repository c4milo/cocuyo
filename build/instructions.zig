//! `zig build instructions` and `zig build instructions-rewrite`: pepegrillo's `instructions` tool
//! over `bench/count.zig` (tools/instructions.zig), and over `bench/count_dnssec.zig`
//! (tools/instructions_dnssec.zig). The program is built ReleaseSafe, cocuyo's only
//! mode, for the host's architecture at its baseline CPU, so every runner of one architecture
//! counts the same code: the baseline records the target and not the CPU (pepegrillo's README,
//! "Instruction counts"). The gate builds the program and the tool; counting needs valgrind, which
//! CI's Linux job installs.
const std = @import("std");
const modules = @import("modules.zig");

/// Two programs, each with its tool and its baseline: `bench/count.zig` and, for cocuyo's half of
/// a validation, `bench/count_dnssec.zig` (docs/design.md §17 question 111).
pub fn add(b: *std.Build, tool: *std.Build.Module, dnssec_tool: *std.Build.Module, test_step: *std.Build.Step) void {
    const target = b.resolveTargetQuery(.{ .cpu_model = .baseline });
    const graph = modules.add_private(b, target, .ReleaseSafe);
    const check_step = b.step("instructions", "Hold each benchmark case to the instructions one operation takes (Linux, valgrind)");
    const rewrite_step = b.step("instructions-rewrite", "Write each case's instruction count anew to its baseline (Linux, valgrind)");
    const programs = [_]struct { root: []const u8, name: []const u8, tool: *std.Build.Module }{
        .{ .root = "bench/count.zig", .name = "count", .tool = tool },
        .{ .root = "bench/count_dnssec.zig", .name = "count-dnssec", .tool = dnssec_tool },
    };
    for (programs) |entry| {
        const program_module = b.createModule(.{
            .root_source_file = b.path(entry.root),
            .target = target,
            .optimize = .ReleaseSafe,
        });
        program_module.addImport("cocuyo", graph.cocuyo);
        modules.add_internal(program_module, graph);
        program_module.addImport("validation", graph.dnssec);
        const program = b.addExecutable(.{ .name = entry.name, .root_module = program_module });
        const instructions = b.addExecutable(.{ .name = b.fmt("instructions-{s}", .{entry.name}), .root_module = entry.tool });
        test_step.dependOn(&program.step);
        test_step.dependOn(&instructions.step);

        // The baseline is a file the build does not track, so both steps run every time.
        const check = b.addRunArtifact(instructions);
        check.addArtifactArg(program);
        check.setCwd(b.path("."));
        check.has_side_effects = true;
        check_step.dependOn(&check.step);
        const rewrite = b.addRunArtifact(instructions);
        rewrite.addArg("--rewrite");
        rewrite.addArtifactArg(program);
        rewrite.setCwd(b.path("."));
        rewrite.has_side_effects = true;
        rewrite_step.dependOn(&rewrite.step);
    }
}
