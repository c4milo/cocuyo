//! Build graph for cocuyo (docs/design.md §15 step 0): `zig build` compiles every module,
//! `zig build lint` scores every function's cognitive complexity and runs the rules of tools/lint
//! over the tree, `zig build test` runs the lint, the graph check and every module's unit tests,
//! and `zig build test-<module>` runs one module's tests with nothing else in the graph, which is
//! what a mutation is measured against.
//!
//! `zig build graph-check` is step 0's own check: it compiles a source that imports `config` from
//! inside a module of the `resolver` shape and requires the compile to fail, so §2's claim that
//! the state machine cannot reach the config parser is checked rather than asserted.
//!
//! `zig build lint-commits` checks the commit messages this branch adds and `zig build hooks`
//! points this clone's core.hooksPath at .githooks; neither is part of `zig build test`, because
//! commit shape is a property of the history, not of the code.
//!
//! The library has no dependencies and is meant to keep it that way (CLAUDE.md, Ask before). The
//! tools take one: pepegrillo, a lazy package in build.zig.zon that only the root build requests,
//! so a project depending on cocuyo never fetches it. The module graph is build/modules.zig.
const std = @import("std");
const assert = std.debug.assert;
const modules = @import("build/modules.zig");
const lint = @import("build/lint.zig");
const graph_check = @import("build/graph_check.zig");
const consumer_check = @import("build/consumer_check.zig");
const examples = @import("build/examples.zig");
const bench = @import("build/bench.zig");
const spec = @import("build/spec.zig");

/// Every directory `zig build lint` scores and `zig build fmt` checks, beside build.zig itself.
const source_directories = [_][]const u8{ "build", "src", "tools", "examples", "bench", "io" };

/// Every directory the tools/lint rules read: the sources above plus the documents, which the
/// markdown rule covers.
const lint_rule_directories = [_][]const u8{ "build", "src", "tools", "examples", "bench", "io", "docs" };

/// Markdown outside `docs/` that the markdown rule reads all the same, because both render on
/// GitHub as written (CLAUDE.md, Conventions).
const lint_rule_files = [_][]const u8{ "README.md", "CLAUDE.md", "spec/README.md" };

/// Every tool whose own tests `zig build test` runs. A build that does not run the checkers' own
/// tests lets a rule lose its test without the build reporting it. The search-order recorder is
/// here for the same reason; its two probes link a C library the gate does not require.
const tool_test_roots = [_][]const u8{
    "tools/lint/main.zig",
    "tools/cognitive_complexity.zig",
    "tools/commit_lint.zig",
    "tools/graph_check.zig",
    "tools/consumer_check.zig",
    "tools/search_order/recorder.zig",
};

/// The git revision range `zig build lint-commits` checks.
const commit_lint_range = "origin/main..HEAD";

/// The directory `zig build hooks` points this clone's core.hooksPath at.
const hooks_directory = ".githooks";

/// The pre-push hook: a copy of pepegrillo's, which `zig build test` compares byte for byte.
const pre_push_hook = hooks_directory ++ "/pre-push";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Assertions stay on in production (CLAUDE.md non-negotiable 3), so the build offers Debug and
    // ReleaseSafe only: `-Drelease` selects ReleaseSafe, and the `-Doptimize` option that would
    // admit ReleaseFast or ReleaseSmall is never declared.
    const release = b.option(bool, "release", "Build ReleaseSafe rather than Debug") orelse false;
    const optimize: std.builtin.OptimizeMode = if (release) .ReleaseSafe else .Debug;
    assert(optimize == .Debug or optimize == .ReleaseSafe);

    const graph = modules.add(b, target, optimize);

    // Everything below is cocuyo's own build: the tests, the checks and the tools. A project that
    // depends on cocuyo stops here, before the tools request pepegrillo.
    if (b.pkg_hash.len != 0) return;
    const pepegrillo_dependency = b.lazyDependency("pepegrillo", .{}) orelse return;
    const pepegrillo = pepegrillo_dependency.module("pepegrillo");

    const install_step = b.getInstallStep();
    const test_step = b.step("test", "Run the lint and the graph check, then every unit test");
    test_step.dependOn(lint.add(b, .{
        .source_directories = &source_directories,
        .rule_directories = &lint_rule_directories,
        .rule_files = &lint_rule_files,
        .complexity = b.addExecutable(.{
            .name = "cognitive_complexity",
            .root_module = tool_module(b, pepegrillo, "tools/cognitive_complexity.zig"),
        }),
        .rules = b.addExecutable(.{
            .name = "lint",
            .root_module = tool_module(b, pepegrillo, "tools/lint/main.zig"),
        }),
    }));

    const unit_test_modules = [_]struct { name: []const u8, module: *std.Build.Module }{
        .{ .name = "core", .module = graph.core },
        .{ .name = "wire", .module = graph.wire },
        .{ .name = "resolver", .module = graph.resolver },
        .{ .name = "config", .module = graph.config },
        .{ .name = "cache", .module = graph.cache },
        .{ .name = "sim", .module = graph.sim },
        .{ .name = "cocuyo", .module = graph.cocuyo },
        .{ .name = "io", .module = graph.io },
    };
    for (unit_test_modules) |entry| {
        const unit_tests = b.addTest(.{ .name = entry.name, .root_module = entry.module });
        install_step.dependOn(&unit_tests.step);
        const run = &b.addRunArtifact(unit_tests).step;
        test_step.dependOn(run);
        add_narrow_test_step(b, entry.name).dependOn(run);
    }

    const tool_test_step = add_narrow_test_step(b, "tools");
    for (tool_test_roots) |root| {
        const tool_tests = b.addTest(.{
            .name = std.fs.path.stem(root),
            .root_module = tool_module(b, pepegrillo, root),
        });
        const run = &b.addRunArtifact(tool_tests).step;
        test_step.dependOn(run);
        tool_test_step.dependOn(run);
    }

    test_step.dependOn(graph_check.add(b, host_module(b, "tools/graph_check.zig")));
    test_step.dependOn(consumer_check.add(b, host_module(b, "tools/consumer_check.zig")));
    // rotor drives the second example and nothing else. `lazyDependency` leaves it null until
    // the build has it, and `build/examples.zig` simply adds no rotor example in that case.
    const rotor = b.lazyDependency("rotor", .{ .target = target });
    examples.add(b, graph.cocuyo, target, optimize, test_step, rotor);
    bench.add(b, target, test_step, tool_test_step, rotor);
    spec.add(b, target, test_step, tool_test_step);
    test_step.dependOn(add_hook_check_step(b, pepegrillo_dependency));
    add_commit_lint_step(b, pepegrillo, install_step);
    add_hooks_step(b);

    const fmt_step = b.step("fmt", "Check formatting of every Zig source");
    fmt_step.dependOn(&b.addFmt(.{
        .paths = &(.{"build.zig"} ++ source_directories),
        .check = true,
    }).step);
}

/// `zig build test-<name>`: the tests of one module, or of the tools, with nothing else in the
/// graph. `zig build test` is the check that must pass; these steps are the inner loop of a
/// mutation, which is run against the narrowest target that can catch it.
fn add_narrow_test_step(b: *std.Build, name: []const u8) *std.Build.Step {
    return b.step(
        b.fmt("test-{s}", .{name}),
        b.fmt("Run the {s} tests alone, with nothing else in the graph", .{name}),
    );
}

/// A module compiled for the build host in Debug: every tool, and nothing else.
fn host_module(b: *std.Build, root_source_file: []const u8) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = b.graph.host,
        .optimize = .Debug,
    });
}

/// A host module that imports `pepegrillo`: every tool built on pepegrillo's engines.
fn tool_module(
    b: *std.Build,
    pepegrillo: *std.Build.Module,
    root_source_file: []const u8,
) *std.Build.Module {
    const module = host_module(b, root_source_file);
    module.addImport("pepegrillo", pepegrillo);
    return module;
}

/// `zig build hook-check`: .githooks/pre-push must be byte-identical to the hook of the pinned
/// pepegrillo. After a pepegrillo bump, copy the new hook over it.
fn add_hook_check_step(b: *std.Build, pepegrillo: *std.Build.Dependency) *std.Build.Step {
    const compare = b.addSystemCommand(&.{"cmp"});
    compare.addFileArg(pepegrillo.path("hooks/pre-push"));
    compare.addFileArg(b.path(pre_push_hook));
    const step = b.step(
        "hook-check",
        "Require " ++ pre_push_hook ++ " to match pepegrillo's hooks/pre-push; copy it when not",
    );
    step.dependOn(&compare.step);
    return step;
}

/// `zig build lint-commits`: the Conventional Commit rules of CLAUDE.md over the commits this
/// branch adds. Not part of `zig build test`: commit shape is a property of the history.
/// `zig build install-commit-lint` installs the linter alone, which .githooks/pre-push runs when
/// zig-out/bin/commit_lint is missing.
fn add_commit_lint_step(
    b: *std.Build,
    pepegrillo: *std.Build.Module,
    install_step: *std.Build.Step,
) void {
    const tool = b.addExecutable(.{
        .name = "commit_lint",
        .root_module = tool_module(b, pepegrillo, "tools/commit_lint.zig"),
    });
    const install_tool = b.addInstallArtifact(tool, .{});
    install_step.dependOn(&install_tool.step);
    const install_tool_step = b.step("install-commit-lint", "Install the commit-message linter alone");
    install_tool_step.dependOn(&install_tool.step);
    const run = b.addRunArtifact(tool);
    run.addArgs(&.{ "--range", commit_lint_range });
    const step = b.step("lint-commits", "Check the commit messages this branch adds");
    step.dependOn(&run.step);
}

fn add_hooks_step(b: *std.Build) void {
    const run = b.addSystemCommand(&.{ "git", "config", "core.hooksPath", hooks_directory });
    const step = b.step("hooks", "Point this clone's core.hooksPath at " ++ hooks_directory);
    step.dependOn(&run.step);
}
