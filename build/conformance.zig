//! `zig build conformance-forward`: the program that hickory-dns's conformance suite asks as the
//! resolver under test (docs/design.md §25 step 17, tools/conformance/forward.zig). It is built
//! where rotor has a backend and colibri resolved, as the cleartext example is, and installed into
//! the prefix for `tools/conformance/run.sh` to copy into the suite's image. build.zig stays short
//! (CLAUDE.md, Layout), so the wiring is here.
const std = @import("std");
const modules = @import("modules.zig");

const root = "tools/conformance/forward.zig";

pub fn add(
    b: *std.Build,
    graph: modules.Graph,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    rotor: ?*std.Build.Dependency,
    colibri: ?*std.Build.Dependency,
) void {
    const dependency = rotor orelse return;
    if (colibri == null) return;
    switch (target.result.os.tag) {
        .linux, .macos => {},
        else => return,
    }
    const engine = b.createModule(.{ .root_source_file = b.path(modules.roots.io), .target = target, .optimize = optimize });
    engine.addImport("cocuyo", graph.cocuyo);
    engine.addImport("rotor", dependency.module("rotor"));
    const server_text = b.createModule(.{ .root_source_file = b.path("examples/server_text.zig"), .target = target, .optimize = optimize });
    server_text.addImport("cocuyo", graph.cocuyo);
    const answer_text = b.createModule(.{ .root_source_file = b.path("examples/answer_text.zig"), .target = target, .optimize = optimize });
    answer_text.addImport("cocuyo", graph.cocuyo);
    const trust_text = b.createModule(.{ .root_source_file = b.path("examples/trust_text.zig"), .target = target, .optimize = optimize });
    trust_text.addImport("cocuyo", graph.cocuyo);
    trust_text.addImport("cocuyo_dnssec", graph.cocuyo_dnssec);
    const module = b.createModule(.{ .root_source_file = b.path(root), .target = target, .optimize = optimize });
    module.addImport("cocuyo", graph.cocuyo);
    module.addImport("rotor", dependency.module("rotor"));
    module.addImport("io", engine);
    module.addImport("answer_text", answer_text);
    module.addImport("server_text", server_text);
    module.addImport("trust_text", trust_text);
    const exe = b.addExecutable(.{ .name = "conformance-forward", .root_module = module });
    test_step.dependOn(&exe.step);
    const step = b.step("conformance-forward", "Build the program hickory-dns's conformance suite asks, into the prefix");
    step.dependOn(&b.addInstallArtifact(exe, .{}).step);
}
