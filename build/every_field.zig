//! `zig build every-field`: consumer-shaped code passes every field of a `Config` and of the
//! engine's `Options` (tools/every_field.zig, docs/design.md §20). build.zig stays short (CLAUDE.md,
//! Layout), so the wiring is here.
const std = @import("std");
const modules = @import("modules.zig");

/// Adds the check and its tests. The tool reads the two types, so it imports the library and the
/// engine as a consumer does: an engine of its own over the twin, with none of the imports that
/// the engine's own tests take. Those reach colibri's one module, which links chapulin's objects
/// into each program that holds it (colibri decision 170). Returns the step the gate runs: the
/// tool's tests, then the check.
pub fn add(b: *std.Build, graph: modules.Graph) *std.Build.Step {
    const engine = b.createModule(.{ .root_source_file = b.path(modules.roots.io), .target = b.graph.host, .optimize = .Debug });
    engine.addImport("cocuyo", graph.cocuyo);
    modules.add_internal(engine, graph);
    engine.addImport("rotor", graph.sim);
    const cocuyo = graph.cocuyo;
    const tool = b.createModule(.{
        .root_source_file = b.path("tools/every_field.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    tool.addImport("cocuyo", cocuyo);
    tool.addImport("cocuyo_rotor", engine);

    const tests = b.addRunArtifact(b.addTest(.{ .name = "every_field", .root_module = tool }));
    const tests_step = b.step("test-every-field", "Run the tests of the every-field check alone");
    tests_step.dependOn(&tests.step);

    const run = b.addRunArtifact(b.addExecutable(.{ .name = "every_field", .root_module = tool }));
    // In the root of the tree, whose files the check reads, wherever `zig build` started.
    run.setCwd(b.path("."));
    // The check reads files it does not name to the build, so it runs every time.
    run.has_side_effects = true;
    run.step.dependOn(&tests.step);

    const step = b.step("every-field", "Require every field of a Config and of the engine's Options in consumer-shaped code");
    step.dependOn(&run.step);
    return step;
}
