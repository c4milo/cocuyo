//! colibri under the engine's request interface, in this build's own tests (docs/design.md §24,
//! decision 29). colibri is a lazy dependency, requested only by cocuyo's root build: `cocuyo_quic`
//! leaves its `quic` and `h3` imports for a consumer to bind, the second only for DoH, and the
//! tests bind colibri's here, into the module's own tests and into the engine's, which run the
//! engine over colibri on the twin.
const std = @import("std");
const modules = @import("modules.zig");

/// Binds colibri's `quic`, `h3` and `h2` into the tests' modules and adds `zig build
/// test-cocuyo_quic` and `zig build test-cocuyo_h2`.
/// Null `colibri` is the build before the fetch, which the build runs again once it has it.
pub fn add(b: *std.Build, graph: modules.Graph, colibri: ?*std.Build.Dependency, test_step: *std.Build.Step) void {
    const dependency = colibri orelse return;
    const quic = dependency.module("quic");
    graph.io_quic.addImport("quic", quic);
    graph.io_quic.addImport("h3", dependency.module("h3"));
    graph.io.addImport("cocuyo_quic", graph.io_quic);
    graph.io.addImport("quic", quic);
    const unit_tests = b.addTest(.{ .name = "cocuyo_quic", .root_module = graph.io_quic });
    const run = &b.addRunArtifact(unit_tests).step;
    test_step.dependOn(run);
    b.step("test-cocuyo_quic", "Run cocuyo_quic's tests, over colibri").dependOn(run);
    graph.io_h2.addImport("h2", dependency.module("h2"));
    graph.io.addImport("cocuyo_h2", graph.io_h2);
    const h2_tests = b.addTest(.{ .name = "cocuyo_h2", .root_module = graph.io_h2 });
    const h2_run = &b.addRunArtifact(h2_tests).step;
    test_step.dependOn(h2_run);
    b.step("test-cocuyo_h2", "Run cocuyo_h2's tests, over colibri").dependOn(h2_run);
}
