//! colibri under the engine's request interface, in this build's own tests (docs/design.md §24,
//! decision 29). colibri is a lazy dependency, requested only by cocuyo's root build: `cocuyo_quic`
//! leaves its `quic` import for a consumer to bind, and the tests bind colibri's here, into the
//! module's own tests and into the engine's, which run the engine over colibri on the twin.
const std = @import("std");
const modules = @import("modules.zig");

/// Binds colibri's `quic` into the tests' modules and adds `zig build test-cocuyo_quic`. Null
/// `colibri` is the build before the fetch, which the build runs again once it has it.
pub fn add(b: *std.Build, graph: modules.Graph, colibri: ?*std.Build.Dependency, test_step: *std.Build.Step) void {
    const dependency = colibri orelse return;
    const quic = dependency.module("quic");
    graph.io_quic.addImport("quic", quic);
    graph.io.addImport("cocuyo_quic", graph.io_quic);
    graph.io.addImport("quic", quic);
    const unit_tests = b.addTest(.{ .name = "cocuyo_quic", .root_module = graph.io_quic });
    const run = &b.addRunArtifact(unit_tests).step;
    test_step.dependOn(run);
    b.step("test-cocuyo_quic", "Run cocuyo_quic's tests, over colibri").dependOn(run);
}
