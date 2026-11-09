//! DNSSEC's verifier over chapulin, through colibri's `dnssec` module (docs/design.md §25 step 10,
//! §16 decision 35 as amended). colibri is a lazy dependency, so the build adds nothing until it is
//! fetched, and neither the library's tests nor a consumer that does not validate needs chapulin.
//!
//! The verifier is `cocuyo_dnssec`, a module the build registers. Its tests use that module, with
//! colibri's `dnssec` bound into it here as a consumer binds it.
const std = @import("std");
const modules = @import("modules.zig");

/// `zig build test-cocuyo_dnssec`, the verifier's tests over the RFCs' examples. The gate runs
/// them, so a colibri or a chapulin that breaks a check fails it.
pub fn add(b: *std.Build, graph: modules.Graph, test_step: *std.Build.Step, colibri: ?*std.Build.Dependency) void {
    const resolved = colibri orelse return;
    graph.cocuyo_dnssec.addImport("dnssec", resolved.module("dnssec"));
    // The tests read cocuyo's `dnssec` too, its signed data and its validator, through a root of
    // their own, so no module a consumer imports carries them.
    const root = b.createModule(.{
        .root_source_file = b.path("io/io_dnssec_test.zig"),
        .target = graph.cocuyo_dnssec.resolved_target,
        .optimize = graph.cocuyo_dnssec.optimize,
    });
    root.addImport("cocuyo", graph.cocuyo);
    root.addImport("core", graph.core);
    root.addImport("wire", graph.wire);
    root.addImport("cocuyo_dnssec", graph.cocuyo_dnssec);
    root.addImport("validation", graph.dnssec);
    const tests = b.addTest(.{ .name = "cocuyo_dnssec", .root_module = root });
    const run = &b.addRunArtifact(tests).step;
    b.step("test-cocuyo_dnssec", "Run the DNSSEC verifier's tests, over colibri's dnssec").dependOn(run);
    test_step.dependOn(run);
}
