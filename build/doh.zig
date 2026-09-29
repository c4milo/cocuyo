//! DoH over colibri's client (docs/design.md §24, DoH over colibri's client): `cocuyo_doh`, colibri's
//! `client.Channel` under the engine's DoH interface. colibri is a lazy dependency, requested only by
//! cocuyo's root build, so the build adds nothing here until it is fetched. The channel's TLS is
//! colibri's `tls`, whose module carries chapulin's objects, so the tests link libc, as the sessions'
//! do (`build/doq.zig`).
const std = @import("std");
const modules = @import("modules.zig");

/// Binds colibri's `client` and `tls` into the tests' module, and its `server`, which the tests
/// answer with, and adds `zig build test-cocuyo_doh`: the type against colibri's server in memory,
/// and the engine over it on the twin. The gate runs them, so a colibri that breaks the type fails
/// it. Null `colibri` is the build before the fetch.
pub fn add(b: *std.Build, graph: modules.Graph, colibri: ?*std.Build.Dependency, test_step: *std.Build.Step) void {
    const dependency = colibri orelse return;
    const module = graph.io_doh_channel;
    module.addImport("client", dependency.module("client"));
    module.addImport("tls", dependency.module("tls"));
    module.addImport("server", dependency.module("server"));
    module.addImport("io", graph.io);
    module.addImport("rotor", graph.sim);
    module.link_libc = true;
    const tests = b.addTest(.{ .name = "cocuyo_doh", .root_module = module });
    const run = &b.addRunArtifact(tests).step;
    test_step.dependOn(run);
    b.step("test-cocuyo_doh", "Run cocuyo_doh's tests, over colibri's client and server").dependOn(run);
}
