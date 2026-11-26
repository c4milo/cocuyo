//! The module `crypto_context`, `tools/crypto_context.zig`, through which the tests of `io/` make
//! the `stdx.crypto.Context` that colibri's TLS takes (docs/design.md §16 decision 48, as amended
//! on 2026-11-26). Since stdx v0.4.0, `stdx.crypto.init` alone makes one.
//!
//! Only a test's root module imports it. A module the build registers is what a consumer imports,
//! so a test of such a module runs on a copy of it that imports `crypto_context` too, and the
//! registered module stays as a consumer gets it. `zig build graph-check` holds both rules.
const std = @import("std");

/// The root of the module, which `build/graph_check_packages.zig` names too.
pub const root = "tools/crypto_context.zig";

/// The module, over stdx's module `stdx`.
pub fn module(b: *std.Build, stdx: *std.Build.Module) *std.Build.Module {
    const created = b.createModule(.{ .root_source_file = b.path(root) });
    created.addImport("stdx", stdx);
    return created;
}

/// A copy of `library` for its tests: the same root, target, mode and imports, and
/// `crypto_context` beside them.
pub fn test_module(b: *std.Build, library: *std.Build.Module, stdx: *std.Build.Module) *std.Build.Module {
    const copy = b.createModule(.{
        .root_source_file = library.root_source_file,
        .target = library.resolved_target,
        .optimize = library.optimize,
        .link_libc = library.link_libc,
    });
    for (library.import_table.keys(), library.import_table.values()) |name, imported| {
        copy.addImport(name, imported);
    }
    copy.addImport("crypto_context", module(b, stdx));
    std.debug.assert(copy.import_table.count() == library.import_table.count() + 1);
    return copy;
}
