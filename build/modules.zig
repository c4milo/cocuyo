//! The module graph of docs/design.md §2. A module can `@import` only what this file gives it, so
//! the dependency direction is enforced by the build rather than by review: `core` imports
//! nothing, `wire` reads `core`, `resolver` reads `core` and `wire`, `config` reads `core` alone,
//! and `resolver` cannot reach `config`. That last one is the split between the state machine and
//! the config parser, and `zig build graph-check` is what shows the compiler enforces it.
//!
//! `sim` is the deterministic harness. It reads everything and is never packaged
//! (build.zig.zon `paths` lists `src`, and `sim` lives under it, so the packaging claim is the
//! consumer never importing it rather than the file never shipping).
const std = @import("std");

/// The public module a consumer imports, and every module `zig build test-<name>` can name.
pub const Graph = struct {
    cocuyo: *std.Build.Module,
    core: *std.Build.Module,
    wire: *std.Build.Module,
    resolver: *std.Build.Module,
    config: *std.Build.Module,
    sim: *std.Build.Module,
};

/// The root source of each module, which `tools/graph_check.zig` reads back when it compiles a
/// fixture as a module of the `resolver` shape.
pub const roots = .{
    .cocuyo = "src/cocuyo.zig",
    .core = "src/core/core.zig",
    .wire = "src/wire/wire.zig",
    .resolver = "src/resolver/resolver.zig",
    .config = "src/config/resolv_conf.zig",
    .sim = "src/sim/sim.zig",
};

pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Graph {
    const graph: Graph = .{
        .cocuyo = module(b, target, optimize, "cocuyo", roots.cocuyo),
        .core = module(b, target, optimize, "core", roots.core),
        .wire = module(b, target, optimize, "wire", roots.wire),
        .resolver = module(b, target, optimize, "resolver", roots.resolver),
        .config = module(b, target, optimize, "config", roots.config),
        .sim = module(b, target, optimize, "sim", roots.sim),
    };

    // core imports nothing, and that is the point of it: every limit and every type that two
    // modules share lives there, so nothing has to reach sideways for one.
    graph.wire.addImport("core", graph.core);
    graph.resolver.addImport("core", graph.core);
    graph.resolver.addImport("wire", graph.wire);
    graph.config.addImport("core", graph.core);
    graph.sim.addImport("core", graph.core);
    graph.sim.addImport("wire", graph.wire);
    graph.sim.addImport("resolver", graph.resolver);
    graph.cocuyo.addImport("core", graph.core);
    graph.cocuyo.addImport("wire", graph.wire);
    graph.cocuyo.addImport("resolver", graph.resolver);
    graph.cocuyo.addImport("config", graph.config);

    return graph;
}

fn module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    root: []const u8,
) *std.Build.Module {
    return b.addModule(name, .{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
    });
}
