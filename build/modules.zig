//! The module graph of docs/design.md §2. A module can `@import` only what this file gives it, so
//! the dependency direction is enforced by the build rather than by review: `core` imports
//! nothing, `wire` reads `core`, `resolver` reads `core` and `wire`, `config` reads `core` alone,
//! `cache` reads `core` and `wire` and never `resolver`, and `resolver` cannot reach `config`. That last one is the split between the state machine and
//! the config parser, and `zig build graph-check` is what shows the compiler enforces it.
//!
//! `sim` is the deterministic harness. It reads everything and is never packaged
//! (build.zig.zon `paths` lists `src`, and `sim` lives under it, so the packaging claim is the
//! consumer never importing it rather than the file never shipping).
const std = @import("std");

/// The module graph as a value. `cocuyo` is the one a consumer imports and the one this build
/// registers by name; the rest are this build's own, named by `zig build test-<name>` through
/// this struct rather than through the package (docs/design.md §20).
pub const Graph = struct {
    cocuyo: *std.Build.Module,
    core: *std.Build.Module,
    wire: *std.Build.Module,
    resolver: *std.Build.Module,
    config: *std.Build.Module,
    cache: *std.Build.Module,
    sim: *std.Build.Module,
    /// The driver of docs/design.md §19 step 13, compiled against the twin: `sim` stands in for
    /// `rotor`, so its tests run with no socket and no kernel. It is not exported: nothing binds
    /// it to rotor itself until a consumer asks for that (owner, 2026-09-22).
    io: *std.Build.Module,
};

/// The root source of each module, which `tools/graph_check.zig` reads back when it compiles a
/// fixture as a module of the `resolver` shape.
pub const roots = .{
    .cocuyo = "src/cocuyo.zig",
    .core = "src/core/core.zig",
    .wire = "src/wire/wire.zig",
    .resolver = "src/resolver/resolver.zig",
    .config = "src/config/resolv_conf.zig",
    .cache = "src/cache/cache.zig",
    .sim = "src/sim/sim.zig",
    .io = "io/io.zig",
};

/// The graph, registered: a consumer names `cocuyo`, and `zig build test-<name>` names the rest.
pub fn add(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Graph {
    return build(b, target, optimize, true);
}

/// The same graph at another optimize mode, unregistered. `zig build bench` measures ReleaseSafe
/// whatever the build was asked for, and a name can be registered once.
pub fn add_private(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) Graph {
    return build(b, target, optimize, false);
}

fn build(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    register: bool,
) Graph {
    // Only `cocuyo` is registered, so `cocuyo` is the only name a dependent can import
    // (docs/design.md §20). The rest are created: this build holds the graph as a value, so
    // `zig build test-<name>` still names each one without the name being part of the package.
    const graph: Graph = .{
        .cocuyo = module(b, target, optimize, "cocuyo", roots.cocuyo, register),
        .core = module(b, target, optimize, "core", roots.core, false),
        .wire = module(b, target, optimize, "wire", roots.wire, false),
        .resolver = module(b, target, optimize, "resolver", roots.resolver, false),
        .config = module(b, target, optimize, "config", roots.config, false),
        .cache = module(b, target, optimize, "cache", roots.cache, false),
        .sim = module(b, target, optimize, "sim", roots.sim, false),
        .io = module(b, target, optimize, "io", roots.io, false),
    };

    // core imports nothing, and that is the point of it: every limit and every type that two
    // modules share lives there, so nothing has to reach sideways for one.
    graph.wire.addImport("core", graph.core);
    graph.resolver.addImport("core", graph.core);
    graph.resolver.addImport("wire", graph.wire);
    graph.config.addImport("core", graph.core);
    graph.cache.addImport("core", graph.core);
    graph.cache.addImport("wire", graph.wire);
    graph.sim.addImport("core", graph.core);
    graph.sim.addImport("wire", graph.wire);
    graph.sim.addImport("resolver", graph.resolver);
    graph.cocuyo.addImport("core", graph.core);
    graph.cocuyo.addImport("wire", graph.wire);
    graph.cocuyo.addImport("resolver", graph.resolver);
    graph.cocuyo.addImport("config", graph.config);
    graph.cocuyo.addImport("cache", graph.cache);
    graph.io.addImport("cocuyo", graph.cocuyo);
    graph.io.addImport("rotor", graph.sim);

    return graph;
}

fn module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    root: []const u8,
    register: bool,
) *std.Build.Module {
    const options: std.Build.Module.CreateOptions = .{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
    };
    return if (register) b.addModule(name, options) else b.createModule(options);
}
