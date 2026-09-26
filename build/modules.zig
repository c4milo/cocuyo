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
const manifest = @import("../build.zig.zon");

/// The module graph as a value. `cocuyo` and `cocuyo_rotor` are the ones a consumer imports and
/// the ones this build registers by name; the rest are this build's own, named by
/// `zig build test-<name>` through this struct rather than through the package (docs/design.md
/// §20, §24).
pub const Graph = struct {
    cocuyo: *std.Build.Module,
    core: *std.Build.Module,
    wire: *std.Build.Module,
    resolver: *std.Build.Module,
    config: *std.Build.Module,
    cache: *std.Build.Module,
    sim: *std.Build.Module,
    /// The driver of docs/design.md §19 step 13, compiled against the twin: `sim` stands in for
    /// `rotor`, so its tests run with no socket and no kernel.
    io: *std.Build.Module,
    /// chapulin's hooks, which an image defines once for every user of chapulin it links
    /// (docs/design.md §21, §24): registered, so a consumer that uses chapulin too binds this one.
    chapulin_hooks: *std.Build.Module,
    /// The same driver as a consumer imports it (docs/design.md §24). Its `rotor` import is left
    /// for the consumer to bind, so the loop it runs on is the consumer's own type, and an image
    /// holds one rotor. Nothing in this build compiles it; `zig build consumer-check` does.
    cocuyo_rotor: *std.Build.Module,
    /// colibri's QUIC under the request interface, as a consumer imports it (docs/design.md §24):
    /// its `quic` import is left for the consumer to bind, as `cocuyo_rotor`'s `rotor` is.
    cocuyo_quic: *std.Build.Module,
    /// The same, for this build's tests, whose `quic` `build/quic.zig` binds to colibri's.
    io_quic: *std.Build.Module,
    /// colibri's HTTP/2 under the request interface, as a consumer imports it (docs/design.md §24,
    /// DoH over HTTP/2): its `h2` import is left for the consumer to bind, as `cocuyo_quic`'s
    /// `quic` is.
    cocuyo_h2: *std.Build.Module,
    /// The same, for this build's tests, whose `h2` `build/quic.zig` binds to colibri's.
    io_h2: *std.Build.Module,
    /// The DNS half of DoH both HTTP transports share (docs/design.md §24): it imports `std`
    /// alone, and each transport imports it, so a consumer gets it with either.
    doh: *std.Build.Module,
};

/// The root source of each module. build/graph_check.zig hands `core`'s and `wire`'s to
/// `tools/graph_check.zig`, which compiles a fixture as a module of the `resolver` shape.
pub const roots = .{
    .cocuyo = "src/cocuyo.zig",
    .core = "src/core/core.zig",
    .wire = "src/wire/wire.zig",
    .resolver = "src/resolver/resolver.zig",
    .config = "src/config/resolv_conf.zig",
    .cache = "src/cache/cache.zig",
    .sim = "src/sim/sim.zig",
    .io = "io/io.zig",
    .chapulin_hooks = "io/io_chapulin_hooks.zig",
    .io_quic = "io/io_quic.zig",
    .doh = "io/io_doh.zig",
    .io_h2 = "io/io_h2.zig",
};

// Every module this build registers has its root under a path the manifest ships. A dependent
// that fetches cocuyo gets those paths and nothing else, and `zig build consumer-check` cannot
// show a path left out: it depends on cocuyo by path, which reads the whole tree
// (docs/mutations.md EX2).
comptime {
    for ([_][]const u8{ roots.cocuyo, roots.io, roots.chapulin_hooks, roots.io_quic, roots.io_h2 }) |root| {
        if (!shipped(root)) @compileError("build.zig.zon's paths do not ship " ++ root);
    }
}

fn shipped(comptime root: []const u8) bool {
    for (manifest.paths) |path| {
        if (std.mem.startsWith(u8, root, path) and root.len > path.len and root[path.len] == '/') return true;
    }
    return false;
}

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

/// The same graph in Debug, unregistered, every module under ThreadSanitizer: the two-engine
/// example's (`build/examples.zig`), where the engine's own code must be instrumented for the
/// sanitizer to see an access its two threads share.
pub fn add_sanitized(b: *std.Build, target: std.Build.ResolvedTarget) Graph {
    const graph = build(b, target, .Debug, false);
    inline for (std.meta.fields(Graph)) |field| @field(graph, field.name).sanitize_thread = true;
    return graph;
}

fn build(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    register: bool,
) Graph {
    // Only `cocuyo`, `cocuyo_rotor`, `cocuyo_quic`, `cocuyo_h2` and `chapulin_hooks` are registered, so they are the only names
    // a dependent can import (docs/design.md §20, §24). The rest are created: this build holds the graph as a
    // value, so `zig build test-<name>` still names each one without the name being part of the
    // package.
    const graph: Graph = .{
        .cocuyo = module(b, target, optimize, "cocuyo", roots.cocuyo, register),
        .core = module(b, target, optimize, "core", roots.core, false),
        .wire = module(b, target, optimize, "wire", roots.wire, false),
        .resolver = module(b, target, optimize, "resolver", roots.resolver, false),
        .config = module(b, target, optimize, "config", roots.config, false),
        .cache = module(b, target, optimize, "cache", roots.cache, false),
        .sim = module(b, target, optimize, "sim", roots.sim, false),
        .io = module(b, target, optimize, "io", roots.io, false),
        .cocuyo_rotor = module(b, target, optimize, "cocuyo_rotor", roots.io, register),
        .chapulin_hooks = module(b, target, optimize, "chapulin_hooks", roots.chapulin_hooks, register),
        .cocuyo_quic = module(b, target, optimize, "cocuyo_quic", roots.io_quic, register),
        .io_quic = module(b, target, optimize, "io_quic", roots.io_quic, false),
        .cocuyo_h2 = module(b, target, optimize, "cocuyo_h2", roots.io_h2, register),
        .io_h2 = module(b, target, optimize, "io_h2", roots.io_h2, false),
        .doh = module(b, target, optimize, "doh", roots.doh, false),
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
    graph.cocuyo_rotor.addImport("cocuyo", graph.cocuyo);
    graph.cocuyo_quic.addImport("cocuyo", graph.cocuyo);
    graph.cocuyo_quic.addImport("doh", graph.doh);
    graph.io_quic.addImport("cocuyo", graph.cocuyo);
    graph.io_quic.addImport("doh", graph.doh);
    graph.cocuyo_h2.addImport("cocuyo", graph.cocuyo);
    graph.cocuyo_h2.addImport("doh", graph.doh);
    graph.io_h2.addImport("cocuyo", graph.cocuyo);
    graph.io_h2.addImport("doh", graph.doh);

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
