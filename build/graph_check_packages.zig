//! The second part of `zig build graph-check` (docs/design.md §2, §16 decision 48). stdx is a
//! dependency of the TLS examples alone, and colibri of the engine and the tools. So the check
//! holds three rules over the build's module graph:
//!
//! - No module rooted in `src/` reaches a module of stdx, at any depth.
//! - No module rooted in `io/` reaches a module of stdx, at any depth, except below a module of
//!   colibri. colibri's `tls` imports stdx's `platform` (colibri's decision 97), and its `client`
//!   imports stdx's decoders. The engine imports both by right.
//! - No module rooted in `src/` reaches a module of colibri, at any depth.
//!
//! The first part, `tools/graph_check.zig`, asks the compiler about one module's shape. This part
//! reads the module graph that the build made: each module that a compile step of the build
//! reaches. A module is this tree's when this build made it from a file of this tree. A module is
//! a package's when the package's build made it, and the package's hash in `build.zig.zon` names
//! it. A module reaches each module that it imports, and each module that those reach, through
//! the modules of this tree and of each package. So the check fails before any compile reads an
//! `@import`.
//!
//! Three controls make the check fail when it did not read the graph:
//!
//! - The walk must reach a module rooted in each directory that a rule names.
//! - The canaries. Each is a module rooted in a rule's directory, under a root that imports it,
//!   and no compile step reaches one. Its rule must flag each canary that reaches the package
//!   directly, through a module of this tree, or below a module of colibri from `src/`. Its rule
//!   must pass the canary in `io/` that reaches stdx only below a module of colibri.
//! - Each package that the graph holds must have its canaries.
const std = @import("std");
const manifest = @import("../build.zig.zon");
const modules = @import("modules.zig");

const assert = std.debug.assert;
const Step = std.Build.Step;
const Module = std.Build.Module;

/// The packages that the rules name.
const Package = enum {
    stdx,
    colibri,

    /// The hash `build.zig.zon` pins the package at, which the package's build carries as its
    /// `pkg_hash`.
    fn hash(package: Package) []const u8 {
        return switch (package) {
            .stdx => manifest.dependencies.stdx.hash,
            .colibri => manifest.dependencies.colibri.hash,
        };
    }
};

/// A package that no module rooted in `under` may reach.
const Rule = struct {
    package: Package,
    /// A directory of this tree, with its slash.
    under: []const u8,
    /// The packages whose modules may import `package` by right. The walk from `under` reads no
    /// import of one of their modules.
    stop_at: []const Package,
};

const rules = [_]Rule{
    .{ .package = .stdx, .under = "src/", .stop_at = &.{} },
    .{ .package = .stdx, .under = "io/", .stop_at = &.{.colibri} },
    .{ .package = .colibri, .under = "src/", .stop_at = &.{} },
};

/// A module rooted at `root`, a file in the directory of a rule of `rule`'s package. It imports
/// `module` of `package`, or a module of this tree rooted at `through` that imports it.
const Canary = struct {
    rule: Package,
    root: []const u8,
    package: Package,
    module: []const u8,
    through: ?[]const u8 = null,
    /// Whether the rule must flag the canary or pass it.
    expect: enum { flagged, passed } = .flagged,
};

/// A file of this tree outside each rule's directory, which a canary reaches a package through.
const canary_through = "examples/cpu_text.zig";

const canaries = [_]Canary{
    // A direct import.
    .{ .rule = .stdx, .root = modules.roots.cocuyo, .package = .stdx, .module = "platform" },
    .{ .rule = .stdx, .root = modules.roots.io, .package = .stdx, .module = "platform" },
    .{ .rule = .colibri, .root = modules.roots.cocuyo, .package = .colibri, .module = "tls" },
    // An import through a module of this tree, rooted outside the rule's directory.
    .{ .rule = .stdx, .root = modules.roots.cocuyo, .package = .stdx, .module = "platform", .through = canary_through },
    .{ .rule = .stdx, .root = modules.roots.io, .package = .stdx, .module = "platform", .through = canary_through },
    .{ .rule = .colibri, .root = modules.roots.cocuyo, .package = .colibri, .module = "tls", .through = modules.roots.io_doh_channel },
    // colibri's `tls`, which imports stdx's `platform`: below it the walk from `src/` reads on, and
    // the walk from `io/` stops.
    .{ .rule = .stdx, .root = modules.roots.cocuyo, .package = .colibri, .module = "tls" },
    .{ .rule = .stdx, .root = modules.roots.io, .package = .colibri, .module = "tls", .expect = .passed },
};

/// The root of each canary's root module: a file the canary itself never imports.
const canary_parent = "tools/graph_check.zig";

/// The packages the canaries import, null before the build has fetched each.
pub const Packages = struct {
    stdx: ?*std.Build.Dependency,
    colibri: ?*std.Build.Dependency,

    fn of(packages: Packages, package: Package) ?*std.Build.Dependency {
        return switch (package) {
            .stdx => packages.stdx,
            .colibri => packages.colibri,
        };
    }
};

const Check = struct {
    step: Step,
    /// The root module of each canary whose package the build resolved, by the canary's index.
    canaries: [canaries.len]?*Module,
};

/// The step that fails when the build's module graph breaks a rule, or when a control fails.
pub fn add(b: *std.Build, packages: Packages) *Step {
    const check = b.allocator.create(Check) catch @panic("OOM");
    check.* = .{
        .step = .init(.{ .id = .custom, .name = "graph-check packages", .owner = b, .makeFn = make }),
        .canaries = @splat(null),
    };
    for (canaries, &check.canaries) |canary, *slot| {
        const found = packages.of(canary.package) orelse continue;
        // The caller passes each package in its own field.
        assert(std.mem.eql(u8, found.builder.pkg_hash, canary.package.hash()));
        slot.* = canary_module(b, canary, found.module(canary.module));
    }
    return &check.step;
}

/// The canary's module, with what it imports, under a root module of its own.
fn canary_module(b: *std.Build, canary: Canary, imported: *Module) *Module {
    const inside = b.createModule(.{ .root_source_file = b.path(canary.root) });
    if (canary.through) |through| {
        // A module rooted in the rule's directory would be flagged itself, at depth one.
        assert(!std.mem.eql(u8, top_directory(through), top_directory(canary.root)));
        const middle = b.createModule(.{ .root_source_file = b.path(through) });
        middle.addImport(canary.module, imported);
        inside.addImport("through", middle);
    } else {
        inside.addImport(canary.module, imported);
    }
    const parent = b.createModule(.{ .root_source_file = b.path(canary_parent) });
    parent.addImport("canary", inside);
    return parent;
}

/// The first directory of `path`, with its slash.
fn top_directory(path: []const u8) []const u8 {
    const slash = std.mem.indexOfScalar(u8, path, '/') orelse return "";
    return path[0 .. slash + 1];
}

fn make(step: *Step, options: Step.MakeOptions) !void {
    const check: *Check = @fieldParentPtr("step", step);
    var arena_state: std.heap.ArenaAllocator = .init(options.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const b = step.owner;
    const reached = try reach(arena, try compile_roots(arena, b), &.{});
    for (rules) |rule| {
        if (!reaches_under(b, reached, rule.under)) {
            return step.fail("graph-check BROKEN: the walk reached no module rooted in {s}", .{rule.under});
        }
    }
    try check_canaries(step, check, arena, reached);
    for (rules) |rule| {
        const found = try find(arena, b, reached, rule) orelse continue;
        const importer = name_of(b, found.importer);
        return step.fail("graph-check FAILED: the module rooted at {s} reaches {s}'s module rooted at {s}, which {s}{s} imports, and no module rooted in {s} may reach {s}", .{
            found.root, @tagName(rule.package), root_path(found.reached), importer[0], importer[1], rule.under, @tagName(rule.package),
        });
    }
    std.debug.print("graph-check: of {d} modules, none rooted in src/ reaches stdx or colibri, and none rooted in io/ reaches stdx but below colibri\n", .{reached.len});
}

/// Fails the step when a rule does not say of a canary what it must, or when the graph holds a
/// package with no canary.
fn check_canaries(step: *Step, check: *const Check, arena: std.mem.Allocator, reached: []const *Module) !void {
    for (canaries, check.canaries) |canary, parent| {
        const root = parent orelse {
            if (!holds(reached, canary.package)) continue;
            return step.fail("graph-check BROKEN: the graph holds {s}, and no canary rooted at {s} imports it", .{ @tagName(canary.package), canary.root });
        };
        try check_canary(step, arena, canary, root);
    }
}

/// Fails the step when the canary's rule does not say of it what it must. `root` is the root
/// module above the canary.
fn check_canary(step: *Step, arena: std.mem.Allocator, canary: Canary, root: *Module) !void {
    const rule = rule_of(canary) orelse {
        return step.fail("graph-check BROKEN: no rule of {s} reads the module rooted at {s}", .{ @tagName(canary.rule), canary.root });
    };
    const flagged = try find(arena, step.owner, try reach(arena, &.{root}, &.{}), rule) != null;
    if (flagged == (canary.expect == .flagged)) return;
    return step.fail("graph-check BROKEN: the rule of {s} in {s} {s} a module rooted at {s} that imports {s}'s {s}{s}{s}", .{
        @tagName(rule.package),   rule.under,    if (flagged) "flags" else "passes",              canary.root,
        @tagName(canary.package), canary.module, if (canary.through == null) "" else " through ", canary.through orelse "",
    });
}

/// The rule of the canary's package whose directory holds the canary's root.
fn rule_of(canary: Canary) ?Rule {
    for (rules) |rule| {
        if (rule.package == canary.rule and std.mem.startsWith(u8, canary.root, rule.under)) return rule;
    }
    return null;
}

/// Whether one of `reached` is a module of `package`.
fn holds(reached: []const *Module, package: Package) bool {
    for (reached) |module| {
        if (of(module, package)) return true;
    }
    return false;
}

/// Whether `module` is a module of `package`.
fn of(module: *const Module, package: Package) bool {
    return std.mem.eql(u8, module.owner.pkg_hash, package.hash());
}

/// Whether `module` is a module of one of `packages`.
fn of_any(module: *const Module, packages: []const Package) bool {
    for (packages) |package| {
        if (of(module, package)) return true;
    }
    return false;
}

/// The root module of each compile step that a top-level step of the build reaches.
fn compile_roots(arena: std.mem.Allocator, b: *std.Build) ![]const *Module {
    var steps: std.AutoArrayHashMapUnmanaged(*Step, void) = .empty;
    for (b.top_level_steps.values()) |top| try steps.put(arena, &top.step, {});
    var roots: std.ArrayList(*Module) = .empty;
    var at: usize = 0;
    while (at < steps.count()) : (at += 1) {
        const step = steps.keys()[at];
        for (step.dependencies.items) |dependency| try steps.put(arena, dependency, {});
        if (step.cast(Step.Compile)) |compile| try roots.append(arena, compile.root_module);
    }
    return roots.items;
}

/// Each module of `roots`, and each module that one of them imports, at any depth, once. The walk
/// reads no import of a module of one of `stop_at`.
fn reach(arena: std.mem.Allocator, roots: []const *Module, stop_at: []const Package) ![]const *Module {
    var found: std.AutoArrayHashMapUnmanaged(*Module, void) = .empty;
    for (roots) |root| try found.put(arena, root, {});
    var at: usize = 0;
    while (at < found.count()) : (at += 1) {
        const module = found.keys()[at];
        if (of_any(module, stop_at)) continue;
        for (module.import_table.values()) |imported| try found.put(arena, imported, {});
    }
    return found.keys();
}

/// The path of `module`'s root in this tree, when this build made the module from a file of it.
fn tree_root(b: *std.Build, module: *const Module) ?[]const u8 {
    if (module.owner != b) return null;
    const root = module.root_source_file orelse return null;
    return switch (root) {
        .src_path => |path| if (path.owner == b) path.sub_path else null,
        else => null,
    };
}

/// The path of `module`'s root in the package or the tree that made it.
fn root_path(module: *const Module) []const u8 {
    const root = module.root_source_file orelse return "no file";
    return switch (root) {
        .src_path => |path| path.sub_path,
        else => "a file the build makes",
    };
}

fn reaches_under(b: *std.Build, reached: []const *Module, directory: []const u8) bool {
    for (reached) |module| {
        const root = tree_root(b, module) orelse continue;
        if (std.mem.startsWith(u8, root, directory)) return true;
    }
    return false;
}

const Finding = struct {
    /// The root of the module rooted in the rule's directory.
    root: []const u8,
    /// The module of the rule's package that it reaches.
    reached: *const Module,
    /// A module that imports `reached`.
    importer: *const Module,
};

/// The first module among `reached` rooted in the rule's directory that reaches a module of the
/// rule's package.
fn find(arena: std.mem.Allocator, b: *std.Build, reached: []const *Module, rule: Rule) !?Finding {
    for (reached) |module| {
        const root = tree_root(b, module) orelse continue;
        if (!std.mem.startsWith(u8, root, rule.under)) continue;
        const closure = try reach(arena, &.{module}, rule.stop_at);
        const target = first_of(closure, rule.package) orelse continue;
        return .{ .root = root, .reached = target, .importer = importer_of(closure, target, rule.stop_at) };
    }
    return null;
}

/// The first module among `reached` of `package`.
fn first_of(reached: []const *Module, package: Package) ?*const Module {
    for (reached) |module| {
        if (of(module, package)) return module;
    }
    return null;
}

/// A module among `reached` that imports `target`. The walk read no import of a module of one of
/// `stop_at`, so none of those is the one. `reached` starts with the module the walk started at,
/// which is the importer when none of `reached` imports `target`.
fn importer_of(reached: []const *Module, target: *const Module, stop_at: []const Package) *const Module {
    assert(reached.len > 0);
    for (reached) |module| {
        if (of_any(module, stop_at)) continue;
        for (module.import_table.values()) |imported| {
            if (imported == target) return module;
        }
    }
    return reached[0];
}

/// What a message calls `module`: the path of its root in this tree, or the package that made it.
fn name_of(b: *std.Build, module: *const Module) struct { []const u8, []const u8 } {
    if (tree_root(b, module)) |root| return .{ "", root };
    for (std.enums.values(Package)) |package| {
        if (of(module, package)) return .{ "a module of ", @tagName(package) };
    }
    return .{ "a module of ", module.owner.pkg_hash };
}
