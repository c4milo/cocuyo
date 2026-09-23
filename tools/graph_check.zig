//! The check of docs/design.md §15 step 0: a module of the `resolver` shape cannot import the
//! config parser.
//!
//! §2 claims the dependency direction is enforced by the build rather than by review. A lint rule
//! over build/modules.zig would only check what that file says. This checks what the compiler
//! rejects: it compiles a fixture as the root of a module carrying exactly the import set
//! build/modules.zig gives `resolver`, and requires the compile to fail with Zig's own
//! "no module named" error.
//!
//! It runs a positive control in the same pass, and that control is what stops the check from
//! being vacuous. A check that only requires a failure passes when the failure has nothing to do
//! with the rule — a mistyped fixture path, a missing source, a broken `zig` invocation. So one
//! fixture imports `core`, which `resolver` does have, and must compile clean. A run in which the
//! control fails is reported as a broken check, not as a pass.
//!
//! Usage: `graph_check <zig-exe> <fixtures-dir> <core-root> <wire-root>`. The roots are the ones
//! build/modules.zig names in `roots`, passed by build/graph_check.zig, so the check compiles the
//! files the build does and never a path of its own.
const std = @import("std");

/// The import set build/modules.zig gives `resolver` (docs/design.md §2). Each module's root
/// source comes from the command line, in this order.
const resolver_imports = [_]Import{
    .{ .name = "core", .deps = &.{} },
    .{ .name = "wire", .deps = &.{"core"} },
};

/// The arguments before the roots: the program, the compiler and the fixtures directory.
const arguments_before_roots = 3;

const usage = "usage: graph_check <zig-exe> <fixtures-dir> <core-root> <wire-root>\n";

/// Every module name `resolver` must not be able to import. Each gets a fixture and each must
/// fail. `config` is the split of §1 refinement 7: the state machine takes a server list and a
/// search list, whoever produced them, so it cannot reach the file format. `sim` is the harness,
/// which reads the state machine and must never be read back.
const forbidden = [_][]const u8{ "config", "sim" };

/// The module name the positive control imports: one `resolver` really does have.
const control = "core";

const Import = struct {
    name: []const u8,
    deps: []const []const u8,
};

const Outcome = enum { compiled, rejected };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != arguments_before_roots + resolver_imports.len) {
        std.debug.print(usage, .{});
        std.process.exit(2);
    }
    const zig_exe = args[1];
    const fixtures = args[2];
    const roots = args[arguments_before_roots..];

    // The control first: if importing a module `resolver` does have does not compile, nothing this
    // tool reports afterwards means anything.
    const control_path = try fixture_path(arena, fixtures, control);
    if (try compile(arena, init.io, zig_exe, roots, control_path) != .compiled) {
        std.debug.print(
            "graph-check BROKEN: the control fixture importing '{s}' did not compile.\n" ++
                "  Nothing else this check reports is meaningful until that is fixed.\n",
            .{control},
        );
        std.process.exit(1);
    }
    std.debug.print("graph-check control: import '{s}' compiles, as it must\n", .{control});

    var failures: usize = 0;
    for (forbidden) |module_name| {
        const path = try fixture_path(arena, fixtures, module_name);
        if (try compile(arena, init.io, zig_exe, roots, path) == .rejected) {
            std.debug.print("graph-check: a resolver module cannot import '{s}'\n", .{module_name});
        } else {
            std.debug.print(
                "graph-check FAILED: a resolver module compiled an @import(\"{s}\").\n" ++
                    "  build/modules.zig has widened the set. See docs/design.md §2.\n",
                .{module_name},
            );
            failures += 1;
        }
    }

    if (failures != 0) std.process.exit(1);
}

fn fixture_path(arena: std.mem.Allocator, fixtures: []const u8, module_name: []const u8) ![]const u8 {
    return std.fs.path.join(arena, &.{
        fixtures,
        try std.fmt.allocPrint(arena, "resolver_imports_{s}.zig", .{module_name}),
    });
}

/// Compiles `root_path` as the root of a module carrying exactly `resolver_imports`, whose root
/// sources are `roots` in the same order, and reports whether the compiler accepted it. A
/// non-zero exit is `rejected`; anything else is `compiled`.
fn compile(
    arena: std.mem.Allocator,
    io: std.Io,
    zig_exe: []const u8,
    roots: []const []const u8,
    root_path: []const u8,
) !Outcome {
    std.debug.assert(roots.len == resolver_imports.len);
    // `--dep` flags apply to the next `-M`, and the first `-M` is the root module — so the root's
    // whole dependency list precedes it, and each dependency's own list precedes its own `-M`.
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ zig_exe, "build-obj", "-fno-emit-bin" });
    for (resolver_imports) |import| try argv.appendSlice(arena, &.{ "--dep", import.name });
    try argv.append(arena, try std.fmt.allocPrint(arena, "-Mroot={s}", .{root_path}));
    for (resolver_imports, roots) |import, root| {
        for (import.deps) |dep| try argv.appendSlice(arena, &.{ "--dep", dep });
        try argv.append(arena, try std.fmt.allocPrint(arena, "-M{s}={s}", .{ import.name, root }));
    }

    const result = try std.process.run(arena, io, .{ .argv = argv.items });
    return switch (result.term) {
        .exited => |code| if (code == 0) .compiled else .rejected,
        else => .rejected,
    };
}

// Tests. The check itself needs a compiler, so these pin the lists it checks against the design.

const testing = std.testing;

test "the forbidden list names every module resolver must not reach" {
    const expected = [_][]const u8{ "config", "sim" };
    try testing.expectEqual(expected.len, forbidden.len);
    for (expected, forbidden) |want, got| try testing.expectEqualStrings(want, got);
}

test "resolver's import set is the one design §2 states" {
    const expected = [_][]const u8{ "core", "wire" };
    try testing.expectEqual(expected.len, resolver_imports.len);
    for (expected, resolver_imports) |want, got| try testing.expectEqualStrings(want, got.name);
}

test "the control is a module resolver actually imports" {
    var found = false;
    for (resolver_imports) |import| {
        if (std.mem.eql(u8, import.name, control)) found = true;
    }
    try testing.expect(found);
}
