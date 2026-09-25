//! The check of docs/design.md §20: a package that depends on cocuyo builds against it, and the
//! same package cannot import a module the surface does not export.
//!
//! §20 claims cocuyo is a package before it is a library, and the branch a dependent takes through
//! cocuyo's own build — the early return before the tools' dependency, the manifest's `paths` —
//! is compiled by nothing else. `test/consumer/` is that dependent: it declares cocuyo by
//! relative path, imports `cocuyo`, and builds a query through the table with the cache under it.
//!
//! The negative control is the same package with `-Dreach-inside`, which asks for `sim`. Only
//! `cocuyo` and `cocuyo_rotor` are registered, so that build must fail. As in `graph_check`, the positive run is what
//! stops the check from being vacuous: a check that only requires a failure passes when the
//! failure has nothing to do with the rule — a mistyped path, a missing Zig, a broken invocation.
//!
//! Usage: `consumer_check <zig-exe> <package-dir> <cache-dir>`
const std = @import("std");

const Outcome = enum { built, refused };

/// The option the fixture's own build reads to import a module the package does not export.
const reach_inside = "-Dreach-inside=true";

/// What the nested build may print before this tool stops reading it. It is swallowed either way;
/// the negative run fails on purpose and its trace is not news.
const output_bytes_max: std.Io.Limit = .limited(1 << 20);

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 4) {
        std.debug.print("usage: consumer_check <zig-exe> <package-dir> <cache-dir>\n", .{});
        std.process.exit(2);
    }
    const zig_exe = args[1];
    const package = args[2];
    const cache = args[3];

    // The control first: if a dependent cannot build at all, nothing this tool reports afterwards
    // means anything.
    if (try run_build(arena, init.io, zig_exe, package, cache, null) != .built) {
        std.debug.print(
            "consumer-check BROKEN: the dependent package did not build.\n" ++
                "  Nothing else this check reports is meaningful until that is fixed.\n",
            .{},
        );
        std.process.exit(1);
    }
    std.debug.print("consumer-check control: a package depending on cocuyo builds, as it must\n", .{});

    if (try run_build(arena, init.io, zig_exe, package, cache, reach_inside) != .refused) {
        std.debug.print("consumer-check: a consumer imported 'sim', which the package must not export\n", .{});
        std.process.exit(1);
    }
    std.debug.print("consumer-check: a consumer cannot import 'sim'\n", .{});
}

/// One nested `zig build`, with its cache and its output under the parent's, so the fixture's own
/// directory holds sources and nothing else.
fn run_build(
    arena: std.mem.Allocator,
    io: std.Io,
    zig_exe: []const u8,
    package: []const u8,
    cache: []const u8,
    option: ?[]const u8,
) !Outcome {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{
        zig_exe,
        "build",
        "--cache-dir",
        cache,
        "--prefix",
        try std.fs.path.join(arena, &.{ cache, "out" }),
    });
    if (option) |one| try argv.append(arena, one);

    const result = std.process.run(arena, io, .{
        .argv = argv.items,
        .cwd = .{ .path = package },
        .stdout_limit = output_bytes_max,
        .stderr_limit = output_bytes_max,
    }) catch return .refused;
    return switch (result.term) {
        .exited => |code| if (code == 0) .built else .refused,
        else => .refused,
    };
}

// Tests. The check itself needs a compiler and a package, so this pins the option the fixture's
// build reads, which is the whole of what the two files agree on.

const testing = std.testing;

test "the option the negative control passes is spelled the way a build option is" {
    // The fixture's own build declares `reach-inside`; the build wiring lists that file as an
    // input, so a rename there re-runs this check rather than passing it quietly.
    try testing.expectEqualStrings("-Dreach-inside=true", reach_inside);
    try testing.expect(std.mem.startsWith(u8, reach_inside, "-D"));
}
