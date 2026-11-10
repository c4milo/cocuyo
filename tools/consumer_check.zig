//! The check of docs/design.md §20: a package that depends on cocuyo builds against it, and the
//! same package cannot reach a module or a path the surface does not export.
//!
//! §20 claims cocuyo is a package before it is a library, and the branch a dependent takes through
//! cocuyo's own build — the early return before the tools' dependency, the manifest's `paths` —
//! is compiled by nothing else. `test/consumer/` is that dependent: it declares cocuyo by
//! relative path, imports `cocuyo`, and builds a query through the table with the cache under it.
//! The tool runs that program once it builds, so what the table asserts of its memory runs too.
//! It also builds the engine on a rotor of its own, and over DoQ and DoT with a colibri of its own.
//!
//! The refusals are the same package with each value of `-Dreach-inside`. The first asks for
//! `sim`, which the build registers under no name. The rest reach for a path that left the surface
//! on 2026-11-09: `cocuyo.wire`, `cocuyo.resolver`, `cocuyo.core`, and the test data under
//! `cocuyo.wire`, `cocuyo.rdata` and `cocuyo.resolv_conf`. Each of those builds must fail. As in
//! `graph_check`, the positive run gives the check its meaning. A check of a failure alone also
//! passes on a failure of another cause. Examples are a path with a typo, an absent Zig and a
//! broken invocation.
//!
//! The package pins its own rotor and colibri, and binds them where a consumer binds them
//! (docs/design.md §24, §16 decision 38, as amended). Each pin must be the one cocuyo's
//! `build.zig.zon` holds: at another pin the package builds cocuyo against a package cocuyo does
//! not pin. So the tool compares the pins first, and stops at one that differs.
//!
//! Usage: `consumer_check <zig-exe> <package-dir> <cache-dir> <build.zig.zon>`
const std = @import("std");
const assert = std.debug.assert;

const Outcome = enum { built, refused };

/// The option the fixture's own build reads to reach a path the package does not export.
const reach_inside = "-Dreach-inside=";

/// One refusal: the value of `reach_inside` the fixture's build takes, and the path its program
/// reaches for.
const Refusal = struct { value: []const u8, path: []const u8 };

/// The paths a consumer must not reach (docs/design.md §20). Each value is a tag of `Inside` in
/// `test/consumer/build.zig`, and names a program of `test/consumer/inside/`.
const refusals = [_]Refusal{
    .{ .value = "sim", .path = "the module 'sim'" },
    .{ .value = "wire", .path = "cocuyo.wire" },
    .{ .value = "resolver", .path = "cocuyo.resolver" },
    .{ .value = "core", .path = "cocuyo.core" },
    .{ .value = "wire_fixtures", .path = "cocuyo.wire.fixtures" },
    .{ .value = "rdata_fixtures", .path = "cocuyo.rdata.fixtures" },
    .{ .value = "resolv_conf_fuzz", .path = "cocuyo.resolv_conf.fuzz" },
};

/// What the nested build may print before this tool stops reading it. It is swallowed either way;
/// the negative run fails on purpose and its trace is not news.
const output_bytes_max: std.Io.Limit = .limited(1 << 20);

/// The most a manifest may take.
const manifest_bytes_max: std.Io.Limit = .limited(1 << 20);

/// The packages the fixture pins for itself, each of which cocuyo's manifest pins too.
const pinned = [_][]const u8{ "rotor", "colibri" };

// Each name of `pinned` is the name of an entry, so none is empty.
comptime {
    assert(pinned.len > 0);
    for (pinned) |name| assert(name.len > 0);
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 5) {
        std.debug.print("usage: consumer_check <zig-exe> <package-dir> <cache-dir> <build.zig.zon>\n", .{});
        std.process.exit(2);
    }
    const zig_exe = args[1];
    const package = args[2];
    const cache = args[3];

    // The pins first: a package at another pin builds against what cocuyo does not pin.
    try require_pins(arena, init.io, args[4], package);

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

    // The program runs too. It does no I/O, and the table asserts the floor of its keys at `init`,
    // which a build alone never runs (docs/design.md §20).
    if (!try runs(arena, init.io, cache)) {
        std.debug.print("consumer-check: the dependent program built and did not run to its query\n", .{});
        std.process.exit(1);
    }
    std.debug.print("consumer-check: the dependent program runs to its query\n", .{});

    // Each refusal runs, so one report names every path a consumer reached.
    var reached: usize = 0;
    for (refusals) |refusal| {
        const option = try std.mem.concat(arena, u8, &.{ reach_inside, refusal.value });
        if (try run_build(arena, init.io, zig_exe, package, cache, option) == .refused) {
            std.debug.print("consumer-check: a consumer cannot reach {s}\n", .{refusal.path});
        } else {
            std.debug.print("consumer-check: a consumer reached {s}, which the package must not export\n", .{refusal.path});
            reached += 1;
        }
    }
    assert(reached <= refusals.len);
    if (reached > 0) std.process.exit(1);
}

/// Stops the program when the package's manifest pins rotor or colibri apart from `manifest_path`.
fn require_pins(arena: std.mem.Allocator, io: std.Io, manifest_path: []const u8, package: []const u8) !void {
    // `build/consumer_check.zig` passes both, and an empty one is that file's error.
    assert(manifest_path.len > 0);
    assert(package.len > 0);
    const cwd = std.Io.Dir.cwd();
    const manifest = try cwd.readFileAlloc(io, manifest_path, arena, manifest_bytes_max);
    const fixture_path = try std.fs.path.join(arena, &.{ package, "build.zig.zon" });
    const fixture = try cwd.readFileAlloc(io, fixture_path, arena, manifest_bytes_max);
    const name = pin_apart(manifest, fixture) orelse return;
    std.debug.print(
        "consumer-check: {s} pins {s} at {s}, where build.zig.zon pins it at {s}\n",
        .{ fixture_path, name, hash_of(fixture, name) orelse "nothing", hash_of(manifest, name) orelse "nothing" },
    );
    std.process.exit(1);
}

/// The first package of `pinned` that the two manifests do not pin at one hash, or that either
/// does not pin. Null when each is pinned at one hash.
pub fn pin_apart(manifest: []const u8, fixture: []const u8) ?[]const u8 {
    for (pinned) |name| {
        const want = hash_of(manifest, name) orelse return name;
        const have = hash_of(fixture, name) orelse return name;
        if (!std.mem.eql(u8, want, have)) return name;
    }
    // Each pin agrees, so the fixture names each package.
    for (pinned) |name| assert(hash_of(fixture, name) != null);
    return null;
}

/// The hash a manifest pins the package `name` at: the `.hash` of the entry `.<name> = .{`, read
/// up to the entry's end. Null when the manifest has no such entry, or the entry no hash.
pub fn hash_of(manifest: []const u8, name: []const u8) ?[]const u8 {
    // A name comes from `pinned` or from a test, never from a manifest.
    assert(name.len > 0);
    const key = ".hash = \"";
    var at: usize = 0;
    for (0..manifest.len + 1) |_| {
        const found = std.mem.indexOfPos(u8, manifest, at, name) orelse return null;
        at = found + name.len;
        if (found == 0 or manifest[found - 1] != '.' or !std.mem.startsWith(u8, manifest[at..], " = .{")) continue;
        const end = std.mem.indexOfScalarPos(u8, manifest, at, '}') orelse return null;
        const start = (std.mem.indexOf(u8, manifest[at..end], key) orelse return null) + at + key.len;
        const close = std.mem.indexOfScalarPos(u8, manifest, start, '"') orelse return null;
        // The key lies inside the entry, and the hash ends at or after its start.
        assert(start <= end);
        assert(start <= close);
        return manifest[start..close];
    }
    return null;
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

/// The program the control build installs, which drives the table with no I/O.
const consumer_program = "consumer";

/// Whether the fixture's `consumer` program, which the control build installed under `cache`,
/// runs and exits with 0.
fn runs(arena: std.mem.Allocator, io: std.Io, cache: []const u8) !bool {
    assert(cache.len > 0);
    const program = try std.fs.path.join(arena, &.{ cache, "out", "bin", consumer_program });
    const result = std.process.run(arena, io, .{
        .argv = &.{program},
        .stdout_limit = output_bytes_max,
        .stderr_limit = output_bytes_max,
    }) catch return false;
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

// Tests. The check itself needs a compiler and a package, so these pin the option the fixture's
// build reads, and how a manifest's pins are read.

const testing = std.testing;

test "the option each refusal passes is spelled the way a build option is" {
    // The fixture's own build declares `reach-inside`; the build wiring lists that file as an
    // input, so a rename there re-runs this check rather than passing it quietly.
    try testing.expectEqualStrings("-Dreach-inside=", reach_inside);
    try testing.expect(std.mem.startsWith(u8, reach_inside, "-D"));
}

test "each refusal names a program of the fixture, once" {
    var directory = try std.Io.Dir.cwd().openDir(testing.io, "test/consumer/inside", .{});
    defer directory.close(testing.io);
    for (refusals, 0..) |refusal, index| {
        const file = try std.mem.concat(testing.allocator, u8, &.{ refusal.value, ".zig" });
        defer testing.allocator.free(file);
        try directory.access(testing.io, file, .{});
        for (refusals[index + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, refusal.value, other.value));
    }
}

/// A manifest as cocuyo's is written: a lazy package before the two, and the two with their URLs.
const manifest_sample =
    \\.dependencies = .{
    \\    .pepegrillo = .{ .url = "git+https://example.invalid/p", .hash = "pepegrillo-0", .lazy = true },
    \\    .rotor = .{
    \\        .url = "git+https://example.invalid/rotor?ref=v0.4.0#1",
    \\        .hash = "rotor-0.4.0-a",
    \\        .lazy = true,
    \\    },
    \\    .colibri = .{
    \\        .url = "git+https://example.invalid/colibri?ref=v0.8.0#2",
    \\        .hash = "colibri-0.8.0-b",
    \\    },
    \\},
;

test "a pin is the hash of the package's own entry, and none when the manifest has no entry" {
    try testing.expectEqualStrings("rotor-0.4.0-a", hash_of(manifest_sample, "rotor").?);
    try testing.expectEqualStrings("colibri-0.8.0-b", hash_of(manifest_sample, "colibri").?);
    try testing.expectEqualStrings("pepegrillo-0", hash_of(manifest_sample, "pepegrillo").?);
    // A name inside another entry's text, or with no `.` before it, is not an entry.
    try testing.expectEqual(null, hash_of(manifest_sample, "example"));
    // An entry with no hash has none, whatever hash the next entry holds.
    try testing.expectEqual(null, hash_of(".stdx = .{ .url = \"u\" },\n.rotor = .{ .hash = \"r\" },", "stdx"));
    try testing.expectEqual(null, hash_of(manifest_sample, "stdx"));
}

test "the fixture's pins must be the manifest's, each of them" {
    try testing.expectEqual(null, pin_apart(manifest_sample, manifest_sample));
    const other_colibri = "    .rotor = .{ .hash = \"rotor-0.4.0-a\" },\n    .colibri = .{ .hash = \"colibri-0.7.0-c\" },\n";
    try testing.expectEqualStrings("colibri", pin_apart(manifest_sample, other_colibri).?);
    const no_colibri = "    .rotor = .{ .hash = \"rotor-0.4.0-a\" },\n";
    try testing.expectEqualStrings("colibri", pin_apart(manifest_sample, no_colibri).?);
    const other_rotor = "    .rotor = .{ .hash = \"rotor-0.5.0-d\" },\n    .colibri = .{ .hash = \"colibri-0.8.0-b\" },\n";
    try testing.expectEqualStrings("rotor", pin_apart(manifest_sample, other_rotor).?);
}
