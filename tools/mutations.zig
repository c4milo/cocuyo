//! The mutations of docs/mutations.md, kept as data and run again on demand: each breaks the code
//! one way, and must be caught by the check it names. A set is one file of `mutations/`, each
//! mutation named by its section of docs/mutations.md and its row there.
//!
//! Run:  zig build mutations -- <set> [--walks <file>] [<id>...]
//!
//! The sets: `engine`, the engine of `io/` and the table under it, caught by the replay of TLC's
//! walks (docs/mutations.md, the engine replay on TLC's walks) or by a build step; `lookup`, the
//! state machine and its transports; `address`, the `getaddrinfo` shape and its walks; `lean`, the
//! Lean model and its proofs, each caught by `zig build spec-lean`. A mutation caught by a build
//! step fails that step. One caught by the walks fails the replay of the short
//! walks; when they miss it, the full run and the picked walks are replayed, and the run names the
//! full run's first walk that catches it, a walk to pick. TLC writes the full run the first time a
//! mutation needs it, unless `--walks <file>` names one written before.
//!
//! Exit status: 0 when every mutation is caught where it should be, 1 otherwise, 2 on a bad
//! command line.
//!
//! This is developer tooling. It is never linked into the library, so it allocates, reads and
//! writes files, and runs `zig`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const mutations_check = @import("mutations_check.zig");
const mutations_edit = @import("mutations_edit.zig");

pub const Edit = mutations_edit.Edit;
const Verdict = mutations_check.Verdict;

/// The check a mutation must fail: the short walks, the picked walks when the short walks miss
/// it, or a `zig build` step.
pub const Check = union(enum) {
    short_walks,
    picked_walks,
    step: []const u8,

    pub fn format(check: Check, writer: *Io.Writer) Io.Writer.Error!void {
        switch (check) {
            .short_walks => try writer.writeAll("the short walks"),
            .picked_walks => try writer.writeAll("the picked walks"),
            .step => |name| try writer.print("zig build {s}", .{name}),
        }
    }
};

pub const Mutation = struct {
    /// The heading of docs/mutations.md the mutation's row is under, and its row's name.
    section: []const u8,
    id: []const u8,
    what: []const u8,
    edits: []const Edit,
    caught_by: Check,
};

const Set = struct { name: []const u8, mutations: []const Mutation };

const sets = [_]Set{
    .{ .name = "engine", .mutations = @import("mutations/engine.zon") },
    .{ .name = "lookup", .mutations = @import("mutations/lookup.zon") },
    .{ .name = "address", .mutations = @import("mutations/address.zon") },
    .{ .name = "lean", .mutations = @import("mutations/lean.zon") },
};

/// The bytes the tool's report is written through.
const output_buffer_bytes: usize = 4096;

const exit_success: u8 = 0;
const exit_failure: u8 = 1;
const exit_usage: u8 = 2;

const usage =
    \\usage: zig build mutations -- <engine|lookup|address|lean> [--walks <file>] [<id>|<section>/<id>...]
    \\  (the build adds --short, --picked, --full and --full-out, the walks it knows)
    \\
;

/// What the command line names: the set, the committed walks, the full run's parameters and a
/// file of it or a place for one, and the mutations to run, every one when it names none.
const Options = struct {
    set: []const u8 = "",
    short: []const u8 = "",
    picked: []const u8 = "",
    full: [3][]const u8 = .{ "", "", "" },
    walks: ?[]const u8 = null,
    full_out: ?[]const u8 = null,
    ids: []const []const u8 = &.{},
};

/// The options the command line may name, each followed by its value, `--full` by three.
const Flag = enum { @"--short", @"--picked", @"--walks", @"--full-out", @"--full" };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    var output_buffer: [output_buffer_bytes]u8 = undefined;
    var out = Io.File.stdout().writerStreaming(init.io, &output_buffer);
    const status = try run(arena, init.io, arguments[1..], &out.interface);
    try out.interface.flush();
    std.process.exit(status);
}

fn run(arena: Allocator, io: Io, arguments: []const []const u8, out: *Io.Writer) !u8 {
    var options = options_of(arguments) orelse {
        try out.writeAll(usage);
        return exit_usage;
    };
    const set = find_set(options.set) orelse {
        try out.print("no set {s}\n", .{options.set});
        return exit_usage;
    };
    for (options.ids) |id| if (!has(set, id)) {
        try out.print("no mutation {s} in {s}\n", .{ id, set.name });
        return exit_usage;
    };
    if (!try baseline(arena, io, &options, set, out)) return exit_usage;
    return run_set(arena, io, &options, set, out);
}

/// Runs the set's chosen mutations, and returns the exit status.
fn run_set(arena: Allocator, io: Io, options: *Options, set: Set, out: *Io.Writer) !u8 {
    var picks: std.ArrayList(u64) = .empty;
    var status = exit_success;
    for (set.mutations) |mutation| {
        if (!chosen(options.ids, mutation)) continue;
        const result = run_one(arena, io, options, mutation, out) catch |failure| switch (failure) {
            error.EditDoesNotApply => {
                try out.print("{s} ({s}): an edit no longer applies, so the mutation must be written again\n", .{ mutation.id, mutation.section });
                status = exit_failure;
                continue;
            },
            else => return failure,
        };
        try write_result(out, mutation, result);
        if (!result.as_expected(mutation.caught_by)) status = exit_failure;
        if (result.pick()) |walk| try picks.append(arena, walk);
    }
    if (picks.items.len > 0) try write_picks(out, picks.items);
    return status;
}

fn options_of(arguments: []const []const u8) ?Options {
    if (arguments.len == 0 or std.mem.startsWith(u8, arguments[0], "--")) return null;
    var options: Options = .{ .set = arguments[0] };
    var at: usize = 1;
    while (at < arguments.len and std.mem.startsWith(u8, arguments[at], "--")) {
        at = read_flag(&options, arguments, at) orelse return null;
    }
    options.ids = arguments[at..];
    const complete = options.short.len > 0 and options.picked.len > 0 and options.full[0].len > 0;
    if (!complete or (options.walks == null and options.full_out == null)) return null;
    return options;
}

/// Reads the flag at `at` and its values into `options`, and returns where the next begins.
fn read_flag(options: *Options, arguments: []const []const u8, at: usize) ?usize {
    const flag = std.meta.stringToEnum(Flag, arguments[at]) orelse return null;
    const values: usize = if (flag == .@"--full") 3 else 1;
    if (at + values >= arguments.len) return null;
    const value = arguments[at + 1];
    switch (flag) {
        .@"--short" => options.short = value,
        .@"--picked" => options.picked = value,
        .@"--walks" => options.walks = value,
        .@"--full-out" => options.full_out = value,
        .@"--full" => options.full = arguments[at + 1 ..][0..3].*,
    }
    return at + values + 1;
}

fn find_set(name: []const u8) ?Set {
    for (sets) |set| if (std.mem.eql(u8, set.name, name)) return set;
    return null;
}

fn has(set: Set, name: []const u8) bool {
    for (set.mutations) |mutation| if (is_named(name, mutation)) return true;
    return false;
}

/// Whether the command line names the mutation, or names none and so every one.
fn chosen(names: []const []const u8, mutation: Mutation) bool {
    if (names.len == 0) return true;
    for (names) |name| if (is_named(name, mutation)) return true;
    return false;
}

/// Whether `name` is the mutation's id, or `<section>/<id>`, a section's start and its row, for an
/// id two sections share.
fn is_named(name: []const u8, mutation: Mutation) bool {
    const slash = std.mem.lastIndexOfScalar(u8, name, '/') orelse return std.mem.eql(u8, name, mutation.id);
    return std.mem.eql(u8, name[slash + 1 ..], mutation.id) and std.mem.startsWith(u8, mutation.section, name[0..slash]);
}

/// Runs each check the chosen mutations name once with nothing mutated, and says so when one
/// fails: a check that fails anyway, for a tool not installed or a step misspelled, catches
/// every mutation and proves nothing.
fn baseline(arena: Allocator, io: Io, options: *Options, set: Set, out: *Io.Writer) !bool {
    var seen: std.ArrayList([]const u8) = .empty;
    for (set.mutations) |mutation| {
        if (!chosen(options.ids, mutation)) continue;
        const name = switch (mutation.caught_by) {
            .step => |step| step,
            .short_walks, .picked_walks => "spec-engine",
        };
        if (listed(seen.items, name)) continue;
        try seen.append(arena, name);
        const verdict = switch (mutation.caught_by) {
            .step => |step| try mutations_check.run_check(arena, io, &.{ "zig", "build", step }),
            .short_walks, .picked_walks => try mutations_check.replay(arena, io, options.short),
        };
        if (verdict == .missed) continue;
        try out.print("zig build {s} fails with no mutation applied, so it can catch nothing: {f}\n", .{ name, verdict });
        return false;
    }
    return true;
}

fn listed(names: []const []const u8, name: []const u8) bool {
    for (names) |one| if (std.mem.eql(u8, one, name)) return true;
    return false;
}

/// The full run: the file `--walks` names, or one TLC writes to `--full-out` the first time a
/// mutation needs it, as `zig build spec` has it written.
fn full_run(io: Io, options: *Options, out: *Io.Writer) ![]const u8 {
    if (options.walks) |path| return path;
    const path = options.full_out.?;
    try out.print("TLC writes the full run, {s} walks of {s} states, to {s}\n", .{ options.full[1], options.full[2], path });
    try out.flush();
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var child = try std.process.spawn(io, .{
        .argv = &.{ "zig", "build", "tla", "--", "walks", options.full[0], options.full[1], options.full[2] },
        .stdin = .ignore,
        .stdout = .{ .file = file },
        .stderr = .inherit,
    });
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) return error.WalksFailed,
        else => return error.WalksFailed,
    }
    options.walks = path;
    return path;
}

/// What each check made of one mutation.
const Result = struct {
    short: Verdict = .skipped,
    full: Verdict = .skipped,
    picked: Verdict = .skipped,
    step: Verdict = .skipped,

    fn as_expected(result: Result, expected: Check) bool {
        return switch (expected) {
            .short_walks => result.short == .caught,
            .picked_walks => result.short == .caught or result.picked == .caught,
            .step => result.step == .caught,
        };
    }

    /// The full run's walk that catches a mutation, a walk to pick: the full run is run only
    /// when the short walks miss.
    fn pick(result: Result) ?u64 {
        return switch (result.full) {
            .caught => |walk| walk,
            else => null,
        };
    }
};

fn run_one(arena: Allocator, io: Io, options: *Options, mutation: Mutation, out: *Io.Writer) !Result {
    var originals = try mutations_edit.apply(arena, io, Io.Dir.cwd(), mutation.edits);
    defer mutations_edit.restore(io, Io.Dir.cwd(), mutation.edits, originals);
    var result: Result = .{};
    switch (mutation.caught_by) {
        .step => |name| result.step = try mutations_check.run_check(arena, io, &.{ "zig", "build", name }),
        .short_walks, .picked_walks => {
            result.short = try mutations_check.replay(arena, io, options.short);
            if (result.short != .missed) return result;
            if (options.walks == null) {
                // TLC writes the full run from the tree as it is, so the mutation steps aside.
                mutations_edit.restore(io, Io.Dir.cwd(), mutation.edits, originals);
                _ = try full_run(io, options, out);
                originals = try mutations_edit.apply(arena, io, Io.Dir.cwd(), mutation.edits);
            }
            result.full = try mutations_check.replay(arena, io, options.walks.?);
            result.picked = try mutations_check.replay(arena, io, options.picked);
        },
    }
    return result;
}

fn write_result(out: *Io.Writer, mutation: Mutation, result: Result) !void {
    const verdict = if (result.as_expected(mutation.caught_by)) "CAUGHT" else "NOT CAUGHT as it should be";
    try out.print("{s} ({s}) {s}: {s} by {f}.", .{ mutation.id, mutation.section, mutation.what, verdict, mutation.caught_by });
    switch (mutation.caught_by) {
        .step => try out.print(" The step {f}.\n", .{result.step}),
        .short_walks, .picked_walks => try out.print(" Short walks {f}, full run {f}, picked walks {f}.\n", .{
            result.short, result.full, result.picked,
        }),
    }
    try out.flush();
}

/// The walks the committed picked walks must hold for the short walks' misses, sorted, once each.
fn write_picks(out: *Io.Writer, picks: []u64) !void {
    std.mem.sort(u64, picks, {}, std.sort.asc(u64));
    try out.writeAll("the short walks' misses, first caught in the full run by walks:");
    var last: ?u64 = null;
    for (picks) |walk| {
        if (last == walk) continue;
        try out.print(" {d}", .{walk});
        last = walk;
    }
    try out.writeAll("\n");
}

// Tests.

const testing = std.testing;

test "every mutation names its section and its edits, and each edit changes something" {
    for (sets) |set| for (set.mutations) |mutation| {
        try testing.expect(mutation.section.len > 0 and mutation.id.len > 0 and mutation.what.len > 0);
        try testing.expect(mutation.edits.len > 0);
        for (mutation.edits) |edit| try testing.expect(!std.mem.eql(u8, edit.old, edit.new));
    };
}

test "a mutation is named by its id, or by its section's start and its id" {
    const mutation: Mutation = .{ .section = "Step 3, the state machine", .id = "S1", .what = "w", .edits = &.{}, .caught_by = .short_walks };
    try testing.expect(is_named("S1", mutation) and is_named("Step 3/S1", mutation));
    try testing.expect(!is_named("The Lean model/S1", mutation) and !is_named("S10", mutation));
    try testing.expect(chosen(&.{}, mutation) and chosen(&.{ "X9", "S1" }, mutation) and !chosen(&.{"X9"}, mutation));
}

test "a mutation the short walks miss is picked at the full run's walk" {
    const missed: Result = .{ .short = .missed, .full = .{ .caught = 51 }, .picked = .{ .caught = 1 } };
    try testing.expectEqual(51, missed.pick().?);
    try testing.expect(missed.as_expected(.picked_walks) and !missed.as_expected(.short_walks));
    const caught: Result = .{ .short = .{ .caught = 8 } };
    try testing.expectEqual(null, caught.pick());
    try testing.expect(caught.as_expected(.short_walks) and caught.as_expected(.picked_walks));
    const step: Result = .{ .step = .{ .caught = null } };
    try testing.expect(step.as_expected(.{ .step = "test-resolver" }) and !step.as_expected(.short_walks));
    const missed_step: Result = .{ .step = .missed };
    try testing.expect(!missed_step.as_expected(.{ .step = "test-resolver" }));
}

test "the command line names a set first, then the committed walks, the full run and its place" {
    const full = [_][]const u8{ "engine", "--short", "g", "--picked", "p", "--full", "1", "2000", "201" };
    try testing.expectEqual(null, options_of(&full));
    const options = options_of(&(full ++ [_][]const u8{ "--walks", "w", "E3", "ET4" })).?;
    try testing.expectEqualStrings("engine", options.set);
    try testing.expectEqualStrings("w", options.walks.?);
    try testing.expectEqualStrings("2000", options.full[1]);
    try testing.expectEqual(2, options.ids.len);
    try testing.expectEqual(null, options_of(&.{ "--short", "g" }));
    try testing.expectEqual(null, options_of(&.{ "engine", "--short", "g", "--bogus", "x" }));
    try testing.expect(find_set("lookup") != null and find_set("nothing") == null);
}

test {
    _ = mutations_check;
    _ = mutations_edit;
}
