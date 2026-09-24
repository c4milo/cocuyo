//! The engine's mutations, kept as data in `engine_mutations.zon` and run again on demand: each
//! breaks the engine of `io/`, or the table under it, one way, and must be caught by the check it
//! names (docs/mutations.md, the engine replay on TLC's walks). TLC's walks change whenever the
//! engine model does, so the picked walks are chosen again this way: for each mutation the short
//! walks miss, the run names the first walk of the full run that catches it.
//!
//! Run:  zig build engine-mutations [-- <id>...]
//!
//! It has TLC write the full run first, unless `--walks <file>` names one written before. Then for
//! each mutation it applies the edits, runs `zig build spec-engine -Dengine-walks=<file>` over the
//! short walks and, when they miss it, over the full run and the picked walks, or `zig build
//! test-io` for one no walk can reach, and puts the files back.
//!
//! Exit status: 0 when every mutation is caught where it should be, 1 otherwise, 2 on a bad
//! command line.
//!
//! This is developer tooling. It is never linked into the library, so it allocates, reads and
//! writes files, and runs `zig`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Edit = struct { file: []const u8, old: []const u8, new: []const u8 };

/// The check a mutation must fail.
pub const Check = enum { short_walks, picked_walks, test_io };

pub const Mutation = struct {
    id: []const u8,
    what: []const u8,
    edits: []const Edit,
    caught_by: Check,
};

const mutations: []const Mutation = @import("engine_mutations.zon");

/// The bytes of one source file the tool edits, and of what a `zig` it runs prints.
const file_bytes_max: usize = 16 * 1024 * 1024;
const output_bytes_max: usize = 64 * 1024 * 1024;
/// The bytes the tool's report is written through.
const output_buffer_bytes: usize = 4096;
/// What the replay prints before the walk it failed in, on a mismatch and on a panic alike.
const replay_marker = "engine replay:";
const walk_marker = "walk ";

const exit_success: u8 = 0;
const exit_failure: u8 = 1;
const exit_usage: u8 = 2;

const usage =
    \\usage: engine-mutations --short <file> --picked <file> --full <seed> <walks> <depth>
    \\           (--walks <file> | --full-out <file>) [<id>...]
    \\
;

/// What the command line names: the committed walks, the full run's parameters or a file of it,
/// and the mutations to run, every one when it names none.
const Options = struct {
    short: []const u8 = "",
    picked: []const u8 = "",
    full: [3][]const u8 = .{ "", "", "" },
    walks: ?[]const u8 = null,
    full_out: ?[]const u8 = null,
    ids: []const []const u8 = &.{},
};

/// How one check ended.
const Verdict = union(enum) {
    /// The check failed, in this walk when a replay said which.
    caught: ?u64,
    missed,
    /// The mutation did not compile: its `old` text no longer says what the code does.
    compile,
    /// Not run, since an earlier check settled the mutation.
    skipped,

    pub fn format(verdict: Verdict, writer: *Io.Writer) Io.Writer.Error!void {
        switch (verdict) {
            .caught => |walk| if (walk) |number| try writer.print("caught, walk {d}", .{number}) else try writer.writeAll("caught"),
            .missed => try writer.writeAll("missed"),
            .compile => try writer.writeAll("did not compile"),
            .skipped => try writer.writeAll("not run"),
        }
    }
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
    const options = options_of(arguments) orelse {
        try out.writeAll(usage);
        return exit_usage;
    };
    for (options.ids) |id| if (find(id) == null) {
        try out.print("no mutation {s}\n", .{id});
        return exit_usage;
    };
    const walks = options.walks orelse try write_full_run(io, options, out);
    var picks: std.ArrayList(u64) = .empty;
    var status = exit_success;
    for (mutations) |mutation| {
        if (options.ids.len > 0 and !named(options.ids, mutation.id)) continue;
        const result = try run_one(arena, io, options, walks, mutation);
        try write_result(out, mutation, result);
        if (!result.as_expected(mutation.caught_by)) status = exit_failure;
        if (result.pick()) |walk| try picks.append(arena, walk);
    }
    try write_picks(out, picks.items);
    return status;
}

fn options_of(arguments: []const []const u8) ?Options {
    var options: Options = .{};
    var at: usize = 0;
    while (at < arguments.len and std.mem.startsWith(u8, arguments[at], "--")) {
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
        at += values + 1;
    }
    options.ids = arguments[at..];
    const complete = options.short.len > 0 and options.picked.len > 0 and options.full[0].len > 0;
    if (!complete or (options.walks == null and options.full_out == null)) return null;
    return options;
}

fn find(id: []const u8) ?Mutation {
    for (mutations) |mutation| if (std.mem.eql(u8, mutation.id, id)) return mutation;
    return null;
}

fn named(ids: []const []const u8, id: []const u8) bool {
    for (ids) |one| if (std.mem.eql(u8, one, id)) return true;
    return false;
}

/// Has TLC write the full run to `--full-out`, as `zig build spec` has it written, and names it.
fn write_full_run(io: Io, options: Options, out: *Io.Writer) ![]const u8 {
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
    return path;
}

/// What each check made of one mutation.
const Result = struct {
    short: Verdict = .skipped,
    full: Verdict = .skipped,
    picked: Verdict = .skipped,
    test_io: Verdict = .skipped,

    fn as_expected(result: Result, expected: Check) bool {
        return switch (expected) {
            .short_walks => result.short == .caught,
            .picked_walks => result.short == .caught or result.picked == .caught,
            .test_io => result.test_io == .caught,
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

fn run_one(arena: Allocator, io: Io, options: Options, walks: []const u8, mutation: Mutation) !Result {
    const originals = try apply(arena, io, Io.Dir.cwd(), mutation.edits);
    defer restore(io, Io.Dir.cwd(), mutation.edits, originals);
    var result: Result = .{};
    if (mutation.caught_by == .test_io) {
        result.test_io = try run_check(arena, io, &.{ "zig", "build", "test-io" });
        return result;
    }
    result.short = try replay(arena, io, options.short);
    if (result.short != .missed) return result;
    result.full = try replay(arena, io, walks);
    result.picked = try replay(arena, io, options.picked);
    return result;
}

/// Applies each edit, and returns each file's bytes as they were. Every file is put back before
/// an edit that cannot apply is reported.
fn apply(arena: Allocator, io: Io, dir: Io.Dir, edits: []const Edit) ![]const []const u8 {
    const originals = try arena.alloc([]const u8, edits.len);
    for (edits, 0..) |edit, index| {
        errdefer restore(io, dir, edits[0..index], originals[0..index]);
        originals[index] = try dir.readFileAlloc(io, edit.file, arena, .limited(file_bytes_max));
        if (std.mem.count(u8, originals[index], edit.old) != 1) return error.EditDoesNotApply;
        const edited = try std.mem.replaceOwned(u8, arena, originals[index], edit.old, edit.new);
        try dir.writeFile(io, .{ .sub_path = edit.file, .data = edited });
    }
    return originals;
}

/// Puts the files back, the last edited first, so a file two edits share ends as it began.
fn restore(io: Io, dir: Io.Dir, edits: []const Edit, originals: []const []const u8) void {
    var index = edits.len;
    while (index > 0) {
        index -= 1;
        dir.writeFile(io, .{ .sub_path = edits[index].file, .data = originals[index] }) catch
            std.debug.panic("could not put {s} back", .{edits[index].file});
    }
}

fn replay(arena: Allocator, io: Io, walks: []const u8) !Verdict {
    const option = try std.fmt.allocPrint(arena, "-Dengine-walks={s}", .{walks});
    return run_check(arena, io, &.{ "zig", "build", "spec-engine", option });
}

/// Runs `argv` and says how it ended: caught when it failed, in the walk the replay names.
fn run_check(arena: Allocator, io: Io, argv: []const []const u8) !Verdict {
    const result = try std.process.run(arena, io, .{
        .argv = argv,
        .stdout_limit = .limited(output_bytes_max),
        .stderr_limit = .limited(output_bytes_max),
    });
    const ended = switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (ended) return .missed;
    return verdict_of(result.stderr);
}

/// What a failed run's output says: the walk the replay failed in, a compile error, or neither.
fn verdict_of(output: []const u8) Verdict {
    if (std.mem.indexOf(u8, output, replay_marker)) |at| return .{ .caught = walk_after(output[at..]) };
    if (std.mem.indexOf(u8, output, ": error: ") != null and std.mem.indexOf(u8, output, ".zig:") != null) {
        if (std.mem.indexOf(u8, output, "error: '") == null) return .compile;
    }
    return .{ .caught = null };
}

/// The number after the first `walk ` in `text`.
fn walk_after(text: []const u8) ?u64 {
    const line_end = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    const line = text[0..line_end];
    const at = std.mem.indexOf(u8, line, walk_marker) orelse return null;
    const digits = line[at + walk_marker.len ..];
    var end: usize = 0;
    while (end < digits.len and std.ascii.isDigit(digits[end])) end += 1;
    return std.fmt.parseInt(u64, digits[0..end], 10) catch null;
}

fn write_result(out: *Io.Writer, mutation: Mutation, result: Result) !void {
    const verdict = if (result.as_expected(mutation.caught_by)) "CAUGHT" else "NOT CAUGHT as it should be";
    try out.print("{s} {s}: short walks {f}, full run {f}, picked walks {f}, test-io {f}. {s} ({t})\n", .{
        mutation.id, mutation.what, result.short, result.full, result.picked, result.test_io, verdict, mutation.caught_by,
    });
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

test "every mutation names its edits and each edit changes something" {
    for (mutations) |mutation| {
        try testing.expect(mutation.id.len > 0 and mutation.what.len > 0 and mutation.edits.len > 0);
        for (mutation.edits) |edit| try testing.expect(!std.mem.eql(u8, edit.old, edit.new));
    }
}

test "a replay's failure names its walk, on a mismatch and on a panic" {
    try testing.expectEqual(Verdict{ .caught = 79 }, verdict_of("engine replay: Mismatch at line 15867, walk 79, depth 109, after start\n"));
    try testing.expectEqual(Verdict{ .caught = 8573 }, verdict_of("x\nengine replay: panic in walk 8573\nthread 1 panic: reached unreachable code\n"));
    try testing.expectEqual(Verdict.compile, verdict_of("io/io_tcp.zig:57:39: error: unused function parameter\n"));
    try testing.expectEqual(Verdict{ .caught = null }, verdict_of("error: 'io_tcp_test.test.a stream send' failed:\n"));
}

test "a mutation the short walks miss is picked at the full run's walk" {
    const missed: Result = .{ .short = .missed, .full = .{ .caught = 51 }, .picked = .{ .caught = 1 } };
    try testing.expectEqual(51, missed.pick().?);
    try testing.expect(missed.as_expected(.picked_walks) and !missed.as_expected(.short_walks));
    const caught: Result = .{ .short = .{ .caught = 8 } };
    try testing.expectEqual(null, caught.pick());
    try testing.expect(caught.as_expected(.short_walks) and caught.as_expected(.picked_walks));
}

test "two edits to one file apply in turn, and the file is put back as it began" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const source = "const a = 1;\nconst b = 2;\n";
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "x.zig", .data = source });
    const edits = [_]Edit{
        .{ .file = "x.zig", .old = "a = 1", .new = "a = 3" },
        .{ .file = "x.zig", .old = "b = 2", .new = "b = 4" },
    };
    const originals = try apply(arena, testing.io, tmp.dir, &edits);
    const edited = try tmp.dir.readFileAlloc(testing.io, "x.zig", arena, .limited(file_bytes_max));
    try testing.expectEqualStrings("const a = 3;\nconst b = 4;\n", edited);
    restore(testing.io, tmp.dir, &edits, originals);
    const back = try tmp.dir.readFileAlloc(testing.io, "x.zig", arena, .limited(file_bytes_max));
    try testing.expectEqualStrings(source, back);
    const twice = [_]Edit{ .{ .file = "x.zig", .old = "a = 1", .new = "a = 3" }, .{ .file = "x.zig", .old = "const", .new = "var" } };
    try testing.expectError(error.EditDoesNotApply, apply(arena, testing.io, tmp.dir, &twice));
    const kept = try tmp.dir.readFileAlloc(testing.io, "x.zig", arena, .limited(file_bytes_max));
    try testing.expectEqualStrings(source, kept);
}

test "the command line needs the committed walks, the full run, and a place for it" {
    const full = [_][]const u8{ "--short", "g", "--picked", "p", "--full", "1", "2000", "201" };
    try testing.expectEqual(null, options_of(&full));
    const options = options_of(&(full ++ [_][]const u8{ "--walks", "w", "E3", "ET4" })).?;
    try testing.expectEqualStrings("w", options.walks.?);
    try testing.expectEqualStrings("2000", options.full[1]);
    try testing.expectEqual(2, options.ids.len);
    try testing.expectEqual(null, options_of(&.{ "--short", "g", "--bogus", "x" }));
}
