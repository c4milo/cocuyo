//! How a check of the mutation tool ended: a `zig build` step run with a mutation applied, and what
//! its output says about where it failed. `mutations.zig` runs the checks.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

/// The bytes of what a `zig` the tool runs prints.
const output_bytes_max: usize = 64 * 1024 * 1024;
/// What the replay prints before the walk it failed in, on a mismatch and on a panic alike.
const replay_marker = "engine replay:";
const walk_marker = "walk ";

/// How one check ended.
pub const Verdict = union(enum) {
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

/// Replays the engine's walks in the file `walks` against the tree as it is.
pub fn replay(arena: Allocator, io: Io, walks: []const u8) !Verdict {
    const option = try std.fmt.allocPrint(arena, "-Dengine-walks={s}", .{walks});
    return run_check(arena, io, &.{ "zig", "build", "spec-engine", option });
}

/// Runs `argv` and says how it ended: caught when it failed, in the walk the replay names.
pub fn run_check(arena: Allocator, io: Io, argv: []const []const u8) !Verdict {
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
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| if (is_compile_error(line)) return .compile;
    return .{ .caught = null };
}

/// Whether `line` is the compiler's: `<file>.zig:<line>:<column>: error: ...`. A failed test says
/// `error: '<name>' failed`, with no place before it.
fn is_compile_error(line: []const u8) bool {
    const at = std.mem.indexOf(u8, line, ": error: ") orelse return false;
    var place = std.mem.splitScalar(u8, line[0..at], ':');
    const file = place.next() orelse return false;
    const row = place.next() orelse return false;
    const column = place.next() orelse return false;
    if (place.next() != null or !std.mem.endsWith(u8, file, ".zig")) return false;
    _ = std.fmt.parseInt(u32, row, 10) catch return false;
    _ = std.fmt.parseInt(u32, column, 10) catch return false;
    return true;
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

// Tests.

const testing = std.testing;

test "a replay's failure names its walk, on a mismatch and on a panic" {
    try testing.expectEqual(Verdict{ .caught = 79 }, verdict_of("engine replay: Mismatch at line 15867, walk 79, depth 109, after start\n"));
    try testing.expectEqual(Verdict{ .caught = 8573 }, verdict_of("x\nengine replay: panic in walk 8573\nthread 1 panic: reached unreachable code\n"));
    try testing.expectEqual(Verdict.compile, verdict_of("io/io_tcp.zig:57:39: error: unused function parameter\n"));
    try testing.expectEqual(Verdict{ .caught = null }, verdict_of("error: 'io_tcp_test.test.a stream send' failed:\n"));
    try testing.expectEqual(Verdict.compile, verdict_of("src/a.zig:3:9: error: 'x' is not marked 'pub'\n"));
    try testing.expectEqual(Verdict{ .caught = null }, verdict_of("error: no step named 'test-nothing'\n"));
    try testing.expectEqual(Verdict{ .caught = null }, verdict_of("tools/run.sh:3:9: error: not the compiler's\n"));
}
