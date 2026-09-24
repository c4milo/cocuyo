//! The engine replay: drives the engine of `io/` down the walks the engine model writes
//! (`cocuyo-spec engine-walks`, spec/lean/Spec/EngineWalk.lean) and fails on the first line where
//! the engine's state is not the model's (spec/README.md).
//!
//! A walk is a chain from `init`: each line is one event on what the line above it left, so the
//! replay keeps one engine and needs no frames. A `config` line starts a walk on a fresh engine
//! of that many slots and connections, over the twin in manual mode (`engine_world.zig`), and
//! the line after the event is the model's whole state, which `engine_text.zig` writes for the
//! engine in the same spelling.
//!
//! `zig build spec` runs this over the walks it has the model write, and `zig build test` runs
//! the tests below, which replay the committed walks of `engine_gate.txt` without Lean.
//!
//! This is developer tooling. It is never linked into the library, so it allocates and reads the
//! filesystem.
const std = @import("std");
const assert = std.debug.assert;
const world_module = @import("engine_world.zig");
const text_module = @import("engine_text.zig");

/// The longest line of a transcript: an event and a state.
const line_bytes_max = world_module.text_bytes_max + 64;

pub const Error = world_module.Error || error{ Mismatch, Empty, OutOfMemory, Unexpected };

/// The configurations the model walks: slots and connections.
const Which = enum { none, one_one, one_two, two_one, two_two };

pub const Replay = struct {
    one_one: *world_module.World(1, 1),
    one_two: *world_module.World(1, 2),
    two_one: *world_module.World(2, 1),
    two_two: *world_module.World(2, 2),
    current: Which = .none,
    depth: usize = 0,
    lines: usize = 0,
    events: usize = 0,
    walks: usize = 0,
    expected: [line_bytes_max]u8 = undefined,
    expected_len: usize = 0,
    got: [world_module.text_bytes_max]u8 = undefined,
    got_len: usize = 0,
    event: [line_bytes_max]u8 = undefined,
    event_len: usize = 0,

    pub fn create(allocator: std.mem.Allocator) error{OutOfMemory}!*Replay {
        const replay = try allocator.create(Replay);
        replay.* = .{
            .one_one = try allocator.create(world_module.World(1, 1)),
            .one_two = try allocator.create(world_module.World(1, 2)),
            .two_one = try allocator.create(world_module.World(2, 1)),
            .two_two = try allocator.create(world_module.World(2, 2)),
        };
        return replay;
    }

    pub fn destroy(replay: *Replay, allocator: std.mem.Allocator) void {
        allocator.destroy(replay.one_one);
        allocator.destroy(replay.one_two);
        allocator.destroy(replay.two_one);
        allocator.destroy(replay.two_two);
        allocator.destroy(replay);
    }

    /// Replays one line of the transcript.
    pub fn line(replay: *Replay, text: []const u8) Error!void {
        replay.lines += 1;
        if (text.len == 0) return;
        if (text.len > line_bytes_max) return error.Malformed;
        var fields = std.mem.splitScalar(u8, text, ' ');
        const first = fields.first();
        if (std.mem.eql(u8, first, "config")) return replay.configure(&fields);
        const depth = std.fmt.parseInt(usize, first, 10) catch return error.Malformed;
        const event = fields.next() orelse return error.Malformed;
        const expected = fields.rest();
        if ((depth == 0) != std.mem.eql(u8, event, "init")) return error.Malformed;
        if (depth != 0 and depth != replay.depth + 1) return error.Malformed;
        replay.depth = depth;
        @memcpy(replay.event[0..event.len], event);
        replay.event_len = event.len;
        switch (replay.current) {
            .none => return error.Malformed,
            inline else => |which| try replay.step(@field(replay, @tagName(which)), depth, event, expected),
        }
    }

    fn configure(replay: *Replay, fields: *std.mem.SplitIterator(u8, .scalar)) Error!void {
        const slots = fields.next() orelse return error.Malformed;
        const conns = fields.next() orelse return error.Malformed;
        const transport = try transport_of(fields.next(), fields.next());
        if (fields.next() != null) return error.Malformed;
        replay.current = which_of(slots, conns) orelse return error.Malformed;
        replay.depth = 0;
        replay.walks += 1;
        switch (replay.current) {
            .none => unreachable,
            inline else => |which| world_module.begin(@field(replay, @tagName(which)), transport) catch
                return error.Unexpected,
        }
    }

    fn step(replay: *Replay, world: anytype, depth: usize, event: []const u8, expected: []const u8) Error!void {
        if (depth > 0) try world_module.apply(world, event);
        const got = text_module.write(world, &replay.got);
        replay.events += 1;
        if (std.mem.eql(u8, got, expected)) return;
        @memcpy(replay.expected[0..expected.len], expected);
        replay.expected_len = expected.len;
        replay.got_len = got.len;
        return error.Mismatch;
    }

    pub fn finish(replay: *const Replay) Error!void {
        if (replay.events == 0) return error.Empty;
    }

    pub fn report(replay: *const Replay, err: anyerror) void {
        std.debug.print("engine replay: {s} at line {d}, walk {d}, depth {d}, after {s}\n", .{
            @errorName(err), replay.lines, replay.walks, replay.depth, replay.event[0..replay.event_len],
        });
        if (err != error.Mismatch) return;
        std.debug.print("  the model:  {s}\n  the engine: {s}\n", .{
            replay.expected[0..replay.expected_len], replay.got[0..replay.got_len],
        });
    }
};

/// The world of `slots` slots and `conns` connections, when the replay has one.
fn which_of(slots: []const u8, conns: []const u8) ?Which {
    const pairs = [_]struct { slots: []const u8, conns: []const u8, which: Which }{
        .{ .slots = "1", .conns = "1", .which = .one_one },
        .{ .slots = "1", .conns = "2", .which = .one_two },
        .{ .slots = "2", .conns = "1", .which = .two_one },
        .{ .slots = "2", .conns = "2", .which = .two_two },
    };
    for (pairs) |pair| {
        if (std.mem.eql(u8, pair.slots, slots) and std.mem.eql(u8, pair.conns, conns)) return pair.which;
    }
    return null;
}

/// Every query over `tcp`, `tls` or `udp`, and the queries a port carries before it is replaced.
fn transport_of(name: ?[]const u8, per_port: ?[]const u8) Error!world_module.Transport {
    const text = name orelse return error.Malformed;
    const tls = std.mem.eql(u8, text, "tls");
    const tcp = tls or std.mem.eql(u8, text, "tcp");
    if (!tcp and !std.mem.eql(u8, text, "udp")) return error.Malformed;
    const count = std.fmt.parseInt(u32, per_port orelse return error.Malformed, 10) catch return error.Malformed;
    return .{ .tcp = tcp, .per_port = count, .tls = tls };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(gpa);
    if (arguments.len != 2) {
        std.debug.print("usage: spec-engine-replay <transcript>\n", .{});
        return error.Usage;
    }
    const replay = try Replay.create(gpa);
    const file = try std.Io.Dir.cwd().openFile(init.io, arguments[1], .{});
    defer file.close(init.io);
    var buffer: [line_bytes_max]u8 = undefined;
    var file_reader = file.reader(init.io, &buffer);
    while (try file_reader.interface.takeDelimiter('\n')) |text| {
        replay.line(text) catch |err| {
            replay.report(err);
            return err;
        };
    }
    replay.finish() catch |err| {
        replay.report(err);
        return err;
    };
    std.debug.print("engine replay: {d} events over {d} walks agree with the model\n", .{ replay.events, replay.walks });
}

// Tests.

const testing = std.testing;

fn replay_text(replay: *Replay, text: []const u8) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |one| try replay.line(one);
    try replay.finish();
}

test "the committed walks of the engine model replay against the engine" {
    const replay = try Replay.create(testing.allocator);
    defer replay.destroy(testing.allocator);
    replay_text(replay, @embedFile("engine_gate.txt")) catch |err| {
        replay.report(err);
        return err;
    };
    try testing.expect(replay.walks >= 4);
}

test "a state the engine does not reach is a mismatch" {
    const replay = try Replay.create(testing.allocator);
    defer replay.destroy(testing.allocator);
    const text = "config 1 1 tcp 0\n0 init free - u- | closed s0 u0- | open s0-- ; open s0-- | L0* L1* | r[] q[] t- w[] f[0,0] e[0] --\n" ++
        "1 start free - u- | closed s0 u0- | open s0-- ; open s0-- | L0* L1* | r[] q[] t- w[] f[0,0] e[0] --\n";
    try testing.expectError(error.Mismatch, replay_text(replay, text));
}

test "a line that skips a depth, or names no configuration, is refused" {
    const replay = try Replay.create(testing.allocator);
    defer replay.destroy(testing.allocator);
    try testing.expectError(error.Malformed, replay.line("0 init free"));
    try testing.expectError(error.Malformed, replay.line("config 3 1 tcp 0"));
    try testing.expectError(error.Malformed, replay.line("config 1 1 sctp 0"));
    try replay.line("config 1 1 tcp 0");
    try testing.expectError(error.Malformed, replay.line("2 start free"));
}
