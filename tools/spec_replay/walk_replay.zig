//! The walks' replay: drives `AddressLookup` and `NameLookup` down the transcript the walks'
//! model writes (`cocuyo-spec walks`, spec/lean/Spec/AddressWalk.lean) and fails on the first line
//! where a walk's state is not the model's (spec/README.md).
//!
//! The transcript is a depth-first walk over every state the model reaches, so a line at depth
//! `d` is one event on what its parent at `d - 1` left. The replay keeps one frame per depth,
//! the table and the walk whole, restores the parent's before each line, and saves its own
//! after. A section line, `address ...` or `name ...`, fixes the configuration for the lines
//! after it.
//!
//! `zig build spec` runs this over the whole transcript, and `zig build test` runs the tests
//! below, which replay the committed slice in `walk_gate.txt` without Lean.
//!
//! This is developer tooling. It is never linked into the library, so it allocates and reads the
//! filesystem.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const world_module = @import("walk_world.zig");
const World = world_module.World;
const Live = world_module.Live;

/// The deepest line the replay follows: far past what the walks' transcript reaches.
const depth_max = 128;

/// The longest line of a transcript.
const line_bytes_max = world_module.text_bytes_max + 64;

pub const Error = world_module.Error || error{ Mismatch, Empty, TooDeep };

pub const Replay = struct {
    world: World = .{},
    frames: [depth_max]Live = undefined,
    depth: usize = 0,
    configured: bool = false,
    lines: usize = 0,
    events: usize = 0,
    sections: usize = 0,
    expected: [line_bytes_max]u8 = undefined,
    expected_len: usize = 0,
    got: [world_module.text_bytes_max]u8 = undefined,
    got_len: usize = 0,

    /// Replays one line of the transcript.
    pub fn line(replay: *Replay, text: []const u8) Error!void {
        replay.lines += 1;
        if (text.len == 0) return;
        if (text.len > line_bytes_max) return error.Malformed;
        var fields = std.mem.splitScalar(u8, text, ' ');
        const first = fields.first();
        if (std.mem.eql(u8, first, "address")) return replay.section(.address, &fields);
        if (std.mem.eql(u8, first, "name")) return replay.section(.name, &fields);
        if (!replay.configured) return error.Malformed;
        const depth = std.fmt.parseInt(usize, first, 10) catch return error.Malformed;
        const event = fields.next() orelse return error.Malformed;
        const expected = fields.rest();
        if ((depth == 0) != std.mem.eql(u8, event, "init")) return error.Malformed;
        if (depth > replay.depth + 1 or depth >= depth_max) return error.TooDeep;
        if (depth == 0) {
            try replay.world.begin();
        } else {
            replay.world.live = replay.frames[depth - 1];
            try replay.world.apply(event);
        }
        replay.frames[depth] = replay.world.live;
        replay.depth = depth;
        replay.events += 1;
        const got = replay.world.text(&replay.got);
        if (std.mem.eql(u8, got, expected)) return;
        @memcpy(replay.expected[0..expected.len], expected);
        replay.expected_len = expected.len;
        replay.got_len = got.len;
        return error.Mismatch;
    }

    fn section(replay: *Replay, walk: world_module.Walk, fields: *std.mem.SplitIterator(u8, .scalar)) Error!void {
        const sources = fields.next() orelse return error.Malformed;
        const hosts_has = std.mem.eql(u8, fields.next() orelse return error.Malformed, "true");
        var candidates: usize = 1;
        var family: ?core.Family = null;
        var slots: usize = 2;
        if (walk == .address) {
            candidates = std.fmt.parseInt(usize, fields.next() orelse return error.Malformed, 10) catch return error.Malformed;
            family = try family_of(fields.next());
            slots = std.fmt.parseInt(usize, fields.next() orelse return error.Malformed, 10) catch return error.Malformed;
        }
        if (fields.next() != null) return error.Malformed;
        try replay.world.configure(walk, sources, hosts_has, candidates, family, slots);
        replay.configured = true;
        replay.depth = 0;
        replay.sections += 1;
    }

    pub fn finish(replay: *const Replay) Error!void {
        if (replay.events == 0) return error.Empty;
    }

    pub fn report(replay: *const Replay, err: anyerror) void {
        std.debug.print("walk replay: {s} at line {d}, section {d}\n", .{ @errorName(err), replay.lines, replay.sections });
        if (err != error.Mismatch) return;
        std.debug.print("  the model: {s}\n  the walk:  {s}\n", .{
            replay.expected[0..replay.expected_len], replay.got[0..replay.got_len],
        });
    }
};

fn family_of(token: ?[]const u8) Error!?core.Family {
    const text = token orelse return error.Malformed;
    if (std.mem.eql(u8, text, "both")) return null;
    if (std.mem.eql(u8, text, "a")) return .ipv4;
    if (std.mem.eql(u8, text, "aaaa")) return .ipv6;
    return error.Malformed;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(gpa);
    if (arguments.len != 2) {
        std.debug.print("usage: spec-walk-replay <transcript>\n", .{});
        return error.Usage;
    }
    const replay = try gpa.create(Replay);
    replay.* = .{};
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
    std.debug.print("walk replay: {d} events over {d} configurations agree with the model\n", .{ replay.events, replay.sections });
}

// Tests.

const testing = std.testing;

fn replay_text(replay: *Replay, text: []const u8) Error!void {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |one| try replay.line(one);
    try replay.finish();
}

test "the committed slice of the walks' transcript replays against the walks" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    replay_text(replay, @embedFile("walk_gate.txt")) catch |err| {
        replay.report(err);
        return err;
    };
    try testing.expect(replay.sections >= 2);
}

test "a state the walk does not reach is a mismatch, and a line out of place is refused" {
    const replay = try testing.allocator.create(Replay);
    defer testing.allocator.destroy(replay);
    replay.* = .{};
    try testing.expectError(error.Mismatch, replay_text(replay, "address dns false 1 both 2\n0 init s1 c0 a:- q:- -- e:- o0\n"));
    replay.* = .{};
    try testing.expectError(error.Malformed, replay.line("0 init s1"));
    try testing.expectError(error.Malformed, replay.line("address dns false 9 both 2"));
}
