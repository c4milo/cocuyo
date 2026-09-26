//! `zig build fuzz` and `zig build fuzz-gate`: the two fuzz targets outside the test runner
//! (docs/design.md §13). `zig build test` runs each target's gate over a fixed range of seeds; this
//! runs one seed and prints what it built, which is how a failure the gate reports is read, or a
//! range as long as the caller likes, which is how a slower search for one is run.
//!
//!     zig build fuzz -- [--text] --seed <hex>
//!     zig build fuzz-gate -- [--text] [<count> [<first>]]
//!
//! Without `--text` the target is the codec's (`src/wire/fuzz.zig`), and with it the text
//! parsers' (`src/config/fuzz/fuzz.zig`). This is developer tooling. It is never linked into the
//! library.
const std = @import("std");
const wire = @import("wire");
const config = @import("config");

const Target = enum { wire, text };
const Command = union(enum) {
    one: u64,
    range: struct { count: u64, first: u64 },
};

/// The seeds `fuzz-gate` runs when it is told no count: what a minute or so reaches.
const count_default = 1 << 20;
const hex_base = 16;
const decimal_base = 10;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    // `--text` may come anywhere: `zig build fuzz-gate` puts `--gate` before what the caller gives.
    var rest: std.ArrayList([]const u8) = .empty;
    var target: Target = .wire;
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--text")) target = .text else try rest.append(arena, arg);
    }
    const command = parse_command(rest.items) catch {
        std.debug.print("usage: fuzz [--text] --seed <hex>\n       fuzz [--text] --gate [<count>] [<first>]\n", .{});
        std.process.exit(2);
    };
    switch (command) {
        .one => |seed| if (!run_one(target, seed)) std.process.exit(1),
        .range => |range| if (!run_range(target, range.count, range.first)) std.process.exit(1),
    }
}

fn parse_command(args: []const []const u8) !Command {
    if (args.len == 2 and std.mem.eql(u8, args[0], "--seed")) {
        const text = if (std.mem.startsWith(u8, args[1], "0x")) args[1][2..] else args[1];
        return .{ .one = try std.fmt.parseInt(u64, text, hex_base) };
    }
    if (args.len >= 1 and args.len <= 3 and std.mem.eql(u8, args[0], "--gate")) {
        const count = if (args.len >= 2) try std.fmt.parseInt(u64, args[1], decimal_base) else count_default;
        const first = if (args.len == 3) try std.fmt.parseInt(u64, args[2], decimal_base) else 0;
        return .{ .range = .{ .count = count, .first = first } };
    }
    return error.Usage;
}

/// Builds one seed's input, prints it and what the check says of it. True when it held.
fn run_one(target: Target, seed: u64) bool {
    const verdict = switch (target) {
        .wire => one_message(seed),
        .text => one_text(seed),
    };
    if (verdict) |what| {
        std.debug.print("broke: {s}\n", .{what});
        return false;
    }
    std.debug.print("held\n", .{});
    return true;
}

fn one_message(seed: u64) ?[]const u8 {
    var message: wire.fuzz.Message = .{};
    wire.fuzz.generate(seed, &message);
    std.debug.print("seed 0x{x}: {t}, {d} octets{s}\n", .{ seed, message.strategy, message.len, if (message.whole) ", its record whole" else "" });
    print_bytes(message.slice());
    return wire.fuzz.verdict(&message);
}

fn one_text(seed: u64) ?[]const u8 {
    var text: config.fuzz.Text = .{};
    var scratch: config.fuzz.Scratch = .{};
    config.fuzz.generate(seed, &text);
    std.debug.print("seed 0x{x}: {t}, {t}, {d} octets\n", .{ seed, text.target, text.shape, text.len });
    print_bytes(text.slice());
    return config.fuzz.check(&text, &scratch);
}

/// The input, printable bytes as they are and every other as `\xNN`.
fn print_bytes(bytes: []const u8) void {
    for (bytes) |byte| {
        if (byte == '\n' or (byte >= ' ' and byte <= '~' and byte != '\\')) {
            std.debug.print("{c}", .{byte});
        } else {
            std.debug.print("\\x{x:0>2}", .{byte});
        }
    }
    std.debug.print("\n", .{});
}

/// Runs a range and prints the first seed that broke a promise, or that every one held.
fn run_range(target: Target, count: u64, first: u64) bool {
    const failure: ?struct { seed: u64, what: []const u8 } = switch (target) {
        .wire => if (wire.fuzz.gate(first, count)) |broke| .{ .seed = broke.seed, .what = broke.what } else null,
        .text => if (config.fuzz.gate(first, count)) |broke| .{ .seed = broke.seed, .what = broke.what } else null,
    };
    if (failure) |broke| {
        std.debug.print("{t} fuzz: seed 0x{x} broke a promise: {s}\n", .{ target, broke.seed, broke.what });
        return false;
    }
    std.debug.print("{t} fuzz: {d} seeds from {d} held\n", .{ target, count, first });
    return true;
}

// Tests.

const testing = std.testing;

test "a seed is read in hexadecimal, and a gate takes a count and a first seed" {
    try testing.expectEqual(Command{ .one = 0x1f }, try parse_command(&.{ "--seed", "0x1f" }));
    try testing.expectEqual(Command{ .one = 0x1f }, try parse_command(&.{ "--seed", "1f" }));
    const range = (try parse_command(&.{ "--gate", "100", "7" })).range;
    try testing.expectEqual(@as(u64, 100), range.count);
    try testing.expectEqual(@as(u64, 7), range.first);
    try testing.expectEqual(@as(u64, count_default), (try parse_command(&.{"--gate"})).range.count);
    try testing.expectError(error.Usage, parse_command(&.{"--seed"}));
}
