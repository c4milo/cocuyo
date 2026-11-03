//! `zig build orders`: the check of `src/sim/sim_orders.zig` over a range of seeds, outside the
//! test runner (c4milo/cocuyo#61). `zig build test` runs seeds 0 to 63. This runs as many as the
//! caller likes, ReleaseSafe, which is how CI's `orders-nightly` workflow runs 65,536.
//!
//!     zig build orders -- [<count> [<first>]]
//!
//! Each seed runs under every twist: no twist, a lookup cancelled, and the key store's entries
//! expired. This is developer tooling. It is never linked into the library.
const std = @import("std");
const sim = @import("sim");
const orders = sim.orders;

const Range = struct { count: u64, first: u64 };

/// The seeds `orders` runs when it is told no count: what CI's nightly run takes.
const count_default: u64 = 1 << 16;
const decimal_base: u8 = 10;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const range = parse(args[1..]) catch {
        std.debug.print("usage: orders [<count> [<first>]]\n", .{});
        std.process.exit(2);
    };
    const expected = orders.alone() catch |err| {
        std.debug.print("orders: a name alone did not end: {t}\n", .{err});
        std.process.exit(1);
    };
    if (orders.gate(&expected, range.first, range.count)) |broke| {
        std.debug.print("orders: seed {d}, {t}: {s}\n", .{ broke.seed, broke.twist, broke.what });
        std.process.exit(1);
    }
    std.debug.print("orders: {d} seeds from {d}, each under every twist, held\n", .{ range.count, range.first });
}

fn parse(args: []const []const u8) !Range {
    if (args.len > 2) return error.Usage;
    const count = if (args.len >= 1) try std.fmt.parseInt(u64, args[0], decimal_base) else count_default;
    const first = if (args.len == 2) try std.fmt.parseInt(u64, args[1], decimal_base) else 0;
    return .{ .count = count, .first = first };
}

// Tests.

const testing = std.testing;

test "a range takes a count and a first seed, and runs 65,536 from 0 when told none" {
    try testing.expectEqual(Range{ .count = count_default, .first = 0 }, try parse(&.{}));
    try testing.expectEqual(Range{ .count = 100, .first = 0 }, try parse(&.{"100"}));
    try testing.expectEqual(Range{ .count = 100, .first = 7 }, try parse(&.{ "100", "7" }));
    try testing.expectError(error.Usage, parse(&.{ "1", "2", "3" }));
    try testing.expectError(error.InvalidCharacter, parse(&.{"x"}));
}
