//! The program `zig build instructions` counts (tools/instructions.zig): one case of `zig build
//! bench`, set up once and then run a given number of times, so that pepegrillo's `instructions`
//! tool can count what each operation takes under cachegrind.
//!
//!     count <case> <rounds>
//!
//! A count is the same on a busy runner as on a quiet one, so it can hold a commit where a time
//! cannot (docs/performance.md). The cases are the benchmark's own, by the name they carry in the
//! baseline, `bench/instructions.zon`; each runs exactly the code its row in design §11 times.
const std = @import("std");
const harness = @import("harness.zig");
const cases = @import("bench_cases.zig");
const cache_cases = @import("bench_cache.zig");

/// A counted case: its name in the baseline, and the benchmark case it runs, by that case's name.
const Counted = struct { name: []const u8, bench: []const u8 };

/// The cases counted, the paths a query takes and the cache's own operations. Their names are
/// what `tools/instructions.zig` passes as each case's argument.
pub const counted = [_]Counted{
    .{ .name = "query-build", .bench = "query build, example.com, EDNS0" },
    .{ .name = "query-build-tcp", .bench = "query build, 255-octet name, TCP" },
    .{ .name = "parse-one", .bench = "response parse, one A" },
    .{ .name = "parse-cname", .bench = "response parse, CNAME then A (+ 256-octet restore)" },
    .{ .name = "parse-sixteen", .bench = "response parse, 16 A of 17" },
    .{ .name = "match-stray", .bench = "datagram match, stray id, 1024 in flight" },
    .{ .name = "match-wrong", .bench = "datagram match, wrong question, 1 in flight" },
    .{ .name = "match-accept", .bench = "datagram match, accepted, 1024 in flight (+ slot restore)" },
    .{ .name = "round-trip", .bench = "lookup round trip: init in place, poll, on_sent, on_response" },
    .{ .name = "resolv-conf", .bench = "resolv.conf parse, three lines" },
    .{ .name = "cache-hit", .bench = "cache hit, one entry, hot" },
    .{ .name = "cache-miss", .bench = "cache miss, 1024 entries, young index" },
    .{ .name = "cache-put", .bench = "cache put, replacing in place" },
    .{ .name = "cache-put-evict", .bench = "cache put, evicting, 1024 entries full" },
};

const every_case = cases.all ++ cache_cases.all;

/// The benchmark case called `name`, which a counted case must name.
fn bench_case(comptime name: []const u8) harness.Case {
    for (every_case) |case| {
        if (std.mem.eql(u8, case.name, name)) return case;
    }
    @compileError("no benchmark case is called " ++ name);
}

/// The counted cases, each with the benchmark case it runs, found once at compile time.
const resolved = resolved: {
    var out: [counted.len]struct { name: []const u8, case: harness.Case } = undefined;
    for (counted, &out) |entry, *slot| slot.* = .{ .name = entry.name, .case = bench_case(entry.bench) };
    break :resolved out;
};

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len != 3) usage();
    const rounds = std.fmt.parseInt(u64, arguments[2], 10) catch usage();
    for (resolved) |entry| {
        if (!std.mem.eql(u8, entry.name, arguments[1])) continue;
        entry.case.setup();
        for (0..rounds) |_| entry.case.run();
        return;
    }
    usage();
}

fn usage() noreturn {
    std.debug.print("usage: count <case> <rounds>, a case one of:", .{});
    for (counted) |entry| std.debug.print(" {s}", .{entry.name});
    std.debug.print("\n", .{});
    std.process.exit(2);
}

const testing = std.testing;

test "every counted case names a benchmark case, and no two share a name" {
    // `bench_case` refuses a name at compile time; this holds the names apart.
    for (counted, 0..) |entry, index| {
        for (counted[index + 1 ..]) |other| try testing.expect(!std.mem.eql(u8, entry.name, other.name));
    }
    try testing.expectEqual(counted.len, resolved.len);
}
