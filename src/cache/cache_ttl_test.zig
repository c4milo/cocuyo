//! An entry's life at the cache's own surface: what is left of a TTL, the cap, what is never
//! cached, the negatives of RFC 2308, and what a get does with an entry it finds expired
//! (docs/design.md §18, §17 question 14). Split from `cache.zig` to keep it under 500 lines.
const std = @import("std");
const testing = std.testing;
const cache = @import("cache.zig");
const constants = @import("constants.zig");
const fixtures = @import("fixtures.zig");
const Cache = cache.Cache;
const Outcome = cache.Outcome;
const ask = fixtures.question;
const second = fixtures.second;

/// Enough slots that no test here fills the table: the hand is cache_sweep.zig's to drive.
const slot_count = 4;

test "a hit reports what is left of the TTL, and an expired entry is a miss that keeps its slot" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = ask("example.com");
    const answers = fixtures.answers_v4(1, 300);
    table.put(&asked, &answers, null, 0);
    try testing.expectEqual(@as(u32, 200), table.get(&asked, 100 * second).?.ttl_seconds);
    try testing.expectEqual(@as(u32, 0), table.get(&asked, 300 * second - 1).?.ttl_seconds);
    try testing.expect(table.get(&asked, 300 * second) == null);
    try testing.expectEqual(@as(usize, 1), table.len());
    try testing.expect(table.get(&asked, 300 * second) == null);
    try testing.expectEqual(@as(usize, 1), table.len());
}

test "the put after an expired miss renews the entry where it stands" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const short = fixtures.answers_v4(1, 10);
    const long = fixtures.answers_v4(2, 300);
    table.put(&ask("a.example"), &short, null, 0);
    table.put(&ask("b.example"), &long, null, 0);
    const oldest = table.order.oldest;
    table.slots[oldest].visited = false;
    try testing.expect(table.get(&ask("a.example"), 20 * second) == null);
    table.put(&ask("a.example"), &long, null, 20 * second);
    // Still the oldest, in the same slot, and not a new entry at the newest end.
    try testing.expectEqual(@as(usize, 2), table.len());
    try testing.expectEqual(oldest, table.order.oldest);
    try testing.expectEqual(oldest, table.find(&ask("a.example"), table.hash_of(&ask("a.example"))).?);
    try testing.expectEqual(@as(u32, 300), table.get(&ask("a.example"), 20 * second).?.ttl_seconds);
}

test "a TTL of zero and a truncated answer are not cached, and a TTL over the cap is capped" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = cache_init_capped(&fixture, 60);
    const zero = fixtures.answers_v4(1, 0);
    table.put(&ask("a.example"), &zero, null, 0);
    var truncated = fixtures.answers_v4(1, 300);
    truncated.truncated = true;
    table.put(&ask("a.example"), &truncated, null, 0);
    table.put_negative(&ask("b.example"), .name_not_found, 0, 0);
    try testing.expectEqual(@as(usize, 0), table.len());
    const long = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &long, null, 0);
    try testing.expectEqual(@as(u32, 60), table.get(&ask("a.example"), 0).?.ttl_seconds);
    try testing.expect(table.get(&ask("a.example"), 60 * second) == null);
}

fn cache_init_capped(fixture: *fixtures.Fixture(slot_count), ttl_seconds_max: u32) Cache {
    return Cache.init(&fixture.slots, &fixture.keys, fixtures.seed, ttl_seconds_max);
}

test "a negative answer is cached with its outcome, its TTL and no records" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    table.put_negative(&ask("nx.example"), .name_not_found, 60, 0);
    table.put_negative(&ask("nodata.example"), .no_data, 30, 0);
    const nx = table.get(&ask("nx.example"), 0).?;
    try testing.expectEqual(Outcome.name_not_found, nx.outcome);
    try testing.expectEqual(@as(u32, 60), nx.ttl_seconds);
    try testing.expectEqual(@as(usize, 0), nx.answers.addresses().len);
    const nodata = table.get(&ask("nodata.example"), 0).?;
    try testing.expectEqual(Outcome.no_data, nodata.outcome);
    try testing.expectEqual(@as(u32, 30), nodata.ttl_seconds);
    // An answer put over a negative entry replaces it, outcome included.
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("nx.example"), &answers, null, 0);
    try testing.expectEqual(Outcome.answered, table.get(&ask("nx.example"), 0).?.outcome);
}
