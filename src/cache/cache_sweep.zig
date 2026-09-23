//! The hand of SIEVE, with the expiry folded in (docs/design.md §18).
//!
//! SIEVE (Zhang et al., NSDI 2024) walks its hand from the oldest entry toward the newest,
//! clearing the visited bit of anything it passes and evicting the first entry it finds with the
//! bit clear. A hit sets the bit and moves nothing, which is what keeps the read path to one
//! write. What the paper does not have is an entry that dies on its own: the hand here evicts an
//! expired entry on sight, visited or not, which is the eviction c-ares spends a skip list on.
const std = @import("std");
const assert = std.debug.assert;
const cache = @import("cache.zig");
const constants = @import("constants.zig");
const none = cache.none;

/// Frees one slot of a full cache. From where the hand stopped, or the oldest entry, toward the
/// newest: an expired entry is evicted on sight; a visited one has its bit cleared and stays; the
/// first unvisited one is evicted. One pass clears every bit and the next must then find one, so
/// twice the slot count bounds the walk, and the bound is asserted rather than trusted.
pub fn evict_one(self: *cache.Cache, now_ns: u64) void {
    assert(self.free == none);
    assert(self.order.len == self.slots.len);
    var index = if (self.hand == none) self.order.oldest else self.hand;
    const bound = constants.sweep_steps_max(self.slots.len);
    var steps: usize = 0;
    while (steps < bound) : (steps += 1) {
        const slot = &self.slots[index];
        assert(slot.occupied);
        if (now_ns >= slot.expires_ns or !slot.visited) {
            self.hand = index;
            self.evict(index);
            assert(self.free != none);
            return;
        }
        slot.visited = false;
        index = self.order.after(self.slots, index);
    }
    unreachable;
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const ask = fixtures.question;
const second = fixtures.second;

fn put_v4(table: *cache.Cache, text: []const u8, last: u8, ttl_seconds: u32, now_ns: u64) void {
    const answers = fixtures.answers_v4(last, ttl_seconds);
    table.put(&ask(text), &answers, null, now_ns);
}

fn hits(table: *cache.Cache, text: []const u8, now_ns: u64) bool {
    return table.get(&ask(text), now_ns) != null;
}

test "a full table evicts the oldest unvisited entry, and the hand keeps its place" {
    var fixture: fixtures.Fixture(3) = .{};
    var table = fixture.init();
    put_v4(&table, "a.example", 1, 300, 0);
    put_v4(&table, "b.example", 2, 300, 0);
    put_v4(&table, "c.example", 3, 300, 0);
    try testing.expectEqual(@as(usize, 3), table.len());
    try testing.expect(hits(&table, "a.example", 0));
    // The hand passes a, visited, and evicts b; it rests on c, past a whose bit is clear now.
    put_v4(&table, "d.example", 4, 300, 0);
    try testing.expectEqual(@as(usize, 3), table.len());
    try testing.expect(!hits(&table, "b.example", 0));
    // From c, not from the oldest again: c goes and a, unvisited, stays.
    put_v4(&table, "e.example", 5, 300, 0);
    try testing.expect(!hits(&table, "c.example", 0));
    try testing.expect(hits(&table, "a.example", 0));
    try testing.expect(hits(&table, "d.example", 0));
    try testing.expect(hits(&table, "e.example", 0));
}

test "a visited entry survives one sweep and not two" {
    var fixture: fixtures.Fixture(2) = .{};
    var table = fixture.init();
    put_v4(&table, "a.example", 1, 300, 0);
    put_v4(&table, "b.example", 2, 300, 0);
    try testing.expect(hits(&table, "a.example", 0));
    // The hand meets a, visited, clears it and moves on; b is unvisited and goes.
    put_v4(&table, "c.example", 3, 300, 0);
    try testing.expect(!hits(&table, "b.example", 0));
    try testing.expect(hits(&table, "c.example", 0));
    // The hand wrapped to a, whose bit is clear now, so a goes before c, which was just read.
    put_v4(&table, "d.example", 4, 300, 0);
    try testing.expect(!hits(&table, "a.example", 0));
    try testing.expect(hits(&table, "c.example", 0));
    try testing.expect(hits(&table, "d.example", 0));
}

test "the hand evicts an expired entry on sight, visited or not" {
    var fixture: fixtures.Fixture(3) = .{};
    var table = fixture.init();
    put_v4(&table, "a.example", 1, 10, 0);
    put_v4(&table, "b.example", 2, 300, 0);
    put_v4(&table, "c.example", 3, 300, 0);
    try testing.expect(hits(&table, "a.example", 0));
    try testing.expect(hits(&table, "b.example", 0));
    // At twenty seconds a has expired; visited, it would otherwise have been passed over for c.
    put_v4(&table, "d.example", 4, 300, 20 * second);
    try testing.expect(hits(&table, "b.example", 20 * second));
    try testing.expect(hits(&table, "c.example", 20 * second));
    try testing.expect(hits(&table, "d.example", 20 * second));
}

test "a sweep over a table where every entry was visited clears every bit and evicts the oldest" {
    var fixture: fixtures.Fixture(4) = .{};
    var table = fixture.init();
    const names = [_][]const u8{ "a.example", "b.example", "c.example", "d.example" };
    for (names, 1..) |name, last| put_v4(&table, name, @intCast(last), 300, 0);
    for (names) |name| try testing.expect(hits(&table, name, 0));
    put_v4(&table, "e.example", 5, 300, 0);
    try testing.expect(!hits(&table, "a.example", 0));
    for (table.slots) |slot| try testing.expect(!slot.visited);
    try testing.expectEqual(@as(usize, 4), table.len());
}

test "an expired entry a get has missed is still the hand's to take" {
    var fixture: fixtures.Fixture(2) = .{};
    var table = fixture.init();
    put_v4(&table, "a.example", 1, 300, 0);
    put_v4(&table, "b.example", 2, 10, 0);
    // Full: the hand starts at a, unvisited, evicts it and comes to rest on b.
    put_v4(&table, "c.example", 3, 300, 0);
    try testing.expectEqual(table.hand, table.find(&ask("b.example"), table.hash_of(&ask("b.example"))).?);
    // At twenty seconds b has expired: the get misses and b keeps its slot.
    try testing.expect(!hits(&table, "b.example", 20 * second));
    try testing.expectEqual(@as(usize, 2), table.len());
    // No put renews b, so the next put that needs a slot takes it, and c stays.
    put_v4(&table, "d.example", 4, 300, 20 * second);
    try testing.expect(hits(&table, "c.example", 20 * second));
    try testing.expect(hits(&table, "d.example", 20 * second));
    try testing.expect(!hits(&table, "b.example", 20 * second));
    try testing.expectEqual(@as(usize, 2), table.len());
}
