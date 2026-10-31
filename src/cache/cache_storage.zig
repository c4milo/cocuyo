//! The memory a cache is built over, and how much of it a slot count takes (docs/design.md §18,
//! Sizing the memory).
//!
//! The memory is the caller's (CLAUDE.md non-negotiable 2): `slots.len` slots and a key index
//! whose length is a power of two at least `keys_per_slot_min` times that. `Cache.init` asserts
//! both. This file says the rule once, for two callers. One knows its slot count when it compiles
//! and declares a `Storage`. The other reads the count at run time, from a configuration file,
//! asks `slot_count_valid` whether to refuse it, and sizes its key index with `keys_for`. Nothing
//! here allocates: a caller that allocates does it with an allocator of its own.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const cache = @import("cache.zig");
const Slot = cache.Slot;
const Key = @import("cache_keys.zig").Key;

/// Whether a cache takes `slot_count` slots: 1 to `limits.slots_max`. A count read at run
/// time is input, so its reader asks this and refuses a bad one itself. `Cache.init` asserts
/// the same bound, which says the caller did.
pub fn slot_count_valid(slot_count: usize) bool {
    return slot_count >= 1 and slot_count <= limits.slots_max;
}

/// The least key index `slot_count` slots take: `keys_per_slot_min` entries a slot, rounded up
/// to a power of two, which the index's mask needs. A longer power of two is taken too.
pub fn keys_for(slot_count: usize) usize {
    assert(slot_count_valid(slot_count));
    const key_count = std.math.ceilPowerOfTwoAssert(usize, slot_count * limits.keys_per_slot_min);
    assert(key_count >= slot_count * limits.keys_per_slot_min);
    return key_count;
}

/// The memory a cache is built over, as `Cache.init` takes it: slices into memory the caller
/// owns, which must outlive the cache built over them. The memory needs no value first, since
/// `Cache.init` writes every slot and every key.
pub const Slices = struct {
    slots: []Slot,
    keys: []Key,

    /// Whether `Cache.init` takes the two: a slot count inside the bounds, and a key index of
    /// a power of two with `keys_per_slot_min` entries a slot at least.
    pub fn valid(self: Slices) bool {
        if (!slot_count_valid(self.slots.len)) return false;
        // Enough entries first: one slot or more takes an index of some, and the power-of-two
        // test is asked of no empty one.
        if (self.keys.len < self.slots.len * limits.keys_per_slot_min) return false;
        return std.math.isPowerOfTwo(self.keys.len);
    }
};

/// The memory of a cache of `slot_count` slots, for a caller that knows the count when it
/// compiles: the slots, and the least key index they take. A count outside the bounds does not
/// compile, and the error says what the bounds are. Declared `undefined`, it is 2992 octets a
/// slot and 8 a key (docs/design.md §18).
pub fn Storage(comptime slot_count: usize) type {
    if (!slot_count_valid(slot_count)) {
        @compileError(std.fmt.comptimePrint(
            "a cache takes 1 to {d} slots, and this Storage names {d}",
            .{ limits.slots_max, slot_count },
        ));
    }
    return struct {
        slots: [slot_count]Slot = undefined,
        keys: [keys_for(slot_count)]Key = undefined,

        /// Both arrays as slices, which point into this value: it must stay where it is.
        pub fn slices(self: *@This()) Slices {
            const both: Slices = .{ .slots = &self.slots, .keys = &self.keys };
            assert(both.valid());
            return both;
        }
    };
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const ask = fixtures.question;

test "the least key index is a power of two with two entries a slot" {
    const cases = [_][2]usize{ .{ 1, 2 }, .{ 2, 4 }, .{ 3, 8 }, .{ 1024, 2048 }, .{ 16384, 32768 } };
    for (cases) |case| {
        const key_count = keys_for(case[0]);
        try testing.expectEqual(case[1], key_count);
        try testing.expect(std.math.isPowerOfTwo(key_count));
        try testing.expect(key_count >= limits.keys_per_slot_min * case[0]);
        // And the least: half of it would hold fewer than two entries a slot.
        try testing.expect(key_count / 2 < limits.keys_per_slot_min * case[0]);
    }
}

test "a cache takes one slot to the most a slot index names, and refuses none and one more" {
    try testing.expect(!slot_count_valid(0));
    try testing.expect(slot_count_valid(1));
    try testing.expect(slot_count_valid(1024));
    try testing.expect(slot_count_valid(16384));
    try testing.expect(!slot_count_valid(16385));
    try testing.expectEqual(@as(usize, 16384), limits.slots_max);
}

test "slices are valid at the least key index and at a longer one, and at no other shape" {
    var slots: [3]Slot = undefined;
    var keys: [16]Key = undefined;
    // Three slots take eight entries, and sixteen do as well.
    try testing.expect((Slices{ .slots = &slots, .keys = keys[0..8] }).valid());
    try testing.expect((Slices{ .slots = &slots, .keys = &keys }).valid());
    // Two slots take four entries, and four are enough: the least index is exactly the bound.
    try testing.expect((Slices{ .slots = slots[0..2], .keys = keys[0..4] }).valid());
    // Four entries are a power of two and too few for three slots, and six are enough and no
    // power of two.
    try testing.expect(!(Slices{ .slots = &slots, .keys = keys[0..4] }).valid());
    try testing.expect(!(Slices{ .slots = &slots, .keys = keys[0..6] }).valid());
    try testing.expect(!(Slices{ .slots = slots[0..0], .keys = &keys }).valid());
    try testing.expect(!(Slices{ .slots = &slots, .keys = keys[0..0] }).valid());
}

test "slices of the most slots are valid, and of one slot more are not, whatever their index" {
    // `valid` reads the two lengths and nothing else, so the slices here are cut longer than
    // the memory under them: 16385 slots would be 46 MiB, and no cache is built over these.
    var slot: [1]Slot = undefined;
    var key: [1]Key = undefined;
    const slots: [*]Slot = &slot;
    const keys: [*]Key = &key;
    const most: usize = limits.slots_max;
    try testing.expect((Slices{ .slots = slots[0..most], .keys = keys[0..keys_for(most)] }).valid());
    // One slot more, under an index that is a power of two and long enough for it.
    const longer = limits.keys_per_slot_min * keys_for(most);
    try testing.expect(std.math.isPowerOfTwo(longer) and longer >= limits.keys_per_slot_min * (most + 1));
    try testing.expect(!(Slices{ .slots = slots[0 .. most + 1], .keys = keys[0..longer] }).valid());
}

test "a storage declares its slots and the least key index, and hands both over as slices" {
    var memory: Storage(3) = .{};
    var slot_count: usize = memory.slots.len;
    _ = &slot_count;
    try testing.expectEqual(@as(usize, 3), slot_count);
    try testing.expectEqual(@as(usize, 8), memory.keys.len);
    try testing.expectEqual(keys_for(slot_count), memory.keys.len);
    const both = memory.slices();
    try testing.expect(both.valid());
    try testing.expectEqual(@as([*]Slot, &memory.slots), both.slots.ptr);
    try testing.expectEqual(@as([*]Key, &memory.keys), both.keys.ptr);
    try testing.expectEqual(memory.slots.len, both.slots.len);
    try testing.expectEqual(memory.keys.len, both.keys.len);
}

test "a cache of one slot over the least memory holds one answer, and the next put evicts it" {
    var memory: Storage(1) = .{};
    try testing.expectEqual(@as(usize, 1), memory.slots.len);
    try testing.expectEqual(@as(usize, 2), memory.keys.len);
    const both = memory.slices();
    var table = cache.Cache.init(both.slots, both.keys, fixtures.seed, constants.ttl_seconds_max_default);
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, .unchecked, 0);
    try testing.expect(table.get(&ask("a.example"), 0) != null);
    table.put(&ask("b.example"), &answers, null, .unchecked, 0);
    try testing.expectEqual(@as(usize, 1), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) == null);
    try testing.expect(table.get(&ask("b.example"), 0) != null);
}

test "a slot count read at run time sizes a cache over part of a larger memory" {
    var memory: Storage(8) = .{};
    // What a configuration file might say: a variable, so nothing here is known at compile time.
    var slot_count: usize = 3;
    _ = &slot_count;
    try testing.expect(slot_count_valid(slot_count));
    const sized: Slices = .{ .slots = memory.slots[0..slot_count], .keys = memory.keys[0..keys_for(slot_count)] };
    try testing.expect(sized.valid());
    var table = cache.Cache.init(sized.slots, sized.keys, fixtures.seed, constants.ttl_seconds_max_default);
    const answers = fixtures.answers_v4(1, 300);
    for ([_][]const u8{ "a.example", "b.example", "c.example", "d.example" }) |name| {
        table.put(&ask(name), &answers, null, .unchecked, 0);
    }
    // Four names went into three slots: the cache holds the count it was sized for.
    try testing.expectEqual(slot_count, table.len());
}
