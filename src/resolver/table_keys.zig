//! The side table that turns a transaction id into candidate slots (docs/design.md §11).
//!
//! Four octets an entry, sixteen to a cache line, open addressing with linear probing. The id is
//! drawn from a generator, so it is uniform and the low bits index well without hashing.
//!
//! Two things the probe must get right. A removed entry becomes a tombstone rather than an empty
//! one, because a later entry in the same chain may still hold the id being looked for. And an id
//! may name several slots — a thousand lookups over sixteen bits of id will collide — so a lookup
//! walks the whole chain and offers the datagram to every candidate, rather than assuming the
//! first is the only one.
const std = @import("std");
const assert = std.debug.assert;

/// An entry's slot field when the entry has never been used. A slot index cannot reach this,
/// because `lookup_slots_max` is far below it.
pub const slot_empty: u16 = 0xffff;

/// An entry whose lookup has gone. The probe walks past it.
pub const slot_tombstone: u16 = 0xfffe;

/// One entry: four octets.
pub const MatchKey = packed struct(u32) {
    transaction_id: u16 = 0,
    slot: u16 = slot_empty,
};

/// Where a probe for `id` starts.
pub fn start_index(keys: []const MatchKey, id: u16) usize {
    assert(std.math.isPowerOfTwo(keys.len));
    return @as(usize, id) & (keys.len - 1);
}

/// The next index in the chain.
pub fn next_index(keys: []const MatchKey, index: usize) usize {
    assert(index < keys.len);
    return (index + 1) & (keys.len - 1);
}

/// Adds an entry for `id` naming `slot`, at the first empty or tombstoned place in its chain.
pub fn insert(keys: []MatchKey, id: u16, slot: u16) void {
    assert(slot < slot_tombstone);
    var index = start_index(keys, id);
    var probe: usize = 0;
    while (probe < keys.len) : (probe += 1) {
        const key = &keys[index];
        if (key.slot == slot_empty or key.slot == slot_tombstone) {
            key.* = .{ .transaction_id = id, .slot = slot };
            return;
        }
        index = next_index(keys, index);
    }
    // The table holds at least two entries per slot and a slot holds one entry at a time, so a
    // full table cannot happen.
    unreachable;
}

/// Tombstones the entry for `id` naming `slot`, if it is there.
pub fn remove(keys: []MatchKey, id: u16, slot: u16) void {
    assert(slot < slot_tombstone);
    var index = start_index(keys, id);
    var probe: usize = 0;
    while (probe < keys.len) : (probe += 1) {
        const key = &keys[index];
        if (key.slot == slot_empty) return;
        if (key.slot == slot and key.transaction_id == id) {
            key.* = .{ .slot = slot_tombstone };
            return;
        }
        index = next_index(keys, index);
    }
}

/// A walk over every slot whose entry holds `id`.
pub const Candidates = struct {
    keys: []const MatchKey,
    id: u16,
    index: usize,
    probe: usize = 0,

    pub fn init(keys: []const MatchKey, id: u16) Candidates {
        return .{ .keys = keys, .id = id, .index = start_index(keys, id) };
    }

    /// The next slot to offer a datagram to, or null when the chain ends.
    pub fn next(self: *Candidates) ?u16 {
        while (self.probe < self.keys.len) {
            const key = self.keys[self.index];
            self.probe += 1;
            const at = self.index;
            self.index = next_index(self.keys, at);
            // An empty entry ends the chain; a tombstone does not, because a later entry may hold
            // the id.
            if (key.slot == slot_empty) return null;
            if (key.slot != slot_tombstone and key.transaction_id == self.id) return key.slot;
        }
        return null;
    }
};

// Tests.

const testing = std.testing;

const key_count = 8;

fn empty_keys() [key_count]MatchKey {
    return @splat(.{});
}

fn collect(keys: []const MatchKey, id: u16, out: []u16) []const u16 {
    var walk = Candidates.init(keys, id);
    var count: usize = 0;
    while (walk.next()) |slot| {
        out[count] = slot;
        count += 1;
    }
    return out[0..count];
}

test "an entry is found by its id" {
    var keys = empty_keys();
    insert(&keys, 0x1234, 3);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{3}, collect(&keys, 0x1234, &found));
    try testing.expectEqualSlices(u16, &.{}, collect(&keys, 0x1235, &found));
}

test "two slots sharing an id are both candidates, in insertion order" {
    var keys = empty_keys();
    insert(&keys, 0x1234, 1);
    insert(&keys, 0x1234, 2);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{ 1, 2 }, collect(&keys, 0x1234, &found));
}

test "a tombstone does not end the chain" {
    var keys = empty_keys();
    insert(&keys, 0x1234, 1);
    insert(&keys, 0x1234, 2);
    remove(&keys, 0x1234, 1);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{2}, collect(&keys, 0x1234, &found));
}

test "an insert reuses a tombstone rather than growing the chain" {
    var keys = empty_keys();
    insert(&keys, 0x1234, 1);
    remove(&keys, 0x1234, 1);
    insert(&keys, 0x1234, 5);
    var used: usize = 0;
    for (keys) |key| {
        if (key.slot != slot_empty) used += 1;
    }
    try testing.expectEqual(@as(usize, 1), used);
}

test "ids that land on the same index do not shadow each other" {
    var keys = empty_keys();
    // Both ids mask to index 1 in a table of eight.
    insert(&keys, 0x0001, 1);
    insert(&keys, 0x0009, 2);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{1}, collect(&keys, 0x0001, &found));
    try testing.expectEqualSlices(u16, &.{2}, collect(&keys, 0x0009, &found));
}

test "removing an entry that is not there changes nothing" {
    var keys = empty_keys();
    insert(&keys, 0x1234, 1);
    remove(&keys, 0x1234, 2);
    remove(&keys, 0x9999, 1);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{1}, collect(&keys, 0x1234, &found));
}

test "a chain of tombstones is walked through, not stopped at" {
    var keys = empty_keys();
    var slot: u16 = 0;
    while (slot < 4) : (slot += 1) insert(&keys, 0x1234, slot);
    slot = 0;
    while (slot < 3) : (slot += 1) remove(&keys, 0x1234, slot);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{3}, collect(&keys, 0x1234, &found));
}
