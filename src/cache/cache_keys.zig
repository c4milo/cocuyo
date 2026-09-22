//! The key index of the cache: a hash to the slots that may hold it (docs/design.md §18).
//!
//! Eight octets an entry, open addressing, linear probing, and a bounded probe. A hash may name
//! several slots — thirty-two bits over a few thousand names will collide now and then — so a
//! lookup walks every candidate and the cache checks the name at each; and the walk is bounded by
//! `probe_max`, so a run of collisions costs a miss, never more work. A removed entry becomes a
//! tombstone the walk steps over and an insert reuses, as `resolver/table_keys.zig` does with its
//! ids.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// One entry: the hash, the slot, and whether the entry is empty, live, or a tombstone.
pub const Key = packed struct(u64) {
    hash: u32 = 0,
    slot: u16 = 0,
    state: State = .empty,

    pub const State = enum(u16) { empty, live, tombstone };
};

pub fn start_index(keys: []const Key, hash: u32) usize {
    assert(std.math.isPowerOfTwo(keys.len));
    return @as(usize, hash) & (keys.len - 1);
}

pub fn next_index(keys: []const Key, index: usize) usize {
    assert(index < keys.len);
    return (index + 1) & (keys.len - 1);
}

/// Adds an entry for `hash` naming `slot` at the first empty or tombstoned place within the
/// probe bound, or refuses.
pub fn insert(keys: []Key, hash: u32, slot: u16) error{Full}!void {
    var index = start_index(keys, hash);
    var probe: usize = 0;
    while (probe < constants.probe_max) : (probe += 1) {
        const key = &keys[index];
        if (key.state != .live) {
            key.* = .{ .hash = hash, .slot = slot, .state = .live };
            return;
        }
        index = next_index(keys, index);
    }
    assert(probe == constants.probe_max);
    return error.Full;
}

/// Tombstones the entry for `hash` naming `slot`, if it is within the probe bound.
pub fn remove(keys: []Key, hash: u32, slot: u16) void {
    var index = start_index(keys, hash);
    var probe: usize = 0;
    while (probe < constants.probe_max) : (probe += 1) {
        const key = &keys[index];
        if (key.state == .empty) return;
        if (key.state == .live and key.hash == hash and key.slot == slot) {
            key.* = .{ .state = .tombstone };
            return;
        }
        index = next_index(keys, index);
    }
}

/// A walk over every slot whose entry holds `hash`, within the probe bound.
pub const Candidates = struct {
    keys: []const Key,
    hash: u32,
    index: usize,
    probe: usize = 0,

    pub fn init(keys: []const Key, hash: u32) Candidates {
        return .{ .keys = keys, .hash = hash, .index = start_index(keys, hash) };
    }

    pub fn next(self: *Candidates) ?u16 {
        while (self.probe < constants.probe_max) {
            const key = self.keys[self.index];
            self.probe += 1;
            self.index = next_index(self.keys, self.index);
            if (key.state == .empty) return null;
            if (key.state == .live and key.hash == self.hash) return key.slot;
        }
        assert(self.probe == constants.probe_max);
        return null;
    }
};

// Tests.

const testing = std.testing;

const key_count = 64;

fn collect(keys: []const Key, hash: u32, out: []u16) []const u16 {
    var walk = Candidates.init(keys, hash);
    var count: usize = 0;
    while (walk.next()) |slot| {
        out[count] = slot;
        count += 1;
    }
    return out[0..count];
}

test "an entry is found by its hash, and a tombstone does not end the chain" {
    var keys: [key_count]Key = @splat(.{});
    try insert(&keys, 0x1234, 1);
    try insert(&keys, 0x1234, 2);
    remove(&keys, 0x1234, 1);
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{2}, collect(&keys, 0x1234, &found));
    try testing.expectEqualSlices(u16, &.{}, collect(&keys, 0x1235, &found));
    // A miss on a chain of one stops at the empty entry after it, not at the probe bound.
    var walk = Candidates.init(&keys, 0x1236);
    try testing.expectEqual(@as(?u16, null), walk.next());
    try testing.expectEqual(@as(usize, 1), walk.probe);
}

test "a chain longer than the probe bound is a miss and a refusal, not a walk" {
    // Every hash here lands on index zero: the low bits are the same, the high bits differ.
    var keys: [key_count]Key = @splat(.{});
    var count: u32 = 0;
    while (count < constants.probe_max) : (count += 1) {
        try insert(&keys, count << 16, @intCast(count));
    }
    try testing.expectError(error.Full, insert(&keys, constants.probe_max << 16, 99));
    // The sixteenth entry is inside the bound and found; a seventeenth would not be.
    var found: [key_count]u16 = undefined;
    try testing.expectEqualSlices(u16, &.{constants.probe_max - 1}, collect(&keys, (constants.probe_max - 1) << 16, &found));
    var walk = Candidates.init(&keys, constants.probe_max << 16);
    try testing.expectEqual(@as(?u16, null), walk.next());
    try testing.expectEqual(@as(usize, constants.probe_max), walk.probe);
}

test "an insert reuses a tombstone rather than lengthening the chain" {
    var keys: [key_count]Key = @splat(.{});
    try insert(&keys, 7, 1);
    remove(&keys, 7, 1);
    try insert(&keys, 7, 2);
    const first = keys[start_index(&keys, 7)];
    try testing.expectEqual(Key.State.live, first.state);
    try testing.expectEqual(@as(u16, 2), first.slot);
    var live: usize = 0;
    for (keys) |key| {
        if (key.state == .live) live += 1;
    }
    try testing.expectEqual(@as(usize, 1), live);
}
