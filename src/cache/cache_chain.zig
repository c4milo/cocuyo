//! The insertion order of the cache's entries, oldest to newest, threaded through the slots
//! themselves: what the SIEVE hand walks (docs/design.md §18).
//!
//! A slot links to its older and its newer neighbour by index, so the chain costs no memory of
//! its own and no slot ever moves. A hit sets a bit; only an insert or an eviction touches a link.
//! The chain is generic over the slot type so that it can be tested on a struct of two links
//! without the cache's own slot, which is 500 octets of things the chain never reads.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// No slot: the end of the chain, the end of the free list, and a hand that has nowhere to be.
pub const none: u16 = 0xffff;

/// The links every slot carries.
pub const Links = struct {
    older: u16 = none,
    newer: u16 = none,
};

/// The order over a slice of `Slot`, each of which carries a `links: Links` field.
pub fn Chain(comptime Slot: type) type {
    return struct {
        const Self = @This();

        oldest: u16 = none,
        newest: u16 = none,
        len: u16 = 0,

        /// Puts `index` at the newest end.
        pub fn link_newest(self: *Self, slots: []Slot, index: u16) void {
            assert(index < slots.len);
            assert(self.len < slots.len);
            slots[index].links = .{ .older = self.newest, .newer = none };
            if (self.newest == none) {
                assert(self.oldest == none);
                self.oldest = index;
            } else {
                slots[self.newest].links.newer = index;
            }
            self.newest = index;
            self.len += 1;
        }

        /// Takes `index` out of the order, wherever it is.
        pub fn unlink(self: *Self, slots: []Slot, index: u16) void {
            assert(index < slots.len);
            assert(self.len >= 1);
            const links = slots[index].links;
            if (links.older == none) {
                self.oldest = links.newer;
            } else {
                slots[links.older].links.newer = links.newer;
            }
            if (links.newer == none) {
                self.newest = links.older;
            } else {
                slots[links.newer].links.older = links.older;
            }
            slots[index].links = .{};
            self.len -= 1;
            assert((self.len == 0) == (self.oldest == none));
        }

        /// The slot after `index` toward the newest, wrapping to the oldest at the end: the hand's
        /// direction.
        pub fn after(self: *const Self, slots: []const Slot, index: u16) u16 {
            assert(index < slots.len);
            const newer = slots[index].links.newer;
            return if (newer == none) self.oldest else newer;
        }
    };
}

// Tests.

const testing = std.testing;

const TestSlot = struct { links: Links = .{} };
const TestChain = Chain(TestSlot);

test "the chain keeps insertion order, oldest to newest" {
    var slots: [4]TestSlot = @splat(.{});
    var chain: TestChain = .{};
    chain.link_newest(&slots, 2);
    chain.link_newest(&slots, 0);
    chain.link_newest(&slots, 3);
    try testing.expectEqual(@as(u16, 2), chain.oldest);
    try testing.expectEqual(@as(u16, 3), chain.newest);
    try testing.expectEqual(@as(u16, 0), chain.after(&slots, 2));
    try testing.expectEqual(@as(u16, 3), chain.after(&slots, 0));
    try testing.expectEqual(@as(u16, 2), chain.after(&slots, 3));
    try testing.expectEqual(@as(u16, 3), chain.len);
}

test "unlinking the oldest, the newest and a middle entry leaves the order intact" {
    var slots: [4]TestSlot = @splat(.{});
    var chain: TestChain = .{};
    for ([_]u16{ 0, 1, 2, 3 }) |index| chain.link_newest(&slots, index);
    chain.unlink(&slots, 0);
    try testing.expectEqual(@as(u16, 1), chain.oldest);
    chain.unlink(&slots, 3);
    try testing.expectEqual(@as(u16, 2), chain.newest);
    chain.unlink(&slots, 1);
    try testing.expectEqual(@as(u16, 2), chain.oldest);
    try testing.expectEqual(@as(u16, 2), chain.newest);
    try testing.expectEqual(@as(u16, 2), chain.after(&slots, 2));
    chain.unlink(&slots, 2);
    try testing.expectEqual(none, chain.oldest);
    try testing.expectEqual(none, chain.newest);
    try testing.expectEqual(@as(u16, 0), chain.len);
}

test "the bound on the chain's length is the slot count, below the sentinel" {
    try testing.expect(constants.slots_max < none);
}
