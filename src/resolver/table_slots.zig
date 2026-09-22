//! The slots of a table: the storage a caller provides, the free list over it, and the handles
//! that name one (docs/design.md §4).
//!
//! A handle carries a generation as well as an index, so a handle kept past its slot's release is
//! detectable rather than a handle to whoever took the slot next. Using one is a programmer error
//! and asserts (CLAUDE.md non-negotiable 3): a caller that has read an answer and freed the slot
//! has no business asking about it again, and silently answering about a different lookup would be
//! worse than halting.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;

/// The end of the free list. A slot index cannot reach it: `lookup_slots_max` is far below.
pub const slot_none: u16 = 0xffff;

/// A lookup's name.
pub const Handle = packed struct(u32) {
    index: u16,
    generation: u16,
};

/// One slot.
pub const Slot = struct {
    /// Valid only while `occupied`. A free slot's lookup is never read.
    lookup: Lookup = undefined,
    generation: u16 = 0,
    occupied: bool = false,
    /// The id the key table currently holds for this slot, so a lookup that drew a new
    /// transaction can be re-keyed without the table having to be told.
    keyed_id: u16 = 0,
    next_free: u16 = slot_none,
};

/// The caller's slot array with a free list threaded through it. The link lives in the slot
/// itself, so the free list costs no memory of its own.
pub const Slots = struct {
    items: []Slot,
    free_head: u16,

    pub fn init(items: []Slot) Slots {
        assert(items.len >= 1);
        assert(items.len <= core.constants.lookup_slots_max);
        for (items, 0..) |*slot, index| {
            slot.* = .{
                .next_free = if (index + 1 == items.len) slot_none else @intCast(index + 1),
            };
        }
        return .{ .items = items, .free_head = 0 };
    }

    /// Takes a free slot, or null when the table is full.
    pub fn acquire(self: *Slots) ?u16 {
        if (self.free_head == slot_none) return null;
        const index = self.free_head;
        const slot = &self.items[index];
        assert(!slot.occupied);
        self.free_head = slot.next_free;
        slot.occupied = true;
        slot.next_free = slot_none;
        return index;
    }

    /// Frees a slot and moves its generation on, which invalidates every handle to it.
    pub fn release(self: *Slots, index: u16) void {
        assert(index < self.items.len);
        const slot = &self.items[index];
        assert(slot.occupied);
        slot.occupied = false;
        slot.generation +%= 1;
        slot.next_free = self.free_head;
        self.free_head = index;
    }

    /// The slot a handle names.
    pub fn get(self: *Slots, handle: Handle) *Slot {
        assert(handle.index < self.items.len);
        const slot = &self.items[handle.index];
        assert(slot.occupied);
        assert(slot.generation == handle.generation);
        return slot;
    }

    pub fn handle_of(self: *const Slots, index: u16) Handle {
        assert(index < self.items.len);
        assert(self.items[index].occupied);
        return .{ .index = index, .generation = self.items[index].generation };
    }

    pub fn occupied_count(self: *const Slots) usize {
        var count: usize = 0;
        for (self.items) |*slot| {
            if (slot.occupied) count += 1;
        }
        assert(count <= self.items.len);
        return count;
    }
};

// Tests.

const testing = std.testing;

test "every slot is handed out once, and then the table is full" {
    var items: [3]Slot = @splat(.{});
    var slots = Slots.init(&items);
    try testing.expectEqual(@as(?u16, 0), slots.acquire());
    try testing.expectEqual(@as(?u16, 1), slots.acquire());
    try testing.expectEqual(@as(?u16, 2), slots.acquire());
    try testing.expectEqual(@as(?u16, null), slots.acquire());
    try testing.expectEqual(@as(usize, 3), slots.occupied_count());
}

test "a freed slot is handed out again, with a new generation" {
    var items: [2]Slot = @splat(.{});
    var slots = Slots.init(&items);
    const first = slots.acquire().?;
    const before = slots.handle_of(first);
    slots.release(first);
    try testing.expectEqual(@as(usize, 0), slots.occupied_count());
    const again = slots.acquire().?;
    try testing.expectEqual(first, again);
    const after = slots.handle_of(again);
    try testing.expectEqual(before.index, after.index);
    try testing.expect(before.generation != after.generation);
}

test "the free list survives releases in any order" {
    var items: [4]Slot = @splat(.{});
    var slots = Slots.init(&items);
    var taken: [4]u16 = undefined;
    for (&taken) |*index| index.* = slots.acquire().?;
    slots.release(taken[1]);
    slots.release(taken[3]);
    slots.release(taken[0]);
    try testing.expectEqual(@as(usize, 1), slots.occupied_count());
    var count: usize = 0;
    while (slots.acquire() != null) count += 1;
    try testing.expectEqual(@as(usize, 3), count);
    try testing.expectEqual(@as(usize, 4), slots.occupied_count());
}

test "a handle names the slot it was taken from" {
    var items: [2]Slot = @splat(.{});
    var slots = Slots.init(&items);
    const index = slots.acquire().?;
    const handle = slots.handle_of(index);
    slots.get(handle).keyed_id = 0x1234;
    try testing.expectEqual(@as(u16, 0x1234), items[index].keyed_id);
}

test "the size of a slot is pinned" {
    // docs/design.md §9: a caller sizing a table needs this number, and it is a lookup plus the
    // few octets the table keeps beside it.
    try testing.expectEqual(@as(usize, 864), @sizeOf(Slot));
    try testing.expectEqual(@as(usize, 4), @sizeOf(Handle));
}
