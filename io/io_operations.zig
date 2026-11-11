//! The engine's operations in flight (docs/design.md §26 step 4.1). Each operation that the engine
//! submits takes an `OperationId` from this table, and keeps it until its final event. The table
//! records what each operation is for, so an event names its handler by its id alone.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const OperationId = @import("io_interface.zig").OperationId;
const Kind = @import("io.zig").Kind;

/// What an operation is for: the handler of its events, and the index that the handler reads.
pub const Origin = struct { kind: Kind, index: u64 };

/// A table of `capacity` operations in flight at most.
pub fn Table(comptime capacity: u32) type {
    comptime assert(capacity >= 1);
    comptime assert(capacity <= constants.operation_slot_mask + 1);
    return struct {
        const Self = @This();

        origins: [capacity]Origin,
        /// The generation of each slot's next id.
        generations: [capacity]u8,
        held: [capacity]bool,
        /// The free slots, as a stack: `take` pops the last.
        free: [capacity]u32,
        free_count: u32,

        /// Every slot free. Only `init` calls it, when no operation of the engine is in flight.
        pub fn reset(self: *Self) void {
            self.generations = @splat(0);
            self.held = @splat(false);
            for (&self.free, 0..) |*slot, index| slot.* = @intCast(capacity - 1 - index);
            self.free_count = capacity;
        }

        /// An id for one more operation, or null when `capacity` operations are in flight.
        pub fn take(self: *Self, origin: Origin) ?OperationId {
            if (self.free_count == 0) return null;
            self.free_count -= 1;
            const slot = self.free[self.free_count];
            assert(!self.held[slot]);
            self.held[slot] = true;
            self.origins[slot] = origin;
            return .of(slot, self.generations[slot]);
        }

        /// What an operation in flight is for. An id that the table does not hold is a halt
        /// (docs/design.md §26, the rules that bind a host, rule 5).
        pub fn origin_of(self: *const Self, id: OperationId) Origin {
            assert(self.holds(id));
            return self.origins[id.slot()];
        }

        /// Whether `id` names an operation in flight.
        pub fn holds(self: *const Self, id: OperationId) bool {
            const slot = id.slot();
            if (slot >= capacity) return false;
            return self.held[slot] and self.generations[slot] == id.generation();
        }

        /// The operation had its final event. Its slot is free, and the slot's next id differs.
        pub fn release(self: *Self, id: OperationId) void {
            assert(self.holds(id));
            const slot = id.slot();
            self.held[slot] = false;
            self.generations[slot] +%= 1;
            assert(self.free_count < capacity);
            self.free[self.free_count] = slot;
            self.free_count += 1;
        }

        pub fn in_flight(self: *const Self) u32 {
            assert(self.free_count <= capacity);
            return capacity - self.free_count;
        }

        /// The id of the one operation in flight for `origin`, or null for none. A test reads it
        /// to build an event, because the engine keeps no id of a send.
        pub fn find(self: *const Self, origin: Origin) ?OperationId {
            var found: ?OperationId = null;
            for (self.origins, self.held, self.generations, 0..) |held_origin, held, generation, slot| {
                if (!held or !std.meta.eql(held_origin, origin)) continue;
                assert(found == null);
                found = .of(@intCast(slot), generation);
            }
            return found;
        }
    };
}

/// What `submit` gave: the operation's id, and the loop's handle, which a cancel names.
pub const Submitted = struct { id: OperationId, handle: rotor.Handle };

/// Submits `operation` for `origin`, under an id of the engine's table. Null when the table or the
/// loop refused it, and then the table holds no id for it.
pub fn submit(self: anytype, origin: Origin, operation: rotor.Operation) ?Submitted {
    const id = self.operations.take(origin) orelse return null;
    var tagged = operation;
    tagged.user_data = @TypeOf(self.*).user_data(id);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{tagged}, &handles) != 1) {
        self.operations.release(id);
        return null;
    }
    return .{ .id = id, .handle = handles[0] };
}

const testing = std.testing;

test "a table gives each slot once, refuses one more, and gives a freed slot a new id" {
    const capacity = 3;
    var table: Table(capacity) = undefined;
    table.reset();
    var ids: [capacity]OperationId = undefined;
    for (&ids, 0..) |*id, index| {
        id.* = table.take(.{ .kind = .udp_send, .index = index }).?;
        try testing.expectEqual(@as(u64, index), table.origin_of(id.*).index);
    }
    try testing.expectEqual(@as(u32, capacity), table.in_flight());
    try testing.expectEqual(@as(?OperationId, null), table.take(.{ .kind = .timer, .index = 0 }));
    table.release(ids[1]);
    try testing.expect(!table.holds(ids[1]));
    const again = table.take(.{ .kind = .timer, .index = 0 }).?;
    try testing.expectEqual(ids[1].slot(), again.slot());
    try testing.expect(again != ids[1]);
    try testing.expect(table.holds(again));
    // The slot is held again, and the id of its earlier generation is still not the table's.
    try testing.expect(!table.holds(ids[1]));
    try testing.expectEqual(again, table.find(.{ .kind = .timer, .index = 0 }).?);
}

test "a slot's generation wraps, and the id after the wrap is the first id again" {
    var table: Table(1) = undefined;
    table.reset();
    const first = table.take(.{ .kind = .timer, .index = 0 }).?;
    table.release(first);
    for (0..std.math.maxInt(u8)) |_| table.release(table.take(.{ .kind = .timer, .index = 0 }).?);
    try testing.expectEqual(first, table.take(.{ .kind = .timer, .index = 0 }).?);
}
