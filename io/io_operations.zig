//! The engine's operations in flight (docs/design.md §26 step 4.1). Each operation that the engine
//! submits takes an `OperationId` from this table, and keeps it until its final event. The table
//! records what each operation is for, so an event names its handler by its id alone. Each place
//! of the engine has one slot, so an id's slot names its place (§26, one operation for each
//! place).
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const OperationId = @import("io_interface.zig").OperationId;
const Kind = @import("io.zig").Kind;

/// What an operation is for: the handler of its events, and the index that the handler reads.
pub const Origin = struct { kind: Kind, index: u64 };

/// A table of `places` operations in flight at most: one at each place, in the place's own slot.
pub fn Table(comptime places: u32) type {
    comptime assert(places >= 1);
    comptime assert(places <= constants.operation_slot_mask + 1);
    return struct {
        const Self = @This();

        origins: [places]Origin,
        /// The generation of each slot's next id.
        generations: [places]u8,
        held: [places]bool,
        held_count: u32,

        /// Every slot free. Only `init` calls it, when no operation of the engine is in flight.
        pub fn reset(self: *Self) void {
            self.generations = @splat(0);
            self.held = @splat(false);
            self.held_count = 0;
        }

        /// The id of one more operation, at `place`. The place holds no other: the engine asks
        /// `busy` before it submits where a cancelled operation can still be in flight.
        pub fn take(self: *Self, place: u32, origin: Origin) OperationId {
            assert(place < places);
            assert(!self.held[place]);
            assert(self.held_count < places);
            self.held[place] = true;
            self.held_count += 1;
            self.origins[place] = origin;
            return .of(place, self.generations[place]);
        }

        /// Whether an operation at `place` is in flight, current or cancelled: the place is taken
        /// until that operation's final event.
        pub fn busy(self: *const Self, place: u32) bool {
            assert(place < places);
            return self.held[place];
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
            if (slot >= places) return false;
            return self.held[slot] and self.generations[slot] == id.generation();
        }

        /// The operation had its final event. Its slot is free, and the slot's next id differs.
        pub fn release(self: *Self, id: OperationId) void {
            assert(self.holds(id));
            const slot = id.slot();
            self.held[slot] = false;
            self.generations[slot] +%= 1;
            assert(self.held_count > 0);
            self.held_count -= 1;
        }

        pub fn in_flight(self: *const Self) u32 {
            assert(self.held_count <= places);
            return self.held_count;
        }

        /// The id of the operation in flight at `place` for `origin`, or null for none. A test
        /// reads it to build an event, because the engine keeps no id of a send.
        pub fn find(self: *const Self, place: u32, origin: Origin) ?OperationId {
            if (!self.busy(place) or !std.meta.eql(self.origins[place], origin)) return null;
            return .of(place, self.generations[place]);
        }
    };
}

/// What `submit` gave: the operation's id, and the loop's handle, which a cancel names.
pub const Submitted = struct { id: OperationId, handle: rotor.Handle };

/// Whether the place of `origin` holds an operation in flight. A place whose cancelled operation
/// is still in flight waits for that operation's final event before it submits again.
pub fn busy(self: anytype, origin: Origin) bool {
    return self.operations.busy(@TypeOf(self.*).place_of(origin));
}

/// The id of the operation in flight for `origin`, or null for none.
pub fn find(self: anytype, origin: Origin) ?OperationId {
    return self.operations.find(@TypeOf(self.*).place_of(origin), origin);
}

/// Submits `operation` for `origin`, under an id of the engine's table, at the place of `origin`,
/// which must be free. Null when the loop refused it, and then the table holds no id for it.
pub fn submit(self: anytype, origin: Origin, operation: rotor.Operation) ?Submitted {
    const id = self.operations.take(@TypeOf(self.*).place_of(origin), origin);
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

test "a table gives each place its slot, and a freed place a new id" {
    const places = 3;
    var table: Table(places) = undefined;
    table.reset();
    var ids: [places]OperationId = undefined;
    for (&ids, 0..) |*id, place| {
        try testing.expect(!table.busy(@intCast(place)));
        id.* = table.take(@intCast(place), .{ .kind = .udp_send, .index = place });
        try testing.expectEqual(@as(u32, @intCast(place)), id.slot());
        try testing.expectEqual(@as(u64, place), table.origin_of(id.*).index);
        try testing.expect(table.busy(@intCast(place)));
    }
    try testing.expectEqual(@as(u32, places), table.in_flight());
    table.release(ids[1]);
    try testing.expect(!table.holds(ids[1]));
    try testing.expect(!table.busy(1));
    try testing.expectEqual(@as(u32, places - 1), table.in_flight());
    const again = table.take(1, .{ .kind = .timer, .index = 0 });
    try testing.expectEqual(ids[1].slot(), again.slot());
    try testing.expect(again != ids[1]);
    try testing.expect(table.holds(again));
    // The place is held again, and the id of its earlier generation is still not the table's.
    try testing.expect(!table.holds(ids[1]));
    try testing.expectEqual(again, table.find(1, .{ .kind = .timer, .index = 0 }).?);
    try testing.expectEqual(@as(?OperationId, null), table.find(1, .{ .kind = .udp_send, .index = 1 }));
}

test "a slot's generation wraps, and the id after the wrap is the first id again" {
    var table: Table(1) = undefined;
    table.reset();
    const first = table.take(0, .{ .kind = .timer, .index = 0 });
    table.release(first);
    for (0..std.math.maxInt(u8)) |_| table.release(table.take(0, .{ .kind = .timer, .index = 0 }));
    try testing.expectEqual(first, table.take(0, .{ .kind = .timer, .index = 0 }));
}
