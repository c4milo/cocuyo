//! The engine's interface to a host (docs/design.md §26, The public API). Each type here is a
//! value, so the engine holds no pointer of the host and the host calls the engine. The types
//! come in the sub-steps of §26 step 4, and the engine's module exports them at step 5.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Names one operation in flight, in the low 32 bits of a host's tag: a slot of the engine's table
/// of operations, and above it a generation byte. The byte changes each time that the slot frees,
/// so an id that the engine no longer holds differs from the next id of its slot.
pub const OperationId = enum(u32) {
    _,

    pub fn of(slot_index: u32, generation_byte: u8) OperationId {
        assert(slot_index <= constants.operation_slot_mask);
        return @enumFromInt((@as(u32, generation_byte) << constants.operation_generation_shift) | slot_index);
    }

    pub fn slot(id: OperationId) u32 {
        return @intFromEnum(id) & constants.operation_slot_mask;
    }

    pub fn generation(id: OperationId) u8 {
        return @truncate(@intFromEnum(id) >> constants.operation_generation_shift);
    }
};

const testing = std.testing;

test "an id keeps its slot and its generation apart, at each end of the two" {
    const slots = [_]u32{ 0, 1, constants.operation_slot_mask };
    const generations = [_]u8{ 0, 1, std.math.maxInt(u8) };
    for (slots) |slot| {
        for (generations) |generation| {
            const id: OperationId = .of(slot, generation);
            try testing.expectEqual(slot, id.slot());
            try testing.expectEqual(generation, id.generation());
        }
    }
}
