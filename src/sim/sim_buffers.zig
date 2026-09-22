//! Buffer groups, as rotor provides them (`provide_datagram_buffers`, `provided_buffer`,
//! `give_back_buffer`): a caller's memory cut into buffers of one size, a free list, and rotor's
//! prefix before each payload so `datagram` reads the same layout on both.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const types = @import("sim_types.zig");

pub const ProvideError = error{ SystemResources, Unexpected };
pub const RegisterError = error{ SystemResources, Unexpected };

pub const ring_alignment = constants.buffer_ring_alignment;

/// The octets a ring of `count` buffers takes, as rotor sizes it, so a caller's array serves
/// both.
pub fn ring_bytes(count: u16) usize {
    assert(count >= 1);
    assert(std.math.isPowerOfTwo(count));
    return @as(usize, count) * constants.buffer_ring_entry_bytes;
}

pub const Group = struct {
    buffers: []u8,
    buffer_bytes: u32,
    count: u16,
    /// Which buffers are free: a bit per buffer, set when free.
    free: [constants.buffers_per_group_max]bool,
    free_count: u16,

    pub const none: Group = .{
        .buffers = &.{},
        .buffer_bytes = 0,
        .count = 0,
        .free = @splat(false),
        .free_count = 0,
    };

    pub fn init(memory: []u8, buffer_bytes: u32) Group {
        assert(buffer_bytes >= 1);
        const count: usize = memory.len / buffer_bytes;
        assert(count >= 1);
        assert(count <= constants.buffers_per_group_max);
        var group: Group = .{
            .buffers = memory,
            .buffer_bytes = buffer_bytes,
            .count = @intCast(count),
            .free = @splat(false),
            .free_count = @intCast(count),
        };
        for (group.free[0..count]) |*flag| flag.* = true;
        return group;
    }

    pub fn bytes_of(group: *const Group, buffer_id: u16) []u8 {
        assert(buffer_id < group.count);
        const start: usize = @as(usize, buffer_id) * group.buffer_bytes;
        return group.buffers[start..][0..group.buffer_bytes];
    }

    /// The lowest free buffer, taken; null when none is. The lowest, so a run replays the same
    /// ids from the same seed.
    pub fn take(group: *Group) ?u16 {
        for (group.free[0..group.count], 0..) |*flag, index| {
            if (!flag.*) continue;
            flag.* = false;
            group.free_count -= 1;
            return @intCast(index);
        }
        assert(group.free_count == 0);
        return null;
    }

    pub fn give_back(group: *Group, buffer_id: u16) void {
        assert(buffer_id < group.count);
        assert(!group.free[buffer_id]);
        group.free[buffer_id] = true;
        group.free_count += 1;
        assert(group.free_count <= group.count);
    }
};

/// Writes a datagram into `buffer` the way rotor lays one out: the head, the peer address at
/// the start of the name reserve, and the payload after the prefix. Returns the payload length.
pub fn write_delivery(
    buffer: []u8,
    options: types.GroupOptions,
    peer: *const types.Address,
    payload: []const u8,
) u32 {
    const prefix = types.prefix_bytes(options);
    assert(buffer.len >= prefix + payload.len);
    @memset(buffer[0..prefix], 0);
    const received: *types.Received = @ptrCast(@alignCast(buffer[constants.prefix_head_bytes..][0..types.metadata_bytes]));
    received.* = .{
        .peer = peer.*,
        .local = peer.*,
        .segment_bytes = 0,
        .ecn = .not_ect,
        .flags = .{},
    };
    @memcpy(buffer[prefix..][0..payload.len], payload);
    return @intCast(payload.len);
}

/// The delivery rotor's `datagram` returns: the metadata written by `write_delivery` and the
/// payload after the prefix.
pub fn read_delivery(buffer: []u8, payload_bytes: u32, options: types.GroupOptions) types.Delivery {
    const prefix = types.prefix_bytes(options);
    assert(buffer.len >= prefix + payload_bytes);
    const received: *const types.Received = @ptrCast(@alignCast(buffer[constants.prefix_head_bytes..][0..types.metadata_bytes]));
    return .{ .from = received.*, .bytes = buffer[prefix..][0..payload_bytes] };
}

comptime {
    // The metadata sits at the start of the name reserve, which rotor keeps at least an address
    // wide and aligned for it; the head before it is a multiple of the alignment.
    assert(constants.prefix_head_bytes % @alignOf(types.Received) == 0);
    assert(constants.name_reserve_default + constants.control_reserve_default >= types.metadata_bytes);
}

// Tests.

const testing = std.testing;

test "a group hands out its lowest free buffer and takes it back" {
    var memory: [4 * 256]u8 = undefined;
    var group = Group.init(&memory, 256);
    try testing.expectEqual(@as(u16, 4), group.count);
    try testing.expectEqual(@as(?u16, 0), group.take());
    try testing.expectEqual(@as(?u16, 1), group.take());
    group.give_back(0);
    try testing.expectEqual(@as(?u16, 0), group.take());
    try testing.expectEqual(@as(?u16, 2), group.take());
    try testing.expectEqual(@as(?u16, 3), group.take());
    try testing.expectEqual(@as(?u16, null), group.take());
    try testing.expectEqual(@as(usize, 256), group.bytes_of(3).len);
}

test "a delivery written into a buffer reads back with its peer and its payload" {
    var buffer: [512]u8 align(ring_alignment) = undefined;
    const peer = types.Address.ipv4(.{ 192, 0, 2, 53 }, 53);
    const written = write_delivery(&buffer, .{}, &peer, "hello");
    try testing.expectEqual(@as(u32, 5), written);
    const delivery = read_delivery(&buffer, written, .{});
    try testing.expectEqualStrings("hello", delivery.bytes);
    try testing.expect(delivery.from.peer.equal(&peer));
}
