//! The chunks a TCP connection reads into: a group of its own, because a datagram group carries
//! rotor's prefix before every payload and a stream has no peer to name. Split out of
//! `io_tcp.zig`.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");

/// A group of `buffers` chunks, in the caller's memory.
pub fn Group(comptime buffers: u16) type {
    return struct {
        const Self = @This();

        const needed = rotor.buffers.group_bytes(buffers, constants.tcp_chunk_bytes);
        const alignment = rotor.buffers.group_alignment;

        /// One alignment more than the group needs, and no alignment claimed for it, for the
        /// reason the datagram group's own `memory` gives: the loader keeps page alignment and
        /// nothing more, and a type that claims more hands the optimizer a false premise.
        memory: [needed + alignment]u8,

        comptime {
            assert(@alignOf(Self) <= constants.storage_alignment_max);
        }

        pub fn ring(self: *Self) []align(alignment) u8 {
            const from = @intFromPtr(&self.memory);
            const at = std.mem.alignForward(usize, from, alignment);
            assert(at - from < alignment);
            return @alignCast(self.memory[at - from ..][0..needed]);
        }

        pub fn provide(self: *Self, loop: *rotor.Loop) error{ReceiveFailed}!void {
            const memory = ring(self);
            assert(@intFromPtr(memory.ptr) % alignment == 0);
            loop.provide_buffers(constants.tcp_group_id, memory, buffers, constants.tcp_chunk_bytes) catch
                return error.ReceiveFailed;
        }
    };
}
