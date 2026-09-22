//! The twin of rotor's `Loop` (docs/design.md §19 step 13, rotor decision 10): the same
//! declarations, over a virtual clock and the network of `sim_network.zig`, so the engine runs
//! on it unchanged and every path is driven from a seed. An operation is performed the moment it
//! is submitted, its events are queued for the instant they fall due, and `tick` moves the
//! clock to the next of them when nothing is due yet.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const buffers = @import("sim_buffers.zig");
const network_module = @import("sim_network.zig");
const perform = @import("sim_loop_perform.zig");
const Operation = types.Operation;
const Event = types.Event;
const Handle = types.Handle;

pub const InitError = error{ SystemResources, Unexpected };
pub const TickError = error{Unexpected};
pub const DrainError = error{ Timeout, Unexpected };

/// What `statistics` hands back: nothing is sampled here.
pub const Statistics = struct { sampled: u64 = 0 };

pub const Registry = struct { loops: u16 = 0 };

pub const Remote = struct {
    pub fn init(remote: *Remote, registry: *Registry, id: types.LoopId) InitError!void {
        _ = remote;
        _ = registry;
        _ = id;
    }
    pub fn deinit(remote: *Remote) void {
        _ = remote;
    }
    pub fn post(remote: *Remote, target: types.LoopId, message: types.Message) error{Unsupported}!void {
        _ = remote;
        _ = target;
        _ = message;
        return error.Unsupported;
    }
};

/// One operation in flight.
pub const Slot = struct {
    live: bool = false,
    cancelling: bool = false,
    generation: u32 = 0,
    user_data: u64 = 0,
    code: Operation.Code = .nop,
    socket: ?types.Descriptor = null,
};

/// An event waiting for its instant.
pub const Pending = struct {
    due_ns: u64,
    sequence: u32,
    slot: u32,
    final: bool,
    /// The group a delivery's buffer came from, so a withdrawn delivery gives it back.
    group: u16,
    event: Event,
};

pub const Loop = struct {
    pub const Options = struct {
        operations: u32,
        entries: u16,
        id: types.LoopId = 0,
        registry: ?*Registry = null,
    };

    operations: u32,
    slots: [constants.operations_max]Slot,
    live: u32,
    next_generation: u32,
    pending: [constants.events_pending_max]Pending,
    pending_count: u32,
    sequence: u32,
    now_ns: u64,
    groups: [constants.buffer_groups_max]buffers.Group,
    group_options: types.GroupOptions,
    /// The draws the network makes: delays, drops, chunk sizes. Seeded by `seed`.
    word: u64,
    statistics_: Statistics,

    /// The twin keeps its tables inside itself, so it needs none of the caller's memory; the
    /// signature is rotor's so a caller's arrays are sized the same.
    pub fn memory_bytes(options: Options) usize {
        assert(options.operations >= 1);
        return 0;
    }

    pub fn init(loop: *Loop, memory: []align(constants.memory_alignment) u8, options: Options) InitError!void {
        assert(options.operations >= 1);
        assert(options.operations <= constants.operations_max);
        assert(memory.len >= memory_bytes(options));
        loop.* = .{
            .operations = options.operations,
            .slots = @splat(.{}),
            .live = 0,
            .next_generation = constants.generation_first,
            .pending = undefined,
            .pending_count = 0,
            .sequence = 0,
            .now_ns = 0,
            .groups = @splat(buffers.Group.none),
            .group_options = .{},
            .word = 0,
            .statistics_ = .{},
        };
        network_module.network.reset();
    }

    /// The seed every draw of the network comes from, and the instant the clock starts at.
    pub fn seed(loop: *Loop, value: u64) void {
        loop.word = value;
    }

    pub fn now(loop: *const Loop) u64 {
        return loop.now_ns;
    }

    pub fn network(loop: *Loop) *network_module.Network {
        _ = loop;
        return &network_module.network;
    }

    pub fn deinit(loop: *Loop) void {
        loop.assert_empty();
    }

    pub fn assert_empty(loop: *const Loop) void {
        assert(loop.live == 0);
    }

    pub fn in_flight(loop: *const Loop) u32 {
        return loop.live;
    }

    pub fn statistics(loop: *const Loop) *const Statistics {
        return &loop.statistics_;
    }

    /// Performs each operation the moment it is taken, and returns how many were taken: the
    /// slot table's room is the bound.
    pub fn submit(loop: *Loop, operations: []const Operation, handles: []Handle) u32 {
        var taken: u32 = 0;
        for (operations, 0..) |*operation, index| {
            const slot_index = loop.allocate(operation) orelse break;
            if (index < handles.len) {
                handles[index] = .{ .index = slot_index, .generation = loop.slots[slot_index].generation };
            }
            perform.perform(loop, slot_index, operation);
            taken += 1;
        }
        assert(taken <= operations.len);
        return taken;
    }

    fn allocate(loop: *Loop, operation: *const Operation) ?u32 {
        if (loop.live >= loop.operations) return null;
        for (&loop.slots, 0..) |*slot, index| {
            if (slot.live) continue;
            slot.* = .{
                .live = true,
                .generation = loop.next_generation,
                .user_data = operation.user_data,
                .code = operation.code(),
                .socket = operation.descriptor(),
            };
            loop.next_generation +%= 1;
            if (loop.next_generation == 0) loop.next_generation = constants.generation_first;
            loop.live += 1;
            return @intCast(index);
        }
        unreachable;
    }

    /// Queues an event for `slot` at `due_ns`. A final event frees the slot when delivered
    /// (rotor decision 5, rule 1).
    pub fn queue(loop: *Loop, slot: u32, event: Event, due_ns: u64, final: bool) void {
        assert(loop.slots[slot].live);
        assert(loop.pending_count < constants.events_pending_max);
        loop.pending[loop.pending_count] = .{
            .due_ns = due_ns,
            .sequence = loop.sequence,
            .slot = slot,
            .final = final,
            .group = 0,
            .event = event,
        };
        loop.pending_count += 1;
        loop.sequence +%= 1;
    }

    /// Queues a delivery into a group buffer for a receiving operation: one event of a
    /// multishot, or the final event of a single-shot receive.
    pub fn queue_delivery(loop: *Loop, receiver: network_module.Receiver, buffer_id: u16, len: u32, due_ns: u64) void {
        var event = Event.success(receiver.user_data, len);
        event.flags = .{ .buffer = true, .more = receiver.multishot, .buffer_id = buffer_id };
        loop.queue(receiver.slot, event, due_ns, !receiver.multishot);
        loop.pending[loop.pending_count - 1].group = receiver.group;
    }

    /// Whether the operation has ended already: a final event is queued and due, and nothing
    /// but its delivery is left. A final event due later is a timer that has not fired, or a
    /// connection still being made, and rotor cancels those at once (decision 5, rules 2 and 5).
    fn has_ended(loop: *const Loop, slot: u32) bool {
        for (loop.pending[0..loop.pending_count]) |*pending| {
            if (pending.slot == slot and pending.final and pending.due_ns <= loop.now_ns) return true;
        }
        return false;
    }

    /// Ends an operation with `Canceled`, unless it ended already (rotor decision 5, rule 2).
    pub fn cancel(loop: *Loop, handle: Handle) void {
        if (handle.is_none()) return;
        const slot = &loop.slots[handle.index];
        if (!slot.live or slot.generation != handle.generation or slot.cancelling) return;
        if (loop.has_ended(handle.index)) return;
        slot.cancelling = true;
        perform.withdraw(loop, handle.index);
        loop.queue(handle.index, Event.failure(slot.user_data, .canceled), loop.now_ns, true);
    }

    pub fn cancel_all(loop: *Loop) void {
        for (&loop.slots, 0..) |*slot, index| {
            if (!slot.live) continue;
            loop.cancel(.{ .index = @intCast(index), .generation = slot.generation });
        }
    }

    /// Delivers what is due, moving the clock to the next event when nothing is, by at most
    /// `wait_ns`.
    pub fn tick(loop: *Loop, events: []Event, wait_ns: u64) TickError!u32 {
        assert(wait_ns <= constants.wait_ns_max);
        perform.materialize(loop);
        if (loop.next_due() == null or loop.next_due().? > loop.now_ns) {
            const horizon = loop.now_ns + wait_ns;
            const due = loop.next_due() orelse horizon;
            loop.now_ns = @min(due, horizon);
            perform.materialize(loop);
        }
        var delivered: u32 = 0;
        while (delivered < events.len) {
            const index = loop.first_due() orelse break;
            events[delivered] = loop.take_pending(index);
            delivered += 1;
        }
        return delivered;
    }

    /// The earliest instant anything is due: a queued event, or a delivery the network holds.
    fn next_due(loop: *const Loop) ?u64 {
        var due: ?u64 = perform.next_delivery_due(loop);
        for (loop.pending[0..loop.pending_count]) |*pending| {
            if (due == null or pending.due_ns < due.?) due = pending.due_ns;
        }
        return due;
    }

    /// The queued event due first, by instant then by the order it was queued in.
    fn first_due(loop: *const Loop) ?u32 {
        var best: ?u32 = null;
        for (loop.pending[0..loop.pending_count], 0..) |*pending, index| {
            if (pending.due_ns > loop.now_ns) continue;
            if (best) |current| {
                const other = &loop.pending[current];
                if (pending.due_ns > other.due_ns) continue;
                if (pending.due_ns == other.due_ns and pending.sequence > other.sequence) continue;
            }
            best = @intCast(index);
        }
        return best;
    }

    fn take_pending(loop: *Loop, index: u32) Event {
        const pending = loop.pending[index];
        loop.pending_count -= 1;
        loop.pending[index] = loop.pending[loop.pending_count];
        if (pending.final) {
            const slot = &loop.slots[pending.slot];
            assert(slot.live);
            slot.* = .{};
            loop.live -= 1;
        }
        return pending.event;
    }

    /// Ticks until nothing is in flight, or gives up after `drain_rounds_max` ticks, which is an
    /// operation nobody ended: a multishot receive left running.
    pub fn drain(loop: *Loop, scratch: []Event) DrainError!void {
        var rounds: u32 = 0;
        while (rounds < constants.drain_rounds_max) : (rounds += 1) {
            if (loop.live == 0) return;
            _ = try loop.tick(scratch, constants.wait_ns_max);
        }
        if (loop.live != 0) return error.Timeout;
    }

    // Buffers.

    pub fn provide_datagram_buffers(
        loop: *Loop,
        group_id: u16,
        ring_memory: []align(buffers.ring_alignment) u8,
        memory: []u8,
        buffer_bytes: u32,
        group: types.GroupOptions,
    ) buffers.ProvideError!void {
        assert(buffer_bytes > types.prefix_bytes(group));
        loop.group_options = group;
        return loop.provide_buffers(group_id, ring_memory, memory, buffer_bytes);
    }

    pub fn provide_buffers(
        loop: *Loop,
        group_id: u16,
        ring_memory: []align(buffers.ring_alignment) u8,
        memory: []u8,
        buffer_bytes: u32,
    ) buffers.ProvideError!void {
        assert(group_id < constants.buffer_groups_max);
        assert(ring_memory.len >= buffers.ring_bytes(@intCast(memory.len / buffer_bytes)));
        loop.groups[group_id] = buffers.Group.init(memory, buffer_bytes);
    }

    pub fn provided_buffer(loop: *const Loop, group_id: u16, buffer_id: u16) []u8 {
        assert(group_id < constants.buffer_groups_max);
        return loop.groups[group_id].bytes_of(buffer_id);
    }

    pub fn give_back_buffer(loop: *Loop, group_id: u16, buffer_id: u16) void {
        assert(group_id < constants.buffer_groups_max);
        loop.groups[group_id].give_back(buffer_id);
    }

    pub fn datagram(loop: *const Loop, buffer: []u8, event: Event) types.Delivery {
        assert(!event.flags.message);
        assert(event.result >= 0);
        return buffers.read_delivery(buffer, @intCast(event.result), loop.group_options);
    }

    pub fn register_buffers(loop: *Loop, registered: []const []u8) buffers.RegisterError!void {
        _ = loop;
        _ = registered;
    }

    pub fn register_descriptors(loop: *Loop, descriptors: []const types.Descriptor) buffers.RegisterError!void {
        _ = loop;
        _ = descriptors;
    }
};

test {
    _ = perform;
}
