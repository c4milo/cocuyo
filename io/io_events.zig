//! What a completion event does to the engine (docs/design.md §19 step 13): a send finished,
//! a datagram arrived, the timer fired. Free functions over the engine, split out of
//! `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const drive_module = @import("io_drive.zig");
const Kind = @import("io.zig").Kind;

/// One completion event. True when it was the engine's, in which case the engine has acted on
/// it; false hands it back to the caller untouched.
pub fn apply(self: anytype, event: rotor.Event, now_ns: u64) bool {
    if (event.user_data >> constants.tag_shift != @TypeOf(self.*).tag) return false;
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data >> constants.kind_shift)));
    const index: usize = @intCast(event.user_data & constants.index_mask);
    switch (kind) {
        .udp_send => on_send_event(self, index, event, now_ns),
        .udp_receive => on_receive_event(self, index, event, now_ns),
        .timer => on_timer_event(self, index),
    }
    drive_module.drive(self, now_ns);
    return true;
}

/// The current timer fired, or ended: it is gone, and so is the deadline it stood for, so the
/// next drive arms one again even for a deadline the caller's clock has not reached yet. The
/// end of an earlier timer, one the deadline moved away from, is nothing: its generation says
/// so, and the current timer is left as it is.
fn on_timer_event(self: anytype, generation: usize) void {
    if (generation != self.timer_generation) return;
    self.timer_handle = null;
    self.timer_due_ns = null;
}

fn on_send_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    assert(index < self.slots.len);
    self.send_in_flight[index] = false;
    const handle = self.handles[index];
    if (!self.slots[index].occupied or self.resolver.lookup_of(handle).is_settled()) return;
    if (event.outcome()) |_| {
        self.resolver.on_sent(handle, now_ns);
    } else |_| {
        self.resolver.on_send_failed(handle, now_ns);
    }
}

fn on_receive_event(self: anytype, server: usize, event: rotor.Event, now_ns: u64) void {
    assert(server < cocuyo.constants.servers_max);
    if (event.outcome()) |bytes| {
        if (bytes > 0) deliver(self, event, now_ns);
    } else |_| {}
    // A multishot that ended is armed again, unless the engine is closing.
    if (event.is_final() and !self.closing) {
        self.sockets.receive_again(self.loop, @intCast(server), @TypeOf(self.*).tag) catch {};
    }
}

fn deliver(self: anytype, event: rotor.Event, now_ns: u64) void {
    const buffer = self.loop.provided_buffer(constants.group_id, event.flags.buffer_id);
    const delivery = self.loop.datagram(buffer, event);
    _ = self.resolver.on_datagram(delivery.bytes, udp.endpoint_of(delivery.from.peer), now_ns);
    self.loop.give_back_buffer(constants.group_id, event.flags.buffer_id);
}
