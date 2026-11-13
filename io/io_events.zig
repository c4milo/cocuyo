//! What a completion event does to the engine (docs/design.md §19 step 13): a send finished,
//! a datagram arrived, the timer fired. Free functions over the engine, split out of
//! `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const tcp = @import("io_tcp.zig");
const drive_module = @import("io_drive.zig");
const send_module = @import("io_send.zig");
const tcp_queue = @import("io_tcp_queue.zig");
const request_events = @import("io_request_events.zig");
const channel_module = @import("io_channel.zig");
const channel_link = @import("io_channel_link.zig");
const OperationId = @import("io_interface.zig").OperationId;

/// One completion event. True when it was the engine's, in which case the engine has acted on
/// it; false hands it back to the caller untouched. The table names the operation's handler,
/// and a final event frees its id first, so the handler may take the slot again (docs/design.md
/// §26 step 4.1).
pub fn apply(self: anytype, event: rotor.Event, now_ns: u64) bool {
    if (event.user_data >> constants.tag_shift != @TypeOf(self.*).tag) return false;
    // The engine writes nothing between its tag and the id.
    assert(event.user_data & ~(@as(u64, std.math.maxInt(u16)) << constants.tag_shift) <= constants.operation_id_mask);
    const id: OperationId = @enumFromInt(@as(u32, @truncate(event.user_data)));
    const origin = self.operations.origin_of(id);
    if (event.is_final()) self.operations.release(id);
    const index: usize = @intCast(origin.index);
    switch (origin.kind) {
        .udp_send => send_module.on_event(self, index, event, now_ns),
        .udp_receive => on_receive_event(self, id, index, event, now_ns),
        .timer => on_timer_event(self, id, event, now_ns),
        .tcp_connect => tcp.on_connect_event(self, index, event, now_ns),
        .tcp_send => tcp_queue.on_send_event(self, index, event, now_ns),
        .tcp_receive => tcp.on_receive_event(self, index, event, now_ns),
        .tls_send => tcp_queue.on_records_event(self, index, event, now_ns),
        .quic_send => request_events.on_send_event(self, index, event, now_ns),
        .quic_receive => request_events.on_receive_event(self, index, event, now_ns),
        .doh_connect => channel_link.on_connect_event(self, index, event, now_ns),
        .doh_send => channel_link.on_send_event(self, index, event, now_ns),
        .doh_receive => channel_link.on_receive_event(self, index, event, now_ns),
    }
    drive_module.drive(self, now_ns);
    return true;
}

/// The timer fired, or ended: it is gone, and so is the deadline it stood for, so the next drive
/// arms one again even for a deadline the caller's clock has not reached yet. Each QUIC
/// connection whose deadline has come is told (docs/design.md §24, request rule 11). A timer that
/// the deadline moved away from ends `canceled`, and tells nobody: the next drive arms the timer
/// of the deadline that moved (§26, one operation for each place).
fn on_timer_event(self: anytype, id: OperationId, event: rotor.Event, now_ns: u64) void {
    // The timer is one place, so the table holds one timer's id at most.
    assert(self.timer_id == id);
    self.timer_id = null;
    self.timer_handle = null;
    self.timer_due_ns = null;
    _ = event.outcome() catch return;
    request_events.expire_due(self, now_ns);
    channel_module.expire_due(self, now_ns);
}

fn on_receive_event(self: anytype, id: OperationId, index: usize, event: rotor.Event, now_ns: u64) void {
    // A receive the socket left behind, because the port was replaced or the configuration was:
    // it changes nothing, and arming another is not this one's to do. A cancelled multishot can
    // still deliver a datagram before its end (rotor decision 5, rule 2), and its buffer goes
    // back to the group (docs/design.md §19 step 13, the datagram's rules 2 and 3).
    const found = self.sockets.find(id, index) orelse {
        if (event.flags.buffer) self.loop.give_back_buffer(self.group.id, event.flags.buffer_id);
        return;
    };
    assert(found.server < cocuyo.limits.servers_max);
    if (event.flags.buffer) deliver(self, event, now_ns);
    // A multishot that ended is armed again on the same socket, current or draining, unless the
    // engine is closing; one the loop refuses is asked for again at the next drive.
    if (!event.is_final()) return;
    found.socket.receiving = false;
    if (!self.closing) self.sockets.arm(self, found.socket, found.server) catch {};
}

/// Hands a datagram to the table, whatever its length, and its buffer back to the group. One
/// longer than a buffer's room comes cut, and the kernel marks it: the table takes it as cut
/// (docs/design.md §19 step 13, the datagram's rule 6).
fn deliver(self: anytype, event: rotor.Event, now_ns: u64) void {
    const delivery = self.loop.datagram(self.group.id, event);
    const from = udp.endpoint_of(delivery.from.peer);
    if (delivery.from.flags.truncated) {
        _ = self.resolver.on_datagram_cut(delivery.bytes, from, now_ns);
    } else {
        _ = self.resolver.on_datagram(delivery.bytes, from, now_ns);
    }
    self.loop.give_back_buffer(self.group.id, event.flags.buffer_id);
}
