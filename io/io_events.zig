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
const Kind = @import("io.zig").Kind;

/// One completion event. True when it was the engine's, in which case the engine has acted on
/// it; false hands it back to the caller untouched.
pub fn apply(self: anytype, event: rotor.Event, now_ns: u64) bool {
    if (event.user_data >> constants.tag_shift != @TypeOf(self.*).tag) return false;
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data >> constants.kind_shift)));
    const index: usize = @intCast(event.user_data & constants.index_mask);
    switch (kind) {
        .udp_send => send_module.on_event(self, index, event, now_ns),
        .udp_receive => on_receive_event(self, index, event, now_ns),
        .timer => on_timer_event(self, index, now_ns),
        .tcp_connect => tcp.on_connect_event(self, index, event, now_ns),
        .tcp_send => tcp_queue.on_send_event(self, index, event, now_ns),
        .tcp_receive => tcp.on_receive_event(self, index, event, now_ns),
        .tls_send => tcp_queue.on_records_event(self, index, event, now_ns),
        .quic_send => request_events.on_send_event(self, index, event, now_ns),
        .quic_receive => request_events.on_receive_event(self, index, event, now_ns),
    }
    drive_module.drive(self, now_ns);
    return true;
}

/// The current timer fired, or ended: it is gone, and so is the deadline it stood for, so the
/// next drive arms one again even for a deadline the caller's clock has not reached yet. Each
/// QUIC connection whose deadline has come is told (docs/design.md §24, request rule 11). The
/// end of an earlier timer, one the deadline moved away from, is nothing: its generation says
/// so, and the current timer is left as it is.
fn on_timer_event(self: anytype, generation: usize, now_ns: u64) void {
    if (generation != self.timer_generation) return;
    self.timer_handle = null;
    self.timer_due_ns = null;
    request_events.expire_due(self, now_ns);
}

fn on_receive_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    // A receive the socket left behind, because the port was replaced or the configuration was:
    // it changes nothing, and arming another is not this one's to do. A cancelled multishot can
    // still deliver a datagram before its end (rotor decision 5, rule 2), and its buffer goes
    // back to the group (docs/design.md §19 step 13, the datagram's rules 2 and 3).
    const found = self.sockets.find(index) orelse {
        if (event.flags.buffer) self.loop.give_back_buffer(constants.group_id, event.flags.buffer_id);
        return;
    };
    assert(found.server < cocuyo.constants.servers_max);
    if (event.flags.buffer) deliver(self, event, now_ns);
    // A multishot that ended is armed again on the same socket, current or draining, unless the
    // engine is closing; one the loop refuses is asked for again at the next drive.
    if (event.is_final() and !self.closing) {
        self.sockets.arm(self.loop, found.socket, found.server, @TypeOf(self.*).tag) catch {};
    }
}

/// Hands a datagram to the table, whatever its length, and its buffer back to the group.
fn deliver(self: anytype, event: rotor.Event, now_ns: u64) void {
    const delivery = self.loop.datagram(constants.group_id, event);
    _ = self.resolver.on_datagram(delivery.bytes, udp.endpoint_of(delivery.from.peer), now_ns);
    self.loop.give_back_buffer(constants.group_id, event.flags.buffer_id);
}
