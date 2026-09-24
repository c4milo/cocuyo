//! A stream's sends (docs/design.md §19 step 13, the stream's rule 9; over TLS, §21's TLS rules 2
//! and 3). rotor's contract has two sends in flight on one socket reach the peer in either order,
//! and a short one leave a gap the other fills, so a connection carries one send at a time. What
//! waits to go out waits in a queue, oldest first (`io_tcp_queue_ring.zig`); the head's is the
//! send in flight, and a send that comes back short sends the rest of the same head before the
//! next one starts.
//!
//! A slot's buffer is lent from the moment its query joins the queue. A query whose lookup
//! leaves the connection before any of it went out leaves the queue and gives its buffer back;
//! one that has started is sent to its end, since half a message would break the stream for
//! every lookup on it. Over TLS a query is sealed as it goes, and its bytes, and the session's
//! own records, go out from the connection's records buffer.
//!
//! Free functions over the engine, split out of `io_tcp.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const tcp = @import("io_tcp.zig");
const tls = @import("io_tls.zig");
const send_module = @import("io_send.zig");
const ring = @import("io_tcp_queue_ring.zig");

pub const Queue = ring.Queue;

/// One lookup's framed query onto its connection: the bytes carry the length prefix `poll`
/// wrote (RFC 7766 §8, RFC 7858 §3.3), the slot's buffer holds them until the last of them has
/// gone, and the query waits its turn.
pub fn send(self: anytype, index: usize, bytes: []const u8, now_ns: u64) void {
    const handle = self.handles[index];
    const at = self.tcp_connection[index] orelse return self.resolver.on_tcp_failed(handle, now_ns);
    const connection = &self.connections[at];
    if (connection.state != .up or connection.descriptor == null) return self.resolver.on_tcp_failed(handle, now_ns);
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    @memcpy(self.send_buffers[index][0..bytes.len], bytes);
    self.send_lengths[index] = @intCast(bytes.len);
    send_module.lend(self, index);
    connection.queue.push(.{ .slot = @intCast(index) });
    pump(self, at, now_ns);
}

/// Sends the head of the connection's queue, unless a send is in flight already. Over TLS a
/// query is sealed as it goes (§21, TLS rule 2).
pub fn pump(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    if (connection.sending) return;
    const head = connection.queue.first() orelse return;
    if (head.is_query() and connection.queue.sealed == 0 and tls.speaks(self)) {
        if (!tls.seal(self, at, head.slot, now_ns)) return;
    }
    submit_rest(self, at, now_ns);
}

/// Submits what is left of the head. A send the loop refuses fails the connection: the stream
/// cannot go on without it.
fn submit_rest(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(!connection.sending);
    const head = connection.queue.first().?;
    const user_data = if (head.is_query())
        @TypeOf(self.*).user_data(.tcp_send, head.slot)
    else
        tcp.user_data_of(self, .tls_send, at);
    const operation: rotor.Operation = .send(user_data, connection.descriptor.?, rest_of(self, at, head));
    if (self.loop.submit(&.{operation}, &.{}) != 1) return tcp.fail(self, at, now_ns);
    connection.sending = true;
    // The records buffer is the loop's until this send's final event (§21, TLS rule 3).
    if (!head.is_query()) connection.records_in_flight = true;
}

/// What is left to send of the head: a query's own bytes over a plain stream, and over TLS the
/// sealed records in the connection's buffer.
fn rest_of(self: anytype, at: u8, head: ring.Entry) []const u8 {
    if (tls.speaks(self)) return tls.pending(self, at, head.end);
    const connection = &self.connections[at];
    const length = self.send_lengths[head.slot];
    assert(connection.sent_bytes < length);
    return self.send_buffers[head.slot][connection.sent_bytes..length];
}

/// The connection whose send in flight is `slot`'s query, if it is still there.
fn sending_connection(self: anytype, slot: usize) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (!connection.sending) continue;
        const head = connection.queue.first() orelse continue;
        if (head.slot == slot) return @intCast(at);
    }
    return null;
}

/// A query's send ended. A short one sends the rest; a whole one returns the buffer, tells the
/// attempt that made it (rule 7), and lets the next go; a failed one fails the connection. One
/// whose connection is gone only returns the buffer.
pub fn on_send_event(self: anytype, slot: usize, event: rotor.Event, now_ns: u64) void {
    assert(slot < self.slots.len);
    const at = sending_connection(self, slot) orelse return send_module.finish(self, slot, null, now_ns);
    const connection = &self.connections[at];
    connection.sending = false;
    const count = event.outcome() catch 0;
    // A send that moved nothing failed, or would be asked again for ever.
    if (count == 0) {
        finish_head(self, at);
        send_module.give_back(self, slot);
        return tcp.fail(self, at, now_ns);
    }
    if (!advance(self, at, count)) return submit_rest(self, at, now_ns);
    finish_head(self, at);
    send_module.finish(self, slot, true, now_ns);
    after_send(self, at, now_ns);
}

/// A send of a TLS session's own records ended (§21, TLS rule 3). Whichever opening made it, the
/// slot's records buffer is the connection's own again, which may let a connection waiting on it
/// connect again (TLS rule 8). One for an opening that is gone does nothing more.
pub fn on_records_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    const slot: u8 = @intCast(index & constants.tcp_slot_mask);
    const borrower = &self.connections[slot];
    assert(borrower.records_in_flight);
    borrower.records_in_flight = false;
    const at = tcp.current_of(self, index, event) orelse return tcp.connect_again(self, slot, now_ns);
    const connection = &self.connections[at];
    connection.sending = false;
    const count = event.outcome() catch 0;
    if (count == 0) return tcp.fail(self, at, now_ns);
    if (!advance(self, at, count)) return submit_rest(self, at, now_ns);
    finish_head(self, at);
    after_send(self, at, now_ns);
}

/// Counts what a send moved of the head, and says whether the head went whole. The loop reports
/// what it moved of what it was given, never more.
fn advance(self: anytype, at: u8, count: u32) bool {
    const connection = &self.connections[at];
    const head = connection.queue.first().?;
    const left = rest_of(self, at, head).len;
    assert(count <= left);
    connection.sent_bytes += @intCast(count);
    return count == left;
}

fn finish_head(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    const head = connection.queue.first().?;
    connection.queue.pop();
    connection.sent_bytes = 0;
    if (tls.speaks(self)) tls.sent_through(self, at, head.end);
}

/// After a whole send: a closing connection whose queue is empty closes, since its
/// `close_notify` has gone (§21, TLS rule 5); any other sends its next.
fn after_send(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    if (connection.state == .closing and connection.queue.count == 0) return tcp.shut(self, at);
    pump(self, at, now_ns);
}

/// A lookup leaves its connection: a query of its that waits and has not started goes, and
/// gives its buffer back.
pub fn drop(self: anytype, at: u8, index: usize) void {
    const connection = &self.connections[at];
    const slot: u16 = @intCast(index);
    if (!connection.queue.contains(slot)) return;
    const head = connection.queue.first().?;
    if (connection.sending and head.slot == slot) return;
    if (connection.queue.sealed > 0 and head.slot == slot) return;
    connection.queue.remove(slot);
    send_module.give_back(self, index);
}

/// The connection is closing: every query waiting in it that is not being sent gives its buffer
/// back. The one in flight keeps its buffer until its send's final event.
pub fn release_all(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    var position: u16 = 0;
    while (position < connection.queue.count) : (position += 1) {
        const entry = connection.queue.at(position);
        if (!entry.is_query()) continue;
        if (connection.sending and position == 0) continue;
        send_module.give_back(self, entry.slot);
    }
}
