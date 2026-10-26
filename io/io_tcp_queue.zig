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
//! own records, go out from the connection's records buffer. Each such send lends that buffer
//! until its final event, whichever opening made it (§21, TLS rule 3).
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
///
/// The lookup's connection is up, and an assertion holds it (docs/design.md §17 question 66):
///
/// - A lookup asks for a send on a stream only after `on_tcp_connected`, which the engine calls
///   only for a connection that is up.
/// - Each end of a connection tells each lookup on it at once, and takes it off the connection
///   (`tcp.abandon`). An idle close ends only a connection that has no users.
/// - A send held for the buffer goes out only on the attempt that asked for it. A failed
///   connection ends that attempt: the lookup moves to a new transaction, or it ends.
pub fn send(self: anytype, index: usize, bytes: []const u8, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    // The lookup is on the stream that it heard was up.
    assert(self.resolver.lookup_of(self.handles[index]).is_on_stream());
    const at_or_null = up_connection(self, index);
    assert(at_or_null != null);
    const at = at_or_null.?;
    const connection = &self.connections[at];
    assert(bytes.len <= cocuyo.limits.query_bytes_max);
    @memcpy(self.send_buffers[index][0..bytes.len], bytes);
    self.send_lengths[index] = @intCast(bytes.len);
    send_module.lend(self, index);
    connection.queue.push(.{ .slot = @intCast(index) });
    pump(self, at, now_ns);
}

/// The slot of the connection that the lookup at `index` is on, while that connection is up.
fn up_connection(self: anytype, index: usize) ?u8 {
    const at = self.tcp_connection[index] orelse return null;
    const connection = &self.connections[at];
    if (connection.state != .up or connection.descriptor == null) return null;
    return at;
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
    assert(!connection.sending and connection.send_handle == null);
    // The slot was free when this opening began, and each send's event gave its buffer back.
    assert(connection.records_send == null);
    const head = connection.queue.first().?;
    const user_data = if (head.is_query())
        @TypeOf(self.*).user_data(.tcp_send, head.slot)
    else
        tcp.user_data_of(self, .tls_send, at);
    const operation: rotor.Operation = .send(user_data, connection.descriptor.?, rest_of(self, at, head));
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) != 1) return tcp.fail(self, at, tcp.reason_of(self, at, .local), now_ns);
    connection.sending = true;
    // `shut` cancels the send by this handle (docs/design.md §16 decision 49).
    connection.send_handle = handles[0];
    // Over TLS each send reads the records buffer, a query's too, and the buffer is the loop's
    // until the send's final event (§21, TLS rule 3).
    if (tls.speaks(self)) connection.records_send = head.slot;
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
/// whose connection is gone only returns the buffer. Over TLS the records buffer it read is its
/// slot's own again, whichever opening sealed the query (§21, TLS rule 3).
pub fn on_send_event(self: anytype, slot: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    assert(slot < self.slots.len);
    const lender = records_back(self, slot);
    const at = sending_connection(self, slot) orelse {
        // A connection that closed during the send kept its slot closed until now.
        if (lender) |closed| assert(self.connections[closed].state == .closed);
        return send_module.finish(self, slot, null, now_ns);
    };
    // Over TLS the send read the sealed records of its own connection.
    assert(if (tls.speaks(self)) lender == at else lender == null);
    const connection = &self.connections[at];
    // The connection kept the handle of the send that just ended.
    assert(connection.send_handle != null);
    connection.sending = false;
    connection.send_handle = null;
    const count = event.outcome() catch 0;
    // A send that moved nothing failed, or would be asked again for ever.
    if (count == 0) {
        finish_head(self, at);
        send_module.give_back(self, slot);
        return tcp.fail(self, at, .closed, now_ns);
    }
    if (!advance(self, at, count)) return submit_rest(self, at, now_ns);
    finish_head(self, at);
    send_module.finish(self, slot, true, now_ns);
    after_send(self, at, now_ns);
}

/// The connection slot whose records buffer the send of `slot`'s query read, which is its own
/// again: over TLS one slot's, of whichever opening (§21, TLS rule 3). Null over a plain stream,
/// where the send read the lookup's own buffer. The scan reads each slot whatever the engine
/// speaks now. After a `reinit` from TLS to the clear, a send of the old configuration still holds
/// its slot.
fn records_back(self: anytype, slot: usize) ?u8 {
    assert(slot < self.slots.len);
    var lender: ?u8 = null;
    for (self.connections[0..], 0..) |*connection, at| {
        const sender = connection.records_send orelse continue;
        if (sender != slot) continue;
        // A lookup has one send in flight at most (the stream's rule 6), so one slot lends to it.
        assert(lender == null);
        connection.records_send = null;
        lender = @intCast(at);
    }
    return lender;
}

/// A send of a TLS session's own records ended (§21, TLS rule 3). Whichever opening made it, the
/// slot's records buffer is the connection's own again, which may let a connection waiting on it
/// connect again (TLS rule 8). One for an opening that is gone does nothing more.
pub fn on_records_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    const slot: u8 = @intCast(index & constants.tcp_slot_mask);
    const borrower = &self.connections[slot];
    assert(borrower.records_send == ring.records);
    borrower.records_send = null;
    const at = tcp.current_of(self, index, event) orelse return tcp.connect_again(self, slot, now_ns);
    const connection = &self.connections[at];
    // The connection kept the handle of the send that just ended.
    assert(connection.sending and connection.send_handle != null);
    connection.sending = false;
    connection.send_handle = null;
    const count = event.outcome() catch 0;
    if (count == 0) return tcp.fail(self, at, tcp.reason_of(self, at, .handshake), now_ns);
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

/// Whether the send in flight on the connection in slot `at` is a query's: its head is a query, and
/// the head's send is in flight (the stream's rule 9). That send holds its lookup's buffer. Over
/// TLS the head may be the session's own records, whose send holds no lookup's buffer
/// (docs/design.md §16 decision 53).
pub fn query_in_flight(self: anytype, at: u8) bool {
    const connection = &self.connections[at];
    if (!connection.sending) return false;
    const head = connection.queue.first().?;
    if (!head.is_query()) return false;
    // A query goes out only on a connection that is up, and none is on one that closes (§21,
    // TLS rule 5). The query's send lent its lookup's buffer (the stream's rule 6).
    assert(connection.state == .up);
    assert(self.send_in_flight[head.slot]);
    return true;
}

/// Asserts the rule of docs/design.md §16 decision 53 over every connection: one that is up and
/// that no lookup is on has no query's send in flight. The last leave during that send shut it.
pub fn assert_none_held(self: anytype) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state != .up or connection.users != 0) continue;
        assert(!query_in_flight(self, @intCast(at)));
    }
}

/// The connection says a fatal alert before it closes: every query not yet sealed leaves the queue
/// and gives its buffer back, since nothing more may be sent (RFC 9846 §6.2). What is sealed stays,
/// and goes out ahead of the alert, in the order it was sealed (§21, TLS rules 2 and 4).
pub fn drop_unsealed(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    assert(connection.queue.sealed <= connection.queue.count);
    for (0..connection.queue.count - connection.queue.sealed) |_| {
        const entry = connection.queue.at(connection.queue.count - 1);
        assert(entry.is_query());
        connection.queue.remove(entry.slot);
        send_module.give_back(self, entry.slot);
    }
    assert(connection.queue.count == connection.queue.sealed);
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
