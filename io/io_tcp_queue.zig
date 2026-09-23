//! A stream's sends (docs/design.md §19 step 13, the stream's rule 9). rotor's contract has two
//! sends in flight on one socket reach the peer in either order, and a short one leave a gap
//! the other fills, so a connection carries one send at a time. The queries pipelined onto it
//! wait in a queue, oldest first; the head's is the send in flight, and a send that comes back
//! short sends the rest of the same message before the next one starts.
//!
//! A slot's buffer is lent from the moment its query joins the queue. A query whose lookup
//! leaves the connection before any of it went out leaves the queue and gives its buffer back;
//! one that has started is sent to its end, since half a message would break the stream for
//! every lookup on it.
//!
//! Free functions over the engine, split out of `io_tcp.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const tcp = @import("io_tcp.zig");
const send_module = @import("io_send.zig");

/// The slots whose query waits on one connection, oldest first: a ring as long as the table.
pub fn Queue(comptime capacity: u16) type {
    return struct {
        const Self = @This();

        items: [capacity]u16 = undefined,
        head: u16 = 0,
        count: u16 = 0,

        pub fn push(queue: *Self, slot: u16) void {
            assert(queue.count < capacity);
            assert(!queue.contains(slot));
            queue.items[(queue.head + queue.count) % capacity] = slot;
            queue.count += 1;
        }

        pub fn first(queue: *const Self) ?u16 {
            if (queue.count == 0) return null;
            return queue.items[queue.head];
        }

        pub fn pop(queue: *Self) void {
            assert(queue.count > 0);
            queue.head = (queue.head + 1) % capacity;
            queue.count -= 1;
        }

        pub fn at(queue: *const Self, position: u16) u16 {
            assert(position < queue.count);
            return queue.items[(queue.head + position) % capacity];
        }

        pub fn contains(queue: *const Self, slot: u16) bool {
            var position: u16 = 0;
            while (position < queue.count) : (position += 1) {
                if (queue.at(position) == slot) return true;
            }
            return false;
        }

        /// Takes `slot` out, keeping the order of the rest.
        pub fn remove(queue: *Self, slot: u16) void {
            var kept: u16 = 0;
            var position: u16 = 0;
            while (position < queue.count) : (position += 1) {
                const item = queue.at(position);
                if (item == slot) continue;
                queue.items[(queue.head + kept) % capacity] = item;
                kept += 1;
            }
            assert(kept + 1 == queue.count);
            queue.count = kept;
        }
    };
}

/// One lookup's framed query onto its connection: the bytes carry the length prefix `poll`
/// wrote (RFC 7766 §8), the slot's buffer holds them until the last of them has gone, and the
/// query waits its turn.
pub fn send(self: anytype, index: usize, bytes: []const u8, now_ns: u64) void {
    const handle = self.handles[index];
    const at = self.tcp_connection[index] orelse return self.resolver.on_tcp_failed(handle, now_ns);
    const connection = &self.connections[at];
    if (connection.state != .up or connection.descriptor == null) return self.resolver.on_tcp_failed(handle, now_ns);
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    @memcpy(self.send_buffers[index][0..bytes.len], bytes);
    self.send_lengths[index] = @intCast(bytes.len);
    send_module.lend(self, index);
    connection.queue.push(@intCast(index));
    pump(self, at, now_ns);
}

/// Sends the head of the connection's queue, unless a send is in flight already.
fn pump(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    if (connection.sending) return;
    const slot = connection.queue.first() orelse return;
    submit_rest(self, at, slot, now_ns);
}

/// Submits what is left of the head's message. A send the loop refuses fails the connection:
/// the stream cannot go on without it.
fn submit_rest(self: anytype, at: u8, slot: u16, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(!connection.sending);
    const length = self.send_lengths[slot];
    assert(connection.sent_bytes < length);
    const operation: rotor.Operation = .send(
        @TypeOf(self.*).user_data(.tcp_send, slot),
        connection.descriptor.?,
        self.send_buffers[slot][connection.sent_bytes..length],
    );
    if (self.loop.submit(&.{operation}, &.{}) != 1) return tcp.fail(self, at, now_ns);
    connection.sending = true;
}

/// The connection whose send in flight is `slot`'s, if it is still there.
fn sending_connection(self: anytype, slot: usize) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (!connection.sending) continue;
        if (connection.queue.first() == @as(u16, @intCast(slot))) return @intCast(at);
    }
    return null;
}

/// A stream's send ended. A short one sends the rest; a whole one returns the buffer, tells the
/// attempt that made it (rule 7), and lets the next query go; a failed one fails the connection.
/// One whose connection is gone only returns the buffer.
pub fn on_send_event(self: anytype, slot: usize, event: rotor.Event, now_ns: u64) void {
    assert(slot < self.slots.len);
    const at = sending_connection(self, slot) orelse return send_module.finish(self, slot, null, now_ns);
    const connection = &self.connections[at];
    connection.sending = false;
    const count = event.outcome() catch 0;
    // A send that moved nothing failed, or would be asked again for ever.
    if (count == 0) {
        finish_head(connection);
        send_module.give_back(self, slot);
        return tcp.fail(self, at, now_ns);
    }
    const length = self.send_lengths[slot];
    // The loop reports what it moved of what it was given, never more.
    assert(count <= length - connection.sent_bytes);
    connection.sent_bytes += @intCast(count);
    if (connection.sent_bytes < length) return submit_rest(self, at, @intCast(slot), now_ns);
    finish_head(connection);
    send_module.finish(self, slot, true, now_ns);
    pump(self, at, now_ns);
}

fn finish_head(connection: anytype) void {
    connection.queue.pop();
    connection.sent_bytes = 0;
}

/// A lookup leaves its connection: a query of its that waits and has not started goes, and
/// gives its buffer back.
pub fn drop(self: anytype, at: u8, index: usize) void {
    const connection = &self.connections[at];
    const slot: u16 = @intCast(index);
    if (!connection.queue.contains(slot)) return;
    if (connection.sending and connection.queue.first() == slot) return;
    connection.queue.remove(slot);
    send_module.give_back(self, index);
}

/// The connection is closing: every query waiting in it that is not being sent gives its buffer
/// back. The one in flight keeps its buffer until its send's final event.
pub fn release_all(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    var position: u16 = 0;
    while (position < connection.queue.count) : (position += 1) {
        const slot = connection.queue.at(position);
        if (connection.sending and position == 0) continue;
        send_module.give_back(self, slot);
    }
}

// Tests.

const testing = std.testing;

test "a queue keeps its order through a removal from the middle, and wraps" {
    var queue: Queue(3) = .{};
    queue.push(4);
    queue.push(5);
    queue.push(6);
    queue.remove(5);
    try testing.expectEqual(@as(?u16, 4), queue.first());
    queue.pop();
    queue.push(7);
    try testing.expectEqual(@as(?u16, 6), queue.first());
    try testing.expect(queue.contains(7) and !queue.contains(5));
    queue.pop();
    try testing.expectEqual(@as(?u16, 7), queue.first());
}
