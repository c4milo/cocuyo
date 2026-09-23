//! A slot's send buffer (docs/design.md §19 step 13, the stream's rules 6 and 7). The buffer is
//! the loop's from a send's submission to the send's final event (rotor decision 5, rule 3), so a
//! send asked for while it is lent is held, and goes out when the buffer comes back. A lookup's
//! next attempt and a new lookup that took the slot both have to wait for it: the loop may still
//! be reading the octets.
//!
//! A send's completion speaks for the attempt that made it and for nobody else. The engine
//! records the lookup's handle and transaction when the send goes out, and a completion that
//! finds the lookup freed, ended or on a new transaction returns the buffer and tells nobody.
//! Telling the lookup would say a query went out on an attempt that never made one.
//!
//! Free functions over the engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const udp = @import("io_udp.zig");
const tcp = @import("io_tcp.zig");

/// The attempt a send was made for: the lookup, and the transaction it was on.
pub const Owner = struct {
    handle: cocuyo.Handle,
    transaction: cocuyo.resolver.entropy.Transaction,
};

/// A send asked for while the slot's buffer was lent. Its octets wait in `held_buffers`.
pub const Held = struct {
    owner: Owner,
    tcp: bool,
    len: u16,
    /// The server a datagram goes to; unused for a stream, which has its connection.
    to: cocuyo.Endpoint,
};

/// What a lookup's poll asked to send.
pub const Asked = union(enum) {
    udp: struct { server: cocuyo.Endpoint, bytes: []const u8 },
    tcp: []const u8,
};

/// A send the drive was handed: out now, or held until the buffer comes back.
pub fn ask(self: anytype, index: usize, asked: Asked, now_ns: u64) void {
    if (!self.send_in_flight[index]) return submit(self, index, asked, now_ns);
    const bytes = switch (asked) {
        .udp => |datagram| datagram.bytes,
        .tcp => |stream| stream,
    };
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    @memcpy(self.held_buffers[index][0..bytes.len], bytes);
    self.held[index] = .{
        .owner = owner_of(self, index),
        .tcp = asked == .tcp,
        .len = @intCast(bytes.len),
        .to = if (asked == .udp) asked.udp.server else undefined,
    };
}

fn submit(self: anytype, index: usize, asked: Asked, now_ns: u64) void {
    assert(!self.send_in_flight[index]);
    switch (asked) {
        .udp => |datagram| send_datagram(self, index, datagram.server, datagram.bytes, now_ns),
        .tcp => |stream| tcp.send(self, index, stream, now_ns),
    }
}

/// Queues a datagram to the lookup's server from its server's socket.
fn send_datagram(self: anytype, index: usize, server: cocuyo.Endpoint, bytes: []const u8, now_ns: u64) void {
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    const slot = self.resolver.lookup_of(self.handles[index]).server_slot();
    @memcpy(self.send_buffers[index][0..bytes.len], bytes);
    self.outbounds[index] = udp.outbound_to(server);
    const operation: rotor.Operation = .{
        .user_data = @TypeOf(self.*).user_data(.udp_send, index),
        .kind = .{ .send_to = .{
            .socket = self.sockets.descriptor_of(slot),
            .buffer = .{ .bytes = self.send_buffers[index][0..bytes.len] },
            .to = &self.outbounds[index],
        } },
    };
    if (self.loop.submit(&.{operation}, &.{}) == 1) {
        lend(self, index);
        self.sent_from[index] = .{ .server = slot, .epoch = self.sockets.epoch_of(slot) };
        _ = self.sockets.count_sent(slot, self.config.udp_queries_per_port);
    } else {
        self.resolver.on_send_failed(self.handles[index], now_ns);
    }
}

/// The send just submitted has the buffer until its final event, and speaks for this attempt.
pub fn lend(self: anytype, index: usize) void {
    assert(!self.send_in_flight[index]);
    self.send_in_flight[index] = true;
    self.send_owner[index] = owner_of(self, index);
}

fn owner_of(self: anytype, index: usize) Owner {
    const handle = self.handles[index];
    return .{ .handle = handle, .transaction = self.resolver.lookup_of(handle).transaction };
}

/// Whether the attempt `owner` names is still the slot's: the same lookup, not ended, on the
/// same transaction.
fn is_current(self: anytype, index: usize, owner: Owner) bool {
    if (!self.slots[index].occupied or self.handles[index] != owner.handle) return false;
    const lookup = self.resolver.lookup_of(owner.handle);
    if (lookup.is_settled()) return false;
    return std.meta.eql(lookup.transaction, owner.transaction);
}

/// A send's final event: the buffer comes back, the attempt that made the send hears how it
/// went if it is still the lookup's, and a held send goes out if its attempt still is.
pub fn on_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    assert(index < self.slots.len);
    // Every send the engine submits lends the buffer, and only its final event returns it.
    assert(self.send_in_flight[index]);
    self.send_in_flight[index] = false;
    const owner = self.send_owner[index];
    self.send_owner[index] = null;
    if (owner) |made| {
        if (is_current(self, index, made)) {
            if (event.outcome()) |_| {
                self.resolver.on_sent(made.handle, now_ns);
            } else |_| {
                self.resolver.on_send_failed(made.handle, now_ns);
            }
        }
    }
    flush(self, index, now_ns);
}

/// The held send goes out, if the attempt that asked for it is still the lookup's; otherwise
/// it is dropped, and the lookup's next poll asks again.
fn flush(self: anytype, index: usize, now_ns: u64) void {
    const held = self.held[index] orelse return;
    self.held[index] = null;
    if (!is_current(self, index, held.owner)) return;
    const bytes = self.held_buffers[index][0..held.len];
    submit(self, index, if (held.tcp) .{ .tcp = bytes } else .{ .udp = .{ .server = held.to, .bytes = bytes } }, now_ns);
}

/// Forgets every attempt the table had, which `reinit` does: a send in flight still has its
/// buffer until its final event, and that event speaks for nobody.
pub fn forget_all(self: anytype) void {
    self.send_owner = @splat(null);
    self.held = @splat(null);
}
