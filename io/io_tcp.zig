//! The stream path of the engine (docs/design.md §19 step 13): the connections a lookup asks for
//! when a UDP answer came back truncated (RFC 7766 §5), or when a server refuses its cookie.
//!
//! One connection serves one server and every lookup that needs it, their queries pipelined onto
//! it and their answers matched back by the table's own demultiplexer (RFC 7766 §6.2.1.1). A
//! stream carries no message boundaries, so each message is a two-octet length and that many
//! octets after it (§8), and this file holds the partial bytes until a whole one is there. A
//! connection nobody is using is closed once `tcp_idle_ns` has passed, which §6.2.3 asks a client
//! to keep short.
//!
//! Free functions over the engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");

pub const Error = error{SocketFailed};

/// One connection, and the bytes it has read and not yet framed. `message_bytes` is what it can
/// assemble: the longest a length prefix can describe, unless the caller knows its answers are
/// smaller and would rather not hold 64 KiB a connection.
pub fn Connection(comptime message_bytes: u32) type {
    return struct {
        const Self = @This();
        pub const State = enum { closed, connecting, up };

        state: State = .closed,
        /// The configured server it goes to. Meaningless while closed.
        server: u8 = 0,
        descriptor: ?rotor.Descriptor = null,
        /// The operation in flight on it: the connect, and then the receive that replaces it. One at
        /// a time, so one handle names it, and cancelling it is what ends it (rotor decision 5).
        handle: ?rotor.Handle = null,
        /// The connect operation borrows this until its event arrives (rotor decision 5, rule 3).
        address: rotor.Address = undefined,
        /// The partial message: a length prefix and as much of the body as has arrived.
        frame: [message_bytes]u8 = undefined,
        used: usize = 0,
        receiving: bool = false,
        /// How many lookups are on it. One with none is closed when it has been idle long enough.
        users: u16 = 0,
        idle_since_ns: u64 = 0,
    };
}

/// The chunks a connection reads into: a group of its own, because a datagram group carries
/// rotor's prefix before every payload and a stream has no peer to name.
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

// What a lookup asks for.

/// The lookup at `index` needs a stream to its current server. It is put on that server's
/// connection, which is opened if there is none; a connection that is already up is reported at
/// once, and one still connecting reports when its event arrives. A lookup that cannot be given
/// one is told, and fails over to the next server.
pub fn want(self: anytype, index: usize, now_ns: u64) void {
    const handle = self.handles[index];
    const server = self.resolver.lookup_of(handle).server_slot();
    const at = attach(self, index, server) orelse {
        self.resolver.on_tcp_failed(handle, now_ns);
        return;
    };
    if (self.connections[at].state == .up) self.resolver.on_tcp_connected(handle, now_ns);
}

/// Puts the lookup on its server's connection, opening one if a slot can be had.
fn attach(self: anytype, index: usize, server: u8) ?u8 {
    if (self.tcp_connection[index]) |at| return at;
    const at = find(self, server) orelse open(self, server) catch return null;
    self.tcp_connection[index] = at;
    self.connections[at].users += 1;
    return at;
}

/// The connection to `server`, if one is open or opening.
fn find(self: anytype, server: u8) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed) continue;
        if (connection.server == server) return @intCast(at);
    }
    return null;
}

/// Opens a connection to `server` in a free slot and submits the connect.
fn open(self: anytype, server: u8) Error!u8 {
    const at = free_slot(self) orelse return error.SocketFailed;
    const connection = &self.connections[at];
    const endpoint = self.config.servers[server].tcp_endpoint();
    const descriptor = rotor.sync.open_socket(family_of(endpoint)) catch return error.SocketFailed;
    udp.size_buffers(descriptor, self.config);
    connection.* = .{
        .state = .connecting,
        .server = server,
        .descriptor = descriptor,
        .address = udp.address_of(endpoint),
    };
    const operation: rotor.Operation = .connect(
        @TypeOf(self.*).user_data(.tcp_connect, at),
        descriptor,
        &connection.address,
    );
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) != 1) {
        rotor.sync.close_now(descriptor);
        connection.* = .{};
        return error.SocketFailed;
    }
    connection.handle = handles[0];
    return at;
}

/// A slot with no connection in it: one that is closed, or one nobody is using, which is closed
/// to make room. A connection with lookups on it is never taken.
fn free_slot(self: anytype) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed) return @intCast(at);
    }
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.users == 0) {
            shut(self, @intCast(at));
            return @intCast(at);
        }
    }
    return null;
}

fn family_of(endpoint: cocuyo.Endpoint) rotor.Address.Family {
    return switch (endpoint.address.family) {
        .ipv4 => .ipv4,
        .ipv6 => .ipv6,
    };
}

/// Sends one lookup's framed query on its connection. The bytes carry the length prefix that
/// `poll` wrote (RFC 7766 §8), and the lookup's own send buffer holds them until the send ends.
pub fn send(self: anytype, index: usize, bytes: []const u8, now_ns: u64) void {
    const handle = self.handles[index];
    const at = self.tcp_connection[index] orelse {
        self.resolver.on_tcp_failed(handle, now_ns);
        return;
    };
    const connection = &self.connections[at];
    if (connection.state != .up or connection.descriptor == null) {
        self.resolver.on_tcp_failed(handle, now_ns);
        return;
    }
    assert(bytes.len <= cocuyo.constants.query_bytes_max);
    @memcpy(self.send_buffers[index][0..bytes.len], bytes);
    const operation: rotor.Operation = .send(
        @TypeOf(self.*).user_data(.tcp_send, index),
        connection.descriptor.?,
        self.send_buffers[index][0..bytes.len],
    );
    if (self.loop.submit(&.{operation}, &.{}) == 1) {
        self.send_in_flight[index] = true;
    } else {
        self.resolver.on_send_failed(handle, now_ns);
    }
}

/// A lookup has ended or been freed: it is off its connection, which may now be idle.
pub fn release(self: anytype, index: usize, now_ns: u64) void {
    const at = self.tcp_connection[index] orelse return;
    self.tcp_connection[index] = null;
    const connection = &self.connections[at];
    assert(connection.users >= 1);
    connection.users -= 1;
    if (connection.users == 0) connection.idle_since_ns = now_ns;
}

// What the loop says.

/// The connect ended. Every lookup on the connection is told, one way or the other.
pub fn on_connect_event(self: anytype, at: usize, event: rotor.Event, now_ns: u64) void {
    assert(at < self.connections.len);
    const connection = &self.connections[at];
    if (connection.state != .connecting) return;
    connection.handle = null;
    if (event.outcome()) |_| {
        connection.state = .up;
        connection.idle_since_ns = now_ns;
        receive_again(self, @intCast(at));
        tell_all(self, @intCast(at), now_ns, true);
    } else |_| {
        fail(self, @intCast(at), now_ns);
    }
}

/// One chunk of a stream: kept with what came before it, and every whole message in them handed
/// to the table, which decides whose it is.
pub fn on_receive_event(self: anytype, at: usize, event: rotor.Event, now_ns: u64) void {
    assert(at < self.connections.len);
    const connection = &self.connections[at];
    // An event for a connection that has been closed names one that is gone: its cancel and its
    // close were asked for together, and this is what they answer with.
    if (connection.state == .closed) return;
    if (event.outcome()) |count| {
        // Zero is the peer closing its side, which ends every lookup on the connection.
        if (count == 0) return fail(self, @intCast(at), now_ns);
        take_chunk(self, @intCast(at), event, count, now_ns);
    } else |err| {
        // A group with no buffer left is not a broken connection: the multishot ends, the bytes
        // wait, and the receive below takes them. A stream is cut into chunks the reader does
        // not choose, so this is the ordinary way a busy connection ends its receive.
        if (err != error.BuffersExhausted) return fail(self, @intCast(at), now_ns);
    }
    if (event.is_final() and !self.closing and connection.state == .up) {
        connection.receiving = false;
        connection.handle = null;
        receive_again(self, @intCast(at));
    }
}

fn take_chunk(self: anytype, at: u8, event: rotor.Event, count: u32, now_ns: u64) void {
    const connection = &self.connections[at];
    const buffer = self.loop.provided_buffer(constants.tcp_group_id, event.flags.buffer_id);
    const chunk = buffer[0..count];
    const fits = connection.used + chunk.len <= connection.frame.len;
    if (fits) {
        @memcpy(connection.frame[connection.used..][0..chunk.len], chunk);
        connection.used += chunk.len;
    }
    self.loop.give_back_buffer(constants.tcp_group_id, event.flags.buffer_id);
    // A message longer than the buffer cannot be assembled, and the stream cannot be resynced
    // after it: the connection is no good to anybody.
    if (!fits) return fail(self, at, now_ns);
    deliver(self, at, now_ns);
}

/// Hands over every whole message the connection holds, oldest first.
fn deliver(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    const from = self.config.servers[connection.server].tcp_endpoint();
    var delivered: usize = 0;
    while (delivered < constants.tcp_messages_per_chunk_max) : (delivered += 1) {
        const prefix = cocuyo.constants.tcp_prefix_bytes;
        if (connection.used < prefix) return;
        const length = cocuyo.message_len(connection.frame[0..prefix]);
        if (connection.used < prefix + length) return;
        _ = self.resolver.on_datagram(connection.frame[prefix..][0..length], from, now_ns);
        const whole = prefix + length;
        std.mem.copyForwards(u8, connection.frame[0 .. connection.used - whole], connection.frame[whole..connection.used]);
        connection.used -= whole;
    }
}

/// Arms the connection's multishot receive, which every answer on it arrives through.
fn receive_again(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    if (connection.receiving or connection.state != .up) return;
    const descriptor = connection.descriptor orelse return;
    const operation: rotor.Operation = .receive_group(
        @TypeOf(self.*).user_data(.tcp_receive, at),
        descriptor,
        constants.tcp_group_id,
    );
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) == 1) {
        connection.receiving = true;
        connection.handle = handles[0];
    }
}

/// Tells every lookup on the connection that it is up, or that it is not.
fn tell_all(self: anytype, at: u8, now_ns: u64, connected: bool) void {
    for (self.tcp_connection[0..], 0..) |held, index| {
        if (held != at) continue;
        if (!self.slots[index].occupied) continue;
        const handle = self.handles[index];
        // Only a lookup that is on the stream hears this: one that moved on has a server of its
        // own now, and telling it would be telling it about somebody else's connection.
        if (!self.resolver.lookup_of(handle).is_on_stream()) continue;
        if (connected) {
            self.resolver.on_tcp_connected(handle, now_ns);
        } else {
            self.resolver.on_tcp_failed(handle, now_ns);
        }
    }
}

/// The connection is no good: every lookup on it is told, and it is closed.
fn fail(self: anytype, at: u8, now_ns: u64) void {
    tell_all(self, at, now_ns, false);
    for (self.tcp_connection[0..], 0..) |held, index| {
        if (held == at) self.tcp_connection[index] = null;
    }
    shut(self, at);
}

/// Ends a connection: the operation on it is cancelled, which is what makes the loop let it go
/// (rotor decision 5, rule 1), and the socket is closed. The events that follow name a
/// connection that is closed, and are ignored.
fn shut(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    if (connection.handle) |handle| self.loop.cancel(handle);
    if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    connection.* = .{};
}

/// Closes every connection nobody is using and has not used for `tcp_idle_ns` (RFC 7766 §6.2.3).
pub fn close_idle(self: anytype, now_ns: u64) void {
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed or connection.users != 0) continue;
        if (now_ns -| connection.idle_since_ns < self.tcp_idle_ns) continue;
        shut(self, @intCast(at));
    }
}

/// Ends every connection's operation, so the loop can be drained (rotor decision 5, rule 7).
/// The sockets stay open until `close_all`, which runs after the drain.
pub fn cancel_all(self: anytype) void {
    for (self.connections[0..]) |*connection| {
        if (connection.state == .closed) continue;
        if (connection.handle) |handle| self.loop.cancel(handle);
        connection.handle = null;
        connection.receiving = false;
    }
}

/// Closes every connection's socket, whatever it was doing: the engine is going away.
pub fn close_all(self: anytype) void {
    for (self.connections[0..]) |*connection| {
        if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
        connection.* = .{};
    }
}
