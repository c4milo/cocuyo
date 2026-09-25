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
const queue_module = @import("io_tcp_queue.zig");
const tls_module = @import("io_tls.zig");

pub const Error = error{SocketFailed};

/// One connection, the queries waiting to go out on it, and the bytes it has read and not yet
/// framed. `message_bytes` is what it can assemble: the longest a length prefix can describe,
/// unless the caller knows its answers are smaller and would rather not hold 64 KiB a
/// connection. `lookups` is the table's size, which bounds its queue. `Tls` is the session type
/// of docs/design.md §21, `io_tls.None` when the engine speaks no TLS.
pub fn Connection(comptime message_bytes: u32, comptime lookups: u16, comptime Tls: type) type {
    return struct {
        const Self = @This();
        /// Over TLS a connection handshakes before it is up, says `close_notify` before an idle
        /// close, and waits to connect again in full after a resumed handshake failed (§21, TLS
        /// rules 1, 5 and 8).
        pub const State = enum { closed, connecting, handshaking, up, closing, reopening };

        state: State = .closed,
        /// The configured server it goes to. Meaningless while closed.
        server: u8 = 0,
        descriptor: ?rotor.Descriptor = null,
        /// The operation in flight on it: the connect, and then the receive that replaces it. One at
        /// a time, so one handle names it, and cancelling it is what ends it (rotor decision 5).
        handle: ?rotor.Handle = null,
        /// The connect operation borrows this until its event arrives (rotor decision 5, rule 3).
        address: rotor.Address = undefined,
        /// Whether a connect is in flight from this slot, of whichever opening: until its event,
        /// the slot is not opened again, since the loop may still read `address` (docs/design.md
        /// §19 step 13, the stream's rule 10). It outlives the connection, for that reason.
        connect_in_flight: bool = false,
        /// The partial message: a length prefix and as much of the body as has arrived.
        frame: [message_bytes]u8 = undefined,
        used: usize = 0,
        receiving: bool = false,
        /// How many lookups are on it. One with none is closed when it has been idle long enough.
        users: u16 = 0,
        idle_since_ns: u64 = 0,
        /// Which opening of the slot this is. Every operation on the connection carries it, so
        /// the event of an opening that is gone is told from the current one's (docs/design.md
        /// §19 step 13, the stream's rule 2). It outlives the connection, for that reason.
        incarnation: u32 = 0,
        /// What waits to go out, oldest first, and how much of the head has gone. The head's
        /// send is in flight while `sending` (`io_tcp_queue.zig`).
        queue: queue_module.Queue(lookups + constants.tls_records_entries_max) = .{},
        sent_bytes: u16 = 0,
        sending: bool = false,
        /// Whether a send of the TLS session's records is in flight from this slot, of whichever
        /// opening: the records buffer is the loop's until its event, so the slot is not opened
        /// again (§21, TLS rule 3). It outlives the connection, as `connect_in_flight` does.
        records_in_flight: bool = false,
        tls: tls_module.State(Tls) = .{},

        /// Whether the loop still holds memory of the slot's, of whichever opening.
        pub fn borrowed(self: *const Self) bool {
            return self.connect_in_flight or self.records_in_flight;
        }

        /// A new opening of the slot: everything reset but what outlives an opening.
        pub fn restart(self: *Self) void {
            const incarnation = self.incarnation;
            const connect_in_flight = self.connect_in_flight;
            const records_in_flight = self.records_in_flight;
            self.tls.session.wipe();
            self.* = .{};
            self.incarnation = incarnation;
            self.connect_in_flight = connect_in_flight;
            self.records_in_flight = records_in_flight;
        }
    };
}

/// Whether a connection in `state` reads what its server sends: while it handshakes and once it
/// is up (§21, TLS rule 1).
fn reads(state: anytype) bool {
    return state == .handshaking or state == .up;
}

/// The chunks a connection reads into (`io_tcp_group.zig`).
pub const Group = @import("io_tcp_group.zig").Group;

// What a lookup asks for.

/// The lookup at `index` needs a stream to its current server. It is put on that server's
/// connection, which is opened if there is none; a connection that is already up is reported at
/// once, and one still connecting reports when its event arrives. A lookup that cannot be given
/// one is told, and fails over to the next server, as it is by an engine that keeps none.
pub fn want(self: anytype, index: usize, now_ns: u64) void {
    const handle = self.handles[index];
    if (comptime !@TypeOf(self.*).keeps_tcp) return self.resolver.on_tcp_failed(handle, now_ns);
    const server = self.resolver.lookup_of(handle).server_slot();
    const at = attach(self, index, server, now_ns) orelse {
        self.resolver.on_tcp_failed(handle, now_ns);
        return;
    };
    if (self.connections[at].state == .up) self.resolver.on_tcp_connected(handle, now_ns);
}

/// Puts the lookup on its server's connection, opening one if a slot can be had.
fn attach(self: anytype, index: usize, server: u8, now_ns: u64) ?u8 {
    if (self.tcp_connection[index]) |at| return at;
    const at = find(self, server) orelse open(self, server, now_ns) catch return null;
    self.tcp_connection[index] = at;
    self.connections[at].users += 1;
    return at;
}

/// The connection to `server`, if one is open or opening: not one that is closing (§21, TLS
/// rule 5).
fn find(self: anytype, server: u8) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed or connection.state == .closing) continue;
        if (connection.server == server) return @intCast(at);
    }
    return null;
}

/// Opens a connection to `server` in a free slot and submits the connect. Over TLS the opening
/// resumes with the server's ticket when one is kept (§21, TLS rule 8).
fn open(self: anytype, server: u8, now_ns: u64) Error!u8 {
    const at = free_slot(self) orelse return error.SocketFailed;
    try connect(self, at, server);
    if (tls_module.speaks(self)) tls_module.spend(self, at, server, now_ns);
    return at;
}

/// A socket for `server` in slot `at`, and its connect submitted: a new opening of the slot,
/// keeping the lookups on it and how long it has been idle. A socket or a connect refused leaves
/// the slot closed.
fn connect(self: anytype, at: u8, server: u8) Error!void {
    const connection = &self.connections[at];
    // Nothing the loop holds names this slot's memory (rule 10, and §21's TLS rule 3).
    assert(!connection.borrowed());
    const endpoint = self.config.servers[server].tcp_endpoint();
    const descriptor = rotor.sync.open_socket(family_of(endpoint)) catch return error.SocketFailed;
    udp.size_buffers(descriptor, self.config);
    const users = connection.users;
    const idle_since_ns = connection.idle_since_ns;
    connection.restart();
    connection.incarnation +%= 1;
    connection.state = .connecting;
    connection.server = server;
    connection.descriptor = descriptor;
    connection.address = udp.address_of(endpoint);
    connection.users = users;
    connection.idle_since_ns = idle_since_ns;
    const operation: rotor.Operation = .connect(user_data_of(self, .tcp_connect, at), descriptor, &connection.address);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) != 1) {
        rotor.sync.close_now(descriptor);
        connection.restart();
        return error.SocketFailed;
    }
    connection.handle = handles[0];
    connection.connect_in_flight = true;
}

/// A slot with no connection in it: one that is closed, or one nobody is using, which is closed
/// to make room. A connection with lookups on it is never taken, and neither is a slot whose
/// memory the loop still borrows (the stream's rule 10). A TLS connection is never closed to make
/// room (§21, TLS rule 6).
fn free_slot(self: anytype) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed and !connection.borrowed()) return @intCast(at);
    }
    if (tls_module.speaks(self)) return null;
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.users == 0 and !connection.borrowed()) {
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

/// Takes the lookup off its connection unless it is on a stream to that connection's server
/// (the stream's rule 3): its deadline passed, its connection failed, it moved to the next name,
/// or it ended. What it asks for next is then asked of the right server's connection.
pub fn follow(self: anytype, index: usize, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    const at = self.tcp_connection[index] orelse return;
    const lookup = self.resolver.lookup_of(self.handles[index]);
    if (lookup.is_on_stream() and self.connections[at].server == lookup.server_slot()) return;
    release(self, index, now_ns);
}

/// A lookup has ended or been freed: it is off its connection, which may now be idle, and a
/// query of its still waiting there goes with it.
pub fn release(self: anytype, index: usize, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    const at = self.tcp_connection[index] orelse return;
    self.tcp_connection[index] = null;
    queue_module.drop(self, at, index);
    const connection = &self.connections[at];
    assert(connection.users >= 1);
    connection.users -= 1;
    if (connection.users == 0) connection.idle_since_ns = now_ns;
}

// What the loop says.

/// The `user_data` of an operation on the connection in slot `at`: the slot, and its opening.
pub fn user_data_of(self: anytype, kind: @import("io.zig").Kind, at: u8) u64 {
    const incarnation: u64 = self.connections[at].incarnation;
    return @TypeOf(self.*).user_data(kind, (incarnation << constants.tcp_incarnation_shift) | at);
}

/// The slot of the connection an event is for, or null when the event is for an opening of the
/// slot that is gone. Such an event changes nothing, whatever it holds: a cancelled connect can
/// still end in success (rotor decision 5, rule 2). A buffer it carries goes back all the same.
pub fn current_of(self: anytype, index: usize, event: rotor.Event) ?u8 {
    const at: u8 = @intCast(index & constants.tcp_slot_mask);
    const incarnation: u32 = @truncate(index >> constants.tcp_incarnation_shift);
    assert(at < self.connections.len);
    const connection = &self.connections[at];
    // A connection waiting to be opened again has dropped its opening's operations (§21, TLS
    // rule 8): their events speak for nobody.
    const live = connection.state != .closed and connection.state != .reopening;
    if (live and connection.incarnation == incarnation) return at;
    if (event.flags.buffer) self.loop.give_back_buffer(constants.tcp_group_id, event.flags.buffer_id);
    return null;
}

/// The connect ended. Every lookup on the connection is told, one way or the other. Its one event
/// is its final one, so the slot's address is its own again whatever opening the event is for.
pub fn on_connect_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    const slot = &self.connections[index & constants.tcp_slot_mask];
    assert(slot.connect_in_flight);
    slot.connect_in_flight = false;
    const at = current_of(self, index, event) orelse {
        // A connect that is gone kept its slot closed until now (rule 10).
        assert(slot.state == .closed);
        return;
    };
    const connection = &self.connections[at];
    // The current opening has one connect, and the receive replaces it when it ends.
    assert(connection.state == .connecting);
    connection.handle = null;
    if (event.outcome()) |_| {
        connection.idle_since_ns = now_ns;
        // Over TLS the session starts, and its first flight goes; the lookups wait for the
        // handshake's end (§21, TLS rule 1).
        if (tls_module.speaks(self)) {
            connection.state = .handshaking;
            receive_again(self, @intCast(at));
            return tls_module.begin(self, @intCast(at), now_ns);
        }
        connection.state = .up;
        receive_again(self, @intCast(at));
        tell_all(self, @intCast(at), now_ns, true);
    } else |_| {
        fail(self, @intCast(at), now_ns);
    }
}

/// One chunk of a stream: kept with what came before it, and every whole message in them handed
/// to the table, which decides whose it is.
pub fn on_receive_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    const at = current_of(self, index, event) orelse return;
    const connection = &self.connections[at];
    // A connection has its receive while it handshakes, once it is up, and while it closes.
    assert(reads(connection.state) or connection.state == .closing);
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
    if (event.is_final() and !self.closing and connection.state != .closed) {
        connection.receiving = false;
        connection.handle = null;
        receive_again(self, @intCast(at));
    }
}

fn take_chunk(self: anytype, at: u8, event: rotor.Event, count: u32, now_ns: u64) void {
    const connection = &self.connections[at];
    const buffer = self.loop.provided_buffer(constants.tcp_group_id, event.flags.buffer_id);
    const chunk = buffer[0..count];
    // Over TLS the chunk is records, which the session opens into the frame (§21, TLS rule 7).
    if (tls_module.speaks(self)) {
        tls_module.take(self, at, chunk, now_ns);
        self.loop.give_back_buffer(constants.tcp_group_id, event.flags.buffer_id);
        return;
    }
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
pub fn deliver(self: anytype, at: u8, now_ns: u64) void {
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
    if (connection.receiving or !(reads(connection.state) or connection.state == .closing)) return;
    const descriptor = connection.descriptor orelse return;
    const operation: rotor.Operation = .receive_group(user_data_of(self, .tcp_receive, at), descriptor, constants.tcp_group_id);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) == 1) {
        connection.receiving = true;
        connection.handle = handles[0];
    }
}

/// Tells every lookup on the connection that it is up, or that it is not.
pub fn tell_all(self: anytype, at: u8, now_ns: u64, connected: bool) void {
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
pub fn fail(self: anytype, at: u8, now_ns: u64) void {
    tell_all(self, at, now_ns, false);
    for (self.tcp_connection[0..], 0..) |held, index| {
        if (held == at) self.tcp_connection[index] = null;
    }
    shut(self, at);
}

/// Ends a connection: the operation on it is cancelled, which is what makes the loop let it go
/// (rotor decision 5, rule 1), the queries waiting on it give their buffers back, and the socket
/// is closed. The events that follow name a connection that is closed, and are ignored.
pub fn shut(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    if (connection.handle) |handle| self.loop.cancel(handle);
    queue_module.release_all(self, at);
    if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    connection.restart();
}

/// A resumed handshake failed, which is not the server's failure (§21, TLS rule 8): the session
/// and its socket go, and the connection waits, its lookups still on it, to connect again in full
/// once the loop holds nothing of its slot's.
pub fn retry_full(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(connection.state == .handshaking);
    if (connection.handle) |handle| self.loop.cancel(handle);
    if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    const server = connection.server;
    const users = connection.users;
    const idle_since_ns = connection.idle_since_ns;
    connection.restart();
    connection.state = .reopening;
    connection.server = server;
    connection.users = users;
    connection.idle_since_ns = idle_since_ns;
    connect_again(self, at, now_ns);
}

/// A connection waiting to be opened again connects, in full, once the loop holds nothing of its
/// slot's (§21, TLS rule 8). A socket or a connect refused fails it, and its lookups hear so.
pub fn connect_again(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    if (connection.state != .reopening or connection.borrowed()) return;
    connect(self, at, connection.server) catch return fail(self, at, now_ns);
}

/// A receive for every connection that is up and has none: one the loop refused before is asked
/// for again, as a socket's is (docs/design.md §19 step 13, the datagram's rule 1).
pub fn tend(self: anytype) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..], 0..) |*connection, at| {
        if (reads(connection.state) and !connection.receiving) receive_again(self, @intCast(at));
    }
}

/// Closes every connection nobody is using and has not used for `tcp_idle_ns` (RFC 7766 §6.2.3).
pub fn close_idle(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed or connection.state == .closing or connection.users != 0) continue;
        if (now_ns -| connection.idle_since_ns < self.tcp_idle_ns) continue;
        // A TLS connection that is up says `close_notify`, and closes once it has gone; one whose
        // handshake has not ended has no session to close (§21, TLS rule 5).
        if (connection.state == .up and tls_module.speaks(self)) {
            tls_module.close(self, @intCast(at), now_ns);
            continue;
        }
        shut(self, @intCast(at));
    }
}

/// Ends every connection's operation, so the loop can be drained (rotor decision 5, rule 7).
/// The sockets stay open until `close_all`, which runs after the drain.
pub fn cancel_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..]) |*connection| {
        if (connection.state == .closed) continue;
        if (connection.handle) |handle| self.loop.cancel(handle);
        connection.handle = null;
        connection.receiving = false;
    }
}

/// Closes every connection's socket, whatever it was doing: the engine is going away.
pub fn close_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..], 0..) |*connection, at| {
        queue_module.release_all(self, @intCast(at));
        if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
        connection.restart();
    }
}
