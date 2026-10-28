//! The stream path of the engine (docs/design.md §19 step 13): the connections a lookup asks for
//! when a UDP answer came back truncated (RFC 7766 §5), or when a server refuses its cookie. A
//! connection serves one server and each lookup that joins it, their queries pipelined onto it and
//! their answers matched back by the table's own demultiplexer (RFC 7766 §6.2.1.1). Each message
//! is a two-octet length and that many octets after it (§8), and `io_tcp_frame.zig` holds the
//! partial bytes until a whole one is there. A connection nobody is using is closed once
//! `tcp_idle_ns` has passed, which §6.2.3 asks a client to keep short. Free functions over the
//! engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const udp = @import("io_udp.zig");
const queue_module = @import("io_tcp_queue.zig");
const tls_module = @import("io_tls.zig");
const frame_module = @import("io_tcp_frame.zig");
const reset = @import("io_reset.zig");
const wait_module = @import("io_tcp_wait.zig");
const mark_module = @import("io_tcp_mark.zig");

pub const Error = error{SocketFailed};
/// What asking for a connection can meet: a socket or a connect refused, or no free slot.
pub const OpenError = error{ SocketFailed, NoSlot };

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
        /// The longest message the connection assembles. A prefix that says more fails it.
        pub const message_bytes_max: usize = message_bytes;
        /// What the frame holds past its partial message: what one take adds. That is a chunk in
        /// the clear, and a record's body over TLS (§19 step 13, the stream's rule 11).
        const room_bytes = if (Tls.enabled) limits.tls_frame_room_bytes_max else limits.tcp_frame_room_bytes_max;
        pub const frame_bytes: usize = cocuyo.constants.tcp_prefix_bytes + message_bytes + room_bytes;

        comptime {
            // The loop over the frame ends at the last whole message, never at its bound.
            assert(frame_bytes / cocuyo.constants.tcp_prefix_bytes <= limits.tcp_messages_per_frame_max);
        }

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
        /// The partial message: a length prefix and as much of the body as has arrived. It holds
        /// the prefix beside the longest message, so that message can be whole in it, and the
        /// room one take adds past it.
        frame: [frame_bytes]u8 = undefined,
        used: usize = 0,
        receiving: bool = false,
        /// How many lookups are on it. One with none is closed when it has been idle long enough.
        users: u16 = 0,
        /// No lookup joins it, since one left during its query's send (`io_tcp_mark.zig`).
        marked: bool = false,
        /// The instant from which the idle close's wait counts while no lookup is on it. Its
        /// connect's success sets it. So do its last lookup's leave and the start of its close (the
        /// stream's rule 4, §21's TLS rule 5).
        idle_since_ns: u64 = 0,
        /// Which opening of the slot this is. Every operation on the connection carries it, so
        /// the event of an opening that is gone is told from the current one's (docs/design.md
        /// §19 step 13, the stream's rule 2). It outlives the connection, for that reason.
        incarnation: u32 = 0,
        /// What waits to go out, oldest first, and how much of the head has gone. The head's
        /// send is in flight while `sending` (`io_tcp_queue.zig`).
        queue: queue_module.Queue(lookups + limits.tls_records_entries_max) = .{},
        sent_bytes: u16 = 0,
        sending: bool = false,
        /// The head's send in flight: a connection carries one at a time (the stream's rule 9). A
        /// send to a peer that stops reading ends only at its cancel. So each way that ends the
        /// connection cancels it: `shut`, `retry_full` and `cancel_all` (docs/design.md §16
        /// decision 49).
        send_handle: ?rotor.Handle = null,
        /// The send in flight from this slot's TLS records buffer, of whichever opening. It names
        /// the table slot of a query whose sealed records it sends, or `records` of
        /// `io_tcp_queue_ring.zig` for the session's own records. The buffer is the loop's until
        /// that send's final event, so the slot is not opened again (§21, TLS rule 3). It outlives
        /// the connection, as `connect_in_flight` does.
        records_send: ?u16 = null,
        tls: tls_module.State(Tls) = .{},

        /// Whether the loop still holds memory of the slot's, of whichever opening.
        pub fn borrowed(self: *const Self) bool {
            return self.connect_in_flight or self.records_send != null;
        }

        /// A new opening of the slot: every field back to its default but what outlives an
        /// opening, and the frame, the address and the queue's entries, whose bytes nothing reads
        /// before it writes them again. Set field by field, the slot writes none of them: assigned
        /// whole, it wrote all of the frame in a safe build, and wrote over the address a cancelled
        /// connect still borrows (docs/design.md §19 step 13, the stream's rule 10). The TLS state
        /// keeps its records the same way (`io_tls.reset`).
        pub fn restart(self: *Self) void {
            tls_module.reset(self);
            reset.defaults_except(@TypeOf(self.queue), &self.queue, &.{"items"});
            reset.defaults_except(Self, self, &.{ "incarnation", "connect_in_flight", "records_send", "address", "frame", "queue", "tls" });
        }
    };
}

/// Whether a connection in `state` reads what its server sends (§21, TLS rule 1).
fn reads(state: anytype) bool {
    return state == .handshaking or state == .up;
}

/// The chunks a connection reads into (`io_tcp_group.zig`).
pub const Group = @import("io_tcp_group.zig").Group;

/// The drive's end, which admits each lookup that waits for a slot (`io_tcp_wait.zig`).
pub const admit = wait_module.admit;

// What a lookup asks for.

/// The lookup at `index` needs a stream to its current server: it joins that server's connection,
/// or opens one. One up is reported at once, and one still connecting at its event. With no slot
/// free, it waits for a pending slot, or for a marked connection's (the stream's rule 12, §16
/// decision 54). The drive's end admits it, or its deadline moves it on. A lookup that can have no
/// slot, or whose socket or connect is refused, is told `local`, and fails over to the next
/// server (docs/design.md §5, The cause of a failure).
pub fn want(self: anytype, index: usize, now_ns: u64) void {
    const handle = self.handles[index];
    if (comptime !@TypeOf(self.*).keeps_tcp) return self.resolver.on_tcp_failed(handle, .local, now_ns);
    const server = self.resolver.lookup_of(handle).server_slot();
    const at = attach(self, index, server, now_ns) catch |err| {
        if (err == error.NoSlot and wait_module.pending(self)) return wait_module.wait(self, index);
        if (err == error.NoSlot and mark_module.holds_slot(self)) return wait_module.wait(self, index);
        return self.resolver.on_tcp_failed(handle, .local, now_ns);
    };
    if (self.connections[at].state == .up) self.resolver.on_tcp_connected(handle, now_ns);
}

/// Puts the lookup on its server's connection, opening one if a slot can be had.
pub fn attach(self: anytype, index: usize, server: u8, now_ns: u64) OpenError!u8 {
    if (self.tcp_connection[index]) |at| return at;
    const at = find(self, server) orelse try open(self, server, now_ns);
    self.tcp_connection[index] = at;
    self.connections[at].users += 1;
    return at;
}

/// The connection to `server` that a lookup may join: open or opening, and neither closing (§21,
/// TLS rule 5) nor marked (docs/design.md §16 decision 54).
fn find(self: anytype, server: u8) ?u8 {
    for (self.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed or connection.state == .closing or connection.marked) continue;
        if (connection.server == server) return @intCast(at);
    }
    return null;
}

/// Opens a connection to `server` in a free slot and submits the connect. Over TLS the opening
/// resumes with the server's ticket when one is kept (§21, TLS rule 8).
fn open(self: anytype, server: u8, now_ns: u64) OpenError!u8 {
    const at = free_slot(self) orelse return error.NoSlot;
    try connect(self, at, server);
    if (tls_module.speaks(self)) tls_module.spend(self, at, server, now_ns);
    return at;
}

/// A socket for `server` in slot `at`, and its connect submitted: a new opening of the slot that
/// keeps its lookups and its idle instant. A socket or a connect refused leaves the slot closed.
fn connect(self: anytype, at: u8, server: u8) Error!void {
    const connection = &self.connections[at];
    // Nothing the loop holds names this slot's memory (rule 10, and §21's TLS rule 3).
    assert(!connection.borrowed());
    const endpoint = self.config.servers[server].tcp_endpoint();
    const descriptor = rotor.sync.open_socket(udp.family_of(endpoint)) catch return error.SocketFailed;
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
/// memory the loop still borrows (the stream's rule 10). With none, and no slot pending, a
/// connection nobody is using whose connect is in flight is closed, so that its slot is pending
/// (rule 12). A TLS connection is never closed to make room (§21, TLS rule 6).
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
    wait_module.make_pending(self);
    return null;
}

/// Takes the lookup off its connection unless it is on a stream to that connection's server
/// (the stream's rule 3): its deadline passed, its connection failed, it moved to the next name,
/// or it ended. What it asks for next is then asked of the right server's connection. A lookup
/// that acts no longer waits for a slot (rule 12).
pub fn follow(self: anytype, index: usize, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    wait_module.unwait(self, index);
    const at = self.tcp_connection[index] orelse return;
    const lookup = self.resolver.lookup_of(self.handles[index]);
    if (lookup.is_on_stream() and self.connections[at].server == lookup.server_slot()) return;
    release(self, index, now_ns);
}

/// A lookup has ended or been freed: it is off its connection, with its query that waits there.
/// When none stays during a query's send, the shut cancels that send, which a peer that does not
/// read never ends (docs/design.md §16 decision 53). `io_tcp_mark.leave` marks it (decision 54).
pub fn release(self: anytype, index: usize, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    const at = self.tcp_connection[index] orelse return;
    self.tcp_connection[index] = null;
    queue_module.drop(self, at, index);
    const connection = &self.connections[at];
    assert(connection.users >= 1);
    connection.users -= 1;
    if (connection.users == 0) connection.idle_since_ns = now_ns;
    if (connection.users == 0 and queue_module.query_in_flight(self, at)) shut(self, at);
    mark_module.leave(self, at, index, now_ns);
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
        tell_all(self, @intCast(at), now_ns, null);
    } else |_| {
        fail(self, @intCast(at), .connect, now_ns);
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
        if (count == 0) return fail(self, @intCast(at), reason_of(self, @intCast(at), .handshake), now_ns);
        frame_module.take_chunk(self, @intCast(at), event, count, now_ns);
    } else |err| {
        // A group with no buffer left is not a broken connection: the multishot ends, the bytes
        // wait, and the receive below takes them. A stream is cut into chunks the reader does
        // not choose, so this is the ordinary way a busy connection ends its receive.
        if (err != error.BuffersExhausted) return fail(self, @intCast(at), reason_of(self, @intCast(at), .handshake), now_ns);
    }
    if (event.is_final() and !self.closing and connection.state != .closed) {
        connection.receiving = false;
        connection.handle = null;
        receive_again(self, @intCast(at));
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

/// Tells every lookup on the connection that it is up, when `failed` is null, or that it failed for
/// `failed` (docs/design.md §5, The cause of a failure).
pub fn tell_all(self: anytype, at: u8, now_ns: u64, failed: ?cocuyo.Reason) void {
    for (self.tcp_connection[0..], 0..) |held, index| {
        if (held != at) continue;
        if (!self.slots[index].occupied) continue;
        const handle = self.handles[index];
        // Only a lookup that is on the stream hears this: one that moved on has a server of its
        // own now, and telling it would be telling it about somebody else's connection.
        if (!self.resolver.lookup_of(handle).is_on_stream()) continue;
        if (failed) |reason| {
            self.resolver.on_tcp_failed(handle, reason, now_ns);
        } else {
            self.resolver.on_tcp_connected(handle, now_ns);
        }
    }
}

/// The connection is no good, for `reason`: every lookup on it is told, and it is closed.
pub fn fail(self: anytype, at: u8, reason: cocuyo.Reason, now_ns: u64) void {
    abandon(self, at, reason, now_ns);
    shut(self, at);
}

/// Every lookup on the connection is told it failed, for `reason`, and leaves it (`reason_of`).
pub fn abandon(self: anytype, at: u8, reason: cocuyo.Reason, now_ns: u64) void {
    const state = self.connections[at].state;
    assert(state == .closing or (state == .up) == (reason == .closed));
    tell_all(self, at, now_ns, reason);
    for (self.tcp_connection[0..], 0..) |held, index| {
        if (held == at) self.tcp_connection[index] = null;
    }
    self.connections[at].users = 0;
}

/// Ends a connection. Each operation on it is cancelled, which is what makes the loop let it go
/// (rotor decision 5, rule 1). The queries waiting on it give their buffers back, and the socket
/// is closed. The events that follow name a connection that is closed, and are ignored. The send
/// keeps what it reads lent until its cancel's event (§21, TLS rule 3; the stream's rule 6). That
/// is the slot's records buffer over TLS, and its lookup's own buffer in the clear.
pub fn shut(self: anytype, at: u8) void {
    const connection = &self.connections[at];
    // A send is in flight exactly while its handle is kept (the stream's rule 9).
    assert(connection.sending == (connection.send_handle != null));
    if (connection.handle) |handle| self.loop.cancel(handle);
    if (connection.send_handle) |handle| self.loop.cancel(handle);
    queue_module.release_all(self, at);
    if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    connection.restart();
}

/// A resumed handshake failed, which is not the server's failure (§21, TLS rule 8). The session
/// and its socket go. The connection waits, its lookups still on it, to connect again in full once
/// the loop holds nothing of its slot's. A send in flight is cancelled, so the loop gives the
/// records buffer back at the cancel's event (docs/design.md §16 decision 49).
pub fn retry_full(self: anytype, at: u8, now_ns: u64) void {
    const connection = &self.connections[at];
    assert(connection.state == .handshaking);
    // A send is in flight exactly while its handle is kept (the stream's rule 9).
    assert(connection.sending == (connection.send_handle != null));
    if (connection.handle) |handle| self.loop.cancel(handle);
    // A peer that stops reading never ends a send of the session's records. The connection waits
    // for that send's event to connect again (TLS rules 3 and 8).
    if (connection.send_handle) |handle| self.loop.cancel(handle);
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
    connect(self, at, connection.server) catch return fail(self, at, .local, now_ns);
}

/// The reason a failure of the connection in slot `at` gives its lookups: `closed` once it is up,
/// and `before` until then (docs/design.md §5, The cause of a failure).
pub fn reason_of(self: anytype, at: u8, before: cocuyo.Reason) cocuyo.Reason {
    assert(before != .closed);
    return if (self.connections[at].state == .up) .closed else before;
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
/// A TLS connection that closes is idle from the instant it began to close, and the same wait
/// bounds it (docs/design.md §16 decision 49).
pub fn close_idle(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..], 0..) |*connection, at| {
        // No lookup is on a connection that closes, and none joins it (§21, TLS rules 4 and 5).
        assert(connection.state != .closing or connection.users == 0);
        if (connection.state == .closed or connection.users != 0) continue;
        if (now_ns -| connection.idle_since_ns < self.tcp_idle_ns) continue;
        // A TLS connection that is up says `close_notify`, and closes once it has gone; one whose
        // handshake has not ended has no session to close (§21, TLS rule 5).
        if (connection.state == .up and tls_module.speaks(self)) {
            tls_module.close(self, @intCast(at), now_ns);
            continue;
        }
        // One that closes has had the wait for its last send, which a peer that stops reading
        // never ends. The shut cancels that send, and the slot frees at the cancel's event.
        shut(self, @intCast(at));
    }
}

/// Ends each operation of every connection, its send among them, so the loop can be drained
/// (rotor decision 5, rule 7). The sockets stay open until `close_all`, after the drain or at a
/// `reinit`. The send's fields stay for its event or for `close_all` (§16 decision 49).
pub fn cancel_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).keeps_tcp) return;
    for (self.connections[0..]) |*connection| {
        if (connection.state == .closed) continue;
        // A send is in flight exactly while its handle is kept (the stream's rule 9).
        assert(connection.sending == (connection.send_handle != null));
        if (connection.handle) |handle| self.loop.cancel(handle);
        connection.handle = null;
        connection.receiving = false;
        // A send to a peer that stops reading ends only at its cancel. After a `reinit` its slot
        // frees at that event, and after a `deinit` the loop drains.
        if (connection.send_handle) |handle| self.loop.cancel(handle);
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
