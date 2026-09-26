//! The engine's requests (docs/design.md §24: the request rules and the request interface). A
//! lookup over DoQ asks for one request for each transaction (§23), and the engine carries it on
//! a new stream of its server's QUIC connection. The engine is generic over the connection type,
//! as it is over the TLS session of §21: colibri's over chapulin's QUIC object when the build
//! links them, the twin's in its tests, and `None`, which refuses a request configuration.
//!
//! Each lookup slot has a request slot, which holds the request's bytes while the stream may still
//! need them (request rule 3), and the attempt the request speaks for. A request its lookup has
//! left is cancelled at the end of every drive (request rule 6), and a failure tells each request
//! on the connection once (request rule 7). The connections are `io_request_connection.zig`'s,
//! and what their events do is `io_request_events.zig`'s.
//!
//! Free functions over the engine, split out of `io.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const constants = @import("constants.zig");
const connection_module = @import("io_request_connection.zig");

/// No request transport: the engine's default. It holds nothing, and `init` refuses a request
/// configuration, so none of its functions is ever called.
pub const None = struct {
    pub const enabled = false;
    pub const http3 = false;
    pub const datagram_bytes_max = 0;
    pub const request_bytes_max = 0;
    pub const Error = error{Failed};
    pub const Context = struct {};
    pub const Ticket = struct {};
    pub const Http = struct { status: u16, age_seconds: u32, dns_message: bool };
    pub const Answered = struct { stream: u64, len: usize, http: ?Http = null };
    pub const Next = union(enum) { up: []const u8, refused, answered: Answered, reset: u64, closed, goaway, ticket: Ticket };

    pub fn start(_: *None, _: anytype) Error!void {
        unreachable;
    }
    pub fn lifetime_ns(_: *const Ticket) u64 {
        unreachable;
    }
    pub fn receive(_: *None, _: []const u8, _: u64) Error!void {
        unreachable;
    }
    pub fn next(_: *None, _: []u8) ?Next {
        unreachable;
    }
    pub fn request(_: *None, _: []u8, _: usize) Error!?u64 {
        unreachable;
    }
    pub fn cancel(_: *None, _: u64) void {
        unreachable;
    }
    pub fn datagram(_: *None, _: []u8, _: u64) usize {
        unreachable;
    }
    pub fn deadline(_: *const None) ?u64 {
        unreachable;
    }
    pub fn expire(_: *None, _: u64) void {
        unreachable;
    }
    pub fn idle_left_ns(_: *const None, _: u64) u64 {
        unreachable;
    }
    pub fn close(_: *None) void {
        unreachable;
    }
    pub fn wipe(_: *None) void {}
};

/// One lookup slot's request: the attempt it speaks for, the server it went to, its stream once it
/// has one, and the bytes the stream carries (request rule 3).
pub fn Request(comptime Quic: type) type {
    return struct {
        live: bool = false,
        handle: cocuyo.Handle = undefined,
        transaction: u16 = 0,
        server: u8 = 0,
        /// Null while the request waits in its connection's queue (request rule 4).
        stream: ?u64 = null,
        len: u16 = 0,
        bytes: [Quic.request_bytes_max]u8 = undefined,
    };
}

/// Whether the engine's lookups go as requests: every server is DoQ (docs/design.md §23).
pub fn speaks(self: anytype) bool {
    return self.config.sends_requests();
}

/// What the drive does with a lookup's `send_request`: the request is taken at once onto its
/// server's connection, whatever the connection's state, and the lookup told it went out, so its
/// deadline covers the handshake (request rule 3). An earlier request of the slot's is cancelled
/// first. A connection that cannot open fails the request, and the lookup moves on.
pub fn take(self: anytype, index: usize, send: anytype, now_ns: u64) void {
    const Quic = @TypeOf(self.*).Quic;
    // `init` refuses a request configuration without a transport (`assert_tls`).
    if (comptime !Quic.enabled) unreachable;
    const set = &self.quic;
    drop(self, set, index, now_ns);
    const handle = self.handles[index];
    self.resolver.on_sent(handle, now_ns);
    const request = &self.requests[index];
    assert(send.message_bytes.len <= request.bytes.len);
    @memcpy(request.bytes[0..send.message_bytes.len], send.message_bytes);
    request.live = true;
    request.handle = handle;
    request.transaction = send.transaction;
    request.server = send.server_index;
    request.stream = null;
    request.len = @intCast(send.message_bytes.len);
    connection_module.place(self, set, index, now_ns);
}

/// Whether slot `index`'s request speaks for its lookup's attempt now: the lookup still waits on
/// the transaction the request carries (request rules 5 and 6).
pub fn current(self: anytype, index: usize) bool {
    const request = &self.requests[index];
    if (!request.live) return false;
    if (!self.slots[index].occupied or self.handles[index] != request.handle) return false;
    const lookup = self.resolver.lookup_of(request.handle);
    return lookup.state == .awaiting_udp and lookup.transaction.number == request.transaction;
}

/// Slot `index`'s request leaves its connection: out of the queue if it waits, and its stream
/// cancelled if it has one, which the transport owes the server STOP_SENDING and a reset for
/// (request rule 6). The slot's bytes are free from here.
pub fn drop(self: anytype, set: anytype, index: usize, now_ns: u64) void {
    const request = &self.requests[index];
    if (!request.live) return;
    request.live = false;
    const connection = &set.connections[request.server];
    assert(connection.state != .closed);
    if (request.stream) |stream| {
        assert(connection.streams >= 1);
        connection.streams -= 1;
        connection.transport.cancel(stream);
        connection_module.drained(set, request.server);
    } else {
        connection_module.dequeue(connection, @intCast(index));
    }
    if (connection.users() == 0) connection.idle_since_ns = now_ns;
}

/// Every request whose lookup has left it is cancelled: its deadline passed, it moved on, it
/// ended, or it was cancelled or released (request rule 6). The drive does this last, after
/// every poll, so a lookup that asked again within the drive keeps its new request.
pub fn cancel_left(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    const set = &self.quic;
    for (self.requests[0..], 0..) |*request, index| {
        if (request.live and !current(self, index)) drop(self, set, index, now_ns);
    }
}

/// Slot `index`'s request failed: its lookup hears so if the request is still its attempt, once,
/// since the slot is free before anyone else could tell it (request rule 7).
fn fail_one(self: anytype, index: usize, now_ns: u64) void {
    const request = &self.requests[index];
    assert(request.live);
    if (current(self, index)) self.resolver.on_request_failed(request.handle, request.transaction, now_ns);
    request.live = false;
}

/// Each request on a stream of server `server`'s connection fails, once; those that wait stay
/// (request rule 13).
pub fn fail_streams_of(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    for (self.requests[0..], 0..) |*request, index| {
        if (request.live and request.server == server and request.stream != null) fail_one(self, index, now_ns);
    }
    set.connections[server].streams = 0;
}

/// Every request on server `server`'s connection fails, each once (request rule 7). Decision 25
/// counts each as the server's failure, which the table does.
pub fn fail_all_of(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    for (self.requests[0..], 0..) |*request, index| {
        if (request.live and request.server == server) fail_one(self, index, now_ns);
    }
    const connection = &set.connections[server];
    connection.queue_len = 0;
    connection.streams = 0;
}

/// The request slot whose stream `stream` is on server `server`'s connection, or null for a
/// stream the engine has let go of.
pub fn of_stream(self: anytype, server: u8, stream: u64) ?usize {
    for (self.requests[0..], 0..) |*request, index| {
        if (!request.live or request.server != server) continue;
        if (request.stream == stream) return index;
    }
    return null;
}

/// Forgets every request, which `reinit` does once every connection is closed.
pub fn forget_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    for (self.requests[0..]) |*request| request.live = false;
}

comptime {
    // A connection's server shares its `user_data` with its incarnation, as a TCP connection's
    // slot does (`io_request_connection.zig`).
    assert(cocuyo.constants.servers_max <= constants.quic_server_mask + 1);
}
