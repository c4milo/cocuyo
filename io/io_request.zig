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
    pub const output_bytes_max: usize = 0;
    pub const request_bytes_max: usize = 0;
    pub const Error = error{Failed};
    pub const Context = struct {};
    pub const Ticket = struct {};
    pub const Answered = struct { stream: u64, len: usize };
    pub const Next = union(enum) { up: []const u8, refused, answered: Answered, reset: u64, closed, ticket: Ticket };

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
    pub fn output(_: *None, _: []u8, _: u64) usize {
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

/// A request of the pool: the lookup it is for, by its handle and its table slot, the try it went
/// for, by its transaction's number, the server it went to, its stream once it has one, and the
/// bytes the stream carries (request rule 3), `bytes_max` of them, which is the most any of the
/// engine's transports asks. `order` is when it was taken, which finds the oldest earlier request.
pub fn Request(comptime bytes_max: usize) type {
    return struct {
        live: bool = false,
        handle: cocuyo.Handle = undefined,
        slot: u16 = 0,
        order: u64 = 0,
        transaction: u16 = 0,
        server: u8 = 0,
        /// Null while the request waits in its connection's queue (request rule 4).
        stream: ?u64 = null,
        /// Over a channel, whether the channel holds the request as an exchange (docs/design.md
        /// §24, rule 21).
        exchange: bool = false,
        len: u16 = 0,
        bytes: [bytes_max]u8 = undefined,
    };
}

/// The pool's free slots, a stack whose top is taken next, and the count of requests taken so far,
/// which orders them (docs/design.md §24, request rule 3). Taking a slot or giving one back costs
/// the same whatever the pool's size.
pub fn Pool(comptime slots: usize) type {
    return struct {
        free: [slots]u16 = undefined,
        free_count: usize = 0,
        taken: u64 = 0,

        /// Every slot free, the lowest on top, so the first request takes slot 0.
        pub fn reset(self: *@This()) void {
            for (&self.free, 0..) |*entry, at| entry.* = @intCast(slots - 1 - at);
            self.free_count = slots;
            self.taken = 0;
            assert(slots == 0 or self.free[slots - 1] == 0);
        }

        pub fn pop(self: *@This()) ?u16 {
            if (self.free_count == 0) return null;
            self.free_count -= 1;
            return self.free[self.free_count];
        }

        pub fn push(self: *@This(), index: u16) void {
            assert(self.free_count < slots);
            self.free[self.free_count] = index;
            self.free_count += 1;
        }
    };
}

/// Whether the engine's lookups go as requests: every server is DoQ or DoH (docs/design.md §22,
/// §23).
pub fn speaks(self: anytype) bool {
    return self.config.sends_requests();
}

/// What the drive does with a lookup's `send_request` over DoQ: the request is taken at once onto
/// its server's connection, whatever the connection's state, and the lookup told it went out, so
/// its deadline covers the handshake (request rule 3). The requests of the lookup's earlier tries
/// stay (rule 6). A connection that cannot open fails the request, and the lookup moves on.
pub fn take(self: anytype, index: usize, send: anytype, now_ns: u64) void {
    // `init` refuses a DoQ configuration without a transport (`assert_tls`).
    if (comptime !@TypeOf(self.*).Quic.enabled) unreachable;
    const at = fill(self, index, send, claim(self, drop, now_ns), now_ns);
    connection_module.place(self, at, now_ns);
}

/// A free slot of the pool: the free list's top, after the oldest earlier request is cancelled by
/// `cancel` when none is free (request rule 3). Its lookup hears `local` if its try is open, so no
/// server failed. The pool holds a slot for each lookup at least, so an earlier request is there.
pub fn claim(self: anytype, comptime cancel: anytype, now_ns: u64) u16 {
    if (self.request_pool.pop()) |at| return at;
    const oldest = oldest_earlier(self) orelse unreachable;
    const request = &self.requests[oldest];
    if (open(self, oldest)) self.resolver.on_request_failed(request.handle, request.transaction, .local, now_ns);
    cancel(self, oldest, now_ns);
    return self.request_pool.pop().?;
}

/// The live request taken first that is no lookup's current one, or null.
fn oldest_earlier(self: anytype) ?usize {
    var found: ?usize = null;
    for (self.requests[0..], 0..) |*request, at| {
        if (!request.live or current(self, at)) continue;
        if (found == null or request.order < self.requests[found.?].order) found = at;
    }
    return found;
}

/// The lookup at `index` is told its request went out, and slot `at` of the pool holds it.
pub fn fill(self: anytype, index: usize, send: anytype, at: u16, now_ns: u64) u16 {
    const handle = self.handles[index];
    self.resolver.on_sent(handle, now_ns);
    const request = &self.requests[at];
    assert(!request.live);
    assert(send.message_bytes.len <= request.bytes.len);
    @memcpy(request.bytes[0..send.message_bytes.len], send.message_bytes);
    // Field by field, so the bytes just copied are not copied onto themselves.
    request.live = true;
    request.handle = handle;
    request.slot = @intCast(index);
    request.order = self.request_pool.taken;
    request.transaction = send.transaction;
    request.server = send.server_index;
    request.stream = null;
    request.exchange = false;
    request.len = @intCast(send.message_bytes.len);
    self.request_pool.taken += 1;
    return at;
}

/// Whether request `at` speaks for its lookup's attempt now: the lookup still waits on the
/// transaction the request carries (request rules 5 and 6).
pub fn current(self: anytype, at: usize) bool {
    const request = &self.requests[at];
    if (!owned(self, request)) return false;
    const lookup = self.resolver.lookup_of(request.handle);
    return lookup.state == .awaiting_udp and lookup.transaction.number == request.transaction;
}

/// Whether request `at`'s try is open: its lookup's current request, or the request of an earlier
/// try the lookup keeps open (§5, Tries kept open; request rule 6).
pub fn open(self: anytype, at: usize) bool {
    if (current(self, at)) return true;
    const request = &self.requests[at];
    if (!owned(self, request)) return false;
    const lookup = self.resolver.lookup_of(request.handle);
    return !lookup.is_settled() and lookup.tries.numbered(request.transaction) != null;
}

/// Whether a request is live and its lookup is still the one in its table slot.
fn owned(self: anytype, request: anytype) bool {
    if (!request.live) return false;
    return self.slots[request.slot].occupied and self.handles[request.slot] == request.handle;
}

/// Request `at` is gone: its slot is the pool's again.
pub fn free(self: anytype, at: usize) void {
    const request = &self.requests[at];
    assert(request.live);
    request.live = false;
    self.request_pool.push(@intCast(at));
}

/// Slot `index`'s request leaves its connection: out of the queue if it waits, and its stream
/// cancelled if it has one, which the transport owes the server STOP_SENDING and a reset for
/// (request rule 6). The slot's bytes are free from here.
pub fn drop(self: anytype, index: usize, now_ns: u64) void {
    const request = &self.requests[index];
    if (!request.live) return;
    free(self, index);
    const connection = &self.quic.connections[request.server];
    assert(connection.state != .closed);
    if (request.stream) |stream| {
        assert(connection.streams >= 1);
        connection.streams -= 1;
        connection.transport.cancel(stream);
    } else {
        connection_module.dequeue(connection, @intCast(index));
    }
    if (connection.users() == 0) connection.idle_since_ns = now_ns;
}

/// Every request whose try closed is cancelled: its lookup ended, moved to another name, was
/// cancelled or released, or heard that try answered or failed. A deadline alone leaves the
/// request (request rule 6). The drive does this last, after every poll, so a lookup that asked
/// again within the drive keeps its new request.
pub fn cancel_left(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    for (self.requests[0..], 0..) |*request, index| {
        if (request.live and !open(self, index)) drop(self, index, now_ns);
    }
}

/// Request `index` failed, for `reason`: its lookup hears so if its try is open, once, since the
/// slot is free before anyone else could tell it (request rule 7).
fn fail_one(self: anytype, index: usize, reason: cocuyo.Reason, now_ns: u64) void {
    const request = &self.requests[index];
    assert(request.live);
    if (open(self, index)) self.resolver.on_request_failed(request.handle, request.transaction, reason, now_ns);
    free(self, index);
}

/// Every request on server `server`'s connection fails, each once, for `reason` (request rule 7).
/// Decision 25 counts each as the server's failure, which the table does.
pub fn fail_all_of(self: anytype, server: u8, reason: cocuyo.Reason, now_ns: u64) void {
    for (self.requests[0..], 0..) |*request, index| {
        if (request.live and request.server == server) fail_one(self, index, reason, now_ns);
    }
    const connection = &self.quic.connections[server];
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
    const Engine = @TypeOf(self.*);
    if (comptime !(Engine.Quic.enabled or Engine.Doh.enabled)) return;
    for (self.requests[0..]) |*request| request.live = false;
    self.request_pool.reset();
}

comptime {
    // A connection's server shares its `user_data` with its incarnation, as a TCP connection's
    // slot does (`io_request_connection.zig`).
    assert(cocuyo.limits.servers_max <= constants.quic_server_mask + 1);
}
