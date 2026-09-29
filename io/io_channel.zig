//! The engine's DoH over a channel (docs/design.md §24, DoH over colibri's client, request rules 18
//! to 25). Each DoH server has a channel, which carries its requests as exchanges and chooses
//! between two links: a QUIC link over a datagram socket and a TCP link over a stream socket, which
//! the engine opens and closes when the channel says. The engine is generic over the channel type,
//! as it is over the request interface's: colibri's `client.Channel` under `cocuyo_doh` when the
//! build links it, the twin's in its tests, and `None`, which refuses a DoH configuration.
//!
//! A request is taken at once (request rule 3). The channel holds it as an exchange while it has
//! room, and the engine keeps it waiting otherwise, or while the channel shuts down, for the next
//! (rules 21 and 24). The channel is read after everything that can move it, and says one thing at
//! a time (request rule 17). The links are `io_channel_link.zig`'s.
//!
//! Free functions over the engine, split out so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const tls = @import("io_tls.zig");
const request_module = @import("io_request.zig");
const request_template = @import("io_request_template.zig");
const link_module = @import("io_channel_link.zig");

/// No channel type: the engine's default. It holds nothing, and `init` refuses a DoH
/// configuration, so none of its functions is ever called.
pub const None = struct {
    pub const enabled = false;
    pub const output_bytes_max = 0;
    pub const Error = error{Failed};
    pub const Context = struct {};
    pub const Ticket = struct {};
    pub const Alternative = struct {};
    pub const Link = enum(u1) { quic, tcp };
    pub const Answer = struct { message: []const u8, age_seconds: u32 };
    pub const Finished = struct { index: u16, answer: ?Answer };
    pub const Open = struct { link: Link, endpoint: cocuyo.Endpoint };
    pub const Event = union(enum) { open: Open, close: Link, ticket: Link, finished: Finished, closed };
    pub const Input = union(enum) { none, datagram: []const u8, stream: []const u8 };

    pub fn start(_: *None, _: anytype) Error!void {
        unreachable;
    }
    pub fn lifetime_ns(_: *const Ticket) u64 {
        unreachable;
    }
    pub fn request(_: *None, _: u16, _: []const u8, _: u64) bool {
        unreachable;
    }
    pub fn cancel(_: *None, _: u16) void {
        unreachable;
    }
    pub fn shutdown(_: *None) void {
        unreachable;
    }
    pub fn receive(_: *None, _: Input, _: u64) void {
        unreachable;
    }
    pub fn next(_: *None, _: u64) ?Event {
        unreachable;
    }
    pub fn datagram(_: *None, _: []u8, _: u64) usize {
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
    pub fn start_link(_: *None, _: Link, _: ?*const Ticket, _: u64) Error!void {
        unreachable;
    }
    pub fn link_ended(_: *None, _: Link) void {
        unreachable;
    }
    pub fn take_ticket(_: *None, _: Link) ?Ticket {
        unreachable;
    }
    pub fn alternative(_: *const None) ?Alternative {
        unreachable;
    }
    pub fn wipe(_: *None) void {}
};

/// One of a channel's links, whichever socket it runs over: its state, its socket, its connect and
/// its receive, where the channel asked it to go, and what it made that has not gone.
pub const LinkState = struct {
    /// A link waits, reopening, while a connect of an earlier opening still borrows its address
    /// (request rule 14), and closes once what it holds has gone after the channel closed it.
    pub const State = enum { down, connecting, reopening, running, closing };

    state: State = .down,
    descriptor: ?rotor.Descriptor = null,
    connect: ?rotor.Handle = null,
    receive: ?rotor.Handle = null,
    endpoint: cocuyo.Endpoint = undefined,
    /// The octets in the link's buffer that have not gone: a datagram the loop refused, or what a
    /// TCP send left, of which `sent` went (request rules 8 and 15).
    made: u16 = 0,
    sent: u16 = 0,
    /// Which opening of the link this is: an event of an earlier one changes nothing.
    incarnation: u32 = 0,

    /// Whether the link has its receive and sends: once its connection started, and after the
    /// channel closed it while what it holds goes.
    pub fn talks(self: *const LinkState) bool {
        return self.state == .running or self.state == .closing;
    }
};

/// How many links a channel of type `Doh` has: one for each of its transports.
pub fn links_of(comptime Doh: type) usize {
    return @typeInfo(Doh.Link).@"enum".fields.len;
}

/// A server's channel: its state, the channel, its links, the requests waiting and how many it
/// holds, when it last went idle, and the HTTP/3 alternative its channels learned (rule 18).
pub fn Slot(comptime Doh: type, comptime lookups: u16) type {
    return struct {
        pub const State = enum { closed, open, shutting };

        state: State = .closed,
        channel: Doh = .{},
        links: [links_of(Doh)]LinkState = @splat(.{}),
        /// The requests waiting, oldest first: for room on the channel, or for the next channel
        /// while this one shuts down (rules 21 and 24).
        queue: [lookups]u16 = undefined,
        queue_len: u16 = 0,
        exchanges: u16 = 0,
        idle_since_ns: u64 = 0,
        alternative: ?Doh.Alternative = null,

        pub fn users(self: *const @This()) u16 {
            return self.queue_len + self.exchanges;
        }
    };
}

/// What the loop borrows from a link, whichever opening lent it: the octets in flight and where a
/// datagram goes, and over TCP where the connect goes (request rules 8 and 14). `incarnation` names
/// the opening whose send holds the buffer.
pub fn Send(comptime Doh: type) type {
    return struct {
        lent: bool = false,
        incarnation: u32 = 0,
        bytes: [Doh.output_bytes_max]u8 = undefined,
        outbound: rotor.datagram.Outbound = undefined,
        connecting: bool = false,
        address: rotor.Address = undefined,
    };
}

/// The engine's channels: a slot for each server, what the loop borrows from each link, the newest
/// ticket of each link's transport (rule 23), what every channel starts from, and how long a channel
/// with no request on it is kept (rule 24). An engine with no channel type holds a set of no slots.
pub fn Set(comptime Doh: type, comptime servers: usize, comptime lookups: u16) type {
    return struct {
        slots: [servers]Slot(Doh, lookups) = @splat(.{}),
        sends: [servers][links_of(Doh)]Send(Doh) = @splat(@splat(.{})),
        tickets: [servers][links_of(Doh)]?tls.Kept(Doh) = @splat(@splat(null)),
        context: Doh.Context = .{},
        idle_ns: u64 = constants.quic_idle_ns_default,

        /// The channel type the set's slots hold.
        pub const Channel = Doh;
    };
}

/// Whether the engine carries a DoH configuration over its channels.
pub fn carries(self: anytype) bool {
    if (comptime !@TypeOf(self.*).Doh.enabled) return false;
    return self.config.uses_https();
}

// Taking and leaving (request rules 3 and 6, rules 21 and 24).

/// What the drive does with a lookup's `send_request` over DoH: the request is taken at once onto
/// its server's channel, whatever the channel's state, and the lookup told it went out (request
/// rule 3). An earlier request of the slot's is cancelled first.
pub fn take(self: anytype, index: usize, send: anytype, now_ns: u64) void {
    // The drive takes onto a channel only in an engine that holds channels (`carries`).
    if (comptime !@TypeOf(self.*).Doh.enabled) unreachable;
    drop(self, index, now_ns);
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
    request.exchange = false;
    request.len = @intCast(send.message_bytes.len);
    place(self, index, now_ns);
}

/// Puts slot `index`'s request on its server's channel. A closed channel opens with it, and one
/// that cannot fails it (request rule 7). An open channel takes it as an exchange while it has
/// room, and it waits otherwise. One shutting down keeps it for the next (rules 18, 21 and 24).
fn place(self: anytype, index: usize, now_ns: u64) void {
    const server = self.requests[index].server;
    const slot = &self.doh.slots[server];
    if (slot.state == .closed and !open(self, server, now_ns)) return fail_one(self, index, now_ns);
    enqueue(slot, @intCast(index));
    if (slot.state == .open) give_waiting(self, server, now_ns);
    hear(self, server, now_ns);
}

/// Slot `index`'s request leaves its channel: out of the queue if it waits, and its exchange
/// cancelled if the channel holds it, whose memory is the engine's again at once (rule 21,
/// request rule 6).
pub fn drop(self: anytype, index: usize, now_ns: u64) void {
    const request = &self.requests[index];
    if (!request.live) return;
    request.live = false;
    const slot = &self.doh.slots[request.server];
    assert(slot.state != .closed);
    if (request.exchange) {
        assert(slot.exchanges >= 1);
        slot.channel.cancel(@intCast(index));
        slot.exchanges -= 1;
        request.exchange = false;
    } else {
        dequeue(slot, @intCast(index));
    }
    if (slot.users() == 0) slot.idle_since_ns = now_ns;
}

/// Every request whose lookup has left it is cancelled (request rule 6). The drive does this last.
pub fn cancel_left(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.requests[0..], 0..) |*request, index| {
        if (request.live and !request_module.current(self, index)) drop(self, index, now_ns);
    }
}

/// Slot `index`'s request failed: its lookup hears so if the request is still its attempt, once
/// (request rule 7), and decision 25 counts it as the server's failure.
fn fail_one(self: anytype, index: usize, now_ns: u64) void {
    const request = &self.requests[index];
    assert(request.live);
    if (request_module.current(self, index)) self.resolver.on_request_failed(request.handle, request.transaction, now_ns);
    request.live = false;
    request.exchange = false;
}

fn enqueue(slot: anytype, index: u16) void {
    assert(slot.queue_len < slot.queue.len);
    slot.queue[slot.queue_len] = index;
    slot.queue_len += 1;
}

/// Takes `index` out of the queue, keeping the order of the rest.
fn dequeue(slot: anytype, index: u16) void {
    const waiting = slot.queue[0..slot.queue_len];
    const at = std.mem.indexOfScalar(u16, waiting, index) orelse unreachable;
    std.mem.copyForwards(u16, waiting[at .. waiting.len - 1], waiting[at + 1 ..]);
    slot.queue_len -= 1;
}

/// The waiting requests become the open channel's exchanges, oldest first, while it has room
/// (rule 21).
pub fn give_waiting(self: anytype, server: u8, now_ns: u64) void {
    const slot = &self.doh.slots[server];
    assert(slot.state == .open);
    while (slot.queue_len > 0) {
        const index = slot.queue[0];
        const request = &self.requests[index];
        if (!slot.channel.request(index, request.bytes[0..request.len], now_ns)) return;
        dequeue(slot, index);
        request.exchange = true;
        slot.exchanges += 1;
    }
}

// Opening and closing (rules 18 and 24).

/// Opens server `server`'s channel, with nothing opened yet: its links open when it says (rule 19).
/// It goes to the server's address on its template's port, since the engine resolves no host to
/// reach a resolver, and knows the server by its template's host (RFC 9110 §4.3.4). False when the
/// engine cannot read the template, or the channel cannot start (request rule 7).
fn open(self: anytype, server: u8, now_ns: u64) bool {
    const slot = &self.doh.slots[server];
    // A channel opens for a request, or again for the requests that waited: it holds no exchange.
    assert(slot.state == .closed and slot.exchanges == 0);
    const configured = &self.config.servers[server];
    const https = configured.https orelse unreachable;
    const template = request_template.split(https.template) orelse return false;
    var endpoint = configured.endpoint;
    endpoint.port = template.port;
    const named: cocuyo.Tls = .{ .name = cocuyo.Name.from_text(template.host) catch unreachable };
    slot.channel.start(.{
        .server = server,
        .endpoint = endpoint,
        .tls = &named,
        .https = template,
        .alternative = slot.alternative,
        .context = &self.doh.context,
        .now_ns = now_ns,
    }) catch return false;
    slot.state = .open;
    // It opens with a request on it, so it has not gone idle.
    slot.idle_since_ns = 0;
    return true;
}

/// The channel said closed: shut down with no exchange left and every link closed. The slot is
/// free, keeping what the channel learned of HTTP/3, and a new channel opens for the requests that
/// waited; one that cannot fails them (rule 24).
fn closed(self: anytype, server: u8, now_ns: u64) void {
    const slot = &self.doh.slots[server];
    assert(slot.state == .shutting and slot.exchanges == 0);
    slot.alternative = slot.channel.alternative() orelse slot.alternative;
    slot.channel.wipe();
    slot.state = .closed;
    if (slot.queue_len == 0) return;
    if (!open(self, server, now_ns)) return fail_waiting(self, server, now_ns);
    give_waiting(self, server, now_ns);
}

/// Each request waiting on server `server`'s channel fails, once (request rule 7).
fn fail_waiting(self: anytype, server: u8, now_ns: u64) void {
    const slot = &self.doh.slots[server];
    for (slot.queue[0..slot.queue_len]) |index| fail_one(self, index, now_ns);
    slot.queue_len = 0;
}

/// A channel with no request on it for the set's `idle_ns` shuts down: it ends each connection as
/// its protocol ends one, closes each link, then says closed (rule 24).
pub fn close_idle(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.doh.slots[0..], 0..) |*slot, at| {
        if (slot.state != .open or slot.users() != 0) continue;
        if (now_ns -| slot.idle_since_ns < self.doh.idle_ns) continue;
        slot.channel.shutdown();
        slot.state = .shutting;
        hear(self, @intCast(at), now_ns);
    }
}

// Reading the channel (request rule 17, rules 19 to 23).

/// Reads what server `server`'s channel says, one thing at a time, until it has nothing more:
/// open or close a link, a ticket, an exchange's end, or closed. One end for each request at most,
/// and `channel_events_max` of the channel's own: what a flood leaves is read next time.
pub fn hear(self: anytype, server: u8, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) unreachable;
    const events_max = self.requests.len + constants.channel_events_max;
    for (0..events_max) |_| {
        const slot = &self.doh.slots[server];
        if (slot.state == .closed) return;
        const event = slot.channel.next(now_ns) orelse return;
        switch (event) {
            .open => |asked| link_module.open(self, server, asked.link, asked.endpoint, now_ns),
            .close => |link| link_module.close(self, server, link),
            .ticket => |link| keep_ticket(self, server, link, now_ns),
            .finished => |finished| ended(self, server, finished, now_ns),
            .closed => closed(self, server, now_ns),
        }
    }
}

/// Keeps the newest ticket of a link's transport, spent once, and dropped at its lifetime or 7 days
/// after it came (rule 23, TLS rule 8).
fn keep_ticket(self: anytype, server: u8, link: anytype, now_ns: u64) void {
    const slot = &self.doh.slots[server];
    const ticket = slot.channel.take_ticket(link) orelse return;
    self.doh.tickets[server][@intFromEnum(link)] = .{ .ticket = ticket, .since_ns = now_ns };
}

/// An exchange ended: a response carrying a DNS message goes to the lookup with its `Age`, and any
/// other end fails the request (rule 22). The lookup hears only if the request is still its
/// attempt, and the channel's room goes to the requests that wait.
fn ended(self: anytype, server: u8, finished: anytype, now_ns: u64) void {
    const index = finished.index;
    const request = &self.requests[index];
    // A request the engine cancelled tells nobody (request rule 6): the channel says no end of it.
    assert(request.live and request.exchange and request.server == server);
    if (request_module.current(self, index)) {
        if (finished.answer) |answer| {
            _ = self.resolver.on_request_answer(request.handle, request.transaction, answer.message, answer.age_seconds, now_ns);
        } else {
            self.resolver.on_request_failed(request.handle, request.transaction, now_ns);
        }
    }
    request.live = false;
    request.exchange = false;
    const slot = &self.doh.slots[server];
    assert(slot.exchanges >= 1);
    slot.exchanges -= 1;
    if (slot.users() == 0) slot.idle_since_ns = now_ns;
    if (slot.state == .open) give_waiting(self, server, now_ns);
}

// The timer (rule 25).

/// The soonest instant any channel wants, or null for none.
pub fn next_deadline(self: anytype) ?u64 {
    if (comptime !@TypeOf(self.*).Doh.enabled) return null;
    var soonest: ?u64 = null;
    for (self.doh.slots[0..]) |*slot| {
        if (slot.state == .closed) continue;
        const due = slot.channel.deadline() orelse continue;
        soonest = if (soonest) |earlier| @min(earlier, due) else due;
    }
    return soonest;
}

/// The engine's timer came: each channel whose instant has come is told, then read (rules 17 and
/// 25).
pub fn expire_due(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.doh.slots[0..], 0..) |*slot, at| {
        if (slot.state == .closed) continue;
        const due = slot.channel.deadline() orelse continue;
        if (due > now_ns) continue;
        slot.channel.expire(now_ns);
        hear(self, @intCast(at), now_ns);
    }
}

// The engine going away, or taking a new configuration.

/// Forgets every channel and what it held, once every link is closed, as `reinit` does. A ticket
/// was a server's of the old configuration (rule 23).
pub fn forget_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.doh.slots[0..]) |*slot| {
        slot.channel.wipe();
        slot.* = .{};
    }
    self.doh.tickets = @splat(@splat(null));
}
