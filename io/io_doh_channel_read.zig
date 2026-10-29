//! What a channel is handed and what it says (docs/design.md §24, rules 17 and 19 to 22): a request
//! as an exchange, and its cancel; what the links read, kept until the channel takes it; and what
//! the channel says, turned into what the engine hears. Split from `io_doh_channel.zig`.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("client");
const constants = @import("io_doh_channel_constants.zig");
const limits = @import("io_doh_channel_limits.zig");
const exchange_module = @import("io_doh_channel_exchange.zig");

/// A channel's two links: QUIC over a datagram socket, TCP over a stream socket.
pub const Link = enum(u1) { quic, tcp };

/// A handle that names no connection: colibri's calls with it change nothing. A link names it
/// before its first `open`, and once its connection is over.
pub const no_connection: client.ConnectionHandle = .{ .slot = std.math.maxInt(u32), .generation = 0 };

/// Takes request slot `index`'s query as colibri's request, or says no answer buffer is free, and
/// the request waits (rule 21).
pub fn request(self: anytype, index: u16, message: []const u8) bool {
    assert(self.started);
    assert(slot_of(self, index) == null);
    const slot = for (&self.exchanges) |*slot| {
        if (!slot.live) break slot;
    } else return false;
    exchange_module.make(slot, index, self.path, message);
    slot.up = self.up != null;
    slot.heard = slot.up or self.heard[@intFromEnum(Link.quic)] or self.heard[@intFromEnum(Link.tcp)];
    // The GET is one colibri takes, and an answer buffer was free, so colibri had room.
    slot.id = self.channel.request(&slot.request, &slot.response) catch unreachable;
    slot.live = true;
    return true;
}

/// Ends slot `index`'s exchange, whose memory is the engine's again at once.
pub fn cancel(self: anytype, index: u16) void {
    const slot = slot_of(self, index) orelse return;
    self.channel.cancel(slot.id);
    slot.live = false;
}

/// Keeps what a link read until the channel takes it. A datagram replaces one the channel did not
/// take, as the network may drop one; stream octets past the buffer end the TCP link, as octets
/// past what a request connection keeps fail it (request rule 7).
pub fn receive(self: anytype, input: anytype) void {
    switch (input) {
        .none => {},
        .datagram => |bytes| {
            if (bytes.len > self.inbound.len) return;
            @memcpy(self.inbound[0..bytes.len], bytes);
            self.inbound_len = bytes.len;
            heard_from(self, .quic);
        },
        .stream => |bytes| {
            if (self.stream_overrun) return;
            if (self.stream_len + bytes.len > self.stream.len) {
                self.stream_overrun = true;
                self.stream_len = 0;
                return;
            }
            @memcpy(self.stream[self.stream_len..][0..bytes.len], bytes);
            self.stream_len += bytes.len;
        },
    }
}

/// What the channel says, one thing at a time, having taken what the links read. What it says that
/// changes nothing the engine does, the version a connection speaks, is read past (rule 20).
pub fn next(self: anytype, now_ns: u64) ?@TypeOf(self.*).Event {
    if (self.stream_overrun) return overrun(self);
    for (0..limits.next_passes_max) |_| {
        const received = self.channel.receive(pending(self), now_ns);
        take(self, received.consumed);
        if (received.event) |said| {
            if (told(self, said)) |event| return event;
            continue;
        }
        if (received.consumed == 0) return null;
    }
    unreachable;
}

/// The QUIC link's next datagram, which colibri writes at the start of `out`.
pub fn datagram(self: anytype, out: []u8, now_ns: u64) usize {
    const sent = self.channel.send_datagram(out, now_ns) orelse return 0;
    assert(sent.bytes.ptr == out.ptr);
    return sent.bytes.len;
}

/// A server took part in `link`'s opening: each live exchange learns it, and each exchange made
/// before that opening is over starts from it (docs/design.md §16 decision 51).
pub fn heard_from(self: anytype, link: Link) void {
    const at = @intFromEnum(link);
    if (self.heard[at]) return;
    self.heard[at] = true;
    for (&self.exchanges) |*slot| {
        if (slot.live) slot.heard = true;
    }
    assert(self.heard[at]);
}

/// The connection on `link` came up and takes the exchanges: each live exchange learns it. A
/// connection on the other link may still drain, so `up` names the newer one.
fn came_up(self: anytype, link: Link) void {
    self.up = link;
    for (&self.exchanges) |*slot| {
        if (!slot.live) continue;
        slot.up = true;
        slot.heard = true;
    }
    assert(self.up == link);
}

/// A link's connection is over: what it read and the ticket it resumed with go, and so do what it
/// told of a server that took part, and of a connection that came up.
pub fn forget(self: anytype, link: Link) void {
    if (self.up == link) self.up = null;
    self.heard[@intFromEnum(link)] = false;
    switch (link) {
        .quic => self.inbound_len = 0,
        .tcp => {
            self.stream_len = 0;
            self.stream_overrun = false;
        },
    }
    self.handles[@intFromEnum(link)] = no_connection;
    self.resuming[@intFromEnum(link)].wipe();
}

fn slot_of(self: anytype, index: u16) ?*exchange_module.Exchange {
    for (&self.exchanges) |*slot| {
        if (slot.live and slot.index == index) return slot;
    }
    return null;
}

fn slot_by_id(self: anytype, id: client.RequestId) ?*exchange_module.Exchange {
    for (&self.exchanges) |*slot| {
        if (slot.live and slot.id == id) return slot;
    }
    return null;
}

/// What a link read that the channel is to take next: the datagram, then the stream.
fn pending(self: anytype) client.Input {
    if (self.inbound_len > 0) return .{ .datagram = .{ .bytes = self.inbound[0..self.inbound_len], .from = self.quic_to } };
    if (self.stream_len > 0) return .{ .stream = .{ .connection = handle_of(self, .tcp), .bytes = self.stream[0..self.stream_len] } };
    return .none;
}

/// The channel took `consumed` octets of what `pending` handed it.
fn take(self: anytype, consumed: usize) void {
    if (consumed == 0) return;
    if (self.inbound_len > 0) {
        assert(consumed == self.inbound_len);
        self.inbound_len = 0;
        return;
    }
    assert(consumed <= self.stream_len);
    std.mem.copyForwards(u8, self.stream[0 .. self.stream_len - consumed], self.stream[consumed..self.stream_len]);
    self.stream_len -= consumed;
}

/// The stream ran past its buffer: the TCP link ends, as the channel's close would end it.
fn overrun(self: anytype) @TypeOf(self.*).Event {
    self.stream_overrun = false;
    self.channel.transport_closed(handle_of(self, .tcp));
    forget(self, .tcp);
    return .{ .close = .tcp };
}

/// What one of colibri's events tells the engine, if anything.
fn told(self: anytype, said: client.Event) ?@TypeOf(self.*).Event {
    switch (said) {
        .open => |asked| {
            const link = link_of(asked.transport);
            forget(self, link);
            self.handles[@intFromEnum(link)] = asked.connection;
            if (link == .quic) self.quic_to = asked.to;
            return .{ .open = .{ .link = link, .endpoint = endpoint_of(asked.to) } };
        },
        // The engine asks for a link's octets each time it can send them (rule 19), so a debt
        // changes nothing it does.
        .send => return null,
        .close => |connection| {
            const link = link_on(self, connection);
            forget(self, link);
            return .{ .close = link };
        },
        .connected => |up| {
            self.protocol = up.protocol;
            came_up(self, link_on(self, up.connection));
            return null;
        },
        .ticket => |connection| return .{ .ticket = link_on(self, connection) },
        .finished => |ended| return finished(self, ended),
        .closed => return .closed,
    }
}

/// The connection that `link` carries now, which each of colibri's calls about the link names.
pub fn handle_of(self: anytype, link: Link) client.ConnectionHandle {
    return self.handles[@intFromEnum(link)];
}

/// The link that carries `connection`. colibri places its TCP slots first and its QUIC slot after
/// them, and the channel holds one TCP slot.
fn link_on(self: anytype, connection: client.ConnectionHandle) Link {
    assert(self.channel.tcp.len == limits.tcp_connections_max);
    return if (connection.slot < self.channel.tcp.len) .tcp else .quic;
}

/// The version the channel's connection came up on, and whether its handshake resumed with the
/// ticket its link offered, as its TLS session says. Null before a connection is up.
pub fn connected(self: anytype) ?@TypeOf(self.*).Connected {
    const protocol = self.protocol orelse return null;
    const link: Link = if (protocol == .h3) .quic else .tcp;
    const resumed = switch (link) {
        .quic => self.channel.quic.session.resumed(),
        .tcp => self.channel.tcp[0].tls_client.resumed(),
    };
    return .{ .protocol = protocol, .resumed = resumed, .offered = self.offered[@intFromEnum(link)] };
}

/// An exchange ended: its answer, or none, goes to its request slot, and its buffer is free. One
/// the engine cancelled tells nothing.
fn finished(self: anytype, ended: client.Finished) ?@TypeOf(self.*).Event {
    const slot = slot_by_id(self, ended.id) orelse return null;
    assert(ended.request == &slot.request);
    assert(ended.response == &slot.response);
    slot.live = false;
    return .{ .finished = .{ .index = slot.index, .result = exchange_module.result_of(slot) } };
}

pub fn link_of(transport: client.Transport) Link {
    return switch (transport) {
        .quic => .quic,
        .tcp => .tcp,
    };
}

/// The endpoint a transport goes to, as colibri names it.
fn endpoint_of(to: client.Address) cocuyo.Endpoint {
    const address = switch (to.len) {
        cocuyo.constants.address_v4_bytes => cocuyo.Address.from_v4(to.octets[0..cocuyo.constants.address_v4_bytes].*),
        cocuyo.constants.address_v6_bytes => cocuyo.Address.from_v6(to.octets[0..cocuyo.constants.address_v6_bytes].*),
        // The channel sends to the addresses `start` handed it, each an IPv4 or an IPv6 one.
        else => unreachable,
    };
    return .{ .address = address, .port = to.port };
}
