//! What a channel is handed and what it says (docs/design.md §24, rules 17 and 19 to 22): a request
//! as an exchange, and its cancel; what the links read, kept until the channel takes it; and what
//! the channel says, turned into what the engine hears. Split from `io_doh_channel.zig`.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("client");
const constants = @import("io_doh_channel_constants.zig");
const exchange_module = @import("io_doh_channel_exchange.zig");

/// A channel's two links: QUIC over a datagram socket, TCP over a stream socket.
pub const Link = enum(u1) { quic, tcp };

/// Takes request slot `index`'s query as an exchange, or says no answer buffer is free, and the
/// request waits (rule 21).
pub fn request(self: anytype, index: u16, message: []const u8) bool {
    assert(self.started);
    assert(slot_of(self, index) == null);
    const slot = for (&self.exchanges) |*slot| {
        if (!slot.live) break slot;
    } else return false;
    const exchange = exchange_module.make(slot, index, self.path, message);
    // The GET is one colibri takes, and an answer buffer was free, so colibri had room.
    slot.id = self.channel.request(exchange) catch unreachable;
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
/// take, as the network may drop one; stream octets past the buffer end the TCP link, as they
/// failed `cocuyo_h2`'s connection (request rule 7).
pub fn receive(self: anytype, input: anytype) void {
    switch (input) {
        .none => {},
        .datagram => |bytes| {
            if (bytes.len > self.inbound.len) return;
            @memcpy(self.inbound[0..bytes.len], bytes);
            self.inbound_len = bytes.len;
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
    for (0..constants.next_passes_max) |_| {
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
    assert(sent.octets.ptr == out.ptr);
    return sent.octets.len;
}

/// A link's connection is over: what it read and the ticket it resumed with go.
pub fn forget(self: anytype, link: Link) void {
    switch (link) {
        .quic => self.inbound_len = 0,
        .tcp => {
            self.stream_len = 0;
            self.stream_overrun = false;
        },
    }
    self.resuming[@intFromEnum(link)].wipe();
}

fn slot_of(self: anytype, index: u16) ?*exchange_module.Exchange {
    for (&self.exchanges) |*slot| {
        if (slot.live and slot.index == index) return slot;
    }
    return null;
}

fn slot_by_id(self: anytype, id: client.Id) ?*exchange_module.Exchange {
    for (&self.exchanges) |*slot| {
        if (slot.live and slot.id == id) return slot;
    }
    return null;
}

/// What a link read that the channel is to take next: the datagram, then the stream.
fn pending(self: anytype) client.channel.Input {
    if (self.inbound_len > 0) return .{ .datagram = .{ .octets = self.inbound[0..self.inbound_len], .from = self.quic_to } };
    if (self.stream_len > 0) return .{ .stream = self.stream[0..self.stream_len] };
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
    self.channel.transport_closed(.tcp);
    forget(self, .tcp);
    return .{ .close = .tcp };
}

/// What one of colibri's events tells the engine, if anything.
fn told(self: anytype, said: client.channel.Event) ?@TypeOf(self.*).Event {
    switch (said) {
        .open => |asked| {
            const link = link_of(asked.transport);
            forget(self, link);
            if (link == .quic) self.quic_to = asked.to;
            return .{ .open = .{ .link = link, .endpoint = endpoint_of(asked.to) } };
        },
        .close => |transport| {
            forget(self, link_of(transport));
            return .{ .close = link_of(transport) };
        },
        .connected => |protocol| {
            self.protocol = protocol;
            return null;
        },
        .ticket => |transport| return .{ .ticket = link_of(transport) },
        .finished => |ended| return finished(self, ended),
        .closed => return .closed,
    }
}

/// The version the channel's connection came up on, and whether its handshake resumed with the
/// ticket its link offered, as its TLS session says. Null before a connection is up.
pub fn connected(self: anytype) ?@TypeOf(self.*).Connected {
    const protocol = self.protocol orelse return null;
    const link: Link = if (protocol == .h3) .quic else .tcp;
    const resumed = switch (link) {
        .quic => self.channel.quic.session.resumed(),
        .tcp => self.channel.tcp.tls_client.resumed(),
    };
    return .{ .protocol = protocol, .resumed = resumed, .offered = self.offered[@intFromEnum(link)] };
}

/// An exchange ended: its answer, or none, goes to its request slot, and its buffer is free. One
/// the engine cancelled tells nothing.
fn finished(self: anytype, ended: client.Finished) ?@TypeOf(self.*).Event {
    const slot = slot_by_id(self, ended.id) orelse return null;
    assert(ended.exchange == &slot.exchange);
    slot.live = false;
    return .{ .finished = .{ .index = slot.index, .answer = exchange_module.answer_of(slot) } };
}

pub fn link_of(transport: client.channel.Transport) Link {
    return switch (transport) {
        .quic => .quic,
        .tcp => .tcp,
    };
}

pub fn transport_of(link: Link) client.channel.Transport {
    return switch (link) {
        .quic => .quic,
        .tcp => .tcp,
    };
}

/// The endpoint a transport goes to, as colibri names it.
fn endpoint_of(to: client.channel.Address) cocuyo.Endpoint {
    const address = switch (to.len) {
        cocuyo.constants.address_v4_bytes => cocuyo.Address.from_v4(to.octets[0..cocuyo.constants.address_v4_bytes].*),
        cocuyo.constants.address_v6_bytes => cocuyo.Address.from_v6(to.octets[0..cocuyo.constants.address_v6_bytes].*),
        // The channel sends to the addresses `start` handed it, each an IPv4 or an IPv6 one.
        else => unreachable,
    };
    return .{ .address = address, .port = to.port };
}
