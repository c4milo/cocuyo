//! A channel's links (docs/design.md §24, request rules 19 and 23, and 8, 14 and 15): each opens
//! when its channel says, a QUIC link over a datagram socket of its own and a TCP link over a
//! stream socket that connects first, and closes when the channel says, once what it holds to send
//! has gone. A link's socket that ends is told to the channel, and the channel is read then (rule
//! 17): the channel decides what that fails.
//!
//! What the loop borrows from a link outlives the opening that lent it, as a request connection's
//! does (`io_request_connection.zig`): the octets in flight, where a datagram goes, and where a
//! connect goes. So a link opened again sends nothing until an earlier opening's send has ended,
//! and connects nothing until an earlier opening's connect has.
//!
//! Free functions over the engine, split out of `io_channel.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const tls = @import("io_tls.zig");
const channel_module = @import("io_channel.zig");

/// The link a `user_data` index names: its server, which link, and its opening.
const Named = struct { server: u8, at: u1, incarnation: u32 };

fn named(index: usize) Named {
    const link_index: u8 = @intCast(index & constants.quic_server_mask);
    return .{
        .server = link_index >> 1,
        .at = @intCast(link_index & 1),
        .incarnation = @truncate(index >> constants.quic_incarnation_shift),
    };
}

/// The `user_data` of an operation on a link: its server and which link, and its opening.
fn user_data_of(self: anytype, kind: anytype, server: u8, at: u1) u64 {
    const link = &self.doh.slots[server].links[at];
    const index: u64 = (@as(u64, link.incarnation) << constants.quic_incarnation_shift) | (@as(u64, server) << 1) | at;
    return @TypeOf(self.*).user_data(kind, index);
}

// Opening (rules 19 and 23, request rule 14).

/// The channel asked for a link, to `endpoint`. A socket of an earlier opening still closing is
/// left to end. A datagram socket opens, its receive armed, and the channel's QUIC connection
/// starts. A stream socket connects first, and waits while a connect of an earlier opening still
/// borrows the link's address (request rule 14). A socket the system refuses, and a connect the
/// loop refuses, end the link (rule 19).
pub fn open(self: anytype, server: u8, link: anytype, endpoint: cocuyo.Endpoint, now_ns: u64) void {
    const at: u1 = @intFromEnum(link);
    const state = &self.doh.slots[server].links[at];
    assert(state.state == .down or state.state == .closing);
    shut(self, server, at);
    state.endpoint = endpoint;
    if (at == @intFromEnum(tcp_link(self))) return connect(self, server, now_ns);
    const descriptor = udp.Sockets.open_bound(endpoint.address.family, 0, udp.Sockets.local_for(self.config, endpoint.address.family)) catch
        return ended(self, server, at, now_ns);
    udp.size_buffers(descriptor, self.config);
    begin(state, descriptor);
    start(self, server, at, now_ns);
}

/// The TCP link's value in the channel type's own `Link`.
fn tcp_link(self: anytype) @TypeOf(self.*).Doh.Link {
    return .tcp;
}

/// A new opening of a link, on `descriptor`.
fn begin(state: *channel_module.LinkState, descriptor: rotor.Descriptor) void {
    state.incarnation +%= 1;
    state.descriptor = descriptor;
    state.made = 0;
    state.sent = 0;
}

/// The TCP link's socket and its connect, whose address the loop borrows until the connect's final
/// event. While a connect of an earlier opening still borrows it, the link waits instead, and opens
/// at that connect's end (request rule 14).
fn connect(self: anytype, server: u8, now_ns: u64) void {
    const at: u1 = @intFromEnum(tcp_link(self));
    const state = &self.doh.slots[server].links[at];
    const slot = &self.doh.sends[server][at];
    if (slot.connecting) {
        state.state = .reopening;
        return;
    }
    const descriptor = rotor.sync.open_socket(udp.family_of(state.endpoint)) catch return ended(self, server, at, now_ns);
    udp.size_buffers(descriptor, self.config);
    begin(state, descriptor);
    state.state = .connecting;
    slot.address = udp.address_of(state.endpoint);
    const operation: rotor.Operation = .connect(user_data_of(self, .doh_connect, server, at), descriptor, &slot.address);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) != 1) return ended(self, server, at, now_ns);
    state.connect = handles[0];
    slot.connecting = true;
}

/// A link's connect ended, and the loop gives the address back (request rule 14). An earlier
/// opening's lets a link that waited for it connect. The current opening's success starts the
/// channel's TCP connection; its failure ends the link.
pub fn on_connect_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    // Only an engine that holds channels submits a link's operations.
    if (comptime !@TypeOf(self.*).Doh.enabled) unreachable;
    const link = named(index);
    const state = &self.doh.slots[link.server].links[link.at];
    const slot = &self.doh.sends[link.server][link.at];
    assert(slot.connecting);
    slot.connecting = false;
    if (state.state == .reopening) {
        state.state = .down;
        return connect(self, link.server, now_ns);
    }
    if (state.state != .connecting or state.incarnation != link.incarnation) return;
    state.connect = null;
    _ = event.outcome() catch return ended(self, link.server, link.at, now_ns);
    start(self, link.server, link.at, now_ns);
}

/// A link's socket carries octets: the channel's connection on it starts, offering the ticket kept
/// for its transport, which it spends (rule 23). One that cannot start ends the link.
fn start(self: anytype, server: u8, at: u1, now_ns: u64) void {
    const slot = &self.doh.slots[server];
    const kept = spend(self, server, at, now_ns);
    const ticket = if (kept) |held| &held.ticket else null;
    slot.channel.start_link(@enumFromInt(at), ticket, now_ns) catch return ended(self, server, at, now_ns);
    slot.links[at].state = .running;
    arm(self, server, at);
}

/// Spends the ticket of a link's transport, unless it has lapsed. A ticket is used once, since
/// reuse lets an observer link two connections (RFC 9846 §C.4, rule 23).
fn spend(self: anytype, server: u8, at: u1, now_ns: u64) ?tls.Kept(@TypeOf(self.*).Doh) {
    const kept = self.doh.tickets[server][at] orelse return null;
    self.doh.tickets[server][at] = null;
    if (!tls.fresh(@TypeOf(self.*).Doh, &kept, now_ns)) return null;
    return kept;
}

// Closing (rule 19).

/// The channel closed a link: its connection writes and reads nothing more, and its socket closes
/// once what the link holds to send has gone. One with nothing to send, and one that connects or
/// waits to, closes at once.
pub fn close(self: anytype, server: u8, link: anytype) void {
    const at: u1 = @intFromEnum(link);
    const state = &self.doh.slots[server].links[at];
    if (state.state == .running and (state.made > 0 or sending(self, server, at))) {
        if (state.receive) |handle| self.loop.cancel(handle);
        state.receive = null;
        state.state = .closing;
        return;
    }
    shut(self, server, at);
}

/// Whether a send of the link's current opening is in flight.
fn sending(self: anytype, server: u8, at: u1) bool {
    const slot = &self.doh.sends[server][at];
    return slot.lent and slot.incarnation == self.doh.slots[server].links[at].incarnation;
}

/// A link's socket ended: it closes, the channel is told, and the channel is read then (rules 17
/// and 19).
fn ended(self: anytype, server: u8, at: u1, now_ns: u64) void {
    shut(self, server, at);
    self.doh.slots[server].channel.link_ended(@enumFromInt(at));
    channel_module.hear(self, server, now_ns);
}

/// Ends a link's opening: its connect and its receive cancelled, and its socket closed. A send or a
/// connect in flight keeps what it borrows until its final event, which then speaks for nobody.
pub fn shut(self: anytype, server: u8, at: u1) void {
    const state = &self.doh.slots[server].links[at];
    if (state.connect) |handle| self.loop.cancel(handle);
    if (state.receive) |handle| self.loop.cancel(handle);
    if (state.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    state.* = .{ .incarnation = state.incarnation, .endpoint = state.endpoint };
}

// What a drive does last (rule 19, request rules 8 and 15).

/// Link by link: a receive armed on each that talks and has none, and what the channel owes sent
/// when the link's buffer is back. The loop may refuse either, and the next drive asks again.
pub fn tend(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.doh.slots[0..], 0..) |*slot, server_at| {
        for (slot.links[0..], 0..) |*state, link_at| {
            if (!state.talks()) continue;
            const server: u8 = @intCast(server_at);
            const at: u1 = @intCast(link_at);
            if (state.state == .running and state.receive == null) arm(self, server, at);
            send(self, server, at, now_ns);
        }
    }
}

/// Arms a link's multishot receive: over UDP every datagram into the datagram group, over TCP every
/// chunk of the stream into the TCP chunks.
fn arm(self: anytype, server: u8, at: u1) void {
    const state = &self.doh.slots[server].links[at];
    assert(state.receive == null);
    const descriptor = state.descriptor orelse return;
    const user_data = user_data_of(self, .doh_receive, server, at);
    const operation: rotor.Operation = if (at == @intFromEnum(tcp_link(self)))
        .receive_group(user_data, descriptor, constants.tcp_group_id)
    else
        .receive_from(user_data, descriptor, constants.group_id);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) == 1) state.receive = handles[0];
}

/// Sends what a link owes, when its buffer is not lent: what the loop refused before, the rest of
/// a TCP send that went short, or what the channel makes now. A closing link sends only what it
/// kept (rule 19).
fn send(self: anytype, server: u8, at: u1, now_ns: u64) void {
    const channel = &self.doh.slots[server].channel;
    const state = &self.doh.slots[server].links[at];
    const slot = &self.doh.sends[server][at];
    const stream = at == @intFromEnum(tcp_link(self));
    if (slot.lent) return;
    if (state.made == 0 and state.state == .running) {
        state.made = @intCast(if (stream) channel.output(&slot.bytes, now_ns) else channel.datagram(&slot.bytes, now_ns));
    }
    if (state.made == 0) return;
    assert(state.sent < state.made);
    const user_data = user_data_of(self, .doh_send, server, at);
    const operation: rotor.Operation = if (stream)
        .send(user_data, state.descriptor.?, slot.bytes[state.sent..state.made])
    else
        datagram_to(self, server, at, user_data);
    if (self.loop.submit(&.{operation}, &.{}) != 1) return;
    slot.lent = true;
    slot.incarnation = state.incarnation;
    if (!stream) state.made = 0;
}

/// The datagram in a link's buffer, to where its channel asked it to go.
fn datagram_to(self: anytype, server: u8, at: u1, user_data: u64) rotor.Operation {
    const state = &self.doh.slots[server].links[at];
    const slot = &self.doh.sends[server][at];
    slot.outbound = udp.outbound_to(state.endpoint);
    return .{
        .user_data = user_data,
        .kind = .{ .send_to = .{
            .socket = state.descriptor.?,
            .buffer = .{ .bytes = slot.bytes[0..state.made] },
            .to = &slot.outbound,
        } },
    };
}

// Events (rules 17 and 19, request rules 8 and 15).

/// A link's send ended: its buffer comes back, whichever opening lent it. A send that failed ends
/// the link. Over TCP one that went short leaves its rest, which the next drive sends before
/// anything the channel makes after it (request rule 15). A closing link with nothing left closes.
/// Then the channel is read: what it held while its octets waited is told now (rule 17).
pub fn on_send_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    // Only an engine that holds channels submits a link's operations.
    if (comptime !@TypeOf(self.*).Doh.enabled) unreachable;
    const link = named(index);
    const slot = &self.doh.sends[link.server][link.at];
    // Only a send's final event returns the buffer, and every send the engine submits lends it.
    assert(slot.lent and slot.incarnation == link.incarnation);
    slot.lent = false;
    const state = &self.doh.slots[link.server].links[link.at];
    if (!state.talks() or state.incarnation != link.incarnation) return;
    const count = event.outcome() catch return ended(self, link.server, link.at, now_ns);
    if (link.at == @intFromEnum(tcp_link(self))) {
        assert(count <= state.made - state.sent);
        state.sent += @intCast(count);
        if (state.sent == state.made) {
            state.made = 0;
            state.sent = 0;
        }
    }
    if (state.state == .closing and state.made == 0) shut(self, link.server, link.at);
    channel_module.hear(self, link.server, now_ns);
}

/// A datagram or a chunk arrived on a link, or its receive ended. What arrived goes to the channel,
/// and what it made of it is read. A receive that ran out of buffers is armed again, and one that
/// failed ends the link, as over TCP does one that ended with no octets, the server's end of the
/// stream (rule 19, request rule 15).
pub fn on_receive_event(self: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    // Only an engine that holds channels submits a link's operations.
    if (comptime !@TypeOf(self.*).Doh.enabled) unreachable;
    const link = named(index);
    const stream = link.at == @intFromEnum(tcp_link(self));
    const group: u16 = if (stream) constants.tcp_group_id else constants.group_id;
    const state = &self.doh.slots[link.server].links[link.at];
    const current = state.state == .running and state.incarnation == link.incarnation;
    if (event.flags.buffer) {
        if (current) take(self, link.server, stream, event, now_ns);
        self.loop.give_back_buffer(group, event.flags.buffer_id);
    }
    if (!current) return;
    if (stream and ended_stream(event)) return ended(self, link.server, link.at, now_ns);
    if (!event.is_final()) return;
    state.receive = null;
    if (event.outcome()) |_| {} else |err| {
        if (err != error.BuffersExhausted) return ended(self, link.server, link.at, now_ns);
    }
    // The next drive arms it again (`tend`).
}

/// Whether a receive over TCP ended with no octets, the server's end of the stream.
fn ended_stream(event: rotor.Event) bool {
    const count = event.outcome() catch return false;
    return count == 0;
}

/// Hands one datagram, or one chunk of the stream, to the channel, and reads what it made of it.
fn take(self: anytype, server: u8, stream: bool, event: rotor.Event, now_ns: u64) void {
    const channel = &self.doh.slots[server].channel;
    if (stream) {
        const count = event.outcome() catch return;
        channel.receive(.{ .stream = self.loop.provided_buffer(constants.tcp_group_id, event.flags.buffer_id)[0..count] }, now_ns);
    } else {
        channel.receive(.{ .datagram = self.loop.datagram(constants.group_id, event).bytes }, now_ns);
    }
    channel_module.hear(self, server, now_ns);
}

// The engine going away.

/// Ends every link's connect and receive, so the loop can be drained. The sockets stay open until
/// `close_all`, which runs after the drain.
pub fn cancel_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.doh.slots[0..]) |*slot| {
        for (slot.links[0..]) |*state| {
            if (state.connect) |handle| self.loop.cancel(handle);
            if (state.receive) |handle| self.loop.cancel(handle);
            state.connect = null;
            state.receive = null;
        }
    }
}

/// Closes every link's socket, whatever it was doing.
pub fn close_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).Doh.enabled) return;
    for (self.doh.slots[0..]) |*slot| {
        for (slot.links[0..]) |*state| {
            if (state.descriptor) |descriptor| rotor.sync.close_now(descriptor);
            state.* = .{ .incarnation = state.incarnation };
        }
    }
}
