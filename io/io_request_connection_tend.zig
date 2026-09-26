//! What a drive does last to the request connections (docs/design.md §24, request rules 4, 8 and
//! 15, the datagram's rule 1): a receive armed on each that has none, the streams the server's
//! credit now allows, and what the transport owes sent when the slot's buffer is back. The timer's
//! deadline, and the engine going away, are here too. Split from `io_request_connection.zig`.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const connection_module = @import("io_request_connection.zig");

/// Connection by connection: a receive armed on each socket that has none, the streams the
/// server's credit now allows, and what the transport owes sent when the buffer is back. The loop
/// may refuse either, and the next drive asks again. A TCP connection does none of it before its
/// connect has succeeded (request rule 14).
pub fn tend(self: anytype, set: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    for (set.connections[0..], 0..) |*connection, at| {
        const server: u8 = @intCast(at);
        if (!connection.talks()) continue;
        if (connection.receive == null) arm(self, set, server);
        connection_module.open_waiting(self, set, server, now_ns);
        if (connection.state != .closed) send(self, set, server, now_ns);
    }
}

/// Arms the connection's multishot receive: every datagram from its server arrives on it, into
/// the datagram group, or over TCP every chunk of the stream, into the TCP chunks.
pub fn arm(self: anytype, set: anytype, server: u8) void {
    const Set = @TypeOf(set.*);
    const connection = &set.connections[server];
    assert(connection.receive == null);
    const descriptor = connection.descriptor orelse return;
    const user_data = connection_module.user_data_of(self, set, Set.receive_kind, server);
    const operation: rotor.Operation = if (comptime Set.stream)
        .receive_group(user_data, descriptor, constants.tcp_group_id)
    else
        .receive_from(user_data, descriptor, constants.group_id);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) == 1) connection.receive = handles[0];
}

/// Sends what the connection owes, when the slot's buffer is not lent: what the loop refused
/// before, the rest of a TCP send that went short, or what the transport makes now. Over UDP the
/// datagram leaves the buffer at its submission; over TCP what went is known at the send's end
/// (request rule 15).
fn send(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    const Set = @TypeOf(set.*);
    const connection = &set.connections[server];
    const slot = &set.sends[server];
    if (slot.lent) return;
    if (connection.made == 0) connection.made = @intCast(connection.transport.output(&slot.bytes, now_ns));
    if (connection.made == 0) return;
    assert(connection.sent < connection.made);
    const user_data = connection_module.user_data_of(self, set, Set.send_kind, server);
    const operation: rotor.Operation = if (comptime Set.stream)
        .send(user_data, connection.descriptor.?, slot.bytes[connection.sent..connection.made])
    else
        datagram_to(self, set, server, user_data);
    if (self.loop.submit(&.{operation}, &.{}) != 1) return;
    slot.lent = true;
    if (comptime !Set.stream) connection.made = 0;
}

/// The datagram in the slot's buffer, to the connection's server.
fn datagram_to(self: anytype, set: anytype, server: u8, user_data: u64) rotor.Operation {
    const connection = &set.connections[server];
    const slot = &set.sends[server];
    slot.outbound = udp.outbound_to(connection_module.endpoint_of(self, set, server));
    return .{
        .user_data = user_data,
        .kind = .{ .send_to = .{
            .socket = connection.descriptor.?,
            .buffer = .{ .bytes = slot.bytes[0..connection.made] },
            .to = &slot.outbound,
        } },
    };
}

// The timer (request rule 11).

/// The soonest transport deadline of every open connection, or null for none.
pub fn next_deadline(set: anytype) ?u64 {
    if (comptime !@TypeOf(set.*).Transport.enabled) return null;
    var soonest: ?u64 = null;
    for (set.connections[0..]) |*connection| {
        if (!connection.talks()) continue;
        const due = connection.transport.deadline() orelse continue;
        soonest = if (soonest) |earlier| @min(earlier, due) else due;
    }
    return soonest;
}

// The engine going away, or taking a new configuration.

/// Ends every connection's connect and receive, so the loop can be drained (rotor decision 5, rule
/// 7). The sockets stay open until `close_all`, which runs after the drain.
pub fn cancel_all(self: anytype, set: anytype) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    for (set.connections[0..]) |*connection| {
        if (connection.connect) |handle| self.loop.cancel(handle);
        if (connection.receive) |handle| self.loop.cancel(handle);
        connection.connect = null;
        connection.receive = null;
    }
}

/// Closes every connection's socket, whatever it was doing: the engine is going away, or taking
/// a new configuration with nothing in flight.
pub fn close_all(set: anytype) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    for (set.connections[0..]) |*connection| {
        if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
        connection.restart();
        connection.queue_len = 0;
    }
}
