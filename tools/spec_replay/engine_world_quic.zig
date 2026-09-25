//! The model's request events, replayed on the engine (spec/tla/engine/EngineRequest.tla,
//! `QuicStep` and `QuicTime`): what colibri makes of a datagram, spelled as the twin's QUIC spells
//! it, one item in a datagram on the connection's receive; and the connection's own timer, due at
//! the instant the walk reaches it (docs/design.md §24, the request interface). Split from
//! `engine_world.zig`, which routes these events here.
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const fixtures = @import("fixtures.zig");
const world_module = @import("engine_world.zig");

const Error = world_module.Error;

/// The step the model names on the receive `op` names, for the request in the slot the event
/// names: a datagram of one item from the connection's server, laid out in the datagram group as
/// rotor lays one out.
pub fn step(self: anytype, op: []const u8, parts: *std.mem.SplitIterator(u8, .scalar)) Error!void {
    const loop_slot = try world_module.operation(self, op);
    const user_data = self.loop.slots[loop_slot].user_data;
    if (world_module.kind_of(user_data) != .quic_receive) return error.Malformed;
    const server: u8 = @intCast((user_data & io.constants.index_mask) & io.constants.quic_server_mask);
    const name = parts.next() orelse return error.Malformed;
    const slot = try world_module.number(parts.next());
    const reply = std.meta.stringToEnum(fixtures.Reply, parts.next() orelse "");
    var datagram: [rotor.constants.quic_datagram_bytes_max]u8 = undefined;
    const len = try item(self, server, name, slot, reply, &datagram);
    const buffer_id = self.loop.groups[io.constants.group_id].take() orelse return error.NoBuffer;
    const buffer = self.loop.provided_buffer(io.constants.group_id, buffer_id);
    const peer = rotor.Network.server_address(server);
    var event = rotor.Event.success(user_data, rotor.buffers.write_delivery(buffer, .{}, &peer, datagram[0..len]));
    event.flags = .{ .buffer = true, .more = true, .buffer_id = buffer_id };
    _ = self.engine.apply(event, self.now_ns);
}

/// The item the step is: a flight while the handshake runs and a PING once up, for a datagram the
/// connection answers; the handshake's end on "doq" or on another protocol; its refusal; the
/// server's close; a ticket; an answer or a reset on the slot's stream.
fn item(self: anytype, server: u8, name: []const u8, slot: usize, reply: ?fixtures.Reply, out: []u8) Error!usize {
    const connection = &self.engine.quic_connections[server];
    const Kind = rotor.quic.Kind;
    const plain = [_]struct { name: []const u8, kind: Kind, bytes: []const u8 }{
        .{ .name = "done", .kind = .done, .bytes = io.constants.quic_alpn_doq },
        .{ .name = "otherAlpn", .kind = .done, .bytes = rotor.constants.quic_alpn_other },
        .{ .name = "failed", .kind = .refused, .bytes = &.{} },
        .{ .name = "close", .kind = .closed, .bytes = &.{} },
        .{ .name = "newTicket", .kind = .ticket, .bytes = &.{} },
    };
    for (plain) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return rotor.quic.write_item(.{ .kind = entry.kind, .bytes = entry.bytes }, out);
    }
    if (std.mem.eql(u8, name, "datagram")) {
        const kind: Kind = if (connection.state == .handshaking) .flight else .ping;
        return rotor.quic.write_item(.{ .kind = kind }, out);
    }
    const stream: u32 = @intCast(self.engine.requests[slot].stream orelse return error.Malformed);
    if (std.mem.eql(u8, name, "reset")) return rotor.quic.write_item(.{ .kind = .reset, .stream = stream }, out);
    if (!std.mem.eql(u8, name, "answer")) return error.Malformed;
    var message: [512 + cocuyo.constants.tcp_prefix_bytes]u8 = undefined;
    const answer = answer_of(self, slot, reply orelse return error.Malformed, &message);
    return rotor.quic.write_item(.{ .kind = .answer, .stream = stream, .bytes = answer }, out);
}

/// The answer `reply` names for the lookup in `slot`, as a DoQ stream carries it: after its
/// length, and with ID 0 (RFC 9250 §4.2, §4.2.1).
fn answer_of(self: anytype, slot: usize, reply: fixtures.Reply, out: []u8) []const u8 {
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    const lookup = self.engine.resolver.lookup_of(self.engine.handles[slot]);
    const body = fixtures.build(lookup, reply, out[prefix..]);
    std.mem.writeInt(u16, out[prefix..][0..@sizeOf(u16)], 0, .big);
    std.mem.writeInt(u16, out[0..prefix], @intCast(body.len), .big);
    return out[0 .. prefix + body.len];
}

/// Server `server`'s connection's QUIC timer comes at this instant, with the outcome the walk
/// names: the connection resends what is unacknowledged, or gives up. The engine hears it through
/// its one timer, as it does whenever a connection's deadline comes (request rule 11). The model
/// has no timer, so the replay fires the engine's own, or, when the loop refused it, delivers its
/// fire by the generation the engine counts.
pub fn expire(self: anytype, server: usize, name: []const u8) Error!void {
    const connection = &self.engine.quic_connections[server];
    connection.quic.expiry = std.meta.stringToEnum(rotor.quic.Connection.Expiry, name) orelse return error.Malformed;
    connection.quic.due_ns = self.now_ns;
    const Resolver = @TypeOf(self.engine);
    var user_data = Resolver.user_data(.timer, self.engine.timer_generation);
    if (self.engine.timer_handle) |handle| {
        user_data = self.loop.slots[handle.index].user_data;
        self.loop.end(handle.index);
    }
    _ = self.engine.apply(rotor.Event.success(user_data, 0), self.now_ns);
}
