//! What a scripted server does with a datagram of the twin's QUIC (docs/design.md §24): each item
//! it carries is heard by the server's side of the connection, and what the server says goes back
//! as datagrams to the socket the datagram came from. Split from `sim_loop_perform.zig`, which
//! routes a datagram to a server's QUIC port here.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const network_module = @import("sim_network.zig");
const server = @import("sim_server.zig");
const quic = @import("sim_quic.zig");
const perform = @import("sim_loop_perform.zig");
const Loop = @import("sim_loop.zig").Loop;
const Network = network_module.Network;

fn network() *Network {
    return &network_module.network;
}

/// Where server `index` speaks QUIC from.
fn quic_address(index: u8) types.Address {
    var address = Network.server_address(index);
    address.port = constants.server_quic_port;
    return address;
}

/// A datagram from `socket` to server `index`'s QUIC port. A server that is down says nothing,
/// and neither does one whose table of connections is full.
pub fn answer(loop: *Loop, socket: types.Descriptor, index: u8, bytes: []const u8) void {
    const script = &network().scripts[index];
    if (script.down) return;
    const entry = network().quic_peer(socket, index) orelse return;
    var at: usize = 0;
    var items: usize = 0;
    while (items < constants.quic_items_per_datagram_max and at < bytes.len) : (items += 1) {
        const read = quic.read_item(bytes[at..]) orelse return;
        at += read.len;
        switch (entry.peer.hear(&script.quic, read.item)) {
            .steps => |steps| say_steps(loop, entry, script, steps.first, steps.second),
            .request => |request| answer_request(loop, entry, script, request.stream, request.bytes),
            .nothing => {},
        }
    }
}

/// The server's handshake steps, together in one datagram, so they arrive in the order they
/// were said.
fn say_steps(loop: *Loop, entry: *network_module.QuicPeer, script: *const server.Script, first: quic.Kind, second: ?quic.Kind) void {
    const pending = queue(entry, loop.now_ns + script.delay_ns_min) orelse return;
    var len = write_step(entry, script, first, &pending.bytes);
    if (second) |kind| len += write_step(entry, script, kind, pending.bytes[len..]);
    pending.len = @intCast(len);
}

/// One step as an item: the handshake's end names the protocol it ends on.
fn write_step(entry: *const network_module.QuicPeer, script: *const server.Script, kind: quic.Kind, out: []u8) usize {
    const bytes = if (kind == .done) entry.peer.negotiated(&script.quic) else &[_]u8{};
    return quic.write_item(.{ .kind = kind, .bytes = bytes }, out);
}

/// A request on a stream: answered on it as the script says, or its stream reset, or the
/// connection closed. A query the script drops is never answered.
fn answer_request(loop: *Loop, entry: *network_module.QuicPeer, script: *const server.Script, stream: u32, bytes: []const u8) void {
    switch (script.quic.instead) {
        .answer => {},
        .reset, .close => {
            const kind: quic.Kind = if (script.quic.instead == .reset) .reset else .closed;
            const pending = queue(entry, loop.now_ns + script.delay_ns_min) orelse return;
            pending.len = @intCast(quic.write_item(.{ .kind = kind, .stream = stream }, &pending.bytes));
            return;
        },
    }
    const prefix = core.constants.tcp_prefix_bytes;
    // A request carries one message after its prefix (RFC 9250 §4.2); the twin answers no other.
    if (bytes.len < prefix or wire.message_len(bytes[0..prefix]) != bytes.len - prefix) return;
    var message: [constants.quic_datagram_bytes_max]u8 = undefined;
    const room = message[prefix .. message.len - constants.quic_item_header_bytes];
    const from = quic_address(entry.server);
    const answered = server.respond(script, &from, bytes[prefix..], true, perform.draw(loop), room) orelse return;
    const len = prefix + answered.len;
    malform(script, message[0..len]);
    const pending = queue(entry, loop.now_ns + answered.delay_ns) orelse return;
    pending.len = @intCast(quic.write_item(.{ .kind = .answer, .stream = stream, .bytes = message[0..len] }, &pending.bytes));
}

/// Writes the prefix, and breaks the answer as the script says: a prefix one octet short of the
/// message, or an ID that is not 0 (RFC 9250 §4.3.3).
fn malform(script: *const server.Script, message: []u8) void {
    const prefix = core.constants.tcp_prefix_bytes;
    const length: u16 = @intCast(message.len - prefix);
    switch (script.quic.malformed) {
        .none => wire.header.write_message_len(message[0..prefix], length),
        .prefix => wire.header.write_message_len(message[0..prefix], length - 1),
        .id => {
            wire.header.write_message_len(message[0..prefix], length);
            message[prefix] = 1;
        },
    }
}

/// A datagram from the server to the connection's socket, due at `due_ns`, or null when the
/// network holds as many as it can, which is a drop.
fn queue(entry: *const network_module.QuicPeer, due_ns: u64) ?*network_module.PendingDatagram {
    const pending = network().queue_datagram() orelse return null;
    pending.socket = entry.socket;
    pending.from = quic_address(entry.server);
    pending.due_ns = due_ns;
    pending.len = 0;
    assert(pending.bytes.len >= constants.quic_datagram_bytes_max);
    return pending;
}
