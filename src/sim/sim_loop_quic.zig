//! What a scripted server does with a datagram of the twin's QUIC (docs/design.md §24): each item
//! it carries is heard by the server's side of the connection, and what the server says goes back
//! as datagrams to the socket the datagram came from. Over TCP, as DoH over HTTP/2 runs, the items
//! come in frames on a connection to the server's HTTPS port, and go back as frames on it
//! (sim_quic_stream.zig). Split from `sim_loop_perform.zig`, which routes a datagram to a server's
//! QUIC port here, and a stream's octets to the HTTPS port.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const network_module = @import("sim_network.zig");
const server = @import("sim_server.zig");
const quic = @import("sim_quic.zig");
const quic_stream = @import("sim_quic_stream.zig");
const perform = @import("sim_loop_perform.zig");
const Loop = @import("sim_loop.zig").Loop;
const Network = network_module.Network;

fn network() *Network {
    return &network_module.network;
}

const quic_address = Network.server_quic_address;

/// A datagram from `socket` to server `index`'s QUIC port: its responder's, when a test put one
/// there, and otherwise the twin's QUIC. A server that is down says nothing, and neither does one
/// whose table of connections is full.
pub fn answer(loop: *Loop, socket: types.Descriptor, index: u8, bytes: []const u8) void {
    if (network().responders[index]) |responder| return responder.hear(responder.context, socket, bytes, loop.now_ns);
    const script = &network().scripts[index];
    if (script.down) return;
    const entry = network().quic_peer(socket, index) orelse return;
    hear_items(loop, .{ .entry = entry }, script, bytes);
}

/// The first whole frame of a client's TCP connection to the server's HTTPS port: its items
/// heard as a datagram's are, and what the server says gone back as frames on the connection.
/// False when no whole frame is there yet.
pub fn answer_stream(loop: *Loop, connection: *network_module.Connection) bool {
    const whole = quic_stream.unframe(connection.partial[0..connection.partial_len]) orelse return false;
    const script = &network().scripts[connection.server];
    if (!script.down) {
        if (network().quic_peer(connection.socket, connection.server)) |entry| {
            hear_items(loop, .{ .entry = entry, .connection = connection }, script, whole.items);
        }
    }
    const rest = connection.partial_len - whole.len;
    std.mem.copyForwards(u8, connection.partial[0..rest], connection.partial[whole.len..connection.partial_len]);
    connection.partial_len = rest;
    return true;
}

/// Where a server's side of a connection says what it says: as datagrams to the client's socket,
/// or as frames on the client's TCP connection.
const Reply = struct {
    entry: *network_module.QuicPeer,
    connection: ?*network_module.Connection = null,
};

/// Room for the items of one datagram or one frame, due at `due_ns`, and where it goes.
const Out = struct {
    bytes: []u8,
    pending: ?*network_module.PendingDatagram,
    connection: ?*network_module.Connection,
    due_ns: u64,
};

/// Each item of `bytes`, heard by the server's side of the connection, and what it says said.
fn hear_items(loop: *Loop, reply: Reply, script: *const server.Script, bytes: []const u8) void {
    const entry = reply.entry;
    var at: usize = 0;
    var items: usize = 0;
    while (items < constants.quic_items_per_datagram_max and at < bytes.len) : (items += 1) {
        const read = quic.read_item(bytes[at..]) orelse return;
        at += read.len;
        switch (entry.peer.hear(&script.quic, read.item)) {
            .steps => |steps| say_steps(loop, reply, script, steps.first, steps.second),
            .request => |request| answer_request(loop, reply, script, request.stream, request.bytes),
            .nothing => {},
        }
    }
}

/// The server's handshake steps, together in one datagram, so they arrive in the order they
/// were said.
fn say_steps(loop: *Loop, reply: Reply, script: *const server.Script, first: quic.Kind, second: ?quic.Kind) void {
    const out = queue(reply, loop.now_ns + script.delay_ns_min) orelse return;
    var len = write_step(reply.entry, script, first, out.bytes);
    if (second) |kind| len += write_step(reply.entry, script, kind, out.bytes[len..]);
    said(out, len);
}

/// One step as an item: the handshake's end names the protocol it ends on.
fn write_step(entry: *const network_module.QuicPeer, script: *const server.Script, kind: quic.Kind, out: []u8) usize {
    const bytes = if (kind == .done) entry.peer.negotiated(&script.quic) else &[_]u8{};
    return quic.write_item(.{ .kind = kind, .bytes = bytes }, out);
}

/// A request on a stream: answered on it as the script says, or its stream reset, or the
/// connection closed. A query the script drops is never answered.
fn answer_request(loop: *Loop, reply: Reply, script: *const server.Script, stream: u32, bytes: []const u8) void {
    const entry = reply.entry;
    goaway_on_take(reply, script, loop.now_ns + script.delay_ns_min);
    switch (script.quic.instead) {
        .answer => {},
        .end_stream => if (reply.connection) |connection| {
            connection.ended = true;
            connection.available_at_ns = @max(connection.available_at_ns, loop.now_ns + script.delay_ns_min);
            return;
        } else {
            const out = queue(reply, loop.now_ns + script.delay_ns_min) orelse return;
            return said(out, quic.write_item(.{ .kind = .closed, .stream = stream }, out.bytes));
        },
        .reset, .close => {
            const kind: quic.Kind = if (script.quic.instead == .reset) .reset else .closed;
            const out = queue(reply, loop.now_ns + script.delay_ns_min) orelse return;
            said(out, quic.write_item(.{ .kind = kind, .stream = stream }, out.bytes));
            return;
        },
    }
    if (speaks_http(entry.peer.negotiated(&script.quic))) {
        return answer_http(loop, reply, script, stream, bytes);
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
    const out = queue(reply, loop.now_ns + answered.delay_ns) orelse return;
    said(out, quic.write_item(.{ .kind = .answer, .stream = stream, .bytes = message[0..len] }, out.bytes));
}

/// Whether a connection's protocol answers a request as a DoH server does: HTTP/3, or HTTP/2 over
/// the twin's TCP.
fn speaks_http(protocol: []const u8) bool {
    return std.mem.eql(u8, protocol, constants.quic_alpn_h3) or std.mem.eql(u8, protocol, constants.alpn_h2);
}

/// A GOAWAY once the server has taken its first request on the connection, when the script says it
/// stops taking streams: it names the streams it took, and answers them (RFC 9114 §5.2). It goes
/// at the shortest delay, ahead of any answer.
fn goaway_on_take(reply: Reply, script: *const server.Script, due_ns: u64) void {
    const entry = reply.entry;
    if (!script.quic.goaway or entry.peer.goaway_sent) return;
    entry.peer.goaway_sent = true;
    const out = queue(reply, due_ns) orelse return;
    said(out, quic.write_item(.{ .kind = .goaway }, out.bytes));
}

/// A DoH request carries the message alone (RFC 8484 §4.1), and its answer goes back as a
/// response: what the script says of it, then the message.
fn answer_http(loop: *Loop, reply: Reply, script: *const server.Script, stream: u32, bytes: []const u8) void {
    const entry = reply.entry;
    var message: [constants.quic_datagram_bytes_max]u8 = undefined;
    const header = constants.quic_http_header_bytes;
    const room = message[header .. message.len - constants.quic_item_header_bytes];
    const from = quic_address(entry.server);
    const answered = server.respond(script, &from, bytes, true, perform.draw(loop), room) orelse return;
    quic.write_http(script.quic.http, message[0..header]);
    const out = queue(reply, loop.now_ns + answered.delay_ns) orelse return;
    const item: quic.Item = .{ .kind = .response, .stream = stream, .bytes = message[0 .. header + answered.len] };
    said(out, quic.write_item(item, out.bytes));
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

/// Room for what the server says next, due at `due_ns`: a datagram to the connection's socket, or
/// a frame on its TCP connection. Null when the network holds as many datagrams as it can, or the
/// connection as many octets, which is a drop.
fn queue(reply: Reply, due_ns: u64) ?Out {
    if (reply.connection) |connection| {
        const prefix = quic_stream.prefix_bytes;
        if (connection.inbound.len - connection.inbound_len < quic_stream.frame_bytes_max) return null;
        const room = connection.inbound[connection.inbound_len + prefix ..][0..constants.quic_datagram_bytes_max];
        return .{ .bytes = room, .pending = null, .connection = connection, .due_ns = due_ns };
    }
    const pending = network().queue_datagram() orelse return null;
    pending.socket = reply.entry.socket;
    pending.from = quic_address(reply.entry.server);
    pending.due_ns = due_ns;
    pending.len = 0;
    assert(pending.bytes.len >= constants.quic_datagram_bytes_max);
    return .{ .bytes = pending.bytes[0..constants.quic_datagram_bytes_max], .pending = pending, .connection = null, .due_ns = due_ns };
}

/// `len` octets of items were written into `out`: the datagram holds them, or the frame is
/// written on the connection, readable once its delay has passed.
fn said(out: Out, len: usize) void {
    assert(len <= out.bytes.len);
    if (out.pending) |pending| {
        pending.len = @intCast(len);
        return;
    }
    const connection = out.connection.?;
    const prefix = quic_stream.prefix_bytes;
    std.mem.writeInt(u16, connection.inbound[connection.inbound_len..][0..prefix], @intCast(len), .big);
    connection.inbound_len += prefix + len;
    connection.available_at_ns = @max(connection.available_at_ns, out.due_ns);
}

/// Wakes each responder whose deadline has come, before what is due is delivered, so the
/// datagrams it answers with at that instant go out with it.
pub fn expire_responders(loop: *const Loop) void {
    for (&network().responders) |*slot| {
        const responder = slot.* orelse continue;
        const due = responder.deadline(responder.context) orelse continue;
        if (due <= loop.now_ns) responder.expire(responder.context, loop.now_ns);
    }
}

/// The soonest deadline of every responder, or null for none.
pub fn responders_due() ?u64 {
    var soonest: ?u64 = null;
    for (&network().responders) |*slot| {
        const responder = slot.* orelse continue;
        const due = responder.deadline(responder.context) orelse continue;
        soonest = if (soonest) |earlier| @min(earlier, due) else due;
    }
    return soonest;
}
