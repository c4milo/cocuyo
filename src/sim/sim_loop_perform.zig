//! What each operation does to the virtual network the moment it is submitted, and what the
//! network delivers when the clock reaches it (docs/design.md §19 step 13). Split from
//! `sim_loop.zig`, which holds the table and the clock.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const buffers = @import("sim_buffers.zig");
const network_module = @import("sim_network.zig");
const server = @import("sim_server.zig");
const tls_module = @import("sim_tls.zig");
const quic_module = @import("sim_loop_quic.zig");
const Loop = @import("sim_loop.zig").Loop;
const Pending = @import("sim_loop.zig").Pending;
const Operation = types.Operation;
const Event = types.Event;
const Network = network_module.Network;

/// The most frames one stream send is cut into: a send holds at most this many whole queries.
const frames_per_send_max = 16;

fn network() *Network {
    return &network_module.network;
}

pub fn draw(loop: *Loop) u64 {
    loop.word = core.mix.next(loop.word);
    return loop.word;
}

pub fn perform(loop: *Loop, slot: u32, operation: *const Operation) void {
    const user_data = operation.user_data;
    switch (operation.kind) {
        .send_to => |send| send_datagram(loop, slot, &send),
        .receive_from => |receive| register(loop, slot, user_data, receive.socket, receive.group, true),
        .connect => |connect| connect_stream(loop, slot, &connect),
        .send => |send| send_stream(loop, slot, &send),
        .receive => |receive| receive_stream(loop, slot, user_data, &receive),
        .timer => |timer| {
            assert(timer.repeat_ns == 0);
            loop.queue(slot, Event.success(user_data, 0), loop.now_ns + timer.after_ns, true);
        },
        .close => |close| {
            network().close(close.descriptor);
            loop.queue(slot, Event.success(user_data, 0), loop.now_ns, true);
        },
        .nop, .shutdown => loop.queue(slot, Event.success(user_data, 0), loop.now_ns, true),
        .accept, .read, .write, .fdatasync, .post => {
            loop.queue(slot, Event.failure(user_data, .unsupported), loop.now_ns, true);
        },
    }
}

/// A datagram to a scripted server is answered as the script says, the reply queued for the
/// socket it came from; to anywhere else it goes into the void. One to its QUIC port is the
/// twin's QUIC (sim_loop_quic.zig). The send itself succeeds now.
fn send_datagram(loop: *Loop, slot: u32, send: *const Operation.SendTo) void {
    const entry = network().socket(send.socket);
    assert(entry.kind == .datagram);
    const bytes = send.buffer.bytes;
    const user_data = loop.slots[slot].user_data;
    if (network().server_of(&send.to.peer)) |index| {
        if (network().scripts[index].no_route) {
            loop.queue(slot, Event.failure(user_data, .network_unreachable), loop.now_ns, true);
            return;
        }
        if (send.to.peer.port == constants.server_quic_port) {
            quic_module.answer(loop, send.socket, index, bytes);
        } else {
            answer_datagram(loop, send.socket, index, bytes);
        }
    }
    loop.queue(slot, Event.success(user_data, @intCast(bytes.len)), loop.now_ns, true);
}

/// A query in a datagram, answered as server `index`'s script says, the reply queued for the
/// socket it came from.
fn answer_datagram(loop: *Loop, socket: types.Descriptor, index: u8, bytes: []const u8) void {
    const script = &network().scripts[index];
    const from = Network.server_address(index);
    const pending = network().queue_datagram() orelse return;
    const answer = server.respond(script, &from, bytes, false, draw(loop), &pending.bytes) orelse {
        pending.live = false;
        return;
    };
    pending.socket = socket;
    pending.from = from;
    pending.due_ns = loop.now_ns + answer.delay_ns;
    pending.len = @intCast(answer.len);
}

fn register(loop: *Loop, slot: u32, user_data: u64, socket: types.Descriptor, group: u16, multishot: bool) void {
    _ = loop;
    const entry = network().socket(socket);
    assert(entry.receiver == null);
    entry.receiver = .{ .slot = slot, .user_data = user_data, .group = group, .multishot = multishot };
}

fn connect_stream(loop: *Loop, slot: u32, connect: *const Operation.Connect) void {
    const entry = network().socket(connect.socket);
    assert(entry.kind == .stream);
    const user_data = loop.slots[slot].user_data;
    const refused = Event.failure(user_data, .connection_refused);
    const index = network().server_of(connect.address) orelse {
        loop.queue(slot, refused, loop.now_ns, true);
        return;
    };
    const script = &network().scripts[index];
    if (!script.tcp or script.down) {
        loop.queue(slot, refused, loop.now_ns + script.delay_ns_min, true);
        return;
    }
    const tls = connect.address.port == constants.server_tls_port;
    const connection = network().open_connection(connect.socket, index, tls) orelse {
        loop.queue(slot, Event.failure(user_data, .system_resources), loop.now_ns, true);
        return;
    };
    entry.connection = connection;
    if (entry.local.port == 0) entry.local.port = network().assign_port_public();
    const delay_ns = if (script.connect_delay_ns != 0) script.connect_delay_ns else script.delay_ns_min;
    loop.queue(slot, Event.success(user_data, 0), loop.now_ns + delay_ns, true);
}

/// Bytes to the server: whole frames are answered, a partial one waits for the rest
/// (RFC 7766 §8). The send succeeds now, and moves no more than the socket's send buffer when
/// the caller sized one: the short send rotor's contract allows, which a caller has to finish.
fn send_stream(loop: *Loop, slot: u32, send: *const Operation.Send) void {
    const entry = network().socket(send.socket);
    const user_data = loop.slots[slot].user_data;
    const index = entry.connection orelse {
        loop.queue(slot, Event.failure(user_data, .not_connected), loop.now_ns, true);
        return;
    };
    const connection = network().connection(index);
    const whole = send.buffer.bytes;
    const bytes = if (entry.send_buffer_bytes == 0) whole else whole[0..@min(whole.len, entry.send_buffer_bytes)];
    assert(connection.partial_len + bytes.len <= connection.partial.len);
    @memcpy(connection.partial[connection.partial_len..][0..bytes.len], bytes);
    connection.partial_len += bytes.len;
    var frames: usize = 0;
    while (frames < frames_per_send_max) : (frames += 1) {
        const answered = if (connection.tls != null) answer_record(loop, connection) else answer_frame(loop, connection);
        if (!answered) break;
    }
    loop.queue(slot, Event.success(user_data, @intCast(bytes.len)), loop.now_ns, true);
}

/// Answers the first whole frame of the connection's partial bytes, if there is one.
fn answer_frame(loop: *Loop, connection: *network_module.Connection) bool {
    const prefix = core.constants.tcp_prefix_bytes;
    if (connection.partial_len < prefix) return false;
    const frame_len: usize = wire.message_len(connection.partial[0..prefix]);
    if (connection.partial_len < prefix + frame_len) return false;
    const query = connection.partial[prefix..][0..frame_len];
    const script = &network().scripts[connection.server];
    const room = connection.inbound.len - connection.inbound_len;
    if (room >= prefix + constants.datagram_bytes_max) {
        const out = connection.inbound[connection.inbound_len + prefix ..][0..constants.datagram_bytes_max];
        if (server.respond(script, &connection.peer, query, true, draw(loop), out)) |answer| {
            wire.header.write_message_len(connection.inbound[connection.inbound_len..][0..prefix], @intCast(answer.len));
            connection.inbound_len += prefix + answer.len;
            connection.available_at_ns = loop.now_ns + answer.delay_ns;
        }
    }
    const consumed = prefix + frame_len;
    std.mem.copyForwards(u8, connection.partial[0 .. connection.partial_len - consumed], connection.partial[consumed..connection.partial_len]);
    connection.partial_len -= consumed;
    return true;
}

/// Answers the first whole record of a TLS connection's partial bytes (docs/design.md §21):
/// the server side says its handshake steps, and answers the query a data record carries.
fn answer_record(loop: *Loop, connection: *network_module.Connection) bool {
    const whole = tls_module.record_len(connection.partial[0..connection.partial_len]) orelse return false;
    const script = &network().scripts[connection.server];
    switch (connection.tls.?.hear(&script.tls, connection.partial[0..whole])) {
        .steps => |steps| {
            write_inbound_step(loop, connection, script, steps.first);
            if (steps.second) |second| write_inbound_step(loop, connection, script, second);
        },
        .data => |data| answer_sealed(loop, connection, script, data),
        .nothing, .close => {},
    }
    consume(connection, whole);
    return true;
}

fn write_inbound_step(loop: *Loop, connection: *network_module.Connection, script: *const server.Script, step: tls_module.Step) void {
    const room = connection.inbound.len - connection.inbound_len;
    if (room < constants.tls_record_header_bytes + 1) return;
    connection.inbound_len += tls_module.write_step(step, connection.inbound[connection.inbound_len..]);
    connection.available_at_ns = loop.now_ns + script.delay_ns_min;
}

/// The one framed query a data record carries, answered in a data record of its own.
fn answer_sealed(loop: *Loop, connection: *network_module.Connection, script: *const server.Script, data: []const u8) void {
    const prefix = core.constants.tcp_prefix_bytes;
    if (data.len < prefix or data.len != prefix + wire.message_len(data[0..prefix])) return;
    var frame: [constants.tls_payload_bytes_max]u8 = undefined;
    const answer = server.respond(script, &connection.peer, data[prefix..], true, draw(loop), frame[prefix..]) orelse return;
    wire.header.write_message_len(frame[0..prefix], @intCast(answer.len));
    const room = connection.inbound.len - connection.inbound_len;
    if (room < constants.tls_record_header_bytes + prefix + answer.len) return;
    connection.inbound_len += tls_module.write_record(constants.tls_content_application, frame[0 .. prefix + answer.len], connection.inbound[connection.inbound_len..]);
    connection.available_at_ns = loop.now_ns + answer.delay_ns;
}

fn consume(connection: *network_module.Connection, count: usize) void {
    assert(count <= connection.partial_len);
    std.mem.copyForwards(u8, connection.partial[0 .. connection.partial_len - count], connection.partial[count..connection.partial_len]);
    connection.partial_len -= count;
}

fn receive_stream(loop: *Loop, slot: u32, user_data: u64, receive: *const Operation.Receive) void {
    // The engine reads into groups; a caller's own buffer is not what the twin delivers into.
    const group = switch (receive.target) {
        .group => |group| group,
        .buffer => unreachable,
    };
    register(loop, slot, user_data, receive.socket, group, receive.multishot);
}

/// A cancelled operation delivers nothing more: its receiver is removed, and its queued events
/// are dropped, but for an end that is due already, which stays the answer to the cancel.
pub fn withdraw(loop: *Loop, slot: u32) void {
    withdraw_receiver(slot);
    var index: u32 = 0;
    while (index < loop.pending_count) {
        const pending = &loop.pending[index];
        if (!withdraws(pending, slot, loop.now_ns)) {
            index += 1;
            continue;
        }
        if (pending.event.flags.buffer) loop.give_back_buffer(pending.group, pending.event.flags.buffer_id);
        loop.pending_count -= 1;
        loop.pending[index] = loop.pending[loop.pending_count];
    }
}

/// Whether a queued event goes with its operation's cancel: every event of the slot that is
/// not its end, and an end that has not come yet, which is a timer's fire or a connection's
/// completion still ahead. An end that is due already stays, as the answer to the cancel.
fn withdraws(pending: *const Pending, slot: u32, now_ns: u64) bool {
    return pending.slot == slot and (!pending.final or pending.due_ns > now_ns);
}

fn withdraw_receiver(slot: u32) void {
    for (&network().sockets) |*entry| {
        if (!entry.open) continue;
        if (entry.receiver) |receiver| {
            if (receiver.slot == slot) entry.receiver = null;
        }
    }
}

/// Delivers what the network holds for the sockets that are receiving, into their groups, as
/// events due at the delivery's instant: every datagram whose time has come, and every stream's
/// bytes in chunks the seed sizes, so a reader's framing is exercised.
pub fn materialize(loop: *Loop) void {
    quic_module.expire_responders(loop);
    materialize_datagrams(loop);
    materialize_streams(loop);
}

fn materialize_datagrams(loop: *Loop) void {
    for (&network().datagrams) |*pending| {
        if (!pending.live or pending.due_ns > loop.now_ns) continue;
        const entry = &network().sockets[@intCast(pending.socket)];
        if (!entry.open) {
            pending.live = false;
            continue;
        }
        const receiver = entry.receiver orelse continue;
        const buffer_id = loop.groups[receiver.group].take() orelse {
            // No buffer for a datagram that is due: the multishot ends the way rotor's does,
            // and the datagram waits for the next receive.
            entry.receiver = null;
            loop.queue(receiver.slot, Event.failure(receiver.user_data, .buffers_exhausted), loop.now_ns, true);
            continue;
        };
        const buffer = loop.provided_buffer(receiver.group, buffer_id);
        const len = buffers.write_delivery(buffer, loop.group_options, &pending.from, pending.bytes[0..pending.len]);
        loop.queue_delivery(receiver, buffer_id, len, pending.due_ns);
        pending.live = false;
    }
}

fn materialize_streams(loop: *Loop) void {
    for (&network().connections) |*connection| {
        const receiver = stream_ready(loop, connection) orelse continue;
        var chunks: usize = 0;
        while (chunks < constants.buffers_per_group_max and connection.inbound_len > 0) : (chunks += 1) {
            if (!deliver_chunk(loop, connection, receiver)) {
                // No buffer for bytes that are ready: the multishot ends the way rotor's does,
                // and the bytes wait for the next receive.
                network().sockets[@intCast(connection.socket)].receiver = null;
                loop.queue(receiver.slot, Event.failure(receiver.user_data, .buffers_exhausted), loop.now_ns, true);
                break;
            }
            if (!receiver.multishot) {
                network().sockets[@intCast(connection.socket)].receiver = null;
                break;
            }
        }
    }
}

/// The receiver of a connection that has bytes ready for a socket that is reading, or null.
fn stream_ready(loop: *const Loop, connection: *const network_module.Connection) ?network_module.Receiver {
    if (!connection.open or connection.inbound_len == 0) return null;
    if (connection.available_at_ns > loop.now_ns) return null;
    const entry = &network().sockets[@intCast(connection.socket)];
    if (!entry.open) return null;
    return entry.receiver;
}

/// One chunk of the stream, sized by the seed, into a free buffer of the receiver's group.
fn deliver_chunk(loop: *Loop, connection: *network_module.Connection, receiver: network_module.Receiver) bool {
    const buffer_id = loop.groups[receiver.group].take() orelse return false;
    const buffer = loop.provided_buffer(receiver.group, buffer_id);
    const most = @min(connection.inbound_len, buffer.len);
    const chunk: usize = constants.stream_chunk_bytes_min + draw(loop) % (most - constants.stream_chunk_bytes_min + 1);
    @memcpy(buffer[0..chunk], connection.inbound[0..chunk]);
    std.mem.copyForwards(u8, connection.inbound[0 .. connection.inbound_len - chunk], connection.inbound[chunk..connection.inbound_len]);
    connection.inbound_len -= chunk;
    loop.queue_delivery(receiver, buffer_id, @intCast(chunk), loop.now_ns);
    return true;
}

/// The earliest instant the network has something to deliver to a receiving socket, or a
/// responder has a deadline.
pub fn next_delivery_due(loop: *const Loop) ?u64 {
    _ = loop;
    return earliest(earliest(next_datagram_due(), next_stream_due()), quic_module.responders_due());
}

fn earliest(a: ?u64, b: ?u64) ?u64 {
    if (a == null) return b;
    if (b == null) return a;
    return @min(a.?, b.?);
}

fn receiving(descriptor: types.Descriptor) bool {
    const entry = &network().sockets[@intCast(descriptor)];
    return entry.open and entry.receiver != null;
}

fn next_datagram_due() ?u64 {
    var due: ?u64 = null;
    for (&network().datagrams) |*pending| {
        if (!pending.live or !receiving(pending.socket)) continue;
        due = earliest(due, pending.due_ns);
    }
    return due;
}

fn next_stream_due() ?u64 {
    var due: ?u64 = null;
    for (&network().connections) |*connection| {
        if (!connection.open or connection.inbound_len == 0 or !receiving(connection.socket)) continue;
        due = earliest(due, connection.available_at_ns);
    }
    return due;
}
