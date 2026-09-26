//! What the loop and the transport say of a request connection (docs/design.md §24, request rules
//! 2, 5, 7, 8, 10, 11, 14 and 15): a connect ended, a send ended, a datagram or a chunk arrived,
//! the timer came, and what the transport made of each, read with `next` one thing at a time.
//!
//! Free functions over the engine, split out of `io_request.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const request_module = @import("io_request.zig");
const connection_module = @import("io_request_connection.zig");

/// The connection an event names, or null for an opening of the slot that is gone, whose events
/// change nothing (the stream's rule 2, as a TCP connection's are). A slot that waits to connect,
/// or connects, has no send or receive of its own yet (request rule 14).
fn current_of(set: anytype, index: usize) ?u8 {
    const server: u8 = @intCast(index & constants.quic_server_mask);
    const incarnation: u32 = @truncate(index >> constants.quic_incarnation_shift);
    assert(server < set.connections.len);
    const connection = &set.connections[server];
    if (!connection.talks() or connection.incarnation != incarnation) return null;
    return server;
}

/// Over TCP, a connect ended, whichever opening made it (request rule 14).
pub fn on_connect_event(self: anytype, set: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(set.*).stream) unreachable;
    const server: u8 = @intCast(index & constants.quic_server_mask);
    const incarnation: u32 = @truncate(index >> constants.quic_incarnation_shift);
    const connection = &set.connections[server];
    // A connecting opening's connect is the only one in flight, since the slot connects nothing
    // while an earlier one is.
    assert(connection.state != .connecting or connection.incarnation == incarnation);
    const succeeded = if (event.outcome()) |_| true else |_| false;
    connection_module.connected(self, set, server, succeeded, now_ns);
}

/// A send ended: the slot's buffer comes back, whichever opening lent it. A send that failed fails
/// its connection, and a closing connection with nothing more to say closes (request rules 7 to
/// 9). Over TCP one that went short leaves its rest, which the next drive sends before anything
/// the transport makes after it (request rule 15).
pub fn on_send_event(self: anytype, set: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    const slot = &set.sends[index & constants.quic_server_mask];
    // Only a send's final event returns the buffer, and every send the engine submits lends it.
    assert(slot.lent);
    slot.lent = false;
    const server = current_of(set, index) orelse return;
    const count = event.outcome() catch return connection_module.fail(self, set, server, now_ns);
    const connection = &set.connections[server];
    if (comptime @TypeOf(set.*).stream) {
        assert(count <= connection.made - connection.sent);
        connection.sent += @intCast(count);
        if (connection.sent < connection.made) return;
        connection.made = 0;
        connection.sent = 0;
    }
    if (connection.state != .closing) return;
    if (connection.made == 0) connection.made = @intCast(connection.transport.output(&slot.bytes, now_ns));
    if (connection.made == 0) connection_module.closed(self, set, server, now_ns);
}

/// A datagram or a chunk arrived, or the receive ended. What arrived goes to the transport, and
/// what it made of it is read. A closing connection has said its last and reads nothing more
/// (request rule 9). A receive that ran out of buffers is armed again, and one that failed fails
/// the connection. Over TCP a receive that ends with no octets is the server's end of the stream,
/// and fails the connection too (request rule 15).
pub fn on_receive_event(self: anytype, set: anytype, index: usize, event: rotor.Event, now_ns: u64) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    const group = if (comptime @TypeOf(set.*).stream) constants.tcp_group_id else constants.group_id;
    const server = current_of(set, index) orelse {
        if (event.flags.buffer) self.loop.give_back_buffer(group, event.flags.buffer_id);
        return;
    };
    const connection = &set.connections[server];
    if (event.flags.buffer and !take(self, set, server, event, now_ns)) return;
    if (connection.state == .closed) return;
    if (ended_stream(set, event)) return connection_module.fail(self, set, server, now_ns);
    if (!event.is_final()) return;
    connection.receive = null;
    if (event.outcome()) |_| {} else |err| {
        if (err != error.BuffersExhausted) return connection_module.fail(self, set, server, now_ns);
    }
    // The next drive arms it again (`tend`).
}

/// Whether a receive over TCP ended with no octets, which is the server's end of the stream
/// (request rule 15). A datagram of no octets is only that.
fn ended_stream(set: anytype, event: rotor.Event) bool {
    if (comptime !@TypeOf(set.*).stream) return false;
    const count = event.outcome() catch return false;
    return count == 0;
}

/// Hands one datagram, or one chunk of the stream, to the transport, gives its buffer back, and
/// reads what the transport made of it. False when the transport refused it, which fails the
/// connection.
fn take(self: anytype, set: anytype, server: u8, event: rotor.Event, now_ns: u64) bool {
    const connection = &set.connections[server];
    const closing = connection.state == .closing;
    const stream = comptime @TypeOf(set.*).stream;
    const group = if (stream) constants.tcp_group_id else constants.group_id;
    var refused = false;
    if (!closing) {
        const bytes = if (stream) chunk_of(self, event) else self.loop.datagram(group, event).bytes;
        connection.transport.receive(bytes, now_ns) catch {
            refused = true;
        };
    }
    self.loop.give_back_buffer(group, event.flags.buffer_id);
    if (refused) {
        connection_module.fail(self, set, server, now_ns);
        return false;
    }
    if (!closing) hear(self, set, server, now_ns);
    return true;
}

/// The octets of a stream's chunk, in its TCP chunk buffer.
fn chunk_of(self: anytype, event: rotor.Event) []const u8 {
    const count = event.outcome() catch unreachable;
    return self.loop.provided_buffer(constants.tcp_group_id, event.flags.buffer_id)[0..count];
}

/// The engine's timer came: each connection whose transport deadline has come is told, and what
/// that did is read (request rule 11).
pub fn expire_due(self: anytype, set: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    for (set.connections[0..], 0..) |*connection, at| {
        if (!connection.talks()) continue;
        const due = connection.transport.deadline() orelse continue;
        if (due > now_ns) continue;
        connection.transport.expire(now_ns);
        hear(self, set, @intCast(at), now_ns);
    }
}

/// Reads what the transport made of a datagram, a chunk or an expiry, one thing at a time, until
/// it has nothing more or the connection fails. One answer or reset for each stream at most, and
/// `quic_connection_events_max` of the connection's own: what a flood leaves is read next time.
fn hear(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    const events_max = self.requests.len + constants.quic_connection_events_max;
    var events: usize = 0;
    while (events < events_max) : (events += 1) {
        const connection = &set.connections[server];
        if (connection.state == .closed) return;
        const next = connection.transport.next(&self.answer) orelse return;
        switch (next) {
            .up => |alpn| up(self, set, server, alpn, now_ns),
            .refused, .closed => connection_module.fail(self, set, server, now_ns),
            .goaway => connection_module.drain(set, server),
            .answered => |answered| answer(self, set, server, answered, now_ns),
            .reset => |stream| ended(self, set, server, stream, null, now_ns),
            .ticket => |ticket| set.tickets[server] = .{ .ticket = ticket, .since_ns = now_ns },
        }
    }
}

/// The handshake ended. The connection is up only on the transport's protocol, and each waiting
/// request opens its stream in the order it was taken (request rules 2 and 4).
fn up(self: anytype, set: anytype, server: u8, alpn: []const u8, now_ns: u64) void {
    const connection = &set.connections[server];
    assert(connection.state == .handshaking);
    // "DoQ support is indicated by selecting the Application-Layer Protocol Negotiation (ALPN)
    // token "doq" in the crypto handshake" (RFC 9250 §4.1), HTTP/3's by "h3" (RFC 9114 §3.2), and
    // "HTTP/2 connections over TLS MUST use protocol negotiation in TLS" (RFC 9113 §3.3), with
    // "h2" (§3.2). colibri's QUIC does not check it.
    if (!std.mem.eql(u8, alpn, connection_module.protocol_of(self, set))) return connection_module.fail(self, set, server, now_ns);
    connection.state = .up;
    connection_module.open_waiting(self, set, server, now_ns);
}

/// A stream was answered. Over DoQ it holds one message and its prefix, and the message's ID is 0;
/// anything else is a protocol error, which fails the connection (request rule 5). An answer
/// longer than the engine's buffer fails it too. Over DoH it is a response, whose content goes to
/// the lookup with its `Age`.
fn answer(self: anytype, set: anytype, server: u8, answered: anytype, now_ns: u64) void {
    if (answered.len > self.answer.len) return connection_module.fail(self, set, server, now_ns);
    const content = self.answer[0..answered.len];
    if (answered.http) |http| return ended(self, set, server, answered.stream, response(http, content), now_ns);
    const message = doq_message(content) orelse return connection_module.fail(self, set, server, now_ns);
    ended(self, set, server, answered.stream, .{ .message = message, .age_seconds = 0 }, now_ns);
}

/// What a lookup is told of a stream: its answer, and the answer's `Age` in seconds.
const Answer = struct { message: []const u8, age_seconds: u32 };

/// A DoH response's answer, or null for a failed request. "A successful HTTP response with a 2xx
/// status code ... is used for any valid DNS response", and "HTTP responses with non-successful
/// HTTP status codes do not contain replies to the original DNS question" (RFC 8484 §4.2.1).
/// Content that is not a DNS message, or was coded, is none either (request rule 12). The TTLs
/// are lowered by the `Age` (RFC 8484 §5.1), which the lookup does.
fn response(http: anytype, content: []const u8) ?Answer {
    const status = http.status;
    if (status < constants.http_status_success_first or status > constants.http_status_success_last) return null;
    if (!http.dns_message) return null;
    return .{ .message = content, .age_seconds = http.age_seconds };
}

/// The message a DoQ stream carries, or null for a protocol error. "All DNS messages ... sent over
/// DoQ connections MUST be encoded as a 2-octet length field followed by the message content"
/// (RFC 9250 §4.2), so a FIN before the prefix's octets have come, or octets after them, is an
/// error (§4.3.3). So is "a message with a non-zero Message ID" (§4.3.3). A message too short to
/// hold an ID goes to the lookup, which reads it as it reads any short message.
pub fn doq_message(bytes: []const u8) ?[]const u8 {
    const prefix = cocuyo.constants.tcp_prefix_bytes;
    if (bytes.len < prefix) return null;
    const message = bytes[prefix..];
    if (cocuyo.message_len(bytes[0..prefix]) != message.len) return null;
    if (message.len < @sizeOf(u16)) return message;
    if (std.mem.readInt(u16, message[0..@sizeOf(u16)], .big) != 0) return null;
    return message;
}

/// A stream ended: answered, or failed when `answered` is null. The lookup hears it if the request
/// is still its attempt (request rules 5 and 7), and the slot is free.
fn ended(self: anytype, set: anytype, server: u8, stream: u64, answered: ?Answer, now_ns: u64) void {
    // A stream the engine let go of: its request was cancelled, and whatever it carries tells
    // nobody (request rule 6).
    const index = request_module.of_stream(self, server, stream) orelse return;
    const request = &self.requests[index];
    if (request_module.current(self, index)) {
        if (answered) |taken| {
            _ = self.resolver.on_request_answer(request.handle, request.transaction, taken.message, taken.age_seconds, now_ns);
        } else {
            self.resolver.on_request_failed(request.handle, request.transaction, now_ns);
        }
    }
    request.live = false;
    const connection = &set.connections[server];
    assert(connection.streams >= 1);
    connection.streams -= 1;
    if (connection.users() == 0) connection.idle_since_ns = now_ns;
    connection_module.drained(set, server);
}

// Tests.

const testing = std.testing;

test "a DoQ stream is one message after its prefix, with an ID of 0, or it is a protocol error" {
    const header_zero = [_]u8{ 0, 0, 0x81, 0x80 };
    try testing.expectEqualSlices(u8, &header_zero, doq_message(&([_]u8{ 0, 4 } ++ header_zero)).?);
    // A FIN before the prefix's octets have all come, and octets after them (RFC 9250 §4.3.3).
    try testing.expectEqual(@as(?[]const u8, null), doq_message(&([_]u8{ 0, 5 } ++ header_zero)));
    try testing.expectEqual(@as(?[]const u8, null), doq_message(&([_]u8{ 0, 3 } ++ header_zero)));
    try testing.expectEqual(@as(?[]const u8, null), doq_message(&[_]u8{0}));
    // A message whose ID is not 0 (RFC 9250 §4.2.1, §4.3.3).
    try testing.expectEqual(@as(?[]const u8, null), doq_message(&[_]u8{ 0, 4, 0, 1, 0x81, 0x80 }));
    // A message too short for an ID is the lookup's to refuse.
    try testing.expectEqualSlices(u8, &[_]u8{7}, doq_message(&[_]u8{ 0, 1, 7 }).?);
}
