//! The engine's QUIC connections (docs/design.md §24, request rules 1 to 4 and 8 to 11). Each
//! server of a request configuration has a connection slot of its own, and a connection is never
//! closed to make room (request rule 1). One opening of a slot is one QUIC connection over one
//! datagram socket, with one multishot receive into the engine's datagram group.
//!
//! What the loop borrows from a slot outlives the opening that lent it: the datagram in flight and
//! where it goes (`Send`, request rule 8). So a slot opened again sends nothing until the send of
//! an earlier opening has ended, and an event of an opening that is gone is told from the
//! current one's by the incarnation its `user_data` carries.
//!
//! Free functions over the engine, split out of `io_request.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const tls = @import("io_tls.zig");
const request_module = @import("io_request.zig");
const request_template = @import("io_request_template.zig");

/// One opening of a server's connection slot: its stage, its socket and receive, the transport's
/// state, and the requests on it. `lookups` bounds the queue.
pub fn Connection(comptime Quic: type, comptime lookups: u16) type {
    return struct {
        const Self = @This();
        /// A draining connection's server sent GOAWAY: it takes no new stream, and closes once its
        /// last one has ended (request rule 13).
        pub const State = enum { closed, handshaking, up, draining, closing };

        state: State = .closed,
        descriptor: ?rotor.Descriptor = null,
        /// The multishot receive every datagram of the connection arrives on, while it is armed.
        /// Null when the loop refused the last arming, which the next drive asks for again.
        receive: ?rotor.Handle = null,
        quic: Quic = .{},
        /// The requests waiting for the handshake's end, or for the close to end, oldest first
        /// (request rules 4 and 9), and how many have a stream.
        queue: [lookups]u16 = undefined,
        queue_len: u16 = 0,
        streams: u16 = 0,
        idle_since_ns: u64 = 0,
        /// The port this opening goes to: a DoQ server's TLS port, or its template's for a DoH one.
        port: u16 = 0,
        /// A datagram the transport made that the loop refused: it waits in the slot's buffer
        /// and goes at the next drive (request rule 8).
        made: u16 = 0,
        /// Which opening of the slot this is. It outlives the opening, as a TCP connection's does.
        incarnation: u32 = 0,

        /// How many requests are on it: waiting, and with a stream.
        pub fn users(self: *const Self) u16 {
            return self.queue_len + self.streams;
        }

        /// A new opening: everything reset but the incarnation, the transport's secrets wiped.
        /// The fields are set one by one, so the queue is not written over while its requests
        /// wait to open the slot again (request rule 9).
        pub fn restart(self: *Self) void {
            self.quic.wipe();
            self.state = .closed;
            self.descriptor = null;
            self.receive = null;
            self.streams = 0;
            self.idle_since_ns = 0;
            self.made = 0;
        }
    };
}

/// What the loop borrows from a server's connection slot, whichever opening lent it: the datagram
/// in flight and where it goes, from the send's submission to its final event (request rule 8,
/// rotor decision 5, rule 3).
pub fn Send(comptime Quic: type) type {
    return struct {
        lent: bool = false,
        bytes: [Quic.datagram_bytes_max]u8 = undefined,
        outbound: rotor.datagram.Outbound = undefined,
    };
}

// Placing a request (request rules 3, 4 and 9).

/// Puts slot `index`'s request on its server's connection. A closed connection opens, and one
/// that cannot fails the request. An idle one near its negotiated idle timeout closes first, and
/// the request waits for the new one (request rule 9, RFC 9250 §4.4).
pub fn place(self: anytype, index: usize, now_ns: u64) void {
    const server = self.requests[index].server;
    const connection = &self.quic_connections[server];
    if (connection.state == .up and connection.users() == 0 and near_idle(self, server, now_ns)) {
        begin_close(self, server);
    }
    if (connection.state == .closed and !open(self, server, now_ns)) {
        return request_module.fail_all_of(self, server, now_ns);
    }
    // The connection opened above is handshaking: the request waits for its end (rule 4).
    if (connection.state == .up and open_stream(self, server, index, now_ns)) return;
    if (connection.state == .closed) return;
    enqueue(connection, @intCast(index));
}

/// Whether an idle connection that is up has less than `quic_idle_margin_ns` left before the idle
/// timeout it negotiated. "When a client prepares to send a new DNS query to the server, it
/// SHOULD check whether the idle time is sufficiently lower than the idle timer" (RFC 9250 §4.4).
fn near_idle(self: anytype, server: u8, now_ns: u64) bool {
    const connection = &self.quic_connections[server];
    return connection.quic.idle_left_ns(now_ns) < constants.quic_idle_margin_ns;
}

pub fn enqueue(connection: anytype, index: u16) void {
    assert(connection.queue_len < connection.queue.len);
    connection.queue[connection.queue_len] = index;
    connection.queue_len += 1;
}

/// Takes `index` out of the queue, keeping the order of the rest.
pub fn dequeue(connection: anytype, index: u16) void {
    const waiting = connection.queue[0..connection.queue_len];
    const at = std.mem.indexOfScalar(u16, waiting, index) orelse unreachable;
    std.mem.copyForwards(u16, waiting[at .. waiting.len - 1], waiting[at + 1 ..]);
    connection.queue_len -= 1;
}

/// Opens slot `index`'s stream on an up connection: its bytes, then FIN (RFC 9250 §4.2). False
/// when the server's stream credit has run out and the request waits (request rule 4), or when the
/// transport failed and the connection with it.
fn open_stream(self: anytype, server: u8, index: usize, now_ns: u64) bool {
    const connection = &self.quic_connections[server];
    const request = &self.requests[index];
    assert(connection.state == .up and request.live and request.stream == null);
    const opened = connection.quic.request(&request.bytes, request.len) catch {
        fail(self, server, now_ns);
        return false;
    };
    const stream = opened orelse return false;
    request.stream = stream;
    connection.streams += 1;
    return true;
}

/// Each waiting request opens its stream, in the order it was taken, until the server's credit
/// runs out (request rule 4).
pub fn open_waiting(self: anytype, server: u8, now_ns: u64) void {
    const connection = &self.quic_connections[server];
    while (connection.state == .up and connection.queue_len > 0) {
        const index = connection.queue[0];
        if (!open_stream(self, server, index, now_ns)) return;
        dequeue(connection, index);
    }
}

// Opening and closing (request rules 1, 7, 9 and 10).

/// The ALPN token a request configuration's servers speak: `h3` for DoH (RFC 9114 §3.2), `doq`
/// for DoQ (RFC 9250 §4.1).
pub fn protocol_of(self: anytype) []const u8 {
    return if (self.config.uses_https()) constants.quic_alpn_h3 else constants.quic_alpn_doq;
}

/// Opens server `server`'s connection: its socket, its receive, and the transport's first flight,
/// resuming with the server's ticket, which it spends (request rules 1 and 10). False when the
/// system refused the socket or the transport could not start, which leaves the slot closed.
fn open(self: anytype, server: u8, now_ns: u64) bool {
    const connection = &self.quic_connections[server];
    assert(connection.state == .closed);
    const configured = &self.config.servers[server];
    // A DoH server's template names its port, its name and its path, and one the engine cannot
    // read fails the connection before it opens (docs/design.md §24, DoH over HTTP/3).
    const template: ?request_template.Template = if (configured.https) |https| request_template.split(https.template) orelse return false else null;
    const family = configured.endpoint.address.family;
    const descriptor = udp.Sockets.open_bound(family, 0, udp.Sockets.local_for(self.config, family)) catch return false;
    udp.size_buffers(descriptor, self.config);
    connection.restart();
    connection.incarnation +%= 1;
    connection.state = .handshaking;
    connection.descriptor = descriptor;
    connection.port = if (template) |split| split.port else configured.quic.?.port;
    return start(self, server, template, now_ns);
}

/// Starts the transport of server `server`'s connection, whose socket is open: its first flight,
/// resuming with the server's ticket, which it spends (request rule 10). False when it cannot
/// start, which closes the socket again.
fn start(self: anytype, server: u8, template: ?request_template.Template, now_ns: u64) bool {
    const connection = &self.quic_connections[server];
    const configured = &self.config.servers[server];
    const kept = spend(self, server, now_ns);
    // A DoQ server is known as a TLS server is (RFC 9250 §5.1), and a DoH server by its
    // template's host (RFC 9110 §4.3.4), which `split` has read as a name.
    var named: cocuyo.Tls = undefined;
    if (template) |split| named = .{ .name = cocuyo.Name.from_text(split.host) catch unreachable };
    connection.quic.start(.{
        .tls = if (template != null) &named else &configured.quic.?,
        .https = template,
        .alpn = protocol_of(self),
        .ticket = if (kept) |ticket| ticket.ticket else null,
        .ticket_age_ns = if (kept) |ticket| now_ns -| ticket.since_ns else 0,
        .context = &self.quic_context,
        .now_ns = now_ns,
    }) catch {
        shut(self, server);
        return false;
    };
    arm(self, server);
    return true;
}

/// Where server `server`'s connection goes: its address, on the port its opening chose. A DoQ
/// server's is UDP's 853 unless the configuration named another (RFC 9250 §4.1.1), and a DoH
/// server's is its template's (RFC 9114 §3.1).
pub fn endpoint_of(self: anytype, server: u8) cocuyo.Endpoint {
    var endpoint = self.config.servers[server].endpoint;
    endpoint.port = self.quic_connections[server].port;
    return endpoint;
}

/// Spends server `server`'s ticket, unless it has lapsed. A ticket is used once, since reuse lets
/// an observer link two connections (RFC 9846 §C.4, request rule 10).
fn spend(self: anytype, server: u8, now_ns: u64) ?tls.Kept(@TypeOf(self.*).Quic) {
    const kept = self.quic_tickets[server] orelse return null;
    self.quic_tickets[server] = null;
    if (!tls.fresh(@TypeOf(self.*).Quic, &kept, now_ns)) return null;
    return kept;
}

/// Server `server`'s connection fails: each request on it hears so once, and it closes (request
/// rule 7).
pub fn fail(self: anytype, server: u8, now_ns: u64) void {
    const connection = &self.quic_connections[server];
    // One that drains or closes fails the requests on its streams alone, and opens again for those
    // that wait, which never went to it (request rule 13).
    if (connection.state == .draining or connection.state == .closing) {
        request_module.fail_streams_of(self, server, now_ns);
        return reopen(self, server, now_ns);
    }
    request_module.fail_all_of(self, server, now_ns);
    shut(self, server);
}

/// The server sent GOAWAY: the connection takes no new stream, and drains (request rule 13). One
/// after the first changes nothing: "An endpoint MAY send multiple GOAWAY frames" (RFC 9114 §5.2),
/// and a draining connection has a stream. A closing one reads nothing, and a handshaking one has
/// no stream a GOAWAY could come on.
pub fn drain(self: anytype, server: u8) void {
    const connection = &self.quic_connections[server];
    assert(connection.state == .up or connection.state == .draining);
    connection.state = .draining;
    drained(self, server);
}

/// A draining connection whose last stream has ended closes as an idle one does, and opens again
/// for the requests that wait once its CONNECTION_CLOSE has gone (request rules 9 and 13).
pub fn drained(self: anytype, server: u8) void {
    const connection = &self.quic_connections[server];
    if (connection.state != .draining or connection.streams != 0) return;
    connection.state = .closing;
    connection.quic.close();
}

/// Ends an opening: its receive cancelled, which is what makes the loop let it go (rotor decision
/// 5, rule 1), and its socket closed. A datagram in flight keeps the slot's buffer until its final
/// event, which then speaks for nobody. The queue is left as it is, for `closed` to open again.
fn shut(self: anytype, server: u8) void {
    const connection = &self.quic_connections[server];
    if (connection.receive) |handle| self.loop.cancel(handle);
    if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    connection.restart();
}

/// An idle connection closes: the transport makes CONNECTION_CLOSE with DOQ_NO_ERROR (RFC 9250
/// §4.4), and the socket closes once that datagram has gone (request rule 9).
fn begin_close(self: anytype, server: u8) void {
    const connection = &self.quic_connections[server];
    assert(connection.state == .handshaking or connection.state == .up);
    assert(connection.users() == 0);
    connection.state = .closing;
    connection.quic.close();
}

/// The CONNECTION_CLOSE has gone: the connection closes, and opens again for the requests taken
/// while it closed (request rule 9). A new one that cannot open fails them.
pub fn closed(self: anytype, server: u8, now_ns: u64) void {
    assert(self.quic_connections[server].state == .closing);
    reopen(self, server, now_ns);
}

/// Ends the opening, and opens again for the requests that wait.
fn reopen(self: anytype, server: u8, now_ns: u64) void {
    const connection = &self.quic_connections[server];
    shut(self, server);
    if (connection.queue_len == 0) return;
    if (!open(self, server, now_ns)) request_module.fail_all_of(self, server, now_ns);
}

/// Closes every connection with no request on it for `quic_idle_ns`, or near the idle timeout it
/// negotiated (request rule 9).
pub fn close_idle(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    for (self.quic_connections[0..], 0..) |*connection, at| {
        if (connection.state != .handshaking and connection.state != .up) continue;
        if (connection.users() != 0) continue;
        const idle = now_ns -| connection.idle_since_ns >= self.quic_idle_ns;
        const server: u8 = @intCast(at);
        if (idle or (connection.state == .up and near_idle(self, server, now_ns))) begin_close(self, server);
    }
}

// What a drive does last (request rules 4 and 8, the datagram's rule 1).

/// Connection by connection: a receive armed on each socket that has none, the streams the
/// server's credit now allows, and the datagram the transport owes sent when the buffer is back.
/// The loop may refuse either, and the next drive asks again.
pub fn tend(self: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    for (self.quic_connections[0..], 0..) |*connection, at| {
        const server: u8 = @intCast(at);
        if (connection.state == .closed) continue;
        if (connection.receive == null) arm(self, server);
        open_waiting(self, server, now_ns);
        if (connection.state != .closed) send(self, server, now_ns);
    }
}

/// Arms the connection's multishot receive, which every datagram from its server arrives on.
fn arm(self: anytype, server: u8) void {
    const connection = &self.quic_connections[server];
    assert(connection.receive == null);
    const descriptor = connection.descriptor orelse return;
    const operation: rotor.Operation = .receive_from(user_data_of(self, .quic_receive, server), descriptor, constants.group_id);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) == 1) connection.receive = handles[0];
}

/// Sends the next datagram the connection owes, when the slot's buffer is not lent: the one the
/// loop refused before, or a new one the transport makes.
fn send(self: anytype, server: u8, now_ns: u64) void {
    const connection = &self.quic_connections[server];
    const slot = &self.quic_sends[server];
    if (slot.lent) return;
    if (connection.made == 0) connection.made = @intCast(connection.quic.datagram(&slot.bytes, now_ns));
    if (connection.made == 0) return;
    slot.outbound = udp.outbound_to(endpoint_of(self, server));
    const operation: rotor.Operation = .{
        .user_data = user_data_of(self, .quic_send, server),
        .kind = .{ .send_to = .{
            .socket = connection.descriptor.?,
            .buffer = .{ .bytes = slot.bytes[0..connection.made] },
            .to = &slot.outbound,
        } },
    };
    if (self.loop.submit(&.{operation}, &.{}) != 1) return;
    slot.lent = true;
    connection.made = 0;
}

/// The `user_data` of an operation on server `server`'s connection: the server, and its opening.
fn user_data_of(self: anytype, kind: @import("io.zig").Kind, server: u8) u64 {
    const incarnation: u64 = self.quic_connections[server].incarnation;
    return @TypeOf(self.*).user_data(kind, (incarnation << constants.quic_incarnation_shift) | server);
}

// The timer (request rule 11).

/// The soonest QUIC deadline of every open connection, or null for none.
pub fn next_deadline(self: anytype) ?u64 {
    if (comptime !@TypeOf(self.*).Quic.enabled) return null;
    var soonest: ?u64 = null;
    for (self.quic_connections[0..]) |*connection| {
        if (connection.state == .closed) continue;
        const due = connection.quic.deadline() orelse continue;
        soonest = if (soonest) |earlier| @min(earlier, due) else due;
    }
    return soonest;
}

// The engine going away, or taking a new configuration.

/// Ends every connection's receive, so the loop can be drained (rotor decision 5, rule 7). The
/// sockets stay open until `close_all`, which runs after the drain.
pub fn cancel_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    for (self.quic_connections[0..]) |*connection| {
        if (connection.receive) |handle| self.loop.cancel(handle);
        connection.receive = null;
    }
}

/// Closes every connection's socket, whatever it was doing: the engine is going away, or taking
/// a new configuration with nothing in flight.
pub fn close_all(self: anytype) void {
    if (comptime !@TypeOf(self.*).Quic.enabled) return;
    for (self.quic_connections[0..]) |*connection| {
        if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
        connection.restart();
        connection.queue_len = 0;
    }
}
