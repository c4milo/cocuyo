//! The engine's request connections (docs/design.md §24, request rules 1 to 4, 7 to 10, and 13 to
//! 16). Each server of a request configuration has a connection slot of its own, and a connection
//! is never closed to make room (request rule 1). One opening of a slot is one QUIC connection over
//! one datagram socket, with one multishot receive into the engine's datagram group; or, for DoH
//! over HTTP/2, one TCP connection, which connects before it handshakes, with one multishot
//! receive into the engine's TCP chunks.
//!
//! What the loop borrows from a slot outlives the opening that lent it: the octets in flight, where
//! a datagram goes, and where a connect goes (`Send`, request rules 8 and 14). So a slot opened
//! again sends nothing until the send of an earlier opening has ended, a TCP slot connects nothing
//! until the connect of an earlier opening has ended, and an event of an opening that is gone is
//! told from the current one's by the incarnation its `user_data` carries.
//!
//! What a drive does last is `io_request_connection_tend.zig`'s. Free functions over the engine,
//! split out of `io_request.zig` so each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const udp = @import("io_udp.zig");
const tls = @import("io_tls.zig");
const request_module = @import("io_request.zig");
const request_template = @import("io_request_template.zig");
const tend_module = @import("io_request_connection_tend.zig");
const Kind = @import("io.zig").Kind;

/// One opening of a server's connection slot: its stage, its socket and receive, the transport's
/// state, and the requests on it. `lookups` bounds the queue.
pub fn Connection(comptime Quic: type, comptime lookups: u16) type {
    return struct {
        const Self = @This();
        /// A draining connection's server sent GOAWAY: it takes no new stream, and closes once its
        /// last one has ended (request rule 13). Over TCP a connection connects before it
        /// handshakes, and waits, reopening, while a connect of an earlier opening still borrows
        /// the slot's address (request rule 14).
        pub const State = enum { closed, reopening, connecting, handshaking, up, draining, closing };

        state: State = .closed,
        descriptor: ?rotor.Descriptor = null,
        /// Over TCP, this opening's connect while it is in flight (request rule 14).
        connect: ?rotor.Handle = null,
        /// The multishot receive every datagram or chunk of the connection arrives on, while it is
        /// armed. Null when the loop refused the last arming, which the next drive asks for again.
        receive: ?rotor.Handle = null,
        transport: Quic = .{},
        /// The requests waiting for the handshake's end, or for the close to end, oldest first
        /// (request rules 4 and 9), and how many have a stream.
        queue: [lookups]u16 = undefined,
        queue_len: u16 = 0,
        streams: u16 = 0,
        idle_since_ns: u64 = 0,
        /// The port this opening goes to: a DoQ server's TLS port, or its template's for a DoH one.
        port: u16 = 0,
        /// The octets of the transport's output in the slot's buffer that have not gone. Over UDP,
        /// a datagram the loop refused, which goes at the next drive (request rule 8). Over TCP,
        /// what the transport made, of which `sent` octets went in a send that went short: the rest
        /// goes next (request rule 15).
        made: u16 = 0,
        sent: u16 = 0,
        /// Which opening of the slot this is. It outlives the opening, as a TCP connection's does.
        incarnation: u32 = 0,

        /// How many requests are on it: waiting, and with a stream.
        pub fn users(self: *const Self) u16 {
            return self.queue_len + self.streams;
        }

        /// Whether the connection has its receive and sends: once its socket is open, and over
        /// TCP once its connect has succeeded too (request rule 14).
        pub fn talks(self: *const Self) bool {
            return self.state != .closed and self.state != .reopening and self.state != .connecting;
        }

        /// A new opening: everything reset but the incarnation, the transport's secrets wiped.
        /// The fields are set one by one, so the queue is not written over while its requests
        /// wait to open the slot again (request rule 9).
        pub fn restart(self: *Self) void {
            self.transport.wipe();
            self.state = .closed;
            self.descriptor = null;
            self.connect = null;
            self.receive = null;
            self.streams = 0;
            self.idle_since_ns = 0;
            self.made = 0;
            self.sent = 0;
        }
    };
}

/// One transport's request connections: a slot for each server, what the loop borrows from each,
/// the newest ticket each server's connections were given, what every session starts from, and
/// how long a connection with no request on it is kept (request rules 1, 8, 9 and 10). An engine
/// with no request transport holds a set of no slots.
pub fn Set(comptime Quic: type, comptime servers: usize, comptime lookups: u16) type {
    return struct {
        connections: [servers]Connection(Quic, lookups) = @splat(.{}),
        sends: [servers]Send(Quic) = @splat(.{}),
        tickets: [servers]?tls.Kept(Quic) = @splat(null),
        context: Quic.Context = .{},
        idle_ns: u64 = constants.quic_idle_ns_default,

        /// The transport the set's connections run.
        pub const Transport = Quic;
        /// Whether they run over TCP, as DoH over HTTP/2 does (request rules 14 to 16), or over
        /// UDP, as QUIC does.
        pub const stream = Quic.socket == .stream;
        /// What the loop's events on them are.
        pub const connect_kind: Kind = .h2_connect;
        pub const send_kind: Kind = if (stream) .h2_send else .quic_send;
        pub const receive_kind: Kind = if (stream) .h2_receive else .quic_receive;
    };
}

/// What the loop borrows from a server's connection slot, whichever opening lent it: the octets in
/// flight and where a datagram goes, from the send's submission to its final event (request rule
/// 8, rotor decision 5, rule 3), and over TCP where the connect goes, from the connect's submission
/// to its final event (request rule 14).
pub fn Send(comptime Quic: type) type {
    return struct {
        lent: bool = false,
        bytes: [Quic.output_bytes_max]u8 = undefined,
        outbound: rotor.datagram.Outbound = undefined,
        connecting: bool = false,
        address: rotor.Address = undefined,
    };
}

// Placing a request (request rules 3, 4 and 9).

/// Puts slot `index`'s request on its server's connection. A closed connection opens, and one
/// that cannot fails the request. An idle one near its negotiated idle timeout closes first, and
/// the request waits for the new one (request rule 9, RFC 9250 §4.4).
pub fn place(self: anytype, set: anytype, index: usize, now_ns: u64) void {
    const server = self.requests[index].server;
    const connection = &set.connections[server];
    if (connection.state == .up and connection.users() == 0 and near_idle(set, server, now_ns)) {
        begin_close(set, server);
    }
    if (connection.state == .closed and !open(self, set, server, now_ns)) {
        return request_module.fail_all_of(self, set, server, now_ns);
    }
    // The connection opened above connects or handshakes: the request waits for its end (rule 4).
    if (connection.state == .up and open_stream(self, set, server, index, now_ns)) return;
    if (connection.state == .closed) return;
    enqueue(connection, @intCast(index));
}

/// Whether an idle connection that is up has less than `quic_idle_margin_ns` left before the idle
/// timeout it negotiated. "When a client prepares to send a new DNS query to the server, it
/// SHOULD check whether the idle time is sufficiently lower than the idle timer" (RFC 9250 §4.4).
fn near_idle(set: anytype, server: u8, now_ns: u64) bool {
    const connection = &set.connections[server];
    return connection.transport.idle_left_ns(now_ns) < constants.quic_idle_margin_ns;
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
fn open_stream(self: anytype, set: anytype, server: u8, index: usize, now_ns: u64) bool {
    const connection = &set.connections[server];
    const request = &self.requests[index];
    assert(connection.state == .up and request.live and request.stream == null);
    const opened = connection.transport.request(&request.bytes, request.len) catch {
        fail(self, set, server, now_ns);
        return false;
    };
    const stream = opened orelse return false;
    request.stream = stream;
    connection.streams += 1;
    return true;
}

/// Each waiting request opens its stream, in the order it was taken, until the server's credit
/// runs out (request rule 4).
pub fn open_waiting(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    const connection = &set.connections[server];
    while (connection.state == .up and connection.queue_len > 0) {
        const index = connection.queue[0];
        if (!open_stream(self, set, server, index, now_ns)) return;
        dequeue(connection, index);
    }
}

// Opening (request rules 1, 10 and 14).

/// The ALPN token a set's connections speak: `h2` over TCP (RFC 9113 §3.2), `h3` for DoH over
/// QUIC (RFC 9114 §3.2), and `doq` for DoQ (RFC 9250 §4.1).
pub fn protocol_of(self: anytype, set: anytype) []const u8 {
    if (comptime @TypeOf(set.*).stream) return constants.alpn_h2;
    return if (self.config.uses_https()) constants.quic_alpn_h3 else constants.quic_alpn_doq;
}

/// A DoH server's template, split; null for a DoQ server. `open` has refused a server whose
/// template the engine cannot read.
fn template_of(self: anytype, server: u8) ?request_template.Template {
    const https = self.config.servers[server].https orelse return null;
    return request_template.split(https.template);
}

/// Opens server `server`'s connection. Over UDP: its socket, its receive, and the transport's first
/// flight, resuming with the server's ticket, which it spends (request rules 1 and 10). Over TCP:
/// its socket and its connect (request rule 14). False when the system refused the socket, the
/// loop the connect, or the transport could not start, which leaves the slot closed.
fn open(self: anytype, set: anytype, server: u8, now_ns: u64) bool {
    const connection = &set.connections[server];
    assert(connection.state == .closed);
    const configured = &self.config.servers[server];
    // A DoH server's template names its port, its name and its path, and one the engine cannot
    // read fails the connection before it opens (docs/design.md §24, DoH over HTTP/3).
    if (configured.https != null and template_of(self, server) == null) return false;
    const port = if (template_of(self, server)) |split| split.port else configured.quic.?.port;
    if (comptime @TypeOf(set.*).stream) return connect(self, set, server, port);
    const family = configured.endpoint.address.family;
    const descriptor = udp.Sockets.open_bound(family, 0, udp.Sockets.local_for(self.config, family)) catch return false;
    udp.size_buffers(descriptor, self.config);
    connection.restart();
    connection.incarnation +%= 1;
    connection.state = .handshaking;
    connection.descriptor = descriptor;
    connection.port = port;
    return start(self, set, server, now_ns);
}

/// Over TCP: the connection's socket, and its connect, whose address the loop borrows until the
/// connect's final event. While a connect of an earlier opening still borrows it, the connection
/// waits instead, and opens at that connect's end (request rule 14). False when the system refused
/// the socket or the loop the connect, which leaves the slot closed.
fn connect(self: anytype, set: anytype, server: u8, port: u16) bool {
    const connection = &set.connections[server];
    const slot = &set.sends[server];
    connection.port = port;
    if (slot.connecting) {
        connection.state = .reopening;
        return true;
    }
    const endpoint = endpoint_of(self, set, server);
    const descriptor = rotor.sync.open_socket(udp.family_of(endpoint)) catch return false;
    udp.size_buffers(descriptor, self.config);
    connection.restart();
    connection.incarnation +%= 1;
    connection.state = .connecting;
    connection.descriptor = descriptor;
    slot.address = udp.address_of(endpoint);
    const operation: rotor.Operation = .connect(user_data_of(self, set, @TypeOf(set.*).connect_kind, server), descriptor, &slot.address);
    var handles: [1]rotor.Handle = undefined;
    if (self.loop.submit(&.{operation}, &handles) != 1) {
        rotor.sync.close_now(descriptor);
        connection.restart();
        return false;
    }
    connection.connect = handles[0];
    slot.connecting = true;
    return true;
}

/// Over TCP, the connect of server `server`'s connection ended, and the loop gives the address
/// back (request rule 14). An earlier opening's lets a connection that waited for it open. The
/// current opening's success arms its receive, and the transport starts; its failure fails the
/// connection.
pub fn connected(self: anytype, set: anytype, server: u8, succeeded: bool, now_ns: u64) void {
    const connection = &set.connections[server];
    const slot = &set.sends[server];
    assert(slot.connecting);
    slot.connecting = false;
    if (connection.state == .reopening) {
        connection.state = .closed;
        if (connection.queue_len == 0) return;
        if (!open(self, set, server, now_ns)) request_module.fail_all_of(self, set, server, now_ns);
        return;
    }
    if (connection.state != .connecting) return;
    connection.connect = null;
    if (!succeeded) return fail(self, set, server, now_ns);
    connection.state = .handshaking;
    connection.idle_since_ns = now_ns;
    if (!start(self, set, server, now_ns)) request_module.fail_all_of(self, set, server, now_ns);
}

/// Starts the transport of server `server`'s connection, whose socket is open, or connected over
/// TCP: its first flight, resuming with the server's ticket, which it spends (request rule 10).
/// False when it cannot start, which closes the socket again.
fn start(self: anytype, set: anytype, server: u8, now_ns: u64) bool {
    const connection = &set.connections[server];
    const configured = &self.config.servers[server];
    const template = template_of(self, server);
    const kept = spend(set, server, now_ns);
    // A DoQ server is known as a TLS server is (RFC 9250 §5.1), and a DoH server by its
    // template's host (RFC 9110 §4.3.4), which `split` has read as a name.
    var named: cocuyo.Tls = undefined;
    if (template) |split| named = .{ .name = cocuyo.Name.from_text(split.host) catch unreachable };
    connection.transport.start(.{
        .tls = if (template != null) &named else &configured.quic.?,
        .https = template,
        .alpn = protocol_of(self, set),
        .ticket = if (kept) |ticket| ticket.ticket else null,
        .ticket_age_ns = if (kept) |ticket| now_ns -| ticket.since_ns else 0,
        .context = &set.context,
        .now_ns = now_ns,
    }) catch {
        shut(self, set, server);
        return false;
    };
    tend_module.arm(self, set, server);
    return true;
}

/// Where server `server`'s connection goes: its address, on the port its opening chose. A DoQ
/// server's is UDP's 853 unless the configuration named another (RFC 9250 §4.1.1), and a DoH
/// server's is its template's (RFC 9114 §3.1).
pub fn endpoint_of(self: anytype, set: anytype, server: u8) cocuyo.Endpoint {
    var endpoint = self.config.servers[server].endpoint;
    endpoint.port = set.connections[server].port;
    return endpoint;
}

/// Spends server `server`'s ticket, unless it has lapsed. A ticket is used once, since reuse lets
/// an observer link two connections (RFC 9846 §C.4, request rule 10).
fn spend(set: anytype, server: u8, now_ns: u64) ?tls.Kept(@TypeOf(set.*).Transport) {
    const kept = set.tickets[server] orelse return null;
    set.tickets[server] = null;
    if (!tls.fresh(@TypeOf(set.*).Transport, &kept, now_ns)) return null;
    return kept;
}

/// The `user_data` of an operation on server `server`'s connection: the server, and its opening.
pub fn user_data_of(self: anytype, set: anytype, kind: Kind, server: u8) u64 {
    const incarnation: u64 = set.connections[server].incarnation;
    return @TypeOf(self.*).user_data(kind, (incarnation << constants.quic_incarnation_shift) | server);
}

// Failing and closing (request rules 7, 9, 13 and 16).

/// Server `server`'s connection fails: each request on it hears so once, and it closes (request
/// rule 7).
pub fn fail(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    const connection = &set.connections[server];
    // One that drains or closes fails the requests on its streams alone, and opens again for those
    // that wait, which never went to it (request rule 13).
    if (connection.state == .draining or connection.state == .closing) {
        request_module.fail_streams_of(self, set, server, now_ns);
        return reopen(self, set, server, now_ns);
    }
    request_module.fail_all_of(self, set, server, now_ns);
    shut(self, set, server);
}

/// The server sent GOAWAY: the connection takes no new stream, and drains (request rule 13). One
/// after the first changes nothing: "An endpoint MAY send multiple GOAWAY frames" (RFC 9114 §5.2),
/// and a draining connection has a stream. A closing one reads nothing, and a handshaking one has
/// no stream a GOAWAY could come on.
pub fn drain(set: anytype, server: u8) void {
    const connection = &set.connections[server];
    assert(connection.state == .up or connection.state == .draining);
    connection.state = .draining;
    drained(set, server);
}

/// A draining connection whose last stream has ended closes as an idle one does, and opens again
/// for the requests that wait once its CONNECTION_CLOSE has gone (request rules 9 and 13).
pub fn drained(set: anytype, server: u8) void {
    const connection = &set.connections[server];
    if (connection.state != .draining or connection.streams != 0) return;
    connection.state = .closing;
    connection.transport.close();
}

/// Ends an opening: its connect and its receive cancelled, which is what makes the loop let them
/// go (rotor decision 5, rule 1), and its socket closed. A send or a connect in flight keeps what
/// it borrows of the slot's until its final event, which then speaks for nobody. The queue is left
/// as it is, for `closed` to open again.
pub fn shut(self: anytype, set: anytype, server: u8) void {
    const connection = &set.connections[server];
    if (connection.connect) |handle| self.loop.cancel(handle);
    if (connection.receive) |handle| self.loop.cancel(handle);
    if (connection.descriptor) |descriptor| rotor.sync.close_now(descriptor);
    connection.restart();
}

/// An idle connection closes: the transport makes CONNECTION_CLOSE with DOQ_NO_ERROR (RFC 9250
/// §4.4), or over TCP a GOAWAY and the session's `close_notify`, and the socket closes once they
/// have gone (request rule 9).
fn begin_close(set: anytype, server: u8) void {
    const connection = &set.connections[server];
    assert(connection.state == .handshaking or connection.state == .up);
    assert(connection.users() == 0);
    connection.state = .closing;
    connection.transport.close();
}

/// The CONNECTION_CLOSE has gone: the connection closes, and opens again for the requests taken
/// while it closed (request rule 9). A new one that cannot open fails them.
pub fn closed(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    assert(set.connections[server].state == .closing);
    reopen(self, set, server, now_ns);
}

/// Ends the opening, and opens again for the requests that wait.
fn reopen(self: anytype, set: anytype, server: u8, now_ns: u64) void {
    const connection = &set.connections[server];
    shut(self, set, server);
    if (connection.queue_len == 0) return;
    if (!open(self, set, server, now_ns)) request_module.fail_all_of(self, set, server, now_ns);
}

/// Closes every connection with no request on it for the set's `idle_ns`, or near the idle
/// timeout it negotiated (request rule 9). Over TCP one whose handshake has not ended has nothing
/// to close, and closes at once, and one that waits to connect opens no more (request rule 16).
pub fn close_idle(self: anytype, set: anytype, now_ns: u64) void {
    if (comptime !@TypeOf(set.*).Transport.enabled) return;
    for (set.connections[0..], 0..) |*connection, at| {
        if (connection.state == .closed or connection.users() != 0) continue;
        const server: u8 = @intCast(at);
        const idle = now_ns -| connection.idle_since_ns >= set.idle_ns;
        const near = connection.state == .up and near_idle(set, server, now_ns);
        if (!idle and !near) continue;
        switch (connection.state) {
            .handshaking => if (comptime @TypeOf(set.*).stream) shut(self, set, server) else begin_close(set, server),
            .up => begin_close(set, server),
            .connecting => shut(self, set, server),
            .reopening => connection.state = .closed,
            .closed, .draining, .closing => {},
        }
    }
}
