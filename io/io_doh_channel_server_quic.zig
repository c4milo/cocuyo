//! A DoH server over colibri's server over QUIC, for `cocuyo_doh`'s tests (docs/design.md §24, DoH
//! over colibri's client): colibri's endpoint under the test identity (`io_doh_channel_identity`),
//! selecting `h3`, which answers each GET as the TCP server does (`io_doh_channel_server.zig`). QUIC
//! reads a response's content in place until the request is done, so each request answered keeps
//! a buffer of its own until then.
const std = @import("std");
const cocuyo = @import("cocuyo");
const server = @import("server");
const tls = @import("tls");
const identity = @import("io_doh_channel_identity.zig");
const constants = @import("io_doh_channel_constants.zig");
const tcp_server = @import("io_doh_channel_server.zig");

/// The connections the server holds at once: a test's channel, and the one after it.
const connections_max = 2;
/// The responses in flight at once, each with its content until it is done.
const responses_max = 4;
/// Keys a server needs, each one octet repeated, and the octet its stream is seeded with.
/// Test-only values.
const cookie_octet = 0x5d;
const ticket_octet = 0x7f;
const stream_octet = 0x34;
const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_octet);
const ticket_key: [tls.constants.server_key_len]u8 = @splat(ticket_octet);
const alpn = [_][]const u8{"h3"};

const Endpoint = server.EndpointOf(connections_max, constants.receive_bytes);

/// A response whose content QUIC still reads: the connection and the request it answers.
const Response = struct {
    live: bool = false,
    connection: *server.QuicConnection = undefined,
    id: server.Id = 0,
    content: [cocuyo.constants.message_bytes_max]u8 = undefined,
};

pub const QuicServer = struct {
    script: tcp_server.Script = .{},
    tls_config: tls.quic.ServerConfig = undefined,
    quic_config: server.QuicConfig = undefined,
    endpoint_config: server.EndpointConfig = undefined,
    endpoint: Endpoint = undefined,
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(stream_octet)),
    /// The datagram being read: the suite opens it in place.
    inbound: [constants.datagram_bytes]u8 = undefined,
    responses: [responses_max]Response = @splat(.{}),
    /// What it heard, which a test reads, as the TCP server keeps it.
    answered: usize = 0,
    held: usize = 0,
    query: [cocuyo.constants.message_bytes_max]u8 = undefined,
    query_len: usize = 0,
    accept: tcp_server.Heard = .{},
    accept_encoding: tcp_server.Heard = .{},

    pub fn init(self: *QuicServer, script: tcp_server.Script, unix_seconds: u64, now_ns: u64) !void {
        self.* = .{ .script = script };
        try self.tls_config.init(.{
            .ecdsa_p256 = .{ .chain = &identity.chain, .public_key = identity.public_key, .private_key = identity.private_key },
            .cookie_key = &cookie_key,
            .ticket_key = if (script.tickets) &ticket_key else null,
            .alpn = &alpn,
        });
        self.quic_config = .{ .tls = &self.tls_config };
        self.endpoint_config = .{ .quic = &self.quic_config };
        self.endpoint.init(&self.endpoint_config, self.stream.random(), unix_seconds, now_ns);
    }

    /// Takes a datagram from `from`, and answers each request the connection that took it reads.
    pub fn receive(self: *QuicServer, bytes: []const u8, from: server.quic_connection.PeerAddress, answerer: tcp_server.Answerer, now_ns: u64) void {
        if (bytes.len > self.inbound.len) return;
        @memcpy(self.inbound[0..bytes.len], bytes);
        const connection = self.endpoint.receive(self.inbound[0..bytes.len], .not_ect, from, now_ns) orelse return;
        self.read(connection, answerer, now_ns);
    }

    /// The next datagram the server owes, written into `out`.
    pub fn send(self: *QuicServer, out: []u8, now_ns: u64) ?[]const u8 {
        const sent = self.endpoint.send(out, now_ns) orelse return null;
        return sent.octets;
    }

    pub fn deadline(self: *QuicServer) ?u64 {
        return self.endpoint.deadline_ns();
    }

    pub fn expire(self: *QuicServer, now_ns: u64) void {
        self.endpoint.on_instant(now_ns);
        // Bounded by the connections the endpoint holds.
        for (0..connections_max) |_| {
            const ended = self.endpoint.ended() orelse break;
            self.forget(ended);
        }
    }

    /// Reads what `connection` has to say until it says nothing more.
    fn read(self: *QuicServer, connection: *server.QuicConnection, answerer: tcp_server.Answerer, now_ns: u64) void {
        // Bounded: each pass reads one event, and a datagram carries finitely many.
        for (0..constants.datagram_bytes) |_| {
            const received = connection.receive(now_ns) catch return;
            const event = received.event orelse return;
            switch (event) {
                .request => |request| self.answer(connection, request, answerer),
                .done => |done| self.free(connection, done.id),
                .cancelled => |cancelled| self.free(connection, cancelled.id),
                .body, .trailers => {},
            }
        }
    }

    fn answer(self: *QuicServer, connection: *server.QuicConnection, request: server.Request, answerer: tcp_server.Answerer) void {
        const query = tcp_server.read_request(self, request) orelse return;
        if (self.script.hold) {
            self.held += 1;
            return;
        }
        const response = for (&self.responses) |*response| {
            if (!response.live) break response;
        } else return;
        const len = answerer.answer(answerer.context, query, &response.content) orelse return;
        response.live = true;
        response.connection = connection;
        response.id = request.id;
        if (tcp_server.respond(connection, request.id, self.script, response.content[0..len])) {
            self.answered += 1;
        } else {
            response.live = false;
        }
    }

    /// A response's content is the server's again.
    fn free(self: *QuicServer, connection: *server.QuicConnection, id: server.Id) void {
        for (&self.responses) |*response| {
            if (response.live and response.connection == connection and response.id == id) response.live = false;
        }
    }

    /// Every response of a connection that is over.
    fn forget(self: *QuicServer, connection: *server.QuicConnection) void {
        for (&self.responses) |*response| {
            if (response.live and response.connection == connection) response.live = false;
        }
    }
};
