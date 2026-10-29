//! A DoH server over QUIC on colibri's `server.Endpoint`, for `cocuyo_doh`'s tests (docs/design.md
//! §24, DoH over colibri's client): an endpoint of QUIC connections under the test identity
//! (`io_doh_channel_identity`), which serves `h3` and answers each GET as the TCP server does
//! (`io_doh_channel_server.zig`). QUIC reads a response's content in place until the request is
//! done, so each request answered keeps a buffer of its own until then.
const std = @import("std");
const cocuyo = @import("cocuyo");
const server = @import("server");
const constants = @import("io_doh_channel_constants.zig");
const limits = @import("io_doh_channel_limits.zig");
const tcp_server = @import("io_doh_channel_server.zig");

/// The octet its stream is seeded with. Test-only.
const stream_octet: u8 = 0x34;
/// The events the server reads after one datagram at most. Each is an event of a request or of a
/// connection, and a datagram carries finitely many.
const events_per_input_max = limits.datagram_bytes_max;

/// An endpoint of QUIC connections alone. Each connection holds the server's unread octets in a
/// pool of the channel's size.
const Endpoint = server.EndpointOf(.{ .tcp_connections = 0, .quic_connections = limits.server_connections_max, .receive_pool_len = limits.receive_bytes_max });

/// A response whose content QUIC still reads: the request it answers, whose id names its
/// connection too.
const Response = struct {
    live: bool = false,
    id: server.RequestId = undefined,
    content: [cocuyo.limits.message_bytes_max]u8 = undefined,
};

pub const QuicServer = struct {
    script: tcp_server.Script = .{},
    config: server.Config = undefined,
    endpoint: Endpoint = undefined,
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(stream_octet)),
    /// The datagram being read: the suite opens it in place.
    inbound: [limits.datagram_bytes_max]u8 = undefined,
    responses: [limits.server_responses_max]Response = @splat(.{}),
    /// What it heard, which a test reads, as the TCP server keeps it.
    answered: usize = 0,
    held: usize = 0,
    query: [cocuyo.limits.message_bytes_max]u8 = undefined,
    query_len: usize = 0,
    accept: tcp_server.Heard = .{},
    accept_encoding: tcp_server.Heard = .{},

    pub fn init(self: *QuicServer, script: tcp_server.Script, unix_seconds: u64, now_ns: u64) !void {
        self.* = .{ .script = script };
        // The endpoint names `h3` for its QUIC connections (RFC 9114 §3.1; colibri's decision 119).
        self.config = .{ .tls = tcp_server.identity_values(script.tickets) };
        try self.endpoint.init(&self.config, self.stream.random(), unix_seconds, now_ns);
    }

    /// Takes a datagram from `from`, and answers each request the endpoint reads.
    pub fn receive(self: *QuicServer, bytes: []const u8, from: server.Address, answerer: tcp_server.Answerer, now_ns: u64) void {
        if (bytes.len > self.inbound.len) return;
        @memcpy(self.inbound[0..bytes.len], bytes);
        self.read(.{ .datagram = .{ .bytes = self.inbound[0..bytes.len], .from = from } }, answerer, now_ns);
    }

    /// The next datagram the server owes, written into `out`.
    pub fn send(self: *QuicServer, out: []u8, now_ns: u64) ?[]const u8 {
        const sent = self.endpoint.send_datagram(out, now_ns) orelse return null;
        return sent.bytes;
    }

    pub fn deadline(self: *QuicServer) ?u64 {
        return self.endpoint.deadline_ns();
    }

    /// Fires what is due, and reads what that changed: a connection that ended frees its
    /// responses.
    pub fn expire(self: *QuicServer, now_ns: u64) void {
        self.endpoint.on_instant(now_ns);
        self.read(.none, null, now_ns);
    }

    /// Hands the endpoint `input`, then reads what it says until it says nothing more. With no
    /// answerer, a request goes unanswered.
    fn read(self: *QuicServer, input: server.Input, answerer: ?tcp_server.Answerer, now_ns: u64) void {
        var next = input;
        for (0..events_per_input_max) |_| {
            const received = self.endpoint.receive(next, now_ns);
            next = .none;
            const event = received.event orelse return;
            switch (event) {
                .request => |request| if (answerer) |given| self.answer(request, given),
                .finished => |finished| self.free(finished.id),
                .ended => |ended| self.forget(ended.connection),
                .body, .trailers, .writable, .send, .close, .closed => {},
            }
        }
    }

    fn answer(self: *QuicServer, request: server.Request, answerer: tcp_server.Answerer) void {
        const query = tcp_server.read_request(self, &self.endpoint, request) orelse return;
        if (self.script.hold) {
            self.held += 1;
            return;
        }
        const response = for (&self.responses) |*response| {
            if (!response.live) break response;
        } else return;
        const len = answerer.answer(answerer.context, query, &response.content) orelse return;
        response.live = true;
        response.id = request.id;
        if (tcp_server.respond(&self.endpoint, request.id, self.script, response.content[0..len])) {
            self.answered += 1;
        } else {
            response.live = false;
        }
    }

    /// A response's content is the server's again.
    fn free(self: *QuicServer, id: server.RequestId) void {
        for (&self.responses) |*response| {
            if (response.live and response.id == id) response.live = false;
        }
    }

    /// Every response of a connection that is over.
    fn forget(self: *QuicServer, connection: server.ConnectionHandle) void {
        for (&self.responses) |*response| {
            if (response.live and response.id.connection == connection) response.live = false;
        }
    }
};
