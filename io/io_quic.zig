//! `cocuyo_quic`: colibri's QUIC under the engine's request interface (docs/design.md §24, colibri
//! under the request interface). A consumer that speaks DoQ names `Connection(...)` in the engine's
//! `Options.quic`, and binds colibri's `quic` module into this one. `cocuyo_rotor` never imports
//! colibri, so a consumer that speaks no DoQ binds nothing more.
//!
//! The type is generic over its TLS: a session that is colibri's TLS provider and packet suite at
//! once. chapulin's QUIC object is the consumer's; `plain` encrypts nothing and is for tests. What
//! colibri asks of the type that holds it is in the design: state read rather than events, a
//! request's bytes kept until the server has them, cancelled streams drained, and the timer read
//! after each call.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const streams_module = @import("io_quic_streams.zig");
const connection_module = @import("io_quic_connection.zig");
/// colibri's `h3` under the interface, read only by a type that speaks HTTP/3.
const h3_module = @import("io_quic_h3.zig");
pub const constants = @import("io_quic_constants.zig");
/// A TLS session that encrypts nothing, and a DoQ server over it, for tests (`io_quic_plain.zig`,
/// `io_quic_server.zig`).
pub const plain = @import("io_quic_plain.zig");
pub const server = @import("io_quic_server.zig");
/// A DoH server over colibri's `h3`, for tests (`io_quic_server_h3.zig`).
pub const server_h3 = @import("io_quic_server_h3.zig");
/// A DoH server's URI template, split and expanded (`io_quic_template.zig`).
pub const template = @import("io_quic_template.zig");
/// What a DoH response's header section says of its content (`io_quic_response.zig`).
pub const response = @import("io_quic_response.zig");

pub const Options = struct {
    /// The TLS: colibri's provider and suite at once, with `start`, `provider`, `suite`,
    /// `take_ticket`, `lifetime_ns` and `wipe`, and its `Context` and `Ticket`.
    Session: type = Plain,
    /// The requests one connection holds at once: the engine's `lookups`, one each at most.
    streams: u16,
    /// colibri's receive pool, a multiple of its 1,024-octet blocks.
    receive_bytes: usize = constants.receive_bytes_default,
    /// Whether a connection speaks HTTP/3 as well, for DoH: colibri's `h3`, which the consumer
    /// then binds beside `quic` (docs/design.md §24, DoH over HTTP/3).
    http3: bool = false,
    /// A DoH connection's answer buffers: the responses it has in flight at once.
    answers: u16 = constants.answers_default,
};

/// `plain.Session` behind the interface a connection's session has.
pub const Plain = struct {
    pub const Context = struct {};
    pub const Ticket = struct {};

    session: plain.Session = undefined,

    pub fn start(self: *Plain, context: anytype) error{Failed}!void {
        self.session = plain.Session.init(.client, context.alpn, false);
    }
    pub fn provider(self: *Plain) quic.tls.QuicProvider {
        return self.session.provider();
    }
    pub fn suite(self: *Plain) quic.crypto.Suite {
        return self.session.suite();
    }
    pub fn take_ticket(self: *Plain) ?Ticket {
        _ = self;
        return null;
    }
    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        _ = ticket;
        return std.math.maxInt(u64);
    }
    pub fn wipe(self: *Plain) void {
        self.session.wipe();
    }
};

pub fn Connection(comptime options: Options) type {
    return struct {
        const Self = @This();
        const Session = options.Session;
        /// A request's slot holds a DoQ query, or a DoH GET's HEADERS frame.
        const slot_bytes = if (options.http3) @max(cocuyo.constants.query_bytes_max, constants.doh_request_bytes_max) else cocuyo.constants.query_bytes_max;
        pub const Streams = streams_module.Streams(options.streams, slot_bytes);
        const H3 = if (options.http3) h3_module.State(options.answers) else void;

        pub const enabled = true;
        /// Whether the connection speaks HTTP/3, which DoH goes over (docs/design.md §24, step 5).
        pub const http3 = options.http3;
        /// colibri never makes a datagram longer than this (RFC 9000 §14.1's smallest).
        pub const datagram_bytes_max = quic.constants.datagram_len_min;
        pub const request_bytes_max = cocuyo.constants.query_bytes_max;
        pub const Error = error{Failed};
        /// What every connection starts from: the session's, and the stream its connection IDs are
        /// drawn from, which the consumer seeds from a CSPRNG (RFC 9000 §7.2: "an unpredictable
        /// value"). The default seed is for tests.
        pub const Context = struct {
            session: Session.Context = .{},
            stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(0)),
        };
        pub const Ticket = Session.Ticket;
        /// What a DoH response says of its content (`response.zig`).
        pub const Http = response.Http;
        pub const Answered = struct { stream: u64, len: usize, http: ?Http = null };
        pub const Next = union(enum) { up: []const u8, refused, answered: Answered, reset: u64, closed, goaway, ticket: Ticket };

        pub const Stage = connection_module.Stage;
        /// colibri's receive pool, which the connection's transport parameters open to the server.
        pub const receive_bytes = options.receive_bytes;

        stage: Stage = .idle,
        connection: quic.Connection = undefined,
        session: Session = .{},
        pool: quic.stream.stream_incoming.Pool(options.receive_bytes) = undefined,
        send_scratch: quic.connection_send.DefaultScratch = undefined,
        scratch: quic.connection_datagram.Scratch = undefined,
        /// The datagram being read: colibri opens packets in place.
        inbound: [constants.datagram_receive_bytes]u8 = undefined,
        destination: [constants.connection_id_bytes]u8 = undefined,
        source: [constants.connection_id_bytes]u8 = undefined,
        streams: Streams = .{},
        /// The connection's next deadline, read after each call that can move it.
        due_ns: ?u64 = null,
        /// Whether this opening is to a DoH server, and speaks HTTP/3.
        https: bool = false,
        h3: H3 = if (options.http3) .{} else {},

        pub fn start(self: *Self, context: anytype) Error!void {
            return connection_module.start(self, context);
        }
        pub fn lifetime_ns(ticket: *const Ticket) u64 {
            return Session.lifetime_ns(ticket);
        }
        pub fn receive(self: *Self, bytes: []const u8, now_ns: u64) Error!void {
            connection_module.receive(self, bytes, now_ns);
        }
        pub fn next(self: *Self, out: []u8) ?Next {
            return connection_module.next(self, out);
        }
        pub fn request(self: *Self, bytes: []u8, len: usize) Error!?u64 {
            return connection_module.request(self, bytes[0..len]);
        }
        pub fn cancel(self: *Self, stream: u64) void {
            connection_module.cancel(self, stream);
        }
        pub fn datagram(self: *Self, out: []u8, now_ns: u64) usize {
            return connection_module.datagram(self, out, now_ns);
        }
        pub fn deadline(self: *const Self) ?u64 {
            return self.due_ns;
        }
        pub fn expire(self: *Self, now_ns: u64) void {
            connection_module.expire(self, now_ns);
        }
        pub fn idle_left_ns(self: *const Self, now_ns: u64) u64 {
            return connection_module.idle_left_ns(self, now_ns);
        }
        pub fn close(self: *Self) void {
            connection_module.close(self);
        }
        pub fn wipe(self: *Self) void {
            connection_module.wipe(self);
        }
    };
}

// Tests.

const testing = std.testing;

/// A client and a server, carried to each other in memory a datagram at a time each way, on a
/// clock that moves a millisecond a round, until neither has anything to send.
const Pair = struct {
    const Client = Connection(.{ .streams = test_streams });
    const Server = server.Server(test_streams);
    const test_streams = 4;
    const round_ns = 1_000_000;
    const rounds_max = 64;

    client: Client = .{},
    server: Server = .{},
    context: Client.Context = .{},
    now_ns: u64 = 1,

    fn start(pair: *Pair) !void {
        try pair.client.start(.{
            .https = null,
            .alpn = "doq",
            .ticket = @as(?Client.Ticket, null),
            .ticket_age_ns = 0,
            .context = &pair.context,
            .now_ns = pair.now_ns,
        });
    }

    fn exchange(pair: *Pair, answerer: server.Answerer) !void {
        var datagram: [quic.constants.datagram_len_min]u8 = undefined;
        var rounds: usize = 0;
        while (rounds < rounds_max) : (rounds += 1) {
            const out = pair.client.datagram(&datagram, pair.now_ns);
            if (out > 0) pair.server.receive(datagram[0..out], pair.now_ns, answerer);
            const back = pair.server.send(&datagram, pair.now_ns);
            if (back > 0) try pair.client.receive(datagram[0..back], pair.now_ns);
            if (out == 0 and back == 0) return;
            pair.now_ns += round_ns;
        }
        return error.NoQuiet;
    }
};

/// Answers a query with the query itself, or declines every one.
const Echo = struct {
    decline: bool = false,

    fn answerer(echo: *Echo) server.Answerer {
        return .{ .context = echo, .answer = answer };
    }

    fn answer(context: *anyopaque, query: []const u8, out: []u8) ?usize {
        const echo: *Echo = @ptrCast(@alignCast(context));
        if (echo.decline) return null;
        @memcpy(out[0..query.len], query);
        return query.len;
    }
};

test "a client over colibri handshakes on doq, and a query on a stream is answered on it" {
    var pair: Pair = .{};
    var echo: Echo = .{};
    try pair.start();
    try pair.exchange(echo.answerer());
    var out: [constants.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("doq", pair.client.next(&out).?.up);
    var query = [_]u8{ 0, 4, 0, 0, 1, 2 };
    const stream = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    const answered = pair.client.next(&out).?.answered;
    try testing.expectEqual(stream, answered.stream);
    try testing.expectEqualSlices(u8, &query, out[0..answered.len]);
    try testing.expectEqual(@as(?Pair.Client.Next, null), pair.client.next(&out));
    try testing.expectEqual(@as(usize, 1), pair.server.answered);
}

test "a server that selects another protocol is heard, and a stream it resets is told once" {
    var pair: Pair = .{};
    pair.server.script.other_protocol = true;
    var echo: Echo = .{ .decline = true };
    try pair.start();
    try pair.exchange(echo.answerer());
    var out: [constants.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(plain.other_protocol, pair.client.next(&out).?.up);
    var query = [_]u8{ 0, 4, 0, 0, 1, 2 };
    const stream = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    try testing.expectEqual(stream, pair.client.next(&out).?.reset);
    try testing.expectEqual(@as(?Pair.Client.Next, null), pair.client.next(&out));
}

test {
    _ = streams_module;
    _ = connection_module;
    _ = plain;
    _ = server;
    _ = template;
    _ = response;
    _ = h3_module;
    _ = server_h3;
}
