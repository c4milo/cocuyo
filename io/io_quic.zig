//! `cocuyo_quic`: colibri's QUIC under the engine's request interface (docs/design.md §24, colibri
//! under the request interface). A consumer that speaks DoQ names `Connection(...)` in the engine's
//! `Options.quic`, and binds colibri's `quic` module into this one. `cocuyo_rotor` never imports
//! colibri, so a consumer that speaks no DoQ binds nothing more.
//!
//! The type is generic over its TLS: a session that is colibri's TLS provider and packet suite at
//! once, which `Options.Session` names. The option has no default, so a consumer that names no
//! session does not compile (docs/design.md §16 decision 38). chapulin's QUIC session is the
//! module `chapulin_quic` (`io_chapulin_quic.zig`), which the package registers beside this one
//! (decision 38, as amended). `plain`, `Plain` and `server` are for tests: they encrypt
//! nothing, authenticate nobody, and are never for a network. What colibri asks of the type that
//! holds it is in the design: state read rather than events, a request's bytes kept until the
//! server has them, cancelled streams drained, and the timer read after each call.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const streams_module = @import("io_quic_streams.zig");
const connection_module = @import("io_quic_connection.zig");
pub const constants = @import("io_quic_constants.zig");
pub const limits = @import("io_quic_limits.zig");
/// A TLS session for tests (`io_quic_plain.zig`). It encrypts nothing and authenticates nobody: a
/// packet goes as it is, and any peer that sends its made-up messages completes its handshake. It
/// is never for a network.
pub const plain = @import("io_quic_plain.zig");
/// A DoQ server over `plain`, for tests (`io_quic_server.zig`). It encrypts nothing either, takes
/// any client, and is never for a network.
pub const server = @import("io_quic_server.zig");

pub const Options = struct {
    /// The TLS: colibri's provider and suite at once, with `start`, `original_version`,
    /// `provider`, `suite`, `take_ticket`, `lifetime_ns` and `wipe`, and its `Context` and
    /// `Ticket`. `original_version` names the QUIC version the session started in, which the
    /// connection starts in too (docs/design.md §24, the session a connection names). It has no
    /// default: a consumer names the session that encrypts its queries and authenticates its
    /// server, as "DoQ stubs SHOULD use a Strict usage profile" (RFC 9250 §5.1), and one that names
    /// none does not compile (docs/design.md §16 decision 38). A test may name `Plain`.
    Session: type,
    /// The requests one connection holds at once: the engine's `lookups`, one each at most.
    streams: u16,
    /// colibri's receive pool, a multiple of its 1,024-octet blocks.
    receive_bytes: usize = constants.receive_bytes_default,
};

/// `plain.Session` behind the interface a connection's session has, for tests. A connection over it
/// encrypts nothing and authenticates nobody: whoever reads the path reads each query, and a peer
/// that answers with the session's made-up messages is taken for the server. A server that speaks
/// DoQ opens none of its packets, so no handshake with one ends (RFC 9001 §5.2). It is never for a
/// network, and never a default: a test that wants it writes `.Session = Plain`.
pub const Plain = struct {
    pub const Context = struct {};
    pub const Ticket = struct {};

    session: plain.Session = undefined,

    pub fn start(self: *Plain, context: anytype) error{Failed}!void {
        self.session = plain.Session.init(.client, context.alpn, false);
    }
    /// QUIC version 1 (RFC 9000 §15): the plain suite refuses a switch to any other.
    pub fn original_version(self: *const Plain) quic.crypto.suite.Version {
        _ = self;
        return .v1;
    }
    pub fn provider(self: *Plain) quic.tls_provider.QuicProvider {
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
        /// A request's slot holds a DoQ query and its prefix.
        pub const Streams = streams_module.Streams(options.streams, cocuyo.limits.query_bytes_max);

        pub const enabled = true;
        /// A datagram at a time, over UDP (docs/design.md §24, the request interface).
        pub const socket = .datagram;
        /// colibri never makes a datagram longer than this (RFC 9000 §14.1's smallest).
        pub const output_bytes_max = quic.constants.datagram_len_min;
        pub const request_bytes_max = cocuyo.limits.query_bytes_max;
        pub const Error = error{Failed};
        /// What every connection starts from (docs/design.md §24, the context a session starts
        /// from): the session's context, and the stream its connection IDs are drawn from, which
        /// the consumer keys with 32 octets of its CSPRNG, drawn apart from the session's seed
        /// (RFC 9000 §7.2: "an unpredictable value"). Neither field has a default, so a consumer
        /// writes both (§16 decision 39).
        pub const Context = struct {
            session: Session.Context,
            stream: std.Random.ChaCha,
        };
        pub const Ticket = Session.Ticket;
        pub const Answered = struct { stream: u64, len: usize };
        pub const Next = union(enum) { up: []const u8, refused, answered: Answered, reset: u64, closed, ticket: Ticket };

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
        inbound: [limits.datagram_receive_bytes]u8 = undefined,
        destination: [constants.connection_id_bytes]u8 = undefined,
        source: [constants.connection_id_bytes]u8 = undefined,
        streams: Streams = .{},
        /// The connection's next deadline, read after each call that can move it.
        due_ns: ?u64 = null,

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
        pub fn output(self: *Self, out: []u8, now_ns: u64) usize {
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
    const Client = Connection(.{ .Session = Plain, .streams = test_streams });
    const Server = server.Server(test_streams);
    const test_streams: usize = 4;
    const round_ns: u64 = 1_000_000;
    const rounds_max: usize = 64;

    client: Client = .{},
    server: Server = .{},
    context: Client.Context = test_context(),
    now_ns: u64 = 1,

    /// A connection's context for a test: the plain session's, which holds nothing, and a stream
    /// of connection IDs seeded with zeros, so each run draws what the last drew. Never for a
    /// network, whose seed comes from a CSPRNG.
    fn test_context() Client.Context {
        return .{ .session = .{}, .stream = std.Random.ChaCha.init(@splat(0)) };
    }

    fn start(pair: *Pair) !void {
        try pair.client.start(.{
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
            const out = pair.client.output(&datagram, pair.now_ns);
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
    var out: [limits.answer_bytes_max]u8 = undefined;
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
    var out: [limits.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(plain.other_protocol, pair.client.next(&out).?.up);
    var query = [_]u8{ 0, 4, 0, 0, 1, 2 };
    const stream = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    try testing.expectEqual(stream, pair.client.next(&out).?.reset);
    try testing.expectEqual(@as(?Pair.Client.Next, null), pair.client.next(&out));
}

test "a cancelled stream keeps its slot until its answer is read, which ends its receiving half" {
    // colibri frees a stream's place once both of its halves have ended (RFC 9000 §3), and the
    // receiving half ends when its data is read (§3.2), so the slot keeps reading until then.
    var pair: Pair = .{};
    var echo: Echo = .{};
    try pair.start();
    try pair.exchange(echo.answerer());
    var out: [limits.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("doq", pair.client.next(&out).?.up);
    var query = [_]u8{ 0, 4, 0, 0, 1, 2 };
    const stream = (try pair.client.request(&query, query.len)).?;
    // The query reaches the server, and its answer is held back.
    var datagram: [quic.constants.datagram_len_min]u8 = undefined;
    const sent = pair.client.output(&datagram, pair.now_ns);
    pair.server.receive(datagram[0..sent], pair.now_ns, echo.answerer());
    var answer: [quic.constants.datagram_len_min]u8 = undefined;
    const answer_len = pair.server.send(&answer, pair.now_ns);
    try testing.expect(answer_len > 0);
    // The stream is cancelled, and the connection read before the answer comes, as the engine
    // reads it when a datagram without the answer arrives, or its timer fires.
    pair.client.cancel(stream);
    try testing.expectEqual(@as(?Pair.Client.Next, null), pair.client.next(&out));
    try pair.client.receive(answer[0..answer_len], pair.now_ns);
    try testing.expectEqual(@as(?Pair.Client.Next, null), pair.client.next(&out));
    const ended = switch (pair.client.connection.streams.lookup(.{ .value = stream })) {
        .live => |live| live.receiving.state.is_terminal(),
        .closed => true,
        .unopened => false,
    };
    try testing.expect(ended);
}

/// `Plain` in the original version `version` names, as a session that resumes with a ticket of
/// another version starts in it. Test-only.
fn PlainIn(comptime version: quic.crypto.suite.Version) type {
    return struct {
        const Self = @This();
        pub const Context = Plain.Context;
        pub const Ticket = Plain.Ticket;
        pub const lifetime_ns = Plain.lifetime_ns;

        plain: Plain = .{},

        pub fn start(self: *Self, context: anytype) error{Failed}!void {
            return self.plain.start(context);
        }
        pub fn original_version(self: *const Self) quic.crypto.suite.Version {
            _ = self;
            return version;
        }
        pub fn provider(self: *Self) quic.tls_provider.QuicProvider {
            return self.plain.provider();
        }
        pub fn suite(self: *Self) quic.crypto.Suite {
            return self.plain.suite();
        }
        pub fn take_ticket(self: *Self) ?Ticket {
            return self.plain.take_ticket();
        }
        pub fn wipe(self: *Self) void {
            self.plain.wipe();
        }
    };
}

/// Where a long header carries its Version field: after its first octet (RFC 9000 §17.2).
const version_at: usize = 1;

/// The Version field of the first datagram a client over `Session` sends.
fn first_version(comptime Session: type) !u32 {
    const Client = Connection(.{ .Session = Session, .streams = 1 });
    const client = try testing.allocator.create(Client);
    defer testing.allocator.destroy(client);
    client.* = .{};
    var context: Client.Context = .{ .session = .{}, .stream = std.Random.ChaCha.init(@splat(0)) };
    try client.start(.{ .alpn = "doq", .ticket = @as(?Client.Ticket, null), .ticket_age_ns = 0, .context = &context, .now_ns = 1 });
    defer client.wipe();
    var datagram: [quic.constants.datagram_len_min]u8 = undefined;
    const sent = client.output(&datagram, 1);
    try testing.expect(sent > version_at + @sizeOf(u32));
    return std.mem.readInt(u32, datagram[version_at..][0..@sizeOf(u32)], .big);
}

test "a connection starts in the QUIC version its session names, as a session that resumes does" {
    // docs/design.md §16 decision 29 and §24: colibri v0.8.0 seals each packet in the connection's
    // version, and chapulin's suite asserts that its own is the same. A session that resumes with
    // a ticket of version 2 starts in version 2, so the connection must too (§17 question 57).
    try testing.expectEqual(@intFromEnum(quic.crypto.suite.Version.v1), try first_version(Plain));
    try testing.expectEqual(@intFromEnum(quic.crypto.suite.Version.v2), try first_version(PlainIn(.v2)));
}

test "a connection's context carries no default, so a consumer writes its session's and its stream" {
    // Until 2026-10-11 the session's context defaulted to its own defaults and the stream to one
    // seeded with zeros, and so did the engine's context when no consumer set one (docs/design.md
    // §16 decision 39).
    inline for (comptime std.meta.fields(Pair.Client.Context)) |field| {
        try testing.expectEqual(@as(?*const anyopaque, null), field.default_value_ptr);
    }
}

test "the options carry no session of their own, so a consumer that names none does not compile" {
    // A field with no default value must be written wherever the options are (docs/design.md §16
    // decision 38): until 2026-10-11 the default was `Plain`, and a consumer that left the field
    // unset ran the session that encrypts nothing and authenticates nobody. A `type` holds no null
    // either, so no value means no session.
    const session = comptime std.meta.fieldInfo(Options, .Session);
    try testing.expectEqual(@as(?*const anyopaque, null), session.default_value_ptr);
    try testing.expect(session.type == type);
}

test {
    _ = limits;
    _ = streams_module;
    _ = connection_module;
    _ = plain;
    _ = server;
}
