//! chapulin's QUIC session through colibri's `tls.quic.Client`: `cocuyo_quic`'s session for real
//! DoQ and DoH on HTTP/3 (docs/design.md §24, chapulin under colibri; §16 decision 32). colibri
//! puts chapulin's QUIC object behind its TLS provider and its packet suite, and chapulin owns every
//! key. The session turns a server's `Tls` and the context into colibri's values, and hands the
//! connection colibri's provider and suite.
//!
//! chapulin draws every random octet from the engine's seeded stream, which `start` hands colibri
//! (colibri#71), and the image supplies chapulin's one remaining hook, `ch_assert_fail`, through
//! the `chapulin_hooks` module it binds.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("cocuyo_quic").constants;
const hooks = @import("chapulin_hooks");

// colibri's objects call `ch_assert_fail` whatever of the session a program uses, so the image
// links it whenever it links the session.
comptime {
    _ = hooks;
}

const tls_provider = quic.tls_provider;

pub const Session = struct {
    /// A root the chain may end at: its subject Name and its SubjectPublicKeyInfo, each a whole
    /// DER TLV (colibri's `values.zig`).
    pub const Anchor = tls.Anchor;
    /// The most roots a context holds: what colibri's configuration takes, chapulin's
    /// `CH_WEBPKI_ANCHOR_MAX`.
    pub const anchors_max = tls.quic.ClientConfig.anchors_max;

    /// What every session starts from: the anchors, the wall clock, and the stream chapulin draws
    /// from, seeded from a CSPRNG. The anchors are the caller's and outlive the engine.
    pub const Context = struct {
        anchors: []const Anchor = &.{},
        stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(0)),
        unix_seconds: u64 = 0,
        at_ns: u64 = 0,

        /// `seed` must come from a CSPRNG; `unix_seconds` is the wall clock at the caller's
        /// `now_ns`.
        pub fn init(anchors: []const Anchor, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
            assert(anchors.len <= anchors_max);
            return .{ .anchors = anchors, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
        }

        /// The wall clock at `now_ns`, carried forward from the instant the context was made.
        pub fn seconds_at(context: *const Context, now_ns: u64) u64 {
            return context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
        }
    };

    /// A ticket as colibri hands it over: the identity, the resumption secret, the lifetime, the
    /// age mask and the binding to the trust it was issued under (RFC 9846 §4.6.1).
    pub const Ticket = tls.Ticket;

    client: tls.quic.Client = undefined,
    /// What the session starts from, which chapulin reads through pointers into it.
    config: tls.quic.ClientConfig = undefined,
    hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined,
    alpn: [1][]const u8 = undefined,
    /// The ticket this session resumes with: a copy, which `wipe` zeroes.
    resuming: Ticket = undefined,
    /// Whether the session offered a ticket, which the server may have declined (RFC 9846 §4.2.11).
    offered: bool = false,
    /// `client` was started, so it has secrets to wipe and state to read.
    started: bool = false,

    pub fn lifetime_ns(ticket: *const Ticket) u64 {
        return @as(u64, ticket.lifetime_s) * constants.ns_per_second;
    }

    /// Prepares a client session for `start.tls`'s server, offering `start.alpn`, resuming with
    /// `start.ticket` when there is one. chapulin starts at `set_transport_params`, once colibri
    /// has the parameters it carries (RFC 9001 §4.1.3), and refuses there a configuration it
    /// cannot check a server by (docs/design.md §24, chapulin under colibri).
    pub fn start(self: *Session, start_with: anytype) error{Failed}!void {
        const server: *const cocuyo.Tls = start_with.tls;
        const context = &start_with.context.session;
        // A strict client knows a server by a name, by pins, or by both (RFC 8310 §5), which
        // `Config.assert_valid` holds.
        assert(server.valid());
        self.* = .{};
        self.alpn = .{start_with.alpn};
        self.config.init(.{ .trust = trust(server, context, &self.hostname), .alpn = &self.alpn }) catch return error.Failed;
        var resumption: ?tls.Resumption = null;
        if (start_with.ticket) |ticket| {
            self.resuming = ticket;
            self.offered = true;
            resumption = .{ .ticket = &self.resuming, .age_ms = start_with.ticket_age_ns / constants.ns_per_millisecond };
        }
        // chapulin draws from the context's stream, which outlives every session of the engine.
        self.started = true;
        self.client.start(&self.config, context.stream.random(), context.seconds_at(start_with.now_ns), resumption) catch return self.fail();
    }

    /// How chapulin checks the server, as the DoT session tells it (`io_chapulin.zig`): a name
    /// against the context's anchors, and pins as they are. A server known by pins alone, RFC 8310
    /// §6.3's "SPKI + IP", gets no anchors and no clock: chapulin then takes the leaf key a pin
    /// names, and reads nothing else of the chain (its decision 65). A named server with no anchors
    /// is judged by its pins alone, its name sent and judged against nothing.
    pub fn trust(server: *const cocuyo.Tls, context: *const Context, hostname: *[cocuyo.constants.name_text_bytes_max]u8) tls.Trust {
        const pins: []const tls.Pin = server.pins;
        const name = server.name orelse return .{ .pins = .{ .pins = pins } };
        var length = name.write_text(hostname);
        // chapulin takes a hostname, which has no root label's dot.
        if (length > 1 and hostname[length - 1] == '.') length -= 1;
        const server_name = hostname[0..length];
        if (context.anchors.len == 0) return .{ .pins = .{ .pins = pins, .server_name = server_name } };
        return .{ .web_pki = .{ .anchors = context.anchors, .server_name = server_name, .pins = pins } };
    }

    pub fn provider(self: *Session) tls_provider.QuicProvider {
        assert(self.started);
        return self.client.provider();
    }

    pub fn suite(self: *Session) quic.crypto.Suite {
        assert(self.started);
        return self.client.suite();
    }

    pub fn take_ticket(self: *Session) ?Ticket {
        if (!self.started) return null;
        return self.client.take_ticket();
    }

    /// Whether the server took the ticket the session offered (RFC 9846 §4.2.11).
    pub fn resumed(self: *const Session) bool {
        return self.started and self.client.resumed();
    }

    /// Every secret gone: colibri wipes chapulin's session and its copy of the ticket, and the
    /// session's own copy is zeroed.
    pub fn wipe(self: *Session) void {
        if (self.started) self.client.close();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.resuming));
        self.started = false;
    }

    fn fail(self: *Session) error{Failed} {
        self.wipe();
        return error.Failed;
    }
};

// Tests.

test {
    _ = @import("io_chapulin_quic_test.zig");
}
