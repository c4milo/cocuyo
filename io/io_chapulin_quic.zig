//! chapulin's QUIC session through colibri's `tls.quic.Client`: `cocuyo_quic`'s session for real
//! DoQ and DoH on HTTP/3 (docs/design.md §24, chapulin under colibri; §16 decision 32). colibri
//! puts chapulin's QUIC object behind its TLS provider and its packet suite, and chapulin owns every
//! key. The session turns a server's `Tls` and the context into colibri's values, and hands the
//! connection colibri's suite and a provider of its own.
//!
//! chapulin draws randomness through the image's `ch_rand_bytes`, which `chapulin_hooks` defines,
//! when its session starts and when handshake octets arrive. The session's provider enters the
//! engine's stream around those two calls and passes every call on to colibri's. It goes once
//! colibri's `start` takes the stream (colibri#71).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("cocuyo_quic").constants;
const hooks = @import("chapulin_hooks");

// colibri's objects call the hooks whatever of the session a program uses, so the image links
// them whenever it links the session.
comptime {
    _ = hooks;
}

const tls_provider = quic.tls_provider;
const quic_provider = tls_provider.quic_provider;
const Level = quic.core.Level;

pub const Session = struct {
    /// A root the chain may end at: its subject Name and its SubjectPublicKeyInfo, each a whole
    /// DER TLV (colibri's `values.zig`).
    pub const Anchor = tls.Anchor;
    /// The most roots a context holds: what colibri's configuration copies them into, chapulin's
    /// `CH_WEBPKI_ANCHOR_MAX`.
    pub const anchors_max = @typeInfo(@FieldType(tls.quic.ClientConfig, "anchors")).array.len;

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
    stream: ?*std.Random.ChaCha = null,
    /// colibri's provider for `client`, which the session's own passes every call on to.
    forwarded: tls_provider.QuicProvider = undefined,
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
        self.stream = &context.stream;
        self.started = true;
        self.client.start(&self.config, context.seconds_at(start_with.now_ns), resumption) catch return self.fail();
        self.forwarded = self.client.provider();
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
        return .{ .context = self, .vtable = &provider_vtable };
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

    fn of(context: *anyopaque) *Session {
        return @ptrCast(@alignCast(context));
    }

    fn of_const(context: *const anyopaque) *const Session {
        return @ptrCast(@alignCast(context));
    }
};

// The TLS provider: colibri's, with the engine's stream entered around the two calls that draw.

const provider_vtable: tls_provider.QuicVTable = .{
    .set_transport_params = set_transport_params,
    .peer_transport_params = peer_transport_params,
    .provide_handshake = provide_handshake,
    .write_handshake = write_handshake,
    .negotiated_alpn = negotiated_alpn,
    .handshake_complete = handshake_complete,
    .take_alert = take_alert,
    .export_keying_material = export_keying_material,
};

/// The parameters colibri encoded, which the hello carries (RFC 9001 §8.2): chapulin's session
/// starts here, drawing its key shares from the engine's stream.
fn set_transport_params(context: *anyopaque, body: []const u8) quic_provider.TransportParamsError!void {
    const self = Session.of(context);
    hooks.enter(self.stream.?);
    defer hooks.leave();
    return self.forwarded.set_transport_params(body);
}

fn peer_transport_params(context: *const anyopaque) ?[]const u8 {
    return Session.of_const(context).forwarded.peer_transport_params();
}

/// Handshake octets at `level`, in order and once (RFC 9001 §4.1.3). chapulin may draw here: a
/// HelloRetryRequest for P-256 makes a new key share.
fn provide_handshake(context: *anyopaque, level: Level, data: []const u8) quic_provider.ProvideError!void {
    const self = Session.of(context);
    hooks.enter(self.stream.?);
    defer hooks.leave();
    return self.forwarded.provide_handshake(level, data);
}

fn write_handshake(context: *anyopaque, level: Level, output: []u8) quic_provider.WriteError!usize {
    return Session.of(context).forwarded.write_handshake(level, output);
}

fn negotiated_alpn(context: *const anyopaque) ?[]const u8 {
    return Session.of_const(context).forwarded.negotiated_alpn();
}

fn handshake_complete(context: *const anyopaque) bool {
    return Session.of_const(context).forwarded.handshake_complete();
}

/// The alert of a handshake that failed, once: a chain that ends at no anchor is `unknown_ca`,
/// a name the certificate does not carry `bad_certificate` (chapulin's webpki.c).
fn take_alert(context: *anyopaque) ?tls_provider.Alert {
    return Session.of(context).forwarded.take_alert();
}

fn export_keying_material(context: *anyopaque, label: []const u8, context_value: ?[]const u8, output: []u8) quic_provider.ExportError!void {
    return Session.of(context).forwarded.export_keying_material(label, context_value, output);
}

// Tests.

test {
    _ = @import("io_chapulin_quic_test.zig");
}
