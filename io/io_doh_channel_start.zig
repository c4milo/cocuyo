//! A channel's start and its links' (docs/design.md §24, rules 18, 19 and 23): colibri's channel
//! made from the server's `Tls`, its address and the template, each link's connection started with
//! the ticket of its transport at its age, and what a link's end and a wipe take away. Split from
//! `io_doh_channel.zig`.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("client");
const tls = @import("tls");
const constants = @import("io_doh_channel_constants.zig");
const exchange_module = @import("io_doh_channel_exchange.zig");
const read_module = @import("io_doh_channel_read.zig");

/// What every channel starts from: the roots a named server's chain may end at, the stream chapulin
/// and the QUIC connection IDs draw from, and the wall clock at an instant of the caller's. The
/// anchors are the caller's and outlive the engine.
pub const Context = struct {
    anchors: []const tls.Anchor = &.{},
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(0)),
    unix_seconds: u64 = 0,
    at_ns: u64 = 0,

    /// `seed` must come from a CSPRNG; `unix_seconds` is the wall clock at the caller's `now_ns`.
    pub fn init(anchors: []const tls.Anchor, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
        assert(anchors.len <= tls.record.ClientConfig.anchors_max);
        return .{ .anchors = anchors, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
    }

    /// The wall clock at `now_ns`, carried forward from the instant the context was made.
    pub fn seconds_at(context: *const Context, now_ns: u64) u64 {
        return context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
    }
};

/// What each transport's connection offers (RFC 7301 §3.1): HTTP/3 over QUIC (RFC 9114 §3.1), and
/// over TCP HTTP/2, then HTTP/1.1 (rule 18).
const quic_alpn = [_][]const u8{"h3"};
const tcp_alpn = [_][]const u8{ "h2", "http/1.1" };

/// Makes a server's channel, with nothing opened (rule 18): its TLS names the server as its `Tls`
/// does, and its connections go to the server's address on the template's port. A template whose
/// GET would not fit is refused.
pub fn start(self: anytype, context: anytype) error{Failed}!void {
    const https = context.https;
    if (!exchange_module.fits(https.path)) return error.Failed;
    assert(!self.started);
    self.* = .{ .context = context.context, .path = https.path };
    const trust = trust_of(context.tls, self.context.anchors, &self.hostname);
    self.record_tls.init(.{ .trust = trust, .alpn = &tcp_alpn }) catch return error.Failed;
    self.quic_tls.init(.{ .trust = trust, .alpn = &quic_alpn }) catch return error.Failed;
    self.tcp_config = .{ .tls = &self.record_tls, .authority = https.authority };
    self.quic_config = .{ .tls = &self.quic_tls, .authority = https.authority };
    self.channel_config = .{ .tcp = &self.tcp_config, .quic = &self.quic_config, .fallback_delay_ns = constants.fallback_delay_ns };
    self.addresses = .{client.channel.Address.of(context.endpoint.address.slice(), 0)};
    self.channel.init(&self.channel_config, .{
        .addresses = &self.addresses,
        .port = context.endpoint.port,
        .alternative = context.alternative,
    }, self.pool.storage());
    self.started = true;
}

/// Starts a link's connection once its socket carries octets: QUIC's with connection IDs and grease
/// drawn from the context's stream (RFC 9000 §7.2), and each with the context's wall clock and the
/// ticket kept for its transport, offered at its age (RFC 9846 §4.3.11.1). One chapulin refuses
/// fails the link.
pub fn start_link(self: anytype, link: read_module.Link, ticket: anytype, ticket_age_ns: u64, now_ns: u64) error{Failed}!void {
    const at = @intFromEnum(link);
    var resumption: ?tls.Resumption = null;
    self.offered[at] = ticket != null;
    if (ticket) |offered| {
        self.resuming[at] = offered.*;
        resumption = .{ .ticket = &self.resuming[at], .age_ms = ticket_age_ns / constants.ns_per_millisecond };
    }
    const random = self.context.stream.random();
    const seconds = self.context.seconds_at(now_ns);
    switch (link) {
        .quic => {
            var start_values: client.QuicStart = undefined;
            self.context.stream.fill(&start_values.source_id);
            self.context.stream.fill(&start_values.original_destination_id);
            start_values.grease = self.context.stream.random().int(u64);
            self.channel.start_quic(start_values, random, seconds, now_ns, resumption) catch return error.Failed;
        },
        .tcp => self.channel.start_tcp(random, seconds, resumption) catch return error.Failed,
    }
}

/// A link's socket ended: its connection is gone, and what the link read of it with it.
pub fn link_ended(self: anytype, link: read_module.Link) void {
    self.channel.transport_closed(read_module.transport_of(link));
    read_module.forget(self, link);
}

/// Every secret gone: each connection ends, which wipes its session, and the copies of the tickets
/// the links resumed with are zeroed.
pub fn wipe(self: anytype) void {
    if (!self.started) return;
    self.channel.transport_closed(.quic);
    self.channel.transport_closed(.tcp);
    for (&self.resuming) |*ticket| ticket.wipe();
    self.started = false;
}

/// How chapulin checks the server, as the DoT and DoQ sessions tell it: a name against the
/// context's anchors, and pins as they are. A server known by pins alone gets no anchors and no
/// clock, and a named server with no anchors is judged by its pins alone, its name sent.
fn trust_of(server: *const cocuyo.Tls, anchors: []const tls.Anchor, hostname: *[cocuyo.constants.name_text_bytes_max]u8) tls.Trust {
    // A strict client knows a server by a name, by pins, or by both (RFC 8310 §5).
    assert(server.valid());
    const pins: []const tls.Pin = server.pins;
    const name = server.name orelse return .{ .pins = .{ .pins = pins } };
    var length = name.write_text(hostname);
    // chapulin takes a hostname, which has no root label's dot.
    if (length > 1 and hostname[length - 1] == '.') length -= 1;
    const server_name = hostname[0..length];
    if (anchors.len == 0) return .{ .pins = .{ .pins = pins, .server_name = server_name } };
    return .{ .web_pki = .{ .anchors = anchors, .server_name = server_name, .pins = pins } };
}
