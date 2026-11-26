//! A channel's start and its links' (docs/design.md §24, rules 18, 19 and 23): colibri's channel
//! made from the server's `Tls`, its address and the template, each link's connection started with
//! the ticket of its transport at its age, and what a link's end and a wipe take away. Split from
//! `io_doh_channel.zig`.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const client = @import("colibri").client;
const tls = @import("colibri").tls;
const constants = @import("io_doh_channel_constants.zig");
const limits = @import("io_doh_channel_limits.zig");
const exchange_module = @import("io_doh_channel_exchange.zig");
const read_module = @import("io_doh_channel_read.zig");

/// The consumer's `stdx.crypto.Context`: its CPU's features, which decide the suites of each hello,
/// and the random source chapulin and the QUIC link draw from (colibri decision 175, docs/design.md
/// §16 decision 48 as amended). The engine names it through colibri, and reaches no stdx of its own.
pub const Crypto = @FieldType(tls.Client, "crypto");

/// What every channel starts from (docs/design.md §24, the context a session starts from). It holds
/// the roots a named server's chain may end at, the consumer's `Crypto`, and the wall clock at an
/// instant of the caller's. No field has a default, so a context is built by `init`, with each of
/// them named (§16 decision 39). The anchors are the caller's and outlive the engine.
pub const Context = struct {
    anchors: []const tls.Anchor,
    crypto: Crypto,
    unix_seconds: u64,
    at_ns: u64,

    /// `crypto` holds the consumer's CPU features and its random source, which the engine cannot
    /// check (§16 decision 48, as amended). Where stdx states that the AES instructions run in
    /// constant time, each hello offers AES-GCM first; elsewhere, ChaCha20-Poly1305 alone. chapulin
    /// draws each handshake's random and its key shares from the random source, and colibri the
    /// QUIC link's connection IDs: it must be a CSPRNG's and outlive the engine. `timestamp` is the
    /// wall clock at an instant of the caller's. A DoH server is known by its template's host, so
    /// `anchors` holds the roots its chain may end at.
    pub fn init(anchors: []const tls.Anchor, crypto: Crypto, timestamp: cocuyo.Timestamp) Context {
        assert(anchors.len <= tls.record.ClientConfig.anchors_max);
        return .{ .anchors = anchors, .crypto = crypto, .unix_seconds = timestamp.unix_seconds, .at_ns = timestamp.monotonic_ns };
    }

    /// The wall clock at `now_ns`, carried forward from the instant the context was made.
    pub fn seconds_at(context: *const Context, now_ns: u64) u64 {
        return context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
    }
};

/// What the channel speaks (rule 18): HTTP/3 over QUIC, and HTTP/2 or HTTP/1.1 over TCP. colibri
/// builds each ALPN list from it: `h3` over QUIC (RFC 9114 §3.1), and `h2`, then `http/1.1`, over
/// TCP (RFC 7301 §3.1; its decision 120). QUIC opens first, and TCP once QUIC fails or the
/// fallback delay passes during its handshake (colibri's decision 117 as amended).
const protocols: client.Protocols = .{ .h11 = true, .h2 = true, .h3 = true, .prefer = .quic };

/// The least memory colibri v0.8.0 names for a TCP transport (its decision 124, ruling 5;
/// docs/design.md §24, the interface). `stream_input_len_min` holds a whole head of HTTP/1.1,
/// which cleartext needs. Over TLS colibri keeps the partial head in its own room beside one
/// whole record. So the type's buffer holds a whole record and a chunk, and not
/// `stream_input_len_min`. Each start asserts it, so a test that starts a channel reads it.
fn assert_sizes() void {
    const record_body_bytes_max = limits.record_bytes_max - constants.record_header_bytes;
    const room_least = client.constants.limits.stream_input_len_min - 1 + record_body_bytes_max;
    assert(client.constants.limits.plaintext_in_len >= room_least);
    assert(limits.stream_bytes_max >= limits.record_bytes_max + limits.engine_chunk_bytes_max);
    // `send_stream` always writes a record it owes into an output this long.
    assert(limits.output_bytes_max >= client.constants.limits.stream_output_len_min);
}

/// Makes a server's channel, with nothing opened (rule 18). Its TLS names the server as its `Tls`
/// does, and states of the CPU what the context states. Its connections go to the server's address
/// on the template's port. colibri builds the TLS configuration of each transport from the one TLS
/// value. A template whose GET would not fit is refused, and so is a TLS value colibri refuses.
pub fn start(self: anytype, context: anytype) error{Failed}!void {
    assert_sizes();
    const https = context.https;
    if (!exchange_module.fits(https.path)) return error.Failed;
    assert(!self.started);
    self.* = .{ .context = context.context, .path = https.path };
    const trust = trust_of(context.tls, self.context.anchors, &self.hostname);
    // The consumer's CPU features decide the suites of each link's hello (§16 decision 48).
    // colibri builds the TLS of both transports from this one value (its decision 120). A server
    // that requires the hybrid gets hellos that offer it alone (§21, TLS rule 10).
    self.channel_config = .{
        .tls = .{ .trust = trust, .crypto = self.context.crypto, .require_pq = context.tls.require_post_quantum },
        // The pool decodes with the instructions the consumer's context names.
        .cpu_features = self.context.crypto.features,
        .protocols = protocols,
        .tcp_connections = limits.tcp_connections_max,
        .requests = @intCast(self.exchanges.len),
        .authority = https.authority,
        .fallback_delay_ns = constants.fallback_delay_ns,
    };
    self.addresses = .{client.Address.init(context.endpoint.address.slice(), 0)};
    const destination: client.Destination = .{
        .addresses = &self.addresses,
        .port = context.endpoint.port,
        .alternative = context.alternative,
    };
    self.channel.init(&self.memory, &self.channel_config, &destination, self.pool.storage()) catch return error.Failed;
    self.started = true;
}

/// Starts a link's connection once its socket carries octets, with the context's wall clock and the
/// ticket kept for its transport, offered at its age (RFC 9846 §4.3.11.1). colibri draws a QUIC
/// connection's grease value and its connection IDs from the random source of the context's
/// `Crypto` (RFC 9000 §7.2; its decisions 120 and 175), then every draw of its handshake. One
/// chapulin refuses fails the link.
pub fn start_link(self: anytype, link: read_module.Link, ticket: anytype, ticket_age_ns: u64, now_ns: u64) error{Failed}!void {
    const at = @intFromEnum(link);
    var resumption: ?tls.Resumption = null;
    self.offered[at] = ticket != null;
    if (ticket) |offered| {
        self.resuming[at] = offered.*;
        resumption = .{ .ticket = &self.resuming[at], .age_ms = ticket_age_ns / constants.ns_per_millisecond };
    }
    const seconds = self.context.seconds_at(now_ns);
    switch (link) {
        .quic => self.channel.start_quic(seconds, now_ns, resumption) catch return error.Failed,
        .tcp => self.channel.start_tcp(read_module.handle_of(self, .tcp), seconds, resumption) catch return error.Failed,
    }
    // A TCP link starts once its connect has finished, so a server took part (docs/design.md §16
    // decision 51). A QUIC link's server takes part when its first datagram comes.
    if (link == .tcp) read_module.heard_from(self, .tcp);
}

/// A link's socket ended: its connection is gone, and what the link read of it with it.
pub fn link_ended(self: anytype, link: read_module.Link) void {
    self.channel.transport_closed(read_module.handle_of(self, link));
    read_module.forget(self, link);
}

/// Every secret gone: each connection ends, which wipes its session, and the copies of the tickets
/// the links resumed with are zeroed.
pub fn wipe(self: anytype) void {
    if (!self.started) return;
    self.channel.transport_closed(read_module.handle_of(self, .quic));
    self.channel.transport_closed(read_module.handle_of(self, .tcp));
    for (&self.resuming) |*ticket| ticket.wipe();
    self.started = false;
}

/// How chapulin checks the server, as the DoT and DoQ sessions tell it: a name against the
/// context's anchors, and pins as they are. A server known by pins alone gets no anchors and no
/// clock, and a named server with no anchors is judged by its pins alone, its name sent.
fn trust_of(server: *const cocuyo.Tls, anchors: []const tls.Anchor, hostname: *[cocuyo.limits.name_text_bytes_max]u8) tls.Trust {
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

// Tests.

const testing = std.testing;
const rig = @import("io_doh_channel_test.zig");
const identity = @import("io_doh_channel_identity.zig");

test "the context carries no default, so each of its fields is named where one is built" {
    // Until 2026-10-11 the fields defaulted to no anchors, a stream seeded with zeros and a wall
    // clock of zero, and so did the engine's context when no consumer set one (docs/design.md §16
    // decision 39).
    inline for (comptime std.meta.fields(Context)) |field| {
        try testing.expectEqual(@as(?*const anyopaque, null), field.default_value_ptr);
    }
}

/// Where a ClientHello's cipher_suites start in its handshake message (RFC 9846 §4, §4.2.2): after
/// the message's type and length, the legacy_version, the random, and the legacy_session_id's
/// length octet and its body. Over TCP a record's header comes first (RFC 9846 §5.1).
const message_header_bytes: usize = 4;
const legacy_version_bytes: usize = 2;
const random_bytes: usize = 32;
/// TLS_AES_128_GCM_SHA256 {0x13,0x01}, TLS_AES_256_GCM_SHA384 {0x13,0x02} and
/// TLS_CHACHA20_POLY1305_SHA256 {0x13,0x03} (RFC 9846 Appendix B.4).
const aes_128_gcm_sha256: u16 = 0x1301;
const aes_256_gcm_sha384: u16 = 0x1302;
const chacha20_poly1305_sha256: u16 = 0x1303;
/// The suites of a hello whose context holds the AES instructions, whose timing stdx states.
/// colibri hands chapulin no order of its own, so the order is that of chapulin's host object (its
/// `suite.h`): AES-256-GCM, AES-128-GCM, ChaCha20.
const suites_with_aes = [_]u16{ aes_256_gcm_sha384, aes_128_gcm_sha256, chacha20_poly1305_sha256 };
/// The suites of a hello whose context holds no AES instructions, or no timing stdx states.
const suites_without_aes = [_]u16{chacha20_poly1305_sha256};
/// max_idle_timeout, of 30,000 milliseconds (RFC 9000 §18.2), which chapulin carries and does not
/// read: its ID, its length, and its value as a two-octet varint.
const transport_parameters = "\x01\x02\x75\x30";

/// Requires that `codes`, a ClientHello's list of two-octet code points, its cipher_suites or its
/// groups, offer `expected` in its order, and nothing else.
fn expect_codes(expected: []const u16, codes: []const u8) !void {
    try testing.expectEqual(expected.len * @sizeOf(u16), codes.len);
    for (expected, 0..) |code, index| {
        const at = index * @sizeOf(u16);
        try testing.expectEqual(code, std.mem.readInt(u16, codes[at..][0..@sizeOf(u16)], .big));
    }
}

/// The cipher_suites a ClientHello handshake message offers.
fn suites_of(message: []const u8) []const u8 {
    const session_id_at = message_header_bytes + legacy_version_bytes + random_bytes;
    const suites_at = session_id_at + 1 + message[session_id_at] + @sizeOf(u16);
    const suites_len = std.mem.readInt(u16, message[suites_at - @sizeOf(u16) ..][0..@sizeOf(u16)], .big);
    return message[suites_at..][0..suites_len];
}

/// A ClientHello's extensions follow its cipher_suites, a legacy_compression_methods of one length
/// octet and its body, and the extensions' two-octet length (RFC 9846 §4.1.2). Each extension is a
/// two-octet type and a two-octet length, then its body (§4.2).
const extension_header_bytes: usize = 4;
/// supported_groups (RFC 9846 §4.2), whose body is a two-octet length, then the groups (§4.2.7).
const extension_supported_groups: u16 = 10;
/// X25519MLKEM768 (RFC 10024 §7.1), x25519 and secp256r1 (RFC 9846 §4.2.7).
const group_x25519_mlkem768: u16 = 0x11ec;
const group_x25519: u16 = 0x001d;
const group_secp256r1: u16 = 0x0017;
/// The groups of a hello to a server that does not require the hybrid, in chapulin's order (its
/// `handshake_groups.h`), and of one to a server that does (docs/design.md §21, TLS rule 10).
const groups_offered = [_]u16{ group_x25519_mlkem768, group_x25519, group_secp256r1 };
const groups_required = [_]u16{group_x25519_mlkem768};

fn read_u16(bytes: []const u8, at: usize) usize {
    return std.mem.readInt(u16, bytes[at..][0..@sizeOf(u16)], .big);
}

/// The groups a ClientHello handshake message offers, or none when it has no supported_groups.
fn groups_of(message: []const u8) []const u8 {
    const suites = suites_of(message);
    var at = @intFromPtr(suites.ptr) - @intFromPtr(message.ptr) + suites.len;
    at += 1 + message[at];
    const extensions_end = at + @sizeOf(u16) + read_u16(message, at);
    at += @sizeOf(u16);
    // Bounded: each pass reads one extension, of four octets at least.
    for (0..message.len) |_| {
        if (at >= extensions_end) break;
        const body = message[at + extension_header_bytes ..][0..read_u16(message, at + @sizeOf(u16))];
        if (read_u16(message, at) == extension_supported_groups) return body[@sizeOf(u16)..];
        at += extension_header_bytes + body.len;
    }
    return &.{};
}

/// Requires that the TCP link of a channel over the CPU of `case` offers `expected` in its first
/// hello. The QUIC link opens first, and goes nowhere; the TCP link's hello is its first output.
/// A case this host cannot state skips the test.
fn expect_tcp_suites(case: identity.support.Case, expected: []const u16) !void {
    const pair = (try rig.Pair.create_with(.{}, case)) orelse return error.SkipZigTest;
    defer pair.free();
    try testing.expect(pair.doh.request(0, &rig.query, pair.now_ns));
    try testing.expectEqual(rig.Doh.Link.quic, (try pair.run(.open)).open.link);
    try testing.expectEqual(rig.Doh.Link.tcp, (try pair.run(.open)).open.link);
    const hello_len = pair.doh.output(&pair.wire, pair.now_ns);
    try expect_codes(expected, suites_of(pair.wire[constants.record_header_bytes..hello_len]));
}

/// Requires that the QUIC link of a channel over the CPU of `case` offers `expected` in its first hello.
/// colibri builds the link's TLS configuration from the channel's one TLS value (its decision 120).
/// A session over that configuration writes the hello of the link's first Initial, and chapulin
/// starts at the transport parameters (RFC 9001 §8.2).
fn expect_quic_suites(case: identity.support.Case, expected: []const u16) !void {
    const pair = (try rig.Pair.create_with(.{}, case)) orelse return error.SkipZigTest;
    defer pair.free();
    const session = try testing.allocator.create(tls.quic.Client);
    defer testing.allocator.destroy(session);
    try session.start(&pair.doh.channel.quic_tls, rig.identity_seconds, null);
    defer session.close();
    try session.provider().set_transport_params(transport_parameters);
    var hello: [limits.hello_bytes_max]u8 = undefined;
    const hello_len = try session.provider().write_handshake(.initial, &hello);
    try expect_codes(expected, suites_of(hello[0..hello_len]));
}

test "a context whose AES instructions stdx states in constant time offers AES-GCM first, on each link" {
    // docs/design.md §24 and §16 decision 48: the channel hands colibri the consumer's context, in
    // its one TLS value. RFC 9846 §9.1 makes TLS_AES_128_GCM_SHA256 the suite to implement.
    try expect_tcp_suites(.with_aes, &suites_with_aes);
    try expect_quic_suites(.with_aes, &suites_with_aes);
}

test "a context of no instruction offers TLS_CHACHA20_POLY1305_SHA256 alone, on each link" {
    // docs/design.md §16 decision 48: a CPU of neither instruction.
    try expect_tcp_suites(.nothing, &suites_without_aes);
    try expect_quic_suites(.nothing, &suites_without_aes);
}

test "a context of the AES instructions with no timing offers TLS_CHACHA20_POLY1305_SHA256 alone, on each link" {
    // docs/design.md §16 decision 48: an arm64 core whose timing stdx cannot state. Off arm64
    // stdx states the timing of each core, and the test skips.
    try expect_tcp_suites(.aes_not_stated, &suites_without_aes);
    try expect_quic_suites(.aes_not_stated, &suites_without_aes);
}

test "a context of a carry-less multiply and no AES instructions offers TLS_CHACHA20_POLY1305_SHA256 alone, on each link" {
    // docs/design.md §16 decision 48, as over DoT.
    try expect_tcp_suites(.without_aes, &suites_without_aes);
    try expect_quic_suites(.without_aes, &suites_without_aes);
}

/// A pair whose server requires the hybrid when `required` says so (docs/design.md §21, TLS rule 10).
fn pair_requiring(required: bool) !*rig.Pair {
    const pair = try testing.allocator.create(rig.Pair);
    errdefer testing.allocator.destroy(pair);
    pair.* = .{ .require_post_quantum = required };
    try pair.open(.{});
    return pair;
}

/// Requires that the TCP link's first hello offers `expected` as its groups, as `expect_tcp_suites`
/// reads its suites.
fn expect_tcp_groups(required: bool, expected: []const u16) !void {
    const pair = try pair_requiring(required);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &rig.query, pair.now_ns));
    try testing.expectEqual(rig.Doh.Link.quic, (try pair.run(.open)).open.link);
    try testing.expectEqual(rig.Doh.Link.tcp, (try pair.run(.open)).open.link);
    const hello_len = pair.doh.output(&pair.wire, pair.now_ns);
    try expect_codes(expected, groups_of(pair.wire[constants.record_header_bytes..hello_len]));
}

/// Requires that the QUIC link's first hello offers `expected` as its groups, as
/// `expect_quic_suites` reads its suites.
fn expect_quic_groups(required: bool, expected: []const u16) !void {
    const pair = try pair_requiring(required);
    defer pair.free();
    const session = try testing.allocator.create(tls.quic.Client);
    defer testing.allocator.destroy(session);
    try session.start(&pair.doh.channel.quic_tls, rig.identity_seconds, null);
    defer session.close();
    try session.provider().set_transport_params(transport_parameters);
    var hello: [limits.hello_bytes_max]u8 = undefined;
    const hello_len = try session.provider().write_handshake(.initial, &hello);
    try expect_codes(expected, groups_of(hello[0..hello_len]));
}

test "a server that requires the post-quantum hybrid gets hellos that offer X25519MLKEM768 alone, on each link" {
    // docs/design.md §21, TLS rule 10: the engine copies the value of `Https` into the channel's
    // `Tls`, and colibri builds the TLS of both links from it (its decision 120).
    try expect_tcp_groups(false, &groups_offered);
    try expect_quic_groups(false, &groups_offered);
    try expect_tcp_groups(true, &groups_required);
    try expect_quic_groups(true, &groups_required);
}

test "a query to a server that requires the hybrid is answered, since colibri's server selects it" {
    // colibri's server holds the hybrid and prefers it, so the handshake that offers it alone
    // completes (RFC 10024 §4.2), and the answer comes back over HTTP/2.
    const pair = try pair_requiring(true);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &rig.query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(u16, 0), finished.index);
    try testing.expect(finished.result == .answer);
    try testing.expectEqual(.h2, pair.doh.connected().?.protocol);
}
