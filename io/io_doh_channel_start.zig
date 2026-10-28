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
const limits = @import("io_doh_channel_limits.zig");
const exchange_module = @import("io_doh_channel_exchange.zig");
const read_module = @import("io_doh_channel_read.zig");

/// What every channel starts from (docs/design.md §24, the context a session starts from). It holds
/// the roots a named server's chain may end at, and the consumer's statement of its CPU. It holds
/// the stream chapulin and the QUIC connection IDs draw from, and the wall clock at an instant of
/// the caller's. No field has a default, so a context is built by `init`, with each of them named
/// (§16 decision 39). The anchors are the caller's and outlive the engine.
pub const Context = struct {
    anchors: []const tls.Anchor,
    cpu: tls.Cpu,
    stream: std.Random.ChaCha,
    unix_seconds: u64,
    at_ns: u64,

    /// `cpu` is the consumer's probe and its thread's timing mode, which the engine cannot check
    /// (§16 decision 48). Under `data_independent`, with the AES instructions found, each hello
    /// offers AES-GCM first; under any other value, ChaCha20-Poly1305 alone. `seed` must be 32
    /// octets of a CSPRNG, drawn for this context alone: chapulin draws each handshake's random and
    /// its key shares from the stream they key, and the QUIC link its connection IDs.
    /// `unix_seconds` is the wall clock at the caller's `now_ns`. A DoH server is known by its
    /// template's host, so `anchors` holds the roots its chain may end at.
    pub fn init(anchors: []const tls.Anchor, cpu: tls.Cpu, seed: [std.Random.ChaCha.secret_seed_length]u8, unix_seconds: u64, now_ns: u64) Context {
        assert(anchors.len <= tls.record.ClientConfig.anchors_max);
        return .{ .anchors = anchors, .cpu = cpu, .stream = std.Random.ChaCha.init(seed), .unix_seconds = unix_seconds, .at_ns = now_ns };
    }

    /// The wall clock at `now_ns`, carried forward from the instant the context was made.
    pub fn seconds_at(context: *const Context, now_ns: u64) u64 {
        return context.unix_seconds + (now_ns -| context.at_ns) / constants.ns_per_second;
    }
};

/// What the channel speaks (rule 18): HTTP/3 over QUIC, and HTTP/2 or HTTP/1.1 over TCP. colibri
/// builds each ALPN list from it: `h3` over QUIC (RFC 9114 §3.1), and `h2`, then `http/1.1`, over
/// TCP (RFC 7301 §3.1; its decision 120).
const versions: client.Versions = .{ .h11 = true, .h2 = true, .h3 = true };

/// The least memory colibri v0.8.0 names for a TCP transport (its decision 124, ruling 5;
/// docs/design.md §24, the interface). `stream_input_len_min` holds a whole head of HTTP/1.1,
/// which cleartext needs. Over TLS colibri keeps the partial head in its own room beside one
/// whole record. So the type's buffer holds a whole record and a chunk, and not
/// `stream_input_len_min`. Each start asserts it, so a test that starts a channel reads it.
fn assert_sizes() void {
    const record_body_bytes_max = limits.record_bytes_max - constants.record_header_bytes;
    const room_least = client.constants.stream_input_len_min - 1 + record_body_bytes_max;
    assert(client.constants.plaintext_in_len >= room_least);
    assert(limits.stream_bytes_max >= limits.record_bytes_max + limits.engine_chunk_bytes_max);
    // `send_stream` always writes a record it owes into an output this long.
    assert(limits.output_bytes_max >= client.constants.stream_output_len_min);
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
    // What the consumer stated of its CPU decides the suites of each link's hello (§16 decision
    // 48). colibri builds the TLS of both transports from this one value (its decision 120).
    self.channel_config = .{
        .tls = .{ .trust = trust, .cpu = self.context.cpu },
        .versions = versions,
        .authority = https.authority,
        .fallback_delay_ns = constants.fallback_delay_ns,
    };
    self.addresses = .{client.Address.of(context.endpoint.address.slice(), 0)};
    self.channel.init(&self.channel_config, .{
        .addresses = &self.addresses,
        .port = context.endpoint.port,
        .alternative = context.alternative,
    }, self.pool.storage()) catch return error.Failed;
    self.started = true;
}

/// Starts a link's connection once its socket carries octets, with the context's wall clock and the
/// ticket kept for its transport, offered at its age (RFC 9846 §4.3.11.1). colibri draws a QUIC
/// connection's grease value and its connection IDs from the context's stream (RFC 9000 §7.2; its
/// decision 120), then every draw of its handshake. One chapulin refuses fails the link.
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
        .quic => self.channel.start_quic(random, seconds, now_ns, resumption) catch return error.Failed,
        .tcp => self.channel.start_tcp(random, seconds, resumption) catch return error.Failed,
    }
    // A TCP link starts once its connect has finished, so a server took part (docs/design.md §16
    // decision 51). A QUIC link's server takes part when its first datagram comes.
    if (link == .tcp) read_module.heard_from(self, .tcp);
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
/// The suites of a hello whose context states the AES instructions and a data-independent timing.
/// colibri hands chapulin no order of its own, so the order is that of chapulin's host object (its
/// `suite.h`): AES-256-GCM, AES-128-GCM, ChaCha20.
const suites_with_aes = [_]u16{ aes_256_gcm_sha384, aes_128_gcm_sha256, chacha20_poly1305_sha256 };
/// The suites of a hello whose context states no timing mode, or no AES instructions found.
const suites_without_aes = [_]u16{chacha20_poly1305_sha256};
/// A probe that found the AES instructions and FEAT_DIT, under a timing mode the test states and
/// nothing checks. A test that names it reads the hello alone, which runs no AES instruction.
const cpu_with_aes: tls.Cpu = .{ .probe = .{ .aes_clmul = .yes, .dit = .yes }, .timing = .data_independent };
/// The same probe, with no timing mode stated.
const cpu_aes_not_stated: tls.Cpu = .{ .probe = cpu_with_aes.probe, .timing = .not_stated };
/// A probe that found FEAT_DIT and no AES instructions, under the timing mode of `cpu_with_aes`.
const cpu_without_aes: tls.Cpu = .{ .probe = .{ .aes_clmul = .no, .dit = .yes }, .timing = .data_independent };
/// A probe that found FEAT_DIT and gave no answer for the AES instructions, under the same mode.
const cpu_aes_not_known: tls.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .yes }, .timing = .data_independent };
/// max_idle_timeout, of 30,000 milliseconds (RFC 9000 §18.2), which chapulin carries and does not
/// read: its ID, its length, and its value as a two-octet varint.
const transport_parameters = "\x01\x02\x75\x30";

/// Requires that `suites`, a ClientHello's cipher_suites, offer `expected` in its order, and
/// nothing else.
fn expect_suites(expected: []const u16, suites: []const u8) !void {
    try testing.expectEqual(expected.len * @sizeOf(u16), suites.len);
    for (expected, 0..) |suite, index| {
        const at = index * @sizeOf(u16);
        try testing.expectEqual(suite, std.mem.readInt(u16, suites[at..][0..@sizeOf(u16)], .big));
    }
}

/// The cipher_suites a ClientHello handshake message offers.
fn suites_of(message: []const u8) []const u8 {
    const session_id_at = message_header_bytes + legacy_version_bytes + random_bytes;
    const suites_at = session_id_at + 1 + message[session_id_at] + @sizeOf(u16);
    const suites_len = std.mem.readInt(u16, message[suites_at - @sizeOf(u16) ..][0..@sizeOf(u16)], .big);
    return message[suites_at..][0..suites_len];
}

/// Requires that the TCP link of a channel over `cpu` offers `expected` in its first hello. The
/// QUIC link opens first, and goes nowhere; the TCP link's hello is its first output.
fn expect_tcp_suites(cpu: tls.Cpu, expected: []const u16) !void {
    const pair = try rig.Pair.create_with(.{}, cpu);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &rig.query, pair.now_ns));
    try testing.expectEqual(rig.Doh.Link.quic, (try pair.run(.open)).open.link);
    try testing.expectEqual(rig.Doh.Link.tcp, (try pair.run(.open)).open.link);
    const hello_len = pair.doh.output(&pair.wire, pair.now_ns);
    try expect_suites(expected, suites_of(pair.wire[constants.record_header_bytes..hello_len]));
}

/// Requires that the QUIC link of a channel over `cpu` offers `expected` in its first hello.
/// colibri builds the link's TLS configuration from the channel's one TLS value (its decision 120).
/// A session over that configuration writes the hello of the link's first Initial, and chapulin
/// starts at the transport parameters (RFC 9001 §8.2).
fn expect_quic_suites(cpu: tls.Cpu, expected: []const u16) !void {
    const pair = try rig.Pair.create_with(.{}, cpu);
    defer pair.free();
    const session = try testing.allocator.create(tls.quic.Client);
    defer testing.allocator.destroy(session);
    try session.start(&pair.doh.channel.quic_tls, pair.context.stream.random(), rig.identity_seconds, null);
    defer session.close();
    try session.provider().set_transport_params(transport_parameters);
    var hello: [limits.hello_bytes_max]u8 = undefined;
    const hello_len = try session.provider().write_handshake(.initial, &hello);
    try expect_suites(expected, suites_of(hello[0..hello_len]));
}

test "a context that states the AES instructions and a data-independent timing offers AES-GCM first, on each link" {
    // docs/design.md §24 and §16 decision 48: the channel hands colibri what its context states,
    // in its one TLS value. RFC 9846 §9.1 makes TLS_AES_128_GCM_SHA256 the suite to implement.
    try expect_tcp_suites(cpu_with_aes, &suites_with_aes);
    try expect_quic_suites(cpu_with_aes, &suites_with_aes);
}

test "a context that states no timing mode offers TLS_CHACHA20_POLY1305_SHA256 alone, on each link, whatever its probe" {
    // docs/design.md §16 decision 48: the value a consumer passes when it cannot state its
    // thread's mode. A probe that found the AES instructions changes nothing without the mode.
    try expect_tcp_suites(identity.cpu_not_stated, &suites_without_aes);
    try expect_quic_suites(identity.cpu_not_stated, &suites_without_aes);
    try expect_tcp_suites(cpu_aes_not_stated, &suites_without_aes);
    try expect_quic_suites(cpu_aes_not_stated, &suites_without_aes);
}

test "a context that states a data-independent timing and no AES instructions offers TLS_CHACHA20_POLY1305_SHA256 alone, on each link" {
    // docs/design.md §16 decision 48, as over DoT: a probe's `no` or `not_known` gives colibri
    // no ground to run the AES instructions.
    try expect_tcp_suites(cpu_without_aes, &suites_without_aes);
    try expect_quic_suites(cpu_without_aes, &suites_without_aes);
    try expect_tcp_suites(cpu_aes_not_known, &suites_without_aes);
    try expect_quic_suites(cpu_aes_not_known, &suites_without_aes);
}
