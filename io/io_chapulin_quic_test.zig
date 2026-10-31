//! The DoQ session's tests (`io_chapulin_quic.zig`, docs/design.md §24, chapulin under colibri): how
//! colibri is told to check a server known by a name, by pins, or by both, and that chapulin's
//! session starts at the transport parameters and draws from the engine's stream. Split out of
//! `io_chapulin_quic.zig`.
const std = @import("std");
const cocuyo = @import("cocuyo");
const tls = @import("tls");
const quic = @import("quic");
const Session = @import("io_chapulin_quic.zig").Session;
const constants = @import("cocuyo_quic").constants;

const testing = std.testing;

/// A context as `cocuyo_quic`'s connections hold one, with the session's inside.
const Context = struct { session: Session.Context };

/// The wall clock the tests' contexts are made at, and the `now_ns` it is pinned to.
const test_seconds: u64 = 1;
const test_ns: u64 = 1;

/// What a test states of the CPU when it names nothing: no answer of the probe, and no timing
/// mode. A consumer that cannot state its thread's mode passes it (docs/design.md §16 decision 48).
const cpu_not_stated: Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known }, .timing = .not_stated };
/// A probe that found the AES instructions and FEAT_DIT, under a timing mode the test states and
/// nothing checks. A test that names it reads the hello alone, which runs no AES instruction.
const cpu_with_aes: Session.Cpu = .{ .probe = .{ .aes_clmul = .yes, .dit = .yes, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known }, .timing = .data_independent };
/// The same probe, with no timing mode stated.
const cpu_aes_not_stated: Session.Cpu = .{ .probe = cpu_with_aes.probe, .timing = .not_stated };
/// A probe that found FEAT_DIT and no AES instructions, under the timing mode of `cpu_with_aes`.
const cpu_without_aes: Session.Cpu = .{ .probe = .{ .aes_clmul = .no, .dit = .yes, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known }, .timing = .data_independent };
/// A probe that found FEAT_DIT and gave no answer for the AES instructions, under the same mode.
const cpu_aes_not_known: Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .yes, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known }, .timing = .data_independent };

/// A session's context for a test: the stream seeded with `seed_octet` repeated, so each run draws
/// what the last drew. It states nothing of the CPU. Never for a network, whose seed comes from a
/// CSPRNG.
fn test_context(anchors: []const tls.Anchor, seed_octet: u8) Session.Context {
    return test_context_with(cpu_not_stated, anchors, seed_octet);
}

/// As `test_context`, with the statement of the CPU that the test names.
fn test_context_with(cpu: Session.Cpu, anchors: []const tls.Anchor, seed_octet: u8) Session.Context {
    return .init(anchors, cpu, @splat(seed_octet), test_seconds, test_ns);
}

/// As `test_context`, with the wall clock the test names: `unix_seconds` at `now_ns`.
fn test_context_at(anchors: []const tls.Anchor, seed_octet: u8, unix_seconds: u64, now_ns: u64) Session.Context {
    return .init(anchors, cpu_not_stated, @splat(seed_octet), unix_seconds, now_ns);
}

/// max_idle_timeout, of 30,000 milliseconds (RFC 9000 §18.2), which chapulin carries without
/// reading: its ID, its length, and its value as a two-octet varint.
const transport_parameters = "\x01\x02\x75\x30";

/// The handshake type of a ClientHello (RFC 9846 §4), the first octet of the Initial CRYPTO data.
const client_hello: u8 = 1;

/// Room for a ClientHello at its longest: a post-quantum key share, a ticket and a cookie.
const hello_bytes_max: usize = 4096;

/// The octets of the pin the tests' servers are known by, which no key hashes to.
const pin_octet: u8 = 0xab;

/// QUIC version 1's Version field (RFC 9000 §15). colibri offers a ticket only to a connection of
/// the QUIC version that issued it, so a test's ticket names the version a session starts on.
const quic_version_1: u32 = 0x0000_0001;

/// A session, which is too large for a test's stack, started as `cocuyo_quic` starts one: the
/// session, then the transport parameters colibri sets, where chapulin starts.
fn started(server: *const cocuyo.Tls, context: *Context, ticket: ?Session.Ticket) !*Session {
    const session = try testing.allocator.create(Session);
    errdefer testing.allocator.destroy(session);
    session.* = .{};
    try session.start(.{
        .tls = server,
        .alpn = "doq",
        .ticket = ticket,
        .ticket_age_ns = @as(u64, 0),
        .context = context,
        .now_ns = @as(u64, 1),
    });
    errdefer session.wipe();
    try session.provider().set_transport_params(transport_parameters);
    return session;
}

fn finish(session: *Session) void {
    session.wipe();
    testing.allocator.destroy(session);
}

/// One octet of DER, which colibri hands chapulin as an anchor's name and key without reading.
const anchor_octet = "\x30";
const anchors_test = [_]tls.Anchor{.{ .subject = anchor_octet, .spki = anchor_octet }};

test "the context carries no default, so each of its fields is named where one is built" {
    // Until 2026-10-11 the fields defaulted to no anchors, a stream seeded with zeros and a wall
    // clock of zero, and so did the engine's context when no consumer set one (docs/design.md §16
    // decision 39).
    inline for (comptime std.meta.fields(Session.Context)) |field| {
        try testing.expectEqual(@as(?*const anyopaque, null), field.default_value_ptr);
    }
}

test "a server known by pins alone is judged by its key, though the context has anchors" {
    // chapulin refuses pins beside anchors with no hostname (its decision 64), so the anchors, for
    // named servers, are not this one's (RFC 8310 §6.3's "SPKI + IP").
    const context = test_context(&anchors_test, 0);
    const pins = [_]cocuyo.Pin{@splat(0)};
    var hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqual(@as(?[]const u8, null), trust.pins.server_name);
}

test "a server known by a name and pins is checked by both" {
    // "both must pass" (RFC 8310 §6.4): the chain against the anchors and the name, a key on it
    // against the pins.
    const context = test_context(&anchors_test, 0);
    const pins = [_]cocuyo.Pin{@splat(0)};
    var hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .web_pki);
    try testing.expectEqual(anchors_test.len, trust.web_pki.anchors.len);
    try testing.expectEqual(pins.len, trust.web_pki.pins.len);
    // chapulin takes a hostname, with no root label's dot.
    try testing.expectEqualStrings("dns.example", trust.web_pki.server_name);
}

test "a named server with no anchors to check it is judged by its pins, its name still sent" {
    const context = test_context(&.{}, 0);
    const pins = [_]cocuyo.Pin{@splat(0)};
    var hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqualStrings("dns.example", trust.pins.server_name.?);
}

test "the wall clock a chain is judged at is carried forward from the context's instant" {
    const seconds = 1_700_000_000;
    const context = test_context_at(&.{}, 0, seconds, constants.ns_per_second);
    try testing.expectEqual(@as(u64, seconds + 4), context.seconds_at(5 * constants.ns_per_second));
    // An instant before the context's is its own.
    try testing.expectEqual(@as(u64, seconds), context.seconds_at(0));
}

test "a server known by a name with no anchor to check it against is refused by chapulin" {
    var context: Context = .{ .session = test_context(&.{}, 0) };
    const name = try cocuyo.Name.from_text("dns.example.");
    try testing.expectError(error.TlsFailed, started(&.{ .name = name }, &context, null));
}

test "chapulin starts a QUIC session for a server of four pins, the most a configuration names" {
    // `spki_pins_max` is chapulin's own bound as well (docs/design.md §21), in QUIC as over TCP.
    // Five pins are no valid configuration's, and the session asserts so before chapulin sees them.
    var context: Context = .{ .session = test_context(&.{}, 0) };
    const pins: [cocuyo.limits.spki_pins_max]cocuyo.Pin = @splat(@splat(pin_octet));
    finish(try started(&.{ .pins = &pins }, &context, null));
}

/// The Initial CRYPTO data a session over `seed` and `cpu` owes first: its ClientHello.
const Hello = struct {
    bytes: [hello_bytes_max]u8 = undefined,
    len: usize = 0,

    fn of(seed: u8, cpu: Session.Cpu) !Hello {
        return of_server(seed, cpu, false);
    }

    /// The hello to a server known by a pin, which requires the hybrid when `required` says so.
    fn of_server(seed: u8, cpu: Session.Cpu, required: bool) !Hello {
        var context: Context = .{ .session = test_context_with(cpu, &.{}, seed) };
        const pins = [_]cocuyo.Pin{@splat(pin_octet)};
        const session = try started(&.{ .pins = &pins, .require_post_quantum = required }, &context, null);
        defer finish(session);
        var hello: Hello = .{};
        hello.len = try session.provider().write_handshake(.initial, &hello.bytes);
        return hello;
    }

    fn slice(hello: *const Hello) []const u8 {
        return hello.bytes[0..hello.len];
    }
};

test "chapulin starts at the transport parameters, and draws its hello from the context's stream" {
    const first = try Hello.of(1, cpu_not_stated);
    const again = try Hello.of(1, cpu_not_stated);
    const other = try Hello.of(2, cpu_not_stated);
    try testing.expect(first.len > 0);
    try testing.expectEqual(@as(u8, client_hello), first.bytes[0]);
    // The same seed makes the same hello, and another seed another: the random and the key shares
    // are the stream's (non-negotiable 4).
    try testing.expectEqualSlices(u8, first.slice(), again.slice());
    try testing.expect(!std.mem.eql(u8, first.slice(), other.slice()));
}

/// Where a ClientHello's cipher_suites start (RFC 9846 §4, §4.2.2): after the message's type and
/// length, the legacy_version, the random, and the legacy_session_id's length octet and its body.
const message_header_bytes: usize = 4;
const legacy_version_bytes: usize = 2;
const random_bytes: usize = 32;
/// TLS_AES_128_GCM_SHA256 {0x13,0x01}, TLS_AES_256_GCM_SHA384 {0x13,0x02} and
/// TLS_CHACHA20_POLY1305_SHA256 {0x13,0x03} (RFC 9846 Appendix B.4).
const aes_128_gcm_sha256: u16 = 0x1301;
const aes_256_gcm_sha384: u16 = 0x1302;
const chacha20_poly1305_sha256: u16 = 0x1303;
/// The suites of a hello whose context states the AES instructions and a data-independent timing.
/// The order is that of chapulin's host object, as over DoT (`io_chapulin_test.zig`).
const suites_with_aes = [_]u16{ aes_256_gcm_sha384, aes_128_gcm_sha256, chacha20_poly1305_sha256 };
/// The suites of a hello whose context states no timing mode, or no AES instructions found.
const suites_without_aes = [_]u16{chacha20_poly1305_sha256};

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

test "a server that requires the post-quantum hybrid gets a hello that offers X25519MLKEM768 alone" {
    // docs/design.md §21, TLS rule 10: the session hands colibri the server's value, and chapulin
    // offers the hybrid alone. Without it the hello offers the hybrid and two classic groups.
    const offered = try Hello.of_server(1, cpu_not_stated, false);
    try expect_codes(&groups_offered, groups_of(offered.slice()));
    const required = try Hello.of_server(1, cpu_not_stated, true);
    try expect_codes(&groups_required, groups_of(required.slice()));
}

test "a context that states the AES instructions and a data-independent timing offers AES-GCM first" {
    // docs/design.md §24, chapulin under colibri, and §16 decision 48, as over DoT.
    const hello = try Hello.of(1, cpu_with_aes);
    try expect_codes(&suites_with_aes, suites_of(hello.slice()));
}

test "a context that states no timing mode offers TLS_CHACHA20_POLY1305_SHA256 alone, whatever its probe" {
    // docs/design.md §16 decision 48: the value a consumer passes when it cannot state its
    // thread's mode. A probe that found the AES instructions changes nothing without the mode.
    const nothing = try Hello.of(1, cpu_not_stated);
    try expect_codes(&suites_without_aes, suites_of(nothing.slice()));
    const probe_alone = try Hello.of(1, cpu_aes_not_stated);
    try expect_codes(&suites_without_aes, suites_of(probe_alone.slice()));
}

test "a context that states a data-independent timing and no AES instructions offers TLS_CHACHA20_POLY1305_SHA256 alone" {
    // docs/design.md §16 decision 48, as over DoT: a probe's `no` or `not_known` gives colibri
    // no ground to run the AES instructions.
    const without = try Hello.of(1, cpu_without_aes);
    try expect_codes(&suites_without_aes, suites_of(without.slice()));
    const not_known = try Hello.of(1, cpu_aes_not_known);
    try expect_codes(&suites_without_aes, suites_of(not_known.slice()));
}

test "the ticket a session would resume with is zeroed when it is wiped, or when its start fails" {
    // The copy holds the resumption secret (RFC 9846 §4.7.1), which nothing may keep past the
    // session it was for.
    var context: Context = .{ .session = test_context(&.{}, 0) };
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var ticket = std.mem.zeroes(Session.Ticket);
    ticket.identity_len = 1;
    ticket.psk_len = tls.constants.sha256_len;
    @memset(&ticket.psk, 0x5a);
    ticket.lifetime_s = 1;
    ticket.quic_version = quic_version_1;
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try session.start(.{ .tls = &cocuyo.Tls{ .pins = &pins }, .alpn = "doq", .ticket = @as(?Session.Ticket, ticket), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 1) });
    try testing.expectEqualSlices(u8, &ticket.psk, &session.resuming.psk);
    try testing.expect(session.offered);
    session.wipe();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&session.resuming), 0));
    // A PSK no hash is as long as, which colibri refuses before chapulin sees it (RFC 9846 §4.7.1).
    ticket.psk_len = 1;
    try testing.expectError(error.Failed, session.start(.{ .tls = &cocuyo.Tls{ .pins = &pins }, .alpn = "doq", .ticket = @as(?Session.Ticket, ticket), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 1) }));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&session.resuming), 0));
    try testing.expect(!session.started);
}

test "the provider's calls reach colibri's client once the session has started" {
    var context: Context = .{ .session = test_context(&.{}, 0) };
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    const session = try started(&.{ .pins = &pins }, &context, null);
    defer finish(session);
    const provider = session.provider();
    try testing.expect(!provider.handshake_complete());
    try testing.expectEqual(@as(?[]const u8, null), provider.negotiated_alpn());
    try testing.expectEqual(@as(?[]const u8, null), provider.peer_transport_params());
    try testing.expectEqual(@as(?quic.tls_provider.Alert, null), provider.take_alert());
    try testing.expect(!session.resumed());
    try testing.expectEqual(@as(?Session.Ticket, null), session.take_ticket());
}
