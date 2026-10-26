//! The DoT session's tests (`io_chapulin.zig`, docs/design.md §21). They need no network: a session
//! starts, stages a hello whose suites follow what its context states of the CPU, and refuses what
//! chapulin refuses. Split out of `io_chapulin.zig`.
const std = @import("std");
const cocuyo = @import("cocuyo");
// The engine's constants, through the engine's module: a file belongs to one module.
const constants = @import("io").constants;
const tls = @import("tls");
const Session = @import("io_chapulin.zig").Session;

const testing = std.testing;

/// A handshake record's content type, and an alert's, and an alert's fatal level (RFC 9846 §5.1,
/// §6).
const content_handshake: u8 = 22;
const content_alert: u8 = 21;
const alert_fatal: u8 = 2;

/// The wall clock the tests' contexts are made at.
const test_seconds: u64 = 1_700_000_000;

/// The octet a test's stream is seeded with when the test does not read what the stream gives.
const test_seed_octet: u8 = 7;

/// What a test states of the CPU when it names nothing: no answer of the probe, and no timing
/// mode. A consumer that cannot state its thread's mode passes it (docs/design.md §16 decision 48).
const cpu_not_stated: Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known }, .timing = .not_stated };
/// A probe that found the AES instructions and FEAT_DIT, under a timing mode the test states and
/// nothing checks. A test that names it reads the hello alone, which runs no AES instruction.
const cpu_with_aes: Session.Cpu = .{ .probe = .{ .aes_clmul = .yes, .dit = .yes }, .timing = .data_independent };
/// The same probe, with no timing mode stated.
const cpu_aes_not_stated: Session.Cpu = .{ .probe = cpu_with_aes.probe, .timing = .not_stated };
/// A probe that found FEAT_DIT and no AES instructions, under the timing mode of `cpu_with_aes`.
const cpu_without_aes: Session.Cpu = .{ .probe = .{ .aes_clmul = .no, .dit = .yes }, .timing = .data_independent };
/// A probe that found FEAT_DIT and gave no answer for the AES instructions, under the same mode.
const cpu_aes_not_known: Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .yes }, .timing = .data_independent };

/// A context for a test: the stream seeded with `seed_octet` repeated, so each run draws what the
/// last drew, and the wall clock at `test_seconds`. It states nothing of the CPU. Never for a
/// network, whose seed comes from a CSPRNG.
fn test_context(anchors: []const tls.Anchor, seed_octet: u8) Session.Context {
    return test_context_with(cpu_not_stated, anchors, seed_octet);
}

/// As `test_context`, with the statement of the CPU that the test names.
fn test_context_with(cpu: Session.Cpu, anchors: []const tls.Anchor, seed_octet: u8) Session.Context {
    return .init(anchors, cpu, @splat(seed_octet), test_seconds, 0);
}

/// The octets of the pin the tests' servers are known by, which no key hashes to.
const pin_octet: u8 = 0xab;

/// A session, which is too large for a test's stack, started as the engine starts one.
fn started(server: *const cocuyo.Tls, context: *Session.Context) !*Session {
    const session = try testing.allocator.create(Session);
    errdefer testing.allocator.destroy(session);
    session.* = .{};
    try session.start(.{ .tls = server, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = @as(u64, 0), .context = context, .now_ns = @as(u64, 0) });
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
    // Until 2026-10-11 the fields defaulted to no anchors, an undefined stream and a wall clock of
    // zero, and so did the engine's context when no consumer set one (docs/design.md §16
    // decision 39).
    inline for (comptime std.meta.fields(Session.Context)) |field| {
        try testing.expectEqual(@as(?*const anyopaque, null), field.default_value_ptr);
    }
}

test "a session starts and stages a hello, a TLS handshake record" {
    var context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    const session = try started(&.{ .pins = &pins }, &context);
    defer finish(session);
    var out: [Session.out_bytes_max]u8 = undefined;
    const made = session.take_out(&out);
    // A handshake record (RFC 9846 §5.1): content type 22, then the length of the body.
    try testing.expect(made > constants.tls_record_header_bytes);
    try testing.expectEqual(@as(u8, content_handshake), out[0]);
    const body = std.mem.readInt(u16, out[constants.tls_record_length_at..][0..@sizeOf(u16)], .big);
    try testing.expectEqual(made, constants.tls_record_header_bytes + body);
}

/// The hello a session over `seed` and `cpu` stages first.
const Hello = struct {
    bytes: [Session.out_bytes_max]u8 = undefined,
    len: usize = 0,

    fn of(seed: u8, cpu: Session.Cpu) !Hello {
        var context = test_context_with(cpu, &.{}, seed);
        const pins = [_]cocuyo.Pin{@splat(pin_octet)};
        const session = try started(&.{ .pins = &pins }, &context);
        defer finish(session);
        var hello: Hello = .{};
        hello.len = session.take_out(&hello.bytes);
        return hello;
    }

    fn slice(hello: *const Hello) []const u8 {
        return hello.bytes[0..hello.len];
    }
};

test "the hello is drawn from the context's stream: the same seed makes the same hello" {
    const first = try Hello.of(1, cpu_not_stated);
    const again = try Hello.of(1, cpu_not_stated);
    const other = try Hello.of(2, cpu_not_stated);
    // The random and the key shares are the stream's (non-negotiable 4).
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
/// colibri hands chapulin no order of its own. So the order is that of chapulin's host object,
/// which colibri builds for arm64 and x86-64 (chapulin's `suite.h`).
const suites_with_aes = [_]u16{ aes_256_gcm_sha384, aes_128_gcm_sha256, chacha20_poly1305_sha256 };
/// The suites of a hello whose context states no timing mode, or no AES instructions found.
const suites_without_aes = [_]u16{chacha20_poly1305_sha256};

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

/// The cipher_suites `hello` offers, after its record's header.
fn hello_suites(hello: *const Hello) []const u8 {
    return suites_of(hello.slice()[constants.tls_record_header_bytes..]);
}

test "a context that states the AES instructions and a data-independent timing offers AES-GCM first" {
    // docs/design.md §16 decision 48: the session hands colibri what its context states. RFC 9846
    // §9.1 makes TLS_AES_128_GCM_SHA256 the suite to implement, so a server may hold it alone.
    const hello = try Hello.of(test_seed_octet, cpu_with_aes);
    try expect_suites(&suites_with_aes, hello_suites(&hello));
}

test "a context that states no timing mode offers TLS_CHACHA20_POLY1305_SHA256 alone, whatever its probe" {
    // docs/design.md §16 decision 48: the value a consumer passes when it cannot state its
    // thread's mode. The AES instructions alone are no ground for colibri to run them.
    const nothing = try Hello.of(test_seed_octet, cpu_not_stated);
    try expect_suites(&suites_without_aes, hello_suites(&nothing));
    const probe_alone = try Hello.of(test_seed_octet, cpu_aes_not_stated);
    try expect_suites(&suites_without_aes, hello_suites(&probe_alone));
}

test "a context that states a data-independent timing and no AES instructions offers TLS_CHACHA20_POLY1305_SHA256 alone" {
    // docs/design.md §16 decision 48: colibri runs the AES instructions only where the probe
    // answered `yes`. A probe's `no` or `not_known` gives no ground to run them.
    const without = try Hello.of(test_seed_octet, cpu_without_aes);
    try expect_suites(&suites_without_aes, hello_suites(&without));
    const not_known = try Hello.of(test_seed_octet, cpu_aes_not_known);
    try expect_suites(&suites_without_aes, hello_suites(&not_known));
}

test "a handshake chapulin refuses hands over its fatal alert, though the session is wiped" {
    // A first record from the server that is no ServerHello: chapulin fails the handshake and
    // colibri writes the alert it chose, which the engine sends before it closes (RFC 9846 §6.2).
    var context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    const session = try started(&.{ .pins = &pins }, &context);
    defer finish(session);
    var out: [Session.out_bytes_max]u8 = undefined;
    _ = session.take_out(&out);
    // A handshake record whose one message is of a type no server sends (RFC 9846 §4).
    var record = [_]u8{ content_handshake, 3, 3, 0, 4, 0xfe, 0, 0, 0 };
    try testing.expectError(Session.Error.Failed, session.handshake(&record));
    try testing.expect(!session.started);
    // An alert record, in the clear before any key: content type 21, and a fatal level (§6).
    const made = session.take_out(&out);
    try testing.expect(made >= constants.tls_record_header_bytes + 2);
    try testing.expectEqual(@as(u8, content_alert), out[0]);
    try testing.expectEqual(@as(u8, alert_fatal), out[constants.tls_record_header_bytes]);
}

test "a server known by pins alone gets no anchors, though the context carries them for named servers" {
    // The anchors are for the servers that have names; one known by its key alone gets none,
    // which chapulin would refuse with no name to check a chain against.
    const context = test_context(&anchors_test, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqual(@as(?[]const u8, null), trust.pins.server_name);
}

test "a named server is checked against the anchors and its name, on the context's clock" {
    const context = test_context(&anchors_test, test_seed_octet);
    var hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example.") }, &context, &hostname);
    try testing.expect(trust == .web_pki);
    try testing.expectEqual(anchors_test.len, trust.web_pki.anchors.len);
    // chapulin takes a hostname, with no root label's dot.
    try testing.expectEqualStrings("dns.example", trust.web_pki.server_name);
    try testing.expectEqual(@as(u64, test_seconds + 5), context.seconds_at(5 * constants.ns_per_second));
}

test "a named server with no anchors to check is judged by its pins, and its name still sent" {
    const context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var hostname: [cocuyo.limits.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqualStrings("dns.example", trust.pins.server_name.?);
}

test "a session with neither pins nor anchors for its name is refused before a byte" {
    var context = test_context(&.{}, test_seed_octet);
    const server: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try testing.expectError(Session.Error.Failed, session.start(.{ .tls = &server, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 0) }));
    var out: [Session.out_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), session.take_out(&out));
}

test "the ticket a session would resume with is zeroed when its start fails" {
    // The copy holds the resumption secret (RFC 9846 §4.7.1), which nothing may keep past the
    // session it was for. This ticket's binding to the server matches nothing, so chapulin refuses
    // it, and the failed start wipes the session.
    var context = test_context(&.{}, test_seed_octet);
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var ticket = std.mem.zeroes(Session.Ticket);
    ticket.identity_len = 1;
    ticket.psk_len = tls.constants.sha256_len;
    @memset(&ticket.psk, 0x5a);
    @memset(&ticket.binding, 0x33);
    ticket.lifetime_s = 1;
    const session = try testing.allocator.create(Session);
    defer testing.allocator.destroy(session);
    session.* = .{};
    try testing.expectError(Session.Error.Failed, session.start(.{ .tls = &cocuyo.Tls{ .pins = &pins }, .ticket = @as(?Session.Ticket, ticket), .ticket_age_ns = @as(u64, 0), .context = &context, .now_ns = @as(u64, 0) }));
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&session.resuming), 0));
    try testing.expect(!session.started);
}

test "chapulin starts a session for a server of four pins, the most a configuration names, and refuses five" {
    // `spki_pins_max` is chapulin's own bound as well (docs/design.md §21). A server of four pins
    // starts. Five pins, which no valid configuration names, are refused at the start.
    var context = test_context(&.{}, test_seed_octet);
    const pins: [cocuyo.limits.spki_pins_max + 1]cocuyo.Pin = @splat(@splat(pin_octet));
    const most = try started(&.{ .pins = pins[0..cocuyo.limits.spki_pins_max] }, &context);
    finish(most);
    try testing.expectError(Session.Error.Failed, started(&.{ .pins = &pins }, &context));
}
