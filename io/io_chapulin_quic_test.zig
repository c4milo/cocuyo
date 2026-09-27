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

/// max_idle_timeout, of 30,000 milliseconds (RFC 9000 §18.2), which chapulin carries without
/// reading: its ID, its length, and its value as a two-octet varint.
const transport_parameters = "\x01\x02\x75\x30";

/// The handshake type of a ClientHello (RFC 9846 §4), the first octet of the Initial CRYPTO data.
const client_hello = 1;

/// Room for a ClientHello at its longest: a post-quantum key share, a ticket and a cookie.
const hello_bytes_max = 4096;

/// The octets of the pin the tests' servers are known by, which no key hashes to.
const pin_octet = 0xab;

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

test "a server known by pins alone is judged by its key, though the context has anchors" {
    // chapulin refuses pins beside anchors with no hostname (its decision 64), so the anchors, for
    // named servers, are not this one's (RFC 8310 §6.3's "SPKI + IP").
    const context: Session.Context = .init(&anchors_test, @splat(0), 1, 1);
    const pins = [_]cocuyo.Pin{@splat(0)};
    var hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqual(@as(?[]const u8, null), trust.pins.server_name);
}

test "a server known by a name and pins is checked by both" {
    // "both must pass" (RFC 8310 §6.4): the chain against the anchors and the name, a key on it
    // against the pins.
    const context: Session.Context = .init(&anchors_test, @splat(0), 1, 1);
    const pins = [_]cocuyo.Pin{@splat(0)};
    var hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .web_pki);
    try testing.expectEqual(anchors_test.len, trust.web_pki.anchors.len);
    try testing.expectEqual(pins.len, trust.web_pki.pins.len);
    // chapulin takes a hostname, with no root label's dot.
    try testing.expectEqualStrings("dns.example", trust.web_pki.server_name);
}

test "a named server with no anchors to check it is judged by its pins, its name still sent" {
    const context: Session.Context = .init(&.{}, @splat(0), 1, 1);
    const pins = [_]cocuyo.Pin{@splat(0)};
    var hostname: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    const trust = Session.trust(&.{ .name = try cocuyo.Name.from_text("dns.example."), .pins = &pins }, &context, &hostname);
    try testing.expect(trust == .pins);
    try testing.expectEqual(pins.len, trust.pins.pins.len);
    try testing.expectEqualStrings("dns.example", trust.pins.server_name.?);
}

test "the wall clock a chain is judged at is carried forward from the context's instant" {
    const seconds = 1_700_000_000;
    const context: Session.Context = .init(&.{}, @splat(0), seconds, constants.ns_per_second);
    try testing.expectEqual(@as(u64, seconds + 4), context.seconds_at(5 * constants.ns_per_second));
    // An instant before the context's is its own.
    try testing.expectEqual(@as(u64, seconds), context.seconds_at(0));
}

test "a server known by a name with no anchor to check it against is refused by chapulin" {
    var context: Context = .{ .session = .init(&.{}, @splat(0), 1, 1) };
    const name = try cocuyo.Name.from_text("dns.example.");
    try testing.expectError(error.TlsFailed, started(&.{ .name = name }, &context, null));
}

/// The Initial CRYPTO data a session over `seed` owes first: its ClientHello.
const Hello = struct {
    bytes: [hello_bytes_max]u8 = undefined,
    len: usize = 0,

    fn of(seed: u8) !Hello {
        var context: Context = .{ .session = .init(&.{}, @splat(seed), 1, 1) };
        const pins = [_]cocuyo.Pin{@splat(pin_octet)};
        const session = try started(&.{ .pins = &pins }, &context, null);
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
    const first = try Hello.of(1);
    const again = try Hello.of(1);
    const other = try Hello.of(2);
    try testing.expect(first.len > 0);
    try testing.expectEqual(@as(u8, client_hello), first.bytes[0]);
    // The same seed makes the same hello, and another seed another: the random and the key shares
    // are the stream's (non-negotiable 4).
    try testing.expectEqualSlices(u8, first.slice(), again.slice());
    try testing.expect(!std.mem.eql(u8, first.slice(), other.slice()));
}

test "the ticket a session would resume with is zeroed when it is wiped, or when its start fails" {
    // The copy holds the resumption secret (RFC 9846 §4.6.1), which nothing may keep past the
    // session it was for.
    var context: Context = .{ .session = .init(&.{}, @splat(0), 1, 1) };
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    var ticket = std.mem.zeroes(Session.Ticket);
    ticket.identity_len = 1;
    ticket.psk_len = tls.constants.sha256_len;
    @memset(&ticket.psk, 0x5a);
    ticket.lifetime_s = 1;
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
    var context: Context = .{ .session = .init(&.{}, @splat(0), 1, 1) };
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
