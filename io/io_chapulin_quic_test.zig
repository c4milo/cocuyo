//! The DoQ session's tests (`io_chapulin_quic.zig`, docs/design.md §24, chapulin under colibri):
//! the object's build record, and how chapulin is told to check a server known by a name, by pins,
//! or by both. Split out of `io_chapulin_quic.zig`.
const std = @import("std");
const cocuyo = @import("cocuyo");
const session_module = @import("io_chapulin_quic.zig");
const Session = session_module.Session;
const c = session_module.c;

const testing = std.testing;

test "the object linked is the one the headers describe" {
    try testing.expect(Session.built_as_read());
}

/// What the engine hands a session's start, for a server known as `server` is, then the transport
/// parameters colibri sets, where chapulin starts and checks its configuration.
fn start_for(server: *const cocuyo.Tls, context: anytype) !Session {
    var session: Session = .{};
    try session.start(.{
        .tls = server,
        .alpn = "doq",
        .ticket = @as(?Session.Ticket, null),
        .ticket_age_ns = 0,
        .context = context,
        .now_ns = 1,
    });
    errdefer session.wipe();
    // max_idle_timeout, of 30,000 milliseconds (RFC 9000 §18.2), which chapulin carries without
    // reading: its ID, its length, and its value as a two-octet varint.
    try session.provider().set_transport_params("\x01\x02\x75\x30");
    return session;
}

/// A context whose anchors are for the named servers, as an engine's is.
fn named_context() struct { session: Session.Context } {
    return .{ .session = .init(&anchors_test, @splat(0), 1, 1) };
}

/// One octet of DER, which chapulin keeps as an anchor's name and key without reading.
const anchor_octet = "\x30";
const anchors_test = [_]c.ch_trust_anchor{.{ .name = anchor_octet, .name_len = anchor_octet.len, .spki = anchor_octet, .spki_len = anchor_octet.len }};

test "a server known by pins alone starts chapulin with no anchors, though the context has some" {
    // chapulin refuses pins beside anchors with no hostname (its decision 64), so the anchors, for
    // named servers, are not this one's (RFC 8310 §6.3's "SPKI + IP").
    var context = named_context();
    const pin: cocuyo.Pin = @splat(0);
    var session = try start_for(&.{ .pins = &.{pin} }, &context);
    defer session.wipe();
    try testing.expectEqual(@as(usize, 0), session.config.anchor_count);
    try testing.expectEqual(@as(usize, 1), session.config.spki_pin_count);
}

test "a server known by a name and pins is checked by both" {
    // "both must pass" (RFC 8310 §6.4): the chain against the anchors and the name, a key on it
    // against the pins.
    var context = named_context();
    const pin: cocuyo.Pin = @splat(0);
    const name = try cocuyo.Name.from_text("dns.example.");
    var session = try start_for(&.{ .name = name, .pins = &.{pin} }, &context);
    defer session.wipe();
    try testing.expectEqual(anchors_test.len, session.config.anchor_count);
    try testing.expectEqual(@as(usize, 1), session.config.spki_pin_count);
    try testing.expectEqualStrings("dns.example", session.config.hostname[0..session.config.hostname_len]);
}

test "a server known by a name with no anchor to check it against is refused by chapulin" {
    var context: struct { session: Session.Context } = .{ .session = .init(&.{}, @splat(0), 1, 1) };
    const name = try cocuyo.Name.from_text("dns.example.");
    try testing.expectError(error.TlsFailed, start_for(&.{ .name = name }, &context));
}
