//! The reason `cocuyo_doh` gives an exchange that ends while no connection of its channel is up,
//! against colibri's server in memory (docs/design.md §5, The cause of a failure; §16 decision
//! 51). colibri ends such an exchange as refused once each connection that its channel tried has
//! failed. The cases:
//!
//! - a name that the certificate does not carry, and a pin that the chain does not hold;
//! - links that end before they connect;
//! - a request made while the TCP handshake runs;
//! - a request made after the connection that came up is over;
//! - a request made while a connection is up, which knows that it is.
//!
//! The pair is `io_doh_channel_test.zig`'s, and the case over QUIC is
//! `io_doh_channel_quic_test.zig`'s.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const identity = @import("io_doh_channel_identity.zig");
const channel_test = @import("io_doh_channel_test.zig");
const Pair = channel_test.Pair;
const Doh = channel_test.Doh;

/// A pin no key of the test's identity hashes to. Test-only.
const pin_octet: u8 = 0x11;

/// A pair whose channel knows the server by `known`, and whose links end at once when `refused`.
fn create(known: *const cocuyo.Tls, refused: bool) !*Pair {
    const pair = try testing.allocator.create(Pair);
    errdefer testing.allocator.destroy(pair);
    pair.* = .{ .refuses_links = refused };
    try pair.server.init(.{}, identity.unix_seconds, pair.now_ns);
    try pair.doh.start(.{
        .server = 0,
        .endpoint = pair.endpoint,
        .tls = known,
        .https = channel_test.template,
        .alternative = null,
        .context = &pair.context,
        .now_ns = pair.now_ns,
    });
    return pair;
}

test "a name the certificate does not carry ends the exchange as a handshake" {
    // The TCP link connected, so a server took part, and its handshake was refused (RFC 9110
    // §4.3.4). QUIC's datagrams went nowhere, and no connection came up.
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("other.example") };
    const pair = try create(&named, false);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &channel_test.query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(Doh.Result{ .failed = .handshake }, finished.result);
    try testing.expectEqual(.refused, pair.doh.exchanges[0].response.result);
    try testing.expectEqual(@as(?Doh.Connected, null), pair.doh.connected());
}

test "a pin that the chain does not hold ends the exchange as a handshake" {
    // A server known by its pin alone, whose leaf key hashes to another (RFC 7858 §4.2).
    const pins = [_]cocuyo.Pin{@splat(pin_octet)};
    const pinned: cocuyo.Tls = .{ .pins = &pins };
    const pair = try create(&pinned, false);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &channel_test.query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(Doh.Result{ .failed = .handshake }, finished.result);
}

test "links whose sockets end before they connect end the exchange as a connect" {
    // No server took part: neither link connected, and no QUIC datagram came.
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
    const pair = try create(&named, true);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &channel_test.query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(Doh.Result{ .failed = .connect }, finished.result);
    try testing.expectEqual(.refused, pair.doh.exchanges[0].response.result);
}

test "a request made while the TCP handshake runs ends as a handshake too" {
    // The second exchange starts after the TCP link connected, so it learns that a server took
    // part from the channel and not from an event of its own.
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("other.example") };
    const pair = try create(&named, false);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &channel_test.query, pair.now_ns));
    for (0..channel_test.rounds_max) |_| {
        if (pair.count(.open) == 2) break;
        _ = try pair.run(.open);
    }
    try testing.expectEqual(@as(usize, 2), pair.count(.open));
    try testing.expect(pair.doh.request(1, &channel_test.query, pair.now_ns));
    for ([_]u16{ 0, 1 }) |_| {
        const finished = (try pair.run(.finished)).finished;
        try testing.expectEqual(Doh.Result{ .failed = .handshake }, finished.result);
    }
}

test "a request after the connection that came up is over starts as if none came up" {
    // The first request is answered over HTTP/2. Its TCP link then ends, and each link after it
    // ends before it connects, so no connection comes up for the second request.
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
    const pair = try create(&named, false);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &channel_test.query, pair.now_ns));
    try testing.expect((try pair.run(.finished)).finished.result == .answer);
    pair.doh.link_ended(.tcp);
    pair.refuses_links = true;
    try testing.expect(pair.doh.request(1, &channel_test.query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(u16, 1), finished.index);
    try testing.expectEqual(Doh.Result{ .failed = .connect }, finished.result);
}

test "a request made while a connection is up is answered over it" {
    // The second request starts on the connection that came up for the first, so it knows that
    // connection is up without an event of its own.
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
    const pair = try create(&named, false);
    defer pair.free();
    try testing.expect(pair.doh.request(0, &channel_test.query, pair.now_ns));
    try testing.expect((try pair.run(.finished)).finished.result == .answer);
    try testing.expect(pair.doh.up != null);
    try testing.expect(pair.doh.request(1, &channel_test.query, pair.now_ns));
    try testing.expect(pair.doh.exchanges[0].up);
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(u16, 1), finished.index);
    try testing.expect(finished.result == .answer);
}
