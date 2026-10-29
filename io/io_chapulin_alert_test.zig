//! The DoT session's alert once up (`io_chapulin.zig`, docs/design.md §16 decision 62): a session
//! completes a handshake with colibri's record server under the test identity of `testdata/`,
//! then stages the alert the engine names, and the server reads it. The session and the server
//! hand each other their records in memory, so the test needs no network. Split out of
//! `io_chapulin_test.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
// The engine's constants, through the engine's module: a file belongs to one module.
const constants = @import("io").constants;
const tls = @import("tls");
const Session = @import("io_chapulin.zig").Session;

const testing = std.testing;

/// The identity the DoH tests run colibri's server under (`io_doh_channel_identity.zig` says how
/// it was made): a leaf for `dns.example` and the CA that signed it, valid from 2026 to 2126.
const chain = [_][]const u8{@embedFile("testdata/identity.leaf.der")};
const public_key: *const [tls.constants.p256_public_key_len]u8 = @embedFile("testdata/identity.pub");
const private_key: *const [tls.constants.p256_private_key_len]u8 = @embedFile("testdata/identity.priv");
const anchors = [_]tls.Anchor{.{ .subject = @embedFile("testdata/identity.name"), .spki = @embedFile("testdata/identity.spki") }};
/// An instant inside the identity's validity, 2026-06-01T00:00:00Z.
const unix_seconds: u64 = 1_780_272_000;

/// What the test states of the CPU: nothing (docs/design.md §16 decision 48).
const cpu_not_stated: Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known }, .timing = .not_stated };
/// RFC 9846 §4.3.2's cookie key, and the octets each side's stream is seeded with. Test-only values.
const cookie_octet: u8 = 0x5e;
const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_octet);
const client_seed_octet: u8 = 0x36;
const server_seed_octet: u8 = 0x35;
/// The outer content type of every protected record, application_data (RFC 9846 §5.2).
const content_application: u8 = 23;
/// The flights of a full handshake: the client's two and the server's two (RFC 9846 §2).
const flights_max: usize = 4;

/// The records one side wrote and the other has not read.
const Flight = struct {
    octets: [Session.out_bytes_max]u8 = undefined,
    len: usize = 0,
};

/// Each side, which is too large for a test's stack.
const Sides = struct {
    session: Session = .{},
    context: Session.Context = undefined,
    config: tls.record.ServerConfig = undefined,
    server: tls.record.Server = undefined,
    server_stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(server_seed_octet)),
    to_server: Flight = .{},
    to_client: Flight = .{},
};

/// Hands each whole record of the server's flight to the session, one at a time, as the engine
/// does (TLS rule 7). True once the session's handshake is done.
fn client_reads(sides: *Sides) !bool {
    var at: usize = 0;
    var done = false;
    // Bounded: each pass takes a record of one octet at least.
    for (0..sides.to_client.len) |_| {
        if (at == sides.to_client.len) break;
        const header = constants.tls_record_header_bytes;
        const body = std.mem.readInt(u16, sides.to_client.octets[at + constants.tls_record_length_at ..][0..@sizeOf(u16)], .big);
        const step = try sides.session.handshake(sides.to_client.octets[at..][0 .. header + body]);
        done = step == .done;
        at += header + body;
    }
    sides.to_client.len = 0;
    return done;
}

/// Runs the handshake until both sides have completed it.
fn shake(sides: *Sides) !void {
    var done = false;
    // Bounded: a full handshake takes two flights each way.
    for (0..flights_max) |_| {
        sides.to_server.len = sides.session.take_out(&sides.to_server.octets);
        if (sides.to_server.len > 0) {
            const progress = try sides.server.handshake(sides.to_server.octets[0..sides.to_server.len], &sides.to_client.octets);
            assert(progress.consumed == sides.to_server.len);
            sides.to_client.len = progress.written;
            if (progress.complete and done) return;
        }
        if (sides.to_client.len > 0) done = try client_reads(sides);
    }
    return error.HandshakeIncomplete;
}

test "a session that is up stages the record_overflow alert the engine names, which the server reads" {
    // "An endpoint that receives a record from its peer with TLSCiphertext.length larger than
    // 2^14 + 256 octets MUST terminate the connection with a "record_overflow" alert" (RFC 9846
    // §5.2). chapulin seals the alert under the session's keys, and the session fails.
    const sides = try testing.allocator.create(Sides);
    defer testing.allocator.destroy(sides);
    sides.* = .{};
    sides.context = .init(&anchors, cpu_not_stated, @splat(client_seed_octet), unix_seconds, 0);
    try sides.config.init(.{ .ecdsa_p256 = .{ .chain = &chain, .public_key = public_key, .private_key = private_key }, .cookie_key = &cookie_key, .cpu = cpu_not_stated });
    try sides.server.start(&sides.config, sides.server_stream.random(), unix_seconds);
    defer sides.server.close();
    const server: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text("dns.example.") };
    try sides.session.start(.{ .tls = &server, .ticket = @as(?Session.Ticket, null), .ticket_age_ns = @as(u64, 0), .context = &sides.context, .now_ns = @as(u64, 0) });
    defer sides.session.wipe();
    try shake(sides);

    sides.session.stage_alert(.record_overflow);
    try testing.expect(!sides.session.live);
    const alert_len = sides.session.take_out(&sides.to_server.octets);
    // A protected record: its outer type is application_data (RFC 9846 §5.2).
    try testing.expect(alert_len > constants.tls_record_header_bytes);
    try testing.expectEqual(content_application, sides.to_server.octets[0]);
    const records = sides.server.provider();
    var plaintext: [Session.out_bytes_max]u8 = undefined;
    try testing.expectError(error.TlsFailed, records.vtable.decrypt_record(records.context, sides.to_server.octets[0..alert_len], &plaintext));
    const report = records.vtable.take_alert(records.context).?;
    try testing.expectEqual(Session.Alert.record_overflow, report.description);
    try testing.expectEqual(.peer, report.origin);
}
