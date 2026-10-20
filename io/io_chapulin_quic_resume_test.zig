//! The DoQ session resumed on QUIC version 2 (docs/design.md §16 decision 29, §24 chapulin under
//! colibri, §17 question 57). A server of colibri's QUIC over chapulin's session runs in memory
//! under cocuyo's test identity (`testdata/`). It selects `doq`, issues a ticket, and switches a
//! client that lists version 2 to it, as colibri's own server does (its decision 111). The client
//! is `cocuyo_quic`'s connection over this module's session. Its first connection runs on version
//! 2, so the ticket names version 2. The next connection resumes with that ticket, and starts in
//! version 2. Split out of `io_chapulin_quic_test.zig`.
const std = @import("std");
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const tls = @import("tls");
const cocuyo_quic = @import("cocuyo_quic");
const session_module = @import("io_chapulin_quic.zig");

const testing = std.testing;
const Session = session_module.Session;
const Version = quic.crypto.suite.Version;
const constants = cocuyo_quic.constants;

/// The client: one stream, which the test never opens.
const Client = cocuyo_quic.Connection(.{ .Session = Session, .streams = 1 });
const streams = 1;

/// The test identity, as `cocuyo_doh`'s tests read it (`io_doh_channel_identity.zig`, which is
/// another module's file): the leaf for `dns.example`, its key, and the CA a client trusts.
const chain = [_][]const u8{@embedFile("testdata/identity.leaf.der")};
const public_key: *const [tls.constants.p256_public_key_len]u8 = @embedFile("testdata/identity.pub");
const private_key: *const [tls.constants.p256_private_key_len]u8 = @embedFile("testdata/identity.priv");
const anchors = [_]tls.Anchor{.{ .subject = @embedFile("testdata/identity.name"), .spki = @embedFile("testdata/identity.spki") }};
const server_name = "dns.example.";
/// 2026-06-01T00:00:00Z, inside the identity's validity.
const unix_seconds: u64 = 1_780_272_000;

/// RFC 9846 §4.3.2's cookie key and the key the server seals its tickets under, each of one octet
/// repeated, and the octets of the three streams: the server's, the client's session, and the
/// client's connection IDs. Test-only values.
const cookie_octet = 0x5d;
const ticket_octet = 0x7f;
const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_octet);
const ticket_key: [tls.constants.server_key_len]u8 = @splat(ticket_octet);
const server_seed_octet = 0x36;
const session_seed_octet = 0x09;
const ids_seed_octet = 0x0a;

/// The protocol the server selects (RFC 9250 §4.1).
const alpn = [_][]const u8{"doq"};
/// The longest connection ID a long header names (RFC 9000 §17.2).
const id_bytes_max = quic.crypto.constants.connection_id_len_max;
/// A millisecond a round, and rounds enough for a handshake and its ticket.
const round_ns = 1_000_000;
const rounds_max = 64;
/// Where a long header carries its Version field: after its first octet (RFC 9000 §17.2).
const version_at = 1;

/// A server of one connection over chapulin's QUIC session, which answers nothing on a stream.
const Server = struct {
    config: tls.quic.ServerConfig = undefined,
    session: tls.quic.Server = undefined,
    connection: quic.Connection = undefined,
    pool: quic.stream.stream_incoming.Pool(constants.server_receive_bytes) = undefined,
    send_scratch: quic.connection_send.DefaultScratch = undefined,
    scratch: quic.connection_datagram.Scratch = undefined,
    inbound: [constants.datagram_receive_bytes]u8 = undefined,
    source: [constants.connection_id_bytes]u8 = @splat(constants.server_id_octet),
    original: [id_bytes_max]u8 = undefined,
    original_len: usize = 0,
    peer: [id_bytes_max]u8 = undefined,
    peer_len: usize = 0,
    stream: std.Random.ChaCha = std.Random.ChaCha.init(@splat(server_seed_octet)),
    started: bool = false,

    fn init(server: *Server) !void {
        server.* = .{};
        try server.config.init(.{
            .ecdsa_p256 = .{ .chain = &chain, .public_key = public_key, .private_key = private_key },
            .cookie_key = &cookie_key,
            .ticket_key = &ticket_key,
            .alpn = &alpn,
            .cpu = session_module.cpu_not_stated,
        });
    }

    /// One datagram of the client's. The first, an Initial, starts the connection in its version.
    fn receive(server: *Server, bytes: []const u8, now_ns: u64) !void {
        @memcpy(server.inbound[0..bytes.len], bytes);
        if (!server.started) try server.start(bytes, now_ns);
        _ = try quic.connection_datagram.receive(
            &server.connection,
            server.session.suite(),
            server.session.provider(),
            .{ .octets = server.inbound[0..bytes.len], .now_ns = now_ns, .ecn = .not_ect },
            &server.scratch,
        );
    }

    /// As colibri's server starts a connection: the transport, the session in the version of the
    /// client's first Initial, the chooser that switches it to version 2, then the parameters and
    /// the Initial keys (RFC 9001 §5.2, §8.2).
    fn start(server: *Server, bytes: []const u8, now_ns: u64) !void {
        const long = switch (try quic.packet.header.read(bytes, constants.connection_id_bytes)) {
            .long => |held| held,
            else => return error.NoInitial,
        };
        @memcpy(server.original[0..long.dcid.len], long.dcid);
        server.original_len = long.dcid.len;
        @memcpy(server.peer[0..long.scid.len], long.scid);
        server.peer_len = long.scid.len;
        server.connection.init(.{
            .role = .server,
            .version = long.version,
            .local_parameters = cocuyo_quic.server.parameters(streams),
            .now_ns = now_ns,
            .identity = .{
                .local_initial_source = &server.source,
                .original_destination = server.original[0..server.original_len],
                .peer_initial_source = server.peer[0..server.peer_len],
            },
            .receive = server.pool.storage(),
        });
        server.send_scratch = .{};
        server.session.start(&server.config, server.stream.random(), unix_seconds, long.version);
        server.session.set_version_chooser(quic.connection_version.chooser(&server.connection));
        var body: [constants.params_bytes_max]u8 = undefined;
        var writer = quic.core.Writer.init(&body);
        try quic.transport_parameters.write(&writer, &server.connection.local_parameters, .server);
        try server.session.provider().set_transport_params(writer.written());
        const suite = server.session.suite();
        try suite.vtable.install_initial_keys(suite.context, .server, server.original[0..server.original_len]);
        server.started = true;
    }

    fn send(server: *Server, out: []u8, now_ns: u64) !usize {
        const provider: quic.stream.StreamProvider = .{ .context = server, .vtable = &no_streams };
        const sent = try quic.connection_send.send(&server.connection, server.session.suite(), server.session.provider(), provider, &server.send_scratch, out, now_ns);
        return if (sent) |made| made.len else 0;
    }

    fn close(server: *Server) void {
        if (server.started) server.session.close();
    }
};

/// The server writes on no stream.
const no_streams: quic.stream.stream_provider.VTable = .{ .read = read_none };

fn read_none(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    _ = offset;
    _ = output;
    return 0;
}

/// A client and the context it starts from, on the heap: chapulin keeps pointers into both.
const Side = struct {
    client: Client = .{},
    context: Client.Context = undefined,

    fn start(side: *Side, ticket: ?Session.Ticket, now_ns: u64) !void {
        side.* = .{};
        side.context = .{
            .session = .init(&anchors, @splat(session_seed_octet), unix_seconds, now_ns),
            .stream = std.Random.ChaCha.init(@splat(ids_seed_octet)),
        };
        const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(server_name) };
        try side.client.start(.{ .tls = &named, .alpn = "doq", .ticket = ticket, .ticket_age_ns = @as(u64, 0), .context = &side.context, .now_ns = now_ns });
    }
};

/// Carries datagrams both ways, a millisecond a round, until neither side sends.
fn exchange(client: *Client, server: *Server, now_ns: *u64) !void {
    var datagram: [quic.constants.datagram_len_min]u8 = undefined;
    for (0..rounds_max) |_| {
        const out = client.output(&datagram, now_ns.*);
        if (out > 0) try server.receive(datagram[0..out], now_ns.*);
        const back = try server.send(&datagram, now_ns.*);
        if (back > 0) try client.receive(datagram[0..back], now_ns.*);
        if (out == 0 and back == 0) return;
        now_ns.* += round_ns;
    }
    return error.NoQuiet;
}

/// What the client said after a handshake: that it is up on `doq`, and the ticket it was given.
fn ticket_after_up(client: *Client) !Session.Ticket {
    var out: [constants.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("doq", client.next(&out).?.up);
    return client.next(&out).?.ticket;
}

test "a session that resumes with a ticket of QUIC version 2 starts its connection in version 2" {
    // colibri v0.8.0's server switches a client that lists version 2 (its decision 111), and the
    // ticket of that connection names version 2. The session that resumes with it starts in
    // version 2, so its connection must too: colibri seals each packet in the connection's
    // version, and chapulin's suite asserts that its own is the same.
    const server = try testing.allocator.create(Server);
    defer testing.allocator.destroy(server);
    const side = try testing.allocator.create(Side);
    defer testing.allocator.destroy(side);
    var now_ns: u64 = round_ns;
    try server.init();
    try side.start(null, now_ns);
    try testing.expectEqual(Version.v1, side.client.session.original_version());
    try exchange(&side.client, server, &now_ns);
    var ticket = try ticket_after_up(&side.client);
    defer ticket.wipe();
    try testing.expectEqual(Version.v2, side.client.connection.versions.negotiated);
    try testing.expectEqual(@intFromEnum(Version.v2), ticket.quic_version);
    side.client.wipe();
    server.close();
    // The next connection resumes: its first Initial names version 2, and the server takes the
    // ticket.
    try server.init();
    try side.start(ticket, now_ns);
    defer side.client.wipe();
    defer server.close();
    try testing.expectEqual(Version.v2, side.client.session.original_version());
    var datagram: [quic.constants.datagram_len_min]u8 = undefined;
    const first = side.client.output(&datagram, now_ns);
    try testing.expect(first > version_at + @sizeOf(u32));
    try testing.expectEqual(@intFromEnum(Version.v2), std.mem.readInt(u32, datagram[version_at..][0..@sizeOf(u32)], .big));
    try server.receive(datagram[0..first], now_ns);
    try exchange(&side.client, server, &now_ns);
    var out: [constants.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("doq", side.client.next(&out).?.up);
    try testing.expect(side.client.session.resumed());
    try testing.expect(server.session.resumed());
}
