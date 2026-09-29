//! `cocuyo_doh` against colibri's server over QUIC in memory (docs/design.md §24, DoH over colibri's
//! client): a query over HTTP/3, its answer and `Age`, a QUIC ticket, and a second channel whose
//! QUIC link resumes with it. The test plays the engine, as `io_doh_channel_test.zig`'s does: a
//! link's connection starts as soon as the channel asks for it, and the channel is read after each
//! datagram. No TCP server listens, so a TCP link the channel asks for fails at once.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const server = @import("server");
const cocuyo_doh = @import("io_doh_channel.zig");
const identity = @import("io_doh_channel_identity.zig");
const tcp_server = @import("io_doh_channel_server.zig");
const quic_server = @import("io_doh_channel_server_quic.zig");
const constants = cocuyo_doh.constants;

const Doh = cocuyo_doh.Channel(.{});
const Event = Doh.Event;
const Tag = std.meta.Tag(Event);

/// A millisecond a round, and rounds enough for a handshake and an exchange and a close.
const round_ns = 1_000_000;
const rounds_max = 2_000;
const said_max = 64;
/// The octet of a DNS header that holds the QR bit, and the bit (RFC 1035 §4.1.1).
const flags_at = 2;
const qr_bit = 0x80;
/// The octet the context's stream is seeded with. Test-only.
const seed_octet = 9;
/// The client's port, as the server sees the datagrams come from it. Test-only.
const client_port = 50_000;

const port = 8443;
const endpoint: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_text("192.0.2.1").?, .port = port };
const client_address = cocuyo.Address.from_text("192.0.2.9").?;
const template = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = "/dns-query{?dns}" };
const anchors = [_]@TypeOf(identity.anchor){identity.anchor};
/// A query of a header alone, ID 0, as DoH asks (RFC 8484 §4.1): the server echoes it.
const query = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

fn echo(context: *anyopaque, asked: []const u8, out: []u8) ?usize {
    _ = context;
    @memcpy(out[0..asked.len], asked);
    out[flags_at] |= qr_bit;
    return asked.len;
}

/// The type, colibri's server over QUIC, and what the type said, on the heap.
const Pair = struct {
    doh: Doh = .{},
    context: Doh.Context = .{},
    server: quic_server.QuicServer = .{},
    wire: [Doh.output_bytes_max]u8 = undefined,
    said: [said_max]Event = undefined,
    said_len: usize = 0,
    now_ns: u64 = round_ns,
    endpoint: cocuyo.Endpoint = endpoint,
    ticket: ?Doh.Ticket = null,
    offer: ?Doh.Ticket = null,
    carried: bool = false,

    fn create(script: tcp_server.Script) !*Pair {
        const pair = try testing.allocator.create(Pair);
        errdefer testing.allocator.destroy(pair);
        pair.* = .{};
        pair.context = .init(&anchors, @splat(seed_octet), identity.unix_seconds, pair.now_ns);
        try pair.open(script);
        return pair;
    }

    fn free(pair: *Pair) void {
        pair.doh.wipe();
        testing.allocator.destroy(pair);
    }

    fn open(pair: *Pair, script: tcp_server.Script) !void {
        try pair.server.init(script, identity.unix_seconds, pair.now_ns);
        const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
        try pair.doh.start(.{
            .server = 0,
            .endpoint = pair.endpoint,
            .tls = &named,
            .https = template,
            .alternative = null,
            .context = &pair.context,
            .now_ns = pair.now_ns,
        });
        pair.said_len = 0;
    }

    /// Reads what the channel says and carries its datagrams both ways, a round at a time, until
    /// the channel says `until`. A round moves the clock a millisecond, or to the next instant
    /// either side wants when nothing moved.
    fn run(pair: *Pair, until: Tag) !Event {
        for (0..rounds_max) |_| {
            if (try pair.hear(until)) |event| return event;
            const moved = pair.carried;
            pair.carried = false;
            if (try pair.carry(until)) |event| return event;
            pair.advance(moved);
        }
        return error.NotSaid;
    }

    /// Moves the clock a millisecond, or to the next instant either side wants when nothing moved
    /// this round or the one before, and fires what is due.
    fn advance(pair: *Pair, moved: bool) void {
        pair.now_ns += round_ns;
        if (!moved and !pair.carried) {
            if (pair.soonest()) |due| pair.now_ns = @max(pair.now_ns, due);
        }
        if (pair.doh.deadline()) |due| {
            if (due <= pair.now_ns) pair.doh.expire(pair.now_ns);
        }
        if (pair.server.deadline()) |due| {
            if (due <= pair.now_ns) pair.server.expire(pair.now_ns);
        }
    }

    fn soonest(pair: *Pair) ?u64 {
        const channel = pair.doh.deadline();
        const peer = pair.server.deadline();
        if (channel == null) return peer;
        if (peer == null) return channel;
        return @min(channel.?, peer.?);
    }

    fn hear(pair: *Pair, until: Tag) !?Event {
        for (0..said_max) |_| {
            const event = pair.doh.next(pair.now_ns) orelse return null;
            if (pair.said_len == pair.said.len) return error.TooMuchSaid;
            pair.said[pair.said_len] = event;
            pair.said_len += 1;
            switch (event) {
                .open => |asked| try pair.start_link(asked.link),
                .ticket => |link| pair.ticket = pair.doh.take_ticket(link),
                else => {},
            }
            if (event == until) return event;
        }
        return error.TooMuchSaid;
    }

    /// A QUIC link starts at once, offering the ticket kept, a second old; no TCP server listens,
    /// so a TCP link's socket ends at once.
    fn start_link(pair: *Pair, link: Doh.Link) !void {
        if (link == .tcp) return pair.doh.link_ended(.tcp);
        const offered: ?*const Doh.Ticket = if (pair.offer != null) &pair.offer.? else null;
        try pair.doh.start_link(link, offered, if (offered != null) std.time.ns_per_s else 0, pair.now_ns);
    }

    /// The channel's datagrams go to the server, and the server's come back, the channel read after
    /// each.
    fn carry(pair: *Pair, until: Tag) !?Event {
        const from = server.quic_connection.PeerAddress.of(client_address.slice(), client_port);
        for (0..said_max) |_| {
            const up = pair.doh.datagram(&pair.wire, pair.now_ns);
            if (up == 0) break;
            pair.carried = true;
            pair.server.receive(pair.wire[0..up], from, .{ .context = pair, .answer = echo }, pair.now_ns);
        }
        for (0..said_max) |_| {
            const down = pair.server.send(&pair.wire, pair.now_ns) orelse break;
            pair.carried = true;
            pair.doh.receive(.{ .datagram = down }, pair.now_ns);
            if (try pair.hear(until)) |event| return event;
        }
        return null;
    }

    fn count(pair: *const Pair, tag: Tag) usize {
        var counted: usize = 0;
        for (pair.said[0..pair.said_len]) |event| counted += @intFromBool(event == tag);
        return counted;
    }
};

test "a query goes over HTTP/3 to colibri's server over QUIC, and the next channel's QUIC link resumes" {
    // Rule 18: QUIC first, and no TCP when its handshake ends in time; rule 23: the ticket QUIC's
    // connection gave is spent by the next QUIC link (RFC 9846 §4.6.1).
    const pair = try Pair.create(.{ .age = "5", .tickets = true });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    var answer = query;
    answer[flags_at] |= qr_bit;
    try testing.expectEqualSlices(u8, &answer, finished.answer.?.message);
    try testing.expectEqual(@as(u32, 5), finished.answer.?.age_seconds);
    const first = pair.doh.connected().?;
    try testing.expectEqual(.h3, first.protocol);
    try testing.expect(!first.offered and !first.resumed);
    try testing.expectEqual(@as(usize, 1), pair.count(.open));
    try testing.expectEqualSlices(u8, &query, pair.server.query[0..pair.server.query_len]);
    if (pair.count(.ticket) == 0) _ = try pair.run(.ticket);
    try testing.expect(pair.ticket != null);
    pair.doh.shutdown();
    _ = try pair.run(.closed);
    pair.doh.wipe();
    pair.offer = pair.ticket;
    try pair.open(.{ .tickets = true });
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    try testing.expect((try pair.run(.finished)).finished.answer != null);
    const second = pair.doh.connected().?;
    try testing.expectEqual(.h3, second.protocol);
    try testing.expect(second.offered and second.resumed);
}
