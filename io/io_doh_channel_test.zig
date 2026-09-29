//! `cocuyo_doh` against colibri's server in memory (docs/design.md §24, DoH over colibri's client):
//! a query over HTTP/2 when QUIC's datagrams go nowhere, and over HTTP/1.1 from a server that
//! selects it or selects nothing; the responses that fail a request; a request past the answer
//! buffers, and one cancelled; a ticket, and a link that resumes with it; stream octets past what
//! the type keeps; and a template too long. The test plays the engine: a link's connection starts
//! as soon as the channel asks for it, and the stream goes over in the engine's chunks, the channel
//! read after each. The engine over the type, on the twin, is `io_doh_channel_engine_test.zig`'s.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const cocuyo_doh = @import("io_doh_channel.zig");
const identity = @import("io_doh_channel_identity.zig");
const server_module = @import("io_doh_channel_server.zig");
const constants = cocuyo_doh.constants;

/// Two answer buffers: a test's second request fits beside its first, and a third waits.
const test_answers = 2;
const Doh = cocuyo_doh.Channel(.{ .answers = test_answers });
const Event = Doh.Event;
const Tag = std.meta.Tag(Event);

/// A millisecond a round, and rounds enough for the fallback delay and a handshake after it.
const round_ns = 1_000_000;
const rounds_max = 1_000;
const said_max = 64;
/// The octet of a DNS header that holds the QR bit, and the bit (RFC 1035 §4.1.1).
const flags_at = 2;
const qr_bit = 0x80;

/// The server's address, and its template as the engine splits it, on a port of its own, so a link
/// that went to HTTPS's 443 anyway shows.
const port = 8443;
const endpoint: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_text("192.0.2.1").?, .port = port };
const template = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = "/dns-query{?dns}" };
const anchors = [_]@TypeOf(identity.anchor){identity.anchor};
/// A query of a header alone, ID 0, as DoH asks (RFC 8484 §4.1), recursion desired: the server
/// echoes it, so it need not ask anything.
const query = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
/// The octet the context's stream is seeded with. Test-only.
const seed_octet = 7;

/// Answers a query with the query itself, the QR bit set.
fn echo(context: *anyopaque, asked: []const u8, out: []u8) ?usize {
    _ = context;
    @memcpy(out[0..asked.len], asked);
    out[flags_at] |= qr_bit;
    return asked.len;
}

/// The type, colibri's server, and what the type said, on the heap: a channel is over a megabyte.
const Pair = struct {
    doh: Doh = .{},
    context: Doh.Context = .{},
    server: server_module.Server = .{},
    wire: [Doh.output_bytes_max]u8 = undefined,
    said: [said_max]Event = undefined,
    said_len: usize = 0,
    now_ns: u64 = round_ns,
    /// The ticket the last `ticket` event handed over, and the one the next TCP link offers.
    ticket: ?Doh.Ticket = null,
    offer: ?Doh.Ticket = null,
    /// Where the server is, held at run time, as the engine's configuration holds it.
    endpoint: cocuyo.Endpoint = endpoint,
    /// Whether the last round carried octets either way over TCP.
    carried: bool = false,

    fn create(script: server_module.Script) !*Pair {
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

    /// A new channel, and a new connection of the server's for it.
    fn open(pair: *Pair, script: server_module.Script) !void {
        try pair.server.init(script, identity.unix_seconds);
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

    /// Reads what the channel says and carries what each side owes the other, a round at a time,
    /// until the channel says `until`. A round moves the clock a millisecond, or to the channel's
    /// next instant when nothing moved, as the engine's timer would.
    fn run(pair: *Pair, until: Tag) !Event {
        for (0..rounds_max) |_| {
            if (try pair.hear(until)) |event| return event;
            const moved = pair.carried;
            pair.carried = false;
            if (try pair.carry(until)) |event| return event;
            pair.now_ns += round_ns;
            const due = pair.doh.deadline() orelse continue;
            if (!moved and !pair.carried) pair.now_ns = @max(pair.now_ns, due);
            if (due <= pair.now_ns) pair.doh.expire(pair.now_ns);
        }
        return error.NotSaid;
    }

    /// Reads the channel until it says nothing more, doing what the engine does with each thing it
    /// says, and returns `until` once it is said.
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

    /// A link's socket carries octets at once in memory: its connection starts, TCP's with the
    /// ticket offered, a second old.
    fn start_link(pair: *Pair, link: Doh.Link) !void {
        const offered: ?*const Doh.Ticket = if (link == .tcp and pair.offer != null) &pair.offer.? else null;
        try pair.doh.start_link(link, offered, if (offered != null) std.time.ns_per_s else 0, pair.now_ns);
    }

    /// QUIC's datagrams go nowhere, since no server listens for them. What the TCP link owes goes
    /// to the server, and what the server owes comes back in the engine's chunks, the channel read
    /// after each.
    fn carry(pair: *Pair, until: Tag) !?Event {
        _ = pair.doh.datagram(&pair.wire, pair.now_ns);
        const up = pair.doh.output(&pair.wire, pair.now_ns);
        if (up > 0) pair.server.receive(pair.wire[0..up], .{ .context = pair, .answer = echo }, pair.now_ns);
        const down = pair.server.send(&pair.wire, pair.now_ns);
        pair.carried = pair.carried or up > 0 or down > 0;
        var at: usize = 0;
        while (at < down) : (at += constants.engine_chunk_bytes) {
            const end = @min(down, at + constants.engine_chunk_bytes);
            pair.doh.receive(.{ .stream = pair.wire[at..end] }, pair.now_ns);
            if (try pair.hear(until)) |event| return event;
        }
        return null;
    }

    /// Whether the channel said `tag`, and how many times.
    fn count(pair: *const Pair, tag: Tag) usize {
        var counted: usize = 0;
        for (pair.said[0..pair.said_len]) |event| counted += @intFromBool(event == tag);
        return counted;
    }
};

/// What a query's answer is: the query, the QR bit set.
fn expected_answer() [query.len]u8 {
    var answer = query;
    answer[flags_at] |= qr_bit;
    return answer;
}

test "a query goes over HTTP/2 once QUIC's datagrams have gone nowhere for the fallback delay, and its answer comes back with its Age" {
    const pair = try Pair.create(.{ .age = "7" });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(u16, 0), finished.index);
    try testing.expectEqualSlices(u8, &expected_answer(), finished.answer.?.message);
    try testing.expectEqual(@as(u32, 7), finished.answer.?.age_seconds);
    // RFC 8484 §4.1: the GET carried the query in `dns`.
    try testing.expectEqualSlices(u8, &query, pair.server.query[0..pair.server.query_len]);
    try testing.expectEqual(.h2, pair.server.connection.protocol().?);
    // QUIC first, and TCP once its handshake had run the fallback delay (rule 18).
    try testing.expectEqual(Doh.Link.quic, pair.said[0].open.link);
    try testing.expectEqual(endpoint.port, pair.said[0].open.endpoint.port);
    try testing.expect(pair.said[0].open.endpoint.address.equal(&endpoint.address));
    try testing.expectEqual(Doh.Link.tcp, pair.said[1].open.link);
    try testing.expect(pair.now_ns >= constants.fallback_delay_ns);
}

test "the GET asks for a DNS message in no content coding, and its path goes into no table" {
    // RFC 8484 §4.1 and request rule 12: the path carries the query, which a table that indexed it
    // would let be probed (RFC 7541 §7.1.3, RFC 9204 §7.1.3).
    const pair = try Pair.create(.{});
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    const exchange = &pair.doh.exchanges[0].exchange;
    try testing.expect(exchange.never_indexed.path);
    try testing.expectEqualStrings("GET", exchange.method);
    _ = try pair.run(.finished);
    try testing.expectEqualStrings("application/dns-message", pair.server.accept.text());
    try testing.expectEqualStrings("identity", pair.server.accept_encoding.text());
}

test "a datagram longer than the type keeps is dropped, and one the channel has not taken gives way to the next" {
    // As the network may drop a datagram, so may the type (docs/design.md §24, the interface).
    const pair = try Pair.create(.{});
    defer pair.free();
    var long: [constants.datagram_bytes + 1]u8 = @splat(1);
    pair.doh.receive(.{ .datagram = &long }, pair.now_ns);
    try testing.expectEqual(@as(usize, 0), pair.doh.inbound_len);
    pair.doh.receive(.{ .datagram = "first" }, pair.now_ns);
    pair.doh.receive(.{ .datagram = "second" }, pair.now_ns);
    try testing.expectEqualStrings("second", pair.doh.inbound[0..pair.doh.inbound_len]);
}

test "a server that selects HTTP/1.1, or selects no protocol, answers over HTTP/1.1" {
    const selections = [_][]const []const u8{ &.{"http/1.1"}, &.{} };
    for (selections) |alpn| {
        const pair = try Pair.create(.{ .alpn = alpn });
        defer pair.free();
        try testing.expect(pair.doh.request(1, &query, pair.now_ns));
        const finished = (try pair.run(.finished)).finished;
        try testing.expectEqual(@as(u16, 1), finished.index);
        try testing.expectEqualSlices(u8, &expected_answer(), finished.answer.?.message);
        try testing.expectEqual(.h11, pair.server.connection.protocol().?);
    }
}

test "a response that is not a 2xx, not a DNS message, or coded fails its request" {
    // RFC 8484 §4.2.1 and request rule 12: none of them is an answer.
    const scripts = [_]server_module.Script{
        .{ .status = 404 },
        .{ .content_type = "text/html" },
        .{ .content_encoding = "gzip" },
    };
    for (scripts) |script| {
        const pair = try Pair.create(script);
        defer pair.free();
        try testing.expect(pair.doh.request(0, &query, pair.now_ns));
        const finished = (try pair.run(.finished)).finished;
        try testing.expectEqual(@as(?Doh.Answer, null), finished.answer);
    }
    // An identity coding is no coding (RFC 9110 §8.4.1).
    const pair = try Pair.create(.{ .content_encoding = "identity" });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    try testing.expect((try pair.run(.finished)).finished.answer != null);
}

test "a 2xx response whose field values do not fit fails its request as too large" {
    // doh_values_bytes: the values the type wants are copied into its buffer, and a response whose
    // values do not fit ends as too large, which is no answer (rule 22).
    const long_type = "application/dns-message; x=" ++ "y" ** constants.values_bytes;
    const pair = try Pair.create(.{ .content_type = long_type });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(?Doh.Answer, null), finished.answer);
    try testing.expectEqual(.too_large, pair.doh.exchanges[0].exchange.outcome);
}

test "a stream the server resets after a 2xx head fails its request" {
    // Rule 22: only a whole response carries an answer, whatever its head said.
    const pair = try Pair.create(.{ .reset_after_head = true });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(?Doh.Answer, null), finished.answer);
    try testing.expectEqual(.reset, pair.doh.exchanges[0].exchange.outcome);
    try testing.expectEqual(@as(u16, 200), pair.doh.exchanges[0].exchange.status);
}

test "a request past the answer buffers waits, and one cancelled frees its buffer and tells nothing" {
    // Rule 21 and request rule 6.
    const pair = try Pair.create(.{});
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    try testing.expect(pair.doh.request(1, &query, pair.now_ns));
    try testing.expect(!pair.doh.request(2, &query, pair.now_ns));
    pair.doh.cancel(0);
    try testing.expect(pair.doh.request(2, &query, pair.now_ns));
    _ = try pair.run(.finished);
    _ = try pair.run(.finished);
    var indexes: [2]u16 = undefined;
    var found: usize = 0;
    for (pair.said[0..pair.said_len]) |event| {
        if (event != .finished) continue;
        indexes[found] = event.finished.index;
        found += 1;
    }
    try testing.expectEqual(@as(usize, 2), found);
    try testing.expect(indexes[0] != 0 and indexes[1] != 0);
    try testing.expectEqual(@as(usize, 2), pair.server.answered);
    // Both ended, so both buffers are free again.
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    try testing.expect(pair.doh.request(3, &query, pair.now_ns));
}

test "a ticket the server gives is taken, and the next channel's TCP link resumes with it" {
    // Rule 23, and RFC 9846 §4.6.1: the server gives a ticket after the handshake.
    const pair = try Pair.create(.{ .tickets = true });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    _ = try pair.run(.finished);
    if (pair.count(.ticket) == 0) _ = try pair.run(.ticket);
    try testing.expect(pair.ticket != null);
    pair.doh.shutdown();
    _ = try pair.run(.closed);
    pair.doh.wipe();
    pair.offer = pair.ticket;
    try pair.open(.{ .tickets = true });
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    try testing.expect((try pair.run(.finished)).finished.answer != null);
    try testing.expect(pair.server.connection.tls_server.resumed());
    // The copy the link resumed with is zeroed once its connection has ended.
    pair.doh.shutdown();
    _ = try pair.run(.closed);
    const resumed = &pair.doh.resuming[@intFromEnum(Doh.Link.tcp)];
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(resumed), 0));
}

test "wiping a channel ends each connection it holds, whose session colibri wipes" {
    const pair = try Pair.create(.{});
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    _ = try pair.run(.finished);
    try testing.expect(!pair.doh.channel.tcp.stopped);
    pair.doh.wipe();
    try testing.expect(pair.doh.channel.tcp.stopped);
}

test "stream octets past what the type keeps end the TCP link, which the channel is told of" {
    // Request rule 7: octets past the buffer fail the link's connection.
    const pair = try Pair.create(.{ .hold = true });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    for (0..rounds_max) |_| {
        if (pair.server.held > 0) break;
        _ = try pair.hear(.closed);
        _ = try pair.carry(.closed);
        pair.now_ns += round_ns;
    }
    try testing.expectEqual(@as(usize, 1), pair.server.held);
    var junk: [constants.stream_bytes + 1]u8 = @splat(0);
    pair.doh.receive(.{ .stream = &junk }, pair.now_ns);
    try testing.expectEqual(Event{ .close = .tcp }, pair.doh.next(pair.now_ns).?);
    // colibri was told the link ended, so the exchange it carried ends as a failure.
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(?Doh.Answer, null), finished.answer);
}

test "a template whose GET would not fit is refused when the channel starts" {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    pair.* = .{};
    const long_path = "/" ++ "p" ** 1400 ++ "{?dns}";
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
    const long = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = long_path };
    try testing.expectError(error.Failed, pair.doh.start(.{
        .server = 0,
        .endpoint = pair.endpoint,
        .tls = &named,
        .https = long,
        .alternative = null,
        .context = &pair.context,
        .now_ns = pair.now_ns,
    }));
}
