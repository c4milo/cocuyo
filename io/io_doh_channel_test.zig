//! `cocuyo_doh` against colibri's server in memory (docs/design.md §24, DoH over colibri's client):
//! a query over HTTP/2 when QUIC's datagrams go nowhere, and over HTTP/1.1 from a server that
//! selects it or selects nothing; the responses that fail a request; a request past the answer
//! buffers, and one cancelled; a ticket, and a link that resumes with it; stream octets past what
//! the type keeps; and a template too long. The test plays the engine: a link's connection starts
//! as soon as the channel asks for it, and the stream goes over in the engine's chunks, the channel
//! read after each. The engine over the type, on the twin, is `io_doh_channel_engine_test.zig`'s.
//! `io_doh_channel_read_test.zig` drives the same pair with whole records back to back.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const cocuyo_doh = @import("io_doh_channel.zig");
const identity = @import("io_doh_channel_identity.zig");
const server_module = @import("io_doh_channel_server.zig");
pub const constants = cocuyo_doh.constants;
const doh_constants = @import("doh").constants;
const tls = @import("tls");

/// Two answer buffers: a test's second request fits beside its first, and a third waits.
const test_answers = 2;
pub const Doh = cocuyo_doh.Channel(.{ .answers = test_answers });
pub const Event = Doh.Event;
pub const Answerer = server_module.Answerer;
pub const Versions = @FieldType(server_module.Script, "versions");
/// The wall clock a test's server starts at, inside the test identity's validity.
pub const identity_seconds = identity.unix_seconds;
const Tag = std.meta.Tag(Event);

/// A millisecond a round, and rounds enough for the fallback delay and a handshake after it.
pub const round_ns = 1_000_000;
pub const rounds_max = 1_000;
const said_max = 64;
/// The octet of a DNS header that holds the QR bit, and the bit (RFC 1035 §4.1.1).
pub const flags_at = 2;
pub const qr_bit = 0x80;

/// The server's address, and its template as the engine splits it, on a port of its own, so a link
/// that went to HTTPS's 443 anyway shows.
const port = 8443;
const endpoint: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_text("192.0.2.1").?, .port = port };
const template = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = "/dns-query{?dns}" };
/// A query of a header alone, ID 0, as DoH asks (RFC 8484 §4.1), recursion desired: the server
/// echoes it, so it need not ask anything.
pub const query = [_]u8{ 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
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
pub const Pair = struct {
    doh: Doh = .{},
    /// A test's context, built where the pair is, at the pair's first instant: no pair holds one
    /// that nobody named.
    context: Doh.Context = identity.test_context(seed_octet, round_ns),
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

    pub fn create(script: server_module.Script) !*Pair {
        return create_with(script, identity.cpu_not_stated);
    }

    /// As `create`, with a context that states `cpu` of the CPU (docs/design.md §16 decision 48).
    pub fn create_with(script: server_module.Script, cpu: tls.Cpu) !*Pair {
        const pair = try testing.allocator.create(Pair);
        errdefer testing.allocator.destroy(pair);
        pair.* = .{ .context = identity.test_context_with(cpu, seed_octet, round_ns) };
        try pair.open(script);
        return pair;
    }

    pub fn free(pair: *Pair) void {
        pair.doh.wipe();
        testing.allocator.destroy(pair);
    }

    /// A new channel, and a new connection of the server's for it.
    pub fn open(pair: *Pair, script: server_module.Script) !void {
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

    /// Reads what the channel says and carries what each side owes the other, a round at a time,
    /// until the channel says `until`. A round moves the clock a millisecond, or to the channel's
    /// next instant when nothing moved, as the engine's timer would.
    pub fn run(pair: *Pair, until: Tag) !Event {
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
            try pair.note(event);
            if (event == until) return event;
        }
        return error.TooMuchSaid;
    }

    /// Keeps one thing the channel said, and does what the engine does with it.
    pub fn note(pair: *Pair, event: Event) !void {
        if (pair.said_len == pair.said.len) return error.TooMuchSaid;
        pair.said[pair.said_len] = event;
        pair.said_len += 1;
        switch (event) {
            .open => |asked| try pair.start_link(asked.link),
            .ticket => |link| pair.ticket = pair.doh.take_ticket(link),
            else => {},
        }
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
        const answerer: server_module.Answerer = .{ .context = pair, .answer = echo };
        const up = pair.doh.output(&pair.wire, pair.now_ns);
        if (up > 0) pair.server.receive(pair.wire[0..up], answerer, pair.now_ns);
        const down = pair.server.send(&pair.wire, answerer, pair.now_ns);
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
    pub fn count(pair: *const Pair, tag: Tag) usize {
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
    try testing.expectEqual(server_module.http_2, pair.server.version.?);
    const connected = pair.doh.connected().?;
    try testing.expectEqual(.h2, connected.protocol);
    try testing.expect(!connected.offered and !connected.resumed);
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
    const request = &pair.doh.exchanges[0].request;
    try testing.expect(request.never_indexed.path);
    try testing.expectEqualStrings("GET", request.method);
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

test "a datagram of exactly what the type keeps is kept, and stream octets of exactly what it keeps are kept" {
    // doh_datagram_bytes and doh_stream_bytes, each at its value: one octet more of either is the
    // test above and the overrun test below.
    const pair = try Pair.create(.{});
    defer pair.free();
    const datagram: [constants.datagram_bytes]u8 = @splat(1);
    pair.doh.receive(.{ .datagram = &datagram }, pair.now_ns);
    try testing.expectEqual(datagram.len, pair.doh.inbound_len);
    const stream: [constants.stream_bytes]u8 = @splat(0);
    pair.doh.receive(.{ .stream = &stream }, pair.now_ns);
    try testing.expectEqual(stream.len, pair.doh.stream_len);
    try testing.expect(!pair.doh.stream_overrun);
}

test "a server that selects HTTP/1.1, or selects no protocol, answers over HTTP/1.1" {
    // colibri speaks HTTP/1.1 when the server selects it or selects nothing (its decision 88).
    const scripts = [_]server_module.Script{ .{ .versions = .{ .h2 = false } }, .{ .selects_none = true } };
    for (scripts) |script| {
        const pair = try Pair.create(script);
        defer pair.free();
        try testing.expect(pair.doh.request(1, &query, pair.now_ns));
        const finished = (try pair.run(.finished)).finished;
        try testing.expectEqual(@as(u16, 1), finished.index);
        try testing.expectEqualSlices(u8, &expected_answer(), finished.answer.?.message);
        try testing.expectEqual(server_module.http_1_1, pair.server.version.?);
        try testing.expectEqual(.h11, pair.doh.connected().?.protocol);
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

test "a status of 299, the last 2xx, is an answer, and 300 is none" {
    // "A successful HTTP response with a 2xx status code" carries the answer (RFC 8484 §4.2.1).
    for ([_]u16{ constants.status_success_last, constants.status_success_last + 1 }) |status| {
        const pair = try Pair.create(.{ .status = status });
        defer pair.free();
        try testing.expect(pair.doh.request(0, &query, pair.now_ns));
        const finished = (try pair.run(.finished)).finished;
        try testing.expectEqual(status == constants.status_success_last, finished.answer != null);
    }
}

test "field values that fill the buffer to its last octet are read, and one octet more is too large" {
    // The server sends one field the type wants, `content-type`, so its value alone fills the
    // buffer (doh_values_bytes, rule 22).
    const media = "application/dns-message; x=";
    const filled = media ++ "y" ** (constants.values_bytes - media.len);
    for ([_][]const u8{ filled, filled ++ "y" }) |content_type| {
        const pair = try Pair.create(.{ .content_type = content_type });
        defer pair.free();
        try testing.expect(pair.doh.request(0, &query, pair.now_ns));
        const finished = (try pair.run(.finished)).finished;
        try testing.expectEqual(content_type.len == constants.values_bytes, finished.answer != null);
    }
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
    try testing.expectEqual(.too_large, pair.doh.exchanges[0].response.outcome);
}

test "a stream the server resets after a 2xx head fails its request" {
    // Rule 22: only a whole response carries an answer, whatever its head said.
    const pair = try Pair.create(.{ .reset_after_head = true });
    defer pair.free();
    try testing.expect(pair.doh.request(0, &query, pair.now_ns));
    const finished = (try pair.run(.finished)).finished;
    try testing.expectEqual(@as(?Doh.Answer, null), finished.answer);
    try testing.expectEqual(.reset, pair.doh.exchanges[0].response.outcome);
    try testing.expectEqual(@as(u16, 200), pair.doh.exchanges[0].response.status);
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
    // Rule 23, and RFC 9846 §4.7.1: the server gives a ticket after the handshake.
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
    try testing.expect(pair.server.endpoint.tcp[0].tls_server.resumed());
    const connected = pair.doh.connected().?;
    try testing.expect(connected.offered and connected.resumed);
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

test "a template whose GET path at its longest fills the path buffer starts, and its longest GET is answered; one octet more is refused" {
    // At `start` the template is expanded with a `dns` value `dns_variable_bytes_max` long, and a
    // path past `doh_request_bytes_max` is refused (docs/design.md §24). Here the path at its
    // longest is a slash, `?x=`, the filler, `&dns=` and the value: 1536 octets. The authority is
    // the longest, a name of 253 octets and a port, and the query is the longest a `dns` value of
    // 512 octets carries, 384 octets in base64url (RFC 4648 §5).
    const query_part = "?x=";
    const value_part = "&dns=";
    const filler = doh_constants.doh_request_bytes_max - 1 - query_part.len - value_part.len - cocuyo.wire.constants.dns_variable_bytes_max;
    const longest = query_part ++ "p" ** filler ++ "{&dns}";
    const host = ("h" ** 63 ++ ".") ** 3 ++ "h" ** 61;
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    pair.* = .{ .endpoint = endpoint };
    try pair.server.init(.{}, identity.unix_seconds, pair.now_ns);
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
    const fits_slot = .{ .authority = host ++ ":8443", .host = host, .port = port, .path = longest };
    try pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = fits_slot, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns });
    var longest_query: [cocuyo.wire.constants.dns_variable_bytes_max / 4 * 3]u8 = @splat(0);
    @memcpy(longest_query[0..query.len], &query);
    try testing.expect(pair.doh.request(0, &longest_query, pair.now_ns));
    const answer = (try pair.run(.finished)).finished.answer orelse return error.TestUnexpectedResult;
    try testing.expectEqual(longest_query.len, answer.message.len);
    pair.doh.wipe();
    const over = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = query_part ++ "p" ** (filler + 1) ++ "{&dns}" };
    try testing.expectError(error.Failed, pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = over, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns }));
}

test "a template whose path starts with a slash and fills the path buffer starts, and its longest GET is answered; one octet more is refused" {
    // The slash is the template's own, so the expansion has the whole buffer: a slash, the
    // filler, `?dns=` and a value of 512 octets make 1536 (docs/design.md §24, §17 question 42).
    const value_part = "?dns=";
    const filler = doh_constants.doh_request_bytes_max - 1 - value_part.len - cocuyo.wire.constants.dns_variable_bytes_max;
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    pair.* = .{ .endpoint = endpoint };
    try pair.server.init(.{}, identity.unix_seconds, pair.now_ns);
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(identity.server_name) };
    const fills = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = "/" ++ "p" ** filler ++ "{?dns}" };
    try pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = fills, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns });
    // The longest query a `dns` value of 512 octets carries goes out on that path, and colibri's
    // server answers it.
    var longest_query: [cocuyo.wire.constants.dns_variable_bytes_max / 4 * 3]u8 = @splat(0);
    @memcpy(longest_query[0..query.len], &query);
    try testing.expect(pair.doh.request(0, &longest_query, pair.now_ns));
    const answer = (try pair.run(.finished)).finished.answer orelse return error.TestUnexpectedResult;
    try testing.expectEqual(longest_query.len, answer.message.len);
    pair.doh.wipe();
    const over = .{ .authority = "dns.example:8443", .host = "dns.example", .port = port, .path = "/" ++ "p" ** (filler + 1) ++ "{?dns}" };
    try testing.expectError(error.Failed, pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = over, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns }));
}
