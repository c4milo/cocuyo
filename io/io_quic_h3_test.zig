//! colibri's HTTP/3 client under the interface against colibri's HTTP/3 server, in memory (docs/
//! design.md §24, DoH over HTTP/3): the GET, the response as the server wrote it, the answer
//! buffers, a GOAWAY and a template too long. Split out of `io_quic_h3.zig`.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("io_quic_constants.zig");
const io_quic = @import("io_quic.zig");
const server_h3 = @import("io_quic_server_h3.zig");

const Writer = h3.core.Writer;

/// A client that speaks HTTP/3 and the test server, carried to each other in memory a datagram at
/// a time each way, on a clock that moves a millisecond a round, until neither has anything to send.
const Pair = struct {
    const Client = io_quic.Connection(.{ .streams = test_streams, .http3 = true, .answers = test_answers });
    const Server = server_h3.Server(test_streams);
    const Target = struct { authority: []const u8, path: []const u8 };
    const test_streams = 4;
    const test_answers = 2;
    const round_ns = 1_000_000;
    const rounds_max = 64;

    client: Client = .{},
    server: Server = .{},
    context: Client.Context = .{},
    now_ns: u64 = 1,

    fn start(pair: *Pair, path: []const u8) !void {
        try pair.client.start(.{
            .tls = @as(?*const cocuyo.Tls, null),
            .https = @as(?Target, .{ .authority = "dns.example", .path = path }),
            .alpn = "h3",
            .ticket = @as(?Client.Ticket, null),
            .ticket_age_ns = 0,
            .context = &pair.context,
            .now_ns = pair.now_ns,
        });
    }

    fn exchange(pair: *Pair, answerer: server_h3.Answerer) !void {
        var datagram: [quic.constants.datagram_len_min]u8 = undefined;
        var rounds: usize = 0;
        while (rounds < rounds_max) : (rounds += 1) {
            const out = pair.client.datagram(&datagram, pair.now_ns);
            if (out > 0) pair.server.receive(datagram[0..out], pair.now_ns, answerer);
            const back = pair.server.send(&datagram, pair.now_ns);
            if (back > 0) try pair.client.receive(datagram[0..back], pair.now_ns);
            if (out == 0 and back == 0) return;
            pair.now_ns += round_ns;
        }
        return error.NoQuiet;
    }

    /// Starts and handshakes, and reads the protocol the handshake ended on.
    fn up(pair: *Pair, echo: *Echo, out: []u8) ![]const u8 {
        try pair.start("/dns-query{?dns}");
        try pair.exchange(echo.answerer());
        return pair.client.next(out).?.up;
    }
};

/// Answers a query with the query itself.
const Echo = struct {
    fn answerer(echo: *Echo) server_h3.Answerer {
        return .{ .context = echo, .answer = answer };
    }

    fn answer(context: *anyopaque, query: []const u8, out: []u8) ?usize {
        _ = context;
        @memcpy(out[0..query.len], query);
        return query.len;
    }
};

/// A query of a header and a question for "a." as cocuyo builds one over DoH: ID 0 (RFC 8484 §4.1).
const query_test = [_]u8{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1 };

test "a GET over colibri's h3 carries the query in dns, and its response comes back whole" {
    var pair: Pair = .{};
    var echo: Echo = .{};
    var out: [constants.answer_bytes_max]u8 = undefined;
    try testing.expectEqualStrings("h3", try pair.up(&echo, &out));
    var query = query_test;
    const stream = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    const answered = pair.client.next(&out).?.answered;
    try testing.expectEqual(stream, answered.stream);
    try testing.expectEqualSlices(u8, &query_test, out[0..answered.len]);
    try testing.expectEqual(@as(u16, 200), answered.http.?.status);
    try testing.expect(answered.http.?.dns_message);
    try testing.expectEqual(@as(u32, 0), answered.http.?.age_seconds);
    try testing.expectEqual(@as(usize, 1), pair.server.answered);
    // The client's control stream carried its SETTINGS: "Each side MUST initiate a single control
    // stream at the beginning of the connection and send its SETTINGS frame as the first frame on
    // this stream" (RFC 9114 §6.2.1).
    try testing.expect(pair.server.h3.peer_settings != null);
}

test "a response's status, Age and coding reach the engine as the server wrote them" {
    var pair: Pair = .{};
    pair.server.script.status = "404";
    pair.server.script.age = "250";
    pair.server.script.content_encoding = "gzip";
    pair.server.script.interim = true;
    var echo: Echo = .{};
    var out: [constants.answer_bytes_max]u8 = undefined;
    _ = try pair.up(&echo, &out);
    var query = query_test;
    _ = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    const http = pair.client.next(&out).?.answered.http.?;
    // The interim response went first, and said nothing (RFC 9114 §4.1).
    try testing.expectEqual(@as(u16, 404), http.status);
    try testing.expectEqual(@as(u32, 250), http.age_seconds);
    try testing.expect(!http.dns_message);
}

test "a request waits for an answer buffer, and a cancelled one gives its buffer back" {
    var pair: Pair = .{};
    var echo: Echo = .{};
    var out: [constants.answer_bytes_max]u8 = undefined;
    _ = try pair.up(&echo, &out);
    var query = query_test;
    const first = (try pair.client.request(&query, query.len)).?;
    _ = (try pair.client.request(&query, query.len)).?;
    // Both of the connection's buffers are taken.
    try testing.expectEqual(@as(?u64, null), try pair.client.request(&query, query.len));
    pair.client.cancel(first);
    _ = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    var answered: usize = 0;
    while (pair.client.next(&out)) |said| {
        if (said == .answered) answered += 1;
    }
    try testing.expectEqual(@as(usize, 2), answered);
}

test "a GOAWAY is told once, beside the answer it came with, and closes nothing itself" {
    // The engine drains the connection (request rule 13): the transport says the GOAWAY came.
    var pair: Pair = .{};
    pair.server.script.goaway = true;
    var echo: Echo = .{};
    var out: [constants.answer_bytes_max]u8 = undefined;
    _ = try pair.up(&echo, &out);
    var query = query_test;
    _ = (try pair.client.request(&query, query.len)).?;
    try pair.exchange(echo.answerer());
    var goaways: usize = 0;
    var answered: usize = 0;
    while (pair.client.next(&out)) |said| switch (said) {
        .goaway => goaways += 1,
        .answered => answered += 1,
        else => return error.Unexpected,
    };
    try testing.expectEqual(@as(usize, 1), goaways);
    try testing.expectEqual(@as(usize, 1), answered);
}

test "after a GOAWAY, a request the server will not process is reset, and none opens" {
    // colibri's server names the first stream it has not taken, which a test cannot leave one of
    // ours past: the GOAWAY is set here as if it had named stream 0 (RFC 9114 §5.2).
    var pair: Pair = .{};
    var echo: Echo = .{};
    var out: [constants.answer_bytes_max]u8 = undefined;
    _ = try pair.up(&echo, &out);
    var query = query_test;
    const stream = (try pair.client.request(&query, query.len)).?;
    pair.client.h3.goaway = stream;
    try testing.expectEqual(stream, pair.client.next(&out).?.reset);
    try testing.expectEqual(@as(?u64, null), try pair.client.request(&query, query.len));
    try testing.expectEqual(@as(?Pair.Client.Next, null), pair.client.next(&out));
}

/// One line of a GET read back, and whether it carried QPACK's N bit (RFC 9204 §4.5.4).
const LineRead = struct { name: []const u8, value: []const u8, never_indexed: bool };

/// Reads back the field line `representation` holds, its name and value from the static table
/// when it names an entry there (RFC 9204 Appendix A). A GET references no dynamic entry.
fn line_of(representation: h3.qpack.representation.Representation) LineRead {
    const entries = &h3.qpack.static_table.entries;
    return switch (representation) {
        .indexed => |line| .{ .name = entries[line.index].name, .value = entries[line.index].value, .never_indexed = false },
        .literal_name_reference => |line| .{ .name = entries[line.name_index].name, .value = line.value, .never_indexed = line.never_indexed },
        .literal => |line| .{ .name = line.name, .value = line.value, .never_indexed = line.never_indexed },
        .indexed_post_base, .literal_post_base_name_reference => unreachable,
    };
}

test "a GET carries the six lines of design §24, and only :path is never indexed" {
    // RFC 8484 §4.1's GET, with `accept-encoding: identity` (request rule 12), and RFC 9204
    // §4.5.4's N bit on the line that carries the query (§7.1.3).
    var pair: Pair = .{};
    var echo: Echo = .{};
    var out: [constants.answer_bytes_max]u8 = undefined;
    _ = try pair.up(&echo, &out);
    var query = query_test;
    const stream = (try pair.client.request(&query, query.len)).?;
    const slot = for (&pair.client.streams.slots) |*slot| {
        if (slot.live and slot.id == stream) break slot;
    } else return error.NoSlot;
    var reader = h3.core.Reader.init(slot.bytes[0..slot.len]);
    // The HEADERS frame's type and length, then the section's prefix (RFC 9114 §7.1, RFC 9204
    // §4.5.1).
    _ = try h3.wire.varint.decode(&reader);
    _ = try h3.wire.varint.decode(&reader);
    _ = try h3.qpack.representation.read_prefix(&reader);
    var strings: [constants.doh_request_bytes_max]u8 = undefined;
    var writer = Writer.init(&strings);
    var variable: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = undefined;
    var path: [constants.doh_request_bytes_max]u8 = undefined;
    const expected_path = try std.fmt.bufPrint(&path, "/dns-query?dns={s}", .{cocuyo.wire.doh.dns_variable(&query_test, &variable)});
    const expected = [_]LineRead{
        .{ .name = ":method", .value = "GET", .never_indexed = false },
        .{ .name = ":scheme", .value = "https", .never_indexed = false },
        .{ .name = ":authority", .value = "dns.example", .never_indexed = false },
        .{ .name = ":path", .value = expected_path, .never_indexed = true },
        .{ .name = "accept", .value = "application/dns-message", .never_indexed = false },
        .{ .name = "accept-encoding", .value = "identity", .never_indexed = false },
    };
    for (expected) |line| {
        const read = line_of(try h3.qpack.representation.read(&reader, &writer));
        try testing.expectEqualStrings(line.name, read.name);
        try testing.expectEqualStrings(line.value, read.value);
        try testing.expectEqual(line.never_indexed, read.never_indexed);
    }
    try testing.expectEqual(@as(usize, 0), reader.remaining_len());
}


test "a template whose GET cannot fit a request's slot is refused at the start" {
    var pair: Pair = .{};
    const long_path = "/" ++ "p" ** 1000 ++ "{?dns}";
    try testing.expectError(error.Failed, pair.start(long_path));
}
