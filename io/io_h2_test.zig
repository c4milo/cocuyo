//! `cocuyo_h2`'s client against colibri's HTTP/2 server over the plain record provider, in memory
//! (docs/design.md §24, DoH over HTTP/2): the handshake on `h2` and a GET answered, what a response
//! says of its content, another protocol, a cancel, a GOAWAY, the idle close and a ticket. The
//! engine over the same client is `io/io_request_h2_test.zig`'s.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const h2 = @import("h2");
const doh = @import("doh");
const io_h2 = @import("io_h2.zig");
const server_module = @import("io_h2_server.zig");

/// Two answer buffers: a test's second request fits beside its first.
const test_answers = 2;
/// What a test's client says at most, and the rounds an exchange takes at most.
const said_max = 16;
const rounds_max = 64;
/// The octet of a DNS header that holds the QR bit, and the bit (RFC 1035 §4.1.1).
const flags_at = 2;
const qr_bit = 0x80;

const Client = io_h2.Connection(.{ .answers = test_answers });
const Server = server_module.Server;

/// The template a test's server is known by, split as the engine splits it.
const Template = struct { authority: []const u8, path: []const u8 };
const template: ?Template = .{ .authority = "dns.example", .path = "/dns-query{?dns}" };

/// A client and a server, placed outside any stack frame, and what the client said.
const Pair = struct {
    client: Client = .{},
    server: Server = .{},
    wire: [io_h2.constants.output_bytes_max]u8 = undefined,
    answer: [cocuyo.constants.message_bytes_max]u8 = undefined,
    said: [said_max]Client.Next = undefined,
    said_len: usize = 0,

    fn start(self: *Pair, script: server_module.Script, ticket: ?Client.Ticket) !void {
        self.* = .{};
        self.server.init(script);
        try self.client.start(.{ .https = template, .alpn = "h2", .ticket = ticket });
    }

    /// Carries what each side owes to the other, and reads what the client makes of it, until
    /// neither owes anything.
    fn exchange(self: *Pair) !void {
        for (0..rounds_max) |_| {
            var moved = false;
            const up = self.client.output(&self.wire, 0);
            if (up > 0) {
                self.server.receive(self.wire[0..up], echo);
                moved = true;
            }
            const down = self.server.send(&self.wire);
            if (down > 0) {
                try self.client.receive(self.wire[0..down], 0);
                moved = true;
            }
            while (self.client.next(&self.answer)) |said| {
                self.said[self.said_len] = said;
                self.said_len += 1;
            }
            if (!moved) return;
        }
        return error.NoEnd;
    }

    fn told(self: *const Pair, comptime tag: std.meta.Tag(Client.Next)) ?Client.Next {
        for (self.said[0..self.said_len]) |said| if (said == tag) return said;
        return null;
    }

    fn count(self: *const Pair, comptime tag: std.meta.Tag(Client.Next)) usize {
        var found: usize = 0;
        for (self.said[0..self.said_len]) |said| found += @intFromBool(said == tag);
        return found;
    }

    /// Whether the answer the client last gave is the echo of `test_query`, octet for octet.
    fn echoed(self: *const Pair, len: usize) bool {
        var expected = test_query;
        expected[flags_at] |= qr_bit;
        return len == expected.len and std.mem.eql(u8, &expected, self.answer[0..len]);
    }
};

threadlocal var pair: Pair = .{};

/// Answers a query with itself, its QR bit set, which is all a test reads of it.
const echo: server_module.Answerer = .{ .context = undefined, .answer = struct {
    fn answer(_: *anyopaque, query: []const u8, out: []u8) ?usize {
        @memcpy(out[0..query.len], query);
        out[flags_at] |= qr_bit;
        return query.len;
    }
}.answer };

/// A query of twelve octets, ID 0, as DoH asks (RFC 8484 §4.1).
threadlocal var test_query = [_]u8{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };

test "a GET goes out once the handshake ends on h2, and its response is answered whole" {
    try pair.start(.{}, null);
    try pair.exchange();
    try testing.expectEqualStrings("h2", pair.told(.up).?.up);
    const stream = (try pair.client.request(&test_query, test_query.len)).?;
    try pair.exchange();
    const answered = pair.told(.answered).?.answered;
    try testing.expectEqual(stream, answered.stream);
    try testing.expectEqual(test_query.len, answered.len);
    try testing.expectEqual(@as(u16, 200), answered.http.?.status);
    try testing.expect(answered.http.?.dns_message);
    try testing.expect(pair.echoed(answered.len));
}

/// A decoder that reads a GET's field block back, placed outside any stack frame.
threadlocal var decoder: h2.hpack.decoder.Decoder = undefined;

test "a GET carries its six lines, and only :path is never indexed" {
    // RFC 8484 §4.1's GET, with `accept-encoding: identity` (request rule 12), and RFC 7541
    // §6.2.3's representation on the line that carries the query (§7.1.3).
    try pair.start(.{}, null);
    try pair.exchange();
    const state = &pair.client.state;
    const before = state.outgoing_len;
    _ = (try pair.client.request(&test_query, test_query.len)).?;
    decoder.init(h2.constants.header_table_size_initial);
    var lines = decoder.block(state.outgoing[before + h2.constants.frame_header_len .. state.outgoing_len]);
    var variable: [cocuyo.wire.constants.dns_variable_bytes_max]u8 = undefined;
    var path: [doh.constants.doh_request_bytes_max]u8 = undefined;
    const expected_path = try std.fmt.bufPrint(&path, "/dns-query?dns={s}", .{cocuyo.wire.doh.dns_variable(&test_query, &variable)});
    const expected = [_]h2.hpack.decoder.FieldLine{
        .{ .name = ":method", .value = "GET", .never_indexed = false },
        .{ .name = ":scheme", .value = "https", .never_indexed = false },
        .{ .name = ":authority", .value = "dns.example", .never_indexed = false },
        .{ .name = ":path", .value = expected_path, .never_indexed = true },
        .{ .name = "accept", .value = "application/dns-message", .never_indexed = false },
        .{ .name = "accept-encoding", .value = "identity", .never_indexed = false },
    };
    for (expected) |line| {
        const read = (try lines.next()) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(line.name, read.name);
        try testing.expectEqualStrings(line.value, read.value);
        try testing.expectEqual(line.never_indexed, read.never_indexed);
    }
    try testing.expectEqual(@as(?h2.hpack.decoder.FieldLine, null), try lines.next());
}

test "a request made as the connection comes up goes after the connection preface" {
    // The engine opens its waiting requests the moment the connection is up, before anything is
    // sent (request rule 4); the preface goes first all the same (RFC 9113 §3.4).
    try pair.start(.{}, null);
    for (0..rounds_max) |_| {
        const up = pair.client.output(&pair.wire, 0);
        if (up > 0) pair.server.receive(pair.wire[0..up], echo);
        const down = pair.server.send(&pair.wire);
        if (down > 0) try pair.client.receive(pair.wire[0..down], 0);
        const said = pair.client.next(&pair.answer) orelse continue;
        if (said == .up) break;
    }
    _ = try pair.client.request(&test_query, test_query.len);
    try pair.exchange();
    try testing.expect(pair.told(.answered) != null);
}

test "a response says its status, its Age, and whether its content is an uncoded DNS message" {
    try pair.start(.{ .status = 404, .age = "30", .interim = true }, null);
    try pair.exchange();
    _ = try pair.client.request(&test_query, test_query.len);
    try pair.exchange();
    const http = pair.told(.answered).?.answered.http.?;
    try testing.expectEqual(@as(u16, 404), http.status);
    try testing.expectEqual(@as(u32, 30), http.age_seconds);
    try pair.start(.{ .content_encoding = "gzip" }, null);
    try pair.exchange();
    _ = try pair.client.request(&test_query, test_query.len);
    try pair.exchange();
    try testing.expect(!pair.told(.answered).?.answered.http.?.dns_message);
}

test "a server that negotiates another protocol leaves the client up on it, which the engine refuses" {
    try pair.start(.{ .other_protocol = true }, null);
    try pair.exchange();
    try testing.expectEqualStrings("http/1.1", pair.told(.up).?.up);
}

test "a cancelled request sends RST_STREAM, and its answer is told to nobody" {
    // The server holds the request, so its stream is open when the client cancels it.
    try pair.start(.{ .hold = true }, null);
    try pair.exchange();
    const stream = (try pair.client.request(&test_query, test_query.len)).?;
    pair.client.cancel(stream);
    try pair.exchange();
    try testing.expectEqual(@as(usize, 1), pair.server.cancels);
    try testing.expect(pair.told(.answered) == null);
    // Its answer buffer is free again: as many requests open as the connection has buffers.
    for (0..test_answers) |_| try testing.expect((try pair.client.request(&test_query, test_query.len)) != null);
}

test "a GOAWAY is told once, and a request above its last stream hears its stream reset" {
    try pair.start(.{ .goaway = true }, null);
    try pair.exchange();
    const first = (try pair.client.request(&test_query, test_query.len)).?;
    const second = (try pair.client.request(&test_query, test_query.len)).?;
    try pair.exchange();
    // The GOAWAY follows the answer in one record, and leaves its content as it was.
    const answered = pair.told(.answered).?.answered;
    try testing.expectEqual(first, answered.stream);
    try testing.expect(pair.echoed(answered.len));
    try testing.expect(pair.told(.goaway) != null);
    try testing.expectEqual(second, pair.told(.reset).?.reset);
    // No new stream opens on a connection that heard GOAWAY (RFC 9113 §6.8).
    try testing.expectEqual(@as(?u64, null), try pair.client.request(&test_query, test_query.len));
    // A second GOAWAY is not told: the connection drains once.
    pair.server.connection.shutdown(h2.constants.error_no_error);
    try pair.exchange();
    try testing.expectEqual(@as(usize, 1), pair.count(.goaway));
}

test "a connection whose stream identifiers run out opens no stream, and is told as a GOAWAY once" {
    // "A client that is unable to establish a new stream identifier can establish a new
    // connection for new streams" (RFC 9113 §5.1.1).
    try pair.start(.{}, null);
    try pair.exchange();
    pair.client.state.connection.streams.next_local_id = h2.constants.stream_id_max;
    const last = (try pair.client.request(&test_query, test_query.len)).?;
    try testing.expectEqual(@as(?u64, null), try pair.client.request(&test_query, test_query.len));
    try pair.exchange();
    try testing.expectEqual(last, pair.told(.answered).?.answered.stream);
    try testing.expectEqual(@as(usize, 1), pair.count(.goaway));
}

test "a template whose longest GET cannot fit is refused at the start" {
    pair = .{};
    const long: ?Template = .{ .authority = "dns.example", .path = "/" ++ "p" ** doh.constants.doh_request_bytes_max ++ "{?dns}" };
    try testing.expectError(error.Failed, pair.client.start(.{ .https = long, .alpn = "h2", .ticket = @as(?Client.Ticket, null) }));
}

/// One octet more than a connection keeps of the stream before it makes whole records.
threadlocal var overflow: [io_h2.constants.records_bytes + 1]u8 = undefined;

test "octets past what a connection keeps of the stream fail it" {
    // Request rule 7: a record longer than the buffer fails the connection.
    try pair.start(.{}, null);
    try testing.expectError(error.Failed, pair.client.receive(&overflow, 0));
}

test "a closing connection reads nothing more, not even an answer" {
    // Request rule 9: a closing connection has said its last.
    try pair.start(.{}, null);
    try pair.exchange();
    _ = try pair.client.request(&test_query, test_query.len);
    const up = pair.client.output(&pair.wire, 0);
    pair.server.receive(pair.wire[0..up], echo);
    pair.client.close();
    const down = pair.server.send(&pair.wire);
    try testing.expect(down > 0);
    try pair.client.receive(pair.wire[0..down], 0);
    try testing.expectEqual(@as(?Client.Next, null), pair.client.next(&pair.answer));
}

test "the server's close_notify ends the connection" {
    // RFC 9846 §6.1: `close_notify` says the sender will send nothing more (request rule 7).
    try pair.start(.{}, null);
    try pair.exchange();
    const len = try h2.connection_tls.close_notify(&pair.server.connection, &pair.wire);
    try pair.client.receive(pair.wire[0..len], 0);
    try testing.expect(pair.client.next(&pair.answer).? == .closed);
}

/// The plaintext of a record the server seals: PING frames, each a header and eight octets.
const ping_frame_bytes = h2.constants.frame_header_len + h2.constants.ping_len;
/// Three records of seven hundred PINGs: after two, the plaintext has no room for a third.
const pings_per_record = 700;
const ping_records = 3;
threadlocal var pings: [pings_per_record * ping_frame_bytes]u8 = undefined;

/// Seven hundred PING frames, each a header and eight octets.
fn fill_pings() !void {
    for (0..pings_per_record) |index| {
        _ = try h2.connection.frame_bytes(pings[index * ping_frame_bytes ..][0..ping_frame_bytes], h2.constants.frame_type_ping, 0, 0, &@as([h2.constants.ping_len]u8, @splat(0)));
    }
}

test "frames that owe more than colibri holds are all read, what they owe written aside between them" {
    // colibri holds four PING acknowledgements (colibri decision 39), and reads no frame while the
    // replies it owes have no room: each is written aside, and the next frame read.
    try pair.start(.{}, null);
    try pair.exchange();
    try fill_pings();
    const sealed = try h2.connection_tls.encrypt(&pair.server.connection, &pings, &pair.wire, 0);
    try pair.client.receive(pair.wire[0..sealed.written], 0);
    try testing.expectEqual(@as(?Client.Next, null), pair.client.next(&pair.answer));
    try testing.expectEqual(@as(usize, 0), pair.client.state.plaintext_len);
    // An acknowledgement is as long as its PING (RFC 9113 §6.7).
    try testing.expectEqual(pings.len, pair.client.state.outgoing_len);
}

test "whole frames colibri cannot read yet leave the next record waiting, and the connection up" {
    // colibri reads no frame while the replies it owes have no room (colibri decision 39): four
    // PINGs owe four acknowledgements, and the outgoing buffer, full, takes none of them. So the
    // PINGs after them stay in the plaintext, and a record that no longer fits beside them waits.
    try pair.start(.{}, null);
    try pair.exchange();
    try fill_pings();
    pair.client.state.outgoing_len = pair.client.state.outgoing.len;
    for (0..ping_records) |_| {
        const sealed = try h2.connection_tls.encrypt(&pair.server.connection, &pings, &pair.wire, 0);
        try testing.expectEqual(pings.len, sealed.consumed);
        try pair.client.receive(pair.wire[0..sealed.written], 0);
        try testing.expectEqual(@as(?Client.Next, null), pair.client.next(&pair.answer));
    }
    try testing.expect(pair.client.state.stage == .up);
    try testing.expect(pair.client.state.records_len > 0);
}

test "an idle close says GOAWAY, then close_notify" {
    try pair.start(.{}, null);
    try pair.exchange();
    pair.client.close();
    try pair.exchange();
    try testing.expect(pair.server.client_goaway and pair.server.client_closed);
}

test "a ticket the server gives is told, and a connection that offers one resumes" {
    try pair.start(.{ .tickets = true }, null);
    try pair.exchange();
    const ticket = pair.told(.ticket).?.ticket;
    try pair.start(.{ .tickets = true }, ticket);
    try pair.exchange();
    try testing.expect(pair.server.session.resumed);
}
