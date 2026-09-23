//! Building a query: the header, one question, and an OPT record unless EDNS0 is off
//! (RFC 1035 §4.1, RFC 6891 §6.1.1).
//!
//! A query is rebuilt on every send rather than stored, and it is byte-identical each time,
//! because everything that varies — the transaction id and the case pattern of the name — is held
//! by the lookup (docs/design.md §16 decision 3). That is what lets one send buffer serve a whole
//! table of lookups.
//!
//! A query that goes encrypted is padded to a whole block with the Padding option (RFC 8467
//! §4.1, RFC 7830 §3), so its length says less about the name in it (docs/design.md §21).
//!
//! EDNS0 can be turned off for one lookup. A server that answers FORMERR to a query carrying OPT
//! is old enough that the retry without it is the only way to reach it (RFC 6891 §6.2.2), and
//! `Query.payload_bytes` being null is how the state machine says so.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Name = core.Name;
const Kind = core.Kind;
const constants = @import("constants.zig");
const header_codec = @import("header.zig");
const question_codec = @import("question.zig");
const edns = @import("edns.zig");

pub const Query = struct {
    /// The transaction id, drawn from the lookup's generator (docs/design.md §7).
    id: u16,
    /// The name as it will be asked, case and all.
    name: Name,
    kind: Kind,
    /// The UDP payload size to advertise, or null to send no OPT record at all.
    payload_bytes: ?u16 = core.constants.udp_payload_bytes_default,
    /// Whether to write the two-octet length prefix a TCP stream needs (RFC 7766 §8).
    tcp: bool = false,
    /// The COOKIE option to carry in the OPT record (RFC 7873 §5.1), which needs `payload_bytes`.
    cookie: ?edns.Cookie = null,
    /// The RD bit (RFC 1035 §4.1.1): a stub asks a recursive server to do the walking, unless
    /// the caller wants the server's own data alone.
    recursion_desired: bool = true,
    /// Whether to pad the message to a multiple of `padding_block_bytes`, which is for a query
    /// that goes encrypted (RFC 7830 §6). A query without OPT cannot carry the option, and goes
    /// unpadded.
    padded: bool = false,
};

/// The octets a query occupies.
pub fn query_bytes(query: *const Query) usize {
    var total: usize = core.constants.header_bytes + question_codec.section_bytes(&query.name);
    if (query.payload_bytes != null) total += edns.record_bytes_padded(cookie_of(query), padding_bytes(query));
    if (query.tcp) total += core.constants.tcp_prefix_bytes;
    assert(total <= core.constants.query_bytes_max);
    return total;
}

fn cookie_of(query: *const Query) ?*const edns.Cookie {
    return if (query.cookie) |*cookie| cookie else null;
}

/// The octets of padding the query's Padding option carries, or null when it carries none.
fn padding_bytes(query: *const Query) ?usize {
    if (!query.padded or query.payload_bytes == null) return null;
    const unpadded = core.constants.header_bytes + question_codec.section_bytes(&query.name) +
        edns.record_bytes(cookie_of(query)) + core.constants.opt_option_header_bytes;
    // "Clients SHOULD pad queries to the closest multiple of 128 octets" (RFC 8467 §4.1).
    const padded = std.mem.alignForward(usize, unpadded, core.constants.padding_block_bytes);
    assert(padded - unpadded < core.constants.padding_block_bytes);
    return padded - unpadded;
}

/// Writes `query` into `out` and returns the octets written. `out` must hold
/// `constants.query_bytes_max`, which is the largest query there is, so one buffer fits every
/// query a caller will ever send.
pub fn write(query: *const Query, out: []u8) usize {
    assert(query.kind.queryable());
    assert(out.len >= core.constants.query_bytes_max);
    const total = query_bytes(query);
    const body = if (query.tcp) out[core.constants.tcp_prefix_bytes..] else out;

    const header: header_codec.Header = .{
        .id = query.id,
        // Nothing but the RD bit is ever set: the query is never authoritative or truncated.
        .flags = if (query.recursion_desired) constants.flag_recursion_desired else 0,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        // One additional record when EDNS0 is on: the OPT record.
        .arcount = if (query.payload_bytes == null) 0 else 1,
    };
    header_codec.write(&header, body);
    var offset: usize = core.constants.header_bytes;
    offset += question_codec.write(&query.name, query.kind, body[offset..]);
    if (query.payload_bytes) |payload_bytes| {
        offset += edns.write_padded(payload_bytes, cookie_of(query), padding_bytes(query), body[offset..]);
    }

    if (query.tcp) {
        header_codec.write_message_len(out, @intCast(offset));
        assert(offset + core.constants.tcp_prefix_bytes == total);
        return total;
    }
    assert(offset == total);
    return total;
}

// Tests.

const testing = std.testing;

const fixtures = @import("fixtures.zig");

fn query_for(text: []const u8) !Query {
    return .{ .id = fixtures.id, .name = try Name.from_text(text), .kind = .a };
}

test "a query is a header, a question and an OPT record" {
    var query = try query_for("example.com");
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    try testing.expectEqual(query_bytes(&query), written);
    const expected = [_]u8{
        0x12, 0x34, // id
        0x01, 0x00, // recursion desired
        0x00, 0x01, // one question
        0x00, 0x00, 0x00, 0x00, // no answers, no authority
        0x00, 0x01, // one additional: OPT
    } ++ "\x07example\x03com\x00\x00\x01\x00\x01".* ++ [_]u8{
        0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectEqualSlices(u8, &expected, out[0..written]);
}

test "the same query written twice is byte-identical" {
    const query = try query_for("example.com");
    var first: [core.constants.query_bytes_max]u8 = @splat(0);
    var second: [core.constants.query_bytes_max]u8 = @splat(0xff);
    const written = write(&query, &first);
    try testing.expectEqual(written, write(&query, &second));
    try testing.expectEqualSlices(u8, first[0..written], second[0..written]);
}

test "EDNS0 off drops the OPT record and the additional count" {
    var query = try query_for("example.com");
    query.payload_bytes = null;
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    try testing.expectEqual(
        core.constants.header_bytes + 13 + core.constants.question_fixed_bytes,
        written,
    );
    const header = try header_codec.parse(out[0..written]);
    try testing.expectEqual(@as(u16, 0), header.arcount);
    try testing.expectEqual(@as(u16, 1), header.qdcount);
}

test "a TCP query carries the length prefix, which counts the message after it" {
    var query = try query_for("example.com");
    query.tcp = true;
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    const length = header_codec.message_len(&out);
    try testing.expectEqual(written - core.constants.tcp_prefix_bytes, length);
    const header = try header_codec.parse(out[core.constants.tcp_prefix_bytes..]);
    try testing.expectEqual(@as(u16, 0x1234), header.id);
}

test "the largest query there is fits the buffer the caller provides" {
    // A maximal name, EDNS0 on with the largest cookie, padded, over TCP: the sum
    // query_bytes_max is defined as.
    var query = try query_for("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61);
    query.tcp = true;
    query.padded = true;
    query.cookie = .{
        .client = fixtures.cookie_client,
        .server = @splat(0xcc),
        .server_len = core.constants.cookie_server_bytes_max,
    };
    try testing.expectEqual(core.constants.name_bytes_max, query.name.len);
    try testing.expectEqual(core.constants.query_bytes_max, query_bytes(&query));
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    try testing.expectEqual(core.constants.query_bytes_max, write(&query, &out));
}

test "a padded query is a whole number of blocks, its padding zero, and an unpadded one has none" {
    const options = @import("edns_options.zig");
    const names = [_][]const u8{ "example.com", "a" ** 63 ++ "." ++ "b" ** 63, "x" };
    for (names) |text| {
        var query = try query_for(text);
        query.tcp = true;
        query.padded = true;
        var out: [core.constants.query_bytes_max]u8 = @splat(0xff);
        const written = write(&query, &out);
        const message = out[core.constants.tcp_prefix_bytes..written];
        try testing.expectEqual(@as(usize, 0), message.len % core.constants.padding_block_bytes);
        const opt_at = core.constants.header_bytes + question_codec.section_bytes(&query.name);
        const padding = (try options.padding(message[opt_at + core.constants.opt_record_bytes ..])).?;
        try testing.expect(std.mem.allEqual(u8, padding, 0));
        query.padded = false;
        const plain = write(&query, &out);
        try testing.expectEqual(@as(?[]const u8, null), try options.padding(out[core.constants.tcp_prefix_bytes + opt_at + core.constants.opt_record_bytes .. plain]));
    }
}

test "a padded query without EDNS carries no OPT record and no padding" {
    var query = try query_for("example.com");
    query.padded = true;
    query.payload_bytes = null;
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    try testing.expectEqual(core.constants.header_bytes + 13 + core.constants.question_fixed_bytes, written);
    try testing.expectEqual(@as(u16, 0), (try header_codec.parse(out[0..written])).arcount);
}

test "the question a query wrote is the question that matches it back" {
    const query = try query_for("example.com");
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    try testing.expect(question_codec.matches(out[0..written], &query.name, query.kind));
}

test "a query with a cookie carries it in the OPT record, and one without EDNS carries none" {
    var query = try query_for("example.com");
    query.cookie = .{ .client = fixtures.cookie_client, .server = @splat(0), .server_len = 0 };
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    const plain_bytes = core.constants.header_bytes + "\x07example\x03com\x00\x00\x01\x00\x01".len + core.constants.opt_record_bytes;
    try testing.expectEqual(plain_bytes + fixtures.opt_cookie_short_rdata.len, written);
    try testing.expectEqualSlices(u8, &fixtures.opt_cookie_short_rdata, out[plain_bytes..written]);
    try testing.expectEqual(@as(u16, 1), (try @import("header.zig").parse(out[0..written])).arcount);
    query.payload_bytes = null;
    try testing.expectEqual(plain_bytes - core.constants.opt_record_bytes, write(&query, &out));
}

test "the RD bit is set unless the caller clears it" {
    var query = try query_for("example.com");
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    _ = write(&query, &out);
    try testing.expect((try header_codec.parse(&out)).flags & constants.flag_recursion_desired != 0);
    query.recursion_desired = false;
    _ = write(&query, &out);
    try testing.expectEqual(@as(u16, 0), (try header_codec.parse(&out)).flags);
}
