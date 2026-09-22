//! Building a query: the header, one question, and an OPT record unless EDNS0 is off
//! (RFC 1035 §4.1, RFC 6891 §6.1.1).
//!
//! A query is rebuilt on every send rather than stored, and it is byte-identical each time,
//! because everything that varies — the transaction id and the case pattern of the name — is held
//! by the lookup (docs/design.md §16 decision 3). That is what lets one send buffer serve a whole
//! table of lookups.
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
};

/// The octets a query occupies.
pub fn query_bytes(query: *const Query) usize {
    var total: usize = core.constants.header_bytes + question_codec.section_bytes(&query.name);
    if (query.payload_bytes != null) total += core.constants.opt_record_bytes;
    if (query.tcp) total += core.constants.tcp_prefix_bytes;
    assert(total <= core.constants.query_bytes_max);
    return total;
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
        // Recursion desired: a stub asks a recursive server to do the walking. Nothing else is
        // set, and the query is never authoritative or truncated.
        .flags = constants.flag_recursion_desired,
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
        offset += edns.write(payload_bytes, body[offset..]);
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
    // A maximal name, EDNS0 on, over TCP: the sum query_bytes_max is defined as.
    var query = try query_for("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61);
    query.tcp = true;
    try testing.expectEqual(core.constants.name_bytes_max, query.name.len);
    try testing.expectEqual(core.constants.query_bytes_max, query_bytes(&query));
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    try testing.expectEqual(core.constants.query_bytes_max, write(&query, &out));
}

test "the question a query wrote is the question that matches it back" {
    const query = try query_for("example.com");
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&query, &out);
    try testing.expect(question_codec.matches(out[0..written], &query.name, query.kind));
}
