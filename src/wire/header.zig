//! The twelve-octet header every message starts with (RFC 1035 §4.1.1), and the two-octet length
//! prefix every message on a TCP stream is preceded by (RFC 7766 §8).
//!
//! The header is the cheapest thing to check and the most decisive, which is why the response
//! check of docs/design.md §7 reads it first: a message too short to hold one, or whose id is not
//! the id we sent, is rejected before any name is decoded.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("constants.zig");
const integer = @import("integer.zig");

pub const Header = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,

    pub fn is_response(self: *const Header) bool {
        return self.flags & constants.flag_response != 0;
    }

    pub fn opcode(self: *const Header) u16 {
        return (self.flags & constants.opcode_mask) >> constants.opcode_shift;
    }

    pub fn truncated(self: *const Header) bool {
        return self.flags & constants.flag_truncated != 0;
    }

    pub fn recursion_desired(self: *const Header) bool {
        return self.flags & constants.flag_recursion_desired != 0;
    }

    pub fn recursion_available(self: *const Header) bool {
        return self.flags & constants.flag_recursion_available != 0;
    }

    pub fn authoritative(self: *const Header) bool {
        return self.flags & constants.flag_authoritative != 0;
    }

    /// The low four bits of the flags. An OPT record can extend this, which edns.zig reads; this
    /// is the header's own four bits and nothing more.
    pub fn rcode_bits(self: *const Header) u8 {
        return @intCast(self.flags & constants.rcode_mask);
    }

    /// The response code, when it is one cocuyo knows. A code it does not know makes the message
    /// malformed rather than something to guess at.
    pub fn rcode(self: *const Header) Error!constants.Rcode {
        const bits = self.rcode_bits();
        assert(bits <= constants.rcode_mask);
        return constants.Rcode.from_bits(bits) orelse Error.MalformedMessage;
    }
};

/// The header of `message`. A message shorter than a header is malformed: the counts and the id
/// are not optional (RFC 1035 §4.1).
pub fn parse(message: []const u8) Error!Header {
    if (message.len < core.constants.header_bytes) return Error.MalformedMessage;
    assert(message.len >= core.constants.header_bytes);
    const header: Header = .{
        .id = integer.read_u16(message, constants.header_id_offset),
        .flags = integer.read_u16(message, constants.header_flags_offset),
        .qdcount = integer.read_u16(message, constants.header_qdcount_offset),
        .ancount = integer.read_u16(message, constants.header_ancount_offset),
        .nscount = integer.read_u16(message, constants.header_nscount_offset),
        .arcount = integer.read_u16(message, constants.header_arcount_offset),
    };
    assert(header.opcode() <= constants.opcode_mask >> constants.opcode_shift);
    return header;
}

/// Writes `header` into the first twelve octets of `out`.
pub fn write(header: *const Header, out: []u8) void {
    assert(out.len >= core.constants.header_bytes);
    integer.write_u16(out, constants.header_id_offset, header.id);
    integer.write_u16(out, constants.header_flags_offset, header.flags);
    integer.write_u16(out, constants.header_qdcount_offset, header.qdcount);
    integer.write_u16(out, constants.header_ancount_offset, header.ancount);
    integer.write_u16(out, constants.header_nscount_offset, header.nscount);
    integer.write_u16(out, constants.header_arcount_offset, header.arcount);
    assert(out[constants.header_id_offset] == @as(u8, @intCast(header.id >> constants.octet_bits)));
}

/// The length a TCP length prefix describes. The caller reads two octets, calls this, reads that
/// many more, and hands the result to `on_response` (docs/design.md §5).
pub fn message_len(prefix: []const u8) u16 {
    assert(prefix.len >= core.constants.tcp_prefix_bytes);
    assert(core.constants.tcp_prefix_bytes == constants.u16_bytes);
    return integer.read_u16(prefix, 0);
}

/// Writes the length prefix for a message of `length` octets.
pub fn write_message_len(out: []u8, length: u16) void {
    assert(out.len >= core.constants.tcp_prefix_bytes);
    assert(length >= core.constants.header_bytes);
    integer.write_u16(out, 0, length);
}

// Tests.

const testing = std.testing;

const query_bytes = @import("fixtures.zig").query_header;

test "a query header parses into its six fields" {
    const header = try parse(&query_bytes);
    try testing.expectEqual(@as(u16, 0x1234), header.id);
    try testing.expectEqual(@as(u16, 1), header.qdcount);
    try testing.expectEqual(@as(u16, 0), header.ancount);
    try testing.expect(!header.is_response());
    try testing.expect(header.recursion_desired());
    try testing.expect(!header.truncated());
    try testing.expectEqual(@as(u16, 0), header.opcode());
    try testing.expectEqual(constants.Rcode.no_error, try header.rcode());
}

test "a message shorter than a header is malformed" {
    try testing.expectError(Error.MalformedMessage, parse(query_bytes[0 .. core.constants.header_bytes - 1]));
    try testing.expectError(Error.MalformedMessage, parse(""));
    _ = try parse(&query_bytes);
}

test "a header round-trips through write" {
    const header = try parse(&query_bytes);
    var out: [core.constants.header_bytes]u8 = @splat(0);
    write(&header, &out);
    try testing.expectEqualSlices(u8, &query_bytes, &out);
}

test "every flag and the rcode read from the bits the RFC fixes" {
    // QR, AA, TC, RA set, opcode 0, rcode 3: 0x8600 | 0x0200 | 0x0080 | 3.
    var bytes = query_bytes;
    bytes[constants.header_flags_offset] = 0x86;
    bytes[constants.header_flags_offset + 1] = 0x83;
    const header = try parse(&bytes);
    try testing.expect(header.is_response());
    try testing.expect(header.truncated());
    try testing.expect(header.recursion_available());
    try testing.expect(header.authoritative());
    try testing.expectEqual(constants.Rcode.name_error, try header.rcode());
}

test "an rcode cocuyo does not know is malformed, not a guess" {
    var bytes = query_bytes;
    bytes[constants.header_flags_offset + 1] = 0x0f;
    const header = try parse(&bytes);
    try testing.expectEqual(@as(u8, 15), header.rcode_bits());
    try testing.expectError(Error.MalformedMessage, header.rcode());
}

test "the TCP length prefix reads and writes two octets" {
    var out: [core.constants.tcp_prefix_bytes]u8 = @splat(0);
    write_message_len(&out, 512);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00 }, &out);
    try testing.expectEqual(@as(u16, 512), message_len(&out));
}
