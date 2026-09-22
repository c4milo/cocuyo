//! Reading and writing the two- and four-octet integers of the wire format, which are big endian
//! (RFC 1035 §2.3.2, "network order").
//!
//! Every read is bounds-checked by the caller before it is made: these functions assert the bound
//! rather than returning an error, because a read past the end is a bug in the parser and not a
//! property of the message (CLAUDE.md non-negotiable 6).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

pub fn read_u16(message: []const u8, offset: usize) u16 {
    assert(offset + constants.u16_bytes <= message.len);
    assert(offset < message.len);
    return std.mem.readInt(u16, message[offset..][0..constants.u16_bytes], .big);
}

pub fn read_u32(message: []const u8, offset: usize) u32 {
    assert(offset + constants.u32_bytes <= message.len);
    assert(offset < message.len);
    return std.mem.readInt(u32, message[offset..][0..constants.u32_bytes], .big);
}

pub fn write_u16(out: []u8, offset: usize, value: u16) void {
    assert(offset + constants.u16_bytes <= out.len);
    assert(offset < out.len);
    std.mem.writeInt(u16, out[offset..][0..constants.u16_bytes], value, .big);
}

pub fn write_u32(out: []u8, offset: usize, value: u32) void {
    assert(offset + constants.u32_bytes <= out.len);
    assert(offset < out.len);
    std.mem.writeInt(u32, out[offset..][0..constants.u32_bytes], value, .big);
}

// Tests.

const testing = std.testing;

test "a two-octet integer reads and writes big endian" {
    var out: [constants.u16_bytes]u8 = @splat(0);
    write_u16(&out, 0, 0x1234);
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x34 }, &out);
    try testing.expectEqual(@as(u16, 0x1234), read_u16(&out, 0));
}

test "a four-octet integer reads and writes big endian" {
    var out: [constants.u32_bytes]u8 = @splat(0);
    write_u32(&out, 0, 0xdeadbeef);
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, &out);
    try testing.expectEqual(@as(u32, 0xdeadbeef), read_u32(&out, 0));
}

test "an integer reads at an offset inside a larger message" {
    const message = [_]u8{ 0xff, 0x00, 0x35, 0xff };
    try testing.expectEqual(@as(u16, 0x0035), read_u16(&message, 1));
}
