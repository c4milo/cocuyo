//! Base32 with the extended hex alphabet, which an NSEC3 owner label holds its hash in (RFC 5155
//! §3.3, RFC 4648 §7). It decodes only: cocuyo never writes a hashed owner name. Split from
//! `dnssec_nsec3.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;

/// The bits one character of the alphabet holds (RFC 4648 §7).
const bits_per_character: u4 = 5;
const bits_per_octet: u4 = 8;
const digit_values: u8 = 10;

/// Decodes `text` into `out`, and returns the octets written. Null when a character is outside the
/// alphabet, when the octets do not fit, or when the last character's spare bits are not zero.
/// Letters are taken in either case, since the label is a DNS name (RFC 1035 §2.3.3). NSEC3 writes
/// no padding (RFC 5155 §1.3), so "=" is refused.
pub fn decode(text: []const u8, out: []u8) ?usize {
    var accumulated: u16 = 0;
    var held: u4 = 0;
    var written: usize = 0;
    for (text) |character| {
        const value = value_of(character) orelse return null;
        accumulated = (accumulated << bits_per_character) | value;
        held += bits_per_character;
        if (held >= bits_per_octet) {
            held -= bits_per_octet;
            if (written == out.len) return null;
            out[written] = @truncate(accumulated >> held);
            written += 1;
            accumulated &= (@as(u16, 1) << held) - 1;
        }
    }
    // A sender writes zero bits after the last octet (RFC 4648 §6, which §7 follows).
    if (accumulated != 0) return null;
    assert(written <= out.len);
    return written;
}

/// The value of one character of "0123456789ABCDEFGHIJKLMNOPQRSTUV" (RFC 4648 §7, Table 4).
fn value_of(character: u8) ?u5 {
    const lower = std.ascii.toLower(character);
    if (lower >= '0' and lower <= '9') return @intCast(lower - '0');
    if (lower >= 'a' and lower <= 'v') return @intCast(lower - 'a' + digit_values);
    return null;
}

// Tests.

const testing = std.testing;

test "RFC 4648 §10's base32hex vectors decode, in either case" {
    var out: [8]u8 = undefined;
    const vectors = [_][2][]const u8{
        .{ "CO", "f" },         .{ "CPNG", "fo" },      .{ "CPNMU", "foo" },
        .{ "CPNMUOG", "foob" }, .{ "cpnmuog", "foob" }, .{ "CPNMUOJ1", "fooba" },
    };
    for (vectors) |vector| {
        const length = decode(vector[0], &out) orelse return error.TestUnexpectedResult;
        try testing.expectEqualSlices(u8, vector[1], out[0..length]);
    }
}

test "a character outside the alphabet, spare bits set, or no room is refused" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(?usize, null), decode("CW", &out));
    try testing.expectEqual(@as(?usize, null), decode("C=", &out));
    try testing.expectEqual(@as(?usize, null), decode("CP", &out));
    try testing.expectEqual(@as(?usize, null), decode("CPNMUOJ1", out[0..4]));
}
