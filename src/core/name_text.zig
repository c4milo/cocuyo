//! A name between presentation form and wire form: the syntax constants of RFC 1035 §5.1, the
//! per-label validation `Name.from_text` applies, and the escaping writer that turns wire bytes
//! back into text a human reads.
//!
//! Version one accepts no escape sequence on input. A label is printable ASCII, so `\.` and `\255`
//! are refused where a name is spelled by the caller, and a name that needs them cannot be asked
//! for. Output is the other direction and must carry anything: a PTR record's rdata is bytes the
//! server chose, so the writer escapes whatever the reader would misread.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const Error = @import("errors.zig").Error;

/// The label separator in presentation form (RFC 1035 §5.1).
pub const separator: u8 = '.';

/// The escape character of presentation form. Refused on input in version one.
pub const escape: u8 = '\\';

/// The printable ASCII range a label may hold on input: aliases of the limits in `limits.zig`, kept
/// as the paths a consumer reached them by (docs/design.md §17 question 76).
pub const printable_min = limits.text_printable_min;
pub const printable_max = limits.text_printable_max;

/// The digits a `\DDD` escape writes, which is why a text buffer is four times the wire length.
pub const escape_digits: usize = 3;

/// An escaped byte written as a pair: the escape character, then the byte itself.
const escape_pair_bytes: usize = 2;

/// The base `\DDD` is written in (RFC 1035 §5.1).
pub const escape_base: u8 = 10;

/// Checks one label of a name the caller spelled. An empty label is a malformed name rather than a
/// too-short one: it is what `a..b` and a leading dot produce.
pub fn validate_label(label: []const u8) Error!void {
    if (label.len == 0) return Error.MalformedName;
    if (label.len > limits.label_bytes_max) return Error.LabelTooLong;
    assert(label.len <= limits.label_bytes_max);
    for (label) |byte| {
        if (byte < limits.text_printable_min or byte > limits.text_printable_max) return Error.MalformedName;
        if (byte == escape or byte == separator) return Error.MalformedName;
    }
}

/// Writes `wire`, an uncompressed name, into `out` as presentation form, and returns the bytes
/// written. The root is a single dot, and every other name ends in one, because a wire name is
/// absolute and presentation form says so with the trailing dot.
///
/// `out` must hold `limits.name_text_bytes_max`, which is the four-bytes-per-wire-byte worst
/// case. The caller owns the buffer; cocuyo allocates nothing.
pub fn write(wire: []const u8, out: []u8) usize {
    assert(wire.len >= 1);
    assert(out.len >= limits.name_text_bytes_max);
    var read: usize = 0;
    var written: usize = 0;
    while (read < wire.len) {
        const length = wire[read];
        assert(length <= limits.label_bytes_max);
        read += 1;
        if (length == 0) break;
        for (wire[read..][0..length]) |byte| written += write_byte(byte, out[written..]);
        written += write_separator(out[written..]);
        read += length;
    }
    if (written == 0) written += write_separator(out[written..]);
    assert(written >= 1);
    assert(written <= limits.name_text_bytes_max);
    return written;
}

fn write_separator(out: []u8) usize {
    assert(out.len >= 1);
    out[0] = separator;
    return 1;
}

/// One byte of a label. A byte the reader would misread is escaped: the separator and the escape
/// character with a backslash, and anything outside printable ASCII as `\DDD`.
fn write_byte(byte: u8, out: []u8) usize {
    assert(out.len >= 1 + escape_digits);
    if (byte == separator or byte == escape) {
        out[0] = escape;
        out[1] = byte;
        return escape_pair_bytes;
    }
    if (byte >= limits.text_printable_min and byte <= limits.text_printable_max) {
        out[0] = byte;
        return 1;
    }
    out[0] = escape;
    var value = byte;
    var digit: usize = escape_digits;
    while (digit > 0) : (digit -= 1) {
        out[digit] = '0' + @as(u8, @intCast(value % escape_base));
        value /= escape_base;
    }
    assert(value == 0);
    return 1 + escape_digits;
}

// Tests.

const testing = std.testing;

test "validate_label refuses what version one cannot spell" {
    try testing.expectError(Error.MalformedName, validate_label(""));
    try testing.expectError(Error.MalformedName, validate_label("a\\b"));
    try testing.expectError(Error.MalformedName, validate_label("a b"));
    try testing.expectError(Error.MalformedName, validate_label("caf\xc3\xa9"));
    try testing.expectError(Error.LabelTooLong, validate_label("a" ** 64));
    try validate_label("a" ** 63);
    try validate_label("xn--caf-dma");
    try validate_label("_dns");
}

test "write turns a wire name into presentation form with the trailing dot" {
    var out: [limits.name_text_bytes_max]u8 = undefined;
    const wire = "\x07example\x03com\x00";
    try testing.expectEqualStrings("example.com.", out[0..write(wire, &out)]);
}

test "write gives the root a single dot" {
    var out: [limits.name_text_bytes_max]u8 = undefined;
    try testing.expectEqualStrings(".", out[0..write("\x00", &out)]);
}

test "write escapes a dot, a backslash and a byte outside printable ASCII" {
    var out: [limits.name_text_bytes_max]u8 = undefined;
    const wire = "\x05a.b\\c\x03com\x00";
    try testing.expectEqualStrings("a\\.b\\\\c.com.", out[0..write(wire, &out)]);
    const control = "\x03a\x00b\x00";
    try testing.expectEqualStrings("a\\000b.", out[0..write(control, &out)]);
    const high = "\x02\xff\x01\x00";
    try testing.expectEqualStrings("\\255\\001.", out[0..write(high, &out)]);
}

test "the longest text a name gives, 1004 octets, fits the buffer" {
    // A name holds 255 octets at most (RFC 1035 §2.3.4). Four labels of 63, 63, 63 and 61 octets
    // carry 250 octets, the most a name carries. Each octet 0xff is written as `\255`, so the text
    // is 1000 octets and four dots. More labels carry fewer octets, so no name gives a longer text.
    // `name_text_bytes_max` keeps 16 octets to spare.
    const longest = limits.label_bytes_max;
    const last = limits.name_bytes_max - 1 - 3 * (1 + longest) - 1;
    const label = [_]u8{longest} ++ [_]u8{0xff} ** longest;
    const wire = label ** 3 ++ [_]u8{last} ++ [_]u8{0xff} ** last ++ [_]u8{0};
    comptime std.debug.assert(wire.len == limits.name_bytes_max);
    var out: [limits.name_text_bytes_max]u8 = undefined;
    const written = write(&wire, &out);
    try testing.expectEqual(@as(usize, 1004), written);
    try testing.expectEqualStrings("\\255", out[0 .. 1 + escape_digits]);
    try testing.expectEqual(@as(u8, separator), out[written - 1]);
}
