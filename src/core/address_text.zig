//! An address from text, IPv4 or IPv6: what a `nameserver` line, a hosts file line and a numeric
//! host given to `AddressLookup` (docs/design.md §19 step 14) carry. `Address.from_text` is the
//! entry point; the two parsers are public for the tests.
//!
//! This is the one place cocuyo reads an address as text, and it formats none: it owns no
//! socket, so it never has to name an address to the host. It lived in `config` while a config
//! file was the only text that carried one, and moved here when the numeric host of §19 step 14
//! made it a need of `resolver`, which cannot import `config` (§2).
//!
//! Anything unparseable returns null. A `resolv.conf` or hosts line with a bad address is skipped,
//! not an error: one bad line must not stop a program from resolving (docs/design.md §10).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const address_module = @import("address.zig");
const Address = address_module.Address;
const Family = address_module.Family;

/// An address from text, IPv4 or IPv6.
///
/// A zone index, a bracketed form and a prefix length are all refused, but not by a check of their
/// own: `%`, `[`, `]` and `/` are not digits, so the group and octet parsers refuse them wherever
/// they appear. A pre-scan for those four was written first and then removed, because no input
/// could reach it (mutation C9 of docs/mutations.md).
pub fn parse(text: []const u8) ?Address {
    if (text.len == 0) return null;
    if (std.mem.indexOfScalar(u8, text, ':') != null) return parse_v6(text);
    return parse_v4(text);
}

/// A dotted quad: four decimal octets (RFC 1035 §3.4.1's "32 bit Internet address" as text).
pub fn parse_v4(text: []const u8) ?Address {
    var octets: [constants.address_v4_octets]u8 = @splat(0);
    var written: usize = 0;
    var parts = std.mem.splitScalar(u8, text, '.');
    while (parts.next()) |part| {
        if (written == octets.len) return null;
        octets[written] = parse_octet(part) orelse return null;
        written += 1;
    }
    if (written != octets.len) return null;
    assert(written == constants.address_v4_octets);
    return Address.from_v4(octets);
}

fn parse_octet(text: []const u8) ?u8 {
    if (text.len == 0 or text.len > constants.address_v4_octet_digits_max) return null;
    // A leading zero is how an octet is read as octal elsewhere, so it is refused rather than
    // guessed at: `010` is ten here and eight in some resolvers.
    if (text.len > 1 and text[0] == '0') return null;
    var value: u16 = 0;
    for (text) |byte| {
        if (byte < '0' or byte > '9') return null;
        value = value * constants.decimal_base + (byte - '0');
    }
    if (value > std.math.maxInt(u8)) return null;
    return @intCast(value);
}

/// An IPv6 address, with at most one `::` and an optional trailing dotted quad (RFC 4291 §2.2 is
/// the text form; the address itself is RFC 3596 §2.2's 128 bits).
pub fn parse_v6(text: []const u8) ?Address {
    var groups: [constants.address_v6_groups]u16 = @splat(0);
    const double = std.mem.indexOf(u8, text, "::");
    if (double == null) {
        const filled = parse_groups(text, &groups) orelse return null;
        if (filled != groups.len) return null;
        return from_groups(groups);
    }
    const at = double.?;
    const left = text[0..at];
    const right = text[at + constants.double_colon_bytes ..];
    // A second `::` needs no check of its own: it leaves an empty group between two colons, and
    // an empty group is not a group (mutation C4 of docs/mutations.md).
    var head: [constants.address_v6_groups]u16 = @splat(0);
    var tail: [constants.address_v6_groups]u16 = @splat(0);
    const head_count = parse_groups(left, &head) orelse return null;
    const tail_count = parse_groups(right, &tail) orelse return null;
    // `::` stands for *one or more* groups of zeros (RFC 4291 §2.2), so an address whose written
    // groups already fill it has no room for the ones `::` stands for.
    if (head_count + tail_count >= groups.len) return null;
    @memcpy(groups[0..head_count], head[0..head_count]);
    @memcpy(groups[groups.len - tail_count ..], tail[0..tail_count]);
    assert(head_count + tail_count < constants.address_v6_groups);
    return from_groups(groups);
}

/// The groups of one side of an address, or null when any of them is malformed. An empty side has
/// no groups, which is what `::1` and `1::` mean.
fn parse_groups(text: []const u8, out: []u16) ?u8 {
    if (text.len == 0) return 0;
    var written: u8 = 0;
    var parts = std.mem.splitScalar(u8, text, ':');
    while (parts.next()) |part| {
        if (written == out.len) return null;
        // A dotted quad may only be last, and it fills two groups (RFC 4291 §2.2 form 3).
        if (std.mem.indexOfScalar(u8, part, '.') != null) {
            if (parts.next() != null) return null;
            return fill_quad(part, out, written);
        }
        out[written] = parse_group(part) orelse return null;
        written += 1;
    }
    return written;
}

/// The two groups a trailing dotted quad fills, written at `written`.
fn fill_quad(text: []const u8, out: []u16, written: u8) ?u8 {
    if (written + constants.groups_per_quad > out.len) return null;
    const address = parse_v4(text) orelse return null;
    const quad = address.slice();
    assert(quad.len == constants.address_v4_bytes);
    for (0..constants.groups_per_quad) |group| {
        const octet = group * constants.address_v6_group_bytes;
        out[written + group] = (@as(u16, quad[octet]) << constants.octet_bits) | quad[octet + 1];
    }
    return written + constants.groups_per_quad;
}

fn parse_group(text: []const u8) ?u16 {
    if (text.len == 0 or text.len > constants.address_v6_group_digits_max) return null;
    var value: u16 = 0;
    for (text) |byte| {
        const digit = hex_digit(byte) orelse return null;
        value = (value << constants.hex_digit_bits) | digit;
    }
    return value;
}

fn hex_digit(byte: u8) ?u4 {
    return switch (byte) {
        '0'...'9' => @intCast(byte - '0'),
        'a'...'f' => @intCast(byte - 'a' + constants.hex_alpha_value),
        'A'...'F' => @intCast(byte - 'A' + constants.hex_alpha_value),
        else => null,
    };
}

fn from_groups(groups: [constants.address_v6_groups]u16) Address {
    var octets: [constants.address_v6_bytes]u8 = @splat(0);
    for (groups, 0..) |group, index| {
        octets[index * constants.address_v6_group_bytes] = @intCast(group >> constants.octet_bits);
        octets[index * constants.address_v6_group_bytes + 1] = @truncate(group);
    }
    return Address.from_v6(octets);
}

// Tests.

const testing = std.testing;

fn expect_v4(text: []const u8, octets: [constants.address_v4_bytes]u8) !void {
    const parsed = parse(text) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Family.ipv4, parsed.family);
    try testing.expectEqualSlices(u8, &octets, parsed.slice());
}

fn expect_v6(text: []const u8, octets: [constants.address_v6_bytes]u8) !void {
    const parsed = parse(text) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Family.ipv6, parsed.family);
    try testing.expectEqualSlices(u8, &octets, parsed.slice());
}

test "a dotted quad parses" {
    try expect_v4("127.0.0.1", .{ 127, 0, 0, 1 });
    try expect_v4("8.8.8.8", .{ 8, 8, 8, 8 });
    try expect_v4("0.0.0.0", .{ 0, 0, 0, 0 });
    try expect_v4("255.255.255.255", .{ 255, 255, 255, 255 });
}

test "a malformed quad is refused rather than guessed at" {
    try testing.expectEqual(@as(?Address, null), parse("1.2.3"));
    try testing.expectEqual(@as(?Address, null), parse("1.2.3.4.5"));
    try testing.expectEqual(@as(?Address, null), parse("1.2.3.256"));
    try testing.expectEqual(@as(?Address, null), parse("1.2.3."));
    try testing.expectEqual(@as(?Address, null), parse(".1.2.3"));
    try testing.expectEqual(@as(?Address, null), parse("1.2.3.x"));
    // A leading zero reads as octal in some resolvers, so it is not accepted as decimal here.
    try testing.expectEqual(@as(?Address, null), parse("010.1.1.1"));
    try testing.expectEqual(@as(?Address, null), parse(""));
}

test "a full IPv6 address parses" {
    try expect_v6(
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    );
    try expect_v6(
        "2001:db8:85a3:0:0:8a2e:370:7334",
        .{ 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34 },
    );
}

test "a compressed IPv6 address parses, wherever the gap is" {
    try expect_v6("::1", .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    try expect_v6("::", @splat(0));
    try expect_v6(
        "2001:db8::1",
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    );
    try expect_v6(
        "2001:db8::",
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
    );
    try expect_v6(
        "2001:4860:4860::8888",
        .{ 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88 },
    );
}

test "an IPv6 address ending in a dotted quad parses" {
    try expect_v6(
        "::ffff:192.0.2.1",
        .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 0, 2, 1 },
    );
    try expect_v6(
        "64:ff9b::192.0.2.33",
        .{ 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 33 },
    );
}

test "a malformed IPv6 address is refused" {
    try testing.expectEqual(@as(?Address, null), parse("2001:db8:::1"));
    try testing.expectEqual(@as(?Address, null), parse("2001::db8::1"));
    try testing.expectEqual(@as(?Address, null), parse("2001:db8:0:0:0:0:0:0:1"));
    try testing.expectEqual(@as(?Address, null), parse("2001:db8:0:0:0:0:1"));
    try testing.expectEqual(@as(?Address, null), parse("12345::1"));
    try testing.expectEqual(@as(?Address, null), parse("2001:db8::g"));
    try testing.expectEqual(@as(?Address, null), parse("::192.0.2.1.5"));
    try testing.expectEqual(@as(?Address, null), parse("::192.0.2.1:1"));
    try testing.expectEqual(@as(?Address, null), parse(":"));
}

test "an address with a zone or brackets is refused, because a nameserver line has neither" {
    try testing.expectEqual(@as(?Address, null), parse("fe80::1%eth0"));
    try testing.expectEqual(@as(?Address, null), parse("[2001:db8::1]"));
    try testing.expectEqual(@as(?Address, null), parse("192.0.2.0/24"));
}

test "a full address and its compressed form are the same address" {
    const full = parse("2001:db8:0:0:0:0:0:1").?;
    const short = parse("2001:db8::1").?;
    try testing.expect(full.equal(&short));
}

test "Address.from_text is the parser, for either family" {
    try testing.expect(Address.from_text("192.0.2.1").?.equal(&Address.from_v4(.{ 192, 0, 2, 1 })));
    try testing.expectEqual(Family.ipv6, Address.from_text("::1").?.family);
    try testing.expectEqual(@as(?Address, null), Address.from_text("example.com"));
}

test "a double colon standing for no groups is refused" {
    // RFC 4291 §2.2: `::` indicates one or more groups of zeros. Eight written groups leave it
    // nothing to stand for, and some resolvers accept it anyway.
    try testing.expectEqual(@as(?Address, null), parse("1:2:3:4:5:6:7::8"));
    try testing.expectEqual(@as(?Address, null), parse("1:2:3:4:5:6:7:8::"));
    try testing.expectEqual(@as(?Address, null), parse("::1:2:3:4:5:6:7:8"));
    // Seven written groups leave it one, which is legal.
    try expect_v6("1:2:3:4:5:6::8", .{ 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 0, 0, 8 });
}
