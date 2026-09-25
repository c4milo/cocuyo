//! The name a reverse lookup asks about: an address turned into a name under `in-addr.arpa` or
//! `ip6.arpa` (RFC 1035 §3.5, RFC 3596 §2.5).
//!
//! An IPv4 address becomes its four octets in decimal, most significant last: 192.0.2.1 asks about
//! `1.2.0.192.in-addr.arpa`. An IPv6 address becomes its thirty-two nibbles in hexadecimal, least
//! significant first, one nibble per label.
//!
//! This is a name construction and not a lookup, so it lives in `core` beside the type it builds.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Error = @import("errors.zig").Error;
const Address = @import("address.zig").Address;
const Name = @import("name.zig").Name;

/// The suffix every IPv4 reverse name carries (RFC 1035 §3.5).
const v4_suffix = [_][]const u8{ "in-addr", "arpa" };

/// The suffix every IPv6 reverse name carries (RFC 3596 §2.5).
const v6_suffix = [_][]const u8{ "ip6", "arpa" };

/// The digits a nibble is written with, lowercase, as RFC 3596 §2.5 writes them.
const hex_digits = "0123456789abcdef";

/// The base an octet is written in for an IPv4 reverse name.
const decimal_base = 10;

/// The most digits one octet needs in decimal: 255.
const decimal_digits_max = 3;

/// The bits a nibble holds, which is how an octet splits into two labels.
const nibble_bits = 4;

/// The low nibble of an octet.
const nibble_mask = 0x0f;

pub fn from_address(address: *const Address) Error!Name {
    var name: Name = Name.empty;
    switch (address.family) {
        .ipv4 => try append_v4(&name, address.slice()),
        .ipv6 => try append_v6(&name, address.slice()),
    }
    const suffix = switch (address.family) {
        .ipv4 => &v4_suffix,
        .ipv6 => &v6_suffix,
    };
    for (suffix) |label| try name.append_label(label);
    try name.terminate();
    assert(name.len > constants.address_v4_bytes);
    assert(!name.is_root());
    return name;
}

/// The four octets in decimal, most significant last.
fn append_v4(name: *Name, octets: []const u8) Error!void {
    assert(octets.len == constants.address_v4_bytes);
    var index = octets.len;
    while (index > 0) {
        index -= 1;
        var digits: [decimal_digits_max]u8 = @splat(0);
        try name.append_label(write_decimal(octets[index], &digits));
    }
    assert(index == 0);
}

/// The thirty-two nibbles in hexadecimal, least significant first, one per label.
fn append_v6(name: *Name, octets: []const u8) Error!void {
    assert(octets.len == constants.address_v6_bytes);
    var index = octets.len;
    while (index > 0) {
        index -= 1;
        const octet = octets[index];
        try name.append_label(&.{hex_digits[octet & nibble_mask]});
        try name.append_label(&.{hex_digits[octet >> nibble_bits]});
    }
    assert(index == 0);
}

/// One octet in decimal, with no leading zero, written into `digits`.
fn write_decimal(octet: u8, digits: *[decimal_digits_max]u8) []const u8 {
    assert(digits.len == decimal_digits_max);
    var value = octet;
    var written: usize = 0;
    while (written < decimal_digits_max) {
        digits[decimal_digits_max - 1 - written] = '0' + (value % decimal_base);
        written += 1;
        value /= decimal_base;
        if (value == 0) break;
    }
    assert(value == 0);
    assert(written >= 1);
    return digits[decimal_digits_max - written ..];
}

// Tests.

const testing = std.testing;

fn text_of(name: *const Name) ![]const u8 {
    const out = struct {
        threadlocal var buffer: [constants.name_text_bytes_max]u8 = undefined;
    };
    return out.buffer[0..name.write_text(&out.buffer)];
}

test "an IPv4 address reverses to in-addr.arpa, most significant last" {
    const name = try from_address(&Address.from_v4(.{ 192, 0, 2, 1 }));
    try testing.expectEqualStrings("1.2.0.192.in-addr.arpa.", try text_of(&name));
}

test "every octet width is written without a leading zero" {
    const name = try from_address(&Address.from_v4(.{ 255, 100, 10, 0 }));
    try testing.expectEqualStrings("0.10.100.255.in-addr.arpa.", try text_of(&name));
}

test "an IPv6 address reverses to ip6.arpa, one nibble per label" {
    var octets: [constants.address_v6_bytes]u8 = @splat(0);
    octets[0] = 0x20;
    octets[1] = 0x01;
    octets[2] = 0x0d;
    octets[3] = 0xb8;
    octets[15] = 0x01;
    const name = try from_address(&Address.from_v6(octets));
    try testing.expectEqualStrings(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        try text_of(&name),
    );
}

test "an IPv6 reverse name holds every nibble and fits the limit" {
    const name = try from_address(&Address.from_v6(@splat(0xff)));
    // 32 nibble labels, then ip6 and arpa: 32 labels of two octets, 4, 5, and the root.
    try testing.expectEqual(@as(u8, 32 * 2 + 4 + 5 + 1), name.len);
    try testing.expectEqual(@as(u8, 34), name.label_count());
}
