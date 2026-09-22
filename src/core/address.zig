//! `Address` and `Endpoint`: an IP address as octets, and a server to send to. cocuyo formats no
//! address — it owns no I/O, so it never has to name one to the host — and reads one only from
//! text it is handed (`from_text`). These types exist so the response check of docs/design.md §7
//! can compare the source of a datagram against the server the query went to, octet for octet.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const address_text = @import("address_text.zig");

pub const Family = enum(u8) {
    ipv4,
    ipv6,

    /// The length of an address of this family, in octets.
    pub fn address_bytes(self: Family) u8 {
        return switch (self) {
            .ipv4 => constants.address_v4_bytes,
            .ipv6 => constants.address_v6_bytes,
        };
    }
};

/// An IP address. IPv4 uses the first `address_v4_bytes` octets and leaves the rest zero, so two
/// addresses of one family compare as their octets and two of different families never compare
/// equal.
pub const Address = struct {
    family: Family,
    octets: [constants.address_v6_bytes]u8,

    pub fn from_v4(octets: [constants.address_v4_bytes]u8) Address {
        var address: Address = .{ .family = .ipv4, .octets = @splat(0) };
        @memcpy(address.octets[0..octets.len], &octets);
        assert(address.family == .ipv4);
        assert(address.octets[octets.len] == 0);
        return address;
    }

    pub fn from_v6(octets: [constants.address_v6_bytes]u8) Address {
        const address: Address = .{ .family = .ipv6, .octets = octets };
        assert(address.family == .ipv6);
        assert(address.octets.len == constants.address_v6_bytes);
        return address;
    }

    /// An address from text, IPv4 or IPv6, or null when the text is not one: no zone index, no
    /// brackets, no prefix length (`address_text.zig` says why each).
    pub fn from_text(text: []const u8) ?Address {
        return address_text.parse(text);
    }

    /// The octets this family uses: the first four for IPv4, all sixteen for IPv6.
    pub fn slice(self: *const Address) []const u8 {
        const length = self.family.address_bytes();
        assert(length == constants.address_v4_bytes or length == constants.address_v6_bytes);
        assert(length <= self.octets.len);
        return self.octets[0..length];
    }

    pub fn equal(self: *const Address, other: *const Address) bool {
        if (self.family != other.family) return false;
        assert(self.family.address_bytes() == other.family.address_bytes());
        return std.mem.eql(u8, self.slice(), other.slice());
    }
};

/// A server to send to: an address and a port. The port is part of the response check, because a
/// reply from the right host on the wrong port is not a reply to our query (docs/design.md §7).
pub const Endpoint = struct {
    address: Address,
    port: u16 = constants.port_dns_default,

    pub fn equal(self: *const Endpoint, other: *const Endpoint) bool {
        if (self.port != other.port) return false;
        assert(self.port == other.port);
        return self.address.equal(&other.address);
    }
};

// Tests.

const testing = std.testing;

test "an IPv4 address uses four octets and leaves the rest zero" {
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    try testing.expectEqual(Family.ipv4, address.family);
    try testing.expectEqual(@as(usize, 4), address.slice().len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, address.slice());
    for (address.octets[4..]) |octet| try testing.expectEqual(@as(u8, 0), octet);
}

test "an IPv6 address uses every octet" {
    const octets: [16]u8 = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35 };
    const address = Address.from_v6(octets);
    try testing.expectEqual(Family.ipv6, address.family);
    try testing.expectEqual(@as(usize, 16), address.slice().len);
    try testing.expectEqualSlices(u8, &octets, address.slice());
}

test "addresses of different families never compare equal" {
    const v4 = Address.from_v4(.{ 0, 0, 0, 0 });
    const v6 = Address.from_v6(@splat(0));
    try testing.expect(!v4.equal(&v6));
    try testing.expect(v4.equal(&Address.from_v4(.{ 0, 0, 0, 0 })));
}

test "an endpoint compares its port as well as its address" {
    const address = Address.from_v4(.{ 9, 9, 9, 9 });
    const server: Endpoint = .{ .address = address };
    const other_port: Endpoint = .{ .address = address, .port = 5353 };
    try testing.expectEqual(@as(u16, 53), server.port);
    try testing.expect(!server.equal(&other_port));
    try testing.expect(server.equal(&.{ .address = address, .port = 53 }));
}

test "the length of an address is the family's, not the buffer's" {
    try testing.expectEqual(@as(u8, 4), Family.ipv4.address_bytes());
    try testing.expectEqual(@as(u8, 16), Family.ipv6.address_bytes());
}
