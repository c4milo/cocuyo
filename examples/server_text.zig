//! Where a server is, read from an engine example's argument: an address alone, or an address and a
//! port after a colon. An IPv6 address that a port follows goes in square brackets, as a URI writes
//! it (RFC 3986 §3.2.2): `2001:db8::1:8853` is itself an IPv6 address, so without the brackets the
//! port would be read as the address's last group.
//!
//!     192.0.2.1    192.0.2.1:8853    2001:db8::1    [2001:db8::1]:8853
const std = @import("std");
const cocuyo = @import("cocuyo");

pub const Place = struct { address: cocuyo.Address, port: ?u16 };

pub fn place_of(text: []const u8) !Place {
    if (std.mem.startsWith(u8, text, "[")) {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return error.BadAddress;
        const address = cocuyo.Address.from_text(text[1..close]) orelse return error.BadAddress;
        if (address.family != .ipv6) return error.BadAddress;
        const rest = text[close + 1 ..];
        if (rest.len == 0) return .{ .address = address, .port = null };
        if (rest[0] != ':') return error.BadAddress;
        return .{ .address = address, .port = try std.fmt.parseInt(u16, rest[1..], 10) };
    }
    if (cocuyo.Address.from_text(text)) |address| return .{ .address = address, .port = null };
    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.BadAddress;
    const address = cocuyo.Address.from_text(text[0..colon]) orelse return error.BadAddress;
    // An IPv6 address and a port with no brackets would have parsed whole above, or is ambiguous.
    if (address.family != .ipv4) return error.BadAddress;
    return .{ .address = address, .port = try std.fmt.parseInt(u16, text[colon + 1 ..], 10) };
}

// Tests.

const testing = std.testing;

test "a server is an address alone, or an address and a port, an IPv6 one in brackets" {
    const v4 = try place_of("192.0.2.1");
    try testing.expectEqual(@as(?u16, null), v4.port);
    try testing.expectEqual(cocuyo.Family.ipv4, v4.address.family);
    try testing.expectEqual(@as(?u16, 8853), (try place_of("192.0.2.1:8853")).port);
    const v6 = try place_of("2001:db8::1");
    try testing.expectEqual(cocuyo.Family.ipv6, v6.address.family);
    try testing.expectEqual(@as(?u16, null), v6.port);
    const bracketed = try place_of("[2001:db8::1]:8853");
    try testing.expect(bracketed.address.equal(&v6.address));
    try testing.expectEqual(@as(?u16, 8853), bracketed.port);
    try testing.expectEqual(@as(?u16, null), (try place_of("[::1]")).port);
}

test "an IPv6 address and a port without brackets is read as the address it spells" {
    // `::1:8053` is the address ::1:1f55, and the port is the default one.
    const place = try place_of("::1:8053");
    try testing.expectEqual(@as(?u16, null), place.port);
    try testing.expectEqual(cocuyo.Family.ipv6, place.address.family);
}

test "a server that is not an address, or brackets around what is not IPv6, is refused" {
    // Nine groups are no address, and the eight before the last colon must not pass for one with a
    // port: an IPv6 address takes a port only in brackets.
    for ([_][]const u8{ "[192.0.2.1]:53", "[::1", "[::1]8053", "[::1]:", "999.0.0.1:53", "dns.example:53", "192.0.2.1:99999", "1:2:3:4:5:6:7:8:53" }) |text| {
        try testing.expect(std.meta.isError(place_of(text)));
    }
}
