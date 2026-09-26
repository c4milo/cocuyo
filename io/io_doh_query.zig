//! A DoH query read back out of a GET's path, as a server reads it (RFC 8484 §4.1, §6). The
//! engine never reads one: its test servers do, over HTTP/3 and over HTTP/2.
const std = @import("std");

const base64url = std.base64.url_safe_no_pad.Decoder;

/// The `dns` parameter of `path`'s query, decoded from base64url (RFC 8484 §4.1, §6), or null when
/// there is none, or it does not decode into `out`.
pub fn query_of(path: []const u8, out: []u8) ?[]const u8 {
    const question = std.mem.indexOfScalar(u8, path, '?') orelse return null;
    var parameters_left = std.mem.splitScalar(u8, path[question + 1 ..], '&');
    // Bounded by the path: each parameter but the last ends at an ampersand.
    for (0..path.len) |_| {
        const parameter = parameters_left.next() orelse return null;
        if (!std.mem.startsWith(u8, parameter, "dns=")) continue;
        const encoded = parameter["dns=".len..];
        const len = base64url.calcSizeForSlice(encoded) catch return null;
        if (len > out.len) return null;
        base64url.decode(out[0..len], encoded) catch return null;
        return out[0..len];
    }
    return null;
}

const testing = std.testing;

test "the dns parameter decodes wherever it sits in the query, and a path without one reads none" {
    var out: [16]u8 = undefined;
    // RFC 8484 §4.1.1's example query starts `AAABAAABAAAAAAAA`: an ID of 0, then a header.
    try testing.expectEqualSlices(u8, &.{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, query_of("/dns-query?ct&dns=AAABAAABAAAAAAAA", &out).?);
    try testing.expect(query_of("/dns-query", &out) == null);
    try testing.expect(query_of("/dns-query?name=x", &out) == null);
    try testing.expect(query_of("/dns-query?dns=!!", &out) == null);
}
