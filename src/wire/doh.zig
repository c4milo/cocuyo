//! The DNS half of a DoH request (docs/design.md §22): the `dns` variable a GET expands its URI
//! template with. The template, the request and everything else HTTP are the driver's.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

/// base64url, the alphabet of RFC 4648 §5, with no `=`: "Padding characters for base64url MUST
/// NOT be included" (RFC 8484 §6).
const encoder = std.base64.url_safe_no_pad.Encoder;

/// Writes the `dns` variable of `message`, a query as `poll` built it, into `out` (RFC 8484 §4.1,
/// §6), and returns what it wrote. A POST sends `message` itself instead. `out` holds
/// `constants.dns_variable_bytes_max` octets, which any query cocuyo builds fits.
pub fn dns_variable(message: []const u8, out: []u8) []const u8 {
    assert(message.len >= core.constants.header_bytes);
    assert(message.len <= core.constants.query_bytes_max - core.constants.tcp_prefix_bytes);
    assert(out.len >= constants.dns_variable_bytes_max);
    const written = encoder.encode(out, message);
    assert(written.len == encoder.calcSize(message.len));
    return written;
}

// Tests.

const testing = std.testing;
const query = @import("query.zig");

const Variable = [constants.dns_variable_bytes_max]u8;

test "the dns variable is base64url without padding, as RFC 4648 §10 gives each length" {
    // RFC 4648 §10's vectors are shorter than a header, so they go through the encoder alone; the
    // three lengths modulo three are the three ways a final group ends.
    const vectors = [_][2][]const u8{
        .{ "f", "Zg" },        .{ "fo", "Zm8" },        .{ "foo", "Zm9v" },
        .{ "foob", "Zm9vYg" }, .{ "fooba", "Zm9vYmE" }, .{ "foobar", "Zm9vYmFy" },
    };
    for (vectors) |vector| {
        var out: [8]u8 = undefined;
        try testing.expectEqualStrings(vector[1], encoder.encode(&out, vector[0]));
    }
}

test "RFC 8484 §4.1.1's query for www.example.com is its dns variable, and ID 0 its octets" {
    const expected = [_]u8{
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00,
        0x01,
    };
    // The query cocuyo builds for it without EDNS0 is the RFC's, octet for octet.
    const www: query.Query = .{
        .id = 0,
        .name = try core.Name.from_text("www.example.com"),
        .kind = .a,
        .payload_bytes = null,
    };
    var message: [core.constants.query_bytes_max]u8 = undefined;
    const written = query.write(&www, &message);
    try testing.expectEqualSlices(u8, &expected, message[0..written]);
    var out: Variable = undefined;
    try testing.expectEqualStrings("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", dns_variable(&expected, &out));
}

test "RFC 8484 §4.1.1's query that tells base64url from base64 has the dash, and no padding" {
    const label = "62characterlabel-makes-base64url-distinct-from-standard-base64";
    const expected = "AAABAAABAAAAAAAAAWE-NjJjaGFyYWN0ZXJsYWJl" ++
        "bC1tYWtlcy1iYXNlNjR1cmwtZGlzdGluY3QtZnJvbS1z" ++
        "dGFuZGFyZC1iYXNlNjQHZXhhbXBsZQNjb20AAAEAAQ";
    const asked: query.Query = .{
        .id = 0,
        .name = try core.Name.from_text("a." ++ label ++ ".example.com"),
        .kind = .a,
        .payload_bytes = null,
    };
    var message: [core.constants.query_bytes_max]u8 = undefined;
    const written = query.write(&asked, &message);
    try testing.expectEqual(@as(usize, 94), written);
    var out: Variable = undefined;
    try testing.expectEqualStrings(expected, dns_variable(message[0..written], &out));
}

test "the longest query cocuyo builds fits the longest dns variable" {
    try testing.expectEqual(@as(usize, 512), constants.dns_variable_bytes_max);
    var message: [core.constants.query_bytes_max - core.constants.tcp_prefix_bytes]u8 = @splat(0xff);
    var out: Variable = undefined;
    const variable = dns_variable(&message, &out);
    try testing.expectEqual(constants.dns_variable_bytes_max, variable.len);
    // Every octet 0xff is every sextet 63, which base64url spells `_` and base64 `/`.
    for (variable) |character| try testing.expectEqual(@as(u8, '_'), character);
}
