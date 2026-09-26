//! What a DoH response's header section says of its content, over HTTP/3 and over HTTP/2 alike
//! (docs/design.md §24, DoH over HTTP/3): its `Age`, and whether the content is a DNS message in no
//! content coding. colibri hands
//! each field's value over as its octets, which hold no CTL and no whitespace at either end.
const std = @import("std");
const assert = std.debug.assert;

/// What a DoH response says of its content, which the engine reads (docs/design.md §24, DoH over
/// HTTP/3): its final status, its `Age`, and whether it is a DNS message in no content coding.
pub const Http = struct { status: u16, age_seconds: u32, dns_message: bool };

/// The `Age` in seconds, from the value of the response's first `Age` line, or null for none. 0
/// when there is none, or when it is not a number.
pub fn age_seconds(value: ?[]const u8) u32 {
    // "a cache encountering a message with a list-based Age field value SHOULD use the first
    // member of the field value, discarding subsequent ones" (RFC 9111 §5.1).
    const member = first_member(value orelse return 0) orelse return 0;
    // `Age = delta-seconds`, `delta-seconds = 1*DIGIT` (§5.1, §1.2.2). "If the field value ... is
    // invalid ..., a cache SHOULD ignore the field" (§5.1).
    for (member) |octet| if (!std.ascii.isDigit(octet)) return 0;
    // "If a cache receives a delta-seconds value greater than the greatest integer it can
    // represent, ... the cache MUST consider the value to be 2147483648 (2^31)" (§1.2.2).
    const seconds = std.fmt.parseInt(u64, member, decimal) catch return age_seconds_max;
    return @intCast(@min(seconds, age_seconds_max));
}

/// RFC 9111 §1.2.2's 2^31, "infinity (over 68 years)".
pub const age_seconds_max: u32 = 2147483648;
const decimal = 10;

/// Whether the content is `application/dns-message` (RFC 8484 §6), from the value of the response's
/// first `Content-Type` line, or null for none.
pub fn is_dns_message(content_type: ?[]const u8) bool {
    // With no Content-Type, "the recipient MAY either assume a media type of
    // "application/octet-stream" ... or examine the data" (RFC 9110 §8.3): not a DNS message.
    const value = content_type orelse return false;
    // `media-type = type "/" subtype parameters`, and "The type and subtype tokens are
    // case-insensitive" (RFC 9110 §8.3.1). No parameter of this type changes what the content is.
    const end = std.mem.indexOfScalar(u8, value, ';') orelse value.len;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, value[0..end], whitespace), "application/dns-message");
}

/// Whether one `Content-Encoding` line names no coding but `identity`: `Content-Encoding =
/// #content-coding`, and "All content codings are case-insensitive" (RFC 9110 §8.4, §8.4.1). A
/// response whose content was coded carries something other than a DNS message.
pub fn is_identity(content_encoding: []const u8) bool {
    var members = std.mem.splitScalar(u8, content_encoding, ',');
    // Bounded by the value's octets: each member but the last ends at a comma.
    for (0..content_encoding.len + 1) |_| {
        const member = members.next() orelse break;
        const coding = std.mem.trim(u8, member, whitespace);
        // "a recipient MUST parse and ignore a reasonable number of empty list elements" (RFC
        // 9110 §5.6.1.2).
        if (coding.len == 0) continue;
        if (!std.ascii.eqlIgnoreCase(coding, "identity")) return false;
    }
    return true;
}

/// `OWS = *( SP / HTAB )` (RFC 9110 §5.6.3).
const whitespace = " \t";

/// The first member of a list that is not empty (RFC 9110 §5.6.1.2), or null.
fn first_member(value: []const u8) ?[]const u8 {
    var members = std.mem.splitScalar(u8, value, ',');
    // Bounded by the value's octets: each member but the last ends at a comma.
    for (0..value.len + 1) |_| {
        const member = std.mem.trim(u8, members.next() orelse return null, whitespace);
        if (member.len > 0) return member;
    }
    return null;
}

// Tests.

const testing = std.testing;

test "an Age is its first member's seconds, and 0 when there is none or it is not a number" {
    try testing.expectEqual(@as(u32, 0), age_seconds(null));
    try testing.expectEqual(@as(u32, 250), age_seconds("250"));
    try testing.expectEqual(@as(u32, 250), age_seconds("250, 17"));
    try testing.expectEqual(@as(u32, 9), age_seconds(" , 9"));
    try testing.expectEqual(@as(u32, 0), age_seconds(""));
    try testing.expectEqual(@as(u32, 0), age_seconds("abc"));
    try testing.expectEqual(@as(u32, 0), age_seconds("-1"));
    try testing.expectEqual(@as(u32, 0), age_seconds("1.5"));
}

test "an Age past 2^31 is 2^31" {
    try testing.expectEqual(@as(u32, 2147483647), age_seconds("2147483647"));
    try testing.expectEqual(age_seconds_max, age_seconds("2147483648"));
    try testing.expectEqual(age_seconds_max, age_seconds("4294967296"));
    try testing.expectEqual(age_seconds_max, age_seconds("99999999999999999999999"));
}

test "the content is a DNS message by its media type, in any case and with any parameter" {
    try testing.expect(is_dns_message("application/dns-message"));
    try testing.expect(is_dns_message("Application/DNS-Message"));
    try testing.expect(is_dns_message("application/dns-message; charset=x"));
    try testing.expect(is_dns_message("application/dns-message ;x=y"));
    try testing.expect(!is_dns_message(null));
    try testing.expect(!is_dns_message("text/html"));
    try testing.expect(!is_dns_message("application/dns-json"));
    try testing.expect(!is_dns_message("application/dns-message+json"));
}

test "content is in no coding when every coding a line names is identity" {
    try testing.expect(is_identity("identity"));
    try testing.expect(is_identity("IDENTITY"));
    try testing.expect(is_identity("identity, , identity"));
    try testing.expect(is_identity(""));
    try testing.expect(!is_identity("gzip"));
    try testing.expect(!is_identity("identity, gzip"));
    try testing.expect(!is_identity(" br "));
}
