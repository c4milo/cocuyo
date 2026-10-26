//! CAA: a flags octet, a tag length, the tag, and the value that fills the rest
//! (RFC 8659 §4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");
const limits = @import("../limits.zig");

pub const Caa = struct {
    flags: u8,
    tag: []const u8,
    value: []const u8,

    pub fn parse(rdata: []const u8) Error!Caa {
        if (rdata.len < constants.caa_fixed_bytes) return Error.MalformedMessage;
        const tag_length: usize = rdata[constants.caa_tag_length_offset];
        // "The tag length MUST be at least 1" (RFC 8659 §4.1).
        if (tag_length < limits.caa_tag_bytes_min) return Error.MalformedMessage;
        const tag_start = constants.caa_fixed_bytes;
        if (tag_start + tag_length > rdata.len) return Error.MalformedMessage;
        const tag = rdata[tag_start..][0..tag_length];
        // "Tags MUST NOT contain any other characters" than ASCII letters and digits (§4.1).
        for (tag) |byte| {
            if (!std.ascii.isAlphanumeric(byte)) return Error.MalformedMessage;
        }
        assert(tag.len >= limits.caa_tag_bytes_min);
        return .{ .flags = rdata[0], .tag = tag, .value = rdata[tag_start + tag_length ..] };
    }

    /// The issuer-critical flag (RFC 8659 §4.1): a CA must not issue for a tag it does not know.
    pub fn critical(self: *const Caa) bool {
        return self.flags & constants.caa_flag_critical != 0;
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a CAA record is a flag, a tag and a value, and the critical bit is the high one" {
    const caa = try Caa.parse(&fixtures.caa);
    try testing.expectEqualStrings("issue", caa.tag);
    try testing.expectEqualStrings("ca.example.net", caa.value);
    try testing.expect(!caa.critical());
    const critical = try Caa.parse(&fixtures.caa_critical);
    try testing.expect(critical.critical());
    try testing.expectEqualStrings("", critical.value);
}

test "a CAA record with an empty tag, a tag past the rdata, or a tag with a bad character is malformed" {
    try testing.expectError(Error.MalformedMessage, Caa.parse(&fixtures.caa_tag_zero));
    try testing.expectError(Error.MalformedMessage, Caa.parse(&fixtures.caa_tag_past_end));
    try testing.expectError(Error.MalformedMessage, Caa.parse(&fixtures.caa_tag_bad_char));
    try testing.expectError(Error.MalformedMessage, Caa.parse(&fixtures.caa_short));
}

test "RFC 8659 §4.2's CAAs read back as their flags, tag and value, the one that forbids issuance too" {
    const issue = try Caa.parse(&fixtures.rfc8659_caa);
    try testing.expectEqual(@as(u8, 0), issue.flags);
    try testing.expectEqualStrings("issue", issue.tag);
    try testing.expectEqualStrings("ca1.example.net", issue.value);
    const none = try Caa.parse(&fixtures.rfc8659_caa_none);
    try testing.expectEqualStrings("issue", none.tag);
    try testing.expectEqualStrings(";", none.value);
}

test "a tag of 255 octets, the longest its length octet says, reads back, and one octet short is malformed" {
    // The tag length is "A single octet" (RFC 8659 §4.1), so 255 is the longest. The tag ends at
    // octet 257, after the flags and the length.
    const longest = std.math.maxInt(u8);
    const rdata = [_]u8{ 0, longest } ++ [_]u8{'a'} ** longest ++ "v".*;
    const caa = try Caa.parse(&rdata);
    try testing.expectEqual(@as(usize, longest), caa.tag.len);
    try testing.expectEqualStrings("v", caa.value);
    // A tag that ends at the last octet of the rdata leaves an empty value, and reads back too.
    const bare = try Caa.parse(rdata[0 .. rdata.len - 1]);
    try testing.expectEqual(@as(usize, longest), bare.tag.len);
    try testing.expectEqual(@as(usize, 0), bare.value.len);
    try testing.expectError(Error.MalformedMessage, Caa.parse(rdata[0 .. rdata.len - 2]));
}
