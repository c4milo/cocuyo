//! CAA: a flags octet, a tag length, the tag, and the value that fills the rest
//! (RFC 8659 §4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");

pub const Caa = struct {
    flags: u8,
    tag: []const u8,
    value: []const u8,

    pub fn parse(rdata: []const u8) Error!Caa {
        if (rdata.len < constants.caa_fixed_bytes) return Error.MalformedMessage;
        const tag_length: usize = rdata[constants.caa_tag_length_offset];
        // "The tag length MUST be at least 1" (RFC 8659 §4.1).
        if (tag_length < constants.caa_tag_bytes_min) return Error.MalformedMessage;
        const tag_start = constants.caa_fixed_bytes;
        if (tag_start + tag_length > rdata.len) return Error.MalformedMessage;
        const tag = rdata[tag_start..][0..tag_length];
        // "Tags MUST NOT contain any other characters" than ASCII letters and digits (§4.1).
        for (tag) |byte| {
            if (!std.ascii.isAlphanumeric(byte)) return Error.MalformedMessage;
        }
        assert(tag.len >= constants.caa_tag_bytes_min);
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
