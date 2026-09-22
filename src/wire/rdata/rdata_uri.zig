//! URI: priority and weight, 16 bits each, then the target, which fills the rest of the rdata and
//! must not be empty (RFC 7553 §4.5).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");

pub const Uri = struct {
    priority: u16,
    weight: u16,
    target: []const u8,

    pub fn parse(rdata: []const u8) Error!Uri {
        // "The length of the Target field MUST be greater than zero" (RFC 7553 §4.5).
        if (rdata.len <= constants.uri_fixed_bytes) return Error.MalformedMessage;
        assert(rdata.len > constants.uri_fixed_bytes);
        return .{
            .priority = integer.read_u16(rdata, 0),
            .weight = integer.read_u16(rdata, constants.uri_weight_offset),
            .target = rdata[constants.uri_fixed_bytes..],
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a URI record is a priority, a weight and a target" {
    const uri = try Uri.parse(&fixtures.uri);
    try testing.expectEqual(@as(u16, 10), uri.priority);
    try testing.expectEqual(@as(u16, 1), uri.weight);
    try testing.expectEqualStrings("https://example.com/", uri.target);
}

test "a URI record with an empty target is malformed" {
    try testing.expectError(Error.MalformedMessage, Uri.parse(&fixtures.uri_empty_target));
    try testing.expectError(Error.MalformedMessage, Uri.parse(&fixtures.uri_short));
}
