//! TLSA: certificate usage, selector and matching type, one octet each, then the certificate
//! association data (RFC 6698 §2.1). cocuyo hands the fields to a caller and matches nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");

pub const Tlsa = struct {
    usage: u8,
    selector: u8,
    matching_type: u8,
    data: []const u8,

    pub fn parse(rdata: []const u8) Error!Tlsa {
        if (rdata.len < constants.tlsa_fixed_bytes) return Error.MalformedMessage;
        assert(rdata.len >= constants.tlsa_fixed_bytes);
        return .{
            .usage = rdata[0],
            .selector = rdata[constants.tlsa_selector_offset],
            .matching_type = rdata[constants.tlsa_matching_type_offset],
            .data = rdata[constants.tlsa_fixed_bytes..],
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a TLSA record is three octets and the data after them" {
    const tlsa = try Tlsa.parse(&fixtures.tlsa);
    try testing.expectEqual(@as(u8, 3), tlsa.usage);
    try testing.expectEqual(@as(u8, 1), tlsa.selector);
    try testing.expectEqual(@as(u8, 1), tlsa.matching_type);
    try testing.expectEqual(@as(usize, 32), tlsa.data.len);
    try testing.expectEqual(@as(u8, 0xab), tlsa.data[0]);
}

test "a TLSA record short of its three octets is malformed" {
    try testing.expectError(Error.MalformedMessage, Tlsa.parse(&fixtures.tlsa_short));
}
