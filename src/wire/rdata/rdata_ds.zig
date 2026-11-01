//! DS: the key tag, algorithm and digest type of a DNSKEY in the child zone, then the digest of it
//! (RFC 4034 §5.1). cocuyo reads the fields and verifies nothing (docs/design.md §25, step 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");

pub const Ds = struct {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: []const u8,

    pub fn parse(rdata: []const u8) Error!Ds {
        if (rdata.len < constants.ds_fixed_bytes) return Error.MalformedMessage;
        assert(rdata.len >= constants.ds_fixed_bytes);
        return .{
            .key_tag = integer.read_u16(rdata, 0),
            .algorithm = rdata[constants.ds_algorithm_offset],
            .digest_type = rdata[constants.ds_digest_type_offset],
            .digest = rdata[constants.ds_fixed_bytes..],
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "RFC 4034 §5.4's DS reads back as key tag 60485, algorithm 5, digest type 1 and its digest" {
    const ds = try Ds.parse(&fixtures.ds_example);
    try testing.expectEqual(@as(u16, 60485), ds.key_tag);
    try testing.expectEqual(@as(u8, 5), ds.algorithm);
    try testing.expectEqual(@as(u8, 1), ds.digest_type);
    try testing.expectEqualSlices(u8, &fixtures.ds_example_digest, ds.digest);
}

test "a DS short of its four fixed octets is malformed" {
    try testing.expectError(Error.MalformedMessage, Ds.parse(fixtures.ds_example[0 .. constants.ds_fixed_bytes - 1]));
}
