//! SIG: type covered, algorithm, labels, original TTL, expiration, inception and key tag, then
//! the signer's name and the signature (RFC 2535 §4.1). The type survives its RFC through
//! SIG(0), the transaction signature of RFC 2931, whose format is this one; cocuyo reads the
//! fields and verifies nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const rdata_name = @import("rdata_name.zig");

pub const Sig = struct {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: Name,
    signature: []const u8,

    pub fn parse(rdata: []const u8) Error!Sig {
        if (rdata.len < constants.sig_fixed_bytes) return Error.MalformedMessage;
        var signer: Name = Name.empty;
        const after_signer = try rdata_name.read(rdata, constants.sig_fixed_bytes, &signer);
        assert(after_signer <= rdata.len);
        return .{
            .type_covered = integer.read_u16(rdata, 0),
            .algorithm = rdata[constants.sig_algorithm_offset],
            .labels = rdata[constants.sig_labels_offset],
            .original_ttl = integer.read_u32(rdata, constants.sig_original_ttl_offset),
            .expiration = integer.read_u32(rdata, constants.sig_expiration_offset),
            .inception = integer.read_u32(rdata, constants.sig_inception_offset),
            .key_tag = integer.read_u16(rdata, constants.sig_key_tag_offset),
            .signer = signer,
            .signature = rdata[after_signer..],
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a SIG record's fixed fields, signer and signature read back" {
    const sig = try Sig.parse(&fixtures.sig);
    try testing.expectEqual(@as(u16, 0), sig.type_covered);
    try testing.expectEqual(@as(u8, 13), sig.algorithm);
    try testing.expectEqual(@as(u8, 2), sig.labels);
    try testing.expectEqual(@as(u32, 0), sig.original_ttl);
    try testing.expectEqual(@as(u32, 0x5f000000), sig.expiration);
    try testing.expectEqual(@as(u32, 0x5e000000), sig.inception);
    try testing.expectEqual(@as(u16, 0x1234), sig.key_tag);
    try testing.expect(sig.signer.equal(&try Name.from_text("example.com")));
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, sig.signature);
}

test "a SIG record short of its fixed fields is malformed, and an empty signature is not" {
    try testing.expectError(Error.MalformedMessage, Sig.parse(&fixtures.sig_short));
    const bare = try Sig.parse(&fixtures.sig_no_signature);
    try testing.expectEqual(@as(usize, 0), bare.signature.len);
}
