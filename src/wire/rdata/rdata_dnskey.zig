//! DNSKEY: flags, protocol and algorithm, then the public key (RFC 4034 §2.1). cocuyo reads the
//! fields and verifies nothing (docs/design.md §25, step 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");

pub const Dnskey = struct {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: []const u8,

    pub fn parse(rdata: []const u8) Error!Dnskey {
        if (rdata.len < constants.dnskey_fixed_bytes) return Error.MalformedMessage;
        assert(rdata.len >= constants.dnskey_fixed_bytes);
        return .{
            .flags = integer.read_u16(rdata, 0),
            .protocol = rdata[constants.dnskey_protocol_offset],
            .algorithm = rdata[constants.dnskey_algorithm_offset],
            .public_key = rdata[constants.dnskey_fixed_bytes..],
        };
    }

    /// Whether the key is a zone key: without the flag it "MUST NOT be used to verify RRSIGs that
    /// cover RRsets" (RFC 4034 §2.1.1).
    pub fn zone_key(self: Dnskey) bool {
        return self.flags & constants.dnskey_flag_zone_key != 0;
    }

    /// The Secure Entry Point flag, a hint to signing software: "validators MUST NOT alter their
    /// behavior during the signature validation process in any way based on the setting of this
    /// bit" (RFC 4034 §2.1.1).
    pub fn secure_entry_point(self: Dnskey) bool {
        return self.flags & constants.dnskey_flag_secure_entry_point != 0;
    }

    /// Whether the protocol field holds 3: "If the value of the Protocol Field is not 3, the
    /// DNSKEY RR MUST be treated as invalid during signature verification" (RFC 4034 §2.1.2).
    pub fn protocol_valid(self: Dnskey) bool {
        return self.protocol == constants.dnskey_protocol;
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "RFC 4034 §5.4's DNSKEY is a zone key of protocol 3 and algorithm 5, with no SEP flag" {
    var bytes: [fixtures.dnskey_example_bytes]u8 = undefined;
    const key = try Dnskey.parse(fixtures.dnskey_example(&bytes));
    try testing.expectEqual(@as(u16, 256), key.flags);
    try testing.expect(key.zone_key());
    try testing.expect(!key.secure_entry_point());
    try testing.expect(key.protocol_valid());
    try testing.expectEqual(@as(u8, 5), key.algorithm);
    try testing.expectEqual(fixtures.dnskey_example_bytes - constants.dnskey_fixed_bytes, key.public_key.len);
}

test "a DNSKEY short of its fixed octets is malformed, and another protocol is not valid" {
    try testing.expectError(Error.MalformedMessage, Dnskey.parse(&.{ 0x01, 0x00, 0x03 }));
    const other = try Dnskey.parse(&.{ 0x01, 0x01, 0x02, 0x0d });
    try testing.expect(!other.protocol_valid());
    try testing.expect(other.zone_key() and other.secure_entry_point());
}
