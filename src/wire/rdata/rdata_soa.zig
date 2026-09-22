//! SOA: the primary server's name, the responsible mailbox as a name, then serial, refresh,
//! retry, expire and minimum, 32 bits each (RFC 1035 §3.3.13). `record.zig` reads the one field
//! a negative answer needs off the wire; this reads all seven back from stored rdata.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const rdata_name = @import("rdata_name.zig");

pub const Soa = struct {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,

    pub fn parse(rdata: []const u8) Error!Soa {
        var mname: Name = Name.empty;
        var rname: Name = Name.empty;
        const after_mname = try rdata_name.read(rdata, 0, &mname);
        const fixed = try rdata_name.read(rdata, after_mname, &rname);
        if (fixed + constants.soa_fixed_bytes != rdata.len) return Error.MalformedMessage;
        assert(fixed + constants.soa_fixed_bytes <= rdata.len);
        return .{
            .mname = mname,
            .rname = rname,
            .serial = integer.read_u32(rdata, fixed),
            .refresh = integer.read_u32(rdata, fixed + constants.soa_refresh_offset),
            .retry = integer.read_u32(rdata, fixed + constants.soa_retry_offset),
            .expire = integer.read_u32(rdata, fixed + constants.soa_expire_offset),
            .minimum = integer.read_u32(rdata, fixed + constants.soa_minimum_offset),
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "an SOA record is two names and five counters" {
    const soa = try Soa.parse(&fixtures.soa);
    try testing.expect(soa.mname.equal(&try Name.from_text("ns1.example.com")));
    try testing.expect(soa.rname.equal(&try Name.from_text("hostmaster.example.com")));
    try testing.expectEqual(@as(u32, 2026092201), soa.serial);
    try testing.expectEqual(@as(u32, 7200), soa.refresh);
    try testing.expectEqual(@as(u32, 900), soa.retry);
    try testing.expectEqual(@as(u32, 1209600), soa.expire);
    try testing.expectEqual(@as(u32, 300), soa.minimum);
}

test "an SOA record whose counters do not fill the rdata exactly is malformed, either way" {
    try testing.expectError(Error.MalformedMessage, Soa.parse(&fixtures.soa_short));
    try testing.expectError(Error.MalformedMessage, Soa.parse(&fixtures.soa_trailing));
}
