//! NAPTR: order and preference, 16 bits each, then the flags, the services and the regexp as
//! character-strings, and the replacement name (RFC 3403 §4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const rdata_name = @import("rdata_name.zig");
const rdata_string = @import("rdata_string.zig");

pub const Naptr = struct {
    order: u16,
    preference: u16,
    flags: []const u8,
    services: []const u8,
    regexp: []const u8,
    replacement: Name,

    pub fn parse(rdata: []const u8) Error!Naptr {
        if (rdata.len < constants.naptr_fixed_bytes) return Error.MalformedMessage;
        const flags = try rdata_string.read(rdata, constants.naptr_fixed_bytes);
        const services = try rdata_string.read(rdata, flags.end);
        const regexp = try rdata_string.read(rdata, services.end);
        var replacement: Name = Name.empty;
        const end = try rdata_name.read(rdata, regexp.end, &replacement);
        if (end != rdata.len) return Error.MalformedMessage;
        assert(regexp.end < end);
        return .{
            .order = integer.read_u16(rdata, 0),
            .preference = integer.read_u16(rdata, constants.naptr_preference_offset),
            .flags = flags.bytes,
            .services = services.bytes,
            .regexp = regexp.bytes,
            .replacement = replacement,
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a NAPTR record is two counters, three strings and a name" {
    const naptr = try Naptr.parse(&fixtures.naptr);
    try testing.expectEqual(@as(u16, 100), naptr.order);
    try testing.expectEqual(@as(u16, 50), naptr.preference);
    try testing.expectEqualStrings("s", naptr.flags);
    try testing.expectEqualStrings("SIP+D2U", naptr.services);
    try testing.expectEqualStrings("", naptr.regexp);
    try testing.expect(naptr.replacement.equal(&try Name.from_text("_sip._udp.example.com")));
}

test "a NAPTR record that ends inside a string, or past its name, is malformed" {
    try testing.expectError(Error.MalformedMessage, Naptr.parse(&fixtures.naptr_short));
    try testing.expectError(Error.MalformedMessage, Naptr.parse(&fixtures.naptr_trailing));
}

test "RFC 3403 §6.1 and §6.2's NAPTRs read back field for field, a regexp and a root replacement too" {
    const urn = try Naptr.parse(&fixtures.rfc3403_naptr_urn);
    try testing.expectEqual(@as(u16, 100), urn.order);
    try testing.expectEqual(@as(u16, 50), urn.preference);
    try testing.expectEqualStrings("a", urn.flags);
    try testing.expectEqualStrings("z3950+N2L+N2C", urn.services);
    try testing.expectEqualStrings("", urn.regexp);
    try testing.expect(urn.replacement.equal(&try Name.from_text("cidserver.example.com")));
    const e164 = try Naptr.parse(&fixtures.rfc3403_naptr_e164);
    try testing.expectEqual(@as(u16, 100), e164.order);
    try testing.expectEqual(@as(u16, 10), e164.preference);
    try testing.expectEqualStrings("u", e164.flags);
    try testing.expectEqualStrings("sip+E2U", e164.services);
    try testing.expectEqualStrings("!^.*$!sip:information@foo.se!i", e164.regexp);
    try testing.expectEqualSlices(u8, "\x00", e164.replacement.wire());
}
