//! MX: a 16-bit preference and the exchange name (RFC 1035 §3.3.9).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const rdata_name = @import("rdata_name.zig");

pub const Mx = struct {
    preference: u16,
    exchange: Name,

    pub fn parse(rdata: []const u8) Error!Mx {
        if (rdata.len < constants.mx_fixed_bytes) return Error.MalformedMessage;
        var exchange: Name = Name.empty;
        const end = try rdata_name.read(rdata, constants.mx_fixed_bytes, &exchange);
        if (end != rdata.len) return Error.MalformedMessage;
        assert(exchange.len >= 1);
        return .{ .preference = integer.read_u16(rdata, 0), .exchange = exchange };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "an MX record is a preference and an exchange" {
    const mx = try Mx.parse(&fixtures.mx);
    try testing.expectEqual(@as(u16, 10), mx.preference);
    try testing.expect(mx.exchange.equal(&try Name.from_text("mail.example.com")));
}

test "an MX record without room for its preference, or with octets after its name, is malformed" {
    try testing.expectError(Error.MalformedMessage, Mx.parse(&fixtures.mx_short));
    try testing.expectError(Error.MalformedMessage, Mx.parse(&fixtures.mx_trailing));
}
