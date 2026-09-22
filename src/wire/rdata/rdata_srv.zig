//! SRV: priority, weight and port, 16 bits each, and the target name (RFC 2782, "The format of
//! the SRV RR"). The RFC has the target sent uncompressed; a compressed one is written out by the
//! collector before it gets here (RFC 3597 §4, docs/design.md §19 step 9).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const rdata_name = @import("rdata_name.zig");

pub const Srv = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,

    pub fn parse(rdata: []const u8) Error!Srv {
        if (rdata.len < constants.srv_fixed_bytes) return Error.MalformedMessage;
        var target: Name = Name.empty;
        const end = try rdata_name.read(rdata, constants.srv_fixed_bytes, &target);
        if (end != rdata.len) return Error.MalformedMessage;
        assert(target.len >= 1);
        return .{
            .priority = integer.read_u16(rdata, 0),
            .weight = integer.read_u16(rdata, constants.srv_weight_offset),
            .port = integer.read_u16(rdata, constants.srv_port_offset),
            .target = target,
        };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "an SRV record is a priority, a weight, a port and a target" {
    const srv = try Srv.parse(&fixtures.srv);
    try testing.expectEqual(@as(u16, 10), srv.priority);
    try testing.expectEqual(@as(u16, 20), srv.weight);
    try testing.expectEqual(@as(u16, 5269), srv.port);
    try testing.expect(srv.target.equal(&try Name.from_text("sip.example.com")));
}

test "an SRV record short of its fixed fields, or long past its target, is malformed" {
    try testing.expectError(Error.MalformedMessage, Srv.parse(&fixtures.srv_short));
    try testing.expectError(Error.MalformedMessage, Srv.parse(&fixtures.srv_trailing));
}
