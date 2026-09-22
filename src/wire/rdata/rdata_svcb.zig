//! SVCB and HTTPS: a 16-bit priority, the target name, and the parameters, each a 16-bit key,
//! a 16-bit length and a value (RFC 9460 §2.2). HTTPS is SVCB under another type code (§9).
//! The target is sent uncompressed (§2.2); a message that compressed it anyway is written out
//! by the collector before it gets here (RFC 3597 §4, docs/design.md §19 step 9).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const rdata_name = @import("rdata_name.zig");
const rdata_string = @import("rdata_string.zig");

pub const Svcb = struct {
    priority: u16,
    target: Name,
    /// The parameters as they sit in the rdata; `params` walks them.
    param_bytes: []const u8,

    pub fn parse(rdata: []const u8) Error!Svcb {
        if (rdata.len < constants.svcb_fixed_bytes) return Error.MalformedMessage;
        var target: Name = Name.empty;
        const after_target = try rdata_name.read(rdata, constants.svcb_fixed_bytes, &target);
        assert(after_target <= rdata.len);
        return .{
            .priority = integer.read_u16(rdata, 0),
            .target = target,
            .param_bytes = rdata[after_target..],
        };
    }

    pub fn params(self: *const Svcb) Params {
        return .{ .bytes = self.param_bytes };
    }
};

pub const Param = struct { key: u16, value: []const u8 };

/// The parameters in order. Each step consumes at least a key and a length, so the walk ends
/// within the bytes. A client takes the record as malformed when the rdata ends inside a
/// parameter, when the keys are not in strictly increasing order, or when a value does not have
/// its key's format (RFC 9460 §2.2), and each of those ends the walk in an error.
pub const Params = struct {
    bytes: []const u8,
    offset: usize = 0,
    previous_key: ?u16 = null,

    pub fn next(self: *Params) Error!?Param {
        if (self.offset == self.bytes.len) return null;
        assert(self.offset < self.bytes.len);
        if (self.offset + constants.svcb_param_fixed_bytes > self.bytes.len) return Error.MalformedMessage;
        const key = integer.read_u16(self.bytes, self.offset);
        const length: usize = integer.read_u16(self.bytes, self.offset + constants.svcb_param_length_offset);
        const start = self.offset + constants.svcb_param_fixed_bytes;
        if (start + length > self.bytes.len) return Error.MalformedMessage;
        if (self.previous_key) |previous| {
            if (key <= previous) return Error.MalformedMessage;
        }
        const param: Param = .{ .key = key, .value = self.bytes[start..][0..length] };
        try check_format(param);
        self.previous_key = key;
        self.offset = start + length;
        assert(self.offset <= self.bytes.len);
        return param;
    }
};

/// The format each key of RFC 9460 §7 gives its value, checked as §2.2 requires. A key cocuyo
/// does not know carries anything.
fn check_format(param: Param) Error!void {
    switch (param.key) {
        constants.svcb_key_mandatory => try check_mandatory(param.value),
        constants.svcb_key_alpn => try check_alpn(param.value),
        // "the presentation and wire-format values MUST be empty" (§7.1).
        constants.svcb_key_no_default_alpn => if (param.value.len != 0) return Error.MalformedMessage,
        // "the corresponding 2-octet numeric value in network byte order" (§7.2).
        constants.svcb_key_port => if (param.value.len != constants.u16_bytes) return Error.MalformedMessage,
        constants.svcb_key_ipv4hint => try check_addresses(param.value, core.constants.address_v4_bytes),
        constants.svcb_key_ipv6hint => try check_addresses(param.value, core.constants.address_v6_bytes),
        else => {},
    }
}

/// "at least one alpn-id prefixed by its length as a single octet" (§7.1), an alpn-id being
/// "a sequence of 1-255 octets".
fn check_alpn(value: []const u8) Error!void {
    if (value.len == 0) return Error.MalformedMessage;
    var ids: rdata_string.Strings = .{ .rdata = value };
    while (try ids.next()) |id| {
        if (id.len == 0) return Error.MalformedMessage;
    }
    assert(ids.offset == value.len);
}

/// "a sequence of IP addresses in network byte order" of one family, and "An empty list of
/// addresses is invalid" (§7.3).
fn check_addresses(value: []const u8, address_bytes: usize) Error!void {
    if (value.len == 0 or value.len % address_bytes != 0) return Error.MalformedMessage;
    assert(value.len >= address_bytes);
}

/// The keys the client must understand: 16 bits each, "in strictly increasing numeric order",
/// and never key 0 itself, which "MUST NOT appear in its own value-list" (§8).
fn check_mandatory(value: []const u8) Error!void {
    if (value.len == 0 or value.len % constants.u16_bytes != 0) return Error.MalformedMessage;
    var offset: usize = 0;
    var previous: ?u16 = null;
    while (offset < value.len) : (offset += constants.u16_bytes) {
        const key = integer.read_u16(value, offset);
        if (key == constants.svcb_key_mandatory) return Error.MalformedMessage;
        if (previous) |before| {
            if (key <= before) return Error.MalformedMessage;
        }
        previous = key;
    }
    assert(offset == value.len);
}

// Tests. The well-formed fixtures are RFC 9460's own vectors, Appendix D.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

fn params_of(rdata: []const u8) !Params {
    const svcb = try Svcb.parse(rdata);
    return svcb.params();
}

test "AliasMode is priority zero, a target and no parameters (D.1)" {
    const svcb = try Svcb.parse(&fixtures.svcb_alias);
    try testing.expectEqual(@as(u16, 0), svcb.priority);
    try testing.expect(svcb.target.equal(&try Name.from_text("foo.example.com")));
    var params = svcb.params();
    try testing.expectEqual(@as(?Param, null), try params.next());
}

test "a root target is a target (D.2)" {
    const svcb = try Svcb.parse(&fixtures.svcb_root);
    try testing.expectEqual(@as(u16, 1), svcb.priority);
    try testing.expect(svcb.target.is_root());
}

test "a port parameter, and a generic key with a value (D.2)" {
    var port = try params_of(&fixtures.svcb_port);
    const param = (try port.next()).?;
    try testing.expectEqual(@as(u16, constants.svcb_key_port), param.key);
    try testing.expectEqual(@as(u16, 53), integer.read_u16(param.value, 0));
    try testing.expectEqual(@as(?Param, null), try port.next());

    var generic = try params_of(&fixtures.svcb_generic);
    const key667 = (try generic.next()).?;
    try testing.expectEqual(@as(u16, 667), key667.key);
    try testing.expectEqualStrings("hello", key667.value);
}

test "two ipv6hint addresses, and the mandatory, alpn and ipv4hint of figure 9 in wire order (D.2)" {
    var hints = try params_of(&fixtures.svcb_ipv6hint);
    const hint = (try hints.next()).?;
    try testing.expectEqual(@as(u16, constants.svcb_key_ipv6hint), hint.key);
    try testing.expectEqual(@as(usize, 2 * core.constants.address_v6_bytes), hint.value.len);

    var params = try params_of(&fixtures.svcb_mandatory);
    const mandatory = (try params.next()).?;
    try testing.expectEqual(@as(u16, constants.svcb_key_mandatory), mandatory.key);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x00, 0x04 }, mandatory.value);
    const alpn = (try params.next()).?;
    try testing.expectEqual(@as(u16, constants.svcb_key_alpn), alpn.key);
    var ids: rdata_string.Strings = .{ .rdata = alpn.value };
    try testing.expectEqualStrings("h2", (try ids.next()).?);
    try testing.expectEqualStrings("h3-19", (try ids.next()).?);
    const ipv4hint = (try params.next()).?;
    try testing.expectEqual(@as(u16, constants.svcb_key_ipv4hint), ipv4hint.key);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, ipv4hint.value);
    try testing.expectEqual(@as(?Param, null), try params.next());
}

test "keys out of order, a duplicate key, and an rdata that ends inside a parameter are malformed" {
    var out_of_order = try params_of(&fixtures.svcb_keys_out_of_order);
    _ = try out_of_order.next();
    try testing.expectError(Error.MalformedMessage, out_of_order.next());
    var duplicate = try params_of(&fixtures.svcb_duplicate_key);
    _ = try duplicate.next();
    try testing.expectError(Error.MalformedMessage, duplicate.next());
    var inside = try params_of(&fixtures.svcb_ends_inside_param);
    try testing.expectError(Error.MalformedMessage, inside.next());
    var cut = try params_of(&fixtures.svcb_param_header_cut);
    try testing.expectError(Error.MalformedMessage, cut.next());
    try testing.expectError(Error.MalformedMessage, Svcb.parse(&fixtures.svcb_short));
}

test "a value without its key's format is malformed: port, alpn, no-default-alpn, the hints, mandatory" {
    const malformed = [_][]const u8{
        &fixtures.svcb_port_three_octets,
        &fixtures.svcb_alpn_empty_id,
        &fixtures.svcb_alpn_no_ids,
        &fixtures.svcb_no_default_alpn_with_value,
        &fixtures.svcb_ipv4hint_odd,
        &fixtures.svcb_ipv6hint_empty,
        &fixtures.svcb_mandatory_lists_itself,
        &fixtures.svcb_mandatory_out_of_order,
    };
    for (malformed) |rdata| {
        var params = try params_of(rdata);
        try testing.expectError(Error.MalformedMessage, params.next());
    }
}
