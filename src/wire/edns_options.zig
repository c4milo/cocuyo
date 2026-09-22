//! The EDNS0 options a response may carry besides the cookie: the name server's identifier, the
//! client subnet it answered for, the padding it added, and what it says went wrong.
//!
//! Each is read from the OPT record's rdata, which `edns.zig` gets from `response_opt.find`. None
//! of them changes what a lookup does: cocuyo reads them so a caller can, which is what c-ares
//! gives its callers (docs/design.md §19 step 10). The cookie is `edns.find_cookie`, because the
//! state machine acts on that one.
//!
//! A reader returns the first option of its code and ignores the rest, as the cookie does
//! (RFC 7873 §5.3), and refuses an option whose length its RFC does not allow.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("constants.zig");
const integer = @import("integer.zig");
const rdata_opt = @import("rdata/rdata_opt.zig");

/// The first option of `code` in `rdata`, or null when there is none.
fn first(rdata: []const u8, code: u16) Error!?[]const u8 {
    var options: rdata_opt.Options = .{ .rdata = rdata };
    while (try options.next()) |option| {
        if (option.code == code) return option.data;
    }
    return null;
}

/// The NSID option: an opaque byte string whose meaning is "deliberately left outside the
/// protocol" (RFC 5001 §2.3). Any length is legal, the empty one included, which is what a query
/// carries to ask for one (§2.1).
pub fn nsid(rdata: []const u8) Error!?[]const u8 {
    return first(rdata, constants.nsid_option_code);
}

/// The Padding option: octets that carry nothing, so that a message's length says less about what
/// is in it (RFC 7830 §3). It must appear at most once per OPT record, so a second is a message
/// to refuse.
pub fn padding(rdata: []const u8) Error!?[]const u8 {
    var options: rdata_opt.Options = .{ .rdata = rdata };
    var found: ?[]const u8 = null;
    while (try options.next()) |option| {
        if (option.code != constants.padding_option_code) continue;
        // "The 'Padding' option MUST occur at most, once per OPT meta-RR" (RFC 7830 §3).
        if (found != null) return Error.MalformedMessage;
        found = option.data;
    }
    return found;
}

/// What the client subnet option says (RFC 7871 §6): the family of the address, how many of its
/// leftmost bits the query asked about, how many the answer covers, and those bits.
pub const ClientSubnet = struct {
    family: core.Family,
    source_prefix_bits: u8,
    scope_prefix_bits: u8,
    /// The address, zero-padded to the whole octets `source_prefix_bits` needs.
    address: core.Address,
};

/// The first client subnet option, or null when there is none.
///
/// Refused, because RFC 7871 §6 says a receiver should refuse each: a family that is neither of
/// the two the document defines, a prefix longer than the family's address, an address of too few
/// or too many octets, and a bit set beyond the source prefix.
pub fn client_subnet(rdata: []const u8) Error!?ClientSubnet {
    const data = try first(rdata, constants.client_subnet_option_code) orelse return null;
    if (data.len < constants.client_subnet_fixed_bytes) return Error.MalformedMessage;
    const family = family_of(integer.read_u16(data, 0)) orelse return Error.MalformedMessage;
    const source_prefix_bits = data[constants.client_subnet_source_offset];
    const scope_prefix_bits = data[constants.client_subnet_scope_offset];
    const address_bytes = family.address_bytes();
    if (source_prefix_bits > address_bytes * constants.bits_per_octet) return Error.MalformedMessage;
    const octets = data[constants.client_subnet_fixed_bytes..];
    if (octets.len != prefix_octets(source_prefix_bits)) return Error.MalformedMessage;
    var full: [core.constants.address_v6_bytes]u8 = @splat(0);
    @memcpy(full[0..octets.len], octets);
    if (has_bits_past(octets, source_prefix_bits)) return Error.MalformedMessage;
    return .{
        .family = family,
        .source_prefix_bits = source_prefix_bits,
        .scope_prefix_bits = scope_prefix_bits,
        .address = switch (family) {
            .ipv4 => core.Address.from_v4(full[0..core.constants.address_v4_bytes].*),
            .ipv6 => core.Address.from_v6(full),
        },
    };
}

/// The families RFC 7871 §6 defines a format for, by their IANA Address Family Number.
fn family_of(code: u16) ?core.Family {
    return switch (code) {
        constants.client_subnet_family_ipv4 => .ipv4,
        constants.client_subnet_family_ipv6 => .ipv6,
        else => null,
    };
}

/// The whole octets a prefix of `bits` needs: "padding with 0 bits to pad to the end of the last
/// octet needed" (RFC 7871 §6).
fn prefix_octets(bits: u8) usize {
    return (@as(usize, bits) + constants.bits_per_octet - 1) / constants.bits_per_octet;
}

/// Whether any bit is set past `bits`, which RFC 7871 §6 refuses.
fn has_bits_past(octets: []const u8, bits: u8) bool {
    const whole = bits / constants.bits_per_octet;
    if (whole >= octets.len) return false;
    const rest: u3 = @intCast(bits % constants.bits_per_octet);
    const keep: u8 = if (rest == 0) 0 else ~(@as(u8, std.math.maxInt(u8)) >> rest);
    return (octets[whole] & ~keep) != 0;
}

/// What the extended error option says (RFC 8914 §2): a code into the registry §5.2 creates, and
/// text that is "not intended for end users" but for whoever is debugging.
pub const ExtendedError = struct {
    info_code: u16,
    /// UTF-8, and not null-terminated: "If the EXTRA-TEXT field is empty, it is zero length"
    /// (RFC 8914 §2).
    extra_text: []const u8,
};

/// The first extended error option, or null when there is none. An option shorter than its info
/// code is malformed: the length "should be 2 plus the length of the EXTRA-TEXT field"
/// (RFC 8914 §2).
pub fn extended_error(rdata: []const u8) Error!?ExtendedError {
    const data = try first(rdata, constants.extended_error_option_code) orelse return null;
    if (data.len < constants.extended_error_fixed_bytes) return Error.MalformedMessage;
    return .{
        .info_code = integer.read_u16(data, 0),
        .extra_text = data[constants.extended_error_fixed_bytes..],
    };
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const rdata_fixtures = @import("rdata/fixtures.zig");

test "the name server identifier comes back as it was sent, empty or not" {
    try testing.expectEqualSlices(u8, &fixtures.nsid_text, (try nsid(&fixtures.opt_nsid)).?);
    try testing.expectEqual(@as(usize, 0), (try nsid(&rdata_fixtures.opt_nsid_only)).?.len);
    try testing.expectEqual(@as(?[]const u8, null), try nsid(&fixtures.opt_extended_error));
}

test "padding comes back, and a second one is a message to refuse" {
    try testing.expectEqual(@as(usize, fixtures.padding_bytes), (try padding(&fixtures.opt_padding)).?.len);
    try testing.expectEqual(@as(?[]const u8, null), try padding(&fixtures.opt_nsid));
    try testing.expectError(Error.MalformedMessage, padding(&fixtures.opt_padding_twice));
}

test "a client subnet reads its family, its prefixes and its address" {
    const subnet = (try client_subnet(&fixtures.opt_client_subnet)).?;
    try testing.expectEqual(core.Family.ipv4, subnet.family);
    try testing.expectEqual(@as(u8, 24), subnet.source_prefix_bits);
    try testing.expectEqual(@as(u8, 20), subnet.scope_prefix_bits);
    try testing.expect(subnet.address.equal(&core.Address.from_v4(.{ 192, 0, 2, 0 })));
    try testing.expectEqual(@as(?ClientSubnet, null), try client_subnet(&fixtures.opt_nsid));
}

test "a client subnet of the wrong shape is refused, each way RFC 7871 §6 names" {
    try testing.expectError(Error.MalformedMessage, client_subnet(&fixtures.opt_client_subnet_family));
    try testing.expectError(Error.MalformedMessage, client_subnet(&fixtures.opt_client_subnet_long_prefix));
    try testing.expectError(Error.MalformedMessage, client_subnet(&fixtures.opt_client_subnet_short_address));
    try testing.expectError(Error.MalformedMessage, client_subnet(&fixtures.opt_client_subnet_long_address));
    try testing.expectError(Error.MalformedMessage, client_subnet(&fixtures.opt_client_subnet_stray_bit));
}

test "an extended error reads its code and its text, and a short one is refused" {
    const extended = (try extended_error(&fixtures.opt_extended_error)).?;
    try testing.expectEqual(@as(u16, fixtures.extended_error_code), extended.info_code);
    try testing.expectEqualStrings(fixtures.extended_error_text, extended.extra_text);
    const bare = (try extended_error(&fixtures.opt_extended_error_bare)).?;
    try testing.expectEqual(@as(usize, 0), bare.extra_text.len);
    try testing.expectError(Error.MalformedMessage, extended_error(&fixtures.opt_extended_error_short));
}
