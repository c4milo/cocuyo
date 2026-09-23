//! The OPT pseudo-record of EDNS0 (RFC 6891), which is how a response larger than 512 octets
//! arrives without going to TCP for everything.
//!
//! OPT is a record in the additional section with the root as its owner name. It carries no rdata
//! that cocuyo sends, and three fields in places a normal record uses for something else: the
//! class holds the requestor's UDP payload size, and the TTL holds the extended rcode's high
//! octet, the version, and the flags (RFC 6891 §6.1.3).
//!
//! Version one sets no flags. The DO bit stays clear, because cocuyo does not validate DNSSEC and
//! asking for records it will not check would be dishonest as well as wasteful (docs/design.md
//! §1). That is the seam a validator would attach to.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("constants.zig");
const integer = @import("integer.zig");
const rdata_opt = @import("rdata/rdata_opt.zig");

/// The only EDNS version cocuyo implements (RFC 6891 §6.1.3).
pub const version_supported = 0;

/// The DO bit of the flags field, which cocuyo never sets (RFC 6891 §6.1.4).
pub const flag_dnssec_ok = 0x8000;

/// Where the extended rcode's high octet sits inside the TTL field.
pub const extended_rcode_shift = 24;

/// Where the version sits inside the TTL field.
pub const version_shift = 16;

/// The low sixteen bits of the TTL field are the flags.
pub const flags_mask = 0xffff;

/// The high four bits an OPT record adds to the header's four (RFC 6891 §6.1.3).
pub const extended_rcode_mask = 0xff;

/// The DNS cookies of one server as a query carries them (RFC 7873 §4): the client cookie
/// always, and the server cookie once it has been learned.
pub const Cookie = struct {
    client: [core.constants.cookie_client_bytes]u8,
    server: [core.constants.cookie_server_bytes_max]u8,
    /// Zero until a server cookie is learned; 8 to 32 after.
    server_len: u8,

    /// The COOKIE option's octets: its code and length, then the cookies.
    pub fn option_bytes(self: *const Cookie) usize {
        assert(self.server_len == 0 or self.server_len >= core.constants.cookie_server_bytes_min);
        assert(self.server_len <= core.constants.cookie_server_bytes_max);
        return constants.opt_option_fixed_bytes + core.constants.cookie_client_bytes + self.server_len;
    }
};

/// The octets an OPT record occupies with `cookie`, or without one.
pub fn record_bytes(cookie: ?*const Cookie) usize {
    return record_bytes_padded(cookie, null);
}

/// The octets an OPT record occupies with `cookie` or without, and with a Padding option of
/// `padding` octets after it, or with none.
pub fn record_bytes_padded(cookie: ?*const Cookie, padding: ?usize) usize {
    const option: usize = if (cookie) |c| c.option_bytes() else 0;
    assert(option <= core.constants.cookie_option_bytes_max);
    const padded: usize = if (padding) |bytes| core.constants.opt_option_header_bytes + bytes else 0;
    assert(padded < core.constants.opt_option_header_bytes + core.constants.padding_block_bytes);
    return core.constants.opt_record_bytes + option + padded;
}

/// Writes the OPT record at the start of `out`, with one COOKIE option when `cookie` is given
/// (RFC 7873 §5.1), and returns the octets written.
pub fn write(payload_bytes: u16, cookie: ?*const Cookie, out: []u8) usize {
    return write_padded(payload_bytes, cookie, null, out);
}

/// `write`, and a Padding option of `padding` zero octets after the cookie when it is given
/// (RFC 7830 §3).
pub fn write_padded(payload_bytes: u16, cookie: ?*const Cookie, padding: ?usize, out: []u8) usize {
    assert(payload_bytes >= core.constants.udp_payload_bytes_min);
    assert(out.len >= core.constants.opt_record_bytes_max);
    assert(out.len >= record_bytes_padded(cookie, padding));
    var offset: usize = 0;
    out[offset] = 0; // the root owner name, one octet (RFC 6891 §6.1.2)
    offset += 1;
    integer.write_u16(out, offset, core.Kind.opt.code());
    offset += constants.u16_bytes;
    integer.write_u16(out, offset, payload_bytes);
    offset += constants.u16_bytes;
    integer.write_u32(out, offset, 0); // extended rcode 0, version 0, no flags
    offset += constants.u32_bytes;
    const rdlength = record_bytes_padded(cookie, padding) - core.constants.opt_record_bytes;
    integer.write_u16(out, offset, @intCast(rdlength));
    offset += constants.u16_bytes;
    assert(offset == core.constants.opt_record_bytes);
    if (cookie) |c| offset += write_cookie(c, out[offset..]);
    if (padding) |bytes| offset += write_padding(bytes, out[offset..]);
    assert(offset == record_bytes_padded(cookie, padding));
    return offset;
}

/// The Padding option: its code, its length, and that many octets, zero as they SHOULD be
/// (RFC 7830 §3).
fn write_padding(bytes: usize, out: []u8) usize {
    assert(bytes < core.constants.padding_block_bytes);
    integer.write_u16(out, 0, constants.padding_option_code);
    integer.write_u16(out, constants.u16_bytes, @intCast(bytes));
    const header = core.constants.opt_option_header_bytes;
    @memset(out[header..][0..bytes], 0);
    return header + bytes;
}

fn write_cookie(cookie: *const Cookie, out: []u8) usize {
    const client = core.constants.cookie_client_bytes;
    var offset: usize = 0;
    integer.write_u16(out, offset, constants.cookie_option_code);
    offset += constants.u16_bytes;
    integer.write_u16(out, offset, @intCast(client + cookie.server_len));
    offset += constants.u16_bytes;
    @memcpy(out[offset..][0..client], &cookie.client);
    offset += client;
    @memcpy(out[offset..][0..cookie.server_len], cookie.server[0..cookie.server_len]);
    offset += cookie.server_len;
    assert(offset == cookie.option_bytes());
    return offset;
}

/// The cookies a response carries: the client cookie it echoes, and the server cookie, which is
/// empty when the option is the short form.
pub const CookieView = struct {
    client: *const [core.constants.cookie_client_bytes]u8,
    server: []const u8,
};

/// The first COOKIE option in an OPT record's rdata, or null when there is none. "All but the
/// first" are ignored (RFC 7873 §5.3), and an option of a length neither form allows makes the
/// message one to discard (§5.3, §5.2.2).
pub fn find_cookie(rdata: []const u8) Error!?CookieView {
    var options: rdata_opt.Options = .{ .rdata = rdata };
    while (try options.next()) |option| {
        if (option.code != constants.cookie_option_code) continue;
        const len = option.data.len;
        const long = len >= constants.cookie_option_long_bytes_min and len <= constants.cookie_option_long_bytes_max;
        if (len != constants.cookie_option_short_bytes and !long) return Error.MalformedMessage;
        assert(len >= core.constants.cookie_client_bytes);
        return .{
            .client = option.data[0..core.constants.cookie_client_bytes],
            .server = option.data[core.constants.cookie_client_bytes..],
        };
    }
    return null;
}

/// What an OPT record in a response says.
pub const Opt = struct {
    /// The payload size the responder is willing to send or receive.
    payload_bytes: u16,
    /// The four high bits of the extended rcode, which sit above the header's four.
    extended_rcode_high: u8,
    flags: u16,

    pub fn dnssec_ok(self: *const Opt) bool {
        return self.flags & flag_dnssec_ok != 0;
    }
};

/// Reads an OPT record's fields from the class and TTL a record walk has already located. A
/// version cocuyo does not implement is an error: a responder that answers EDNS1 has not answered
/// the question cocuyo asked (RFC 6891 §6.1.3).
pub fn parse(class: u16, ttl: u32) Error!Opt {
    const version: u8 = @intCast((ttl >> version_shift) & extended_rcode_mask);
    if (version != version_supported) return Error.UnsupportedEdnsVersion;
    const opt: Opt = .{
        .payload_bytes = class,
        .extended_rcode_high = @intCast((ttl >> extended_rcode_shift) & extended_rcode_mask),
        .flags = @intCast(ttl & flags_mask),
    };
    assert(version == version_supported);
    return opt;
}

// Tests.

const testing = std.testing;

test "the OPT record cocuyo writes is eleven octets with no flags" {
    var out: [core.constants.opt_record_bytes_max]u8 = @splat(0xff);
    const written = write(core.constants.udp_payload_bytes_default, null, &out);
    try testing.expectEqual(core.constants.opt_record_bytes, written);
    try testing.expectEqualSlices(u8, &.{
        0x00, // root owner
        0x00, 0x29, // type OPT, 41
        0x04, 0xd0, // class: 1232
        0x00, 0x00, 0x00, 0x00, // extended rcode 0, version 0, no flags
        0x00, 0x00, // rdlength 0
    }, out[0..written]);
}

test "parse reads the payload size, the extended rcode and the flags" {
    const opt = try parse(1232, 0x01_00_8000);
    try testing.expectEqual(@as(u16, 1232), opt.payload_bytes);
    try testing.expectEqual(@as(u8, 1), opt.extended_rcode_high);
    try testing.expect(opt.dnssec_ok());
}

test "a version cocuyo does not implement is refused" {
    try testing.expectError(Error.UnsupportedEdnsVersion, parse(1232, 0x00_01_0000));
    _ = try parse(1232, 0);
}

test "the record cocuyo writes parses back as version 0 with no flags" {
    var out: [core.constants.opt_record_bytes_max]u8 = @splat(0);
    _ = write(core.constants.udp_payload_bytes_default, null, &out);
    const class = integer.read_u16(&out, 3);
    const ttl = integer.read_u32(&out, 5);
    const opt = try parse(class, ttl);
    try testing.expectEqual(core.constants.udp_payload_bytes_default, opt.payload_bytes);
    try testing.expectEqual(@as(u8, 0), opt.extended_rcode_high);
    try testing.expect(!opt.dnssec_ok());
}

const fixtures = @import("fixtures.zig");
const rdata_fixtures = @import("rdata/fixtures.zig");

/// A cookie whose server part is the fixture's, repeated to fill the room.
fn cookie_with(server_len: u8) Cookie {
    var cookie: Cookie = .{ .client = fixtures.cookie_client, .server = @splat(fixtures.cookie_server[1]), .server_len = server_len };
    cookie.server[0] = fixtures.cookie_server[0];
    return cookie;
}

test "a client cookie alone is the short option, and a learned server cookie makes it the long one" {
    var out: [core.constants.opt_record_bytes_max]u8 = @splat(0xff);
    const short = cookie_with(0);
    const written = write(core.constants.udp_payload_bytes_default, &short, &out);
    try testing.expectEqual(core.constants.opt_record_bytes + 4 + 8, written);
    try testing.expectEqualSlices(u8, &fixtures.opt_cookie_short_rdata, out[core.constants.opt_record_bytes..written]);
    try testing.expectEqual(@as(u16, 12), integer.read_u16(&out, core.constants.opt_record_bytes - 2));

    const long = cookie_with(16);
    const written_long = write(core.constants.udp_payload_bytes_default, &long, &out);
    try testing.expectEqual(core.constants.opt_record_bytes + 4 + 24, written_long);
    const view = (try find_cookie(out[core.constants.opt_record_bytes..written_long])).?;
    try testing.expectEqualSlices(u8, &fixtures.cookie_client, view.client);
    try testing.expectEqual(@as(usize, 16), view.server.len);
    try testing.expectEqual(@as(u8, 0xc0), view.server[0]);
}

test "the largest cookie fills the largest OPT record" {
    var out: [core.constants.opt_record_bytes_max]u8 = @splat(0);
    const largest = cookie_with(core.constants.cookie_server_bytes_max);
    try testing.expectEqual(core.constants.opt_record_bytes_max, write(core.constants.udp_payload_bytes_default, &largest, &out));
}

test "find_cookie reads the short and the long form, takes the first of two, and finds none" {
    const short = (try find_cookie(&fixtures.opt_cookie_short_rdata)).?;
    try testing.expectEqual(@as(usize, 0), short.server.len);
    const first = (try find_cookie(&fixtures.opt_two_cookies_rdata)).?;
    try testing.expectEqualSlices(u8, &fixtures.cookie_client, first.client);
    try testing.expectEqual(@as(?CookieView, null), try find_cookie(&rdata_fixtures.opt_nsid_only));
    try testing.expectEqual(@as(?CookieView, null), try find_cookie(&.{}));
}

test "a COOKIE option of a length neither form allows is malformed" {
    try testing.expectError(Error.MalformedMessage, find_cookie(&fixtures.opt_cookie_nine_rdata));
    try testing.expectError(Error.MalformedMessage, find_cookie(&fixtures.opt_cookie_fifteen_rdata));
    try testing.expectError(Error.MalformedMessage, find_cookie(&fixtures.opt_cookie_forty_one_rdata));
}
