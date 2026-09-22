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

/// Writes the OPT record at the start of `out` and returns the octets written.
pub fn write(payload_bytes: u16, out: []u8) usize {
    assert(payload_bytes >= core.constants.udp_payload_bytes_min);
    assert(out.len >= core.constants.opt_record_bytes);
    var offset: usize = 0;
    out[offset] = 0; // the root owner name, one octet
    offset += 1;
    integer.write_u16(out, offset, core.Kind.opt.code());
    offset += constants.u16_bytes;
    integer.write_u16(out, offset, payload_bytes);
    offset += constants.u16_bytes;
    integer.write_u32(out, offset, 0); // extended rcode 0, version 0, no flags
    offset += constants.u32_bytes;
    integer.write_u16(out, offset, 0); // no rdata
    offset += constants.u16_bytes;
    assert(offset == core.constants.opt_record_bytes);
    return offset;
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
    var out: [core.constants.opt_record_bytes]u8 = @splat(0xff);
    const written = write(core.constants.udp_payload_bytes_default, &out);
    try testing.expectEqual(core.constants.opt_record_bytes, written);
    try testing.expectEqualSlices(u8, &.{
        0x00, // root owner
        0x00, 0x29, // type OPT, 41
        0x04, 0xd0, // class: 1232
        0x00, 0x00, 0x00, 0x00, // extended rcode 0, version 0, no flags
        0x00, 0x00, // rdlength 0
    }, &out);
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
    var out: [core.constants.opt_record_bytes]u8 = @splat(0);
    _ = write(core.constants.udp_payload_bytes_default, &out);
    const class = integer.read_u16(&out, 3);
    const ttl = integer.read_u32(&out, 5);
    const opt = try parse(class, ttl);
    try testing.expectEqual(core.constants.udp_payload_bytes_default, opt.payload_bytes);
    try testing.expectEqual(@as(u8, 0), opt.extended_rcode_high);
    try testing.expect(!opt.dnssec_ok());
}
