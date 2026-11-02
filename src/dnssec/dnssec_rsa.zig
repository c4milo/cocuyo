//! The form of an RSA key, read before a check hands it to the verifier (docs/design.md §25, New
//! limits): "exponent length 1 or 3 octets", the exponent, then the modulus in the "remaining
//! space" (RFC 3110 §2, which RFC 5702 §2 points to for algorithms 8 and 10). A key outside the
//! bounds is passed over, as a key of an algorithm the verifier does not check is.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const limits = @import("limits.zig");

/// Whether `public_key`, the Public Key field of a DNSKEY of `algorithm`, is one a check may use.
/// A key of any algorithm but 8 or 10 is left to the verifier.
pub fn usable(algorithm: u8, public_key: []const u8) bool {
    if (algorithm != constants.algorithm_rsa_sha256 and algorithm != constants.algorithm_rsa_sha512) return true;
    if (public_key.len == 0) return false;
    var at: usize = 1;
    var exponent_bytes: usize = public_key[0];
    // "a zero octet followed by a two octet unsigned length if it is longer than 255 bytes" (RFC
    // 3110 §2).
    if (exponent_bytes == 0) {
        if (public_key.len < constants.rsa_exponent_length_long_bytes) return false;
        exponent_bytes = std.mem.readInt(u16, public_key[1..constants.rsa_exponent_length_long_bytes], .big);
        at = constants.rsa_exponent_length_long_bytes;
    }
    // A bound on what one check costs (§25, New limits).
    if (exponent_bytes == 0 or exponent_bytes > limits.rsa_exponent_bytes_max) return false;
    // The modulus takes the "remaining space", which must hold one octet at least.
    if (public_key.len <= at + exponent_bytes) return false;
    const exponent = public_key[at..][0..exponent_bytes];
    const modulus = public_key[at + exponent_bytes ..];
    assert(exponent.len >= 1 and modulus.len >= 1);
    // "Leading zero octets are prohibited in the exponent and modulus" (RFC 3110 §2).
    if (exponent[0] == 0 or modulus[0] == 0) return false;
    const bits = modulus.len * @bitSizeOf(u8) - @clz(modulus[0]);
    // RFC 5702 §2's ceiling, and §25's floor, which is above RFC 5702 §2's 512 bits.
    return bits >= limits.rsa_modulus_bits_min and bits <= limits.rsa_modulus_bits_max;
}

// Tests.

const testing = std.testing;
const wire = @import("wire");
const fixtures = @import("fixtures.zig");
const rrset = @import("dnssec_rrset.zig");

/// Any octet of a test's modulus after its first, which sets the key's size.
const modulus_filler: u8 = 0xa5;

/// A key of `exponent` and a modulus of `modulus_bytes` octets, its first `first`.
fn key(out: []u8, exponent: []const u8, modulus_bytes: usize, first: u8) []const u8 {
    out[0] = @intCast(exponent.len);
    @memcpy(out[1..][0..exponent.len], exponent);
    const modulus = out[1 + exponent.len ..][0..modulus_bytes];
    @memset(modulus, modulus_filler);
    modulus[0] = first;
    return out[0 .. 1 + exponent.len + modulus_bytes];
}

test "an RSA key of 1024 to 4096 bits is usable, and one outside them is not" {
    var buffer: [1 + 8 + 520]u8 = undefined;
    const f4 = [_]u8{ 1, 0, 1 };
    try testing.expect(usable(8, key(&buffer, &f4, 128, 0x80)));
    try testing.expect(usable(10, key(&buffer, &f4, 512, 0xff)));
    // 1,023 bits, then 512 bits: RFC 5702 §6.1's key size, which RFC 5702 §2 allows and §25 does
    // not.
    try testing.expect(!usable(8, key(&buffer, &f4, 128, 0x7f)));
    try testing.expect(!usable(8, key(&buffer, &f4, 64, 0xc1)));
    // 4,097 bits.
    try testing.expect(!usable(8, key(&buffer, &f4, 513, 0x01)));
    // Another algorithm is left to the verifier.
    try testing.expect(usable(13, key(&buffer, &f4, 64, 0xc1)));
}

test "an RSA key of the wrong form is not usable" {
    var buffer: [1 + 9 + 260]u8 = undefined;
    const f4 = [_]u8{ 1, 0, 1 };
    // No key; leading zeros in the exponent and in the modulus; no modulus at all.
    try testing.expect(!usable(8, ""));
    try testing.expect(!usable(8, key(&buffer, &.{ 0, 1, 0, 1 }, 128, 0x80)));
    try testing.expect(!usable(8, key(&buffer, &f4, 129, 0x00)));
    try testing.expect(!usable(8, &.{ 3, 1, 0, 1 }));
    // An exponent past `rsa_exponent_bytes_max`, and one of eight octets, which is not.
    try testing.expect(!usable(8, key(&buffer, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 }, 128, 0x80)));
    try testing.expect(usable(8, key(&buffer, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, 128, 0x80)));
    // The three-octet length: zero, then a length of three, then the exponent.
    var long: [3 + 3 + 128]u8 = undefined;
    long[0..6].* = .{ 0, 0, 3, 1, 0, 1 };
    @memset(long[6..], 0xa5);
    try testing.expect(usable(8, &long));
    // A three-octet length cut short.
    try testing.expect(!usable(8, &.{ 0, 0 }));
}

test "an RSA key or a signature outside §25's bounds is passed over before the verifier" {
    var sums: fixtures.Sums = .{};
    const verifier = sums.verifier();
    var buffer: [18 + 9 + limits.signature_bytes_max + 1]u8 = undefined;
    // 1,024 bits are handed on, and 512, which RFC 5702 §2 allows, are not.
    const usable_key = fixtures.rsa_key(128);
    const parsed = try wire.rdata.Dnskey.parse(&usable_key);
    try testing.expect(rrset.names(verifier, &try fixtures.rsa_rrsig(&buffer, &usable_key, 128), &usable_key, &parsed));
    const small_key = fixtures.rsa_key(64);
    const small = try wire.rdata.Dnskey.parse(&small_key);
    try testing.expect(!rrset.names(verifier, &try fixtures.rsa_rrsig(&buffer, &small_key, 64), &small_key, &small));
    // A signature of `signature_bytes_max` octets is handed on, and one octet more is not.
    try testing.expect(rrset.names(verifier, &try fixtures.rsa_rrsig(&buffer, &usable_key, limits.signature_bytes_max), &usable_key, &parsed));
    try testing.expect(!rrset.names(verifier, &try fixtures.rsa_rrsig(&buffer, &usable_key, limits.signature_bytes_max + 1), &usable_key, &parsed));
}
