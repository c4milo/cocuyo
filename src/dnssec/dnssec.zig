//! `dnssec`: the DNS half of DNSSEC validation (docs/design.md §25, Stage B), with no cryptography
//! in it. It reads `core` and `wire`, and it hands every octet a digest or a signature covers to
//! a `Hash` the caller supplies, so a verifier over chapulin fills it in outside `src/` (§16
//! decision 35, as amended).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
pub const constants = @import("constants.zig");
pub const limits = @import("limits.zig");
pub const canonical = @import("dnssec_canonical.zig");
pub const nsec = @import("dnssec_nsec.zig");
pub const nsec3 = @import("dnssec_nsec3.zig");
/// The key store and the admission of a DNSKEY set to it, the validator of whole messages
/// (docs/design.md §25 step 9), and the walks for keys (step 12). The module is cocuyo's own and never registered: the verifier
/// outside `src/` and its tests read it, and no consumer can name it.
pub const store = @import("dnssec_store.zig");
pub const store_keys = @import("dnssec_store_keys.zig");
pub const validate = @import("dnssec_validate.zig");
pub const walk = @import("dnssec_walk.zig");
/// The memory one validation writes, which the key store owns (§17 question 108).
pub const scratch = @import("dnssec_scratch.zig");
/// The key store a consumer owns, and the calls of the table's `Trust` (step 12).
pub const keys = @import("dnssec_keys.zig");
/// The trust anchors from text, which `cocuyo.trust_anchors` names (§25 step 15).
pub const anchors = @import("dnssec_anchors.zig");
/// The tests' verifier and the response builder that signs for it, for the twin's signed server
/// (docs/design.md §25 step 14), as `wire.fixtures` is for the tests of the modules above it.
pub const fixtures = @import("fixtures.zig");

/// Where `dnssec` feeds the octets a digest or a signature covers, in order and in pieces. The
/// caller's: a digest or a signature over chapulin, or a test that records what it was given.
pub const Hash = struct {
    context: *anyopaque,
    update: *const fn (context: *anyopaque, octets: []const u8) void,

    pub fn feed(self: Hash, octets: []const u8) void {
        self.update(self.context, octets);
    }
};

/// What `dnssec` asks of the cryptography (docs/design.md §25 step 9). The caller's: a verifier
/// over chapulin outside `src/`, or a test's. One check or one digest runs at a time.
pub const Verifier = struct {
    context: *anyopaque,
    /// Whether it checks signatures of the DNSSEC algorithm `algorithm` (RFC 4034 Appendix A.1).
    checks: *const fn (context: *anyopaque, algorithm: u8) bool,
    /// Whether it computes digests of the DS digest type `digest_type` (RFC 4034 Appendix A.2).
    digests: *const fn (context: *anyopaque, digest_type: u8) bool,
    /// Begins a check under `algorithm`, one it checks, of `signature` under `public_key`, and
    /// returns where the signed data goes. Both come first, since Ed25519 hashes R and the key
    /// before the data (RFC 8032 §5.1.7, RFC 8080 §4). Null when the algorithm refuses the form of
    /// the key or of the signature, which is a check that failed.
    check_begin: *const fn (context: *anyopaque, algorithm: u8, public_key: []const u8, signature: []const u8) ?Hash,
    /// Ends the check: whether `signature` verifies under `public_key` over what was fed.
    check_end: *const fn (context: *anyopaque, public_key: []const u8, signature: []const u8) bool,
    /// Begins a digest of `digest_type`, one it computes, and returns where its input goes.
    digest_begin: *const fn (context: *anyopaque, digest_type: u8) Hash,
    /// Ends the digest, writes it into `out`, and returns its length.
    digest_end: *const fn (context: *anyopaque, out: *[constants.digest_bytes]u8) usize,
};

/// The key tag of a DNSKEY's rdata: the sum of its 16-bit groups, the carry folded in once (RFC
/// 4034 Appendix B). Algorithm 1 has another tag (Appendix B.1). Its use "MUST NOT" be
/// implemented (RFC 9904 §3), so no key of it is ever checked, and this sum is never asked of
/// one.
pub fn key_tag(rdata: []const u8) u16 {
    var sum: u32 = 0;
    for (rdata, 0..) |octet, index| {
        sum += if (index & 1 == 0) @as(u32, octet) << constants.key_tag_high_shift else octet;
    }
    sum += (sum >> constants.key_tag_carry_shift) & constants.key_tag_mask;
    return @truncate(sum);
}

/// Whether `now` lies between `inception` and `expiration`, both included, in serial number
/// arithmetic: "The Signature Expiration and Inception field values specify a date and time in
/// the form of a 32-bit unsigned number of seconds elapsed since 1 January 1970 00:00:00 UTC
/// ... in serial number arithmetic" (RFC 4034 §3.1.5, RFC 1982 §3.2, RFC 4035 §5.3.1).
pub fn within(now: u32, inception: u32, expiration: u32) bool {
    return !before(now, inception) and !before(expiration, now);
}

/// Whether `a` is before `b` in serial number arithmetic over 32 bits (RFC 1982 §3.2). Two times
/// exactly half the space apart compare as neither, as §3.2 leaves them undefined.
pub fn before(a: u32, b: u32) bool {
    if (a == b) return false;
    return (a < b and b - a < constants.serial_half) or (a > b and a - b > constants.serial_half);
}

/// What a DS digest covers: the canonical form of the DNSKEY's owner name, then its rdata: "digest
/// = digest_algorithm( DNSKEY owner name | DNSKEY RDATA)" (RFC 4034 §5.1.4). The owner's
/// canonical form is its letters in lowercase (§6.2).
pub fn ds_input(owner: *const Name, dnskey_rdata: []const u8, hash: Hash) void {
    assert(owner.len >= 1);
    var lowered = owner.*;
    lowered.fold_case();
    hash.feed(lowered.wire());
    hash.feed(dnskey_rdata);
}

// Tests.

const testing = std.testing;
const rdata_fixtures = wire.rdata.fixtures;

const Recorded = @import("fixtures.zig").Recorded;

test "RFC 4034 §5.4's DNSKEY has the key tag 60485 that its DS names" {
    var bytes: [rdata_fixtures.dnskey_example_bytes]u8 = undefined;
    try testing.expectEqual(@as(u16, 60485), key_tag(rdata_fixtures.dnskey_example(&bytes)));
    try testing.expectEqual(@as(u16, 60485), (try wire.rdata.Ds.parse(&rdata_fixtures.ds_example)).key_tag);
}

test "the key tag folds the carry of its sum in" {
    // 0xffff + 0x0002 is 0x10001, whose carry folds to 0x0002.
    try testing.expectEqual(@as(u16, 0x0002), key_tag(&.{ 0xff, 0xff, 0x00, 0x02 }));
    // An odd count of octets ends on a high half.
    try testing.expectEqual(@as(u16, 0x0100), key_tag(&.{0x01}));
}

test "a time is within a signature's dates, both included, in serial number arithmetic" {
    try testing.expect(within(150, 100, 200));
    try testing.expect(within(100, 100, 200));
    try testing.expect(within(200, 100, 200));
    try testing.expect(!within(99, 100, 200));
    try testing.expect(!within(201, 100, 200));
    // RFC 1982 §3.2: across the wrap of the 32-bit space, 0x00000005 comes after 0xfffffff0.
    try testing.expect(within(0x00000002, 0xfffffff0, 0x00000005));
    try testing.expect(!within(0x00000006, 0xfffffff0, 0x00000005));
    try testing.expect(!before(0x80000000, 0) and !before(0, 0x80000000));
}

test "a DS digest covers the DNSKEY's owner in lowercase, then its rdata" {
    // RFC 4034 §5.4: dskey.example.com, whose DS digest is the SHA-1 of these octets.
    var bytes: [rdata_fixtures.dnskey_example_bytes]u8 = undefined;
    const key = rdata_fixtures.dnskey_example(&bytes);
    var recorded: Recorded = .{};
    ds_input(&try Name.from_text("DSKEY.Example.COM."), key, recorded.hash());
    const owner = "\x05dskey\x07example\x03com\x00";
    try testing.expectEqualSlices(u8, owner, recorded.octets[0..owner.len]);
    try testing.expectEqualSlices(u8, key, recorded.octets[owner.len..recorded.len]);
}

test {
    _ = canonical;
    _ = nsec;
    _ = nsec3;
    _ = @import("dnssec_nsec3_proof.zig");
    _ = @import("dnssec_base32.zig");
    _ = @import("dnssec_message.zig");
    _ = @import("dnssec_rrset.zig");
    _ = @import("dnssec_store.zig");
    _ = @import("dnssec_store_keys.zig");
    _ = @import("dnssec_validate.zig");
    _ = @import("dnssec_validate_denial.zig");
    _ = walk;
    _ = keys;
    _ = @import("dnssec_walk_test.zig");
    _ = anchors;
    _ = @import("dnssec_anchors_test.zig");
    _ = @import("dnssec_base64.zig");
    _ = @import("dnssec_rsa.zig");
}
