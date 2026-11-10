//! The signatures over one RRset of a message: which RRSIGs count, which keys are tried, and what
//! the RRset is when none verifies (docs/design.md §25, items 2 to 4, 6, 7 and 16, and step 9).
//! Split from `dnssec.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Kind = core.Kind;
const Name = core.Name;
const dnssec = @import("dnssec.zig");
const Verifier = dnssec.Verifier;
const limits = @import("limits.zig");
const canonical = @import("dnssec_canonical.zig");
const rsa = @import("dnssec_rsa.zig");
const message_reader = @import("dnssec_message.zig");
const Message = message_reader.Message;
const Rrset = message_reader.Rrset;
const Section = message_reader.Section;
const Entry = @import("dnssec_store.zig").Entry;

/// The DNSKEY rdatas of one zone, read where they are: in the store's entry, or in a list the
/// caller keeps while they are read. Nothing is copied, so a verification fills nothing (§17
/// question 108).
pub const Keys = union(enum) {
    list: []const []const u8,
    entry: *const Entry,

    pub fn len(self: *const Keys) usize {
        return switch (self.*) {
            .list => |list| list.len,
            .entry => |entry| entry.len,
        };
    }

    pub fn record(self: *const Keys, index: usize) []const u8 {
        assert(index < self.len());
        return switch (self.*) {
            .list => |list| list[index],
            .entry => |entry| entry.record(index),
        };
    }
};

/// What is held for a signer's zone: its keys, nothing yet, or nothing that will come, since no
/// anchor is at or above it.
pub const Held = union(enum) { keys: Keys, wanted, outside };

/// Where the keys of a signer come from: the store, or a set the caller fixes.
pub const Signers = struct {
    context: *const anyopaque,
    keys: *const fn (context: *const anyopaque, signer: *const Name) Held,
};

/// The verifications one message may still cost (RFC 4035 §5.4, RFC 4033 §12).
pub const Budget = struct {
    left: usize = limits.verifications_per_message_max,
};

/// What one verification reads: the message, where keys come from, the cryptography, the time of
/// day as a signature's dates count it, and what is left of the budget.
pub const Check = struct {
    message: *const Message,
    signers: Signers,
    verifier: Verifier,
    now_seconds: u32,
    budget: *Budget,
    /// Where the signed data is written, in the key store's scratch.
    buffers: *canonical.Buffers,
};

/// An RRset one signature verified: the signer, the RRSIG's Labels field, and the longest the
/// RRset may be kept (item 7).
pub const Valid = struct { signer: Name, labels: u8, ttl_seconds: u32 };

pub const Outcome = union(enum) {
    valid: Valid,
    /// No RRSIG counts for it, or none whose key the signer's zone holds.
    unsigned,
    /// An RRSIG counts whose signer's keys the store does not hold yet.
    keys_wanted: Name,
    /// A check failed, and none verified; or the work ran past a limit.
    bogus,
};

/// Verifies `set`, the RRset of its kind that `owner` holds in `section`, against the RRSIGs at
/// `owner` in the same section. One valid signature is enough (RFC 6840 §5.4).
pub fn verify(check: Check, set: *const Rrset, owner: *const Name, section: Section) Error!Outcome {
    assert(set.count() >= 1);
    const message = check.message;
    var tally: Tally = .{};
    for (0..message.count) |index| {
        const sig = try counting(message, index, set.kind, owner, section) orelse continue;
        tally.tried += 1;
        if (tally.tried > limits.signatures_per_rrset_max) return .bogus;
        if (try weigh(check, set, owner, &message.records[index], &sig, &tally)) |ended| return ended;
    }
    if (tally.wanted) |signer| return .{ .keys_wanted = signer };
    return if (tally.failed) .bogus else .unsigned;
}

/// What the RRSIGs tried so far came to.
const Tally = struct { tried: usize = 0, wanted: ?Name = null, failed: bool = false };

/// The RRSIG at `index`, when it is one at `owner` in `section` that counts for the RRset of
/// `kind`. A malformed RRSIG counts for nothing.
fn counting(message: *const Message, index: usize, kind: Kind, owner: *const Name, section: Section) Error!?wire.rdata.Rrsig {
    if (!try message.holds(index, section, .rrsig, owner)) return null;
    const sig = wire.rdata.Rrsig.parse(message.records[index].rdata) catch return null;
    return if (counts(&sig, kind, owner)) sig else null;
}

/// Tries one RRSIG that counts, and returns the RRset's end when it decides it.
fn weigh(
    check: Check,
    set: *const Rrset,
    owner: *const Name,
    record: *const wire.Record,
    sig: *const wire.rdata.Rrsig,
    tally: *Tally,
) Error!?Outcome {
    switch (check.signers.keys(check.signers.context, &sig.signer)) {
        .outside => {},
        .wanted => tally.wanted = sig.signer,
        .keys => |keys| switch (try one(check, set, owner, record, sig, &keys)) {
            .valid => return .{ .valid = valid(check, set, record, sig) },
            .failed => tally.failed = true,
            .disregarded => {},
            .exhausted => return .bogus,
        },
    }
    return null;
}

/// Whether an RRSIG speaks for an RRset of `kind` at `owner`: it covers the type, its Labels field
/// is no larger than the owner's labels, and its signer is the owner or an ancestor of it (RFC 4035
/// §5.3.1). The last is the condition docs/design.md §25 item 2 adds, so that one zone's key signs
/// no other zone's data.
fn counts(sig: *const wire.rdata.Rrsig, kind: Kind, owner: *const Name) bool {
    if (sig.type_covered != kind.code()) return false;
    if (sig.labels > owner.label_count()) return false;
    return core.canonical.shared_labels(&sig.signer, owner) == sig.signer.label_count();
}

const One = enum { valid, failed, disregarded, exhausted };

/// Tries each key of the signer's zone that `sig` may name, `keys_per_signature_max` at most,
/// since a key tag is not unique (RFC 4034 Appendix B). No such key disregards the RRSIG (RFC 6840
/// §5.12).
fn one(
    check: Check,
    set: *const Rrset,
    owner: *const Name,
    record: *const wire.Record,
    sig: *const wire.rdata.Rrsig,
    keys: *const Keys,
) Error!One {
    var keys_tried: usize = 0;
    assert(keys.len() <= limits.zone_keys_max);
    for (0..keys.len()) |index| {
        const rdata = keys.record(index);
        const key = wire.rdata.Dnskey.parse(rdata) catch continue;
        if (!names(check.verifier, sig, rdata, &key)) continue;
        if (keys_tried == limits.keys_per_signature_max) break;
        keys_tried += 1;
        // "The validator's notion of the current time MUST be less than or equal to the time
        // listed in the RRSIG RR's Expiration field" and greater or equal to Inception (RFC 4035
        // §5.3.1).
        if (!dnssec.within(check.now_seconds, sig.inception, sig.expiration)) return .failed;
        if (check.budget.left == 0) return .exhausted;
        check.budget.left -= 1;
        if (try signs(check, set, owner, record, sig, &key)) return .valid;
    }
    return if (keys_tried == 0) .disregarded else .failed;
}

/// Whether `sig` verifies under `key` over what it signs of `set`. A key or a signature of a form
/// the algorithm refuses verifies nothing.
fn signs(
    check: Check,
    set: *const Rrset,
    owner: *const Name,
    record: *const wire.Record,
    sig: *const wire.rdata.Rrsig,
    key: *const wire.rdata.Dnskey,
) Error!bool {
    const verifier = check.verifier;
    const hash = verifier.check_begin(verifier.context, sig.algorithm, key.public_key, sig.signature) orelse
        return false;
    try canonical.signed_data_in(check.buffers, record.rdata, owner, set.kind, core.constants.class_internet, set, hash);
    return verifier.check_end(verifier.context, key.public_key, sig.signature);
}

/// Whether `key` is one `sig` names, and one a check can use: the same algorithm and key tag
/// (RFC 4035 §5.3.1), the Zone Key flag set (RFC 4034 §2.1.1), the protocol 3 (§2.1.2), and an
/// algorithm the verifier checks.
pub fn names(verifier: Verifier, sig: *const wire.rdata.Rrsig, rdata: []const u8, key: *const wire.rdata.Dnskey) bool {
    if (key.algorithm != sig.algorithm or dnssec.key_tag(rdata) != sig.key_tag) return false;
    if (!key.zone_key() or !key.protocol_valid()) return false;
    // A key or a signature outside §25's bounds is passed over, as one the verifier cannot use.
    if (sig.signature.len > limits.signature_bytes_max or !rsa.usable(key.algorithm, key.public_key)) return false;
    return verifier.checks(verifier.context, sig.algorithm);
}

/// The longest a valid RRset may be kept: the smallest of its TTL as received, the RRSIG's TTL,
/// the Original TTL and the time left before the signature expires (RFC 4035 §5.3.3).
fn valid(check: Check, set: *const Rrset, record: *const wire.Record, sig: *const wire.rdata.Rrsig) Valid {
    assert(dnssec.within(check.now_seconds, sig.inception, sig.expiration));
    const left = sig.expiration -% check.now_seconds;
    const ttl = @min(@min(set.ttl_seconds(), record.ttl_seconds), @min(sig.original_ttl, left));
    return .{ .signer = sig.signer, .labels = sig.labels, .ttl_seconds = ttl };
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const zone = @import("rfc4035/fixtures.zig");
const Sums = fixtures.Sums;
const Builder = fixtures.Builder;

/// RFC 4035 Appendix A's dates hold this instant: 2004-04-20.
const now_seconds: u32 = 1082419200;

const mx_xx = "\x00\x01\x02xx\x07example\x00";

/// Signers that hold `keys` for `zone`, wait for `wanted`, and know nothing else.
const Fixed = struct {
    keys: KeyList,
    zone: []const u8 = "example",
    wanted: ?[]const u8 = null,

    fn signers(self: *const Fixed) Signers {
        return .{ .context = self, .keys = held };
    }

    fn held(context: *const anyopaque, signer: *const Name) Held {
        const self: *const Fixed = @ptrCast(@alignCast(context));
        if (signer.equal(&(Name.parse(self.zone) catch unreachable))) return .{ .keys = .{ .list = self.keys.slice() } };
        const wanted = self.wanted orelse return .outside;
        return if (signer.equal(&(Name.parse(wanted) catch unreachable))) .wanted else .outside;
    }
};

/// A zone's keys a test holds, as a list it keeps.
const KeyList = struct {
    records: [limits.zone_keys_max][]const u8 = undefined,
    len: usize = 0,

    fn slice(self: *const KeyList) []const []const u8 {
        return self.records[0..self.len];
    }
};

fn zone_keys(records: []const []const u8) KeyList {
    var keys: KeyList = .{};
    for (records) |rdata| {
        keys.records[keys.len] = rdata;
        keys.len += 1;
    }
    return keys;
}

/// Verifies the RRset of `kind` at `owner` in the answer of `bytes`, asked as `asked`.
fn outcome(bytes: []const u8, asked: []const u8, owner: []const u8, kind: Kind, fixed: *const Fixed, sums: *Sums, budget: *Budget) !Outcome {
    var message: Message = undefined;
    try testing.expect(try message.read(bytes, &try Name.parse(asked)));
    const owner_name = try Name.parse(owner);
    const set = try message.rrset(.answer, kind, &owner_name);
    // A changed owner or type leaves no RRset to verify.
    if (set.count() == 0) return .unsigned;
    var buffers: canonical.Buffers = undefined;
    const check: Check = .{ .message = &message, .signers = fixed.signers(), .verifier = sums.verifier(), .now_seconds = now_seconds, .budget = budget, .buffers = &buffers };
    return verify(check, &set, &owner_name, .answer);
}

fn answer_outcome(bytes: []const u8, fixed: *const Fixed) !Outcome {
    var sums: Sums = .{};
    var budget: Budget = .{};
    return outcome(bytes, "x.w.example", "x.w.example", .mx, fixed, &sums, &budget);
}

/// A response to `x.w.example MX` with its one MX record, signed by `signing`.
fn signed_mx(signing: fixtures.Signing) Builder {
    var builder = Builder.init("x.w.example", .mx, 0);
    builder.rrset("x.w.example", .mx, &.{mx_xx}, signing);
    return builder;
}

test "B.1's MX RRset verifies under the zone's key, kept no longer than its TTL" {
    var builder = zone.answer();
    const fixed: Fixed = .{ .keys = zone_keys(&.{ &zone.ksk, &zone.zsk }) };
    var sums: Sums = .{};
    var budget: Budget = .{};
    const result = try outcome(builder.message(), "x.w.example", "x.w.example", .mx, &fixed, &sums, &budget);
    // The key of the other tag is never tried.
    try testing.expectEqual(@as(usize, 1), sums.checked);
    try testing.expectEqual(@as(u32, 3600), result.valid.ttl_seconds);
    try testing.expectEqual(@as(u8, 3), result.valid.labels);
    try testing.expect(result.valid.signer.equal(&try Name.parse("example")));
}

test "an RRset whose signature has under a day left is kept no longer than that" {
    var signing = zone.by_zone;
    signing.expiration = now_seconds + 60;
    var builder = signed_mx(signing);
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    try testing.expectEqual(@as(u32, 60), (try answer_outcome(builder.message(), &fixed)).valid.ttl_seconds);
}

test "any changed octet of the RRset or of its RRSIG's signed fields makes it bogus or unsigned" {
    var builder = zone.answer();
    const bytes = builder.message();
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    var message: Message = undefined;
    _ = try message.read(bytes, &try Name.parse("x.w.example"));
    // The answer section's two records: every octet but the TTLs, which the signature does not
    // cover (RFC 4035 §5.3.2), and the RRSIG's own record TTL.
    for (0..2) |index| {
        const record = message.records[index];
        const ttl_at = record.end - record.rdata.len - 6;
        for (record.owner_offset..record.end) |at| {
            if (at >= ttl_at and at < ttl_at + 4) continue;
            var changed: [4096]u8 = undefined;
            @memcpy(changed[0..bytes.len], bytes);
            changed[at] +%= 1;
            const result = answer_outcome(changed[0..bytes.len], &fixed) catch continue;
            try testing.expect(result != .valid);
        }
    }
}

test "a signature out of its dates, or of an algorithm not checked, does not verify" {
    for ([_]struct { inception: u32, expiration: u32, algorithm: u8, expected: std.meta.Tag(Outcome) }{
        .{ .inception = now_seconds + 1, .expiration = now_seconds + 9, .algorithm = 5, .expected = .bogus },
        .{ .inception = now_seconds - 9, .expiration = now_seconds - 1, .algorithm = 5, .expected = .bogus },
        .{ .inception = now_seconds, .expiration = now_seconds, .algorithm = 5, .expected = .valid },
        .{ .inception = now_seconds - 9, .expiration = now_seconds + 9, .algorithm = 15, .expected = .unsigned },
    }) |case| {
        var signing = zone.by_zone;
        signing.inception = case.inception;
        signing.expiration = case.expiration;
        signing.algorithm = case.algorithm;
        const key = if (case.algorithm == 15) zone.zsk_of_algorithm(15) else zone.zsk;
        try testing.expectEqual(dnssec.key_tag(&zone.zsk), dnssec.key_tag(&key));
        signing.public_key = key[4..];
        var builder = signed_mx(signing);
        const fixed: Fixed = .{ .keys = zone_keys(&.{&key}) };
        try testing.expectEqual(case.expected, std.meta.activeTag(try answer_outcome(builder.message(), &fixed)));
    }
}

test "an RRset verifies in another order, with compressed names, lowered TTLs and mixed case" {
    // RFC 4034 §6.2 and §6.3: the signature covers the canonical form, whatever the message holds.
    const records = [_][]const u8{
        "\x00\x01\x01x\x01w\x07example\x00",
        "\x00\x02\x02xx\x07example\x00",
        "\x00\x03\x02xy\x07example\x00",
    };
    var builder = Builder.init("x.w.example", .mx, 0);
    builder.record_wire("\x01X\x01W\x07ExAmPlE\x00", .mx, 60, "\x00\x03\x02XY\x07Example\x00");
    builder.record_wire("\x01x\x01W\x07example\x00", .mx, 3600, "\x00\x02\x02XX\x07Example\x00");
    // The exchange is the question's name, behind a pointer, and so is the owner.
    builder.record_wire("\xc0\x0c", .mx, 3600, "\x00\x01\xc0\x0c");
    builder.rrsig("x.w.example", .mx, &records, zone.by_zone);
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    const result = try answer_outcome(builder.message(), &fixed);
    try testing.expectEqual(@as(u32, 60), result.valid.ttl_seconds);
}

test "two keys with one tag: the signature verifies under the second" {
    const twin = zone.zsk_twin;
    try testing.expectEqual(dnssec.key_tag(&zone.zsk), dnssec.key_tag(&twin));
    var builder = zone.answer();
    var fixed: Fixed = .{ .keys = zone_keys(&.{ &twin, &zone.zsk }) };
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .valid);
    // A third key of the tag is past `keys_per_signature_max`.
    fixed = .{ .keys = zone_keys(&.{ &twin, &twin, &zone.zsk }) };
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .bogus);
}

fn signed_twice(builder: *Builder, bad: usize) void {
    builder.record("x.w.example", .mx, zone.by_zone.original_ttl, mx_xx);
    for (0..bad) |_| builder.rrsig("x.w.example", .mx, &.{mx_xx}, zone.by_wrong_key);
    builder.rrsig("x.w.example", .mx, &.{mx_xx}, zone.by_zone);
}

test "an RRset with bad signatures and a good one is valid, up to signatures_per_rrset_max" {
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    var builder = Builder.init("x.w.example", .mx, 0);
    signed_twice(&builder, limits.signatures_per_rrset_max - 1);
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .valid);
    builder = Builder.init("x.w.example", .mx, 0);
    signed_twice(&builder, limits.signatures_per_rrset_max);
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .bogus);
}

test "a message past verifications_per_message_max is bogus" {
    var builder = zone.answer();
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    var sums: Sums = .{};
    var budget: Budget = .{ .left = 0 };
    try testing.expect(try outcome(builder.message(), "x.w.example", "x.w.example", .mx, &fixed, &sums, &budget) == .bogus);
    budget.left = 1;
    try testing.expect(try outcome(builder.message(), "x.w.example", "x.w.example", .mx, &fixed, &sums, &budget) == .valid);
    try testing.expectEqual(@as(usize, 0), budget.left);
}

test "a signer whose keys are not held is wanted, and one that is no ancestor counts for nothing" {
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}), .wanted = "w.example" };
    for ([_]struct { signer: []const u8, labels: ?u8, expected: std.meta.Tag(Outcome) }{
        .{ .signer = "w.example", .labels = null, .expected = .keys_wanted },
        .{ .signer = "x.w.example", .labels = null, .expected = .unsigned },
        .{ .signer = "other", .labels = null, .expected = .unsigned },
        .{ .signer = "example", .labels = 4, .expected = .unsigned },
        // Fewer labels sign a wildcard expansion, which the validator holds to its proof.
        .{ .signer = "example", .labels = 2, .expected = .valid },
    }) |case| {
        var signing = zone.by_zone;
        signing.signer = case.signer;
        signing.labels = case.labels;
        var builder = signed_mx(signing);
        try testing.expectEqual(case.expected, std.meta.activeTag(try answer_outcome(builder.message(), &fixed)));
    }
}

test "a key without the Zone Key flag, or of a protocol other than 3, is passed over" {
    // Each change keeps the key tag: a high octet down by one and the next one up, or the reverse.
    var not_zone = zone.zsk;
    not_zone[0] -= 1;
    not_zone[4] += 1;
    var not_three = zone.zsk;
    not_three[2] += 1;
    not_three[4] -= 1;
    for ([_][]const u8{ &not_zone, &not_three }) |key| {
        try testing.expectEqual(dnssec.key_tag(&zone.zsk), dnssec.key_tag(key));
        var signing = zone.by_zone;
        signing.public_key = key[4..];
        var builder = signed_mx(signing);
        const fixed: Fixed = .{ .keys = zone_keys(&.{key}) };
        try testing.expect(try answer_outcome(builder.message(), &fixed) == .unsigned);
    }
}

test "an RRSIG over another type, or in another section, counts for nothing" {
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    var signing = zone.by_zone;
    signing.covered = .ns;
    var builder = signed_mx(signing);
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .unsigned);
    builder = Builder.init("x.w.example", .mx, 0);
    builder.record("x.w.example", .mx, zone.by_zone.original_ttl, mx_xx);
    builder.authority();
    builder.rrsig("x.w.example", .mx, &.{mx_xx}, zone.by_zone);
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .unsigned);
}

test "an MX at another owner is not part of the RRset" {
    var builder = zone.answer();
    builder.record("y.w.example", .mx, zone.by_zone.original_ttl, mx_xx);
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .valid);
}

test "a zone's key signs nothing outside the zone, nor under a key of another algorithm" {
    var signing = zone.by_zone;
    signing.signer = "other";
    var builder = signed_mx(signing);
    const other: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}), .zone = "other" };
    try testing.expect(try answer_outcome(builder.message(), &other) == .unsigned);
    // The same tag, and algorithm 8 where the RRSIG says 5.
    signing = zone.by_zone;
    const algorithm_8 = zone.zsk_of_algorithm(8);
    signing.public_key = algorithm_8[4..];
    builder = signed_mx(signing);
    const fixed: Fixed = .{ .keys = zone_keys(&.{&algorithm_8}) };
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .unsigned);
}

test "an RRset is kept no longer than its RRSIG's TTL, nor than the Original TTL" {
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    for ([_][2]u32{ .{ 30, 3600 }, .{ 3600, 20 } }) |ttls| {
        var signing = zone.by_zone;
        signing.ttl = ttls[0];
        signing.original_ttl = ttls[1];
        var builder = signed_mx(signing);
        try testing.expectEqual(@min(ttls[0], ttls[1]), (try answer_outcome(builder.message(), &fixed)).valid.ttl_seconds);
    }
}

test "a signature of a form the algorithm refuses is a check that failed" {
    var signing = zone.by_zone;
    signing.cut = 1;
    var builder = signed_mx(signing);
    const fixed: Fixed = .{ .keys = zone_keys(&.{&zone.zsk}) };
    try testing.expect(try answer_outcome(builder.message(), &fixed) == .bogus);
}
