//! Tests of the proofs of a negative, a wildcard and an alias (`dnssec_validate_denial.zig`).
//! Split from it by the file-length rule.
const std = @import("std");
const core = @import("core");
const Kind = core.Kind;
const Name = core.Name;
const constants = @import("constants.zig");
const validate = @import("dnssec_validate.zig");
const Validation = validate.Validation;

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const zone = @import("rfc4035/fixtures.zig");
const Builder = fixtures.Builder;

fn named(text: []const u8) Name {
    return Name.from_text(text) catch unreachable;
}

const address = zone.address;

test "a signed CNAME links to its target, and an unsigned target waits for a walk" {
    var setup: zone.Setup = .{};
    setup.init();
    var builder = Builder.init("c.example", .a, 0);
    builder.rrset("c.example", .cname, &.{"\x01x\x01w\x07example\x00"}, zone.by_zone);
    builder.rrset("x.w.example", .a, &.{&address}, zone.by_zone);
    try testing.expectEqual(validate.Ending.answer, setup.validate("c.example", .a, builder.message()).secure.ending);
    var unsigned = Builder.init("c.example", .a, 0);
    unsigned.rrset("c.example", .cname, &.{"\x01x\x01w\x07example\x00"}, zone.by_zone);
    unsigned.record("x.w.example", .a, 3600, &address);
    try testing.expect(setup.validate("c.example", .a, unsigned.message()).keys_wanted.equal(&named("x.w.example")));
}

test "an unsigned CNAME stands when a valid DNAME makes it, and not otherwise" {
    var setup: zone.Setup = .{};
    setup.init();
    // RFC 6672 §2.2: `d.example DNAME w.example` makes `x.d.example CNAME x.w.example`.
    for ([_]struct { target: []const u8, stands: bool }{
        .{ .target = "\x01x\x01w\x07example\x00", .stands = true },
        .{ .target = "\x01y\x01w\x07example\x00", .stands = false },
    }) |case| {
        var builder = Builder.init("x.d.example", .a, 0);
        builder.rrset("d.example", .dname, &.{"\x01w\x07example\x00"}, zone.by_zone);
        builder.record("x.d.example", .cname, 3600, case.target);
        builder.rrset(if (case.stands) "x.w.example" else "y.w.example", .a, &.{&address}, zone.by_zone);
        const result = setup.validate("x.d.example", .a, builder.message());
        if (case.stands) try testing.expect(result == .secure) else try testing.expect(result.keys_wanted.equal(&named("x.d.example")));
    }
    // A DNAME whose own signature fails makes nothing.
    var forged = Builder.init("x.d.example", .a, 0);
    forged.rrset("d.example", .dname, &.{"\x01w\x07example\x00"}, zone.by_wrong_key);
    forged.record("x.d.example", .cname, 3600, "\x01x\x01w\x07example\x00");
    forged.rrset("x.w.example", .a, &.{&address}, zone.by_zone);
    try testing.expect(setup.validate("x.d.example", .a, forged.message()) == .keys_wanted);
}

test "an answer to ANY is each RRset at the name, and one unsigned waits for a walk" {
    var setup: zone.Setup = .{};
    setup.init();
    var builder = Builder.init("x.w.example", .any, 0);
    builder.rrset("x.w.example", .mx, &.{zone.mx_xx}, zone.by_zone);
    builder.rrset("x.w.example", .a, &.{&address}, zone.by_zone);
    try testing.expectEqual(validate.Ending.answer, setup.validate("x.w.example", .any, builder.message()).secure.ending);
    builder.record("x.w.example", .aaaa, 3600, &([_]u8{0x20} ++ [_]u8{0} ** 15));
    try testing.expect(setup.validate("x.w.example", .any, builder.message()) == .keys_wanted);
}

test "NOERROR with NXNAME is a name error, and a negative with no proof is bogus" {
    var setup: zone.Setup = .{};
    setup.init();
    // RFC 9824 §3.1: the NSEC at the name asked, NXNAME set, its next name the one after it.
    var compact = Builder.init("ml.example", .a, 0);
    compact.authority();
    zone.apex_soa(&compact);
    compact.rrset("ml.example", .nsec, &.{"\x01\x00\x02ml\x07example\x00" ++ fixtures.compact}, zone.by_zone);
    try testing.expectEqual(validate.Ending.name_error, setup.validate("ml.example", .a, compact.message()).secure.ending);
    var bare = Builder.init("ml.example", .a, 3);
    bare.authority();
    zone.apex_soa(&bare);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("ml.example", .a, bare.message()));
}

test "a negative that rests on nothing signed waits for a walk, and an unsigned SOA does too" {
    var setup: zone.Setup = .{};
    setup.init();
    var bare = Builder.init("ml.example", .a, 3);
    bare.authority();
    bare.record("example", .soa, 3600, zone.soa);
    try testing.expect(setup.validate("ml.example", .a, bare.message()).keys_wanted.equal(&named("ml.example")));
    var name_error = zone.name_error();
    const bytes = name_error.message();
    // The SOA's RRSIG is the second record: its type covered turned to A leaves the SOA unsigned.
    var message: @import("dnssec_message.zig").Message = undefined;
    _ = try message.read(bytes, &named("ml.example"));
    var changed: [4096]u8 = undefined;
    @memcpy(changed[0..bytes.len], bytes);
    changed[message.records[1].end - message.records[1].rdata.len + 1] = @intCast(Kind.a.code());
    try testing.expect(setup.validate("ml.example", .a, changed[0..bytes.len]).keys_wanted.equal(&named("ml.example")));
}

test "a literal wildcard owner is no expansion, and a wildcard CNAME needs its proof" {
    var setup: zone.Setup = .{};
    setup.init();
    var literal = Builder.init("*.w.example", .mx, 0);
    literal.rrset("*.w.example", .mx, &.{zone.mx_xx}, zone.by_zone);
    try testing.expect(setup.validate("*.w.example", .mx, literal.message()) == .secure);
    var expanded_signing = zone.by_zone;
    expanded_signing.labels = 2;
    var alias = Builder.init("a.z.w.example", .a, 0);
    alias.rrset("a.z.w.example", .cname, &.{"\x01x\x01w\x07example\x00"}, expanded_signing);
    alias.rrset("x.w.example", .a, &.{&address}, zone.by_zone);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("a.z.w.example", .a, alias.message()));
}

test "a DNAME at the name itself, or at no ancestor of it, makes no CNAME" {
    var setup: zone.Setup = .{};
    setup.init();
    for ([_][]const u8{ "x.d.example", "e.example" }) |owner| {
        var builder = Builder.init("x.d.example", .a, 0);
        builder.rrset(owner, .dname, &.{"\x01w\x07example\x00"}, zone.by_zone);
        builder.record("x.d.example", .cname, 3600, if (owner.len == "e.example".len) "\x01x\x01w\x07example\x00" else "\x01w\x07example\x00");
        builder.rrset("x.w.example", .a, &.{&address}, zone.by_zone);
        builder.rrset("w.example", .a, &.{&address}, zone.by_zone);
        try testing.expect(setup.validate("x.d.example", .a, builder.message()) == .keys_wanted);
    }
}

test "ANY verifies each RRset once, holds an expansion to its proof, and denies nothing" {
    var setup: zone.Setup = .{};
    setup.init();
    var builder = Builder.init("x.w.example", .any, 0);
    builder.rrset("x.w.example", .mx, &.{ zone.mx_xx, "\x00\x02\x02xy\x07example\x00" }, zone.by_zone);
    builder.rrset("x.w.example", .a, &.{&address}, zone.by_zone);
    try testing.expect(setup.validate("x.w.example", .any, builder.message()) == .secure);
    try testing.expectEqual(@as(usize, 2), setup.sums.checked);
    var expanded_signing = zone.by_zone;
    expanded_signing.labels = 2;
    var wild = Builder.init("a.z.w.example", .any, 0);
    wild.rrset("a.z.w.example", .mx, &.{zone.mx_xx}, expanded_signing);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("a.z.w.example", .any, wild.message()));
    // B.3's proof shows the name exists, and says nothing of ANY.
    var none = zone.no_data();
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("ns1.example", .any, none.message()));
}

test "a referral proves an unsigned delegation at the name, but not at another name" {
    var setup: zone.Setup = .{};
    setup.init();
    for ([_]struct { asked: []const u8, insecure: bool }{
        .{ .asked = "b.example", .insecure = true },
        .{ .asked = "x.c.example", .insecure = false },
    }) |case| {
        var builder = Builder.init(case.asked, .a, 0);
        builder.authority();
        builder.rrset("b.example", .nsec, &.{"\x03ns1\x07example\x00" ++ fixtures.ns}, zone.by_zone);
        const result = setup.validate(case.asked, .a, builder.message());
        if (case.insecure) try testing.expectEqual(Validation.insecure, result) else try testing.expectEqual(Validation{ .bogus = .proof }, result);
    }
}

test "a negative's RRset is verified once, and the answer section is no part of its proof" {
    var setup: zone.Setup = .{};
    setup.init();
    var builder = Builder.init("ml.example", .a, 3);
    builder.record("example", .soa, 3600, zone.soa);
    builder.authority();
    builder.rrset("example", .soa, &.{ zone.soa, zone.soa[0 .. zone.soa.len - 1] ++ "\x11" }, zone.by_zone);
    builder.rrset("b.example", .nsec, &.{"\x03ns1\x07example\x00" ++ fixtures.ns}, zone.by_zone);
    builder.rrset("example", .nsec, &.{"\x01a\x07example\x00" ++ fixtures.apex}, zone.by_zone);
    try testing.expectEqual(validate.Ending.name_error, setup.validate("ml.example", .a, builder.message()).secure.ending);
    try testing.expectEqual(@as(usize, 3), setup.sums.checked);
}

test "an unsigned NSEC is passed over, and a bogus one ends the message" {
    var setup: zone.Setup = .{};
    setup.init();
    var extra = zone.name_error();
    extra.record("c.example", .nsec, 3600, "\x01d\x07example\x00" ++ fixtures.ns);
    try testing.expectEqual(validate.Ending.name_error, setup.validate("ml.example", .a, extra.message()).secure.ending);
    var forged = Builder.init("ml.example", .a, 3);
    forged.authority();
    zone.apex_soa(&forged);
    forged.rrset("b.example", .nsec, &.{"\x03ns1\x07example\x00" ++ fixtures.ns}, zone.by_wrong_key);
    forged.rrset("example", .nsec, &.{"\x01a\x07example\x00" ++ fixtures.apex}, zone.by_zone);
    try testing.expectEqual(Validation{ .bogus = .signature }, setup.validate("ml.example", .a, forged.message()));
}

test "a link whose target is under an insecure delegation is insecure" {
    var setup: zone.Setup = .{};
    setup.init();
    try testing.expect(setup.store.put(&named("w.example"), .insecure, &.{}, std.math.maxInt(u64)));
    var builder = Builder.init("c.example", .a, 0);
    builder.rrset("c.example", .cname, &.{"\x01x\x01w\x07example\x00"}, zone.by_zone);
    builder.record("x.w.example", .a, 3600, &address);
    try testing.expectEqual(Validation.insecure, setup.validate("c.example", .a, builder.message()));
}

test "a chain whose end the message does not say is secure as far as it goes" {
    var setup: zone.Setup = .{};
    setup.init();
    var builder = Builder.init("c.example", .a, 0);
    builder.rrset("c.example", .cname, &.{"\x01x\x01w\x07example\x00"}, zone.by_zone);
    try testing.expectEqual(validate.Ending.alias, setup.validate("c.example", .a, builder.message()).secure.ending);
    // The same message with an SOA in its authority section is a negative, and proves nothing.
    builder.authority();
    zone.apex_soa(&builder);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("c.example", .a, builder.message()));
}

/// An NSEC3 rdata of another zone: SHA-1, no flags, one iteration, no salt, a 20-octet next hash,
/// and an A in its type map (RFC 5155 §3.2).
const other_zone_nsec3 = [_]u8{ constants.nsec3_hash_sha1, 0, 0, 1, 0, constants.nsec3_hash_bytes } ++
    [_]u8{'z'} ** constants.nsec3_hash_bytes ++ fixtures.address3;

test "an NSEC3 of another zone, as a CNAME's own proof, is no part of an NSEC negative" {
    var setup: zone.Setup = .{};
    setup.init();
    // RFC 5155 §3: an NSEC3 record's owner is a hash label, then its zone. One of `alias.test`,
    // where a CNAME's wildcard was proved, says nothing of `ns1.example`, whose zone uses NSEC.
    var builder = zone.no_data();
    builder.record("7k0jip1idpcols26lo7prvrpmq5qj17a.alias.test", .nsec3, 3600, &other_zone_nsec3);
    const result = setup.validate("ns1.example", .mx, builder.message());
    try testing.expectEqual(std.meta.Tag(Validation).secure, std.meta.activeTag(result));
    try testing.expectEqual(validate.Ending.no_data, result.secure.ending);
}
