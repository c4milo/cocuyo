//! The parts of a message's validation that read records beside the answer: a CNAME link and the
//! DNAME that makes it, an answer to ANY, a negative and its proof, and a wildcard's proof
//! (docs/design.md §25 items 8 to 15, and step 9). Split from `dnssec_validate.zig` by the
//! file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Kind = core.Kind;
const Name = core.Name;
const limits = @import("limits.zig");
const constants = @import("constants.zig");
const nsec = @import("dnssec_nsec.zig");
const nsec3 = @import("dnssec_nsec3.zig");
const validate = @import("dnssec_validate.zig");
const Validation = validate.Validation;
const Walk = validate.Walk;

/// What a CNAME at a name of the chain does: nothing, a link to its target, or an end.
pub const Link = union(enum) { none, next: Name, ended: Validation };

/// The CNAME at `name`, when the answer holds one. It is a link when its signature is valid, or
/// when it has none and a valid DNAME in the answer makes the same CNAME (RFC 6672 §5.3.1).
pub fn link(walk: *Walk, name: *const Name) Error!Link {
    const set = try walk.message.rrset(.answer, .cname, name);
    if (set.count() == 0) return .none;
    var target: Name = Name.empty;
    try set.record(0).rdata_name(walk.message.bytes, &target);
    const outcome = try walk.verify(&set, name, .answer);
    switch (outcome) {
        .valid => |valid| {
            if (!expanded(name, valid.labels)) return .{ .next = target };
            const end = try wildcard(walk, name, valid.labels, .answer);
            return if (end == .secure) .{ .next = target } else .{ .ended = end };
        },
        .unsigned => if (try synthesized(walk, name, &target)) return .{ .next = target },
        else => {},
    }
    return .{ .ended = Walk.failed(outcome, name) };
}

/// Whether a valid DNAME of the answer, at a proper ancestor of `name`, makes `target` of it: the
/// labels of `name` above the DNAME's owner, then the DNAME's target (RFC 6672 §2.2).
fn synthesized(walk: *Walk, name: *const Name, target: *const Name) Error!bool {
    const message = walk.message;
    for (0..message.count) |index| {
        const record = &message.records[index];
        if (message.sections[index] != .answer or !record.is_kind(.dname)) continue;
        var owner: Name = Name.empty;
        try record.owner_name(message.bytes, &owner);
        const owner_labels = owner.label_count();
        if (owner_labels >= name.label_count() or core.canonical.shared_labels(&owner, name) != owner_labels) continue;
        const prefix = try leading(name, name.label_count() - owner_labels);
        const made = try prefix.concat(&try wire.rdata.name.whole(record.rdata));
        if (!made.equal(target)) continue;
        const set = try message.rrset(.answer, .dname, &owner);
        if (try walk.verify(&set, &owner, .answer) == .valid) return true;
    }
    return false;
}

/// The first `count` labels of `name`, as a name of their own.
fn leading(name: *const Name, count: u8) Error!Name {
    assert(count < name.label_count());
    var out: Name = Name.empty;
    var at: usize = 0;
    for (0..count) |_| {
        const length = name.bytes[at];
        try out.append_label(name.bytes[at + 1 ..][0..length]);
        at += 1 + @as(usize, length);
    }
    try out.terminate();
    return out;
}

/// An answer to ANY: every RRset at `name` in the answer, one at a time, and bogus if any one is
/// (RFC 6840 §4.2). With none, the chain ends in a negative.
pub fn any(walk: *Walk, name: *const Name) Error!Validation {
    const message = walk.message;
    var seen: [core.limits.records_max]u16 = undefined;
    var kinds: usize = 0;
    for (0..message.count) |index| {
        const record = &message.records[index];
        if (record.kind_code == Kind.rrsig.code()) continue;
        if (!try message.holds(index, .answer, Kind.of(record.kind_code), name)) continue;
        if (std.mem.indexOfScalar(u16, seen[0..kinds], record.kind_code) != null) continue;
        seen[kinds] = record.kind_code;
        kinds += 1;
        const set = try message.rrset(.answer, Kind.of(record.kind_code), name);
        const outcome = try walk.verify(&set, name, .answer);
        if (outcome != .valid) return Walk.failed(outcome, name);
        if (expanded(name, outcome.valid.labels)) {
            const end = try wildcard(walk, name, outcome.valid.labels, .answer);
            if (end != .secure) return end;
        }
    }
    if (kinds == 0) return negative(walk, name, .any);
    return walk.secure(.answer);
}

/// Whether an RRSIG with `labels` over an RRset at `name` signed a wildcard expansion: fewer
/// labels than the owner's, the wildcard label of a literal `*` owner not counted (RFC 4035
/// §5.3.4, RFC 4034 §3.1.3).
pub fn expanded(name: *const Name, labels: u8) bool {
    const literal = std.mem.eql(u8, name.bytes[1..][0..name.bytes[0]], constants.wildcard_label);
    return labels < name.label_count() - @intFromBool(literal);
}

/// A wildcard answer at `name`, signed under `labels`, is valid only with a proof that no closer
/// match exists (RFC 4035 §5.3.4, RFC 5155 §8.8).
pub fn wildcard(walk: *Walk, name: *const Name, labels: u8, ending: validate.Ending) Error!Validation {
    const nsecs = emptied(&walk.validator.scratch.nsecs);
    if (try gather_nsec(walk, name, nsecs)) |end| return end;
    if (nsec.wildcard_answer(name, labels, nsecs.slice())) return walk.secure(ending);
    const nsec3s = emptied(&walk.validator.scratch.nsec3s);
    if (try gather_nsec3(walk, name, nsec3s)) |end| return end;
    return switch (nsec3.wildcard_answer(name, labels, nsec3s.slice(), walk.hasher())) {
        .yes => walk.secure(ending),
        .insecure => .insecure,
        .no => .{ .bogus = .proof },
    };
}

/// A chain that ends at `name` with no RRset of `kind`: its SOA and its NSEC or NSEC3 records are
/// validated, and their proof gives the end (RFC 4035 §5.4, RFC 5155 §8, RFC 9824 §8).
pub fn negative(walk: *Walk, name: *const Name, kind: Kind) Error!Validation {
    var signed = false;
    if (try soa(walk, name, &signed)) |end| return end;
    if (has(walk, .nsec3)) return negative_nsec3(walk, name, kind, signed);
    return negative_nsec(walk, name, kind, signed);
}

fn negative_nsec(walk: *Walk, name: *const Name, kind: Kind, signed: bool) Error!Validation {
    const nsecs = emptied(&walk.validator.scratch.nsecs);
    if (try gather_nsec(walk, name, nsecs)) |end| return end;
    // Nothing the negative rests on is signed: the walk decides (§25 item 14).
    if (nsecs.len == 0 and !signed) return .{ .keys_wanted = name.* };
    switch (nsec.deny(name, kind, nsecs.slice())) {
        .no_data => return walk.secure(.no_data),
        .name_error => return walk.secure(.name_error),
        .none => {},
    }
    // The name or an ancestor is an unsigned delegation, as a referral to it shows: the data at
    // and under the cut is the unsigned child's (RFC 4035 §5.2).
    for (nsecs.slice()) |*record| {
        if (core.canonical.shared_labels(&record.owner, name) != record.owner.label_count()) continue;
        if (nsec.unsigned_delegation(&record.owner, nsecs.slice())) return .insecure;
    }
    return .{ .bogus = .proof };
}

fn negative_nsec3(walk: *Walk, name: *const Name, kind: Kind, signed: bool) Error!Validation {
    const nsec3s = emptied(&walk.validator.scratch.nsec3s);
    if (try gather_nsec3(walk, name, nsec3s)) |end| return end;
    if (nsec3s.len == 0 and !signed) return .{ .keys_wanted = name.* };
    return switch (nsec3.deny(name, kind, nsec3s.slice(), walk.hasher())) {
        .no_data => walk.secure(.no_data),
        .name_error => walk.secure(.name_error),
        .insecure => .insecure,
        .none => try delegated3(walk, name, nsec3s),
    };
}

/// Whether `name` or an ancestor below the zone is an unsigned delegation the records prove, as
/// a referral to it shows (RFC 5155 §8.9, RFC 6840 §4.4). One proof holds its own hashes to
/// `nsec3_hashes_per_message_max`, and this loop of proofs stops once the message passes it.
fn delegated3(walk: *Walk, name: *const Name, nsec3s: *const Nsec3s) Error!Validation {
    if (nsec3s.len == 0) return .{ .bogus = .proof };
    const zone_labels = nsec3s.items[0].signer.label_count();
    for (zone_labels + 1..name.label_count() + 1) |labels| {
        if (walk.hashed_past()) break;
        const ancestor = core.canonical.ancestor(name, @intCast(labels));
        if (nsec3.unsigned_delegation(&ancestor, nsec3s.slice(), walk.hasher()) != .no) return .insecure;
    }
    return .{ .bogus = .proof };
}

/// Whether the verified NSEC or NSEC3 records prove `name` an unsigned delegation (RFC 4035 §5.2,
/// RFC 5155 §8.9). A record past its limit of iterations makes the delegation insecure too.
pub fn delegated(walk: *Walk, name: *const Name) Error!bool {
    const nsecs = emptied(&walk.validator.scratch.nsecs);
    if (try gather_nsec(walk, name, nsecs) != null) return false;
    if (nsec.unsigned_delegation(name, nsecs.slice())) return true;
    const nsec3s = emptied(&walk.validator.scratch.nsec3s);
    if (try gather_nsec3(walk, name, nsec3s) != null) return false;
    return nsec3.unsigned_delegation(name, nsec3s.slice(), walk.hasher()) != .no;
}

/// Validates every SOA of the authority section, whatever its owner, since the lookup takes a
/// negative's TTL from the first one (`wire.response.negative_ttl_seconds`). `signed` says one was
/// valid. An SOA that is not valid ends the message.
fn soa(walk: *Walk, name: *const Name, signed: *bool) Error!?Validation {
    const message = walk.message;
    for (0..message.count) |index| {
        var owner: Name = Name.empty;
        if (!try first_of(walk, index, .soa, &owner)) continue;
        const set = try message.rrset(.authority, .soa, &owner);
        const outcome = try walk.verify(&set, &owner, .authority);
        if (outcome != .valid) return Walk.failed(outcome, name);
        signed.* = true;
    }
    return null;
}

/// Whether the record at `index` is the first of its RRset of `kind` in the authority section;
/// its owner goes in `owner`.
fn first_of(walk: *Walk, index: usize, kind: Kind, owner: *Name) Error!bool {
    const message = walk.message;
    if (message.sections[index] != .authority or !message.records[index].is_kind(kind)) return false;
    try message.records[index].owner_name(message.bytes, owner);
    for (0..index) |earlier| if (try message.holds(earlier, .authority, kind, owner)) return false;
    return true;
}

/// Whether the authority section holds no SOA, NSEC or NSEC3: nothing a negative rests on.
pub fn silent(walk: *const Walk) bool {
    return !has(walk, .soa) and !has(walk, .nsec) and !has(walk, .nsec3);
}

fn has(walk: *const Walk, kind: Kind) bool {
    const message = walk.message;
    for (0..message.count) |index| {
        if (message.sections[index] == .authority and message.records[index].is_kind(kind)) return true;
    }
    return false;
}

/// The verified records a proof reads. Each one costs a verification at least, so the message's
/// budget bounds them.
pub const Nsecs = Gathered(nsec.Record);
pub const Nsec3s = Gathered(nsec3.Record);

/// The list in the scratch, with nothing in it. Its items are left as the last message wrote them.
fn emptied(list: anytype) @TypeOf(list) {
    list.len = 0;
    return list;
}

fn Gathered(comptime Record: type) type {
    return struct {
        items: [limits.verifications_per_message_max]Record = undefined,
        len: usize = 0,

        fn slice(self: *const @This()) []const Record {
            return self.items[0..self.len];
        }
    };
}

/// Verifies each NSEC RRset of the authority section, and keeps the valid ones. One with no
/// signature is passed over; one whose signer's keys are wanted, or that is bogus, ends the
/// message, at `name`.
fn gather_nsec(walk: *Walk, name: *const Name, out: *Nsecs) Error!?Validation {
    const message = walk.message;
    for (0..message.count) |index| {
        var owner: Name = Name.empty;
        if (!try first_of(walk, index, .nsec, &owner)) continue;
        const set = try message.rrset(.authority, .nsec, &owner);
        const outcome = try walk.verify(&set, &owner, .authority);
        switch (outcome) {
            .valid => |valid| {
                assert(out.len < out.items.len);
                const parsed = wire.rdata.Nsec.parse(set.record(0).rdata) catch return .{ .bogus = .message };
                out.items[out.len] = .{ .owner = owner, .signer = valid.signer, .labels = valid.labels, .nsec = parsed };
                out.len += 1;
            },
            .unsigned => {},
            else => return Walk.failed(outcome, name),
        }
    }
    return null;
}

/// As `gather_nsec`, for NSEC3.
fn gather_nsec3(walk: *Walk, name: *const Name, out: *Nsec3s) Error!?Validation {
    const message = walk.message;
    for (0..message.count) |index| {
        var owner: Name = Name.empty;
        if (!try first_of(walk, index, .nsec3, &owner)) continue;
        const set = try message.rrset(.authority, .nsec3, &owner);
        const outcome = try walk.verify(&set, &owner, .authority);
        switch (outcome) {
            .valid => |valid| {
                assert(out.len < out.items.len);
                const parsed = wire.rdata.Nsec3.parse(set.record(0).rdata) catch return .{ .bogus = .message };
                out.items[out.len] = .{ .owner = owner, .signer = valid.signer, .nsec3 = parsed };
                out.len += 1;
            },
            .unsigned => {},
            else => return Walk.failed(outcome, name),
        }
    }
    return null;
}

// Tests.

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
