//! The validator: it reads a whole message for the name and the type a lookup asks, and says
//! whether what the lookup takes from it is secure, insecure or bogus, or whose keys it waits for
//! (docs/design.md §25, Stage B: what is verified in a message, and step 9). It reads the message
//! in place and keeps none of it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Kind = core.Kind;
const Name = core.Name;
const dnssec = @import("dnssec.zig");
const Verifier = dnssec.Verifier;
const proof = @import("dnssec_nsec3_proof.zig");
const rrset = @import("dnssec_rrset.zig");
const message_reader = @import("dnssec_message.zig");
const Message = message_reader.Message;
const Rrset = message_reader.Rrset;
const store_module = @import("dnssec_store.zig");
const Store = store_module.Store;
const denial = @import("dnssec_validate_denial.zig");
const limits = @import("limits.zig");

/// What a secure message ends a lookup with: its answer, or the negative its proof gives (RFC
/// 9824 §8: the response code is not signed, so the proof decides).
pub const Ending = enum { answer, no_data, name_error };

pub const Secure = struct {
    ending: Ending,
    /// The smallest TTL of item 7 over every RRset the lookup used.
    ttl_seconds: u32,
};

pub const Reason = enum {
    /// A signature over an RRset the lookup uses failed, or the work ran past a limit.
    signature,
    /// The NSEC or NSEC3 records of a negative, or of a wildcard answer, prove nothing.
    proof,
    /// The message is malformed, holds more than `records_max` records, or a chain longer than
    /// `cname_hops_max`, which the lookup fails anyway.
    message,
};

pub const Validation = union(enum) {
    secure: Secure,
    insecure,
    /// The question cannot be secure: an RRSIG is never signed (RFC 4035 §2.2, item 15).
    unchecked,
    bogus: Reason,
    /// The validator waits for the keys of this zone, or, for data with no signature, for a walk
    /// to this name (§25, walk rule 1).
    keys_wanted: Name,
};

pub const Validator = struct {
    store: *const Store,
    verifier: Verifier,
    hasher: proof.Hasher,

    /// Reads `bytes`, a response that passed the checks of docs/design.md §7, for `asked` of
    /// `kind`.
    pub fn validate(self: *const Validator, asked: *const Name, kind: Kind, bytes: []const u8, now_ns: u64) Validation {
        assert(asked.len >= 1);
        if (kind == .rrsig) return .unchecked;
        if (self.insecure_at(asked, now_ns)) return .insecure;
        var message: Message = undefined;
        const fits = message.read(bytes, asked) catch return .{ .bogus = .message };
        if (!fits) return .{ .bogus = .message };
        var walk: Walk = .{
            .validator = self,
            .message = &message,
            .at = .{ .store = self.store, .now_ns = now_ns },
            .now_seconds = self.store.now_seconds(now_ns),
        };
        return walk.chain(asked, kind) catch .{ .bogus = .message };
    }

    /// Whether `name` is insecure by what the store holds: under no anchor, or at or under an
    /// insecure delegation (§25).
    pub fn insecure_at(self: *const Validator, name: *const Name, now_ns: u64) bool {
        if (!self.store.anchored(name)) return true;
        const entry = self.store.deepest(name, now_ns) orelse return false;
        return entry.known == .insecure;
    }
};

/// One message's validation: what it reads, the budget left, and the smallest TTL so far.
pub const Walk = struct {
    validator: *const Validator,
    message: *const Message,
    at: store_module.At,
    now_seconds: u32,
    budget: rrset.Budget = .{},
    ttl_seconds: u32 = std.math.maxInt(u32),
    /// The NSEC3 hashes the message cost so far.
    hashes: usize = 0,

    /// The caller's hasher, counted against `nsec3_hashes_per_message_max` (RFC 4035 §5.4).
    pub fn hasher(self: *Walk) proof.Hasher {
        return .{ .context = self, .compute = counted };
    }

    fn counted(context: *anyopaque, name: []const u8, salt: []const u8, iterations: u16, out: *proof.Hash) void {
        const self: *Walk = @ptrCast(@alignCast(context));
        self.hashes += 1;
        self.validator.hasher.compute(self.validator.hasher.context, name, salt, iterations, out);
    }

    /// Whether the message cost more hashes than one proof may, which makes it bogus.
    pub fn hashed_past(self: *const Walk) bool {
        return self.hashes > limits.nsec3_hashes_per_message_max;
    }

    pub fn verify(self: *Walk, set: *const Rrset, owner: *const Name, section: message_reader.Section) Error!rrset.Outcome {
        const check: rrset.Check = .{
            .message = self.message,
            .signers = self.validator.store.signers(&self.at),
            .verifier = self.validator.verifier,
            .now_seconds = self.now_seconds,
            .budget = &self.budget,
        };
        const outcome = try rrset.verify(check, set, owner, section);
        if (outcome == .valid) self.ttl_seconds = @min(self.ttl_seconds, outcome.valid.ttl_seconds);
        return outcome;
    }

    /// The end an RRset's outcome gives when it is not valid: its signer's keys, a walk to `at`
    /// when it has no signature, or bogus.
    pub fn failed(outcome: rrset.Outcome, at: *const Name) Validation {
        return switch (outcome) {
            .valid => unreachable,
            .unsigned => .{ .keys_wanted = at.* },
            .keys_wanted => |signer| .{ .keys_wanted = signer },
            .bogus => .{ .bogus = .signature },
        };
    }

    pub fn secure(self: *const Walk, ending: Ending) Validation {
        return .{ .secure = .{ .ending = ending, .ttl_seconds = self.ttl_seconds } };
    }

    /// The chain from `asked`: an RRset of `kind` ends it, and a CNAME is a link to its target,
    /// `cname_hops_max` links at most (item 9). With neither, the chain ends in a negative. A
    /// question for CNAME finds its RRset first, so it follows no link.
    fn chain(self: *Walk, asked: *const Name, kind: Kind) Error!Validation {
        var name = asked.*;
        for (0..core.limits.cname_hops_max + 1) |_| {
            if (self.validator.insecure_at(&name, self.at.now_ns)) return .insecure;
            if (kind == .any) return denial.any(self, &name);
            const set = try self.message.rrset(.answer, kind, &name);
            if (set.count() > 0) return self.answer(&name, &set);
            switch (try denial.link(self, &name)) {
                .none => return denial.negative(self, &name, kind),
                .next => |target| name = target,
                .ended => |end| return end,
            }
        }
        return .{ .bogus = .message };
    }

    fn answer(self: *Walk, name: *const Name, set: *const Rrset) Error!Validation {
        const outcome = try self.verify(set, name, .answer);
        if (outcome != .valid) return failed(outcome, name);
        if (denial.expanded(name, outcome.valid.labels)) return denial.wildcard(self, name, outcome.valid.labels, .answer);
        return self.secure(.answer);
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const zone = @import("rfc4035/fixtures.zig");
const Builder = fixtures.Builder;

const Setup = zone.Setup;

fn named(text: []const u8) Name {
    return Name.from_text(text) catch unreachable;
}

fn expect_secure(result: Validation, ending: Ending) !void {
    try testing.expect(result == .secure);
    try testing.expectEqual(ending, result.secure.ending);
    try testing.expectEqual(zone.by_zone.original_ttl, result.secure.ttl_seconds);
}

test "B.1's answer, B.2's name error and B.3's no data are secure, by their proofs" {
    var setup: Setup = .{};
    setup.init();
    var answer = zone.answer();
    try expect_secure(setup.validate("x.w.example", .mx, answer.message()), .answer);
    var name_error = zone.name_error();
    try expect_secure(setup.validate("ml.example", .a, name_error.message()), .name_error);
    var no_data = zone.no_data();
    try expect_secure(setup.validate("ns1.example", .mx, no_data.message()), .no_data);
}

test "B.6's wildcard answer and B.7's wildcard no data are secure, and need their proofs" {
    var setup: Setup = .{};
    setup.init();
    var wildcard = zone.wildcard();
    try expect_secure(setup.validate("a.z.w.example", .mx, wildcard.message()), .answer);
    var wildcard_no_data = zone.wildcard_no_data();
    try expect_secure(setup.validate("a.z.w.example", .aaaa, wildcard_no_data.message()), .no_data);
    // B.6 without its NSEC record: nothing proves no closer match exists.
    var bare = Builder.init("a.z.w.example", .mx, 0);
    var expanded_signing = zone.by_zone;
    expanded_signing.labels = 2;
    bare.rrset("a.z.w.example", .mx, &.{"\x00\x01\x02ai\x07example\x00"}, expanded_signing);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("a.z.w.example", .mx, bare.message()));
}

test "B.4's referral waits for a walk, B.5's is insecure, and B.8's DS at the child is bogus" {
    var setup: Setup = .{};
    setup.init();
    var signed = zone.referral_signed();
    const wanted = setup.validate("mc.a.example", .mx, signed.message());
    try testing.expect(wanted.keys_wanted.equal(&named("mc.a.example")));
    var unsigned = zone.referral_unsigned();
    try testing.expectEqual(Validation.insecure, setup.validate("mc.b.example", .mx, unsigned.message()));
    var ds = zone.ds_at_child();
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("example", .ds, ds.message()));
}

/// Whether the record at `index` is one a validation of the message uses: no NS RRset, nor its
/// RRSIG, since neither the answer nor a proof rests on them (§25 item 1).
fn used(message: *const Message, index: usize) bool {
    const record = &message.records[index];
    if (record.is_kind(.ns)) return false;
    if (!record.is_kind(.rrsig)) return true;
    const sig = @import("wire").rdata.Rrsig.parse(record.rdata) catch return true;
    return sig.type_covered != Kind.ns.code();
}

const Case = struct { builder: *const fn () Builder, asked: []const u8, kind: Kind };

test "every response of Appendix B is refused with any signed octet changed" {
    var setup: Setup = .{};
    setup.init();
    const cases = [_]Case{
        .{ .builder = zone.answer, .asked = "x.w.example", .kind = .mx },
        .{ .builder = zone.name_error, .asked = "ml.example", .kind = .a },
        .{ .builder = zone.no_data, .asked = "ns1.example", .kind = .mx },
        .{ .builder = zone.wildcard, .asked = "a.z.w.example", .kind = .mx },
        .{ .builder = zone.wildcard_no_data, .asked = "a.z.w.example", .kind = .aaaa },
    };
    for (cases) |case| try refused_when_changed(&setup, case);
}

/// Changes each signed octet of each record the validation of `case` uses, one at a time, and
/// requires the message to be secure before and never after.
fn refused_when_changed(setup: *Setup, case: Case) !void {
    var builder = case.builder();
    const bytes = builder.message();
    try testing.expect(setup.validate(case.asked, case.kind, bytes) == .secure);
    var message: Message = undefined;
    _ = try message.read(bytes, &named(case.asked));
    for (0..message.count) |index| {
        if (!used(&message, index)) continue;
        const record = message.records[index];
        for (record.owner_offset..record.end) |at| {
            if (!signed_octet(&record, at)) continue;
            var changed: [fixtures.message_bytes_max]u8 = undefined;
            @memcpy(changed[0..bytes.len], bytes);
            changed[at] +%= 1;
            try testing.expect(setup.validate(case.asked, case.kind, changed[0..bytes.len]) != .secure);
        }
    }
}

/// Whether the octet at `at` of `record` is one a change to must be refused. The TTLs are not
/// signed (RFC 4035 §5.3.2). An SOA turned into another type or class leaves a negative with no
/// SOA, whose proof holds and whose TTL the lookup takes as 0 (`wire.response`).
fn signed_octet(record: *const @import("wire").Record, at: usize) bool {
    const wire = @import("wire");
    const fixed_at = record.end - record.rdata.len - core.constants.record_fixed_bytes;
    const ttl_at = fixed_at + wire.constants.record_ttl_offset;
    if (at >= ttl_at and at < ttl_at + @sizeOf(u32)) return false;
    return !(record.is_kind(.soa) and at >= fixed_at and at < ttl_at);
}

test "an RRSIG question is unchecked, and a name under no anchor or an insecure delegation is insecure" {
    var setup: Setup = .{};
    setup.init();
    var answer = zone.answer();
    try testing.expectEqual(Validation.unchecked, setup.validate("x.w.example", .rrsig, answer.message()));
    try testing.expectEqual(Validation.insecure, setup.validate("x.w.org", .mx, answer.message()));
    try testing.expect(setup.store.put(&named("w.example"), .insecure, &.{}, std.math.maxInt(u64)));
    try testing.expectEqual(Validation.insecure, setup.validate("x.w.example", .mx, answer.message()));
}

test "an answer signed by a zone whose keys are not held waits for them, and one unsigned for a walk" {
    var setup: Setup = .{};
    setup.init();
    var signing = zone.by_zone;
    signing.signer = "w.example";
    var builder = Builder.init("x.w.example", .mx, 0);
    builder.rrset("x.w.example", .mx, &.{zone.mx_xx}, signing);
    try testing.expect(setup.validate("x.w.example", .mx, builder.message()).keys_wanted.equal(&named("w.example")));
    var unsigned = Builder.init("x.w.example", .mx, 0);
    unsigned.record("x.w.example", .mx, 3600, zone.mx_xx);
    try testing.expect(setup.validate("x.w.example", .mx, unsigned.message()).keys_wanted.equal(&named("x.w.example")));
    var wrong = Builder.init("x.w.example", .mx, 0);
    wrong.rrset("x.w.example", .mx, &.{zone.mx_xx}, zone.by_wrong_key);
    try testing.expectEqual(Validation{ .bogus = .signature }, setup.validate("x.w.example", .mx, wrong.message()));
}

test "a message past records_max, or malformed, is bogus" {
    var setup: Setup = .{};
    setup.init();
    var builder = Builder.init("x.w.example", .mx, 0);
    for (0..core.limits.records_max + 1) |_| builder.record("x.w.example", .mx, 3600, zone.mx_xx);
    try testing.expectEqual(Validation{ .bogus = .message }, setup.validate("x.w.example", .mx, builder.message()));
    var answer = zone.answer();
    const bytes = answer.message();
    try testing.expectEqual(Validation{ .bogus = .message }, setup.validate("x.w.example", .mx, bytes[0 .. bytes.len - 1]));
}

test "a chain of cname_hops_max links ends in its answer, and one link more is bogus" {
    var setup: Setup = .{};
    setup.init();
    const names = [_][]const u8{ "c0.example", "c1.example", "c2.example", "c3.example", "c4.example", "c5.example", "c6.example", "c7.example", "c8.example", "c9.example" };
    const targets = [_][]const u8{ "\x02c1\x07example\x00", "\x02c2\x07example\x00", "\x02c3\x07example\x00", "\x02c4\x07example\x00", "\x02c5\x07example\x00", "\x02c6\x07example\x00", "\x02c7\x07example\x00", "\x02c8\x07example\x00", "\x02c9\x07example\x00" };
    for ([_]usize{ core.limits.cname_hops_max, core.limits.cname_hops_max + 1 }) |links| {
        var builder = Builder.init("c0.example", .a, 0);
        for (0..links) |index| builder.rrset(names[index], .cname, &.{targets[index]}, zone.by_zone);
        builder.rrset(names[links], .a, &.{&.{ 192, 0, 2, 1 }}, zone.by_zone);
        const result = setup.validate("c0.example", .a, builder.message());
        if (links == core.limits.cname_hops_max) try testing.expectEqual(Ending.answer, result.secure.ending) else try testing.expectEqual(Validation{ .bogus = .message }, result);
    }
}

test "a name under no anchor is insecure before its message is read" {
    var setup: Setup = .{};
    setup.init();
    var answer = Builder.init("x.w.org", .mx, 0);
    answer.record("x.w.org", .mx, 3600, zone.mx_xx);
    const bytes = answer.message();
    try testing.expectEqual(Validation.insecure, setup.validate("x.w.org", .mx, bytes[0 .. bytes.len - 1]));
}

const nsec3_zone = @import("rfc5155/fixtures.zig");

test "RFC 5155 B.1 to B.6, with the Opt-Out flag as printed and cleared" {
    var setup: Setup = .{};
    setup.init();
    const cleared: nsec3_zone.Options = .{ .flags = 0 };
    const printed: nsec3_zone.Options = .{};
    // As printed, every proof that rests on the closest encloser proof is insecure (RFC 5155 §9.2).
    var name_error = nsec3_zone.name_error(printed);
    try testing.expectEqual(Validation.insecure, setup.validate("a.c.x.w.example", .a, name_error.message()));
    name_error = nsec3_zone.name_error(cleared);
    try testing.expectEqual(Ending.name_error, setup.validate("a.c.x.w.example", .a, name_error.message()).secure.ending);
    var no_data = nsec3_zone.no_data(printed);
    try testing.expectEqual(Ending.no_data, setup.validate("ns1.example", .mx, no_data.message()).secure.ending);
    var empty = nsec3_zone.empty_non_terminal(printed);
    try testing.expectEqual(Ending.no_data, setup.validate("y.w.example", .a, empty.message()).secure.ending);
    var referral = nsec3_zone.referral(printed);
    try testing.expectEqual(Validation.insecure, setup.validate("mc.c.example", .mx, referral.message()));
    referral = nsec3_zone.referral(cleared);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("mc.c.example", .mx, referral.message()));
    // A wildcard answer needs a cover of its next closer name alone (RFC 5155 §8.8).
    for ([_]nsec3_zone.Options{ printed, cleared }) |options| {
        var wildcard_answer = nsec3_zone.wildcard(options);
        try testing.expectEqual(Ending.answer, setup.validate("a.z.w.example", .mx, wildcard_answer.message()).secure.ending);
    }
    var wildcard_none = nsec3_zone.wildcard_no_data(cleared);
    try testing.expectEqual(Ending.no_data, setup.validate("a.z.w.example", .aaaa, wildcard_none.message()).secure.ending);
    var ds = nsec3_zone.ds_at_child(printed);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("example", .ds, ds.message()));
}

fn name_error3() Builder {
    return nsec3_zone.name_error(.{ .flags = 0 });
}
fn no_data3() Builder {
    return nsec3_zone.no_data(.{ .flags = 0 });
}
fn empty_non_terminal3() Builder {
    return nsec3_zone.empty_non_terminal(.{ .flags = 0 });
}
fn wildcard3() Builder {
    return nsec3_zone.wildcard(.{ .flags = 0 });
}
fn wildcard_no_data3() Builder {
    return nsec3_zone.wildcard_no_data(.{ .flags = 0 });
}

test "every secure response of RFC 5155 Appendix B is refused with any signed octet changed" {
    var setup: Setup = .{};
    setup.init();
    const cases = [_]Case{
        .{ .builder = name_error3, .asked = "a.c.x.w.example", .kind = .a },
        .{ .builder = no_data3, .asked = "ns1.example", .kind = .mx },
        .{ .builder = empty_non_terminal3, .asked = "y.w.example", .kind = .a },
        .{ .builder = wildcard3, .asked = "a.z.w.example", .kind = .mx },
        .{ .builder = wildcard_no_data3, .asked = "a.z.w.example", .kind = .aaaa },
    };
    for (cases) |case| try refused_when_changed(&setup, case);
}

test "an NSEC3 past the iteration limit is insecure once its signature verifies, and bogus before" {
    var setup: Setup = .{};
    setup.init();
    // RFC 9276 §3.2, before any hash: the tests' hasher refuses any iteration count but 12.
    var costly = nsec3_zone.no_data(.{ .iterations = 101 });
    try testing.expectEqual(Validation.insecure, setup.validate("ns1.example", .mx, costly.message()));
    var forged = Builder.init("ns1.example", .mx, 0);
    forged.authority();
    zone.apex_soa(&forged);
    const rdata = nsec3_zone.nsec3("2vptu5timamqttgl4luu9kg21e0aor3s", &fixtures.address3, 1, 101);
    forged.rrset("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", .nsec3, &.{&rdata}, zone.by_wrong_key);
    try testing.expectEqual(Validation{ .bogus = .signature }, setup.validate("ns1.example", .mx, forged.message()));
}

test "an unsigned NSEC3 is passed over, and a negative on nothing signed waits for a walk" {
    var setup: Setup = .{};
    setup.init();
    const rdata = nsec3_zone.nsec3("2vptu5timamqttgl4luu9kg21e0aor3s", &fixtures.address3, 0, 12);
    var extra = nsec3_zone.no_data(.{});
    extra.record("4g6p9u5gvfshp30pqecj98b3maqbn1ck.example", .nsec3, 3600, &rdata);
    try testing.expectEqual(Ending.no_data, setup.validate("ns1.example", .mx, extra.message()).secure.ending);
    var bare = Builder.init("ns1.example", .mx, 0);
    bare.authority();
    bare.record("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", .nsec3, 3600, &rdata);
    try testing.expect(setup.validate("ns1.example", .mx, bare.message()).keys_wanted.equal(&named("ns1.example")));
    // Signed, and with no NSEC3 that verifies: no proof.
    zone.apex_soa(&bare);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate("ns1.example", .mx, bare.message()));
}

test "an NSEC3 at a delegation with no DS makes a referral to it, or to its name, insecure" {
    var setup: Setup = .{};
    setup.init();
    // The hash of `c.example`, its map NS and MX: a delegation with no DS (RFC 5155 §8.9).
    const cut = nsec3_zone.nsec3("4g6p9u5gvfshp30pqecj98b3maqbn1cl", &fixtures.ns3, 0, 12);
    for ([_][]const u8{ "mc.c.example", "c.example" }) |asked| {
        var builder = Builder.init(asked, .mx, 0);
        builder.authority();
        builder.rrset("4g6p9u5gvfshp30pqecj98b3maqbn1ck.example", .nsec3, &.{&cut}, zone.by_zone);
        try testing.expectEqual(Validation.insecure, setup.validate(asked, .mx, builder.message()));
    }
}

test "an NSEC3 of the answer section is no part of an NSEC negative" {
    var setup: Setup = .{};
    setup.init();
    var builder = Builder.init("ns1.example", .mx, 0);
    const rdata = nsec3_zone.nsec3("2vptu5timamqttgl4luu9kg21e0aor3s", &fixtures.address3, 0, 12);
    builder.record("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", .nsec3, 3600, &rdata);
    builder.authority();
    zone.apex_soa(&builder);
    builder.rrset("ns1.example", .nsec, &.{"\x03ns2\x07example\x00" ++ fixtures.address}, zone.by_zone);
    try testing.expectEqual(Ending.no_data, setup.validate("ns1.example", .mx, builder.message()).secure.ending);
}

test "a referral's proofs stop once the message passes nsec3_hashes_per_message_max" {
    var setup: Setup = .{};
    setup.init();
    const deep = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.example";
    var builder = Builder.init(deep, .a, 0);
    builder.authority();
    const rdata = nsec3_zone.nsec3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", &fixtures.secure_cut3, 0, 12);
    builder.rrset("2t7b4g4vsa5smi47k61mv5bv1a22bojr.example", .nsec3, &.{&rdata}, zone.by_zone);
    try testing.expectEqual(Validation{ .bogus = .proof }, setup.validate(deep, .a, builder.message()));
    try testing.expect(setup.hashes.computed <= 2 * limits.nsec3_hashes_per_message_max);
}
