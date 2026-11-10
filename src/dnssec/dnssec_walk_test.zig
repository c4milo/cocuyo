//! Tests of the walks for keys (`dnssec_walk.zig`). Split from it by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Kind = core.Kind;
const Name = core.Name;
const Question = core.Question;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const store_module = @import("dnssec_store.zig");
const Store = store_module.Store;
const walk_module = @import("dnssec_walk.zig");
const End = walk_module.End;
const Scratch = @import("dnssec_scratch.zig").Scratch;
const Walker = walk_module.Walker;

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const zone = @import("rfc4035/fixtures.zig");
const nsec3_zone = @import("rfc5155/fixtures.zig");
const Builder = fixtures.Builder;

fn named(text: []const u8) Name {
    return Name.parse(text) catch unreachable;
}

/// A store of eight entries holds every zone a test's walk reaches, and none is replaced.
const entries_count: usize = 8;

/// The anchors a fixture may hold: `example`'s, and the root's.
const anchors_count: usize = 2;

/// The questions a walk asks to enter `a.example` from `example`'s anchor: `example DNSKEY`, then
/// `a.example DS` and `a.example DNSKEY`.
const child_questions: u8 = 3;

/// The questions of the test whose walk begins again: three, the first one counted.
const restart_questions: u8 = 3;

/// RFC 4035 Appendix A's zone under a DNSKEY anchor, with a store and the tests' cryptography.
const Fixture = struct {
    entries: [entries_count]store_module.Entry = undefined,
    anchors: [anchors_count]store_module.Anchor = undefined,
    store: Store = undefined,
    sums: fixtures.Sums = .{},
    hashes: fixtures.Hashes = .{},
    walker: Walker = undefined,
    scratch: Scratch = .{},

    fn init(self: *Fixture) void {
        self.init_anchored(1);
    }

    /// `example`'s anchor, and with `count` of 2 the root's too, of another key.
    fn init_anchored(self: *Fixture, count: usize) void {
        self.anchors = .{
            .{ .zone = named("example"), .kind = .dnskey, .rdata = &zone.ksk },
            .{ .zone = Name.root, .kind = .dnskey, .rdata = &zone.zsk_twin },
        };
        self.store = Store.init(&self.entries, self.anchors[0..count]);
        self.store.set_clock(.{ .unix_seconds = zone.now_seconds, .monotonic_ns = 0 });
        self.walker = .{ .store = &self.store, .verifier = self.sums.verifier(), .hasher = self.hashes.hasher(), .scratch = &self.scratch };
    }

    /// The store holds `example`'s keys until `expires_ns`, as an earlier walk left them.
    fn hold_example(self: *Fixture, expires_ns: u64) void {
        assert(self.store.put(&named("example"), .keys, &.{ &zone.zsk, &zone.ksk }, expires_ns));
    }

    /// The walk asks `name` of `kind`, and reads `bytes` as the answer at `now_ns`.
    fn ask(self: *Fixture, index: u8, name: []const u8, kind: Kind, bytes: []const u8, now_ns: u64) !void {
        const asked = self.walker.question(index) orelse return error.NoQuestion;
        try testing.expect(asked.name.equal(&named(name)));
        try testing.expectEqual(kind, asked.kind);
        try testing.expect(asked.absolute);
        try testing.expectEqual(@as(?Question, null), self.walker.question(index));
        self.walker.answered(index, bytes, now_ns);
    }

    fn known(self: *const Fixture, name: []const u8) ?store_module.Known {
        const entry = self.store.find(&named(name), 0) orelse return null;
        return entry.known;
    }
};

/// The walk at `index` enters `example` under its anchor, then the signed child `a.example`.
fn enter_child(fixture: *Fixture, index: u8) !void {
    var keys = zone.keys();
    try fixture.ask(index, "example", .dnskey, keys.message(), 0);
    const ds = zone.child_ds();
    var ds_answer = zone.ds_answer(&ds);
    try fixture.ask(index, "a.example", .ds, ds_answer.message(), 0);
    try testing.expectEqual(store_module.Known.ds, fixture.known("a.example").?);
    try testing.expectEqual(@as(?End, null), fixture.walker.end(index));
    var child_keys = zone.child_keys();
    try fixture.ask(index, "a.example", .dnskey, child_keys.message(), 0);
    try testing.expectEqual(store_module.Known.keys, fixture.known("a.example").?);
    try testing.expectEqual(child_questions, fixture.walker.walks[index].questions);
}

test "a walk enters the anchor, then a signed child, and ends with the child's keys held" {
    var fixture: Fixture = .{};
    fixture.init();
    const index = fixture.walker.join(&named("a.example"), 0).?;
    try enter_child(&fixture, index);
    try testing.expectEqual(End.ready, fixture.walker.end(index).?);
    // A name under the child begins where the store stands: one question, of the next label.
    fixture.walker.release(index);
    const below = fixture.walker.join(&named("mc.a.example"), 0).?;
    try testing.expect(fixture.walker.question(below).?.name.equal(&named("mc.a.example")));
}

test "a walk below a signed child stands in the child once its keys enter" {
    var fixture: Fixture = .{};
    fixture.init();
    const index = fixture.walker.join(&named("mc.a.example"), 0).?;
    try enter_child(&fixture, index);
    try testing.expectEqual(@as(?End, null), fixture.walker.end(index));
    const asked = fixture.walker.question(index).?;
    try testing.expect(asked.name.equal(&named("mc.a.example")));
    try testing.expectEqual(Kind.ds, asked.kind);
}

test "the deepest anchor above the target is the one a walk enters" {
    var fixture: Fixture = .{};
    fixture.init_anchored(anchors_count);
    const index = fixture.walker.join(&named("a.example"), 0).?;
    try testing.expect(fixture.walker.question(index).?.name.equal(&named("example")));
}

test "a DNSKEY set that matches no held DS set fails the walk as bogus" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("a.example"), 0).?;
    const other = fixtures.ds_of(&named("a.example"), &zone.zsk_twin, 5, 2);
    var ds_answer = zone.ds_answer(&other);
    try fixture.ask(index, "a.example", .ds, ds_answer.message(), 0);
    var child_keys = zone.child_keys();
    try fixture.ask(index, "a.example", .dnskey, child_keys.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
    try testing.expectEqual(store_module.Known.ds, fixture.known("a.example").?);
    // The DS set stays, so a walk for the child asks its keys at once.
    fixture.walker.release(index);
    const again = fixture.walker.join(&named("a.example"), 0).?;
    try testing.expectEqual(Kind.dnskey, fixture.walker.question(again).?.kind);
}

test "keys that expire as they enter fail the walk" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("a.example"), 0).?;
    const ds = zone.child_ds();
    var ds_answer = zone.ds_answer(&ds);
    try fixture.ask(index, "a.example", .ds, ds_answer.message(), 0);
    var brief = Builder.init("a.example", .dnskey, 0);
    var signing = zone.by_key_signing;
    signing.signer = "a.example";
    signing.original_ttl = 0;
    brief.rrset("a.example", .dnskey, &.{ &zone.zsk, &zone.ksk }, signing);
    try fixture.ask(index, "a.example", .dnskey, brief.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
}

test "a DS set of more records than the store keeps fails the walk" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("a.example"), 0).?;
    var records: [limits.ds_records_max + 1]fixtures.DsRdata = undefined;
    var slices: [limits.ds_records_max + 1][]const u8 = undefined;
    for (&records, &slices, 0..) |*rdata, *slice, count| {
        rdata.* = zone.child_ds();
        rdata[0] = @intCast(count);
        slice.* = rdata;
    }
    var many = Builder.init("a.example", .ds, 0);
    many.rrset("a.example", .ds, &slices, zone.by_zone);
    try fixture.ask(index, "a.example", .ds, many.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
    try testing.expectEqual(@as(?store_module.Known, null), fixture.known("a.example"));
}

test "a delegation with no DS ends the walk with the store holding it insecure" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("mc.b.example"), 0).?;
    var denied = zone.ds_denied("b.example", "b.example", zone.nsec_at_b);
    try fixture.ask(index, "b.example", .ds, denied.message(), 0);
    try testing.expectEqual(End.ready, fixture.walker.end(index).?);
    try testing.expectEqual(store_module.Known.insecure, fixture.known("b.example").?);
}

test "a second walk's answer, which the store already speaks for, ends it too" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const first = fixture.walker.join(&named("mc.b.example"), 0).?;
    const second = fixture.walker.join(&named("x.b.example"), 0).?;
    var denied = zone.ds_denied("b.example", "b.example", zone.nsec_at_b);
    const asked = fixture.walker.question(second).?;
    try fixture.ask(first, "b.example", .ds, denied.message(), 0);
    try testing.expect(asked.name.equal(&named("b.example")));
    fixture.walker.answered(second, denied.message(), 0);
    try testing.expectEqual(End.ready, fixture.walker.end(second).?);
}

test "a walk whose zone another walk entered first stands in it, and keeps its keys" {
    const ds = zone.child_ds();
    var ds_answer = zone.ds_answer(&ds);
    var child_keys = zone.child_keys();
    // Both walks ask `a.example DS`. The first enters the zone before the second's answer
    // comes, which must not put the DS set back in place of the keys.
    var late_ds: Fixture = .{};
    late_ds.init();
    late_ds.hold_example(std.math.maxInt(u64));
    const first = late_ds.walker.join(&named("a.example"), 0).?;
    const second = late_ds.walker.join(&named("x.a.example"), 0).?;
    _ = late_ds.walker.question(second).?;
    try late_ds.ask(first, "a.example", .ds, ds_answer.message(), 0);
    try late_ds.ask(first, "a.example", .dnskey, child_keys.message(), 0);
    try testing.expectEqual(End.ready, late_ds.walker.end(first).?);
    late_ds.walker.answered(second, ds_answer.message(), 0);
    try testing.expectEqual(store_module.Known.keys, late_ds.known("a.example").?);
    try testing.expect(late_ds.walker.question(second).?.name.equal(&named("x.a.example")));
    // Both walks ask `a.example DNSKEY`. The second's answer finds the keys held, not the DS
    // set, and stands in the zone with no new start.
    var late_keys: Fixture = .{};
    late_keys.init();
    late_keys.hold_example(std.math.maxInt(u64));
    const one = late_keys.walker.join(&named("a.example"), 0).?;
    const other = late_keys.walker.join(&named("x.a.example"), 0).?;
    try late_keys.ask(one, "a.example", .ds, ds_answer.message(), 0);
    try late_keys.ask(other, "a.example", .ds, ds_answer.message(), 0);
    _ = late_keys.walker.question(other).?;
    try late_keys.ask(one, "a.example", .dnskey, child_keys.message(), 0);
    late_keys.walker.answered(other, child_keys.message(), 0);
    try testing.expect(!late_keys.walker.walks[other].restarted);
    try testing.expect(late_keys.walker.question(other).?.name.equal(&named("x.a.example")));
}

test "an NSEC3 at a delegation with no DS bit ends the walk insecure" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("mc.c.example"), 0).?;
    var denied = nsec3_zone.ds_unsigned(.{ .flags = 0 });
    try fixture.ask(index, "c.example", .ds, denied.message(), 0);
    try testing.expectEqual(End.ready, fixture.walker.end(index).?);
    try testing.expectEqual(store_module.Known.insecure, fixture.known("c.example").?);
}

test "an empty non-terminal moves the walk down, and unsigned data in a signed zone is bogus" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("x.w.example"), 0).?;
    var empty = zone.ds_denied("w.example", "ns2.example", zone.nsec_at_ns2);
    try fixture.ask(index, "w.example", .ds, empty.message(), 0);
    try testing.expectEqual(@as(?End, null), fixture.walker.end(index));
    var host = zone.ds_denied("x.w.example", "x.w.example", zone.nsec_at_x_w);
    try fixture.ask(index, "x.w.example", .ds, host.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
    try testing.expectEqual(@as(?store_module.Known, null), fixture.known("x.w.example"));
}

test "a CNAME that no valid DNAME makes fails its walk as bogus, and is never insecure" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    // RFC 6672 §2.2: `d.example DNAME w.example` makes `x.d.example CNAME x.w.example`, and not
    // the unsigned CNAME to `y.w.example` that this message holds.
    var forged = Builder.init("x.d.example", .a, 0);
    forged.rrset("d.example", .dname, &.{"\x01w\x07example\x00"}, zone.by_zone);
    forged.record("x.d.example", .cname, 3600, "\x01y\x01w\x07example\x00");
    forged.rrset("y.w.example", .a, &.{&zone.address}, zone.by_zone);
    const wanted = fixture.walker.validator().validate(&named("x.d.example"), .a, forged.message(), 0);
    const index = fixture.walker.join(&wanted.keys_wanted, 0).?;
    // `d.example` exists, holds the DNAME and no DS, and is no delegation.
    var no_ds = zone.ds_denied("d.example", "d.example", "\x03ns1\x07example\x00" ++ fixtures.redirect);
    try fixture.ask(index, "d.example", .ds, no_ds.message(), 0);
    try testing.expectEqual(@as(?End, null), fixture.walker.end(index));
    // Below it the DNAME speaks: `x.d.example` is the alias it makes, so no data of its own is
    // there to be unsigned.
    var alias = Builder.init("x.d.example", .ds, 0);
    alias.rrset("d.example", .dname, &.{"\x01w\x07example\x00"}, zone.by_zone);
    alias.record("x.d.example", .cname, 3600, "\x01x\x01w\x07example\x00");
    try fixture.ask(index, "x.d.example", .ds, alias.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
    try testing.expectEqual(@as(?store_module.Known, null), fixture.known("x.d.example"));
}

test "an answer that proves nothing at a name moves the walk on, and fails it at the target" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    // `b.example DS` answered with the zone's SOA and no NSEC: signed, and a proof of nothing, as
    // NSD's answer at an empty non-terminal under Opt-Out is (docs/design.md §25 walk rule 6).
    var unproven = Builder.init("b.example", .ds, 0);
    unproven.authority();
    zone.apex_soa(&unproven);
    const index = fixture.walker.join(&named("a.b.example"), 0).?;
    try fixture.ask(index, "b.example", .ds, unproven.message(), 0);
    try testing.expectEqual(@as(?End, null), fixture.walker.end(index));
    // One label down, the NSEC at `b.example` proves a delegation with no DS (rule 5).
    var below = zone.ds_denied("a.b.example", "b.example", zone.nsec_at_b);
    try fixture.ask(index, "a.b.example", .ds, below.message(), 0);
    try testing.expectEqual(End.ready, fixture.walker.end(index).?);
    // At the target itself the same answer fails the walk (rule 8).
    const at_target = fixture.walker.join(&named("b.example"), 0).?;
    try fixture.ask(at_target, "b.example", .ds, unproven.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(at_target).?);
    // A signature that fails ends the walk at once, wherever it is.
    var forged = Builder.init("b.example", .ds, 0);
    forged.authority();
    forged.rrset("example", .soa, &.{zone.soa}, zone.by_wrong_key);
    const signed_wrongly = fixture.walker.join(&named("x.b.example"), 0).?;
    try fixture.ask(signed_wrongly, "b.example", .ds, forged.message(), 0);
    try testing.expectEqual(@as(?End, .{ .failed = .bogus }), fixture.walker.end(signed_wrongly));
}

test "a proof that a name on the way does not exist fails the walk as bogus" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(std.math.maxInt(u64));
    const index = fixture.walker.join(&named("mc.ml.example"), 0).?;
    var missing = Builder.init("ml.example", .ds, 3);
    missing.authority();
    zone.apex_soa(&missing);
    missing.rrset("b.example", .nsec, &.{zone.nsec_at_b}, zone.by_zone);
    missing.rrset("example", .nsec, &.{zone.nsec_at_apex}, zone.by_zone);
    try fixture.ask(index, "ml.example", .ds, missing.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
}

test "a walk whose own answer wants keys the store lost begins again, once" {
    var fixture: Fixture = .{};
    fixture.init();
    fixture.hold_example(1);
    const index = fixture.walker.join(&named("a.example"), 0).?;
    const ds = zone.child_ds();
    var ds_answer = zone.ds_answer(&ds);
    try fixture.ask(index, "a.example", .ds, ds_answer.message(), 2);
    var keys = zone.keys();
    try fixture.ask(index, "example", .dnskey, keys.message(), 2);
    // The keys enter for their TTL of an hour; past it, the second loss is bogus.
    const later = 3601 * constants.ns_per_second;
    try fixture.ask(index, "a.example", .ds, ds_answer.message(), later);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(index).?);
    // The DS set, `example`'s keys, then the DS set again: the restart kept the count.
    try testing.expectEqual(restart_questions, fixture.walker.walks[index].questions);
}

test "an unanswered question fails the walk with its failure, and the questions are bounded" {
    var fixture: Fixture = .{};
    fixture.init();
    const index = fixture.walker.join(&named("a.example"), 0).?;
    _ = fixture.walker.question(index).?;
    fixture.walker.question_failed(index, .timeout);
    try testing.expectEqual(End{ .failed = .timeout }, fixture.walker.end(index).?);
    fixture.walker.release(index);
    const bounded = fixture.walker.join(&named("a.example"), 0).?;
    fixture.walker.walks[bounded].questions = limits.chain_questions_max - 1;
    var keys = zone.keys();
    try fixture.ask(bounded, "example", .dnskey, keys.message(), 0);
    try testing.expectEqual(@as(?End, null), fixture.walker.end(bounded));
    const ds = zone.child_ds();
    var ds_answer = zone.ds_answer(&ds);
    try fixture.ask(bounded, "a.example", .ds, ds_answer.message(), 0);
    try testing.expectEqual(End{ .failed = .bogus }, fixture.walker.end(bounded).?);
}

test "one walk serves a target, and a target that finds every walk busy gets none" {
    var fixture: Fixture = .{};
    fixture.init();
    const targets = [_][]const u8{ "a.example", "b.example", "c.example", "d.example" };
    comptime assert(targets.len == limits.walks_max);
    for (targets, 0..) |target, index| {
        try testing.expectEqual(@as(?u8, @intCast(index)), fixture.walker.join(&named(target), 0));
    }
    try testing.expectEqual(@as(?u8, 1), fixture.walker.join(&named("B.example"), 0));
    try testing.expectEqual(@as(?u8, null), fixture.walker.join(&named("e.example"), 0));
    _ = fixture.walker.question(2).?;
    fixture.walker.question_failed(2, .failed);
    fixture.walker.release(2);
    try testing.expectEqual(@as(?u8, 2), fixture.walker.join(&named("e.example"), 0));
    // A name under no anchor needs no walk: it is insecure at once.
    var lone: Fixture = .{};
    lone.init();
    const elsewhere = lone.walker.join(&named("example.org"), 0).?;
    try testing.expectEqual(End.ready, lone.walker.end(elsewhere).?);
}

test "the table takes each walk's question once, the first walk's first" {
    var fixture: Fixture = .{};
    fixture.init_anchored(anchors_count);
    const first = fixture.walker.join(&named("a.example"), 0).?;
    const second = fixture.walker.join(&named("c.example"), 0).?;
    try testing.expect(first != second);
    try testing.expectEqual(first, fixture.walker.next_question().?.walk);
    try testing.expectEqual(second, fixture.walker.next_question().?.walk);
    try testing.expectEqual(@as(?core.validation.Asked, null), fixture.walker.next_question());
}
