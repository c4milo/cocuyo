//! The key store a validating consumer owns, and the calls a table's `Trust` makes of it
//! (docs/design.md §25, step 12). `cocuyo.validated_by` names these calls in a `Trust`, since
//! `resolver` and `dnssec` may not import each other. A consumer names `KeyStore`, its `Entry`
//! and `Anchor`, and nothing else of this module.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Kind = core.Kind;
const Name = core.Name;
const Validation = core.Validation;
const validation = core.validation;
const dnssec = @import("dnssec.zig");
const store_module = @import("dnssec_store.zig");
const Walker = @import("dnssec_walk.zig").Walker;
const Scratch = @import("dnssec_scratch.zig").Scratch;

/// A trust anchor: a DS or a DNSKEY record for a zone, whose rdata the caller keeps for as long as
/// the store lives (RFC 4035 §4.4).
pub const Anchor = store_module.Anchor;

/// The keys a validating table has proved, and the walks that fetch the keys it lacks. The caller
/// owns its entries and sizes them; cocuyo allocates nothing. Started in place, since the walks
/// name the store beside them, and it must not move once started.
pub const KeyStore = struct {
    /// One zone the store holds. The caller supplies them, and never reads one.
    pub const Entry = store_module.Entry;

    store: store_module.Store,
    walker: Walker,
    /// The memory one validation writes, held here so that none fills it (§17 question 108).
    scratch: Scratch,

    /// `verifier` and `hasher` are the cryptography, `cocuyo_dnssec`'s over chapulin. `clock` is
    /// the time of day at an instant of the caller's (§25, Time).
    pub fn init(
        self: *KeyStore,
        entries: []Entry,
        anchors: []const Anchor,
        verifier: dnssec.Verifier,
        hasher: dnssec.nsec3.Hasher,
        clock: core.Clock,
    ) void {
        assert(anchors.len >= 1);
        self.store = .init(entries, anchors);
        self.store.set_clock(clock);
        self.scratch = .{};
        self.walker = .{ .store = &self.store, .verifier = verifier, .hasher = hasher, .scratch = &self.scratch };
    }

    /// The caller corrected its clock: `clock` is the time of day now. Its `unix_seconds` may go
    /// backwards, and its `now_ns` never does.
    pub fn set_clock(self: *KeyStore, clock: core.Clock) void {
        self.store.set_clock(clock);
    }

    /// The context of every call below.
    pub fn context(self: *KeyStore) *anyopaque {
        assert(self.walker.store == &self.store);
        return &self.walker;
    }
};

/// The calls of a `Trust`, each over the walker a `KeyStore.context` names.
pub const calls = struct {
    pub fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation {
        return walker_of(context).validator().validate(asked, kind, message, now_ns);
    }

    pub fn join(context: *anyopaque, target: *const Name, now_ns: u64) ?u8 {
        return walker_of(context).join(target, now_ns);
    }

    pub fn next_question(context: *anyopaque) ?validation.Asked {
        return walker_of(context).next_question();
    }

    pub fn answered(context: *anyopaque, walk: u8, message: []const u8, now_ns: u64) void {
        walker_of(context).answered(walk, message, now_ns);
    }

    pub fn question_failed(context: *anyopaque, walk: u8, failure: validation.Walked) void {
        walker_of(context).question_failed(walk, failure);
    }

    pub fn end(context: *anyopaque, walk: u8) ?validation.End {
        return walker_of(context).end(walk);
    }

    pub fn release(context: *anyopaque, walk: u8) void {
        walker_of(context).release(walk);
    }

    fn walker_of(context: *anyopaque) *Walker {
        return @ptrCast(@alignCast(context));
    }
};

// Tests. The walks' rules are `dnssec_walk.zig`'s and tested there; these show that each call
// reaches its walk.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const zone = @import("rfc4035/fixtures.zig");

/// The entries of a test's store.
const entries_count: usize = 4;

const Fixture = struct {
    entries: [entries_count]KeyStore.Entry = undefined,
    anchors: [1]Anchor = .{.{ .zone = named("example"), .kind = .dnskey, .rdata = &zone.ksk }},
    sums: fixtures.Sums = .{},
    hashes: fixtures.Hashes = .{},
    keys: KeyStore = undefined,

    fn init(self: *Fixture) *anyopaque {
        self.keys.init(&self.entries, &self.anchors, self.sums.verifier(), self.hashes.hasher(), .{ .unix_seconds = zone.now_seconds, .now_ns = 0 });
        return self.keys.context();
    }
};

fn named(text: []const u8) Name {
    return Name.from_text(text) catch unreachable;
}

test "a joined walk asks the anchor's keys, and fails as its question failed" {
    var fixture: Fixture = .{};
    const context = fixture.init();
    const walk = calls.join(context, &named("a.example"), 0).?;
    const asked = calls.next_question(context).?;
    try testing.expectEqual(walk, asked.walk);
    try testing.expect(asked.question.name.equal(&named("example")));
    try testing.expectEqual(Kind.dnskey, asked.question.kind);
    try testing.expectEqual(@as(?validation.Asked, null), calls.next_question(context));
    try testing.expectEqual(@as(?validation.End, null), calls.end(context, walk));
    calls.question_failed(context, walk, .timeout);
    try testing.expectEqual(validation.End{ .failed = .timeout }, calls.end(context, walk).?);
    calls.release(context, walk);
    try testing.expect(fixture.keys.walker.walks[walk].phase == .free);
}

test "a walk's answer reaches its walk, under the store's time of day" {
    var fixture: Fixture = .{};
    const context = fixture.init();
    var keys = zone.keys();
    // Before the walk, `example`'s keys are wanted to read their own set.
    try testing.expect(calls.validate(context, &named("example"), .dnskey, keys.message(), 0) == .keys_wanted);
    const walk = calls.join(context, &named("example"), 0).?;
    _ = calls.next_question(context).?;
    // The set matches the anchor and verifies at the time of day `init` pinned (walk rule 4).
    calls.answered(context, walk, keys.message(), 0);
    try testing.expectEqual(validation.End.ready, calls.end(context, walk).?);
    try testing.expect(calls.validate(context, &named("example"), .dnskey, keys.message(), 0) == .secure);
}
