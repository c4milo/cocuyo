//! The cache above the resolver (docs/design.md §18): a caller-sized table of answers keyed by the
//! folded name and the type, evicted by SIEVE with the expiry folded into the hand.
//!
//! It imports `core` and `wire` and never the state machine: a caller asks the cache, starts a
//! lookup on a miss, and puts the answer in when the lookup ends. Like everything else here it
//! owns no memory and reads no clock: the slots and the key index are the caller's, `now_ns` comes
//! in on every call, and the hash is keyed by the caller's seed so that a peer choosing the names a
//! process resolves cannot choose where they land.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Kind = core.Kind;
const Question = core.Question;
const Error = core.Error;
pub const constants = @import("constants.zig");
pub const limits = @import("limits.zig");
const cache_keys = @import("cache_keys.zig");
const cache_chain = @import("cache_chain.zig");
const cache_sweep = @import("cache_sweep.zig");
const cache_failure = @import("cache_failure.zig");
pub const resolution_failure = cache_failure.resolution_failure;
pub const failure_seconds_min_valid = cache_failure.failure_seconds_min_valid;

pub const Key = cache_keys.Key;
pub const Links = cache_chain.Links;
pub const none = cache_chain.none;

const cache_storage = @import("cache_storage.zig");
/// The memory a cache is built over, and how much of it a slot count takes (docs/design.md §18).
pub const Slices = cache_storage.Slices;
pub const Storage = cache_storage.Storage;
pub const keys_for = cache_storage.keys_for;
pub const slot_count_valid = cache_storage.slot_count_valid;

/// Whether a cache takes `ttl_seconds_max` as its cap: 1 second to seven days. A cap of zero
/// would keep nothing, and "Values SHOULD be capped on the order of days to weeks, with a
/// recommended cap of 604,800 seconds (7 days)" (RFC 8767 §4). A cap read at run time is input,
/// so its reader asks this and refuses a bad one itself; `Cache.init` asserts the same bound.
pub fn ttl_seconds_max_valid(ttl_seconds_max: u32) bool {
    return ttl_seconds_max >= 1 and ttl_seconds_max <= core.limits.cache_ttl_seconds_max;
}

/// What an entry remembers: records, one of the two negative answers RFC 2308 caches, or a
/// resolution failure (RFC 9520 §3.2, docs/design.md §16 decision 60).
pub const Outcome = enum { answered, name_not_found, no_data, failed };

/// One entry. The name is stored folded: it is the key, and what a hit hands back.
pub const Slot = struct {
    name: Name,
    answers: wire.Answers,
    /// The end of the CNAME chain the answers were reached through, when `aliased` says there
    /// was one: what a lookup that went out reports as the canonical name, kept so that a hit
    /// reports it too (docs/design.md §17 question 13).
    canonical: Name,
    expires_ns: u64,
    hash: u32,
    links: Links,
    kind: Kind,
    outcome: Outcome,
    /// The error of a `failed` entry, and how often its time was doubled (§16 decision 60): one
    /// octet, which fits in padding the slot had.
    kept: cache_failure.Kept,
    absolute: bool,
    aliased: bool,
    visited: bool,
    occupied: bool,

    pub const empty: Slot = .{
        .name = Name.root,
        .answers = wire.Answers.init(.a),
        .canonical = Name.root,
        .expires_ns = 0,
        .hash = 0,
        .links = .{},
        .kind = .a,
        .outcome = .answered,
        .kept = .{},
        .absolute = false,
        .aliased = false,
        .visited = false,
        .occupied = false,
    };
};

/// What a `get` returns. The pointers are into the table and stay valid until the next call on
/// the cache, which may evict the entry.
pub const Hit = struct {
    outcome: Outcome,
    /// The answers as they were put, but for their own TTL, which is the life the entry was
    /// given: theirs, or `ttl_seconds_max` when that is less. Each record keeps the TTL it came
    /// with; a lookup the cache answers lowers every one by that life less `ttl_seconds`.
    answers: *const wire.Answers,
    name: *const Name,
    /// The end of the CNAME chain, when the answers were reached through one.
    canonical_name: ?*const Name,
    /// What is left, not what was put: the expiry less `now_ns`, rounded down to a second.
    ttl_seconds: u32,
    /// The error the caller ends its lookup with, on a `failed` entry alone, and sends no query.
    failure: ?Error,
};

/// Keeps the chain's end with the answers, or says there was none. The name is copied only
/// when there is one: a slot that never held an aliased answer never pays the 256 octets' copy.
fn keep_canonical(slot: *Slot, canonical: ?*const Name) void {
    slot.aliased = canonical != null;
    if (canonical) |name| slot.canonical = name.*;
}

pub const Cache = struct {
    slots: []Slot,
    keys: []Key,
    seed: u64,
    ttl_seconds_max: u32,
    /// The time the first resolution failure of a name is kept: one `failure_seconds_min_valid`
    /// takes, 5 s unless the caller sets it after `init` (RFC 9520 §3.2, §16 decision 60).
    failure_seconds_min: u32 = constants.failure_seconds_min_default,
    order: cache_chain.Chain(Slot) = .{},
    /// Where the hand stopped, or `none` for the oldest entry.
    hand: u16 = none,
    /// The free list, threaded through `links.newer` of the slots outside the order.
    free: u16 = none,

    /// `keys.len` is a power of two at least `keys_per_slot_min` times `slots.len`, which
    /// `keys_for` gives at its least, and `slots.len` is one `slot_count_valid` takes.
    /// `ttl_seconds_max` caps every TTL put, the way c-ares's `qcache_max_ttl` does, and is a
    /// cap `ttl_seconds_max_valid` takes.
    pub fn init(slots: []Slot, keys: []Key, seed: u64, ttl_seconds_max: u32) Cache {
        assert(slots.len >= 1 and slots.len <= limits.slots_max);
        assert(std.math.isPowerOfTwo(keys.len));
        assert(keys.len >= slots.len * limits.keys_per_slot_min);
        assert(ttl_seconds_max_valid(ttl_seconds_max));
        var self: Cache = .{
            .slots = slots,
            .keys = keys,
            .seed = seed,
            .ttl_seconds_max = ttl_seconds_max,
        };
        self.flush();
        return self;
    }

    /// Empties the table, which is what a caller does when its servers change.
    pub fn flush(self: *Cache) void {
        @memset(self.keys, .{});
        self.order = .{};
        self.hand = none;
        self.free = none;
        var index: usize = self.slots.len;
        while (index > 0) {
            index -= 1;
            self.slots[index] = Slot.empty;
            self.release(@intCast(index));
        }
        assert(self.free == 0);
        assert(self.order.len == 0);
    }

    pub fn len(self: *const Cache) usize {
        return self.order.len;
    }

    /// The entry for `question`, if the cache holds one that has not expired. A hit sets the
    /// visited bit and moves nothing. An expired entry is a miss that keeps its slot, its place
    /// and its bit: the put after the miss renews it where it stands, and the hand takes it on
    /// sight if that put never comes (docs/design.md §17 question 14). Evicted here, the put
    /// would go in as new at the newest end, which is a promotion earned by a miss.
    pub fn get(self: *Cache, question: *const Question, now_ns: u64) ?Hit {
        const index = self.find(question, self.hash_of(question)) orelse return null;
        const slot = &self.slots[index];
        assert(slot.occupied);
        if (now_ns >= slot.expires_ns) return null;
        slot.visited = true;
        return .{
            .outcome = slot.outcome,
            .answers = &slot.answers,
            .name = &slot.name,
            .canonical_name = if (slot.aliased) &slot.canonical else null,
            .ttl_seconds = self.remaining(slot.expires_ns, now_ns),
            .failure = if (slot.outcome == .failed) cache_failure.error_of(slot.kept.failure) else null,
        };
    }

    /// Remembers `answers` for `question`, with the end of the CNAME chain that reached them, or
    /// null when none did. A TTL of zero is not cached, and neither is an answer marked
    /// truncated, which may be missing records (c-ares does the same). The TTL is capped at
    /// `ttl_seconds_max`.
    pub fn put(
        self: *Cache,
        question: *const Question,
        answers: *const wire.Answers,
        canonical: ?*const Name,
        now_ns: u64,
    ) void {
        assert(question.kind.queryable());
        // A possibly partial set is not cached (RFC 1035 §7.4), and a zero TTL "should not be
        // cached" (RFC 1035 §3.2.1).
        if (answers.truncated or answers.ttl_seconds == 0) return self.forget_failure(question);
        _ = self.insert(question, .answered, answers, canonical, answers.ttl_seconds, now_ns);
    }

    /// Remembers that `question` has no answer, for the SOA minimum a `Failure` carries
    /// (RFC 2308 §5). Zero, which a failure that is not a negative answer carries, is not cached.
    pub fn put_negative(
        self: *Cache,
        question: *const Question,
        outcome: Outcome,
        ttl_seconds: u32,
        now_ns: u64,
    ) void {
        assert(outcome != .answered and outcome != .failed);
        if (ttl_seconds == 0) return self.forget_failure(question);
        // No records: the slot's answers are reset where they are, rather than filled in a local
        // and copied, as a safe build fills a local left `undefined` (docs/design.md §16
        // decision 34).
        _ = self.insert(question, outcome, null, null, ttl_seconds, now_ns);
    }

    /// Remembers that `question` ended in `err`, when `resolution_failure` says it is one
    /// (RFC 9520 §3.2). The time is `failure_seconds_min` for the first, and doubles at each
    /// failure after the entry expired, to `limits.failure_seconds_max`. A failure while the entry
    /// lives, or over a live answer or negative, changes nothing (§16 decision 60).
    pub fn put_failure(self: *Cache, question: *const Question, err: Error, now_ns: u64) void {
        assert(question.kind.queryable());
        assert(failure_seconds_min_valid(self.failure_seconds_min));
        const failure = cache_failure.failure_of(err) orelse return;
        var doublings: u4 = 0;
        if (self.find(question, self.hash_of(question))) |index| {
            const held = &self.slots[index];
            // "MUST NOT send any corresponding outgoing queries until after the cache entries
            // expire" (RFC 9520 §3.2): a lookup that ends while the entry lives was no new try.
            if (now_ns < held.expires_ns) return;
            // Only a failure after a failure doubles; an answer ended the backoff (RFC 9520 §3.2).
            if (held.outcome == .failed) doublings = cache_failure.next_doublings(self.failure_seconds_min, held.kept.doublings);
        }
        const seconds = cache_failure.seconds_for(self.failure_seconds_min, doublings);
        const slot = self.insert(question, .failed, null, null, seconds, now_ns) orelse return;
        slot.kept = .{ .failure = failure, .doublings = doublings };
    }

    /// An answer the cache refuses still ends a name's backoff (RFC 9520 §3.2): its failure
    /// entry goes, and the next failure starts at `failure_seconds_min` (§16 decision 60).
    fn forget_failure(self: *Cache, question: *const Question) void {
        const index = self.find(question, self.hash_of(question)) orelse return;
        if (self.slots[index].outcome == .failed) self.evict(index);
    }

    fn insert(
        self: *Cache,
        question: *const Question,
        outcome: Outcome,
        answers: ?*const wire.Answers,
        canonical: ?*const Name,
        ttl_seconds: u32,
        now_ns: u64,
    ) ?*Slot {
        // "Values SHOULD be capped on the order of days to weeks" (RFC 8767 §4); an hour by default.
        const ttl = @min(ttl_seconds, self.ttl_seconds_max);
        assert(ttl >= 1);
        const expires_ns = now_ns + @as(u64, ttl) * constants.ns_per_s;
        const hash = self.hash_of(question);
        if (self.find(question, hash)) |index| {
            // Replaced in place, and the bit set: a name put twice is a name being used.
            const slot = &self.slots[index];
            keep_answers(slot, answers, question.kind, ttl);
            keep_canonical(slot, canonical);
            slot.outcome = outcome;
            slot.expires_ns = expires_ns;
            slot.visited = true;
            return slot;
        }
        if (self.free == none) cache_sweep.evict_one(self, now_ns);
        const index = self.acquire();
        cache_keys.insert(self.keys, hash, index) catch {
            // A chain past the probe bound: refused, and the slot goes back.
            self.release(index);
            return null;
        };
        // Field by field, not as one literal: a literal would write the whole slot, and the
        // answers' storage is copied only as far as it is used.
        const slot = &self.slots[index];
        slot.name = question.name;
        keep_answers(slot, answers, question.kind, ttl);
        keep_canonical(slot, canonical);
        slot.expires_ns = expires_ns;
        slot.hash = hash;
        slot.links = .{};
        slot.kind = question.kind;
        slot.outcome = outcome;
        slot.absolute = question.absolute;
        slot.visited = false;
        slot.occupied = true;
        slot.name.fold_case();
        self.order.link_newest(self.slots, index);
        assert(self.order.len <= self.slots.len);
        return slot;
    }

    /// What a put keeps: the answers it was given, copied as far as they are used, or none for a
    /// negative entry, which resets the slot's own.
    ///
    /// The answers keep `ttl_seconds`, the life the entry is given, as their own TTL, which is
    /// theirs or the cap. A hit's `ttl_seconds` is what is left of it, so the two differ by the
    /// time the entry has spent here, and that is what each record's TTL loses on a hit
    /// (RFC 1035 §6.1.3). Left at the answers' own, a TTL over the cap would count that time
    /// from the wrong start.
    fn keep_answers(slot: *Slot, answers: ?*const wire.Answers, kind: Kind, ttl_seconds: u32) void {
        const kept = answers orelse {
            slot.answers.reset(kind);
            return;
        };
        assert(ttl_seconds <= kept.ttl_seconds);
        slot.answers.assign(kept, kind);
        slot.answers.ttl_seconds = ttl_seconds;
    }

    /// Takes the entry at `index` out of the table. The hand, if it was there, moves on.
    pub fn evict(self: *Cache, index: u16) void {
        const slot = &self.slots[index];
        assert(slot.occupied);
        const next = self.order.after(self.slots, index);
        cache_keys.remove(self.keys, slot.hash, index);
        self.order.unlink(self.slots, index);
        if (self.hand == index) self.hand = if (self.order.len == 0) none else next;
        slot.occupied = false;
        self.release(index);
    }

    /// The slot holding `question`, found through the key index and confirmed by the name.
    pub fn find(self: *const Cache, question: *const Question, hash: u32) ?u16 {
        var candidates = cache_keys.Candidates.init(self.keys, hash);
        while (candidates.next()) |index| {
            const slot = &self.slots[index];
            assert(slot.occupied);
            if (slot.kind == question.kind and slot.absolute == question.absolute and
                slot.name.equal(&question.name)) return index;
        }
        return null;
    }

    /// The keyed hash of the question's folded name, its type and whether it was absolute. Two
    /// questions that differ only in `absolute` can resolve differently through the search list,
    /// so they are two keys. The name is folded eight octets at a time as it is read, so a hash
    /// costs no copy and no per-octet loop. Its length is not mixed in: the last chunk is padded
    /// with zeros, and a name ends at its root octet, so no name is another's zero padding
    /// (mutation Q34 found the length redundant).
    pub fn hash_of(self: *const Cache, question: *const Question) u32 {
        const prefix = self.seed ^
            (@as(u64, question.kind.code()) << constants.hash_kind_shift) ^
            (@as(u64, @intFromBool(question.absolute)) << constants.hash_absolute_shift);
        var word = core.mix.next(prefix);
        const bytes = question.name.wire();
        var offset: usize = 0;
        while (offset + @sizeOf(u64) <= bytes.len) : (offset += @sizeOf(u64)) {
            const chunk = std.mem.readInt(u64, bytes[offset..][0..@sizeOf(u64)], .little);
            word = core.mix.next(word ^ Name.fold_word(chunk));
        }
        var tail: [@sizeOf(u64)]u8 = @splat(0);
        @memcpy(tail[0 .. bytes.len - offset], bytes[offset..]);
        word = core.mix.next(word ^ Name.fold_word(std.mem.readInt(u64, &tail, .little)));
        assert(offset <= core.limits.name_bytes_max);
        return @truncate(word);
    }

    fn remaining(self: *const Cache, expires_ns: u64, now_ns: u64) u32 {
        assert(expires_ns > now_ns);
        const left = (expires_ns - now_ns) / constants.ns_per_s;
        assert(left <= self.ttl_seconds_max);
        return @intCast(left);
    }

    fn acquire(self: *Cache) u16 {
        assert(self.free != none);
        const index = self.free;
        self.free = self.slots[index].links.newer;
        self.slots[index].links = .{};
        return index;
    }

    fn release(self: *Cache, index: u16) void {
        assert(!self.slots[index].occupied);
        self.slots[index].links = .{ .newer = self.free };
        self.free = index;
    }
};

// Tests. The hand is driven in cache_sweep.zig; these pin what a get and a put do.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const ask = fixtures.question;
const second = fixtures.second;

/// Enough slots that no test here fills the table: the hand is cache_sweep.zig's to drive.
const slot_count: usize = 4;

test "the size of a slot is pinned" {
    // Measured, not derived: Zig orders the fields (docs/design.md §18). 2984 since the slot
    // keeps the chain's end: one `Name`, 256 octets, with its flag in padding that was there.
    try testing.expectEqual(@as(usize, 2984), @sizeOf(Slot));
}

test "a put is a hit whatever the case, and a miss for another type, name or absoluteness" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = ask("Example.COM");
    try testing.expect(table.get(&asked, 0) == null);
    const answers = fixtures.answers_v4(1, 300);
    table.put(&asked, &answers, null, 0);
    try testing.expectEqual(@as(usize, 1), table.len());

    const hit = table.get(&ask("EXAMPLE.com"), 0).?;
    try testing.expectEqual(Outcome.answered, hit.outcome);
    try testing.expectEqual(@as(u32, 300), hit.ttl_seconds);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, hit.answers.addresses()[0].slice());
    // The name comes back folded, whatever case it was put or asked in.
    try testing.expectEqualSlices(u8, ask("example.com").name.wire(), hit.name.wire());

    const aaaa = try Question.from_text("example.com", .aaaa);
    try testing.expect(table.get(&aaaa, 0) == null);
    try testing.expect(table.get(&ask("example.org"), 0) == null);
    var absolute = asked;
    absolute.absolute = true;
    try testing.expect(table.get(&absolute, 0) == null);
}

test "a hit sets the visited bit and moves nothing" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, 0);
    table.put(&ask("b.example"), &answers, null, 0);
    table.put(&ask("c.example"), &answers, null, 0);
    const oldest = table.order.oldest;
    const newest = table.order.newest;
    try testing.expect(table.get(&ask("b.example"), 0) != null);
    const b = table.find(&ask("b.example"), table.hash_of(&ask("b.example"))).?;
    try testing.expect(table.slots[b].visited);
    try testing.expect(!table.slots[oldest].visited);
    try testing.expect(!table.slots[newest].visited);
    try testing.expectEqual(oldest, table.order.oldest);
    try testing.expectEqual(newest, table.order.newest);
    try testing.expectEqual(b, table.order.after(table.slots, oldest));
}

test "a put for a question the cache holds replaces it in place, sets the bit, and moves nothing" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const first = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &first, null, 0);
    table.put(&ask("b.example"), &first, null, 0);
    const oldest = table.order.oldest;
    const later = fixtures.answers_v4(2, 600);
    table.put(&ask("A.EXAMPLE"), &later, null, 10 * second);
    try testing.expectEqual(@as(usize, 2), table.len());
    try testing.expectEqual(oldest, table.order.oldest);
    try testing.expect(table.slots[oldest].visited);
    const hit = table.get(&ask("a.example"), 10 * second).?;
    try testing.expectEqual(@as(u32, 600), hit.ttl_seconds);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, hit.answers.addresses()[0].slice());
}

test "flush empties the table, and a put after it works" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, 0);
    table.put(&ask("b.example"), &answers, null, 0);
    try testing.expect(table.get(&ask("a.example"), 0) != null);
    table.flush();
    try testing.expectEqual(@as(usize, 0), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) == null);
    try testing.expect(table.get(&ask("b.example"), 0) == null);
    for (table.keys) |key| try testing.expectEqual(Key.State.empty, key.state);
    table.put(&ask("a.example"), &answers, null, 0);
    try testing.expectEqual(@as(usize, 1), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) != null);
}

test {
    _ = limits;
    _ = cache_storage;
    _ = @import("cache_canonical_test.zig");
    _ = @import("cache_failure.zig");
    _ = @import("cache_kinds_test.zig");
    _ = @import("cache_probe_test.zig");
    _ = @import("cache_ttl_test.zig");
}
