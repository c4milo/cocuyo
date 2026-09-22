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
pub const constants = @import("constants.zig");
const cache_keys = @import("cache_keys.zig");
const cache_chain = @import("cache_chain.zig");
const cache_sweep = @import("cache_sweep.zig");

pub const Key = cache_keys.Key;
pub const Links = cache_chain.Links;
pub const none = cache_chain.none;

/// What an entry remembers: records, or one of the two negative answers RFC 2308 caches.
pub const Outcome = enum { answered, name_not_found, no_data };

/// One entry. The name is stored folded: it is the key, and what a hit hands back.
pub const Slot = struct {
    name: Name,
    answers: wire.Answers,
    expires_ns: u64,
    hash: u32,
    links: Links,
    kind: Kind,
    outcome: Outcome,
    absolute: bool,
    visited: bool,
    occupied: bool,

    pub const empty: Slot = .{
        .name = Name.root,
        .answers = wire.Answers.init(.a),
        .expires_ns = 0,
        .hash = 0,
        .links = .{},
        .kind = .a,
        .outcome = .answered,
        .absolute = false,
        .visited = false,
        .occupied = false,
    };
};

/// What a `get` returns. The pointers are into the table and stay valid until the next call on
/// the cache, which may evict the entry.
pub const Hit = struct {
    outcome: Outcome,
    answers: *const wire.Answers,
    name: *const Name,
    /// What is left, not what was put: the expiry less `now_ns`, rounded down to a second.
    ttl_seconds: u32,
};

pub const Cache = struct {
    slots: []Slot,
    keys: []Key,
    seed: u64,
    ttl_seconds_max: u32,
    order: cache_chain.Chain(Slot) = .{},
    /// Where the hand stopped, or `none` for the oldest entry.
    hand: u16 = none,
    /// The free list, threaded through `links.newer` of the slots outside the order.
    free: u16 = none,

    /// `keys.len` is a power of two at least `keys_per_slot_min` times `slots.len`, and
    /// `ttl_seconds_max` caps every TTL put, the way c-ares's `qcache_max_ttl` does.
    pub fn init(slots: []Slot, keys: []Key, seed: u64, ttl_seconds_max: u32) Cache {
        assert(slots.len >= 1 and slots.len <= constants.slots_max);
        assert(std.math.isPowerOfTwo(keys.len));
        assert(keys.len >= slots.len * constants.keys_per_slot_min);
        assert(ttl_seconds_max >= 1);
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

    /// The entry for `question`, if the cache holds one that has not expired. An expired entry is
    /// evicted on sight and is a miss; a hit sets the visited bit and moves nothing.
    pub fn get(self: *Cache, question: *const Question, now_ns: u64) ?Hit {
        const index = self.find(question, self.hash_of(question)) orelse return null;
        const slot = &self.slots[index];
        assert(slot.occupied);
        if (now_ns >= slot.expires_ns) {
            self.evict(index);
            return null;
        }
        slot.visited = true;
        return .{
            .outcome = slot.outcome,
            .answers = &slot.answers,
            .name = &slot.name,
            .ttl_seconds = self.remaining(slot.expires_ns, now_ns),
        };
    }

    /// Remembers `answers` for `question`. A TTL of zero, or an answer marked truncated, is not
    /// cached (c-ares does the same); the TTL is capped at `ttl_seconds_max`.
    pub fn put(self: *Cache, question: *const Question, answers: *const wire.Answers, now_ns: u64) void {
        assert(question.kind.queryable());
        if (answers.truncated or answers.ttl_seconds == 0) return;
        self.insert(question, .answered, answers, answers.ttl_seconds, now_ns);
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
        assert(outcome != .answered);
        if (ttl_seconds == 0) return;
        const empty = wire.Answers.init(question.kind);
        self.insert(question, outcome, &empty, ttl_seconds, now_ns);
    }

    fn insert(
        self: *Cache,
        question: *const Question,
        outcome: Outcome,
        answers: *const wire.Answers,
        ttl_seconds: u32,
        now_ns: u64,
    ) void {
        const ttl = @min(ttl_seconds, self.ttl_seconds_max);
        assert(ttl >= 1);
        const expires_ns = now_ns + @as(u64, ttl) * constants.ns_per_s;
        const hash = self.hash_of(question);
        if (self.find(question, hash)) |index| {
            // Replaced in place, and the bit set: a name put twice is a name being used.
            const slot = &self.slots[index];
            slot.answers = answers.*;
            slot.outcome = outcome;
            slot.expires_ns = expires_ns;
            slot.visited = true;
            return;
        }
        if (self.free == none) cache_sweep.evict_one(self, now_ns);
        const index = self.acquire();
        cache_keys.insert(self.keys, hash, index) catch {
            // A chain past the probe bound: refused, and the slot goes back.
            self.release(index);
            return;
        };
        const slot = &self.slots[index];
        slot.* = .{
            .name = question.name,
            .answers = answers.*,
            .expires_ns = expires_ns,
            .hash = hash,
            .links = .{},
            .kind = question.kind,
            .outcome = outcome,
            .absolute = question.absolute,
            .visited = false,
            .occupied = true,
        };
        slot.name.fold_case();
        self.order.link_newest(self.slots, index);
        assert(self.order.len <= self.slots.len);
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
        assert(offset <= core.constants.name_bytes_max);
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
const slot_count = 4;

test "the size of a slot is pinned" {
    // Measured, not derived: Zig orders the fields (docs/design.md §18).
    try testing.expectEqual(@as(usize, 568), @sizeOf(Slot));
}

test "a put is a hit whatever the case, and a miss for another type, name or absoluteness" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = ask("Example.COM");
    try testing.expect(table.get(&asked, 0) == null);
    const answers = fixtures.answers_v4(1, 300);
    table.put(&asked, &answers, 0);
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

test "a hit reports what is left of the TTL, and an expired entry is evicted on sight" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const asked = ask("example.com");
    const answers = fixtures.answers_v4(1, 300);
    table.put(&asked, &answers, 0);
    try testing.expectEqual(@as(u32, 200), table.get(&asked, 100 * second).?.ttl_seconds);
    try testing.expectEqual(@as(u32, 0), table.get(&asked, 300 * second - 1).?.ttl_seconds);
    try testing.expect(table.get(&asked, 300 * second) == null);
    try testing.expectEqual(@as(usize, 0), table.len());
    try testing.expect(table.get(&asked, 300 * second) == null);
    // The slot went back: the table fills to its size again.
    for ([_][]const u8{ "a.example", "b.example", "c.example", "d.example" }) |name| {
        table.put(&ask(name), &answers, 0);
    }
    try testing.expectEqual(@as(usize, 4), table.len());
}

test "a hit sets the visited bit and moves nothing" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, 0);
    table.put(&ask("b.example"), &answers, 0);
    table.put(&ask("c.example"), &answers, 0);
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
    table.put(&ask("a.example"), &first, 0);
    table.put(&ask("b.example"), &first, 0);
    const oldest = table.order.oldest;
    const later = fixtures.answers_v4(2, 600);
    table.put(&ask("A.EXAMPLE"), &later, 10 * second);
    try testing.expectEqual(@as(usize, 2), table.len());
    try testing.expectEqual(oldest, table.order.oldest);
    try testing.expect(table.slots[oldest].visited);
    const hit = table.get(&ask("a.example"), 10 * second).?;
    try testing.expectEqual(@as(u32, 600), hit.ttl_seconds);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, hit.answers.addresses()[0].slice());
}

test "a TTL of zero and a truncated answer are not cached, and a TTL over the cap is capped" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = cache_init_capped(&fixture, 60);
    const zero = fixtures.answers_v4(1, 0);
    table.put(&ask("a.example"), &zero, 0);
    var truncated = fixtures.answers_v4(1, 300);
    truncated.truncated = true;
    table.put(&ask("a.example"), &truncated, 0);
    table.put_negative(&ask("b.example"), .name_not_found, 0, 0);
    try testing.expectEqual(@as(usize, 0), table.len());
    const long = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &long, 0);
    try testing.expectEqual(@as(u32, 60), table.get(&ask("a.example"), 0).?.ttl_seconds);
    try testing.expect(table.get(&ask("a.example"), 60 * second) == null);
}

fn cache_init_capped(fixture: *fixtures.Fixture(slot_count), ttl_seconds_max: u32) Cache {
    return Cache.init(&fixture.slots, &fixture.keys, fixtures.seed, ttl_seconds_max);
}

test "a negative answer is cached with its outcome, its TTL and no records" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    table.put_negative(&ask("nx.example"), .name_not_found, 60, 0);
    table.put_negative(&ask("nodata.example"), .no_data, 30, 0);
    const nx = table.get(&ask("nx.example"), 0).?;
    try testing.expectEqual(Outcome.name_not_found, nx.outcome);
    try testing.expectEqual(@as(u32, 60), nx.ttl_seconds);
    try testing.expectEqual(@as(usize, 0), nx.answers.addresses().len);
    const nodata = table.get(&ask("nodata.example"), 0).?;
    try testing.expectEqual(Outcome.no_data, nodata.outcome);
    try testing.expectEqual(@as(u32, 30), nodata.ttl_seconds);
    // An answer put over a negative entry replaces it, outcome included.
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("nx.example"), &answers, 0);
    try testing.expectEqual(Outcome.answered, table.get(&ask("nx.example"), 0).?.outcome);
}

test "flush empties the table, and a put after it works" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, 0);
    table.put(&ask("b.example"), &answers, 0);
    try testing.expect(table.get(&ask("a.example"), 0) != null);
    table.flush();
    try testing.expectEqual(@as(usize, 0), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) == null);
    try testing.expect(table.get(&ask("b.example"), 0) == null);
    for (table.keys) |key| try testing.expectEqual(Key.State.empty, key.state);
    table.put(&ask("a.example"), &answers, 0);
    try testing.expectEqual(@as(usize, 1), table.len());
    try testing.expect(table.get(&ask("a.example"), 0) != null);
}

test "the hash is keyed: two seeds land one name in two places" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    const one = Cache.init(&fixture.slots, &fixture.keys, 1, constants.ttl_seconds_max_default);
    const two = Cache.init(&fixture.slots, &fixture.keys, 2, constants.ttl_seconds_max_default);
    const asked = ask("example.com");
    try testing.expect(one.hash_of(&asked) != two.hash_of(&asked));
    try testing.expectEqual(one.hash_of(&asked), one.hash_of(&ask("EXAMPLE.COM")));
    try testing.expect(one.hash_of(&asked) != one.hash_of(&ask("example.org")));
    const aaaa = try Question.from_text("example.com", .aaaa);
    try testing.expect(one.hash_of(&asked) != one.hash_of(&aaaa));
    var absolute = asked;
    absolute.absolute = true;
    try testing.expect(one.hash_of(&asked) != one.hash_of(&absolute));
}

test {
    _ = @import("cache_probe_test.zig");
}
