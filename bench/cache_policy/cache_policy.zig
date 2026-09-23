//! The two eviction policies docs/design.md §18 weighs, as models over name indices, so that one
//! trace decides between them (§17 question 9, its second half).
//!
//! The library holds SIEVE and nothing else. S3-FIFO (`cache_policy_s3fifo.zig`) and c-ares's
//! rule (`cache_policy_cares.zig`) are here and not in `src/`: a policy goes into the library when
//! a measurement says so, and these files are that measurement. The model of SIEVE in this file
//! is the control. It must reproduce the real cache's hit rate on the same trace, or nothing the
//! other models say against it means anything.
//!
//! Neither paper models an entry that dies on its own, and both models fold it in the same way.
//! An eviction that meets an expired entry takes it, whatever its bits say. A get that finds its
//! entry expired misses, and then does one of two things, `Expiry` says which. It removes the
//! entry and keeps no memory of it, as the cache did before docs/design.md §17 question 14, so the
//! put after the miss goes in as new. Or it renews the entry's life where it stands and counts
//! the renewal as a use, as the cache's put in place does since: SIEVE's bit is set, and
//! S3-FIFO's counter goes up by one.
const std = @import("std");
const assert = std.debug.assert;

pub const Id = u32;
pub const none: Id = std.math.maxInt(Id);

/// What a get does with an entry it finds expired, after it misses.
pub const Expiry = enum { evict_on_get, refresh_in_place };

/// The newer and older neighbour of every name, for queues a name can also leave from the middle.
pub fn Links(comptime names: usize) type {
    return struct {
        older: [names]Id,
        newer: [names]Id,
    };
}

/// A queue threaded through per-name links, oldest to newest. Which queue a name is on, if any,
/// is kept by the model: a lone entry's links are empty either way.
pub const Queue = struct {
    oldest: Id = none,
    newest: Id = none,
    len: usize = 0,

    pub fn push(self: *Queue, older: []Id, newer: []Id, id: Id) void {
        assert(older[id] == none and newer[id] == none);
        older[id] = self.newest;
        if (self.newest == none) self.oldest = id else newer[self.newest] = id;
        self.newest = id;
        self.len += 1;
    }

    pub fn remove(self: *Queue, older: []Id, newer: []Id, id: Id) void {
        assert(self.len > 0);
        const before = older[id];
        const after = newer[id];
        if (before == none) self.oldest = after else newer[before] = after;
        if (after == none) self.newest = before else older[after] = before;
        older[id] = none;
        newer[id] = none;
        self.len -= 1;
    }
};

/// SIEVE as `src/cache/cache_sweep.zig` has it: insertion order, a visited bit, and a hand that
/// walks from the oldest toward the newest and wraps.
/// How SIEVE picks what to evict. `hand` is the cache's: the hand takes the first entry it
/// meets that is expired or unvisited. `expired_first` keeps the entries in expiry order too, as
/// c-ares does, and takes the soonest one when it has expired, before the hand moves at all.
pub const Eviction = enum { hand, expired_first };

pub fn Sieve(comptime names: usize) type {
    return struct {
        const Self = @This();

        links: Links(names),
        resident: [names]bool,
        visited: [names]bool,
        expires_ns: [names]u64,
        order: Queue,
        hand: Id,
        capacity: usize,
        expiry: Expiry,
        eviction: Eviction,
        /// The entries by expiry, kept only for `expired_first`.
        by_expiry: KeyedHeap(names),

        pub fn init(self: *Self, capacity: usize, expiry: Expiry, eviction: Eviction) void {
            sieve_init(self, capacity, expiry, eviction);
        }

        /// True on a hit. A miss puts the name in, as the replay's put after a miss does.
        pub fn access(self: *Self, id: Id, life_ns: u64, now_ns: u64) bool {
            return sieve_access(self, id, life_ns, now_ns);
        }
    };
}

fn sieve_init(self: anytype, capacity: usize, expiry: Expiry, eviction: Eviction) void {
    assert(capacity > 0 and capacity <= self.resident.len);
    @memset(&self.links.older, none);
    @memset(&self.links.newer, none);
    @memset(&self.resident, false);
    @memset(&self.visited, false);
    self.order = .{};
    self.hand = none;
    self.capacity = capacity;
    self.expiry = expiry;
    self.eviction = eviction;
    self.by_expiry.len = 0;
}

fn sieve_access(self: anytype, id: Id, life_ns: u64, now_ns: u64) bool {
    if (self.resident[id]) {
        if (now_ns < self.expires_ns[id]) {
            self.visited[id] = true;
            return true;
        }
        if (self.expiry == .refresh_in_place) {
            self.expires_ns[id] = now_ns + life_ns;
            self.visited[id] = true;
            if (self.eviction == .expired_first) self.by_expiry.update(&self.expires_ns, id);
            return false;
        }
        sieve_remove(self, id);
    }
    sieve_insert(self, id, life_ns, now_ns);
    return false;
}

fn sieve_insert(self: anytype, id: Id, life_ns: u64, now_ns: u64) void {
    if (self.order.len == self.capacity) sieve_evict_one(self, now_ns);
    assert(self.order.len < self.capacity);
    self.resident[id] = true;
    self.visited[id] = false;
    self.expires_ns[id] = now_ns + life_ns;
    self.order.push(&self.links.older, &self.links.newer, id);
    if (self.eviction == .expired_first) self.by_expiry.push(&self.expires_ns, id);
}

fn sieve_after(self: anytype, id: Id) Id {
    const newer = self.links.newer[id];
    return if (newer == none) self.order.oldest else newer;
}

/// The hand moves on when its own entry goes, as `Cache.evict` moves it.
fn sieve_remove(self: anytype, id: Id) void {
    const next = sieve_after(self, id);
    self.order.remove(&self.links.older, &self.links.newer, id);
    if (self.hand == id) self.hand = if (self.order.len == 0) none else next;
    self.resident[id] = false;
    if (self.eviction == .expired_first) self.by_expiry.remove(&self.expires_ns, id);
}

fn sieve_evict_one(self: anytype, now_ns: u64) void {
    if (self.eviction == .expired_first) {
        const soonest = self.by_expiry.smallest().?;
        if (now_ns >= self.expires_ns[soonest]) return sieve_remove(self, soonest);
    }
    var id = if (self.hand == none) self.order.oldest else self.hand;
    // One pass clears every bit, so the second finds an entry: the bound the cache asserts.
    const steps_max = 2 * self.capacity;
    var steps: usize = 0;
    while (steps < steps_max) : (steps += 1) {
        if (now_ns >= self.expires_ns[id] or !self.visited[id]) {
            self.hand = id;
            sieve_remove(self, id);
            return;
        }
        self.visited[id] = false;
        id = sieve_after(self, id);
    }
    unreachable;
}

/// Names ordered by a key the model keeps, smallest first, with where each one sits so that one
/// can also leave from the middle. Keyed by expiry it is the order c-ares's skip list keeps; the
/// optimal replay keys it by how far off a name's next useful request is. The keys are the
/// model's own array, passed to every call, so the heap holds names and nothing else.
pub fn KeyedHeap(comptime names: usize) type {
    return struct {
        const Self = @This();

        heap: [names]Id,
        at: [names]usize,
        len: usize,

        pub fn smallest(self: *const Self) ?Id {
            return if (self.len == 0) null else self.heap[0];
        }

        pub fn push(self: *Self, keys: []const u64, id: Id) void {
            index_push(self, keys, id);
        }

        pub fn remove(self: *Self, keys: []const u64, id: Id) void {
            index_remove(self, keys, id);
        }

        /// After `id`'s key changed, either way.
        pub fn update(self: *Self, keys: []const u64, id: Id) void {
            sift_down(self, keys, self.at[id]);
            sift_up(self, keys, self.at[id]);
        }
    };
}

fn earlier(self: anytype, keys: []const u64, one: usize, other: usize) bool {
    return keys[self.heap[one]] < keys[self.heap[other]];
}

fn swap(self: anytype, one: usize, other: usize) void {
    std.mem.swap(Id, &self.heap[one], &self.heap[other]);
    self.at[self.heap[one]] = one;
    self.at[self.heap[other]] = other;
}

fn index_push(self: anytype, keys: []const u64, id: Id) void {
    assert(self.len < self.heap.len);
    self.heap[self.len] = id;
    self.at[id] = self.len;
    self.len += 1;
    sift_up(self, keys, self.len - 1);
}

fn index_remove(self: anytype, keys: []const u64, id: Id) void {
    const position = self.at[id];
    assert(position < self.len and self.heap[position] == id);
    self.len -= 1;
    if (position == self.len) return;
    self.heap[position] = self.heap[self.len];
    self.at[self.heap[position]] = position;
    sift_down(self, keys, position);
    sift_up(self, keys, position);
}

fn sift_up(self: anytype, keys: []const u64, start: usize) void {
    var at = start;
    while (at > 0) {
        const parent = (at - 1) / 2;
        if (!earlier(self, keys, at, parent)) return;
        swap(self, at, parent);
        at = parent;
    }
}

fn sift_down(self: anytype, keys: []const u64, start: usize) void {
    var at = start;
    while (2 * at + 1 < self.len) {
        const left = 2 * at + 1;
        const right = left + 1;
        const child = if (right < self.len and earlier(self, keys, right, left)) right else left;
        if (!earlier(self, keys, child, at)) return;
        swap(self, child, at);
        at = child;
    }
}

/// The sample W over which `Histogram` counts, as a multiple of the cache size C: ten, as
/// Caffeine keeps it (TinyLFU §5.1). A counter needs to reach no higher than W / C (§3.4.1), so
/// that is its cap.
pub const sample_per_slot = 10;
pub const count_max = sample_per_slot;

/// How often each name has been asked lately: TinyLFU's frequency histogram (Einziger, Friedman
/// and Manes, arXiv 1512.00727v2), kept exactly, one counter a name. Every counter and the record
/// count halve once a sample has gone by (§3.3), and no counter passes `count_max` (§3.4.1).
pub fn Histogram(comptime names: usize) type {
    return struct {
        const Self = @This();

        counts: [names]u8,
        /// Records since the counters were last halved, which the halving halves too (§3.3).
        recorded: usize,
        sample: usize,

        pub fn init(self: *Self, capacity: usize) void {
            assert(capacity >= 1);
            @memset(&self.counts, 0);
            self.recorded = 0;
            self.sample = capacity * sample_per_slot;
        }

        pub fn record(self: *Self, id: Id) void {
            histogram_record(self, id);
        }
    };
}

fn histogram_record(self: anytype, id: Id) void {
    self.counts[id] = @min(self.counts[id] + 1, count_max);
    self.recorded += 1;
    if (self.recorded < self.sample) return;
    for (&self.counts) |*count| count.* /= 2;
    self.recorded /= 2;
}

/// Xorshift64*: three shifts and a multiply, enough for a popularity draw and small enough to
/// read. It moves `state` on and returns the next number. The trace draws its names with it and
/// expected hits its evictions; the bench is not cryptography.
pub fn xorshift_next(state: *u64) u64 {
    var x = state.*;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state.* = x;
    return x *% 0x2545_f491_4f6c_dd1d;
}

// Tests. Small tables whose every step can be followed by hand.

const testing = std.testing;
const test_names = 64;
const second: u64 = std.time.ns_per_s;
const life: u64 = 100 * second;

test "the SIEVE model keeps a visited entry through one sweep and evicts the unvisited one" {
    var model: Sieve(test_names) = undefined;
    model.init(2, .evict_on_get, .hand);
    try testing.expect(!model.access(0, life, 0));
    try testing.expect(!model.access(1, life, 0));
    try testing.expect(model.access(0, life, 0));
    // Full: the hand passes 0, visited, and takes 1.
    try testing.expect(!model.access(2, life, 0));
    try testing.expect(model.access(0, life, 0));
    try testing.expect(!model.access(1, life, 0));
}

test "the SIEVE model misses on an expired entry and takes it before a live one" {
    var model: Sieve(test_names) = undefined;
    model.init(2, .evict_on_get, .hand);
    _ = model.access(0, second, 0);
    _ = model.access(1, life, 0);
    try testing.expect(!model.access(0, second, 2 * second));
    // 0 was put back; 1 is older, unvisited, and goes when 2 comes.
    _ = model.access(2, life, 2 * second);
    try testing.expect(model.access(0, second, 2 * second));
}

test "under the old rule an expired entry goes back in at the newest end" {
    var model: Sieve(test_names) = undefined;
    // Room to spare, so no sweep runs and only the get can have moved it.
    model.init(4, .evict_on_get, .hand);
    _ = model.access(0, second, 0);
    _ = model.access(1, life, 0);
    _ = model.access(2, life, 0);
    try testing.expect(!model.access(0, second, 2 * second));
    try testing.expectEqual(@as(Id, 1), model.order.oldest);
    try testing.expectEqual(@as(Id, 0), model.order.newest);
    try testing.expectEqual(@as(usize, 3), model.order.len);
}

test "the SIEVE model's hand takes an expired entry even when it was visited" {
    var model: Sieve(test_names) = undefined;
    model.init(2, .evict_on_get, .hand);
    _ = model.access(0, second, 0);
    _ = model.access(1, life, 0);
    try testing.expect(model.access(0, second, 0));
    // At two seconds 0 has expired. Visited, it would otherwise be passed over and 1 taken.
    _ = model.access(2, life, 2 * second);
    try testing.expect(model.access(1, life, 2 * second));
}

test "an entry refreshed in place keeps its place and has its bit set" {
    var model: Sieve(test_names) = undefined;
    model.init(2, .refresh_in_place, .hand);
    _ = model.access(0, second, 0);
    _ = model.access(1, life, 0);
    try testing.expect(!model.access(0, second, 2 * second));
    try testing.expectEqual(3 * second, model.expires_ns[0]);
    try testing.expect(model.visited[0]);
    // 0 is still the oldest, and visited: the hand clears it and takes 1 behind it.
    _ = model.access(2, life, 2 * second);
    try testing.expect(model.access(0, second, 2 * second));
    try testing.expect(!model.access(1, life, 2 * second));
}

test "the heap gives the smallest key, and a name can leave from the middle" {
    var index: KeyedHeap(test_names) = undefined;
    index.len = 0;
    var expires: [test_names]u64 = @splat(0);
    const lives = [_]u64{ 50, 10, 40, 20, 30 };
    for (lives, 0..) |value, id| {
        expires[id] = value;
        index.push(&expires, @intCast(id));
    }
    try testing.expectEqual(@as(?Id, 1), index.smallest());
    index.remove(&expires, 3);
    index.remove(&expires, 1);
    // 3, at 20, left from the middle, and 1 from the top: 4, at 30, is next.
    try testing.expectEqual(@as(?Id, 4), index.smallest());
    expires[4] = 60;
    index.update(&expires, 4);
    try testing.expectEqual(@as(?Id, 2), index.smallest());
    try testing.expectEqual(@as(usize, 3), index.len);
    // A key can move earlier too.
    expires[0] = 5;
    index.update(&expires, 0);
    try testing.expectEqual(@as(?Id, 0), index.smallest());
}

test "expired first takes the soonest expired entry, wherever the hand is" {
    var hand: Sieve(test_names) = undefined;
    var expired_first: Sieve(test_names) = undefined;
    hand.init(3, .refresh_in_place, .hand);
    expired_first.init(3, .refresh_in_place, .expired_first);
    for ([_]*Sieve(test_names){ &hand, &expired_first }) |model| {
        _ = model.access(0, life, 0);
        _ = model.access(1, second, 0);
        _ = model.access(2, life, 0);
        _ = model.access(3, life, 2 * second);
    }
    // The hand meets 0 first, unvisited and live, and takes it; expired first takes 1.
    try testing.expect(!hand.resident[0] and hand.resident[1]);
    try testing.expect(expired_first.resident[0] and !expired_first.resident[1]);
    try testing.expectEqual(@as(usize, 3), expired_first.by_expiry.len);
}

test "expired first leaves a live soonest entry to the hand" {
    var model: Sieve(test_names) = undefined;
    model.init(3, .refresh_in_place, .expired_first);
    _ = model.access(0, life, 0);
    _ = model.access(1, 2 * life, 0);
    _ = model.access(2, 2 * life, 0);
    try testing.expect(model.access(0, life, second));
    // Nothing has expired. 0 expires soonest, but it is visited: the hand clears it and takes 1.
    _ = model.access(3, life, 2 * second);
    try testing.expect(model.resident[0] and !model.resident[1]);
}

test "expired first follows a renewal to its new expiry" {
    var model: Sieve(test_names) = undefined;
    model.init(3, .refresh_in_place, .expired_first);
    _ = model.access(0, second, 0);
    _ = model.access(2, life, 0);
    _ = model.access(1, 5 * second, 0);
    // 0 expires and is renewed for a hundred seconds, so 1 is the soonest now.
    try testing.expect(!model.access(0, life, 2 * second));
    _ = model.access(3, life, 6 * second);
    // 1 has expired and goes. Read with 0's old expiry, the hand would have taken 2.
    try testing.expect(!model.resident[1] and model.resident[2]);
}
