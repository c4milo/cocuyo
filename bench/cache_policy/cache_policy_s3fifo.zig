//! S3-FIFO, Algorithm 1 of Yang et al., SOSP 2023, read from the paper: a model over name indices
//! for the replay of `cache_trace.zig`, with the expiry rules of `cache_policy.zig`. Split from
//! `cache_policy.zig` to keep it under 500 lines.
const std = @import("std");
const assert = std.debug.assert;
const policy = @import("cache_policy.zig");
const Id = policy.Id;
const none = policy.none;
const Expiry = policy.Expiry;
const Links = policy.Links;
const Queue = policy.Queue;

/// S3-FIFO's frequency counter caps at 3, two bits (Algorithm 1 line 3).
const frequency_max = 3;

/// The small queue's share of the cache is a tenth, and the main queue's nine tenths (§4.1;
/// Algorithm 1 line 15).
const share_whole = 10;
const small_share = 1;
const main_share = share_whole - small_share;

/// Where an S3-FIFO name is. A ghost is not a place: it is a stamp, below.
const Place = enum(u8) { out, small, main };

/// S3-FIFO, Algorithm 1 of Yang et al., SOSP 2023: a small queue S, a main queue M, and a ghost
/// queue G of names only.
pub fn S3Fifo(comptime names: usize) type {
    return struct {
        const Self = @This();

        links: Links(names),
        place: [names]Place,
        frequency: [names]u8,
        expires_ns: [names]u64,
        /// G as §4.2 builds it: each ghost keeps the count of insertions into G made before it,
        /// and a stamp more than G's size behind the count has left G.
        ghost_stamp: [names]u64,
        ghost_inserts: u64,
        small: Queue,
        main: Queue,
        capacity: usize,
        /// The frequency a name must exceed to move from S to M. Algorithm 1 line 23 says
        /// `t.freq > 1`, so 1; Figure 5 says a name "not visited" goes to G, so 0. The two
        /// disagree, and the replay runs both.
        promote_above: u8,
        expiry: Expiry,

        pub fn init(self: *Self, capacity: usize, promote_above: u8, expiry: Expiry) void {
            fifo_init(self, capacity, promote_above, expiry);
        }

        /// Algorithm 1's `read`, lines 1 to 6, with expiry folded in.
        pub fn access(self: *Self, id: Id, life_ns: u64, now_ns: u64) bool {
            return fifo_access(self, id, life_ns, now_ns);
        }
    };
}

const ghost_none = std.math.maxInt(u64);

fn fifo_init(self: anytype, capacity: usize, promote_above: u8, expiry: Expiry) void {
    assert(capacity >= share_whole and capacity <= self.place.len);
    assert(promote_above < frequency_max);
    @memset(&self.links.older, none);
    @memset(&self.links.newer, none);
    @memset(&self.place, .out);
    @memset(&self.ghost_stamp, ghost_none);
    self.ghost_inserts = 0;
    self.small = .{};
    self.main = .{};
    self.capacity = capacity;
    self.promote_above = promote_above;
    self.expiry = expiry;
}

fn fifo_access(self: anytype, id: Id, life_ns: u64, now_ns: u64) bool {
    if (self.place[id] != .out) {
        if (now_ns < self.expires_ns[id]) {
            self.frequency[id] = @min(self.frequency[id] + 1, frequency_max);
            return true;
        }
        if (self.expiry == .refresh_in_place) {
            self.expires_ns[id] = now_ns + life_ns;
            self.frequency[id] = @min(self.frequency[id] + 1, frequency_max);
            return false;
        }
        const queue = if (self.place[id] == .small) &self.small else &self.main;
        queue.remove(&self.links.older, &self.links.newer, id);
        self.place[id] = .out;
    }
    fifo_insert(self, id, now_ns);
    self.frequency[id] = 0;
    self.expires_ns[id] = now_ns + life_ns;
    return false;
}

fn fifo_resident(self: anytype) usize {
    return self.small.len + self.main.len;
}

fn fifo_ghost_size(self: anytype) u64 {
    // "The ghost queue G stores the same number of ghost entries (no data) as M" (§4.1).
    return self.capacity * main_share / share_whole;
}

fn fifo_in_ghost(self: anytype, id: Id) bool {
    const stamp = self.ghost_stamp[id];
    return stamp <= self.ghost_inserts and self.ghost_inserts - stamp <= fifo_ghost_size(self);
}

/// Lines 7 to 13. A ghost that is asked for again leaves G (§4.2).
fn fifo_insert(self: anytype, id: Id, now_ns: u64) void {
    var evictions: usize = 0;
    while (fifo_resident(self) >= self.capacity and evictions < self.capacity) : (evictions += 1) {
        fifo_evict(self, now_ns);
    }
    assert(fifo_resident(self) < self.capacity);
    if (fifo_in_ghost(self, id)) {
        self.ghost_stamp[id] = ghost_none;
        self.main.push(&self.links.older, &self.links.newer, id);
        self.place[id] = .main;
    } else {
        self.small.push(&self.links.older, &self.links.newer, id);
        self.place[id] = .small;
    }
}

/// Lines 14 to 18.
fn fifo_evict(self: anytype, now_ns: u64) void {
    if (self.small.len * share_whole >= self.capacity * small_share) {
        fifo_evict_small(self, now_ns);
    } else {
        fifo_evict_main(self, now_ns);
    }
}

fn fifo_main_full(self: anytype) bool {
    return self.main.len * share_whole >= self.capacity * main_share;
}

/// Lines 19 to 30. Each pass takes one name out of S, so S's length bounds the walk. A name
/// moved to M has its bits cleared (§4.1: "its access bits are cleared during the move").
fn fifo_evict_small(self: anytype, now_ns: u64) void {
    const steps_max = self.small.len;
    var steps: usize = 0;
    while (steps < steps_max) : (steps += 1) {
        const tail = self.small.oldest;
        self.small.remove(&self.links.older, &self.links.newer, tail);
        self.place[tail] = .out;
        if (now_ns >= self.expires_ns[tail]) return;
        if (self.frequency[tail] <= self.promote_above) {
            self.ghost_stamp[tail] = self.ghost_inserts;
            self.ghost_inserts += 1;
            return;
        }
        self.frequency[tail] = 0;
        self.main.push(&self.links.older, &self.links.newer, tail);
        self.place[tail] = .main;
        if (fifo_main_full(self)) fifo_evict_main(self, now_ns);
    }
}

/// Lines 31 to 40. A name goes round at most once per unit of frequency, so the length of M
/// times the cap, and one more, bounds the walk.
fn fifo_evict_main(self: anytype, now_ns: u64) void {
    const steps_max = self.main.len * (frequency_max + 1) + 1;
    var steps: usize = 0;
    while (steps < steps_max and self.main.len > 0) : (steps += 1) {
        const tail = self.main.oldest;
        self.main.remove(&self.links.older, &self.links.newer, tail);
        if (now_ns < self.expires_ns[tail] and self.frequency[tail] > 0) {
            self.frequency[tail] -= 1;
            self.main.push(&self.links.older, &self.links.newer, tail);
            continue;
        }
        self.place[tail] = .out;
        return;
    }
}

// Tests. Small tables whose every step can be followed by hand.

const testing = std.testing;
const test_names = 64;
const second: u64 = std.time.ns_per_s;
const life: u64 = 100 * second;

/// Fills an S3-FIFO model of ten entries with names 0 to 9, all live for `life`.
fn filled(model: *S3Fifo(test_names), promote_above: u8) void {
    model.init(share_whole, promote_above, .evict_on_get);
    var id: Id = 0;
    while (id < share_whole) : (id += 1) _ = model.access(id, life, 0);
}

test "S3-FIFO sends a name read once to the ghost, and its return to the main queue" {
    var model: S3Fifo(test_names) = undefined;
    filled(&model, 1);
    // Full, and S holds everything: 0, never read again, leaves for G.
    try testing.expect(!model.access(10, life, 0));
    try testing.expectEqual(Place.out, model.place[0]);
    try testing.expect(fifo_in_ghost(&model, 0));
    try testing.expect(!model.access(0, life, 0));
    try testing.expectEqual(Place.main, model.place[0]);
    try testing.expect(!fifo_in_ghost(&model, 0));
}

test "S3-FIFO moves a name to M above the threshold, and not at it" {
    var model: S3Fifo(test_names) = undefined;
    filled(&model, 1);
    _ = model.access(0, life, 0);
    _ = model.access(1, life, 0);
    _ = model.access(1, life, 0);
    // 0 was read once, which is not above 1: it goes to G. 1 was read twice and goes to M.
    _ = model.access(10, life, 0);
    try testing.expectEqual(Place.out, model.place[0]);
    _ = model.access(11, life, 0);
    try testing.expectEqual(Place.main, model.place[1]);
    try testing.expectEqual(@as(u8, 0), model.frequency[1]);
}

test "Figure 5's reading moves a name read once" {
    var model: S3Fifo(test_names) = undefined;
    filled(&model, 0);
    _ = model.access(0, life, 0);
    _ = model.access(10, life, 0);
    try testing.expectEqual(Place.main, model.place[0]);
}

test "the frequency caps at three, and the main queue spends one a pass" {
    var model: S3Fifo(test_names) = undefined;
    filled(&model, 0);
    var reads: usize = 0;
    while (reads < 2 * frequency_max) : (reads += 1) _ = model.access(0, life, 0);
    try testing.expectEqual(@as(u8, frequency_max), model.frequency[0]);
    model.frequency[0] = 1;
    model.small.remove(&model.links.older, &model.links.newer, 0);
    model.main.push(&model.links.older, &model.links.newer, 0);
    model.place[0] = .main;
    fifo_evict_main(&model, 0);
    // 0 had one unit: it went round once, and was still the only name in M, so it went next.
    try testing.expectEqual(Place.out, model.place[0]);
}

test "S3-FIFO evicts an expired name on sight, and does not ghost it" {
    var model: S3Fifo(test_names) = undefined;
    model.init(share_whole, 1, .evict_on_get);
    _ = model.access(0, second, 0);
    var id: Id = 1;
    while (id < share_whole) : (id += 1) _ = model.access(id, life, 0);
    _ = model.access(10, life, 2 * second);
    try testing.expectEqual(Place.out, model.place[0]);
    try testing.expect(!fifo_in_ghost(&model, 0));
}

test "S3-FIFO refreshes an expired name where it stands, and counts the refresh a use" {
    var model: S3Fifo(test_names) = undefined;
    model.init(share_whole, 1, .refresh_in_place);
    _ = model.access(0, second, 0);
    _ = model.access(0, second, 0);
    try testing.expect(!model.access(0, second, 2 * second));
    try testing.expectEqual(Place.small, model.place[0]);
    try testing.expectEqual(@as(u8, 2), model.frequency[0]);
}

test "a ghost leaves G once G's size more names have gone in after it" {
    var model: S3Fifo(test_names) = undefined;
    filled(&model, 1);
    // Each new name pushes the oldest of S, read never, into G; G holds nine.
    var id: Id = share_whole;
    while (id < share_whole + main_share) : (id += 1) _ = model.access(id, life, 0);
    try testing.expect(fifo_in_ghost(&model, 0));
    _ = model.access(id, life, 0);
    try testing.expect(!fifo_in_ghost(&model, 0));
    try testing.expect(fifo_in_ghost(&model, 1));
}
