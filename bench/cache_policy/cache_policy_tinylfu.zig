//! W-TinyLFU, from Einziger, Friedman and Manes, "TinyLFU: A Highly Efficient Cache Admission
//! Policy" (arXiv 1512.00727v2), read from the paper, as a model over name indices for the replay
//! of `cache_trace.zig`.
//!
//! Every name asked for enters a window cache, LRU, without admission. The window's victim then
//! competes with the main cache's victim, and the one asked for more often recently stays (§3.1,
//! §4). The main cache is segmented LRU: a probation segment new names enter, and a protected one
//! a hit in probation promotes to; the victim is probation's oldest (§2.1, §4).
//!
//! The paper counts with a minimal-increment counting Bloom filter behind a doorkeeper (§3.2,
//! §3.4.2), which approximate a histogram. This model keeps the histogram itself: one counter a
//! name, halved every sample and capped as §3.3 and §3.4.1 say. What it measures is the policy
//! with no counting error, which is the most the sketch could give.
//!
//! Two things the paper does not have are folded in as in the other models. An expired name is
//! renewed where it stands when asked again, and the renewal counts as a use, as the cache's put
//! in place does. And an expired name loses the admission contest, on either side.
const std = @import("std");
const assert = std.debug.assert;
const policy = @import("cache_policy.zig");
const Id = policy.Id;
const Links = policy.Links;
const Queue = policy.Queue;

/// The window's share of the cache: 1%, and at least one entry (§4, Caffeine 2.0).
const window_share_percent = 1;
/// The protected segment's share of the main cache: 80%, and probation the rest (§4).
const protected_share_percent = 80;
const percent_whole = 100;

/// The sample W, as a multiple of the cache size C: ten, as Caffeine keeps it (§5.1). A counter
/// needs to reach no higher than W / C (§3.4.1), so that is its cap.
const sample_per_slot = 10;
const count_max = sample_per_slot;

/// Where a name is.
const Place = enum(u8) { out, window, probation, protected };

pub fn WTinyLfu(comptime names: usize) type {
    return struct {
        const Self = @This();

        links: Links(names),
        place: [names]Place,
        expires_ns: [names]u64,
        /// The frequency histogram TinyLFU approximates.
        counts: [names]u8,
        /// Records since the counters were last halved, which the halving halves too (§3.3).
        recorded: usize,
        sample: usize,
        window: Queue,
        probation: Queue,
        protected: Queue,
        window_capacity: usize,
        main_capacity: usize,
        protected_capacity: usize,

        pub fn init(self: *Self, capacity: usize) void {
            tiny_init(self, capacity);
        }

        /// True on a hit. A miss puts the name in, as the replay's put after a miss does.
        pub fn access(self: *Self, id: Id, life_ns: u64, now_ns: u64) bool {
            return tiny_access(self, id, life_ns, now_ns);
        }
    };
}

fn tiny_init(self: anytype, capacity: usize) void {
    assert(capacity >= 2 and capacity <= self.place.len);
    @memset(&self.links.older, policy.none);
    @memset(&self.links.newer, policy.none);
    @memset(&self.place, .out);
    @memset(&self.counts, 0);
    self.recorded = 0;
    self.sample = capacity * sample_per_slot;
    self.window = .{};
    self.probation = .{};
    self.protected = .{};
    self.window_capacity = @max(1, capacity * window_share_percent / percent_whole);
    self.main_capacity = capacity - self.window_capacity;
    self.protected_capacity = self.main_capacity * protected_share_percent / percent_whole;
}

fn tiny_access(self: anytype, id: Id, life_ns: u64, now_ns: u64) bool {
    record(self, id);
    if (self.place[id] != .out) {
        const hit = now_ns < self.expires_ns[id];
        if (!hit) self.expires_ns[id] = now_ns + life_ns;
        touch(self, id);
        return hit;
    }
    self.expires_ns[id] = now_ns + life_ns;
    push(self, &self.window, id, .window);
    if (self.window.len > self.window_capacity) {
        const candidate = self.window.oldest;
        take(self, candidate);
        admit(self, candidate, now_ns);
    }
    return false;
}

/// One arrival into the histogram, and the halving once a sample has gone by (§3.3).
fn record(self: anytype, id: Id) void {
    self.counts[id] = @min(self.counts[id] + 1, count_max);
    self.recorded += 1;
    if (self.recorded < self.sample) return;
    for (&self.counts) |*count| count.* /= 2;
    self.recorded /= 2;
}

fn push(self: anytype, queue: *Queue, id: Id, place: Place) void {
    queue.push(&self.links.older, &self.links.newer, id);
    self.place[id] = place;
}

/// Takes a name out of whichever queue holds it.
fn take(self: anytype, id: Id) void {
    const queue = switch (self.place[id]) {
        .window => &self.window,
        .probation => &self.probation,
        .protected => &self.protected,
        .out => unreachable,
    };
    queue.remove(&self.links.older, &self.links.newer, id);
    self.place[id] = .out;
}

/// A use of a name the cache holds: LRU in the window and in protected, and a promotion out of
/// probation, whose overflow goes back to probation's newest end (§2.1).
fn touch(self: anytype, id: Id) void {
    const place = self.place[id];
    take(self, id);
    switch (place) {
        .window => push(self, &self.window, id, .window),
        .probation, .protected => push(self, &self.protected, id, .protected),
        .out => unreachable,
    }
    if (self.protected.len > self.protected_capacity) {
        const demoted = self.protected.oldest;
        take(self, demoted);
        push(self, &self.probation, demoted, .probation);
    }
}

/// The window's victim against the main cache's (§4). While the main cache has room it goes in;
/// otherwise the one asked for more often stays, the victim keeping a tie.
fn admit(self: anytype, candidate: Id, now_ns: u64) void {
    if (self.probation.len + self.protected.len < self.main_capacity) {
        return push(self, &self.probation, candidate, .probation);
    }
    if (now_ns >= self.expires_ns[candidate]) return;
    const victim = if (self.probation.len > 0) self.probation.oldest else self.protected.oldest;
    const victim_dead = now_ns >= self.expires_ns[victim];
    if (!victim_dead and self.counts[candidate] <= self.counts[victim]) return;
    take(self, victim);
    push(self, &self.probation, candidate, .probation);
}

// Tests. A cache of ten: a window of one, a main cache of nine, seven of them protected.

const testing = std.testing;
const test_names = 64;
const test_capacity = 10;
const second: u64 = std.time.ns_per_s;
const life: u64 = 100 * second;

/// Names 0 to 9 asked once each: 9 in the window, 0 to 8 in probation, oldest first.
fn filled(model: *WTinyLfu(test_names), short_lived: ?Id) void {
    model.init(test_capacity);
    var id: Id = 0;
    while (id < test_capacity) : (id += 1) {
        _ = model.access(id, if (short_lived == id) second else life, 0);
    }
}

test "the window takes every newcomer, and passes its victim on while the main cache has room" {
    var model: WTinyLfu(test_names) = undefined;
    filled(&model, null);
    try testing.expectEqual(Place.window, model.place[9]);
    try testing.expectEqual(@as(usize, 9), model.probation.len);
    try testing.expectEqual(@as(Id, 0), model.probation.oldest);
}

test "a newcomer asked no more often than the main victim is turned away" {
    var model: WTinyLfu(test_names) = undefined;
    filled(&model, null);
    // 9 leaves the window for 10, asked once, as 0 was: the victim keeps a tie.
    try testing.expect(!model.access(10, life, 0));
    try testing.expectEqual(Place.out, model.place[9]);
    try testing.expectEqual(Place.probation, model.place[0]);
}

test "a newcomer asked more often than the main victim takes its place" {
    var model: WTinyLfu(test_names) = undefined;
    filled(&model, null);
    try testing.expect(model.access(9, life, 0));
    try testing.expect(!model.access(10, life, 0));
    try testing.expectEqual(Place.probation, model.place[9]);
    try testing.expectEqual(Place.out, model.place[0]);
}

test "a hit in probation promotes, and protected's overflow goes back to probation" {
    var model: WTinyLfu(test_names) = undefined;
    filled(&model, null);
    var id: Id = 0;
    while (id < 8) : (id += 1) try testing.expect(model.access(id, life, 0));
    try testing.expectEqual(@as(usize, 7), model.protected.len);
    try testing.expectEqual(Place.probation, model.place[0]);
    try testing.expectEqual(Place.protected, model.place[7]);
}

test "every counter halves once a sample has gone by, and none passes the cap" {
    var model: WTinyLfu(test_names) = undefined;
    model.init(test_capacity);
    var made: usize = 0;
    while (made < model.sample / 2) : (made += 1) _ = model.access(0, life, 0);
    try testing.expectEqual(@as(u8, count_max), model.counts[0]);
    while (made < model.sample - 1) : (made += 1) _ = model.access(1, life, 0);
    try testing.expectEqual(@as(u8, count_max), model.counts[1]);
    _ = model.access(1, life, 0);
    try testing.expectEqual(@as(u8, count_max / 2), model.counts[0]);
    try testing.expectEqual(model.sample / 2, model.recorded);
}

test "an expired victim loses to any newcomer" {
    var model: WTinyLfu(test_names) = undefined;
    filled(&model, 0);
    _ = model.access(10, life, 2 * second);
    try testing.expectEqual(Place.probation, model.place[9]);
    try testing.expectEqual(Place.out, model.place[0]);
}

test "an expired newcomer loses to any victim" {
    var model: WTinyLfu(test_names) = undefined;
    filled(&model, 9);
    try testing.expect(model.access(9, second, 0));
    try testing.expect(model.access(9, second, 0));
    // 9 is asked more often than 0, but it has expired by the time it leaves the window.
    _ = model.access(10, life, 2 * second);
    try testing.expectEqual(Place.out, model.place[9]);
    try testing.expectEqual(Place.probation, model.place[0]);
}
