//! Expected hits: an experiment of this repository's, not a published design, as a model over
//! name indices for the replay of `cache_trace.zig`.
//!
//! The optimal of docs/design.md §18 keeps a name while it will be asked again before its answer
//! expires. This ranks each entry by an estimate of that: how often its name has been asked
//! lately, as `cache_policy.Histogram` counts it, times how long its answer has left. An expired
//! entry is worth nothing. `Estimate` says what is counted: every ask, or only the asks after the
//! first, so that a name asked once is worth nothing until it is asked again. The entry worth least is evicted, and with admission on, a newcomer
//! worth no more than that entry is turned away, the victim keeping a tie as TinyLFU's does.
//!
//! The counts live outside the entries, so a name evicted keeps its history. The worths drift as
//! time passes, and two of them can swap order, so no index keeps them sorted: an eviction either
//! reads every entry, which is the ideal, or the least of a few drawn at random, which is what a
//! cache could afford on its put path.
const std = @import("std");
const assert = std.debug.assert;
const policy = @import("cache_policy.zig");
const Id = policy.Id;

/// The draws start from a fixed seed, so a replay repeats byte for byte.
const draw_seed = 0x9e37_79b9_7f4a_7c15;

/// What a name's count stands for. Counting every ask gives a name brought in by a single ask a
/// rate of one a sample, which a long TTL then multiplies into a large worth; counting reuse
/// gives it none.
pub const Estimate = enum { every_ask, reuse };

pub fn ExpectedHits(comptime names: usize) type {
    return struct {
        const Self = @This();

        resident: [names]bool,
        expires_ns: [names]u64,
        /// The names held, in no order, and where each one sits, so that one can leave from the
        /// middle and a draw can pick any of them.
        members: [names]Id,
        at: [names]usize,
        len: usize,
        capacity: usize,
        frequency: policy.Histogram(names),
        /// Entries read per eviction; the capacity or more reads them all.
        draws: usize,
        admission: bool,
        estimate: Estimate,
        state: u64,

        pub fn init(self: *Self, capacity: usize, draws: usize, admission: bool, estimate: Estimate) void {
            expected_init(self, capacity, draws, admission, estimate);
        }

        /// True on a hit. A miss puts the name in, unless admission turns it away.
        pub fn access(self: *Self, id: Id, life_ns: u64, now_ns: u64) bool {
            return expected_access(self, id, life_ns, now_ns);
        }
    };
}

fn expected_init(self: anytype, capacity: usize, draws: usize, admission: bool, estimate: Estimate) void {
    assert(capacity >= 1 and capacity <= self.resident.len);
    assert(draws >= 1);
    @memset(&self.resident, false);
    self.len = 0;
    self.capacity = capacity;
    self.frequency.init(capacity);
    self.draws = draws;
    self.admission = admission;
    self.estimate = estimate;
    self.state = draw_seed;
}

fn expected_access(self: anytype, id: Id, life_ns: u64, now_ns: u64) bool {
    self.frequency.record(id);
    if (self.resident[id]) {
        if (now_ns < self.expires_ns[id]) return true;
        // Renewed where it stands, as the cache's put in place renews it.
        self.expires_ns[id] = now_ns + life_ns;
        return false;
    }
    self.expires_ns[id] = now_ns + life_ns;
    if (self.len < self.capacity) {
        add(self, id);
        return false;
    }
    const victim = least(self, now_ns);
    if (self.admission and worth(self, id, now_ns) <= worth(self, victim, now_ns)) return false;
    remove(self, victim);
    add(self, id);
    return false;
}

/// The hits an entry can still give, up to a constant: its name's count times the time left.
fn worth(self: anytype, id: Id, now_ns: u64) u64 {
    const count = self.frequency.counts[id];
    const counted: u64 = if (self.estimate == .reuse) count -| 1 else count;
    return counted * (self.expires_ns[id] -| now_ns);
}

/// The entry worth least among every one held, or among `draws` of them drawn at random.
fn least(self: anytype, now_ns: u64) Id {
    assert(self.len > 0);
    const everything = self.draws >= self.len;
    const reads = if (everything) self.len else self.draws;
    var found = self.members[if (everything) 0 else draw(self)];
    var read: usize = 1;
    while (read < reads) : (read += 1) {
        const candidate = self.members[if (everything) read else draw(self)];
        if (worth(self, candidate, now_ns) < worth(self, found, now_ns)) found = candidate;
    }
    return found;
}

/// A position among the names held. Xorshift64*, as the trace draws its names.
fn draw(self: anytype) usize {
    var x = self.state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    self.state = x;
    return @intCast((x *% 0x2545_f491_4f6c_dd1d) % self.len);
}

fn add(self: anytype, id: Id) void {
    assert(self.len < self.capacity and !self.resident[id]);
    self.members[self.len] = id;
    self.at[id] = self.len;
    self.len += 1;
    self.resident[id] = true;
}

fn remove(self: anytype, id: Id) void {
    assert(self.resident[id]);
    const position = self.at[id];
    self.len -= 1;
    const last = self.members[self.len];
    self.members[position] = last;
    self.at[last] = position;
    self.resident[id] = false;
}

// Tests.

const testing = std.testing;
const test_names = 64;
const second: u64 = std.time.ns_per_s;
const life: u64 = 100 * second;

test "a name asked often outlives one asked once, with the same time left" {
    var model: ExpectedHits(test_names) = undefined;
    model.init(2, test_names, false, .every_ask);
    _ = model.access(0, life, 0);
    try testing.expect(model.access(0, life, 0));
    try testing.expect(model.access(0, life, 0));
    _ = model.access(1, life, 0);
    _ = model.access(2, life, 0);
    try testing.expect(model.resident[0] and !model.resident[1] and model.resident[2]);
}

test "an answer about to expire is worth less than a colder one with time left" {
    var model: ExpectedHits(test_names) = undefined;
    model.init(2, test_names, false, .every_ask);
    _ = model.access(0, 2 * second, 0);
    try testing.expect(model.access(0, 2 * second, 0));
    try testing.expect(model.access(0, 2 * second, 0));
    _ = model.access(1, life, 0);
    // At a second, 0 is worth three times one second and 1 is worth once ninety-nine.
    _ = model.access(2, life, second);
    try testing.expect(!model.resident[0] and model.resident[1]);
}

test "an expired entry is worth nothing, and an asked-again one is renewed where it stands" {
    var model: ExpectedHits(test_names) = undefined;
    model.init(2, test_names, false, .every_ask);
    _ = model.access(0, second, 0);
    try testing.expect(model.access(0, second, 0));
    _ = model.access(1, life, 0);
    try testing.expectEqual(@as(u64, 0), worth(&model, 0, 2 * second));
    try testing.expect(!model.access(0, life, 2 * second));
    try testing.expect(model.resident[0]);
    try testing.expectEqual(2 * second + life, model.expires_ns[0]);
}

test "admission turns away a newcomer worth no more than the entry it would replace" {
    var model: ExpectedHits(test_names) = undefined;
    model.init(1, test_names, true, .every_ask);
    _ = model.access(0, life, 0);
    try testing.expect(model.access(0, life, 0));
    // 1, asked once, is worth half of 0 with the same life: it is turned away.
    try testing.expect(!model.access(1, life, 0));
    try testing.expect(model.resident[0] and !model.resident[1]);
    // A tie goes to the entry held, as TinyLFU's does.
    model.init(1, test_names, true, .every_ask);
    _ = model.access(0, life, 0);
    try testing.expect(!model.access(1, life, 0));
    try testing.expect(model.resident[0] and !model.resident[1]);
    // Without admission it takes 0's place.
    model.init(1, test_names, false, .every_ask);
    _ = model.access(0, life, 0);
    _ = model.access(0, life, 0);
    _ = model.access(1, life, 0);
    try testing.expect(!model.resident[0] and model.resident[1]);
}

test "a drawn eviction reads only the entries it drew" {
    var model: ExpectedHits(test_names) = undefined;
    model.init(4, 1, false, .every_ask);
    var id: Id = 0;
    while (id < 4) : (id += 1) _ = model.access(id, life, 0);
    // One draw: the victim is whichever entry the generator names, not the least worth.
    var copy = model;
    const expected = copy.members[draw(&copy)];
    _ = model.access(4, life, 0);
    try testing.expect(!model.resident[expected]);
    try testing.expectEqual(@as(usize, 4), model.len);
}

test "counting reuse makes a name asked once worth nothing" {
    var model: ExpectedHits(test_names) = undefined;
    model.init(2, test_names, false, .reuse);
    _ = model.access(0, life, 0);
    try testing.expectEqual(@as(u64, 0), worth(&model, 0, 0));
    try testing.expect(model.access(0, life, 0));
    try testing.expectEqual(life, worth(&model, 0, 0));
    // The long-lived name asked once goes before the short-lived one asked again.
    _ = model.access(1, 10 * life, 0);
    _ = model.access(2, life, 0);
    try testing.expect(model.resident[0] and !model.resident[1]);
}
