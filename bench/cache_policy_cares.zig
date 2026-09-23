//! c-ares's cache as docs/design.md §18 records it from `src/lib/ares_qcache.c`: no bound on the
//! entry count, and a skip list ordered by expiry that every fetch drains of what has expired.
//! Nothing is evicted to make room, so a name is a hit whenever it is asked inside its TTL. On a
//! given trace no cache with the same TTL rules hits more often; what the rule costs is the
//! entries it holds, and `entries_peak` counts them.
//!
//! The skip list is a binary heap here. Both keep the entries in expiry order, and which one does
//! it changes no hit and no count. The TTL rules are the ones the trace already applies: c-ares
//! caps a TTL at an hour by default, as `cache.constants.ttl_seconds_max_default` does, and no
//! TTL in the trace is longer.
const std = @import("std");
const assert = std.debug.assert;
const Id = @import("cache_policy.zig").Id;

pub fn Unbounded(comptime names: usize) type {
    return struct {
        const Self = @This();

        resident: [names]bool,
        expires_ns: [names]u64,
        /// The live entries, soonest expiry first: the skip list's order.
        heap: [names]Id,
        heap_len: usize,
        /// The most entries live at once over the replay: what this rule needs to hold.
        entries_peak: usize,

        pub fn init(self: *Self) void {
            unbounded_init(self);
        }

        /// True on a hit. A miss puts the name in, as the replay's put after a miss does.
        pub fn access(self: *Self, id: Id, life_ns: u64, now_ns: u64) bool {
            return unbounded_access(self, id, life_ns, now_ns);
        }
    };
}

fn unbounded_init(self: anytype) void {
    @memset(&self.resident, false);
    self.heap_len = 0;
    self.entries_peak = 0;
}

/// A fetch drains what has expired and then looks, so a name found is a live one.
fn unbounded_access(self: anytype, id: Id, life_ns: u64, now_ns: u64) bool {
    drain(self, now_ns);
    if (self.resident[id]) {
        assert(now_ns < self.expires_ns[id]);
        return true;
    }
    self.resident[id] = true;
    self.expires_ns[id] = now_ns + life_ns;
    push(self, id);
    self.entries_peak = @max(self.entries_peak, self.heap_len);
    return false;
}

/// Each pass takes one entry out, so the heap's length when the drain starts bounds it.
fn drain(self: anytype, now_ns: u64) void {
    const steps_max = self.heap_len;
    var steps: usize = 0;
    while (steps < steps_max and self.heap_len > 0) : (steps += 1) {
        const soonest = self.heap[0];
        if (now_ns < self.expires_ns[soonest]) return;
        self.resident[soonest] = false;
        pop(self);
    }
}

fn earlier(self: anytype, one: usize, other: usize) bool {
    return self.expires_ns[self.heap[one]] < self.expires_ns[self.heap[other]];
}

fn push(self: anytype, id: Id) void {
    assert(self.heap_len < self.heap.len);
    var at = self.heap_len;
    self.heap[at] = id;
    self.heap_len += 1;
    while (at > 0) {
        const parent = (at - 1) / 2;
        if (!earlier(self, at, parent)) return;
        std.mem.swap(Id, &self.heap[parent], &self.heap[at]);
        at = parent;
    }
}

fn pop(self: anytype) void {
    assert(self.heap_len > 0);
    self.heap_len -= 1;
    self.heap[0] = self.heap[self.heap_len];
    var at: usize = 0;
    while (2 * at + 1 < self.heap_len) {
        const left = 2 * at + 1;
        const right = left + 1;
        const child = if (right < self.heap_len and earlier(self, right, left)) right else left;
        if (!earlier(self, child, at)) return;
        std.mem.swap(Id, &self.heap[child], &self.heap[at]);
        at = child;
    }
}

// Tests.

const testing = std.testing;
const test_names = 64;
const second: u64 = std.time.ns_per_s;
const life: u64 = 100 * second;

test "a name asked inside its TTL is a hit, however many others came between" {
    var model: Unbounded(test_names) = undefined;
    model.init();
    try testing.expect(!model.access(0, life, 0));
    var id: Id = 1;
    while (id < test_names) : (id += 1) try testing.expect(!model.access(id, life, 0));
    try testing.expect(model.access(0, life, second));
    try testing.expectEqual(@as(usize, test_names), model.entries_peak);
}

test "a fetch drains what has expired, soonest first, and nothing else" {
    var model: Unbounded(test_names) = undefined;
    model.init();
    _ = model.access(0, 3 * second, 0);
    _ = model.access(1, 1 * second, 0);
    _ = model.access(2, 2 * second, 0);
    // At a second and a half only 1 has expired: it goes, and 0 and 2 stay.
    _ = model.access(3, life, 1500 * std.time.ns_per_ms);
    try testing.expect(!model.resident[1]);
    try testing.expect(model.resident[0] and model.resident[2]);
    try testing.expectEqual(@as(usize, 3), model.heap_len);
    // 1 went before 3 came in, so no more than three were ever live at once.
    try testing.expectEqual(@as(usize, 3), model.entries_peak);
    // At four seconds 0 and 2 have gone too, and 0 is a miss.
    try testing.expect(!model.access(0, life, 4 * second));
    try testing.expectEqual(@as(usize, 2), model.heap_len);
}
