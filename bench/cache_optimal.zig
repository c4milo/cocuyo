//! The optimal: Belady's rule over a recorded trace, which reads the trace's future (docs/design.md
//! §18). No cache can run it; it is the bound a real policy is measured against.
//!
//! A name whose next question comes after its answer expires is worth nothing, since that question
//! misses whatever the cache holds. Otherwise the name needed latest goes first, and a newcomer
//! can be the one turned away. An expired name it holds is renewed in place.
const std = @import("std");
const policy = @import("cache_policy/cache_policy.zig");
const recording_module = @import("trace_recording.zig");
const Id = recording_module.Id;
const Outcome = recording_module.Outcome;
const Recording = recording_module.Recording;
const no_request = recording_module.no_request;

pub fn Optimal(comptime names: usize) type {
    return struct {
        const Self = @This();

        resident: [names]bool,
        expires_ns: [names]u64,
        keys: [names]u64,
        heap: policy.KeyedHeap(names),

        /// The most hits any policy could make at `slot_count` slots on `recording`.
        pub fn replay(self: *Self, recording: *const Recording, slot_count: usize) Outcome {
            std.debug.assert(recording.lives_ns.len <= names);
            @memset(&self.resident, false);
            self.heap.len = 0;
            var outcome: Outcome = .{};
            for (0..recording.names.len) |at| {
                if (step(self, recording, at, slot_count)) outcome.hits += 1 else outcome.misses += 1;
            }
            return outcome;
        }
    };
}

/// How much a name is worth keeping after question `at`, smallest first to go.
pub fn useful_key(recording: *const Recording, at: usize, expires_ns: u64) u64 {
    const next = recording.next[at];
    if (next == no_request or recording.times_ns[next] >= expires_ns) return 0;
    return std.math.maxInt(u64) - @as(u64, next);
}

fn step(self: anytype, recording: *const Recording, at: usize, slot_count: usize) bool {
    const name = recording.names[at];
    const now_ns = recording.times_ns[at];
    const hit = self.resident[name] and now_ns < self.expires_ns[name];
    if (!hit) self.expires_ns[name] = now_ns + recording.lives_ns[name];
    self.keys[name] = useful_key(recording, at, self.expires_ns[name]);
    if (self.resident[name]) {
        self.heap.update(&self.keys, name);
        return hit;
    }
    self.resident[name] = true;
    self.heap.push(&self.keys, name);
    if (self.heap.len > slot_count) {
        const least = self.heap.smallest().?;
        self.heap.remove(&self.keys, least);
        self.resident[least] = false;
    }
    return false;
}

// Tests: A, B, A, with every question a second apart and every answer living ten.

const testing = std.testing;
const second: u64 = std.time.ns_per_s;

const Fixture = struct {
    names: [3]Id = .{ 0, 1, 0 },
    times: [3]u64 = .{ second, 2 * second, 3 * second },
    next: [3]u32 = undefined,
    lives: [2]u64 = .{ 10 * second, 10 * second },
    last_seen: [2]u32 = undefined,

    fn recording(self: *Fixture) Recording {
        const out: Recording = .{ .names = &self.names, .times_ns = &self.times, .next = &self.next, .lives_ns = &self.lives };
        out.link(&self.last_seen);
        return out;
    }
};

test "a name is worth nothing when its next question comes after it expires, or never" {
    var fixture: Fixture = .{};
    const recording = fixture.recording();
    try testing.expectEqual(@as(u32, 2), recording.next[0]);
    try testing.expectEqual(no_request, recording.next[1]);
    try testing.expectEqual(@as(u64, 0), useful_key(&recording, 1, std.math.maxInt(u64)));
    try testing.expectEqual(@as(u64, 0), useful_key(&recording, 0, 3 * second));
    try testing.expectEqual(std.math.maxInt(u64) - 2, useful_key(&recording, 0, 3 * second + 1));
}

test "the optimal turns a newcomer away when it is needed later than what it would replace" {
    // A, B, A in one slot. Any real cache takes B in and loses A; the optimal keeps A.
    var fixture: Fixture = .{};
    const recording = fixture.recording();
    var optimal: Optimal(2) = undefined;
    const outcome = optimal.replay(&recording, 1);
    try testing.expectEqual(@as(u64, 1), outcome.hits);
    var sieve: policy.Sieve(2) = undefined;
    sieve.init(1, .refresh_in_place, .hand);
    try testing.expectEqual(@as(u64, 0), recording_module.replay_model(&sieve, &recording).hits);
}
