//! A trace written down: every question in order, when it came, where the next question for the
//! same name is, and how long each name's answer lives. Every replay in `bench/` reads one, so a
//! synthetic trace and a real log go through the same code (docs/design.md §18).
//!
//! The link to the next question is what the optimal of `cache_optimal.zig` reads and no real
//! cache can. The arrays are the caller's: static for the synthetic trace, allocated for a log
//! whose size is known only once it is read.
const std = @import("std");
const assert = std.debug.assert;
const policy = @import("cache_policy/cache_policy.zig");

pub const Id = policy.Id;
pub const no_request = std.math.maxInt(u32);

/// What a replay counts.
pub const Outcome = struct {
    hits: u64 = 0,
    misses: u64 = 0,

    pub fn rate_percent(self: Outcome) f64 {
        const total: f64 = @floatFromInt(self.hits + self.misses);
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) * 100.0 / total;
    }

    pub fn add(self: *Outcome, other: Outcome) void {
        self.hits += other.hits;
        self.misses += other.misses;
    }
};

pub const Recording = struct {
    /// The name each question asked, by position.
    names: []Id,
    /// When each question came, never decreasing.
    times_ns: []u64,
    /// The position of the next question for the same name, or `no_request`.
    next: []u32,
    /// How long each name's answer lives, by name.
    lives_ns: []u64,

    /// The first `count` questions, with every name's life.
    pub fn prefix(self: *const Recording, count: usize) Recording {
        assert(count <= self.names.len);
        return .{
            .names = self.names[0..count],
            .times_ns = self.times_ns[0..count],
            .next = self.next[0..count],
            .lives_ns = self.lives_ns,
        };
    }

    /// Links each question to the next one for the same name, walking backward so that one pass
    /// does it. `last_seen` has room for every name.
    pub fn link(self: *const Recording, last_seen: []u32) void {
        assert(last_seen.len >= self.lives_ns.len);
        assert(self.names.len < no_request);
        @memset(last_seen[0..self.lives_ns.len], no_request);
        var at = self.names.len;
        while (at > 0) {
            at -= 1;
            const name = self.names[at];
            self.next[at] = last_seen[name];
            last_seen[name] = @intCast(at);
        }
    }
};

/// Replays a recording through a model of `bench/cache_policy/`, already sized.
pub fn replay_model(model: anytype, recording: *const Recording) Outcome {
    var outcome: Outcome = .{};
    for (recording.names, recording.times_ns) |name, now_ns| {
        if (model.access(name, recording.lives_ns[name], now_ns)) outcome.hits += 1 else outcome.misses += 1;
    }
    return outcome;
}

// Tests.

const testing = std.testing;

test "each question links to the next one for its name, and the last to none" {
    var names = [_]Id{ 0, 1, 0, 2, 1 };
    var times = [_]u64{ 1, 2, 3, 4, 5 };
    var next: [names.len]u32 = undefined;
    var lives = [_]u64{ 1, 1, 1 };
    var last_seen: [lives.len]u32 = undefined;
    const recording: Recording = .{ .names = &names, .times_ns = &times, .next = &next, .lives_ns = &lives };
    recording.link(&last_seen);
    try testing.expectEqualSlices(u32, &.{ 2, 4, no_request, no_request, no_request }, &next);
    const short = recording.prefix(2);
    try testing.expectEqual(@as(usize, 2), short.names.len);
    try testing.expectEqual(@as(usize, 3), short.lives_ns.len);
}
