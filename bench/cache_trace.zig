//! Does the cache earn its keep? `zig build bench` prints this table after the nanosecond rows
//! (docs/design.md §18, the question §17 left open).
//!
//! The nanosecond rows say what a hit costs. They cannot say whether hits happen, and that is the
//! question a cache exists to answer. This replays a stream of questions through the real
//! `cocuyo.Cache` at several sizes and reports the hit rate, the evictions and the expiries.
//!
//! **The trace is synthetic, and that is the weakness of this table.** What it models is stated
//! below and nothing else: a popularity distribution, a TTL mixture and an arrival rate, each a
//! named constant a reader can disagree with. The trace is written down once as a
//! `trace_recording.Recording` and every replay reads that, so `log_replay.zig` puts a real log
//! through the same replays.
const std = @import("std");
const assert = std.debug.assert;
const policy = @import("cache_policy/cache_policy.zig");
const cares_policy = @import("cache_policy/cache_policy_cares.zig");
const s3fifo_policy = @import("cache_policy/cache_policy_s3fifo.zig");
const tinylfu_policy = @import("cache_policy/cache_policy_tinylfu.zig");
const expected_policy = @import("cache_policy/cache_policy_expected.zig");
const recording_module = @import("trace_recording.zig");
const cache_replay = @import("cache_replay.zig");
const optimal_module = @import("cache_optimal.zig");
const Outcome = recording_module.Outcome;
const Recording = recording_module.Recording;
const replay_model = recording_module.replay_model;

/// The sizes swept, in slots. The smallest is a cache too small to hold the working set and the
/// largest holds it whole, so the table shows where the curve bends.
pub const sizes = [_]usize{ 64, 256, 1024, 4096, 16384 };

/// How many distinct names the trace draws from, and how many questions it asks. A resolver on a
/// laptop sees a few tens of thousands of distinct names in a day.
const names_distinct = 50_000;
const requests = 1_000_000;

/// Zipf's exponent. One is the value measured for web object popularity over decades, and DNS
/// name popularity is the same shape for the same reason: a few names carry most of the traffic.
/// This is the assumption the whole table rests on.
const zipf_exponent = 1.0;

/// How far apart two questions arrive. A million of them at this spacing is a little under three
/// hours of virtual time, which is long enough for every TTL below to expire many times over.
const arrival_ns = 10 * std.time.ns_per_ms;

/// The TTL mixture, in seconds, and how many of the thousand names take each. A minute is what a
/// CDN gives, five minutes what most zones give, and an hour what infrastructure names give.
pub const ttl_seconds = [_]u32{ 60, 300, 3600 };
const ttl_shares = [_]u32{ 400, 400, 200 };
pub const ttl_share_total = 1000;

/// The name every request asks about has five decimal digits, which covers the names above.
const name_digits = 5;

/// The questions asked, in order. Deterministic: one seed replays byte for byte, which is the
/// rule the library keeps and a bench that decides a policy should keep too.
const Trace = struct {
    state: u64,
    weights: *const [names_distinct]f64,
    total_weight: f64,

    fn init(seed: u64, curve: *const [names_distinct]f64) Trace {
        return .{ .state = seed, .weights = curve, .total_weight = curve[names_distinct - 1] };
    }

    /// Xorshift64*: three shifts and a multiply, enough for a popularity draw and small enough to
    /// read. The bench is not cryptography.
    fn next_random(self: *Trace) u64 {
        var x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        return x *% 0x2545_f491_4f6c_dd1d;
    }

    /// The next name's index, drawn from the popularity curve by binary search over its running
    /// sum. Bounded: the search is over a fixed array.
    fn next_name(self: *Trace) usize {
        const draw = @as(f64, @floatFromInt(self.next_random() >> 11)) /
            @as(f64, @floatFromInt(@as(u64, 1) << 53)) * self.total_weight;
        var low: usize = 0;
        var high: usize = names_distinct - 1;
        while (low < high) {
            const middle = low + (high - low) / 2;
            if (self.weights[middle] < draw) low = middle + 1 else high = middle;
        }
        return low;
    }
};

/// The running sum of `1 / (rank ** exponent)`, so a draw against it is a Zipf draw.
fn build_weights(into: *[names_distinct]f64) void {
    var running: f64 = 0;
    for (into, 0..) |*slot, index| {
        const rank: f64 = @floatFromInt(index + 1);
        running += 1.0 / std.math.pow(f64, rank, zipf_exponent);
        slot.* = running;
    }
}

/// The TTL a name keeps for the whole run, by the shares above. A name's TTL does not change
/// under it, which is what a zone's own configuration does.
///
/// The share follows the name's rank, and the names are drawn in rank order, so the most popular
/// 40% of names take a minute, the next 40% five minutes and the least popular 20% an hour. That
/// is an assumption of its own, and `log_replay.zig` measures a real log both ways.
fn ttl_of(index: usize) u32 {
    return ttl_for_share(@intCast((index * ttl_share_total / names_distinct) % ttl_share_total));
}

/// The TTL of a name whose place in the mixture is `bucket`, out of `ttl_share_total`.
pub fn ttl_for_share(bucket: u32) u32 {
    std.debug.assert(bucket < ttl_share_total);
    var edge: u32 = 0;
    for (ttl_shares, ttl_seconds) |share, seconds| {
        edge += share;
        if (bucket < edge) return seconds;
    }
    return ttl_seconds[ttl_seconds.len - 1];
}

var weights: [names_distinct]f64 = undefined;
var sieve_model: policy.Sieve(names_distinct) = undefined;
var s3fifo_model: s3fifo_policy.S3Fifo(names_distinct) = undefined;
var cares_model: cares_policy.Unbounded(names_distinct) = undefined;
var tinylfu_model: tinylfu_policy.WTinyLfu(names_distinct) = undefined;
var expected_model: expected_policy.ExpectedHits(names_distinct) = undefined;

/// How many entries the affordable form of expected hits reads per eviction: few enough for a put
/// path, and the number the replay reports beside reading them all.
const expected_draws = 16;

/// The trace written down once: `record` fills these, and every replay reads them.
var trace_names: [requests]policy.Id = undefined;
var trace_times_ns: [requests]u64 = undefined;
var trace_next: [requests]u32 = undefined;
var trace_lives_ns: [names_distinct]u64 = undefined;
var last_seen: [names_distinct]u32 = undefined;
var optimal: optimal_module.Optimal(names_distinct) = undefined;

/// S3-FIFO's two readings of when a name leaves the small queue for the main one: above one
/// read, as Algorithm 1 line 23 has it, and above none, as Figure 5 has it.
const s3fifo_line_23 = 1;
const s3fifo_figure_5 = 0;

/// Writes down `request_count` questions of the trace, one every `arrival_ns`, with every name's
/// life from `ttl_of`, and links each to the next one for the same name.
fn record(seed: u64, request_count: usize) Recording {
    assert(request_count <= requests);
    var trace = Trace.init(seed, &weights);
    for (trace_names[0..request_count], trace_times_ns[0..request_count], 0..) |*name, *time, at| {
        name.* = @intCast(trace.next_name());
        time.* = (@as(u64, at) + 1) * arrival_ns;
    }
    for (&trace_lives_ns, 0..) |*life, index| life.* = @as(u64, ttl_of(index)) * std.time.ns_per_s;
    const recording: Recording = .{
        .names = trace_names[0..request_count],
        .times_ns = trace_times_ns[0..request_count],
        .next = trace_next[0..request_count],
        .lives_ns = &trace_lives_ns,
    };
    recording.link(&last_seen);
    return recording;
}

/// The real cache over the recording.
fn replay(recording: *const Recording, slot_count: usize, seed: u64) Outcome {
    return cache_replay.replay(name_digits, recording, slot_count, seed);
}

/// The cache against what could be done better: the same SIEVE taking the soonest expired entry
/// first, W-TinyLFU, and the optimal, which no policy can pass.
fn run_bounds(recording: *const Recording, seed: u64) void {
    std.debug.print("\nhow far from the best: the cache, two policies that might do better, and the optimal\n\n", .{});
    std.debug.print("{s:>8} {s:>10} {s:>14} {s:>10} {s:>10}\n", .{ "slots", "cache", "expired first", "w-tinylfu", "optimal" });
    for (sizes) |slot_count| {
        const cache_rate = replay(recording, slot_count, seed).rate_percent();
        sieve_model.init(slot_count, .refresh_in_place, .expired_first);
        const expired_first = replay_model(&sieve_model, recording).rate_percent();
        tinylfu_model.init(slot_count);
        const tinylfu = replay_model(&tinylfu_model, recording).rate_percent();
        const best = optimal.replay(recording, slot_count).rate_percent();
        std.debug.print("{d:>8} {d:>9.2}% {d:>13.2}% {d:>9.2}% {d:>9.2}%\n", .{ slot_count, cache_rate, expired_first, tinylfu, best });
    }
}

/// Expected hits, `cache_policy_expected.zig`: counting every ask, then counting reuse with every
/// entry read, with admission, and with a few drawn at random, which is the form a cache could run.
fn run_expected(recording: *const Recording, seed: u64) void {
    std.debug.print("\nexpected hits: a name's count times the time its answer has left\n\n", .{});
    std.debug.print("{s:>8} {s:>10} {s:>12} {s:>12} {s:>14} {s:>14}\n", .{ "slots", "cache", "every ask", "reuse", "reuse, admit", "reuse, 16" });
    for (sizes) |slot_count| {
        const cache_rate = replay(recording, slot_count, seed).rate_percent();
        expected_model.init(slot_count, slot_count, false, .every_ask);
        const every_ask = replay_model(&expected_model, recording).rate_percent();
        expected_model.init(slot_count, slot_count, false, .reuse);
        const reuse = replay_model(&expected_model, recording).rate_percent();
        expected_model.init(slot_count, slot_count, true, .reuse);
        const admitted = replay_model(&expected_model, recording).rate_percent();
        expected_model.init(slot_count, expected_draws, true, .reuse);
        const drawn = replay_model(&expected_model, recording).rate_percent();
        std.debug.print("{d:>8} {d:>9.2}% {d:>11.2}% {d:>11.2}% {d:>13.2}% {d:>13.2}%\n", .{ slot_count, cache_rate, every_ask, reuse, admitted, drawn });
    }
}

/// SIEVE against S3-FIFO on the trace above, under each rule for an expired entry, with the
/// model of SIEVE as the control: it must match the real cache's column before the other
/// columns mean anything (docs/design.md §18).
fn run_policies(recording: *const Recording, seed: u64) void {
    std.debug.print("\nthe same trace, hit rate by policy and by what a get does with an expired entry\n\n", .{});
    std.debug.print("{s:>8} {s:>10} | {s:>36} | {s:>36}\n", .{ "", "", "evicted by the get", "renewed in place, as the cache does" });
    std.debug.print("{s:>8} {s:>10} | {s:>10} {s:>12} {s:>12} | {s:>10} {s:>12} {s:>12}\n", .{
        "slots", "cache", "sieve", "s3-fifo l23", "s3-fifo f5", "sieve", "s3-fifo l23", "s3-fifo f5",
    });
    for (sizes) |slot_count| {
        const cache_rate = replay(recording, slot_count, seed).rate_percent();
        std.debug.print("{d:>8} {d:>9.2}% |", .{ slot_count, cache_rate });
        for ([_]policy.Expiry{ .evict_on_get, .refresh_in_place }) |expiry| {
            sieve_model.init(slot_count, expiry, .hand);
            const sieve = replay_model(&sieve_model, recording).rate_percent();
            s3fifo_model.init(slot_count, s3fifo_line_23, expiry);
            const line_23 = replay_model(&s3fifo_model, recording).rate_percent();
            s3fifo_model.init(slot_count, s3fifo_figure_5, expiry);
            const figure_5 = replay_model(&s3fifo_model, recording).rate_percent();
            std.debug.print(" {d:>9.2}% {d:>11.2}% {d:>11.2}% |", .{ sieve, line_23, figure_5 });
        }
        std.debug.print("\n", .{});
    }
    run_bounds(recording, seed);
    run_expected(recording, seed);
    cares_model.init();
    const cares = replay_model(&cares_model, recording);
    std.debug.print(
        "\nc-ares's rule, no bound on the entry count: {d:.2}% hits, at most {d} entries live at once\n",
        .{ cares.rate_percent(), cares_model.entries_peak },
    );
}

pub fn run(seed: u64) void {
    build_weights(&weights);
    const recording = record(seed, requests);
    std.debug.print(
        "\ncache over a synthetic trace: {d} questions, {d} distinct names, Zipf {d:.1}, " ++
            "one every {d} ms, TTLs {d}/{d}/{d} s\n\n",
        .{ requests, names_distinct, zipf_exponent, arrival_ns / std.time.ns_per_ms, ttl_seconds[0], ttl_seconds[1], ttl_seconds[2] },
    );
    std.debug.print("{s:>8} {s:>10} {s:>12} {s:>12}\n", .{ "slots", "hit rate", "hits", "misses" });
    for (sizes) |slot_count| {
        const outcome = replay(&recording, slot_count, seed);
        std.debug.print(
            "{d:>8} {d:>9.1}% {d:>12} {d:>12}\n",
            .{ slot_count, outcome.rate_percent(), outcome.hits, outcome.misses },
        );
    }
    run_policies(&recording, seed);
}

// Tests. The replay is a measurement, so what is tested is that its parts say what they claim.

const testing = std.testing;

test {
    _ = recording_module;
    _ = cache_replay;
    _ = optimal_module;
    _ = policy;
    _ = cares_policy;
    _ = s3fifo_policy;
    _ = tinylfu_policy;
    _ = expected_policy;
}

/// The control's own check, on a trace short enough for a Debug test: the smallest size, where
/// evictions are most frequent and a model that strayed would stray first.
const control_requests = 50_000;

test "the model of SIEVE answers every question as the cache does" {
    build_weights(&weights);
    const recording = record(1, control_requests);
    const slot_count = sizes[0];
    const cache_outcome = replay(&recording, slot_count, 1);
    sieve_model.init(slot_count, .refresh_in_place, .hand);
    const model_outcome = replay_model(&sieve_model, &recording);
    try testing.expectEqual(cache_outcome.hits, model_outcome.hits);
}

test "the popularity curve is a running sum, so a draw against it is a Zipf draw" {
    build_weights(&weights);
    try testing.expect(weights[0] > 0);
    var index: usize = 1;
    while (index < names_distinct) : (index += 1) {
        try testing.expect(weights[index] > weights[index - 1]);
    }
    // The first name carries more than the thousandth: that is what Zipf says.
    const first = weights[0];
    const thousandth = weights[999] - weights[998];
    try testing.expect(first > thousandth * 100);
}

test "a name's TTL is one of the mixture, and the same every time it is asked" {
    var index: usize = 0;
    while (index < names_distinct) : (index += 1) {
        const ttl = ttl_of(index);
        try testing.expect(ttl == ttl_seconds[0] or ttl == ttl_seconds[1] or ttl == ttl_seconds[2]);
        try testing.expectEqual(ttl, ttl_of(index));
    }
}

test "one seed replays the same questions" {
    build_weights(&weights);
    var first = Trace.init(1, &weights);
    var second = Trace.init(1, &weights);
    var made: usize = 0;
    while (made < 1000) : (made += 1) {
        try testing.expectEqual(first.next_name(), second.next_name());
    }
}

test "the recording holds the trace's questions, one every arrival" {
    build_weights(&weights);
    const recording = record(1, control_requests);
    var trace = Trace.init(1, &weights);
    for (recording.names[0..1000], recording.times_ns[0..1000], 0..) |name, time, at| {
        try testing.expectEqual(@as(policy.Id, @intCast(trace.next_name())), name);
        try testing.expectEqual((@as(u64, at) + 1) * arrival_ns, time);
    }
    try testing.expectEqual(@as(u64, ttl_of(0)) * std.time.ns_per_s, recording.lives_ns[0]);
}

test "no policy beats the optimal on the trace" {
    build_weights(&weights);
    const recording = record(1, control_requests);
    const slot_count = sizes[0];
    const best = optimal.replay(&recording, slot_count);
    const cache_outcome = replay(&recording, slot_count, 1);
    sieve_model.init(slot_count, .refresh_in_place, .expired_first);
    const expired_first = replay_model(&sieve_model, &recording);
    tinylfu_model.init(slot_count);
    const tinylfu = replay_model(&tinylfu_model, &recording);
    try testing.expect(best.hits >= cache_outcome.hits);
    try testing.expect(best.hits >= expired_first.hits);
    try testing.expect(best.hits >= tinylfu.hits);
    expected_model.init(slot_count, slot_count, true, .reuse);
    const expected = replay_model(&expected_model, &recording);
    try testing.expect(best.hits >= expected.hits);
}
