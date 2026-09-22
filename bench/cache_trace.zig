//! Does the cache earn its keep? `zig build bench` prints this table after the nanosecond rows
//! (docs/design.md §18, the question §17 left open).
//!
//! The nanosecond rows say what a hit costs. They cannot say whether hits happen, and that is the
//! question a cache exists to answer. This replays a stream of questions through the real
//! `cocuyo.Cache` at several sizes and reports the hit rate, the evictions and the expiries.
//!
//! **The trace is synthetic, and that is the weakness of this table.** No DNS trace was measured
//! to make it. What it models is stated below and nothing else: a popularity distribution, a TTL
//! mixture and an arrival rate, each a named constant a reader can disagree with. A real trace
//! replaces `Trace.next` and nothing else, so the day one exists the table can be remade.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const cache_module = cocuyo.cache;
const Question = cocuyo.Question;
const wire = cocuyo.wire;

/// The sizes swept, in slots. The smallest is a cache too small to hold the working set and the
/// largest holds it whole, so the table shows where the curve bends.
const sizes = [_]usize{ 64, 256, 1024, 4096, 16384 };
const slots_max = sizes[sizes.len - 1];
const keys_max = slots_max * cache_module.constants.keys_per_slot_min;

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
const ttl_seconds = [_]u32{ 60, 300, 3600 };
const ttl_shares = [_]u32{ 400, 400, 200 };
const ttl_share_total = 1000;

/// The name every request asks about: `n` and five decimal digits, which covers the names above.
const name_prefix = "n";
const name_suffix = ".example.";
const name_digits = 5;

/// What the replay counts.
const Outcome = struct {
    hits: u64 = 0,
    misses: u64 = 0,

    fn rate_percent(self: Outcome) f64 {
        const total: f64 = @floatFromInt(self.hits + self.misses);
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) * 100.0 / total;
    }
};

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
fn ttl_of(index: usize) u32 {
    const bucket: u32 = @intCast((index * ttl_share_total / names_distinct) % ttl_share_total);
    var edge: u32 = 0;
    for (ttl_shares, ttl_seconds) |share, seconds| {
        edge += share;
        if (bucket < edge) return seconds;
    }
    return ttl_seconds[ttl_seconds.len - 1];
}

fn question_of(index: usize, text: *[name_prefix.len + name_digits + name_suffix.len]u8) Question {
    @memcpy(text[0..name_prefix.len], name_prefix);
    var value = index;
    var at = name_prefix.len + name_digits;
    while (at > name_prefix.len) {
        at -= 1;
        text[at] = '0' + @as(u8, @intCast(value % 10));
        value /= 10;
    }
    @memcpy(text[name_prefix.len + name_digits ..], name_suffix);
    return Question.from_text(text, .a) catch unreachable;
}

/// One answer, reused: this table counts hits, not what they carry.
fn answers_with(ttl: u32) wire.Answers {
    var out = wire.Answers.init(.a);
    out.items.addresses[0] = cocuyo.Address.from_text("192.0.2.1").?;
    out.count = 1;
    out.ttl_seconds = ttl;
    return out;
}

var weights: [names_distinct]f64 = undefined;
var slots: [slots_max]cache_module.Slot = undefined;
var keys: [keys_max]cache_module.Key = undefined;

/// Replays the whole trace through a cache of `slot_count` slots.
fn replay(slot_count: usize, seed: u64) Outcome {
    const key_count = std.math.ceilPowerOfTwoAssert(usize, slot_count * cache_module.constants.keys_per_slot_min);
    @memset(slots[0..slot_count], cache_module.Slot.empty);
    var store = cache_module.Cache.init(slots[0..slot_count], keys[0..key_count], seed, cache_module.constants.ttl_seconds_max_default);
    var trace = Trace.init(seed, &weights);
    var outcome: Outcome = .{};
    var now_ns: u64 = 0;
    var made: usize = 0;
    while (made < requests) : (made += 1) {
        now_ns += arrival_ns;
        const index = trace.next_name();
        var text: [name_prefix.len + name_digits + name_suffix.len]u8 = undefined;
        const question = question_of(index, &text);
        if (store.get(&question, now_ns) != null) {
            outcome.hits += 1;
            continue;
        }
        outcome.misses += 1;
        const answers = answers_with(ttl_of(index));
        store.put(&question, &answers, now_ns);
    }
    return outcome;
}

pub fn run(seed: u64) void {
    build_weights(&weights);
    std.debug.print(
        "\ncache over a synthetic trace: {d} questions, {d} distinct names, Zipf {d:.1}, " ++
            "one every {d} ms, TTLs {d}/{d}/{d} s\n\n",
        .{ requests, names_distinct, zipf_exponent, arrival_ns / std.time.ns_per_ms, ttl_seconds[0], ttl_seconds[1], ttl_seconds[2] },
    );
    std.debug.print("{s:>8} {s:>10} {s:>12} {s:>12}\n", .{ "slots", "hit rate", "hits", "misses" });
    for (sizes) |slot_count| {
        const outcome = replay(slot_count, seed);
        std.debug.print(
            "{d:>8} {d:>9.1}% {d:>12} {d:>12}\n",
            .{ slot_count, outcome.rate_percent(), outcome.hits, outcome.misses },
        );
    }
}

// Tests. The replay is a measurement, so what is tested is that its parts say what they claim.

const testing = std.testing;

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

test "a name's question is its own, and reads back as the index it came from" {
    var text: [name_prefix.len + name_digits + name_suffix.len]u8 = undefined;
    const first = question_of(0, &text);
    var other: [name_prefix.len + name_digits + name_suffix.len]u8 = undefined;
    const second = question_of(1, &other);
    try testing.expect(!first.name.equal(&second.name));
    _ = question_of(42, &text);
    try testing.expectEqualStrings("n00042.example.", &text);
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
