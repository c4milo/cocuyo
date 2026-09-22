//! The cache rows of `zig build bench`: what a hit, a miss and a put cost (docs/design.md §18),
//! at 1024 entries, which is the table size the datagram-match rows use too.
//!
//! The rows are read against each other. A hot hit is the hash, one probe and the name compare;
//! the rotating hit adds the slot read out of the first-level cache; a miss on a young index stops
//! at the first empty key entry, and a miss after churn walks the probe bound, because an evicted
//! entry leaves a tombstone the walk steps over and nothing reclaims them but `flush`. The
//! eviction row is that churned state: the table full, every put a fresh name, and the hand one
//! step from the entry it takes.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const cache = cocuyo.cache;
const Case = @import("harness.zig").Case;
const iterations = @import("bench_cases.zig").iterations;
const Question = cocuyo.Question;

const doNotOptimizeAway = std.mem.doNotOptimizeAway;

const slot_count = 1024;
const key_count = slot_count * cache.constants.keys_per_slot_min;

/// The seed the datagram-match rows use, so the two tables are keyed alike.
const seed = 0x5eed_5eed;
const ttl_seconds = 300;

/// Every row runs at one instant: nothing here expires, so what is measured is the policy.
const now_ns = 0;

/// How many fresh names are put before the churned-miss row is measured: enough evictions that
/// every key entry that is not live is a tombstone, which takes one eviction per entry.
const churn_puts = key_count * 2;

/// The name every eviction-row put steps: ten decimal digits, which is more puts than a run makes.
const fresh_text = "fresh0000000000.example";
const fresh_digits_start = "fresh".len + 1;
const fresh_digits_end = fresh_digits_start + "0000000000".len;

pub const all = [_]Case{
    .{ .name = "cache hit, one entry, hot", .iterations = iterations, .run = &run_hit_hot, .setup = &setup_cache },
    .{ .name = "cache hit, rotating over 1024 entries", .iterations = iterations, .run = &run_hit_rotating, .setup = &setup_cache },
    .{ .name = "cache miss, 1024 entries, young index", .iterations = iterations, .run = &run_miss, .setup = &setup_cache },
    .{ .name = "cache miss, 1024 entries, after churn", .iterations = iterations, .run = &run_miss, .setup = &setup_churned },
    .{ .name = "cache put, replacing in place", .iterations = iterations, .run = &run_put_replace, .setup = &setup_cache },
    .{ .name = "cache put, evicting, 1024 entries full", .iterations = iterations, .run = &run_put_evict, .setup = &setup_cache },
};

var slots: [slot_count]cache.Slot = undefined;
var keys: [key_count]cache.Key = undefined;
var table: cache.Cache = undefined;
var questions: [slot_count]Question = undefined;
var answers: cocuyo.wire.Answers = undefined;
var absent: Question = undefined;
var fresh: Question = undefined;
var rotation: usize = 0;

fn setup_cache() void {
    table = cache.Cache.init(&slots, &keys, seed, cache.constants.ttl_seconds_max_default);
    answers = cocuyo.wire.Answers.init(.a);
    answers.items.addresses[0] = cocuyo.Address.from_v4(.{ 192, 0, 2, 1 });
    answers.count = 1;
    answers.ttl_seconds = ttl_seconds;
    var buffer: [24]u8 = undefined;
    for (&questions, 0..) |*question, index| {
        const text = std.fmt.bufPrint(&buffer, "l{d}.example", .{index}) catch unreachable;
        question.* = Question.from_text(text, .a) catch unreachable;
        table.put(question, &answers, now_ns);
    }
    // Every name went in: no chain reached the probe bound at this seed.
    assert(table.len() == slot_count);
    absent = Question.from_text("absent.example", .a) catch unreachable;
    fresh = Question.from_text(fresh_text, .a) catch unreachable;
    rotation = 0;
}

fn setup_churned() void {
    setup_cache();
    var puts: usize = 0;
    while (puts < churn_puts) : (puts += 1) run_put_evict();
    assert(table.len() == slot_count);
}

fn run_hit_hot() void {
    doNotOptimizeAway(table.get(&questions[0], now_ns));
}

fn run_hit_rotating() void {
    doNotOptimizeAway(table.get(&questions[rotation], now_ns));
    rotation = (rotation + 1) & (slot_count - 1);
}

fn run_miss() void {
    doNotOptimizeAway(table.get(&absent, now_ns));
}

fn run_put_replace() void {
    table.put(&questions[0], &answers, now_ns);
    doNotOptimizeAway(&table);
}

fn run_put_evict() void {
    advance(&fresh);
    table.put(&fresh, &answers, now_ns);
    doNotOptimizeAway(&table);
}

/// Steps the digits of the first label, so every put names a name the table does not hold. The
/// digits sit after the length octet and the five letters; the last digit moves fastest.
fn advance(question: *Question) void {
    var index: usize = fresh_digits_end;
    while (index > fresh_digits_start) {
        index -= 1;
        if (question.name.bytes[index] < '9') {
            question.name.bytes[index] += 1;
            return;
        }
        question.name.bytes[index] = '0';
    }
    unreachable;
}

test "the fresh name steps through distinct names" {
    var question = try Question.from_text(fresh_text, .a);
    const first = question.name;
    advance(&question);
    try std.testing.expect(!question.name.equal(&first));
    var steps: usize = 0;
    while (steps < 10) : (steps += 1) advance(&question);
    const eleventh = try Question.from_text("fresh0000000011.example", .a);
    try std.testing.expect(question.name.equal(&eleventh.name));
}
