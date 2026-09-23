//! The real `cocuyo.Cache` replayed over a recorded trace (docs/design.md §18): each question a
//! get, each miss a put of one answer with the name's life. The name of question `n` is the text
//! `n` followed by the index in `digits` decimal digits and `.example.`, so the cache hashes and
//! compares real names while the recording keeps only indices.
const std = @import("std");
const cocuyo = @import("cocuyo");
const cache_module = cocuyo.cache;
const Question = cocuyo.Question;
const wire = cocuyo.wire;
const recording_module = @import("trace_recording.zig");
const Outcome = recording_module.Outcome;
const Recording = recording_module.Recording;

/// The largest cache a replay makes: `cache.constants.slots_max`, the most the library allows.
pub const slots_max = cache_module.constants.slots_max;
const keys_max = std.math.ceilPowerOfTwoAssert(usize, slots_max * cache_module.constants.keys_per_slot_min);

const name_prefix = "n";
const name_suffix = ".example.";

var slots: [slots_max]cache_module.Slot = undefined;
var keys: [keys_max]cache_module.Key = undefined;

pub fn NameText(comptime digits: usize) type {
    return [name_prefix.len + digits + name_suffix.len]u8;
}

/// The question for name `index`, written into `text`.
pub fn question_of(comptime digits: usize, index: usize, text: *NameText(digits)) Question {
    @memcpy(text[0..name_prefix.len], name_prefix);
    var value = index;
    var at = name_prefix.len + digits;
    while (at > name_prefix.len) {
        at -= 1;
        text[at] = '0' + @as(u8, @intCast(value % 10));
        value /= 10;
    }
    std.debug.assert(value == 0);
    @memcpy(text[name_prefix.len + digits ..], name_suffix);
    return Question.from_text(text, .a) catch unreachable;
}

/// The address every answer carries: a replay counts hits, not what they carry.
const answer_address = cocuyo.Address.from_v4(.{ 192, 0, 2, 1 });

/// Replays `recording` through a cache of `slot_count` slots, its hash keyed by `seed`.
pub fn replay(comptime digits: usize, recording: *const Recording, slot_count: usize, seed: u64) Outcome {
    std.debug.assert(slot_count >= 1 and slot_count <= slots_max);
    const key_count = std.math.ceilPowerOfTwoAssert(usize, slot_count * cache_module.constants.keys_per_slot_min);
    // `init` empties the slots it is handed, so a replay starts from an empty table.
    var store = cache_module.Cache.init(slots[0..slot_count], keys[0..key_count], seed, cache_module.constants.ttl_seconds_max_default);
    var outcome: Outcome = .{};
    for (recording.names, recording.times_ns) |index, now_ns| {
        var text: NameText(digits) = undefined;
        const question = question_of(digits, index, &text);
        if (store.get(&question, now_ns) != null) {
            outcome.hits += 1;
            continue;
        }
        outcome.misses += 1;
        const ttl: u32 = @intCast(recording.lives_ns[index] / std.time.ns_per_s);
        const answers = wire.fixtures.answers_address(answer_address, ttl);
        store.put(&question, &answers, null, now_ns);
    }
    return outcome;
}

// Tests.

const testing = std.testing;

test "a name's question is its own, and reads back as the index it came from" {
    var text: NameText(5) = undefined;
    const first = question_of(5, 0, &text);
    var other: NameText(5) = undefined;
    const second = question_of(5, 1, &other);
    try testing.expect(!first.name.equal(&second.name));
    _ = question_of(5, 42, &text);
    try testing.expectEqualStrings("n00042.example.", &text);
    var wide: NameText(8) = undefined;
    _ = question_of(8, 12_345_678, &wide);
    try testing.expectEqualStrings("n12345678.example.", &wide);
}
