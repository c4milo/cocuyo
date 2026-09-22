//! One deterministic mixing step over a 64-bit word: SplitMix64's finalizer, as published by
//! Steele, Lea and Flood (2014) and used by `std.Random.SplitMix64`.
//!
//! cocuyo needs a mix in two places — the DNS-0x20 case pattern in `wire`, and the transaction id
//! and source-port hint in `resolver` — so it lives in `core`, which both can reach, and is
//! written once with its constants named.
//!
//! This is not a cryptographic generator and cocuyo does not claim it is. It spreads the caller's
//! seed, and the strength of the spoofing defences rests on that seed coming from a CSPRNG
//! (docs/design.md §7). What the mix buys is determinism: one seed replays byte for byte, which is
//! what makes the state machine testable.
const std = @import("std");
const assert = std.debug.assert;

/// The golden-ratio increment: 2^64 divided by the golden ratio, rounded to an odd integer.
const increment = 0x9e3779b97f4a7c15;

/// SplitMix64's two multipliers and three shifts.
const multiplier_first = 0xbf58476d1ce4e5b9;
const multiplier_second = 0x94d049bb133111eb;
const shift_first = 30;
const shift_second = 27;
const shift_final = 31;

/// The bits one word holds, which is how many one-bit decisions a word can answer.
pub const word_bits = @bitSizeOf(u64);

/// The next word after `word`. Wrapping arithmetic throughout: the mix is defined modulo 2^64.
pub fn next(word: u64) u64 {
    var value = word +% increment;
    value = (value ^ (value >> shift_first)) *% multiplier_first;
    value = (value ^ (value >> shift_second)) *% multiplier_second;
    const mixed = value ^ (value >> shift_final);
    assert(shift_final < word_bits);
    return mixed;
}

// Tests.

const testing = std.testing;

test "the mix is a pure function of its input" {
    try testing.expectEqual(next(0), next(0));
    try testing.expectEqual(next(1), next(1));
    try testing.expect(next(0) != next(1));
}

test "the mix is the published SplitMix64 step, pinned by its own vectors" {
    // Nothing under src/ may name a random source (non-negotiable 4), so these two words are
    // vectors rather than a comparison against std. Both were checked against
    // std.Random.SplitMix64 outside src/ on 2026-09-21 and against the published algorithm's
    // arithmetic, and they agree; a change to the constants above fails here.
    try testing.expectEqual(@as(u64, 0xe220a8397b1dcdaf), next(0));
    try testing.expectEqual(@as(u64, 0x910a2dec89025cc1), next(1));
}

test "a zero seed does not stay zero, and low seeds do not stay close" {
    try testing.expect(next(0) != 0);
    const first = next(0);
    const second = next(1);
    try testing.expect(@popCount(first ^ second) > word_bits / 4);
}
