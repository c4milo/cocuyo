//! The fuzz target for the codec: one seed in, one message built by fuzz_generate.zig, every
//! parser run over it by fuzz_check.zig.
//!
//! The gate below is a test, so `zig build test` runs it over `seed_count` seeds and prints
//! nothing unless a seed fails. `zig build fuzz -- --seed <hex>` runs one seed and prints what it
//! built, which is how a failure is reproduced: the seed is the whole input.
//!
//! Zig 0.16 has a coverage-guided fuzzer of its own behind `zig build test --fuzz`, which needs a
//! build with instrumentation. It is not wired here. This gate is portable, deterministic and runs
//! on every host, which is what a check that must pass before every commit needs to be; a guided
//! fuzzer is a good thing to add beside it, not instead of it.
const std = @import("std");
const generate_module = @import("fuzz_generate.zig");
const check_module = @import("fuzz_check.zig");

pub const Message = generate_module.Message;
pub const Strategy = generate_module.Strategy;
pub const generate = generate_module.generate;
pub const check = check_module.check;

/// How many seeds `zig build test` runs. Every seed builds a message of up to 1232 octets and runs
/// five parsers over it, so this is the largest count that keeps the gate inside a second or two.
pub const seed_count = 4096;

/// Runs one seed. Returns the promise that broke, or null when the message held up.
pub fn run(seed: u64, out: *Message) ?[]const u8 {
    generate(seed, out);
    return check(out.slice());
}

/// Runs `count` seeds from `first`. Returns the first seed that failed and what broke.
pub const Failure = struct { seed: u64, what: []const u8 };

pub fn gate(first: u64, count: u64) ?Failure {
    var message: Message = .{};
    var seed = first;
    const last = first + count;
    while (seed < last) : (seed += 1) {
        if (run(seed, &message)) |what| return .{ .seed = seed, .what = what };
    }
    return null;
}

// Tests.

const testing = std.testing;

test "the fuzz gate holds over every seed it runs" {
    if (gate(0, seed_count)) |failure| {
        std.debug.print(
            "fuzz: seed 0x{x} broke a promise: {s}\n  reproduce with: zig build fuzz -- --seed 0x{x}\n",
            .{ failure.seed, failure.what, failure.seed },
        );
        return error.FuzzInvariantViolated;
    }
}

test "a seed that built a message reaching the parsers is checked, not merely rejected" {
    // A gate that only ever built unparseable noise would pass while checking nothing, so this
    // pins that some seeds produce messages the record walk actually reads.
    var message: Message = .{};
    var parsed: usize = 0;
    var seed: u64 = 0;
    while (seed < 256) : (seed += 1) {
        generate(seed, &message);
        if (message.strategy == .question_then_noise and message.len > 64) parsed += 1;
    }
    try testing.expect(parsed > 0);
}
