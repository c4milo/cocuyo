//! The fuzz target for the text parsers: one seed in, one text built by fuzz_generate.zig, its
//! parser run over it by fuzz_check.zig (docs/design.md §13).
//!
//! The codec's target, `src/wire/fuzz.zig`, reads what the network sends. This one reads what the
//! caller hands in: an address, a name, a `resolv.conf`, a hosts file and an SPKI pin. The caller
//! is trusted and its files are not proof against a stray byte (SECURITY.md): a file with a
//! malformed line must still configure a resolver, and nothing in it may trip an assertion.
//!
//! The gate is a test, so `zig build test` runs it over `seed_count` seeds and prints nothing
//! unless a seed fails. `zig build fuzz -- --text --seed <hex>` runs one seed and prints the text
//! it built, which is how a failure is reproduced: the seed is the whole input.
const std = @import("std");
const generate_module = @import("fuzz_generate.zig");
const check_module = @import("fuzz_check.zig");

pub const Text = generate_module.Text;
pub const Target = generate_module.Target;
pub const Shape = generate_module.Shape;
pub const Scratch = check_module.Scratch;
pub const generate = generate_module.generate;
pub const check = check_module.check;

/// How many seeds `zig build test` runs. A text is at most a couple of kilobytes and one parser
/// reads it twice, so this is the codec's count, and keeps the gate inside a second or two.
pub const seed_count = 4096;

/// Runs one seed. Returns the promise that broke, or null when the text held up.
pub fn run(seed: u64, out: *Text, scratch: *Scratch) ?[]const u8 {
    generate(seed, out);
    return check(out, scratch);
}

pub const Failure = struct { seed: u64, what: []const u8 };

/// Runs `count` seeds from `first`. Returns the first seed that failed and what broke.
pub fn gate(first: u64, count: u64) ?Failure {
    var text: Text = .{};
    var scratch: Scratch = .{};
    for (0..count) |offset| {
        const seed = first + offset;
        if (run(seed, &text, &scratch)) |what| return .{ .seed = seed, .what = what };
    }
    return null;
}

// Tests.

const testing = std.testing;

test "the text fuzz gate holds over every seed it runs" {
    if (gate(0, seed_count)) |failure| {
        std.debug.print(
            "text fuzz: seed 0x{x} broke a promise: {s}\n  reproduce with: zig build fuzz -- --text --seed 0x{x}\n",
            .{ failure.seed, failure.what, failure.seed },
        );
        return error.FuzzInvariantViolated;
    }
}

test "the gate reaches every parser in every shape" {
    // A gate that only ever built noise would pass while checking nothing a parser reads whole.
    var reached: [Target.count][Shape.count]usize = @splat(@splat(0));
    var text: Text = .{};
    for (0..seed_count) |seed| {
        generate(seed, &text);
        reached[@intFromEnum(text.target)][@intFromEnum(text.shape)] += 1;
    }
    for (reached) |shapes| {
        for (shapes) |count| try testing.expect(count > 0);
    }
}

test "a whole text read back as something else, and a near miss taken, are failures" {
    var scratch: Scratch = .{};
    var text: Text = .{ .target = .address, .shape = .whole };
    text.put("192.0.2.2");
    text.expected.add_address(@import("core").Address.from_v4(.{ 192, 0, 2, 1 }));
    try testing.expect(check(&text, &scratch) != null);
    var miss: Text = .{ .target = .pin, .shape = .near_miss };
    miss.put("FHkyLhvI0n70E47cJlRTamTrnYVcsYdjUGbr79CfAVI=");
    try testing.expect(check(&miss, &scratch) != null);
}

test {
    _ = generate_module;
    _ = check_module;
}
