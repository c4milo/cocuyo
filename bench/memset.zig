//! The `memset` a benchmark program exports on Linux under Zig 0.16, in place of compiler_rt's:
//! the recipe of pepegrillo's `docs/performance/performance_zig.md`, "Copies and fills", which
//! `zig build guide` installs.
//!
//! On Linux every `memset` a Zig 0.16 program calls is compiler_rt's, whether glibc is linked or
//! not, and it stores one octet at a time. It serves each `@memset` whose length is known only at
//! run time, and each 0xAA fill a safe build makes of an `undefined` too large to write in place.
//! A benchmark over it charges cocuyo for a loop that Zig's master has replaced with vector
//! stores. The guide measured a 4 KiB fill at 94 to 100 ns through this one and at 1,372 to
//! 1,377 ns through compiler_rt's, on an M1 Pro under arm64 Linux.
//!
//! The export sits in each program's root file, `bench/bench.zig` and `bench/cares.zig`, because
//! the symbol belongs to the program: a library that exported one would collide with its
//! caller's, so nothing under `src/` or `io/` does. `bench/count.zig` exports none. Its counts are
//! those of a consumer's Zig 0.16 program, where a fill costs instructions for every octet, so a
//! fill that appears on a hot path moves them far past their threshold.
//!
//! c-ares keeps glibc's `memset`. An ELF symbol takes the narrowest visibility of all its
//! definitions, and compiler_rt's is hidden, so the program's `memset` is hidden too: it stays out
//! of the dynamic symbol table, and the calls of a shared library such as c-ares bind to glibc's.
//! Zig's own linker, which a Debug build for x86-64 uses, exports it, so there c-ares's calls
//! come here.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

/// Whether a program needs this `memset`: on Linux, where compiler_rt's serves every call, and
/// under Zig 0.16, whose compiler_rt stores an octet at a time. Zig's master stores vectors, so
/// the upgrade past 0.16 turns the export off, and should delete this file.
pub const needed = builtin.os.tag == .linux and
    builtin.zig_version.major == 0 and builtin.zig_version.minor == 16;

/// Octets each step of the loop stores: the recipe's 32.
const block_bytes = 32;

/// C's `memset`: sets `length` octets from `destination` to the low octet of `value`, as C
/// converts it to an `unsigned char`, and returns `destination` (C11 §7.24.6.1). Blocks of
/// `block_bytes` cover a fill of at least one block, the last ending where the fill ends, so it
/// may overlap the one before it. A shorter fill is stored an octet at a time.
pub fn memset(destination: ?[*]u8, value: c_int, length: usize) callconv(.c) ?[*]u8 {
    // compiler_rt's turns safety off too: every caller holds `length` octets at `destination`, so
    // no offset here can overflow, and a check on each block would only cost.
    @setRuntimeSafety(false);
    const octets = destination orelse return destination;
    const octet: u8 = @truncate(@as(c_uint, @bitCast(value)));
    if (length < block_bytes) {
        for (0..length) |index| {
            octets[index] = octet;
            // The barrier keeps the compiler from turning the loop into a call to `memset`, which
            // is this function. Both loops keep it.
            std.mem.doNotOptimizeAway(octets);
        }
        return destination;
    }
    const block: @Vector(block_bytes, u8) = @splat(octet);
    var offset: usize = 0;
    while (offset + block_bytes <= length) : (offset += block_bytes) {
        octets[offset..][0..block_bytes].* = block;
        std.mem.doNotOptimizeAway(octets);
    }
    octets[length - block_bytes ..][0..block_bytes].* = block;
    return destination;
}

// Tests. They call the function by its Zig name, so they hold on every host, whether or not the
// program exports it.

const testing = std.testing;

/// The octet around a fill in the tests, which no fill writes.
const untouched: u8 = 0x5a;

/// The octet the tests fill with.
const octet_filled: u8 = 0xa5;

/// The value the tests pass: `octet_filled` with a bit set above it, which C's conversion drops.
const value_filled: c_int = 0x100 | @as(c_int, octet_filled);

/// Fills `length` octets of a buffer of `buffer_bytes`, from an octet past its start so that no
/// block is aligned, then checks every octet of the buffer.
fn expect_fill(comptime buffer_bytes: usize, length: usize) !void {
    var buffer: [buffer_bytes]u8 = @splat(untouched);
    const start = 1;
    assert(start + length < buffer.len);
    const returned = memset(buffer[start..].ptr, value_filled, length);
    try testing.expectEqual(@as(?[*]u8, buffer[start..].ptr), returned);
    for (buffer, 0..) |octet, index| {
        const covered = index >= start and index < start + length;
        try testing.expectEqual(if (covered) octet_filled else untouched, octet);
    }
}

test "a fill sets every octet it covers to the value's low octet, and none either side of it" {
    // Every length up to three blocks and one: each path, and each overlap of the last block.
    for (0..3 * block_bytes + 2) |length| try expect_fill(4 * block_bytes, length);
    // The guide's 4 KiB.
    try expect_fill(4096 + 2, 4096);
}
