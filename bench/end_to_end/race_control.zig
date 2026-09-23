//! A race ThreadSanitizer must report: the positive control `-Dsanitize-thread` runs before the
//! comparison's tests, and whose report the build requires. A sanitizer that reports nothing
//! passes every test it is given, which is how it passed on Zig 0.16's own x86_64 backend: that
//! backend instruments no access, and the flag said nothing about it (docs/mutations.md T1).
//!
//! Two threads meet, then both write one plain integer with nothing ordering the writes. The
//! process exits with ThreadSanitizer's `exitcode` when it reported, and with zero when it did
//! not, which the build refuses.
const std = @import("std");

/// Writes each thread makes after the two meet: enough that both are writing at once.
const writes_per_thread = 100_000;
const threads = 2;

var shared: u64 = 0;
var arrived: std.atomic.Value(u32) = .init(0);

fn write_unordered() void {
    _ = arrived.fetchAdd(1, .acq_rel);
    while (arrived.load(.acquire) < threads) std.atomic.spinLoopHint();
    for (0..writes_per_thread) |_| shared += 1;
}

pub fn main() !void {
    const other = try std.Thread.spawn(.{}, write_unordered, .{});
    write_unordered();
    other.join();
}
