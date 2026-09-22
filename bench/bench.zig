//! The microbenchmarks of docs/design.md §15 step 7: what one query build, one response parse and
//! one datagram match cost, in nanoseconds per operation, on the machine that ran them.
//!
//!     zig build bench
//!
//! Every case is built ReleaseSafe whatever `-Drelease` says, because ReleaseSafe is the mode
//! cocuyo ships in: assertions stay on in production (CLAUDE.md non-negotiable 3), and a number
//! measured with them off would be a number for a build nobody runs.
//!
//! The first row is the harness itself: an empty call through the same function pointer, so a
//! reader knows how much of every other row is the loop and not the operation. The method is in
//! `bench/harness.zig`, and the cases in `bench/bench_cases.zig` and `bench/bench_cache.zig`.
const harness = @import("harness.zig");
const cases = @import("bench_cases.zig");
const cache_cases = @import("bench_cache.zig");

pub fn main() void {
    harness.run("cocuyo bench", &(cases.all ++ cache_cases.all));
}

test {
    _ = harness;
    _ = cases;
    _ = cache_cases;
}
