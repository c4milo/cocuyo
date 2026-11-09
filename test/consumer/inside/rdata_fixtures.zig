//! A refusal of `zig build consumer-check` (docs/design.md §20, the surface since 2026-11-09): a
//! consumer that reaches for `cocuyo.rdata.fixtures`. `rdata` holds the readers of record data, and
//! not their test data. So this must not build.
const cocuyo = @import("cocuyo");

pub fn main() void {
    _ = cocuyo.rdata.fixtures;
}
