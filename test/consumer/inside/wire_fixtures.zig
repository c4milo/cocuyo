//! A refusal of `zig build consumer-check` (docs/design.md §20, the surface since 2026-11-09): a
//! consumer that reaches for `cocuyo.wire.fixtures`. The test data of `wire` is not public. So this
//! must not build.
const cocuyo = @import("cocuyo");

pub fn main() void {
    _ = cocuyo.wire.fixtures;
}
