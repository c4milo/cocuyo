//! A refusal of `zig build consumer-check` (docs/design.md §20, the surface since 2026-11-09): a
//! consumer that reaches for `cocuyo.resolv_conf.fuzz`. `resolv_conf` holds the parser, and not the
//! test data of its fuzz gate. So this must not build.
const cocuyo = @import("cocuyo");

pub fn main() void {
    _ = cocuyo.resolv_conf.fuzz;
}
