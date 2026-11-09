//! A refusal of `zig build consumer-check` (docs/design.md §20, the surface since 2026-11-09): a
//! consumer that reaches for `cocuyo.resolver`. The module `resolver` left the surface, and its
//! parts are not public. So this must not build.
const cocuyo = @import("cocuyo");

pub fn main() void {
    _ = cocuyo.resolver;
}
