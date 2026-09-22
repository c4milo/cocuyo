//! The negative control of `zig build consumer-check` (docs/design.md §20): a consumer that tries
//! to reach past the surface and import the deterministic twin. The package registers `cocuyo`
//! and nothing else, so this must not build — the way `zig build graph-check` requires its own
//! fixture to be rejected.
const sim = @import("sim");

pub fn main() void {
    _ = sim;
}
