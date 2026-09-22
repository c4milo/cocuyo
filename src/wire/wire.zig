//! wire: the codec. Byte slices in, values out, no state beyond an offset. This is the half of
//! cocuyo that faces an attacker, so it is the half with the fuzz target and most of the mutations
//! (docs/design.md §8 and §13).
//!
//! Step 2 of §15 fills this module.
const core = @import("core");

test {
    _ = core;
}
