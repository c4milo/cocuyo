//! The Lean proofs, built with lake: pepegrillo's `lean` tool over spec/lean/, the Lake package
//! that holds the models of docs/design.md §5 and §19 step 14 and the lookup's proofs. It runs
//! first in `zig build spec`, so a proof left unfinished stops the step before any replay.
//!
//! Run:  zig build spec
//!
//! The Lean release is the one spec/lean/lean-toolchain pins. This file holds cocuyo's
//! configuration of the tool, which is pepegrillo's defaults.
const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.lean.main(init, .{});
}
