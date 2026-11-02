//! `zig build instructions`, its second part: pepegrillo's `instructions` tool over
//! `bench/count_dnssec.zig`, which holds cocuyo's half of one validation to the instructions it
//! takes, against `bench/instructions_dnssec.zon` (docs/design.md §17 question 111). A program and
//! a baseline of their own, so the validator's code changes no count of `bench/count.zig`.
const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.instructions.main(init, .{
        .cases = &.{
            .{ .name = "validate-one", .arguments = &.{"validate-one"} },
        },
        .baseline = "bench/instructions_dnssec.zon",
        // 2%, the floor docs/performance.md sets, as `tools/instructions.zig` has it.
        .threshold_per_mille = 20,
    });
}
