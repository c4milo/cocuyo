//! The second program `zig build instructions` counts (tools/instructions_dnssec.zig): cocuyo's
//! half of one validation, `bench/bench_validate.zig`'s case, set up once and run a given number of
//! times (docs/design.md §17 question 111).
//!
//!     count-dnssec validate-one <rounds>
//!
//! It is a program apart from `bench/count.zig` because the validator calls the codec. In one
//! program the compiler inlined the codec's functions otherwise, and `parse-sixteen` moved 2.1%
//! with no change to its code. Apart, each program counts its own code as it was compiled before.
const std = @import("std");
const validate_cases = @import("bench_validate.zig");

/// The one case, by its name in `bench/instructions_dnssec.zon`.
pub const name = "validate-one";

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len != 3 or !std.mem.eql(u8, arguments[1], name)) usage();
    const rounds = std.fmt.parseInt(u64, arguments[2], 10) catch usage();
    const case = validate_cases.all[0];
    case.setup();
    for (0..rounds) |_| case.run();
}

fn usage() noreturn {
    std.debug.print("usage: count-dnssec " ++ name ++ " <rounds>\n", .{});
    std.process.exit(2);
}
