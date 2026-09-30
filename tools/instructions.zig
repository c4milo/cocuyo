//! `zig build instructions`: pepegrillo's `instructions` tool over `bench/count.zig`, which holds
//! each case to the instructions one operation takes, against `bench/instructions.zon`
//! (docs/performance.md). It counts under cachegrind, which runs on Linux; anywhere else it says it
//! cannot count and exits 2, so the gate builds it and CI's Linux job runs it.
//!
//! The names are the ones `bench/count.zig` takes, each the argument of the case it names.
const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.instructions.main(init, .{
        .cases = &.{
            .{ .name = "query-build", .arguments = &.{"query-build"} },
            .{ .name = "query-build-tcp", .arguments = &.{"query-build-tcp"} },
            .{ .name = "parse-one", .arguments = &.{"parse-one"} },
            .{ .name = "parse-cname", .arguments = &.{"parse-cname"} },
            .{ .name = "parse-sixteen", .arguments = &.{"parse-sixteen"} },
            .{ .name = "match-stray", .arguments = &.{"match-stray"} },
            .{ .name = "match-wrong", .arguments = &.{"match-wrong"} },
            .{ .name = "match-accept", .arguments = &.{"match-accept"} },
            .{ .name = "round-trip", .arguments = &.{"round-trip"} },
            .{ .name = "resolv-conf", .arguments = &.{"resolv-conf"} },
            .{ .name = "cache-hit", .arguments = &.{"cache-hit"} },
            .{ .name = "cache-miss", .arguments = &.{"cache-miss"} },
            .{ .name = "cache-put", .arguments = &.{"cache-put"} },
            .{ .name = "cache-put-evict", .arguments = &.{"cache-put-evict"} },
        },
        // 2%, the floor docs/performance.md sets: a count moves by nothing but code, so any move
        // past it is the code's.
        .threshold_per_mille = 20,
    });
}
