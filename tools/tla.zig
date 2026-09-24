//! The TLA+ models, checked by TLC: pepegrillo's `tla` tool over spec/tla/, one directory a model,
//! each `.cfg` one run with the verdict its header expects (docs/design.md §16 decision 24).
//!
//! Run:  zig build tla
//!
//! TLC is the jar `$TLA2TOOLS_JAR` names, or else the pinned release, which the tool fetches into
//! its cache and refuses unless its SHA-256 is the one below. It needs Java 11 or newer.
const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.tla.main(init, .{
        .tlc_release = "v1.7.4",
        .tlc_sha256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
    });
}
