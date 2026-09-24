//! The TLA+ models, checked by TLC: pepegrillo's `tla` tool over spec/tla/, one directory a model,
//! each `.cfg` one run with the verdict its header expects (docs/design.md §16 decision 24). With
//! `walks` first, it writes the engine model's walks for the replay instead (`tla_walks.zig`).
//!
//! Run:  zig build tla
//!       zig build tla -- walks <seed> <walks> <depth> [--pick <file> <walk>...]
//!
//! TLC is the jar `$TLA2TOOLS_JAR` names, or else the pinned release, which the tool fetches into
//! its cache and refuses unless its SHA-256 is the one below. It needs Java 11 or newer.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const walks = @import("tla_walks.zig");

const project: pepegrillo.tla.Config = .{
    .tlc_release = "v1.7.4",
    .tlc_sha256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88",
};

/// The bytes the walks are written through: a walk's lines go out by the million.
const output_buffer_bytes: usize = 64 * 1024;

pub fn main(init: std.process.Init) !void {
    const arguments = try init.minimal.args.toSlice(init.arena.allocator());
    if (arguments.len < 2 or !std.mem.eql(u8, arguments[1], "walks")) return pepegrillo.tla.main(init, project);
    var output_buffer: [output_buffer_bytes]u8 = undefined;
    var error_buffer: [output_buffer_bytes]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &output_buffer);
    var errors = std.Io.File.stderr().writerStreaming(init.io, &error_buffer);
    const status = try walks.run(init, project, arguments[2..], &out.interface, &errors.interface);
    try errors.interface.flush();
    try out.interface.flush();
    std.process.exit(status);
}

test {
    _ = walks;
}
