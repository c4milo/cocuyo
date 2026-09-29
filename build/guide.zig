//! `zig build guide`: pepegrillo's `docs/performance.md`, the method every performance change
//! follows, installed at the commit `build.zig.zon` pins to `zig-out/docs/performance-method.md`.
//! cocuyo's appendix to it, `docs/performance.md`, sends the reader there first.
const std = @import("std");

/// Adds `zig build guide`, which installs pepegrillo's method from the package the build fetched.
pub fn add(b: *std.Build, pepegrillo: *std.Build.Dependency) void {
    const guide = b.step("guide", "Install pepegrillo's performance method, the one every change follows, to zig-out/docs/performance-method.md");
    guide.dependOn(&b.addInstallFile(pepegrillo.path("docs/performance.md"), "docs/performance-method.md").step);
}
