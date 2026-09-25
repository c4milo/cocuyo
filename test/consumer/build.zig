//! A package that depends on cocuyo the way any project would, so the branch a dependent takes
//! through cocuyo's own build — the early return, the manifest's `paths` — is compiled rather
//! than assumed (docs/design.md §20). `zig build consumer-check` in the parent runs this twice:
//! once as it stands, which must build, and once with `-Dreach-inside`, which must not.
//!
//! It builds two programs: `consumer`, which drives the table with no I/O, and `embedded`, which
//! runs `cocuyo_rotor`'s resolver on a rotor loop of its own, the rotor this package declares and
//! binds into it (docs/design.md §24).
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const inside = b.option(bool, "reach-inside", "Import a module the package does not export") orelse false;
    const cocuyo = b.dependency("cocuyo", .{ .target = target });
    const exe = b.addExecutable(.{
        .name = "consumer",
        .root_module = b.createModule(.{
            .root_source_file = b.path(if (inside) "inside.zig" else "main.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    exe.root_module.addImport("cocuyo", cocuyo.module("cocuyo"));
    // `sim` is not a name this package registers, so asking for it fails the build here.
    if (inside) exe.root_module.addImport("sim", cocuyo.module("sim"));
    b.installArtifact(exe);

    // The consumer's own rotor, bound into cocuyo's resolver, so the loop the program makes is the
    // type the resolver takes and the image holds one rotor.
    const rotor = b.dependency("rotor", .{ .target = target }).module("rotor");
    const resolver = cocuyo.module("cocuyo_rotor");
    resolver.addImport("rotor", rotor);
    const embedded = b.addExecutable(.{
        .name = "embedded",
        .root_module = b.createModule(.{
            .root_source_file = b.path("embed.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    embedded.root_module.addImport("rotor", rotor);
    embedded.root_module.addImport("cocuyo", cocuyo.module("cocuyo"));
    embedded.root_module.addImport("cocuyo_rotor", resolver);
    b.installArtifact(embedded);
}
