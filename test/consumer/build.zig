//! A package that depends on cocuyo the way any project would, so the branch a dependent takes
//! through cocuyo's own build — the early return, the manifest's `paths` — is compiled rather
//! than assumed (docs/design.md §20). `zig build consumer-check` in the parent runs this twice:
//! once as it stands, which must build, and once with `-Dreach-inside`, which must not.
//!
//! It builds four programs:
//!
//! - `consumer` drives the table with no I/O.
//! - `embedded` runs `cocuyo_rotor`'s resolver on a rotor loop of its own, the rotor this package
//!   declares and binds into it (docs/design.md §24).
//! - `doq` runs the same resolver over DoQ. It names the session over chapulin, `chapulin_quic`,
//!   into which this package binds its colibri (§16 decision 38, as amended).
//! - `dot` runs the same resolver over DoT. It names the DoT session over chapulin, `chapulin`,
//!   into which this package binds its colibri (§16 decision 38, as amended for §17 question 64).
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

    // The consumer's own colibri, bound where a consumer that speaks DoQ binds it. Its `quic` goes
    // into cocuyo's connection, and its `quic` and `tls` into the session the connection names.
    const colibri = b.dependency("colibri", .{ .target = target });
    const quic = cocuyo.module("cocuyo_quic");
    quic.addImport("quic", colibri.module("quic"));
    const session = cocuyo.module("chapulin_quic");
    session.addImport("quic", colibri.module("quic"));
    session.addImport("tls", colibri.module("tls"));
    const doq = b.addExecutable(.{
        .name = "doq",
        .root_module = b.createModule(.{
            .root_source_file = b.path("doq.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    doq.root_module.addImport("rotor", rotor);
    doq.root_module.addImport("cocuyo", cocuyo.module("cocuyo"));
    doq.root_module.addImport("cocuyo_rotor", resolver);
    doq.root_module.addImport("cocuyo_quic", quic);
    doq.root_module.addImport("chapulin_quic", session);
    b.installArtifact(doq);

    // The same colibri, bound where a consumer that speaks DoT binds it: its `tls` and
    // `tls_provider` into the DoT session. The session's `io` is `cocuyo_rotor`, into which this
    // package bound its rotor above.
    const tls_session = cocuyo.module("chapulin");
    tls_session.addImport("tls", colibri.module("tls"));
    tls_session.addImport("tls_provider", colibri.module("tls_provider"));
    const dot = b.addExecutable(.{
        .name = "dot",
        .root_module = b.createModule(.{
            .root_source_file = b.path("dot.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    dot.root_module.addImport("rotor", rotor);
    dot.root_module.addImport("cocuyo", cocuyo.module("cocuyo"));
    dot.root_module.addImport("cocuyo_rotor", resolver);
    dot.root_module.addImport("chapulin", tls_session);
    b.installArtifact(dot);
}
