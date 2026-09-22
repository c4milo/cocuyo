//! io: cocuyo owns no I/O (CLAUDE.md non-negotiable 1). No socket, no file descriptor, no poll, no
//! thread, no timer. Queries are written into storage the caller owns and responses are parsed out
//! of bytes the caller has already read, so every function that would block returns a value naming
//! the I/O it wants instead.
//!
//! Over every `.zig` file under `src/`, the rule flags a chain that starts with one of
//! `forbidden_prefixes` at a dot boundary. Nothing under `src/` is exempt: `examples/` is where a
//! socket is allowed to appear, and it is not part of the library.
//!
//! The rule reads what a file names, not what it reaches. This is what stops a file under `src/`
//! reaching the host through `std` directly; the module graph is what bounds the rest.
//!
//! The list held `std.net` until 2026-09-22, when reading the standard library showed Zig 0.16
//! has no such declaration: the network moved to `std.Io.net`. The entry guarded nothing, and
//! what covered the network was `std.Io` happening to be a prefix of where it went. That is luck,
//! and luck that would not have held had it moved anywhere else, so the name below says where the
//! network actually is.
//!
//! The rule is pepegrillo's `forbidden_references`. This file holds cocuyo's configuration of it
//! and the fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const forbidden_references = lint.rules.forbidden_references;

/// A chain that starts with one of these at a dot boundary is a finding. Each names a way to reach
/// the host: the syscall surface, the filesystem, threads, the `std.Io` interface every blocking
/// call now takes — the network among them, at `std.Io.net` — and the process table.
const forbidden_prefixes = [_][]const u8{
    "std.posix",
    "std.fs",
    "std.Thread",
    "std.Io",
    "std.process",
};

const reason = "cocuyo owns no socket and makes no syscall; the caller does the I/O" ++
    " (non-negotiable 1)";

pub const config: forbidden_references.Config = .{
    .name = "io",
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{"src"} },
    .prefixes = &forbidden_prefixes,
    .reason = reason,
};

const Rule = forbidden_references.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

test "io flags every way of reaching the host" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/resolver/resolver.zig",
        \\const std = @import("std");
        \\pub fn send() void {
        \\    _ = std.posix.socket;
        \\    _ = std.Io.net.Address;
        \\    _ = std.Io.Reader;
        \\}
        \\
    );
    try harness.expect_messages(findings, &.{
        "reference to std.posix.socket: " ++ reason,
        "reference to std.Io.net.Address: " ++ reason,
        "reference to std.Io.Reader: " ++ reason,
    });
}

test "io leaves the examples alone, because that is where a socket belongs" {
    try testing.expect(!config.scope.applies("examples/udp_blocking.zig"));
    try testing.expect(config.scope.applies("src/resolver/resolver.zig"));
}
