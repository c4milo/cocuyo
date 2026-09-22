//! determinism: time is a value the caller passes and entropy is a seed the caller supplies
//! (CLAUDE.md non-negotiable 4). One seed replays byte-identically across hosts and build modes,
//! which holds only while a lookup's output is a pure function of its configuration, the bytes it
//! was fed, the instants it was given and its seed.
//!
//! Over every `.zig` file under `src/`, the rule flags a chain that starts with `std.time` or
//! `std.Random` at a dot boundary. The transaction id, the source-port hint and the 0x20 case
//! pattern all come from a generator seeded by the caller (docs/design.md §7), so a file that
//! names a global random source has taken that decision away from the caller — and a file that
//! names a clock has taken back one of the `now_ns` parameters.
//!
//! The list held `std.crypto.random` until 2026-09-22, when reading the standard library showed
//! Zig 0.16 has no such declaration: `std/crypto.zig` has no `random` at all, and no global
//! CSPRNG replaced it. The entry guarded nothing, and an entry that guards nothing reads like
//! cover. System entropy in 0.16 is reached through `std.Io` or `std.posix`, which the io rule
//! forbids under `src/` already, so dropping it loses no coverage.
//!
//! `std.time` is flagged whole, its unit constants included: `std.time.ns_per_s` reads no clock,
//! but a duration cocuyo uses is a named limit in a module's `constants.zig` (non-negotiable 5),
//! and that file spells the duration out as a literal with the arithmetic in its doc comment. The
//! magic-numbers rule exempts `constants.zig` for exactly that reason.
//!
//! What the rule cannot see: a clock reached through a parameter, `now_ns`. That is the shape
//! cocuyo wants, and the rule cannot tell it from any other caller-supplied integer. It reads what
//! a file under `src/` names in `std`, which is where a clock would have to come from.
//!
//! The rule is pepegrillo's `forbidden_references`. This file holds cocuyo's configuration of it
//! and the fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const forbidden_references = lint.rules.forbidden_references;

/// A chain that starts with either of these at a dot boundary is a finding: the clock, and the
/// pseudo-random generators. The system entropy source is the io rule's, because in Zig 0.16 it
/// is reached through `std.Io` and `std.posix`.
const forbidden_prefixes = [_][]const u8{ "std.time", "std.Random" };

// A name that has moved or gone leaves the rule holding it checking nothing, and a clean tree
// cannot say which: it passes either way. This fails the build instead, naming the entry. Two of
// these lists held such a name until 2026-09-22 — `std.crypto.random`, which Zig 0.16 does not
// have, and `std.net`, which moved under `std.Io`.
comptime {
    lint.names.assert_all_resolve(std, "std", &forbidden_prefixes);
}

const reason = "time is a caller-supplied parameter and entropy is a caller-supplied seed" ++
    " (non-negotiable 4)";

pub const config: forbidden_references.Config = .{
    .name = "determinism",
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

test "determinism flags the clock and both random sources" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/resolver/lookup.zig",
        \\const std = @import("std");
        \\pub fn identifier() u16 {
        \\    _ = std.time.nanoTimestamp();
        \\    return std.Random.int(u16);
        \\}
        \\
    );
    try harness.expect_messages(findings, &.{
        "reference to std.time.nanoTimestamp: " ++ reason,
        "reference to std.Random.int: " ++ reason,
    });
}

test "determinism flags a unit constant too, because a duration is a named limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/core/constants.zig",
        \\const std = @import("std");
        \\pub const timeout_ns_default = 5 * std.time.ns_per_s;
        \\
    );
    try harness.expect_messages(findings, &.{"reference to std.time.ns_per_s: " ++ reason});
}
