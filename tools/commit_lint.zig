//! Commit-message linter for the Conventional Commit rules of CLAUDE.md (Commits). It reads commit
//! messages out of git, or one message from a file, and prints one line per finding; it changes
//! nothing.
//!
//! Run:  zig build lint-commits            # the commits this branch adds to origin/main
//!       zig-out/bin/commit_lint --range REV [REV...]
//!       zig-out/bin/commit_lint --message PATH
//!
//! The linter is pepegrillo's. This file holds cocuyo's configuration of it: the module scopes of
//! docs/design.md §2, and the first words refused as not imperative. The limits are the ones
//! CLAUDE.md states, which are pepegrillo's defaults.
//!
//! Exit status: 0 when no rule was violated, warnings included; 1 when any rule was violated; 2 on
//! a usage error, an unreadable message file, or a git log that failed. .githooks/pre-push reads
//! the difference.
const std = @import("std");
const pepegrillo = @import("pepegrillo");

/// The scopes CLAUDE.md names: one per module of docs/design.md §2, plus the two directories that
/// carry code and are not modules.
pub const module_scopes = [_][]const u8{
    "core", "wire", "resolver", "config", "sim", "bench", "examples",
};

/// First words that describe the commit instead of commanding it.
const third_person_forms = [_][]const u8{
    "adds",    "fixes", "updates", "removes", "implements", "splits",
    "renames", "moves", "makes",   "drops",   "lands",      "keeps",
};

/// Commands whose spelling ends in `ed` or `ing` all the same. The suffix test reads the last two
/// or three bytes of a word, not its grammar, so without this list it refuses `bring the hook
/// back` and `seed the corpus`.
const imperative_exceptions = [_][]const u8{
    "bring",  "embed", "seed", "speed", "feed", "exceed", "proceed", "succeed", "shed", "ring",
    "string",
};

pub const config: pepegrillo.commit.Config = .{
    .scope_admits_digits = false,
    .known_scopes = &module_scopes,
    .unknown_scope_reason = "is not a module of the graph",
    .third_person_forms = &third_person_forms,
    .imperative_exceptions = &imperative_exceptions,
};

pub fn main(init: std.process.Init) !void {
    return pepegrillo.commit.main(init, config);
}

// Tests. pepegrillo tests the rules; these pin cocuyo's configuration of them.

const testing = std.testing;
const commit = pepegrillo.commit;

/// Lints `text` under cocuyo's configuration and checks each finding, in order, as
/// `severity: rule: message`.
fn expect_findings(text: []const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: commit.Findings = .{ .arena = arena, .max_findings = config.max_findings };
    try commit.lint_message_text(arena, config, &findings, "message", text);
    try testing.expectEqual(expected.len, findings.items.items.len);
    for (findings.items.items, expected) |finding, wanted| {
        const line = try std.fmt.allocPrint(arena, "{s}: {s}: {s}", .{
            finding.severity.text(), finding.rule, finding.message,
        });
        try testing.expectEqualStrings(wanted, line);
    }
}

test "every scope CLAUDE.md names passes" {
    // Written out rather than read from `module_scopes`, so a scope dropped from that list fails.
    const scopes = [_][]const u8{
        "core", "wire", "resolver", "config", "sim", "bench", "examples",
    };
    try testing.expectEqual(scopes.len, module_scopes.len);
    for (scopes) |scope| {
        var buffer: [96]u8 = undefined;
        const text = try std.fmt.bufPrint(&buffer, "feat({s}): add the name decoder\n", .{scope});
        try expect_findings(text, &.{});
    }
}

test "a well-formed scope the graph does not name draws a warning" {
    try expect_findings("refactor(lookup): split the poll path\n", &.{
        "warning: scope-known: the scope \"lookup\" is not a module of the graph" ++
            " (core, wire, resolver, config, sim, bench, examples)",
    });
}

test "a third-person subject is refused" {
    try expect_findings("feat: adds the name decoder\n", &.{
        "violation: subject-description: \"adds\" is a third-person form, not imperative",
    });
}

test "a command whose spelling ends in ed passes" {
    try expect_findings("test(wire): seed the fuzz corpus\n", &.{});
}
