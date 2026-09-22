//! markdown: every Markdown file renders on GitHub as written (CLAUDE.md, Conventions). Four
//! checks, each one a way GitHub renders something other than what the writer meant: a bare `3b.`
//! or `0a.` line, which GitHub folds into the paragraph above; a fenced code block opened with no
//! language; a table row whose column count disagrees with its header, which drops a cell; and
//! trailing whitespace, which is a line break nobody typed.
//!
//! The rule reads every `.md` file it is given, so build.zig passes `docs/` and also README.md and
//! CLAUDE.md, which render on GitHub the same way.
//!
//! The rule is pepegrillo's `markdown`. This file holds cocuyo's configuration of it and the
//! fixtures that pin that configuration.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const markdown = lint.rules.markdown;

pub const config: markdown.Config = .{
    .scope = .{ .extensions = &.{".md"} },
    .pseudo_list_item = true,
    .pseudo_list_letters = .any,
    .pseudo_list_column = .first,
    .fence_language = true,
    .table_columns = true,
    .trailing_whitespace = true,
    .messages = .{
        .pseudo_list_item = "bare \"{[marker]s}\" folds into the paragraph above on GitHub;" ++
            " nest it as a list item",
        .fence_language = "fenced code block opened with no language",
        .table_columns = "table row holds {[columns]d} columns; its header holds {[header_columns]d}",
        .trailing_whitespace = "trailing whitespace",
    },
};

const Rule = markdown.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

test "markdown flags a fence with no language" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "docs/design.md",
        \\# cocuyo
        \\
        \\```
        \\code
        \\```
        \\
    );
    try harness.expect_messages(findings, &.{"fenced code block opened with no language"});
}

test "markdown reads README.md and CLAUDE.md as well as docs" {
    try testing.expect(config.scope.applies("README.md"));
    try testing.expect(config.scope.applies("CLAUDE.md"));
    try testing.expect(config.scope.applies("docs/design.md"));
    try testing.expect(!config.scope.applies("src/wire/wire.zig"));
}
