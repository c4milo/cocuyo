//! That the lint reads every tracked file it has a rule for (c4milo/cocuyo#12). `zig build lint`
//! walks the directories build.zig lists, and a clean tree passes whether or not a directory is on
//! the list: a directory dropped from it, or a new directory of code that never joined it, holds
//! no violation anyone looks for. This reads the tracked files, as `git ls-files` names them, and
//! fails on each one the lint would never read.
//!
//!     lint_coverage --rules <dir>... --rule-files <file>... --score <dir>... --score-files <file>...
//!         --exempt <prefix>...
//!
//! It runs in the build root. The rules read `rule_extensions`, under `--rules` and in
//! `--rule-files`; the complexity score reads `.zig`, under `--score` and in `--score-files`. A path
//! that starts with an `--exempt` prefix is read by neither, on purpose.
const std = @import("std");

/// What the rules of tools/lint read, by extension: the Zig the code rules score, the scripts and
/// the models the file-length rule bounds, and the Markdown the markdown rule reads.
pub const rule_extensions = [_][]const u8{ ".zig", ".sh", ".lean", ".tla", ".md" };
/// What the complexity score reads.
pub const score_extensions = [_][]const u8{".zig"};

/// Where a check reads: the directories it walks, the files it is handed, and what it reads there.
pub const Reach = struct {
    directories: []const []const u8,
    files: []const []const u8,
    extensions: []const []const u8,
};

/// Whether `path`, a tracked file, is one `reach` should read and does not: its extension is one
/// the check reads, it lies under none of the check's directories, it is none of its files, and it
/// is exempt by no prefix.
pub fn unread(path: []const u8, reach: Reach, exempt: []const []const u8) bool {
    if (!has_extension(path, reach.extensions)) return false;
    for (exempt) |prefix| if (std.mem.startsWith(u8, path, prefix)) return false;
    for (reach.files) |file| if (std.mem.eql(u8, path, file)) return false;
    for (reach.directories) |directory| if (under(path, directory)) return false;
    return true;
}

fn has_extension(path: []const u8, extensions: []const []const u8) bool {
    for (extensions) |extension| if (std.mem.endsWith(u8, path, extension)) return true;
    return false;
}

/// Whether `path` lies under `directory`, a path relative to the root with no trailing slash.
fn under(path: []const u8, directory: []const u8) bool {
    return path.len > directory.len and std.mem.startsWith(u8, path, directory) and path[directory.len] == '/';
}

/// The lists the build hands over, each flag starting one.
const Lists = struct {
    rules: std.ArrayList([]const u8) = .empty,
    rule_files: std.ArrayList([]const u8) = .empty,
    score: std.ArrayList([]const u8) = .empty,
    score_files: std.ArrayList([]const u8) = .empty,
    exempt: std.ArrayList([]const u8) = .empty,
};

fn parse(allocator: std.mem.Allocator, arguments: []const []const u8) !Lists {
    var lists: Lists = .{};
    var into: ?*std.ArrayList([]const u8) = null;
    for (arguments) |argument| {
        if (list_of(&lists, argument)) |list| {
            into = list;
            continue;
        }
        const list = into orelse return error.UsageNoFlag;
        try list.append(allocator, argument);
    }
    return lists;
}

fn list_of(lists: *Lists, flag: []const u8) ?*std.ArrayList([]const u8) {
    if (std.mem.eql(u8, flag, "--rules")) return &lists.rules;
    if (std.mem.eql(u8, flag, "--rule-files")) return &lists.rule_files;
    if (std.mem.eql(u8, flag, "--score")) return &lists.score;
    if (std.mem.eql(u8, flag, "--score-files")) return &lists.score_files;
    if (std.mem.eql(u8, flag, "--exempt")) return &lists.exempt;
    return null;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    const lists = try parse(arena, arguments[1..]);
    const rules: Reach = .{ .directories = lists.rules.items, .files = lists.rule_files.items, .extensions = &rule_extensions };
    const score: Reach = .{ .directories = lists.score.items, .files = lists.score_files.items, .extensions = &score_extensions };
    const tracked = try std.process.run(arena, init.io, .{ .argv = &.{ "git", "ls-files", "-z" } });
    if (tracked.term != .exited or tracked.term.exited != 0) {
        std.debug.print("lint-coverage: `git ls-files` failed; the check reads the tracked files\n", .{});
        std.process.exit(1);
    }
    var unread_count: usize = 0;
    var paths = std.mem.splitScalar(u8, tracked.stdout, 0);
    while (paths.next()) |path| {
        if (path.len == 0) continue;
        if (unread(path, rules, lists.exempt.items)) {
            std.debug.print("{s}: no tools/lint rule reads it; add its directory to lint_rule_directories in build.zig, or exempt it\n", .{path});
            unread_count += 1;
        }
        if (unread(path, score, lists.exempt.items)) {
            std.debug.print("{s}: the complexity score reads no file there; add its directory to source_directories in build.zig\n", .{path});
            unread_count += 1;
        }
    }
    if (unread_count > 0) std.process.exit(1);
    std.debug.print("lint-coverage: every tracked file a check reads is read\n", .{});
}

// Tests.

const testing = std.testing;

const reach_test: Reach = .{
    .directories = &.{ "src", "docs" },
    .files = &.{ "README.md", "build.zig" },
    .extensions = &rule_extensions,
};

test "a file under a walked directory, or handed over by name, is read" {
    try testing.expect(!unread("src/core/core.zig", reach_test, &.{}));
    try testing.expect(!unread("docs/design.md", reach_test, &.{}));
    try testing.expect(!unread("README.md", reach_test, &.{}));
    try testing.expect(!unread("build.zig", reach_test, &.{}));
}

test "a file of a read extension under no walked directory is unread" {
    // `spec/` dropped from the list: the models it holds go unread.
    try testing.expect(unread("spec/lean/Spec/LookupProofs.lean", reach_test, &.{}));
    try testing.expect(unread("tools/lint/main.zig", reach_test, &.{}));
    // A directory whose name only starts like a walked one is not under it.
    try testing.expect(unread("srcs/a.zig", reach_test, &.{}));
    try testing.expect(unread("CLAUDE.md", reach_test, &.{}));
}

test "a file no check reads by its extension, or exempt by its prefix, is not unread" {
    try testing.expect(!unread(".github/workflows/ci.yml", reach_test, &.{}));
    try testing.expect(!unread("LICENSE", reach_test, &.{}));
    try testing.expect(!unread("test/consumer/main.zig", reach_test, &.{"test/"}));
}

test "the lists are read flag by flag, and an argument before any flag is refused" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const lists = try parse(arena.allocator(), &.{ "--rules", "src", "docs", "--rule-files", "README.md", "--exempt", "test/" });
    try testing.expectEqual(@as(usize, 2), lists.rules.items.len);
    try testing.expectEqualStrings("README.md", lists.rule_files.items[0]);
    try testing.expectEqualStrings("test/", lists.exempt.items[0]);
    try testing.expectError(error.UsageNoFlag, parse(arena.allocator(), &.{"src"}));
}
