//! The coverage report (`zig build coverage`, build/coverage.zig): reads the merged
//! `cobertura.xml` kcov wrote over every module's unit tests, and writes a table of line coverage
//! for each part of the tree, the files with the most lines left unrun, and the README's badge.
//!
//! Tests live in the files they test (CLAUDE.md, Conventions), so kcov counts their lines too, and
//! they always run. The report leaves them out: a file named `*_test.zig` is test code, and so is
//! every line from a file's `// Tests` marker on, and every top-level `test` block before it.
//! `src/sim/`, the deterministic twin of rotor that the engine's tests run on, is test machinery:
//! it has a row of its own and stays out of the total.
//!
//! A line counts when the compiler emitted code for it. Zig compiles a function only when
//! something references it, so a function nothing references has no lines here at all: it is
//! neither covered nor uncovered.
//!
//! Usage: `coverage <cobertura.xml> <repo root> <out dir>`, which writes `coverage.md` and
//! `coverage.svg` into the out dir and prints the total. It exits 1 when the total is under
//! `floor_percent`, or when a part of the tree counted no line, which is a report whose paths
//! missed the tree.
const std = @import("std");
const assert = std.debug.assert;

/// The parts of the tree the table has a row for, in the order it lists them.
pub const areas = [_][]const u8{ "src/core", "src/wire", "src/resolver", "src/config", "src/cache", "io", "src/sim" };
/// The one area that is not the library or the engine, and stays out of the total.
const machinery = "src/sim";
/// The files the table lists under the total: those with the most lines left unrun.
const files_listed = 12;
const file_bytes_max: std.Io.Limit = .limited(1 << 24);
const percent_scale = 100;
/// The least share of the library's and the engine's lines the tests may run, in percent. Set on
/// 2026-09-26, when CI measured 97.5% of 6,807 lines on x86_64 Linux and a container measured
/// 96.9% on arm64 Linux: kcov reads each architecture's line tables, which differ by some forty
/// lines, so the floor sits under the lower figure by some thirty. A change that takes tests away
/// fails the report, and one that adds them may raise the floor.
pub const floor_percent: f64 = 96.5;

pub const Line = struct { number: u32, covered: bool };

pub const Tally = struct {
    covered: usize = 0,
    total: usize = 0,

    pub fn add(self: *Tally, other: Tally) void {
        self.covered += other.covered;
        self.total += other.total;
    }

    pub fn percent(self: Tally) f64 {
        if (self.total == 0) return percent_scale;
        return @as(f64, @floatFromInt(self.covered)) * percent_scale / @as(f64, @floatFromInt(self.total));
    }
};

/// What kcov recorded for one source file: its path as the compiler wrote it, and its lines.
pub const File = struct {
    path: []const u8,
    lines: std.ArrayList(Line) = .empty,
};

/// Reads kcov's `cobertura.xml`: a `<source>` prefix, then a `<class>` for each file, whose
/// `filename` is relative to it, holding a `<line number="N" hits="H"/>` for each line with code.
pub fn read_cobertura(arena: std.mem.Allocator, xml: []const u8) ![]File {
    var files: std.ArrayList(File) = .empty;
    var source: []const u8 = "";
    var lines = std.mem.splitScalar(u8, xml, '\n');
    for (0..xml.len + 1) |_| {
        const text = std.mem.trim(u8, lines.next() orelse break, " \t\r");
        if (between(text, "<source>", "</source>")) |prefix| {
            source = prefix;
        } else if (std.mem.startsWith(u8, text, "<class ")) {
            const name = attribute(text, "filename") orelse return error.MalformedReport;
            try files.append(arena, .{ .path = try std.fs.path.join(arena, &.{ source, name }) });
        } else if (std.mem.startsWith(u8, text, "<line ")) {
            if (files.items.len == 0) return error.MalformedReport;
            const number = try std.fmt.parseInt(u32, attribute(text, "number") orelse return error.MalformedReport, 10);
            const hits = try std.fmt.parseInt(u64, attribute(text, "hits") orelse return error.MalformedReport, 10);
            try files.items[files.items.len - 1].lines.append(arena, .{ .number = number, .covered = hits > 0 });
        }
    }
    return files.items;
}

fn between(text: []const u8, open: []const u8, close: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, text, open) or !std.mem.endsWith(u8, text, close)) return null;
    return text[open.len .. text.len - close.len];
}

/// The value of `name="..."` in one XML tag.
fn attribute(tag: []const u8, name: []const u8) ?[]const u8 {
    var key_buffer: [32]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buffer, " {s}=\"", .{name}) catch return null;
    const start = (std.mem.indexOf(u8, tag, key) orelse return null) + key.len;
    const end = std.mem.indexOfScalarPos(u8, tag, start, '"') orelse return null;
    return tag[start..end];
}

/// Which lines of `source` are test code, by the rules the header gives; true at an index means
/// line index + 1 is.
pub fn test_lines(arena: std.mem.Allocator, path: []const u8, source: []const u8) ![]bool {
    const count = std.mem.count(u8, source, "\n") + 1;
    const mask = try arena.alloc(bool, count);
    @memset(mask, std.mem.endsWith(u8, path, "_test.zig"));
    var lines = std.mem.splitScalar(u8, source, '\n');
    var in_test = false;
    var after_marker = false;
    for (mask) |*line_is_test| {
        const line = lines.next() orelse break;
        if (std.mem.startsWith(u8, line, "// Tests")) after_marker = true;
        if (std.mem.startsWith(u8, line, "test ")) in_test = true;
        line_is_test.* = line_is_test.* or after_marker or in_test;
        if (in_test and std.mem.eql(u8, std.mem.trimEnd(u8, line, "\r"), "}")) in_test = false;
    }
    return mask;
}

/// A file's covered and total lines, test code left out.
pub fn tally_file(lines: []const Line, mask: []const bool) Tally {
    var tally: Tally = .{};
    for (lines) |line| {
        if (line.number == 0 or line.number > mask.len or mask[line.number - 1]) continue;
        tally.total += 1;
        if (line.covered) tally.covered += 1;
    }
    return tally;
}

/// The area a repository path belongs to, or null for one outside every area.
pub fn area_of(relative: []const u8) ?usize {
    for (areas, 0..) |area, index| {
        if (std.mem.startsWith(u8, relative, area) and relative.len > area.len and relative[area.len] == '/') return index;
    }
    return null;
}

/// The library's and the engine's total, the twin left out. An area with no line counted is a
/// report whose paths missed the tree, `<source>` leading somewhere else, and not an area that
/// all ran: every area has code its tests reach. So it is refused rather than read as 100%.
pub fn library_total(by_area: []const Tally) error{AreaUnread}!Tally {
    assert(by_area.len == areas.len);
    var total: Tally = .{};
    for (areas, by_area) |area, tally| {
        if (tally.total == 0) return error.AreaUnread;
        if (!std.mem.eql(u8, area, machinery)) total.add(tally);
    }
    assert(total.total > 0);
    return total;
}

/// Whether `total` runs a smaller share of its lines than `floor`, in percent.
pub fn below_floor(total: Tally, floor: f64) bool {
    assert(total.total > 0);
    return total.percent() < floor;
}

const Row = struct { path: []const u8, tally: Tally };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 4) {
        std.debug.print("usage: coverage <cobertura.xml> <repo root> <out dir>\n", .{});
        std.process.exit(2);
    }
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    const files = try read_cobertura(arena, try cwd.readFileAlloc(io, args[1], arena, file_bytes_max));
    const root = std.mem.trimEnd(u8, args[2], "/");
    var by_area: [areas.len]Tally = @splat(.{});
    var rows: std.ArrayList(Row) = .empty;
    for (files) |file| {
        if (!std.mem.startsWith(u8, file.path, root)) continue;
        const relative = std.mem.trimStart(u8, file.path[root.len..], "/");
        const area = area_of(relative) orelse continue;
        const source = try cwd.readFileAlloc(io, file.path, arena, file_bytes_max);
        const tally = tally_file(file.lines.items, try test_lines(arena, relative, source));
        by_area[area].add(tally);
        const counted = !std.mem.eql(u8, areas[area], machinery);
        if (counted and tally.total > 0) try rows.append(arena, .{ .path = relative, .tally = tally });
    }
    const total = library_total(&by_area) catch {
        for (areas, by_area) |area, tally| std.debug.print("coverage: {s}: {d} lines\n", .{ area, tally.total });
        std.debug.print("coverage: kcov recorded no line of an area under {s}: its paths do not lead into the tree\n", .{root});
        std.process.exit(1);
    };
    var markdown: std.Io.Writer.Allocating = .init(arena);
    try write_markdown(&markdown.writer, &by_area, total, rows.items);
    var badge: std.Io.Writer.Allocating = .init(arena);
    try write_badge(&badge.writer, total.percent());
    try cwd.createDirPath(io, args[3]);
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ args[3], "coverage.md" }), .data = markdown.written() });
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ args[3], "coverage.svg" }), .data = badge.written() });
    std.debug.print("coverage: {d:.1}% of {d} lines of the library and the engine, tests left out\n", .{ total.percent(), total.total });
    // The table goes with the refusal: a step that fails installs nothing, and it says which
    // files lost their lines.
    if (below_floor(total, floor_percent)) {
        std.debug.print("{s}coverage: {d:.1}% is under the floor of {d:.1}%\n", .{ markdown.written(), total.percent(), floor_percent });
        std.process.exit(1);
    }
}

fn write_markdown(writer: *std.Io.Writer, by_area: []const Tally, total: Tally, rows: []Row) !void {
    try writer.writeAll("## Line coverage\n\n| Part | Lines run | Lines | Coverage |\n| --- | --- | --- | --- |\n");
    for (areas, by_area) |area, tally| {
        const note: []const u8 = if (std.mem.eql(u8, area, machinery)) " (test machinery, not in the total)" else "";
        try writer.print("| `{s}`{s} | {d} | {d} | {d:.1}% |\n", .{ area, note, tally.covered, tally.total, tally.percent() });
    }
    try writer.print("| The library and the engine | {d} | {d} | {d:.1}% |\n\n", .{ total.covered, total.total, total.percent() });
    std.mem.sort(Row, rows, {}, most_unrun_first);
    try writer.writeAll("The files with the most lines left unrun:\n\n| File | Lines unrun | Coverage |\n| --- | --- | --- |\n");
    for (rows[0..@min(files_listed, rows.len)]) |row| {
        try writer.print("| `{s}` | {d} | {d:.1}% |\n", .{ row.path, row.tally.total - row.tally.covered, row.tally.percent() });
    }
    try writer.writeAll("\nTest code is left out, and a function nothing references has no lines to count (tools/coverage.zig).\n");
}

fn most_unrun_first(_: void, left: Row, right: Row) bool {
    return left.tally.total - left.tally.covered > right.tally.total - right.tally.covered;
}

/// A flat badge, as chapulin draws its own: grey label, and a value green at 90% or more, yellow
/// above 75%, and red at 75% or less.
pub fn write_badge(writer: *std.Io.Writer, percent: f64) !void {
    const color = if (percent >= 90) "#4c1" else if (percent > 75) "#dfb317" else "#e05d44";
    const label_width = 61;
    const value_width = 46;
    try writer.print(
        \\<svg xmlns="http://www.w3.org/2000/svg" width="{[width]d}" height="20" role="img" aria-label="coverage: {[percent]d:.1}%">
        \\  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
        \\  <clipPath id="r"><rect width="{[width]d}" height="20" rx="3" fill="#fff"/></clipPath>
        \\  <g clip-path="url(#r)">
        \\    <rect width="{[label]d}" height="20" fill="#555"/>
        \\    <rect x="{[label]d}" width="{[value]d}" height="20" fill="{[color]s}"/>
        \\    <rect width="{[width]d}" height="20" fill="url(#s)"/>
        \\  </g>
        \\  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
        \\    <text x="{[label_middle]d}" y="14">coverage</text>
        \\    <text x="{[value_middle]d}" y="14">{[percent]d:.1}%</text>
        \\  </g>
        \\</svg>
        \\
    , .{
        .width = label_width + value_width,
        .label = label_width,
        .value = value_width,
        .color = color,
        .percent = percent,
        .label_middle = label_width / 2,
        .value_middle = label_width + value_width / 2,
    });
}

// Tests.

const testing = std.testing;

test "kcov's report reads into files and lines, each path joined to its source" {
    const xml =
        \\<?xml version="1.0" ?>
        \\<coverage line-rate="0.5">
        \\ <sources>
        \\  <source>/repo/src/core/</source>
        \\ </sources>
        \\ <packages><package name="core_tests"><classes>
        \\    <class name="a_zig" filename="a.zig" line-rate="0.5">
        \\     <lines>
        \\      <line number="3" hits="2"/>
        \\      <line number="4" hits="0"/>
        \\     </lines>
        \\    </class>
        \\ </classes></package></packages>
        \\</coverage>
    ;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const files = try read_cobertura(arena_state.allocator(), xml);
    try testing.expectEqual(@as(usize, 1), files.len);
    try testing.expectEqualStrings("/repo/src/core/a.zig", files[0].path);
    try testing.expectEqual(@as(usize, 2), files[0].lines.items.len);
    try testing.expect(files[0].lines.items[0].covered and !files[0].lines.items[1].covered);
}

test "test code is left out: a test file, a test block, and everything from the marker on" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const source = "fn a() void {}\ntest \"x\" {\n    a();\n}\nfn b() void {}\n// Tests.\nfn helper() void {}\n";
    const mask = try test_lines(arena, "src/core/a.zig", source);
    try testing.expectEqualSlices(bool, &.{ false, true, true, true, false, true, true, true }, mask);
    const whole = try test_lines(arena, "src/core/a_test.zig", "fn a() void {}\n");
    try testing.expect(whole[0]);
    const lines = [_]Line{ .{ .number = 1, .covered = true }, .{ .number = 3, .covered = true }, .{ .number = 5, .covered = false } };
    const tally = tally_file(&lines, mask);
    try testing.expectEqual(Tally{ .covered = 1, .total = 2 }, tally);
}

test "a path falls in its area, and the twin's lines stay out of the total" {
    try testing.expectEqual(@as(?usize, 0), area_of("src/core/name.zig"));
    try testing.expectEqual(@as(?usize, 5), area_of("io/io.zig"));
    try testing.expectEqual(@as(?usize, null), area_of("tools/fuzz.zig"));
    try testing.expectEqual(@as(?usize, null), area_of("src/corex/a.zig"));
    try testing.expectEqualStrings(machinery, areas[area_of("src/sim/sim.zig").?]);
}

test "the total leaves the twin out, and an area with no line counted is refused, not 100%" {
    var by_area: [areas.len]Tally = @splat(.{ .covered = 1, .total = 2 });
    by_area[area_of("src/sim/sim.zig").?] = .{ .covered = 0, .total = 50 };
    const total = try library_total(&by_area);
    try testing.expectEqual(Tally{ .covered = areas.len - 1, .total = 2 * (areas.len - 1) }, total);
    by_area[area_of("io/io.zig").?] = .{};
    try testing.expectError(error.AreaUnread, library_total(&by_area));
}

test "a total under the floor is refused, and one at the floor is not" {
    try testing.expect(below_floor(.{ .covered = 964, .total = 1000 }, 96.5));
    try testing.expect(!below_floor(.{ .covered = 965, .total = 1000 }, 96.5));
    try testing.expect(!below_floor(.{ .covered = 1000, .total = 1000 }, floor_percent));
}

test "the badge says the figure, in the colour of its band" {
    var badge: std.Io.Writer.Allocating = .init(testing.allocator);
    defer badge.deinit();
    try write_badge(&badge.writer, 91.24);
    try testing.expect(std.mem.indexOf(u8, badge.written(), ">91.2%<") != null);
    try testing.expect(std.mem.indexOf(u8, badge.written(), "#4c1") != null);
}
