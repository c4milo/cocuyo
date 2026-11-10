//! every-field: consumer-shaped code passes every field of a `Config` and of the engine's
//! `Options` (docs/design.md §20, Every field). TigerStyle has a caller pass each option where it
//! calls. The owner ruled on 2026-11-10 that the two structs keep their defaults, for tests, and
//! that the README's blocks, the examples and the consumer fixture pass each field all the same.
//!
//! A struct with defaults compiles when a literal leaves a field out. So a field that joins
//! `Config` later would be missing from every example, and nothing would say so. This check reads
//! each literal its list names, and requires each field of the literal's type at the literal's own
//! depth. It counts the literals of each tracked file too: one more than the list names fails.
//!
//! `zig build every-field` runs it, and the gate runs it.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const engine = @import("cocuyo_rotor");

/// The type a literal builds.
const Kind = enum { config, options };

/// One literal of consumer-shaped code: its file, and the text that opens it, up to its brace.
const Site = struct { file: []const u8, opens: []const u8, kind: Kind };

const config_opens = "const config: cocuyo.Config = .{";
const options_opens_io = "const Resolver = io.Resolver(.{";
const options_opens_dns = "const Resolver = dns.Resolver(.{";

/// Each literal the check reads. A program that builds one more joins here by hand.
const sites = [_]Site{
    .{ .file = "README.md", .opens = options_opens_dns, .kind = .options },
    .{ .file = "examples/cleartext_rotor.zig", .opens = options_opens_io, .kind = .options },
    .{ .file = "examples/cleartext_rotor.zig", .opens = config_opens, .kind = .config },
    .{ .file = "examples/doh_rotor.zig", .opens = options_opens_io, .kind = .options },
    .{ .file = "examples/doh_rotor.zig", .opens = config_opens, .kind = .config },
    .{ .file = "examples/doq_rotor.zig", .opens = options_opens_io, .kind = .options },
    .{ .file = "examples/doq_rotor.zig", .opens = config_opens, .kind = .config },
    .{ .file = "examples/dot_rotor.zig", .opens = options_opens_io, .kind = .options },
    .{ .file = "examples/dot_rotor.zig", .opens = config_opens, .kind = .config },
    .{ .file = "examples/threads_rotor.zig", .opens = options_opens_io, .kind = .options },
    .{ .file = "examples/threads_rotor.zig", .opens = config_opens, .kind = .config },
    .{ .file = "test/consumer/doq.zig", .opens = options_opens_dns, .kind = .options },
    .{ .file = "test/consumer/doq.zig", .opens = config_opens, .kind = .config },
    .{ .file = "test/consumer/dot.zig", .opens = options_opens_dns, .kind = .options },
    .{ .file = "test/consumer/dot.zig", .opens = config_opens, .kind = .config },
    .{ .file = "test/consumer/embed.zig", .opens = options_opens_dns, .kind = .options },
    .{ .file = "test/consumer/embed.zig", .opens = config_opens, .kind = .config },
    .{ .file = "test/consumer/main.zig", .opens = config_opens, .kind = .config },
};

/// Whether a fault is printed as it is counted. The check prints each, and a test of the check
/// counts them and prints none.
const Report = enum {
    printed,
    counted,

    fn say(report: Report, comptime format: []const u8, arguments: anytype) void {
        if (report == .printed) std.debug.print(format, arguments);
    }
};

/// Where consumer-shaped code lives: what `git ls-files` is asked for.
const roots = [_][]const u8{ "README.md", "examples", "test/consumer" };

/// The largest file the check reads. The README is the largest, under 64 KiB.
const file_bytes_max: std.Io.Limit = .limited(1 << 20);

const config_fields = names_of(cocuyo.Config);
const options_fields = names_of(engine.Options);

/// The name of each field of `Struct`.
fn names_of(comptime Struct: type) [@typeInfo(Struct).@"struct".fields.len][]const u8 {
    const fields = @typeInfo(Struct).@"struct".fields;
    var names: [fields.len][]const u8 = undefined;
    for (fields, &names) |field, *name| name.* = field.name;
    return names;
}

fn fields_of(kind: Kind) []const []const u8 {
    return switch (kind) {
        .config => &config_fields,
        .options => &options_fields,
    };
}

/// The text each literal of a kind holds, whatever name it is given: what the count reads.
fn marker(kind: Kind) []const u8 {
    return switch (kind) {
        .config => "cocuyo.Config = .{",
        .options => "Resolver(.{",
    };
}

fn noun(kind: Kind) []const u8 {
    return switch (kind) {
        .config => "Config",
        .options => "Options",
    };
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    const tracked = try std.process.run(arena, init.io, .{ .argv = &(.{ "git", "ls-files", "-z", "--" } ++ roots) });
    if (tracked.term != .exited or tracked.term.exited != 0) {
        std.debug.print("every-field: `git ls-files` failed; the check reads the tracked files\n", .{});
        std.process.exit(1);
    }
    var faults: usize = 0;
    var paths = std.mem.splitScalar(u8, tracked.stdout, 0);
    while (paths.next()) |path| {
        if (!read_for_count(path)) continue;
        const text = try cwd.readFileAlloc(init.io, path, arena, file_bytes_max);
        faults += count_faults(path, try code_of(arena, text), .printed);
    }
    for (sites) |site| {
        const text = try cwd.readFileAlloc(init.io, site.file, arena, file_bytes_max);
        faults += site_faults(site, try code_of(arena, text), .printed);
    }
    if (faults > 0) std.process.exit(1);
    std.debug.print("every-field: {d} literals pass every field of their type\n", .{sites.len});
}

/// Whether the count reads the file: the README, and each Zig file under the roots.
fn read_for_count(path: []const u8) bool {
    if (path.len == 0) return false;
    return std.mem.eql(u8, path, "README.md") or std.mem.endsWith(u8, path, ".zig");
}

/// How many literals of each kind the file builds beyond, or short of, those the list names: one
/// fault for each kind that differs.
fn count_faults(path: []const u8, code: []const u8, report: Report) usize {
    var faults: usize = 0;
    for (std.enums.values(Kind)) |kind| {
        const built = std.mem.count(u8, code, marker(kind));
        const listed = listed_count(path, kind);
        if (built == listed) continue;
        report.say("{s}: builds {d} {s} and the list of tools/every_field.zig names {d}\n", .{ path, built, noun(kind), listed });
        faults += 1;
    }
    return faults;
}

fn listed_count(path: []const u8, kind: Kind) usize {
    var count: usize = 0;
    for (sites) |site| {
        if (site.kind == kind and std.mem.eql(u8, site.file, path)) count += 1;
    }
    assert(count <= sites.len);
    return count;
}

/// One fault for each field of the site's type that its literal does not pass, or one when the
/// literal is not there.
fn site_faults(site: Site, code: []const u8, report: Report) usize {
    const inside = literal(code, site.opens) orelse {
        report.say("{s}: no literal opens with `{s}`\n", .{ site.file, site.opens });
        return 1;
    };
    var faults: usize = 0;
    for (fields_of(site.kind)) |name| {
        if (passes(inside, name)) continue;
        report.say("{s}: its {s} does not pass `.{s}`\n", .{ site.file, noun(site.kind), name });
        faults += 1;
    }
    assert(faults <= fields_of(site.kind).len);
    return faults;
}

/// `text` with each line comment and each string turned to spaces, octet for octet. So a brace or
/// a field's name in one of them is no part of the code, and an offset still names the same place.
fn code_of(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    const code = try arena.alloc(u8, text.len);
    var state: State = .code;
    for (text, code, 0..) |octet, *kept, at| {
        kept.* = if (state == .code) octet else ' ';
        const next: u8 = if (at + 1 < text.len) text[at + 1] else '\n';
        state = state.after(octet, next);
    }
    assert(code.len == text.len);
    return code;
}

/// What the scan of a file is inside of.
const State = enum {
    code,
    comment,
    string,
    escape,

    /// The state after `octet`, which `next` follows. A string ends at its line's end at the latest,
    /// as Zig's does, so a quote in the README's prose hides no more than its line.
    fn after(state: State, octet: u8, next: u8) State {
        if (octet == '\n') return .code;
        return switch (state) {
            .code => if (octet == '"') .string else if (octet == '/' and next == '/') .comment else .code,
            .comment => .comment,
            .string => if (octet == '\\') .escape else if (octet == '"') .code else .string,
            .escape => .string,
        };
    }
};

/// The inside of the literal that `opens` starts, or null when the code holds none or does not end
/// it. `opens` ends at the literal's brace.
fn literal(code: []const u8, opens: []const u8) ?[]const u8 {
    assert(opens.len >= 1);
    assert(opens[opens.len - 1] == '{');
    const start = (std.mem.indexOf(u8, code, opens) orelse return null) + opens.len;
    var depth: usize = 1;
    for (code[start..], start..) |octet, at| {
        if (octet == '{') depth += 1;
        if (octet == '}') depth -= 1;
        if (depth == 0) return code[start..at];
    }
    return null;
}

/// Whether a literal passes the field: `.name =` at the literal's own depth, and in no literal
/// inside it. `inside` is what `literal` returned, so its braces close.
fn passes(inside: []const u8, name: []const u8) bool {
    assert(name.len >= 1);
    var depth: usize = 0;
    for (inside, 0..) |octet, at| {
        if (octet == '{') depth += 1;
        if (octet == '}') depth -= 1;
        if (depth == 0 and names_field(inside, at, name)) return true;
    }
    return false;
}

/// Whether a field's initializer for `name` starts at `at`: `.name =`, after a space, a line's
/// end, a comma, or the literal's own brace.
fn names_field(inside: []const u8, at: usize, name: []const u8) bool {
    assert(at < inside.len);
    if (inside[at] != '.') return false;
    if (at > 0 and std.mem.indexOfScalar(u8, " \n\t,", inside[at - 1]) == null) return false;
    const rest = inside[at + 1 ..];
    if (!std.mem.startsWith(u8, rest, name)) return false;
    return std.mem.startsWith(u8, rest[name.len..], " =");
}

// Tests.

const testing = std.testing;

/// The inside of the literal `opens` starts in `text`, as the check reads it.
fn inside_of(arena: std.mem.Allocator, text: []const u8, opens: []const u8) !?[]const u8 {
    return literal(try code_of(arena, text), opens);
}

test "a literal ends at the brace that closes it, whatever it holds inside" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = "const config: cocuyo.Config = .{ .servers = &.{ .{ .port = 53 } }, .rotate = false };\nconst after = .{ .ndots = 1 };";
    const inside = (try inside_of(arena, text, config_opens)).?;
    try testing.expectEqualStrings(" .servers = &.{ .{ .port = 53 } }, .rotate = false ", inside);
    try testing.expect((try inside_of(arena, "const other = 1;", config_opens)) == null);
    // A literal whose brace never closes is none.
    try testing.expect((try inside_of(arena, "const config: cocuyo.Config = .{ .rotate = false", config_opens)) == null);
}

test "a field counts at the literal's own depth, and in no literal inside it" {
    const inside = " .servers = &.{ .{ .port = 53, .rotate = true } }, .ndots = 1,\n    .timeout_ns_max = 5 ";
    try testing.expect(passes(inside, "servers"));
    try testing.expect(passes(inside, "ndots"));
    try testing.expect(passes(inside, "timeout_ns_max"));
    // Named one literal down, and so no field of this one.
    try testing.expect(!passes(inside, "port"));
    try testing.expect(!passes(inside, "rotate"));
    // A longer field's name holds this one, and is not it.
    try testing.expect(!passes(inside, "timeout_ns"));
    try testing.expect(!passes(inside, "ns_max"));
}

test "a field named in a comment or in a string is no field of the code" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = "const config: cocuyo.Config = .{\n    // .rotate = false, and a brace }\n    .ndots = 1, .name = \" .primary = true }\",\n};";
    const inside = (try inside_of(arena, text, config_opens)).?;
    try testing.expect(passes(inside, "ndots"));
    try testing.expect(passes(inside, "name"));
    try testing.expect(!passes(inside, "rotate"));
    try testing.expect(!passes(inside, "primary"));
}

test "a site whose literal leaves a field out has one fault for each, and a site with no literal has one" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const site: Site = .{ .file = "a test", .opens = config_opens, .kind = .config };
    const two = "const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };";
    try testing.expectEqual(config_fields.len - 2, site_faults(site, try code_of(arena, two), .counted));
    try testing.expectEqual(@as(usize, 1), site_faults(site, try code_of(arena, "const other = 1;"), .counted));
}

test "a file that builds a literal the list does not name has a fault, and a listed one has none" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const one = "const config: cocuyo.Config = .{};";
    try testing.expectEqual(@as(usize, 0), count_faults("test/consumer/main.zig", try code_of(arena, one), .counted));
    try testing.expectEqual(@as(usize, 1), count_faults("test/consumer/main.zig", try code_of(arena, one ++ "\n" ++ one), .counted));
    try testing.expectEqual(@as(usize, 1), count_faults("examples/not_listed.zig", try code_of(arena, one), .counted));
    // A literal in a comment is none.
    try testing.expectEqual(@as(usize, 0), count_faults("examples/not_listed.zig", try code_of(arena, "// " ++ one), .counted));
}

test "the list names each type's fields from the type itself" {
    try testing.expectEqual(@typeInfo(cocuyo.Config).@"struct".fields.len, config_fields.len);
    try testing.expectEqualStrings("servers", config_fields[0]);
    try testing.expectEqual(@typeInfo(engine.Options).@"struct".fields.len, options_fields.len);
    try testing.expectEqualStrings("lookups", options_fields[0]);
}
