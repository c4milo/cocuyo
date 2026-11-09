//! A mutation's edits, applied to the tree and taken back. `mutations.zig` applies them around each
//! check.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Edit = struct { file: []const u8, old: []const u8, new: []const u8 };

/// The bytes of one source file the tool edits.
const file_bytes_max: usize = 16 * 1024 * 1024;

/// Applies each edit, and returns each file's bytes as they were. Every file is put back before
/// an edit that cannot apply is reported.
pub fn apply(arena: Allocator, io: Io, dir: Io.Dir, edits: []const Edit) ![]const []const u8 {
    const originals = try arena.alloc([]const u8, edits.len);
    for (edits, 0..) |edit, index| {
        errdefer restore(io, dir, edits[0..index], originals[0..index]);
        originals[index] = try dir.readFileAlloc(io, edit.file, arena, .limited(file_bytes_max));
        if (std.mem.count(u8, originals[index], edit.old) != 1) return error.EditDoesNotApply;
        const edited = try std.mem.replaceOwned(u8, arena, originals[index], edit.old, edit.new);
        try dir.writeFile(io, .{ .sub_path = edit.file, .data = edited });
    }
    return originals;
}

/// Puts the files back, the last edited first, so a file two edits share ends as it began. Every
/// file is tried before a failure stops the program, so one that cannot be written leaves the
/// others back as they were.
pub fn restore(io: Io, dir: Io.Dir, edits: []const Edit, originals: []const []const u8) void {
    var failed: ?[]const u8 = null;
    var index = edits.len;
    while (index > 0) {
        index -= 1;
        dir.writeFile(io, .{ .sub_path = edits[index].file, .data = originals[index] }) catch {
            failed = edits[index].file;
        };
    }
    if (failed) |file| std.debug.panic("could not put {s} back; `git diff` shows what is left", .{file});
}

/// The files of a tree, read from `dir`, as `first_stale` reads them.
pub const Tree = struct {
    arena: Allocator,
    io: Io,
    dir: Io.Dir,

    pub fn read(tree: *const Tree, path: []const u8) ![]const u8 {
        return tree.dir.readFileAlloc(tree.io, path, tree.arena, .limited(file_bytes_max));
    }
};

/// The index of the first edit that `apply` would refuse, or null when every edit applies. Each
/// edit applies in memory to the bytes that the edits before it left, as `apply` writes them, so
/// nothing on disk changes. A file that `source` cannot find refuses its first edit.
pub fn first_stale(arena: Allocator, source: anytype, edits: []const Edit) !?usize {
    var files: std.StringHashMapUnmanaged([]const u8) = .empty;
    for (edits, 0..) |edit, index| {
        const entry = try files.getOrPut(arena, edit.file);
        if (!entry.found_existing) entry.value_ptr.* = source.read(edit.file) catch |failure| {
            if (failure == error.FileNotFound) return index;
            return failure;
        };
        if (std.mem.count(u8, entry.value_ptr.*, edit.old) != 1) return index;
        entry.value_ptr.* = try std.mem.replaceOwned(u8, arena, entry.value_ptr.*, edit.old, edit.new);
    }
    return null;
}

// Tests.

const testing = std.testing;

/// Files held in memory, for the tests of `first_stale`.
const Files = struct {
    names: []const []const u8,
    contents: []const []const u8,

    fn read(files: *const Files, path: []const u8) error{FileNotFound}![]const u8 {
        for (files.names, files.contents) |name, content| if (std.mem.eql(u8, name, path)) return content;
        return error.FileNotFound;
    }
};

test "an edit is stale when its text is not in its file once, after the edits before it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const files: Files = .{ .names = &.{"x.zig"}, .contents = &.{"const a = 1;\nconst b = 2;\n"} };
    // The second edit reads what the first one wrote.
    const in_turn = [_]Edit{ .{ .file = "x.zig", .old = "a = 1", .new = "a = 3" }, .{ .file = "x.zig", .old = "a = 3", .new = "a = 4" } };
    try testing.expectEqual(null, try first_stale(arena, &files, &in_turn));
    const moved = [_]Edit{ .{ .file = "x.zig", .old = "a = 1", .new = "a = 3" }, .{ .file = "x.zig", .old = "c = 3", .new = "c = 4" } };
    try testing.expectEqual(1, (try first_stale(arena, &files, &moved)).?);
    const twice = [_]Edit{.{ .file = "x.zig", .old = "const", .new = "var" }};
    try testing.expectEqual(0, (try first_stale(arena, &files, &twice)).?);
    const missing = [_]Edit{.{ .file = "y.zig", .old = "a", .new = "b" }};
    try testing.expectEqual(0, (try first_stale(arena, &files, &missing)).?);
}

test "two edits to one file apply in turn, and the file is put back as it began" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const source = "const a = 1;\nconst b = 2;\n";
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "x.zig", .data = source });
    const edits = [_]Edit{
        .{ .file = "x.zig", .old = "a = 1", .new = "a = 3" },
        .{ .file = "x.zig", .old = "b = 2", .new = "b = 4" },
    };
    const originals = try apply(arena, testing.io, tmp.dir, &edits);
    const edited = try tmp.dir.readFileAlloc(testing.io, "x.zig", arena, .limited(file_bytes_max));
    try testing.expectEqualStrings("const a = 3;\nconst b = 4;\n", edited);
    restore(testing.io, tmp.dir, &edits, originals);
    const back = try tmp.dir.readFileAlloc(testing.io, "x.zig", arena, .limited(file_bytes_max));
    try testing.expectEqualStrings(source, back);
    const twice = [_]Edit{ .{ .file = "x.zig", .old = "a = 1", .new = "a = 3" }, .{ .file = "x.zig", .old = "const", .new = "var" } };
    try testing.expectError(error.EditDoesNotApply, apply(arena, testing.io, tmp.dir, &twice));
    const kept = try tmp.dir.readFileAlloc(testing.io, "x.zig", arena, .limited(file_bytes_max));
    try testing.expectEqualStrings(source, kept);
}
