//! `zig build readme-check`: the README's Zig code, compiled and run against the library as it is.
//! A README is read and copied more than any other page, and nothing else builds its code: an API
//! that moves leaves a block behind that no longer compiles, as the driving loop once did.
//!
//! Each Zig block of README.md sits under a marker naming the harness that gives it its names:
//!
//! ```markdown
//! <!-- readme-check: loop -->
//! ```
//!
//! - `loop` is a lookup driven by hand: it is given `config`, `seed`, `name`, a `clock` and a
//!   `socket`, and returns the answer.
//! - `quick-start` is given `config`, `seed` and `now_ns`, and ends with `event`, the table's first
//!   event, whose action must be `send_udp`.
//! - `build` is the part of a dependent's `build.zig` that imports cocuyo: it is given `b`,
//!   `target` and `exe`.
//!
//! A Zig block with no marker, or a marker with no block, fails the check, so a new block cannot
//! go unbuilt: it brings its harness with it. The tool writes a package that depends on cocuyo by
//! relative path and on the rotor cocuyo pins, with the `build` block as its build and the other
//! two in its `main.zig`, builds it under the parent's cache, and runs it.
//!
//! Usage: `readme_check <zig-exe> <README.md> <build.zig.zon> <package-dir> <cache-dir>`
const std = @import("std");

pub const Error = error{ Unmarked, MarkerWithoutBlock, UnknownHarness, Duplicate, Unclosed, Missing, NoRotorPin };

pub const Harness = enum {
    loop,
    quick_start,
    build,

    /// The name a marker spells: `quick-start` for `quick_start`.
    fn of(name: []const u8) ?Harness {
        if (std.mem.eql(u8, name, "quick-start")) return .quick_start;
        if (std.mem.eql(u8, name, "quick_start")) return null;
        return std.meta.stringToEnum(Harness, name);
    }
};

pub const Blocks = std.EnumArray(Harness, []const u8);

const marker_prefix = "<!-- readme-check: ";
const marker_suffix = " -->";
const zig_fence = "```zig";
const fence = "```";
/// The most a README or a manifest may take.
const file_bytes_max: std.Io.Limit = .limited(1 << 20);
/// What the nested build and the program may print before this tool stops reading it.
const output_bytes_max: std.Io.Limit = .limited(1 << 20);
/// The name the package takes, and the fingerprint Zig asks of a package of that name.
const package_name = "readme_check";
const package_fingerprint = "0x38996b9c783622d2";
/// What the program prints when the quick start reached its first action as the README says.
const quick_start_line = "readme: the quick start's first action is send_udp";

/// Every marked Zig block of `readme`, each under its harness.
pub fn blocks_of(readme: []const u8) Error!Blocks {
    var reader: Reader = .{ .readme = readme };
    var lines = std.mem.splitScalar(u8, readme, '\n');
    var at: usize = 0;
    for (0..readme.len + 1) |_| {
        const line = lines.next() orelse break;
        at += line.len + 1;
        try reader.line(std.mem.trim(u8, line, " \r"), at);
    }
    return reader.finish();
}

/// The walk over the README's lines: the blocks found so far, and the marker waiting for its block.
const Reader = struct {
    readme: []const u8,
    found: std.EnumArray(Harness, ?[]const u8) = .initFill(null),
    pending: ?Harness = null,

    /// One line, trimmed, and the offset after it.
    fn line(self: *Reader, text: []const u8, after: usize) Error!void {
        if (marked(text)) |name| {
            if (self.pending != null) return Error.MarkerWithoutBlock;
            self.pending = Harness.of(name) orelse return Error.UnknownHarness;
            return;
        }
        if (std.mem.eql(u8, text, zig_fence)) return self.block(after);
        if (self.pending != null and text.len > 0) return Error.MarkerWithoutBlock;
    }

    /// A Zig block that starts at `after`, which the marker before it names.
    fn block(self: *Reader, after: usize) Error!void {
        const harness = self.pending orelse return Error.Unmarked;
        if (self.found.get(harness) != null) return Error.Duplicate;
        self.found.set(harness, try code_until_fence(self.readme[@min(after, self.readme.len)..]));
        self.pending = null;
    }

    fn finish(self: *const Reader) Error!Blocks {
        if (self.pending != null) return Error.MarkerWithoutBlock;
        var blocks: Blocks = undefined;
        for (std.enums.values(Harness)) |harness| blocks.set(harness, self.found.get(harness) orelse return Error.Missing);
        return blocks;
    }
};

/// The harness name a marker line spells, or null for any other line.
fn marked(text: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, text, marker_prefix) or !std.mem.endsWith(u8, text, marker_suffix)) return null;
    return text[marker_prefix.len .. text.len - marker_suffix.len];
}

/// The code from the start of `rest` to the line that closes its fence.
fn code_until_fence(rest: []const u8) Error![]const u8 {
    var lines = std.mem.splitScalar(u8, rest, '\n');
    var at: usize = 0;
    for (0..rest.len + 1) |_| {
        const line = lines.next() orelse return Error.Unclosed;
        if (std.mem.eql(u8, std.mem.trim(u8, line, " \r"), fence)) return rest[0..at];
        at += line.len + 1;
    }
    return Error.Unclosed;
}

pub const Pin = struct { url: []const u8, hash: []const u8 };

/// The rotor that cocuyo's own manifest pins, which the package pins too.
pub fn rotor_pin(manifest: []const u8) Error!Pin {
    const entry = std.mem.indexOf(u8, manifest, ".rotor = .{") orelse return Error.NoRotorPin;
    const rest = manifest[entry..];
    return .{
        .url = quoted_after(rest, ".url = \"") orelse return Error.NoRotorPin,
        .hash = quoted_after(rest, ".hash = \"") orelse return Error.NoRotorPin,
    };
}

fn quoted_after(text: []const u8, key: []const u8) ?[]const u8 {
    const start = (std.mem.indexOf(u8, text, key) orelse return null) + key.len;
    const end = std.mem.indexOfScalarPos(u8, text, start, '"') orelse return null;
    return text[start..end];
}

pub fn write_manifest(writer: *std.Io.Writer, cocuyo_path: []const u8, pin: Pin) std.Io.Writer.Error!void {
    try writer.print(
        \\.{{
        \\    .name = .{s},
        \\    .version = "0.0.0",
        \\    .fingerprint = {s},
        \\    .minimum_zig_version = "0.16.0",
        \\    .dependencies = .{{
        \\        .cocuyo = .{{ .path = "{s}" }},
        \\        .rotor = .{{ .url = "{s}", .hash = "{s}" }},
        \\    }},
        \\    .paths = .{{""}},
        \\}}
        \\
    , .{ package_name, package_fingerprint, cocuyo_path, pin.url, pin.hash });
}

pub fn write_build(writer: *std.Io.Writer, build_block: []const u8) std.Io.Writer.Error!void {
    try writer.writeAll(
        \\//! Written by tools/readme_check.zig from README.md, on every run.
        \\const std = @import("std");
        \\
        \\pub fn build(b: *std.Build) void {
        \\    const target = b.standardTargetOptions(.{});
        \\    const exe = b.addExecutable(.{ .name = "readme", .root_module = b.createModule(.{
        \\        .root_source_file = b.path("main.zig"),
        \\        .target = target,
        \\    }) });
        \\
    );
    try writer.writeAll(build_block);
    try writer.writeAll(
        \\    b.installArtifact(exe);
        \\}
        \\
    );
}

/// The import a block needs, unless it makes its own.
fn import_unless_made(block: []const u8) []const u8 {
    if (std.mem.indexOf(u8, block, "const cocuyo = @import(\"cocuyo\");") != null) return "";
    return "    const cocuyo = @import(\"cocuyo\");\n";
}

pub fn write_main(writer: *std.Io.Writer, blocks: Blocks) std.Io.Writer.Error!void {
    try writer.writeAll(
        \\//! Written by tools/readme_check.zig from README.md, on every run: each Zig block of the
        \\//! README, as it is, inside the function that gives it its names.
        \\const std = @import("std");
        \\
        \\/// The caller's monotonic clock, and its UDP socket, which the loop drives the lookup with.
        \\const Clock = struct {
        \\    fn read(_: Clock) u64 {
        \\        return 1;
        \\    }
        \\};
        \\const Datagram = struct { bytes: []const u8, from: @import("cocuyo").Endpoint };
        \\const Socket = struct {
        \\    fn send(_: Socket, _: @import("cocuyo").Endpoint, _: []const u8) !void {}
        \\    fn receive_until(_: Socket, _: u64) !?Datagram {
        \\        return null;
        \\    }
        \\};
        \\
        \\fn loop(config: @import("cocuyo").Config, seed: u64, name: []const u8, clock: Clock, socket: Socket) !@import("cocuyo").Answer {
        \\
    );
    try writer.print("{s}{s}}}\n\n", .{ import_unless_made(blocks.get(.loop)), blocks.get(.loop) });
    try writer.writeAll(
        \\fn quick_start(config: @import("cocuyo").Config, seed: u64, now_ns: u64) ![]const u8 {
        \\
    );
    try writer.print("{s}{s}    return @tagName(event.action);\n}}\n\n", .{ import_unless_made(blocks.get(.quick_start)), blocks.get(.quick_start) });
    try writer.print(
        \\pub fn main() !void {{
        \\    _ = &loop;
        \\    _ = @import("cocuyo_rotor").Resolver;
        \\    const address = @import("cocuyo").Address.from_v4(.{{ 192, 0, 2, 1 }});
        \\    const servers = [_]@import("cocuyo").Server{{.{{ .endpoint = .{{ .address = address }} }}}};
        \\    const config: @import("cocuyo").Config = .{{ .servers = &servers, .search = &.{{}} }};
        \\    const first = try quick_start(config, 0x5eed, 1);
        \\    if (!std.mem.eql(u8, first, "send_udp")) {{
        \\        std.debug.print("readme: the quick start's first action is {{s}}, not send_udp\n", .{{first}});
        \\        std.process.exit(1);
        \\    }}
        \\    std.debug.print("{s}\n", .{{}});
        \\}}
        \\
    , .{quick_start_line});
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 6) {
        std.debug.print("usage: readme_check <zig-exe> <README.md> <build.zig.zon> <package-dir> <cache-dir>\n", .{});
        std.process.exit(2);
    }
    const io = init.io;
    const cwd = std.Io.Dir.cwd();
    const readme = try cwd.readFileAlloc(io, args[2], arena, file_bytes_max);
    const blocks = blocks_of(readme) catch |err| {
        std.debug.print("readme-check: README.md: {t}. Every ```zig block sits under a marker, as tools/readme_check.zig says.\n", .{err});
        std.process.exit(1);
    };
    const pin = try rotor_pin(try cwd.readFileAlloc(io, args[3], arena, file_bytes_max));
    const package = args[4];
    try write_package(arena, io, package, std.fs.path.dirname(args[2]) orelse ".", blocks, pin);
    try build_and_run(arena, io, args[1], package, args[5]);
    std.debug.print("readme-check: every Zig block of the README builds, and the quick start runs\n", .{});
}

fn write_package(arena: std.mem.Allocator, io: std.Io, package: []const u8, root: []const u8, blocks: Blocks, pin: Pin) !void {
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, package);
    const cocuyo_path = try std.fs.path.relative(arena, package, null, package, root);
    var text: std.Io.Writer.Allocating = .init(arena);
    try write_manifest(&text.writer, cocuyo_path, pin);
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ package, "build.zig.zon" }), .data = text.written() });
    text.clearRetainingCapacity();
    try write_build(&text.writer, blocks.get(.build));
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ package, "build.zig" }), .data = text.written() });
    text.clearRetainingCapacity();
    try write_main(&text.writer, blocks);
    try cwd.writeFile(io, .{ .sub_path = try std.fs.path.join(arena, &.{ package, "main.zig" }), .data = text.written() });
}

/// Builds the package under the parent's cache, then runs what it built.
fn build_and_run(arena: std.mem.Allocator, io: std.Io, zig_exe: []const u8, package: []const u8, cache: []const u8) !void {
    const prefix = try std.fs.path.join(arena, &.{ cache, "out" });
    const built = try std.process.run(arena, io, .{
        .argv = &.{ zig_exe, "build", "--cache-dir", cache, "--prefix", prefix },
        .cwd = .{ .path = package },
        .stdout_limit = output_bytes_max,
        .stderr_limit = output_bytes_max,
    });
    if (!exited_zero(built.term)) {
        std.debug.print("readme-check: the README's code does not build:\n{s}\n", .{built.stderr});
        std.process.exit(1);
    }
    const ran = try std.process.run(arena, io, .{
        .argv = &.{try std.fs.path.join(arena, &.{ prefix, "bin", "readme" })},
        .stdout_limit = output_bytes_max,
        .stderr_limit = output_bytes_max,
    });
    if (!exited_zero(ran.term) or std.mem.indexOf(u8, ran.stderr, quick_start_line) == null) {
        std.debug.print("readme-check: the README's quick start did not run as it says:\n{s}\n", .{ran.stderr});
        std.process.exit(1);
    }
}

fn exited_zero(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

// Tests. The check itself needs a compiler and a package; these pin how the README is read.

const testing = std.testing;

const sample =
    \\Some prose.
    \\
    \\<!-- readme-check: loop -->
    \\```zig
    \\var a = 1;
    \\```
    \\
    \\```bash
    \\zig build test
    \\```
    \\
    \\<!-- readme-check: build -->
    \\
    \\```zig
    \\const cocuyo = b.dependency("cocuyo", .{});
    \\```
    \\
    \\<!-- readme-check: quick-start -->
    \\```zig
    \\const cocuyo = @import("cocuyo");
    \\const event = 1;
    \\```
    \\
;

test "every marked block is read under its harness, and other code blocks are left alone" {
    const blocks = try blocks_of(sample);
    try testing.expectEqualStrings("var a = 1;\n", blocks.get(.loop));
    try testing.expectEqualStrings("const cocuyo = b.dependency(\"cocuyo\", .{});\n", blocks.get(.build));
    try testing.expectEqualStrings("", import_unless_made(blocks.get(.quick_start)));
    try testing.expect(import_unless_made(blocks.get(.loop)).len > 0);
}

test "a block with no marker, a marker with no block, and a harness named twice or never are refused" {
    try testing.expectError(Error.Unmarked, blocks_of("```zig\nx\n```\n"));
    try testing.expectError(Error.MarkerWithoutBlock, blocks_of("<!-- readme-check: loop -->\nprose\n```zig\nx\n```\n"));
    try testing.expectError(Error.MarkerWithoutBlock, blocks_of("<!-- readme-check: loop -->\n"));
    try testing.expectError(Error.UnknownHarness, blocks_of("<!-- readme-check: other -->\n```zig\nx\n```\n"));
    try testing.expectError(Error.UnknownHarness, blocks_of("<!-- readme-check: quick_start -->\n```zig\nx\n```\n"));
    try testing.expectError(Error.Duplicate, blocks_of("<!-- readme-check: loop -->\n```zig\nx\n```\n<!-- readme-check: loop -->\n```zig\ny\n```\n"));
    try testing.expectError(Error.Unclosed, blocks_of("<!-- readme-check: loop -->\n```zig\nx\n"));
    try testing.expectError(Error.Missing, blocks_of("<!-- readme-check: loop -->\n```zig\nx\n```\n"));
}

test "the rotor pin comes from cocuyo's manifest" {
    const manifest =
        \\.pepegrillo = .{ .url = "git+https://example.invalid/p", .hash = "p-0" },
        \\.rotor = .{
        \\    .url = "git+https://github.com/c4milo/rotor?ref=v0.4.0#abc",
        \\    .hash = "rotor-0.4.0-xyz",
        \\    .lazy = true,
        \\},
    ;
    const pin = try rotor_pin(manifest);
    try testing.expectEqualStrings("git+https://github.com/c4milo/rotor?ref=v0.4.0#abc", pin.url);
    try testing.expectEqualStrings("rotor-0.4.0-xyz", pin.hash);
    try testing.expectError(Error.NoRotorPin, rotor_pin(".pepegrillo = .{}"));
}
