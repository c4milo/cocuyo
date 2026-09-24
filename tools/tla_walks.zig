//! The engine model's walks for the replay (tools/spec_replay/engine_replay.zig): TLC's simulation
//! mode over spec/tla/engine/EngineTrace.tla, one run for each configuration under
//! spec/tla/engine/trace/. The runs go at once, each on one worker and seeded by the caller, so a
//! seed always writes the same walks. What each run prints goes to standard output in the
//! configurations' order, with TLC's quotes taken off and TLC's own lines left out.
//!
//! Run:  zig build tla -- walks <seed> <walks> <depth> [--pick <file> <walk>...]
//!
//! `zig build spec` runs it. A walk of `<depth>` holds that many states: its `init`, then one
//! event fewer than the depth. The walks `--pick` names go to its file as well, each numbered as
//! the replay counts it in the whole run, from 1 in the configurations' order: the committed
//! walks keep a few of the full run's this way, and the build requires them to be TLC's own.
const std = @import("std");
const Io = std.Io;
const pepegrillo = @import("pepegrillo");
const tlc = pepegrillo.tla.tlc;

/// Where the walks come from, from the repository's root: the model's directory, which TLC runs
/// in, the configurations inside it, and the module that writes the walks.
const model_directory = "spec/tla/engine";
const trace_directory = "trace";
const trace_module = "EngineTrace";
const configuration_extension = ".cfg";

/// The configurations the trace directory may hold. It holds eight, one for each of the replay's.
const configurations_max: usize = 32;
/// The heap each run may take. A walk keeps one state and its successors, so a run needs little,
/// and a run left at Java's default of a quarter of memory starves the other runs of theirs.
const java_heap = "-Xmx1g";
/// The bytes the picked walks are written through.
const output_buffer_bytes: usize = 64 * 1024;
/// The longest line of a run's output. A state line is a few hundred bytes; TLC's own lines about
/// an error it met can be longer, and are read only to be reported.
const line_bytes_max: usize = 64 * 1024;
/// Lines of a failed run's output reported, from its end.
const failure_tail_lines: usize = 40;
/// The mark TLC's `PrintT` puts around a string, which a line of the walks starts and ends with.
const quote = '"';

const exit_success: u8 = 0;
const exit_failure: u8 = 1;
const exit_usage: u8 = 2;

pub const usage = "usage: tla walks <seed> <walks> <depth> [--pick <file> <walk>...]\n";

/// The option that names the file the picked walks go to, and the walks after it.
const pick_option = "--pick";

/// What the command line asks for: TLC's seed, the walks in each configuration and the states in
/// each, as TLC takes them, and the file the walks it names go to as well, if it names one.
const Request = struct {
    seed: []const u8,
    walks: u64,
    depth: []const u8,
    pick_path: ?[]const u8 = null,
    picked: []const u64 = &.{},
};

/// The request the arguments make, or null when they make none.
fn request_of(arena: std.mem.Allocator, arguments: []const []const u8) !?Request {
    if (arguments.len < 3) return null;
    for (arguments[0..3]) |argument| _ = std.fmt.parseInt(u64, argument, 10) catch return null;
    const walks = try std.fmt.parseInt(u64, arguments[1], 10);
    if (walks == 0) return null;
    const request: Request = .{ .seed = arguments[0], .walks = walks, .depth = arguments[2] };
    if (arguments.len == 3) return request;
    if (arguments.len < 6 or !std.mem.eql(u8, arguments[3], pick_option)) return null;
    const picked = try arena.alloc(u64, arguments.len - 5);
    for (arguments[5..], picked) |argument, *walk| {
        walk.* = std.fmt.parseInt(u64, argument, 10) catch return null;
        if (walk.* == 0) return null;
    }
    return .{ .seed = request.seed, .walks = walks, .depth = request.depth, .pick_path = arguments[4], .picked = picked };
}

/// Writes the walks, and returns the exit status: 0 when every run ended as it should.
pub fn run(
    init: std.process.Init,
    comptime project: pepegrillo.tla.Config,
    arguments: []const []const u8,
    out: *Io.Writer,
    errors: *Io.Writer,
) !u8 {
    const arena = init.arena.allocator();
    const request = try request_of(arena, arguments) orelse {
        try errors.writeAll(usage);
        return exit_usage;
    };
    const context: pepegrillo.tla.Context = .{ .arena = arena, .io = init.io, .environ = init.environ_map, .out = out, .errors = errors };
    const jar = try pepegrillo.tla.verified_jar(context, project);
    const names = try configurations(arena, init.io);
    if (beyond(request, names.len)) |walk| {
        try errors.print("there is no walk {d}: {d} configurations of {d} walks\n", .{ walk, names.len, request.walks });
        return exit_usage;
    }
    var runs: [configurations_max]Run = undefined;
    for (names, runs[0..names.len]) |name, *one| one.* = try start(init, project, jar, name, request);
    var status = exit_success;
    for (runs[0..names.len]) |*one| {
        if (!try finish(arena, init.io, one, errors)) status = exit_failure;
    }
    if (status != exit_success) return status;
    try write_walks(init.io, runs[0..names.len], request, out);
    return exit_success;
}

/// The first named walk past the whole run's end, if there is one.
fn beyond(request: Request, configurations_count: usize) ?u64 {
    const total = request.walks * configurations_count;
    for (request.picked) |walk| if (walk > total) return walk;
    return null;
}

/// Every run's walks to `out`, in the configurations' order, and the picked ones to their file.
fn write_walks(io: Io, runs: []const Run, request: Request, out: *Io.Writer) !void {
    const path = request.pick_path orelse {
        for (runs) |one| try copy_walks(io, one.output, out, null);
        return;
    };
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buffer: [output_buffer_bytes]u8 = undefined;
    var writer = file.writerStreaming(io, &buffer);
    for (runs, 0..) |one, position| {
        try copy_walks(io, one.output, out, .{ .writer = &writer.interface, .request = request, .position = position });
    }
    try writer.interface.flush();
}

/// Where a run's picked walks go: the writer, and what says which of its walks are picked.
const Picking = struct {
    writer: *Io.Writer,
    request: Request,
    /// The run's place among the configurations.
    position: usize,

    /// Whether the run's walk `own`, counted from 1, is picked: whether the walk it is in the
    /// whole run, counted from 1 in the configurations' order, is named.
    fn picks(picking: Picking, own: u64) bool {
        const walk = picking.request.walks * picking.position + own;
        return std.mem.indexOfScalar(u64, picking.request.picked, walk) != null;
    }
};

/// The trace configurations' paths from the model's directory, sorted, so the walks come out in
/// one order.
fn configurations(arena: std.mem.Allocator, io: Io) ![]const []const u8 {
    const path = model_directory ++ "/" ++ trace_directory;
    var directory = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer directory.close(io);
    var found: std.ArrayList([]const u8) = .empty;
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, configuration_extension)) continue;
        if (found.items.len == configurations_max) return error.TooManyConfigurations;
        try found.append(arena, try std.fs.path.join(arena, &.{ trace_directory, entry.name }));
    }
    if (found.items.len == 0) return error.NoConfiguration;
    std.mem.sort([]const u8, found.items, {}, less_than);
    return found.items;
}

fn less_than(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

/// One run of TLC: the configuration it walks, its process, and the file its output goes to.
const Run = struct {
    configuration: []const u8,
    child: std.process.Child,
    output: []const u8,
};

fn start(
    init: std.process.Init,
    comptime project: pepegrillo.tla.Config,
    jar: []const u8,
    configuration: []const u8,
    request: Request,
) !Run {
    const arena = init.arena.allocator();
    // Named for the request as well: the build runs the committed walks and the full run at once.
    const label = try std.fmt.allocPrint(arena, "walks-{s}-{s}-{d}-{s}", .{
        std.fs.path.stem(configuration), request.seed, request.walks, request.depth,
    });
    const states = try tlc.states_path(arena, init.environ_map, label);
    Io.Dir.cwd().deleteTree(init.io, states) catch {};
    try Io.Dir.cwd().createDirPath(init.io, states);
    const output = try std.fs.path.join(arena, &.{ states, "walks.out" });
    const file = try Io.Dir.cwd().createFile(init.io, output, .{});
    defer file.close(init.io);
    const argv = try tlc.argv(arena, .{
        .java_program = project.java_program,
        .java_options = try std.mem.concat(arena, []const u8, &.{ &.{java_heap}, project.java_options }),
        .workers = "1",
        .jar = jar,
        .states = states,
        .configuration = configuration,
        .module = trace_module,
        .tlc_options = &.{
            "-simulate", try std.fmt.allocPrint(arena, "num={d}", .{request.walks}),
            "-depth",    request.depth,
            "-seed",     request.seed,
        },
    });
    const child = try std.process.spawn(init.io, .{
        .argv = argv,
        .cwd = .{ .path = model_directory },
        .stdin = .ignore,
        .stdout = .{ .file = file },
        .stderr = .{ .file = file },
    });
    return .{ .configuration = configuration, .child = child, .output = output };
}

/// Waits for a run, and reports it when it did not end as a walk should: TLC exits 0 once it has
/// taken every walk, and otherwise found a state that breaks an invariant or could not run.
fn finish(arena: std.mem.Allocator, io: Io, one: *Run, errors: *Io.Writer) !bool {
    const term = try one.child.wait(io);
    const ended = switch (term) {
        .exited => |code| code == exit_success,
        else => false,
    };
    if (ended) return true;
    try errors.print("{s}/{s}: TLC ended {any}; the end of its output:\n", .{ model_directory, one.configuration, term });
    try write_tail(arena, io, one.output, errors);
    return false;
}

/// Writes the last of TLC's own lines in a run's output, which say why it stopped; the walk's lines
/// before them are left out.
fn write_tail(arena: std.mem.Allocator, io: Io, path: []const u8, errors: *Io.Writer) !void {
    var tail: [failure_tail_lines][]const u8 = undefined;
    var count: usize = 0;
    var buffer: [line_bytes_max]u8 = undefined;
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var reader = file.reader(io, &buffer);
    while (reader.interface.takeDelimiter('\n') catch null) |line| {
        if (walk_line(line) != null) continue;
        tail[count % failure_tail_lines] = try arena.dupe(u8, line);
        count += 1;
    }
    const kept = @min(count, failure_tail_lines);
    for (count - kept..count) |index| try errors.print("  {s}\n", .{tail[index % failure_tail_lines]});
}

/// The line a walk starts with, which names its configuration.
const walk_start = "config ";

/// Copies a run's walks out of its output, its quoted lines unquoted, and the picked ones to
/// their file as well.
fn copy_walks(io: Io, path: []const u8, out: *Io.Writer, picking: ?Picking) !void {
    var buffer: [line_bytes_max]u8 = undefined;
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    var reader = file.reader(io, &buffer);
    var own: u64 = 0;
    var picked = false;
    while (try reader.interface.takeDelimiter('\n')) |line| {
        const text = walk_line(line) orelse continue;
        if (std.mem.startsWith(u8, text, walk_start)) {
            own += 1;
            picked = if (picking) |one| one.picks(own) else false;
        }
        try write_line(out, text);
        if (picked) try write_line(picking.?.writer, text);
    }
}

fn write_line(writer: *Io.Writer, text: []const u8) !void {
    try writer.writeAll(text);
    try writer.writeByte('\n');
}

/// The line of a walk that `line` of TLC's output carries, or null when it is one of TLC's own.
fn walk_line(line: []const u8) ?[]const u8 {
    if (line.len < 2 or line[0] != quote or line[line.len - 1] != quote) return null;
    const text = line[1 .. line.len - 1];
    // A state line never holds a quote, so one inside is not a line of the walks.
    if (std.mem.indexOfScalar(u8, text, quote) != null) return null;
    return text;
}

// Tests.

const testing = std.testing;

test "a picked walk is named by its place in the whole run, from 1 in the configurations' order" {
    const request: Request = .{ .seed = "1", .walks = 10, .depth = "41", .pick_path = "p", .picked = &.{ 3, 12, 20, 21 } };
    var sink: Io.Writer = .failing;
    const first: Picking = .{ .writer = &sink, .request = request, .position = 0 };
    const second: Picking = .{ .writer = &sink, .request = request, .position = 1 };
    try testing.expect(first.picks(3) and !first.picks(2) and !first.picks(10));
    try testing.expect(second.picks(2) and second.picks(10) and !second.picks(3));
    try testing.expectEqual(null, beyond(request, 3));
    try testing.expectEqual(21, beyond(request, 2));
}

test "a request needs a seed, a count and a depth, and picked walks counted from 1" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const picking = (try request_of(arena, &.{ "1", "10", "41", "--pick", "p", "3" })).?;
    try testing.expectEqualStrings("p", picking.pick_path.?);
    try testing.expectEqual(3, picking.picked[0]);
    try testing.expectEqual(null, (try request_of(arena, &.{ "1", "10", "41" })).?.pick_path);
    try testing.expectEqual(null, try request_of(arena, &.{ "1", "10" }));
    try testing.expectEqual(null, try request_of(arena, &.{ "1", "x", "41" }));
    try testing.expectEqual(null, try request_of(arena, &.{ "1", "0", "41" }));
    try testing.expectEqual(null, try request_of(arena, &.{ "1", "10", "41", "3" }));
    try testing.expectEqual(null, try request_of(arena, &.{ "1", "10", "41", "--pick", "p" }));
    try testing.expectEqual(null, try request_of(arena, &.{ "1", "10", "41", "--pick", "p", "0" }));
}

test "walk_line takes the quotes off a printed string and keeps nothing else" {
    try testing.expectEqualStrings("config 1 1 tcp 0", walk_line("\"config 1 1 tcp 0\"").?);
    try testing.expectEqualStrings("1 jam free - u-", walk_line("\"1 jam free - u-\"").?);
    try testing.expectEqual(null, walk_line("Progress: 17823 states checked."));
    try testing.expectEqual(null, walk_line("\""));
    try testing.expectEqual(null, walk_line("\"a\" and \"b\""));
    try testing.expectEqual(null, walk_line(""));
}
