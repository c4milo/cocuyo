//! fill-check: the library's hot paths call no fill, `memset` or `bzero`, beyond the ones `known`
//! names (c4milo/cocuyo#35). ReleaseSafe fills memory declared `undefined` with 0xAA through
//! `memset`, LLVM turns zeroing loops into the same call, and on Linux that `memset` stores one
//! byte at a time (pepegrillo's `docs/performance/performance_zig.md`, "Copies and fills"). A fill
//! on a hot path is a cost no timing on a shared runner would see, and a count of calls is exact.
//!
//! `build/fill_check.zig` compiles `fill_probe.zig` ReleaseSafe for each target the library ships
//! to and hands this tool the assembly. The tool splits it into functions, follows the calls from
//! each probe through every function the file defines but the panic handlers, which run once and
//! never on a path that returns, and counts the calls to a fill. A probe whose count is not its
//! known count fails the check: more is a new fill, and fewer is a fill gone, which the change
//! that removed it takes out of `known`.
const std = @import("std");
const assert = std.debug.assert;

/// The fills each probe reaches today, by target, of two kinds:
///
/// - The fills of the answers' storage c4milo/cocuyo#34 found. `Lookup.init` fills the lookup it
///   builds, `Lookup.init_in_place` and `Cache.put_negative` the answers they leave undefined, and
///   `Answers.reset` and `Answers.assign`, which `response.collect` and the cache's recall reach,
///   the member of the storage they make active. They stay here until #34 removes them.
/// - The zeros of the EDNS Padding option, which `query.write` writes for a query that goes
///   encrypted (RFC 7830 §3): fewer than one block of them, and on purpose.
///
/// Arm64 writes the 272-octet fills as stores of its own, so it makes fewer calls. A probe not
/// listed reaches none.
pub const Known = struct { target: []const u8, probe: []const u8, fills: u32 };
pub const known = [_]Known{
    .{ .target = "x86_64-linux-gnu", .probe = "probe_query_write", .fills = 1 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_response_collect", .fills = 2 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_table_start", .fills = 3 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_table_poll", .fills = 3 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_table_datagram", .fills = 2 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_cache_put", .fills = 2 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_cache_put_negative", .fills = 5 },
    .{ .target = "x86_64-linux-gnu", .probe = "probe_lookup_init", .fills = 4 },
    .{ .target = "aarch64-macos", .probe = "probe_query_write", .fills = 1 },
    .{ .target = "aarch64-macos", .probe = "probe_response_collect", .fills = 1 },
    .{ .target = "aarch64-macos", .probe = "probe_table_start", .fills = 2 },
    .{ .target = "aarch64-macos", .probe = "probe_table_poll", .fills = 2 },
    .{ .target = "aarch64-macos", .probe = "probe_table_datagram", .fills = 1 },
    .{ .target = "aarch64-macos", .probe = "probe_cache_put", .fills = 1 },
    .{ .target = "aarch64-macos", .probe = "probe_cache_put_negative", .fills = 3 },
    .{ .target = "aarch64-macos", .probe = "probe_lookup_init", .fills = 3 },
};

/// How a target's assembly spells what the tool reads: the prefixes a function's symbol may carry,
/// whether a label is a function only when a `.type` directive says so, and the mnemonics of a
/// call and of a jump to another function, which is a tail call.
const Flavor = struct {
    name: []const u8,
    symbol_prefixes: []const []const u8,
    typed_functions: bool,
    call: []const u8,
    jump: []const u8,
};

/// The targets the library ships to, as `build/fill_check.zig` names them. A stripped build names
/// a function it does not export as a local symbol: `.L` and the name on ELF, where a basic block
/// is a `.L` label too and only `.type` tells the two apart, and `l_` and the name on Mach-O,
/// where a basic block is `LBB` or `Ltmp`. An exported or external symbol goes bare on ELF and
/// behind `_` on Mach-O.
pub const flavors = [_]Flavor{
    .{ .name = "x86_64-linux-gnu", .symbol_prefixes = &.{ ".L", "" }, .typed_functions = true, .call = "call", .jump = "jmp" },
    .{ .name = "aarch64-macos", .symbol_prefixes = &.{ "l_", "_" }, .typed_functions = false, .call = "bl", .jump = "b" },
};

/// The symbols a fill compiles to: `memset` for any byte, and `bzero`, which Darwin's LLVM calls
/// for a zero fill.
const fill_symbols = [_][]const u8{ "memset", "bzero", "__bzero" };

/// The functions a probe's walk skips: the panic handlers. A failed check calls one and never
/// returns, so a fill there is not a cost of the path.
const skipped_prefix = "debug.";

/// Where every probe's name starts: the probe file's own namespace.
const probe_prefix = "fill_probe.";

/// The most assembly one target's probe compiles to. Stripped of debug information, one target's
/// ran to a few megabytes; this is room for a library ten times the size.
const assembly_bytes_max: std.Io.Limit = .limited(256 * 1024 * 1024);

const Function = struct {
    fills: u32 = 0,
    callees: std.ArrayList([]const u8) = .empty,
};

pub const Functions = std.StringArrayHashMapUnmanaged(Function);

/// Splits `text` into functions, each with its calls to a fill and the functions it calls.
pub fn parse(arena: std.mem.Allocator, text: []const u8, flavor: Flavor) !Functions {
    var parser: Parser = .{ .arena = arena, .flavor = flavor };
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| try parser.read(line);
    return parser.functions;
}

/// The functions read so far, the names `.type` has declared functions, and the function the
/// lines belong to now.
const Parser = struct {
    arena: std.mem.Allocator,
    flavor: Flavor,
    functions: Functions = .empty,
    typed: std.StringHashMapUnmanaged(void) = .empty,
    current: ?*Function = null,

    fn read(self: *Parser, line: []const u8) !void {
        if (typed_function(line)) |written| return self.typed.put(self.arena, written, {});
        if (label_of(line)) |written| return self.label(written);
        const function = self.current orelse return;
        const target = call_target(line, self.flavor) orelse return;
        if (is_fill(target)) function.fills += 1 else try function.callees.append(self.arena, target);
    }

    /// A label starts a function when it names one; a basic block's leaves the lines where they
    /// were.
    fn label(self: *Parser, written: []const u8) !void {
        if (self.flavor.typed_functions and !self.typed.contains(written)) return;
        const name = symbol_of(written, self.flavor) orelse return;
        const entry = try self.functions.getOrPut(self.arena, name);
        if (!entry.found_existing) entry.value_ptr.* = .{};
        self.current = entry.value_ptr;
    }
};

/// The name a `.type <name>,@function` directive declares a function, as written.
fn typed_function(line: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, line, " \t");
    const directive = ".type";
    if (!std.mem.startsWith(u8, trimmed, directive)) return null;
    const rest = std.mem.trim(u8, trimmed[directive.len..], " \t");
    if (!std.mem.endsWith(u8, rest, ",@function")) return null;
    const written = rest[0 .. rest.len - ",@function".len];
    if (written.len == 0) return null;
    return if (written[0] == '"') unquote(written) else written;
}

/// The name a line labels, as written and unquoted, or null for any other line: an instruction
/// or a directive, which the assembly indents.
fn label_of(line: []const u8) ?[]const u8 {
    if (line.len < 2 or line[line.len - 1] != ':') return null;
    const written = line[0 .. line.len - 1];
    if (written[0] == ' ' or written[0] == '\t') return null;
    return if (written[0] == '"') unquote(written) else written;
}

/// The function a call or a jump names, without the target's prefix and without `@PLT`, or null
/// for a line that is neither, or that jumps to a local label or through a register.
fn call_target(line: []const u8, flavor: Flavor) ?[]const u8 {
    const trimmed = std.mem.trim(u8, line, " \t");
    const space = std.mem.indexOfAny(u8, trimmed, " \t") orelse return null;
    const mnemonic = trimmed[0..space];
    if (!std.mem.eql(u8, mnemonic, flavor.call) and !std.mem.eql(u8, mnemonic, flavor.jump)) return null;
    const operand = std.mem.trim(u8, trimmed[space..], " \t");
    if (operand.len == 0) return null;
    const written = if (operand[0] == '"') unquote(operand) orelse return null else bare_operand(operand);
    return symbol_of(written, flavor);
}

/// An operand written without quotes, up to its first space, comma or `@`.
fn bare_operand(operand: []const u8) []const u8 {
    const end = std.mem.indexOfAny(u8, operand, " \t,@") orelse operand.len;
    return operand[0..end];
}

/// What sits between the quotes a symbol with spaces or parentheses is written in.
fn unquote(written: []const u8) ?[]const u8 {
    assert(written.len >= 1 and written[0] == '"');
    const close = std.mem.indexOfScalarPos(u8, written, 1, '"') orelse return null;
    return written[1..close];
}

/// `name` without the first of the target's symbol prefixes it carries, or null when it carries
/// none, as a Mach-O basic block does.
fn symbol_of(name: []const u8, flavor: Flavor) ?[]const u8 {
    for (flavor.symbol_prefixes) |prefix| {
        if (!std.mem.startsWith(u8, name, prefix)) continue;
        const bare = name[prefix.len..];
        return if (bare.len == 0) null else bare;
    }
    return null;
}

fn is_fill(name: []const u8) bool {
    for (fill_symbols) |fill| {
        if (std.mem.eql(u8, name, fill)) return true;
    }
    return false;
}

/// The calls to a fill in every function `probe` reaches, each function counted once.
pub fn fills_reached(arena: std.mem.Allocator, functions: *const Functions, probe: []const u8) !u32 {
    var fills: u32 = 0;
    for (try path_of(arena, functions, probe)) |name| fills += functions.getPtr(name).?.fills;
    return fills;
}

/// Every function `probe` reaches, itself first, each once, the panic handlers left out.
fn path_of(arena: std.mem.Allocator, functions: *const Functions, probe: []const u8) ![]const []const u8 {
    var seen: std.StringArrayHashMapUnmanaged(void) = .empty;
    var pending: std.ArrayList([]const u8) = .empty;
    try pending.append(arena, probe);
    while (pending.pop()) |name| {
        if (std.mem.startsWith(u8, name, skipped_prefix)) continue;
        const function = functions.getPtr(name) orelse continue;
        if ((try seen.getOrPut(arena, name)).found_existing) continue;
        try pending.appendSlice(arena, function.callees.items);
    }
    return seen.keys();
}

/// A probe's count, against what `table` says it is.
pub const Finding = struct {
    probe: []const u8,
    reached: u32,
    known: u32,
};

/// Every probe of the file whose count is not the one `table` knows for `target`, and every
/// entry of `table` for `target` whose probe the file does not have, as a count of none.
pub fn compare(arena: std.mem.Allocator, functions: *const Functions, target: []const u8, table: []const Known) ![]const Finding {
    var findings: std.ArrayList(Finding) = .empty;
    var probes: usize = 0;
    for (functions.keys()) |name| {
        if (!std.mem.startsWith(u8, name, probe_prefix)) continue;
        probes += 1;
        const probe = name[probe_prefix.len..];
        const reached = try fills_reached(arena, functions, name);
        const expected = known_fills(table, target, probe);
        if (reached != expected) try findings.append(arena, .{ .probe = probe, .reached = reached, .known = expected });
    }
    for (table) |entry| {
        if (!std.mem.eql(u8, entry.target, target)) continue;
        const name = try std.mem.concat(arena, u8, &.{ probe_prefix, entry.probe });
        if (!functions.contains(name)) try findings.append(arena, .{ .probe = entry.probe, .reached = 0, .known = entry.fills });
    }
    if (probes == 0) return error.NoProbes;
    return findings.items;
}

fn known_fills(table: []const Known, target: []const u8, probe: []const u8) u32 {
    for (table) |entry| {
        if (std.mem.eql(u8, entry.target, target) and std.mem.eql(u8, entry.probe, probe)) return entry.fills;
    }
    return 0;
}

fn flavor_of(target: []const u8) ?Flavor {
    for (flavors) |flavor| {
        if (std.mem.eql(u8, flavor.name, target)) return flavor;
    }
    return null;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        std.debug.print("usage: fill_check <target> <assembly>\n", .{});
        std.process.exit(2);
    }
    const flavor = flavor_of(args[1]) orelse {
        std.debug.print("fill-check: no flavour of assembly for {s}\n", .{args[1]});
        std.process.exit(2);
    };
    const text = try std.Io.Dir.cwd().readFileAlloc(init.io, args[2], arena, assembly_bytes_max);
    const functions = try parse(arena, text, flavor);
    const findings = try compare(arena, &functions, flavor.name, &known);
    for (findings) |finding| try report(arena, &functions, flavor.name, finding);
    if (findings.len != 0) std.process.exit(1);
    std.debug.print("fill-check: {s}: every hot path calls only the fills known\n", .{flavor.name});
}

/// One finding, and under it each function on the probe's path that calls a fill.
fn report(arena: std.mem.Allocator, functions: *const Functions, target: []const u8, finding: Finding) !void {
    const what = if (finding.reached > finding.known)
        "a new fill on a hot path; remove it, or name it in `known` with the reason"
    else
        "a fill went; take it out of `known`";
    std.debug.print("tools/fill_check/fill_check.zig: error: [fill] {s}: {s} reaches {d} calls to memset or bzero, {d} known: {s}\n", .{ target, finding.probe, finding.reached, finding.known, what });
    const probe = try std.mem.concat(arena, u8, &.{ probe_prefix, finding.probe });
    for (try path_of(arena, functions, probe)) |name| {
        const fills = functions.getPtr(name).?.fills;
        if (fills != 0) std.debug.print("  {d} in {s}\n", .{ fills, name });
    }
}

const testing = std.testing;

test "a call and a tail call to a fill both count, in each target's spelling" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const elf = try parse(arena, "\t.type\t.Lfill_probe.probe_a,@function\n.Lfill_probe.probe_a:\n\tcall\tmemset@PLT\n\tjmp\tmemset@PLT\n", flavors[0]);
    try testing.expectEqual(@as(u32, 2), try fills_reached(arena, &elf, "fill_probe.probe_a"));
    const macho = try parse(arena, "l_fill_probe.probe_a:\n\tbl\t_memset\n\tb\t_bzero\n", flavors[1]);
    try testing.expectEqual(@as(u32, 2), try fills_reached(arena, &macho, "fill_probe.probe_a"));
}

test "a called function's fills count, a panic handler's do not, and a cycle counts once" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const text = "\t.type\t.Lfill_probe.probe_a,@function\n" ++
        ".Lfill_probe.probe_a:\n" ++
        "\tcall\t.Llookup.Lookup.init_in_place\n" ++
        "\tcall\t\".Ldebug.FullPanic((function 'defaultPanic')).integerOverflow\"\n" ++
        "\t.type\t.Llookup.Lookup.init_in_place,@function\n" ++
        ".Llookup.Lookup.init_in_place:\n" ++
        "\tcall\tmemset@PLT\n" ++
        "\tcall\t.Lresponse.Answers.reset\n" ++
        "\t.type\t.Lresponse.Answers.reset,@function\n" ++
        ".Lresponse.Answers.reset:\n" ++
        "\tcall\tmemset@PLT\n" ++
        "\tcall\t.Llookup.Lookup.init_in_place\n" ++
        "\t.type\t\".Ldebug.FullPanic((function 'defaultPanic')).integerOverflow\",@function\n" ++
        "\".Ldebug.FullPanic((function 'defaultPanic')).integerOverflow\":\n" ++
        "\tcall\tmemset@PLT\n";
    const functions = try parse(arena, text, flavors[0]);
    try testing.expectEqual(@as(u32, 2), try fills_reached(arena, &functions, "fill_probe.probe_a"));
}

test "a basic block's label starts no function, and its fills stay with the function" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const elf = try parse(arena, "\t.type\t.Lfill_probe.probe_a,@function\n.Lfill_probe.probe_a:\n.LBB0_1:\n\tcall\tmemset@PLT\n\tjmp\t.LBB0_1\n", flavors[0]);
    try testing.expectEqual(@as(usize, 1), elf.count());
    try testing.expectEqual(@as(u32, 1), try fills_reached(arena, &elf, "fill_probe.probe_a"));
    const macho = try parse(arena, "l_fill_probe.probe_a:\nLBB0_1:\n\tbl\t_bzero\n\tb\tLBB0_1\n", flavors[1]);
    try testing.expectEqual(@as(usize, 1), macho.count());
    try testing.expectEqual(@as(u32, 1), try fills_reached(arena, &macho, "fill_probe.probe_a"));
    try testing.expectEqual(@as(usize, 0), macho.getPtr("fill_probe.probe_a").?.callees.items.len);
}

test "a count off the known one fails either way, and so does a known probe that is gone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const functions = try parse(arena, "l_fill_probe.probe_a:\n\tbl\t_memset\nl_fill_probe.probe_b:\n\tret\n", flavors[1]);
    const table = [_]Known{
        .{ .target = "x86_64-linux-gnu", .probe = "probe_a", .fills = 1 },
        .{ .target = "aarch64-macos", .probe = "probe_b", .fills = 3 },
    };
    try testing.expectEqual(@as(usize, 0), (try compare(arena, &functions, "x86_64-linux-gnu", &table)).len);
    const more = try compare(arena, &functions, "x86_64-linux-gnu", table[1..]);
    try testing.expectEqual(@as(usize, 1), more.len);
    try testing.expectEqualStrings("probe_a", more[0].probe);
    const fewer = try compare(arena, &functions, "aarch64-macos", &table);
    try testing.expectEqual(@as(usize, 2), fewer.len);
    const gone = [_]Known{.{ .target = "x86_64-linux-gnu", .probe = "probe_c", .fills = 1 }};
    const missing = try compare(arena, &functions, "x86_64-linux-gnu", &(table[0..1].* ++ gone));
    try testing.expectEqual(@as(usize, 1), missing.len);
    try testing.expectEqualStrings("probe_c", missing[0].probe);
}

test "assembly with no probe in it is refused, not passed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const functions = try parse(arena, "l_lookup.Lookup.init:\n\tbl\t_memset\n", flavors[1]);
    try testing.expectError(error.NoProbes, compare(arena, &functions, "aarch64-macos", &known));
}
