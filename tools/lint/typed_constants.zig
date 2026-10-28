//! typed-constants: every integer constant of `src/` and `io/` carries a type, and every limit
//! lives in a limits file (docs/design.md §16 decisions 40 and 56).
//!
//! The type. An integer constant with no type is a `comptime_int`. When it meets a runtime
//! integer, the sum takes the runtime integer's type. So `header_bytes + name.len` was a sum in
//! the octet that holds a name's length, and it overflowed from a name of 244 octets
//! (docs/mutations.md, Sums at the most their operands reach). A constant of type `usize` makes
//! that sum a `usize`.
//!
//! The rule reads each Zig file of `src/` and `io/`. It reads each `const` that is a member of a
//! container: the file's top level, or a `struct`, `union`, `enum` or `opaque` in it. It reports
//! such a `const` when its type is `comptime_int`. It also reports it when it has no type and its
//! value is integer-shaped (`typed_constants_shape.zig`). These values are integer-shaped:
//!
//! - an integer literal or a character literal;
//! - an arithmetic, bitwise or shift operator, whatever its operands are;
//! - a builtin that gives a `comptime_int` from comptime operands, such as `@sizeOf` or `@min`;
//! - `@as(comptime_int, ...)`;
//! - a call of `maxInt` or `minInt`;
//! - a negation, a bitwise not, parentheses, or an `if`, around one of these;
//! - a `switch` with one of these in a prong, and a block with one of these in a `break`.
//!
//! A prong or a `break` of another type can make a false report. A written type ends it.
//!
//! The rule does not report an identifier or a field access. That is an alias, and it has the type
//! of what it names. It does not report another call, which has its return type, or `@as` of
//! another type. It does not read an `orelse`, a `catch` or an index into a tuple. It does not read
//! the constants of a function body or of a `comptime` block. The test in each constants file and
//! limits file reads the types of its public constants, and it catches what this rule cannot see:
//! an alias of a constant with no type, or a call that gives a `comptime_int`.
//!
//! The rule cannot see a sum of two narrow runtime values with no constant in it. The type of the
//! sum is the type of its operands, and no constant is there to widen it.
//!
//! The place. A limit is a bound the code holds or checks. Its name ends in `_max`, `_min`,
//! `_limit` or `_least`, and it lives in a limits file: a Zig file whose stem has the word `limits`
//! between its underscores, or a Zig file under a directory named `limits`. So the rule reports a
//! `const` at the top level of any other file of `src/` and `io/` when its name ends in one of
//! those suffixes and its value is no alias. A constants file is such a file: it holds the protocol
//! sizes and the defaults alone. An alias of a limit is no limit of its own.
//!
//! The name. The rule reads a limit by its name, so a limit with no suffix can live in any file.
//! So the rule also reports a `const` at the top level of a limits file when its name has none of
//! those suffixes, alias or not (docs/design.md §17 question 78). It passes an import. It passes a
//! name that ends in `_count`, the count of seeds that a fuzz gate runs (§17 question 90). The
//! place check does not read `_count`, because the count of a test ends in it too.
//!
//! The place has three bounds. A limit with no suffix outside a limits file passes. The rule reads
//! no test file, whose stem ends in `_test` or holds `_test_`, and no `fixtures.zig`: their bounds
//! are a test's own. It reads the top level of a file alone: a member of a type is that type's
//! interface.
//!
//! The rule is cocuyo's own, and the only rule here that is not pepegrillo's.
const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const ast = lint.ast;
const report = lint.report;
const shape = @import("typed_constants_shape.zig");

pub const Config = struct {
    /// The rule name findings are reported under and `--rule` selects.
    name: []const u8 = "typed-constants",
    /// The files the rule reads.
    scope: lint.Scope,
};

/// The configuration: the Zig files of the library and of the engine. `bench/` and `tools/` are
/// outside it, since neither is linked into the library.
pub const config: Config = .{
    .scope = .{ .extensions = &.{".zig"}, .include_directories = &.{ "src", "io" } },
};

/// The part of a name that makes a file a limits file, or a directory a directory of them.
const limits_name = "limits";

/// The endings of a limit's name: a most, a least, a limit, and a least that an RFC states as "at
/// least" beside a `_min` of `Config` with another meaning (docs/design.md §16 decision 60).
const limit_suffixes = [_][]const u8{ "_max", "_min", "_limit", "_least" };

/// The ending of a count in a limits file that is no bound with a suffix: the seeds of a fuzz gate.
const count_suffix = "_count";

/// The builtin that names another file. A `const` that holds one is no constant of its file.
const import_builtin = "@import";

/// The stem segment of a test file, and the basename of a module's fixtures.
const test_segment = "_test";
const fixtures_basename = "fixtures.zig";

/// Whether the rule reads `path`: a Zig file of the scope.
fn reads_file(scope: *const lint.Scope, path: []const u8) bool {
    return scope.applies(path);
}

/// Whether `path` is a limits file: a file whose stem has the word `limits` between its
/// underscores, or a file under a directory named `limits`. So the pieces of a split limits file
/// are limits files too, and a stem such as `delimits` is not.
fn is_limits_file(path: []const u8) bool {
    const basename = lint.paths.basename(path);
    const stem = basename[0 .. std.mem.lastIndexOfScalar(u8, basename, '.') orelse basename.len];
    var words = std.mem.splitScalar(u8, stem, '_');
    while (words.next()) |word| {
        if (std.mem.eql(u8, word, limits_name)) return true;
    }
    return lint.paths.is_under(path, limits_name);
}

/// Whether the rule reads the place of the limits of `path`: no limits file, no test file and no
/// fixtures file.
fn places_limits(path: []const u8) bool {
    if (is_limits_file(path)) return false;
    const basename = lint.paths.basename(path);
    if (std.mem.eql(u8, basename, fixtures_basename)) return false;
    const stem = basename[0 .. std.mem.lastIndexOfScalar(u8, basename, '.') orelse basename.len];
    if (std.mem.endsWith(u8, stem, test_segment)) return false;
    return std.mem.indexOf(u8, stem, test_segment ++ "_") == null;
}

/// Whether a name ends in one of `limit_suffixes`.
fn is_limit_name(constant: []const u8) bool {
    for (limit_suffixes) |suffix| {
        if (std.mem.endsWith(u8, constant, suffix)) return true;
    }
    return false;
}

const Rule = TypedConstants(config);
pub const name = Rule.name;
pub const check = Rule.check;

/// The rule for one configuration: a type with the `name` and `check` the driver dispatches to.
fn TypedConstants(comptime rule_config: Config) type {
    comptime std.debug.assert(rule_config.name.len != 0);
    return struct {
        pub const name = rule_config.name;
        const settings: Config = rule_config;

        pub fn check(context: *report.Context, file: report.File) !void {
            if (!reads_file(&settings.scope, file.path)) return;
            const tree = file.tree orelse return;
            var visitor: Visitor = .{
                .tree = tree,
                .findings = &context.findings,
                .path = file.path,
                .name = settings.name,
            };
            visitor.check_members(tree.rootDecls());
            if (places_limits(file.path)) visitor.check_places(tree.rootDecls());
            if (is_limits_file(file.path)) visitor.check_names(tree.rootDecls());
            if (visitor.failure) |failure| return failure;
        }
    };
}

const Visitor = struct {
    tree: *const Ast,
    findings: *report.Findings,
    path: []const u8,
    name: []const u8,
    depth: u32 = 0,
    failure: ?anyerror = null,

    /// Each member of one container, and each container inside a member.
    fn check_members(self: *Visitor, members: []const Node.Index) void {
        for (members) |member| {
            if (self.tree.fullVarDecl(member)) |declaration| self.check_declaration(declaration);
            ast.for_each_child(self.tree, member, self);
        }
    }

    /// The walk below a member. It looks for containers, and reads no `const` that is not a
    /// container's member.
    pub fn child(self: *Visitor, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        var buffer: [2]Node.Index = undefined;
        if (self.tree.fullContainerDecl(&buffer, node)) |container| {
            return self.check_members(container.ast.members);
        }
        ast.for_each_child(self.tree, node, self);
    }

    fn check_declaration(self: *Visitor, declaration: Ast.full.VarDecl) void {
        if (self.tree.tokenTag(declaration.ast.mut_token) != .keyword_const) return;
        if (!shape.has_no_type(self.tree, declaration)) return;
        self.report_constant(declaration, "const {s} is an integer with no type: write the type of what it names");
    }

    /// Each limit at the top level of a file that is no limits file: a `const` whose name ends in
    /// one of `limit_suffixes` and whose value is no alias.
    fn check_places(self: *Visitor, members: []const Node.Index) void {
        for (members) |member| {
            const declaration = self.tree.fullVarDecl(member) orelse continue;
            if (self.tree.tokenTag(declaration.ast.mut_token) != .keyword_const) continue;
            if (!is_limit_name(self.tree.tokenSlice(declaration.ast.mut_token + 1))) continue;
            const value = declaration.ast.init_node.unwrap() orelse continue;
            if (is_alias(self.tree, value)) continue;
            self.report_constant(declaration, "const {s} is a limit: name it in its module's limits.zig");
        }
    }

    /// Each `const` at the top level of a limits file whose name is no limit's: none of
    /// `limit_suffixes` and no `count_suffix`. An import is no constant of the file.
    fn check_names(self: *Visitor, members: []const Node.Index) void {
        for (members) |member| {
            const declaration = self.tree.fullVarDecl(member) orelse continue;
            if (self.tree.tokenTag(declaration.ast.mut_token) != .keyword_const) continue;
            const constant = self.tree.tokenSlice(declaration.ast.mut_token + 1);
            if (is_limit_name(constant) or std.mem.endsWith(u8, constant, count_suffix)) continue;
            const value = declaration.ast.init_node.unwrap() orelse continue;
            if (is_import(self.tree, value)) continue;
            self.report_constant(declaration, "const {s} is in a limits file: end its name in _max, _min, _limit or _least");
        }
    }

    fn report_constant(self: *Visitor, declaration: Ast.full.VarDecl, comptime format: []const u8) void {
        const name_token = declaration.ast.mut_token + 1;
        const location = ast.token_location(self.tree, name_token);
        self.findings.add(
            self.name,
            self.path,
            location.line,
            location.column,
            format,
            .{self.tree.tokenSlice(name_token)},
        ) catch |failure| {
            self.failure = failure;
        };
    }
};

/// Whether a value is an alias: an identifier or a field access, which names a constant that is
/// declared elsewhere.
fn is_alias(tree: *const Ast, value: Node.Index) bool {
    return switch (tree.nodeTag(value)) {
        .identifier, .field_access => true,
        else => false,
    };
}

/// Whether a value is an import, or a field of one, such as `core` of the `cocuyo` module.
fn is_import(tree: *const Ast, value: Node.Index) bool {
    var node = value;
    while (tree.nodeTag(node) == .field_access) node = tree.nodeData(node).node_and_token[0];
    const builtin = switch (tree.nodeTag(node)) {
        .builtin_call_two, .builtin_call_two_comma => tree.tokenSlice(tree.nodeMainToken(node)),
        else => return false,
    };
    return std.mem.eql(u8, builtin, import_builtin);
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try harness.expect_messages(try harness.run(arena_state.allocator(), Rule, path, source), expected);
}

fn message(comptime constant: []const u8) []const u8 {
    return "const " ++ constant ++ " is an integer with no type: write the type of what it names";
}

test "typed-constants reports a literal, an operator and a builtin with no type" {
    try expect_findings("src/core/constants.zig",
        \\pub const header_bytes = 12;
        \\pub const comment_start = '#';
        \\pub const negative = -1;
        \\pub const sum = header_bytes + 4;
        \\pub const mask = (1 << 8) - 1;
        \\pub const wrapped = header_bytes +% 4;
        \\pub const octet_bits = @bitSizeOf(u8);
        \\pub const least = @min(header_bytes, 4);
        \\pub const most = std.math.maxInt(u16);
        \\pub const chosen = if (header_bytes > 4) 1 else 2;
        \\pub const grouped = (4);
        \\const private_bytes = 3;
        \\
    , &.{
        message("header_bytes"), message("comment_start"), message("negative"),
        message("sum"),          message("mask"),          message("wrapped"),
        message("octet_bits"),   message("least"),         message("most"),
        message("chosen"),       message("grouped"),       message("private_bytes"),
    });
}

test "typed-constants reports a switch, a labeled block, @abs and a comptime_int type" {
    try expect_findings("src/core/constants.zig",
        \\pub const page_bytes = switch (builtin.cpu.arch) {
        \\    .x86_64 => 4096,
        \\    else => 16384,
        \\};
        \\pub const chunk_bytes = chunk: {
        \\    const half = @as(u16, 512);
        \\    break :chunk half * 2;
        \\};
        \\pub const distance = @abs(-4);
        \\pub const pinned: comptime_int = 4;
        \\pub const cast = @as(comptime_int, 4);
        \\pub const typed_switch = switch (builtin.cpu.arch) {
        \\    .x86_64 => @as(u16, 4096),
        \\    else => @as(u16, 16384),
        \\};
        \\pub const typed_block = chunk: {
        \\    break :chunk @as(u16, 1024);
        \\};
        \\pub const typed_cast = @as(u16, 4);
        \\
    , &.{
        message("page_bytes"), message("chunk_bytes"), message("distance"),
        message("pinned"),     message("cast"),
    });
}

test "typed-constants reads a container's members, and no function's or block's locals" {
    try expect_findings("io/io_quic_constants.zig",
        \\pub const Limits = struct {
        \\    pub const inner_bytes = 8;
        \\    pub fn sweep(count: usize) usize {
        \\        const local = 4;
        \\        return count * local;
        \\    }
        \\};
        \\comptime {
        \\    const unpadded = 12 + 255;
        \\    _ = unpadded;
        \\}
        \\test "a test's constant" {
        \\    const expected = 3;
        \\    _ = expected;
        \\}
        \\
    , &.{message("inner_bytes")});
}

test "typed-constants passes a typed constant, an alias, a call and every value of another type" {
    try expect_findings("io/constants.zig",
        \\const std = @import("std");
        \\const core = @import("core");
        \\pub const header_bytes: usize = 12;
        \\pub const typed_sum: usize = header_bytes + 4;
        \\pub var counter = 0;
        \\pub const alias = core.constants.servers_max;
        \\pub const local_alias = header_bytes;
        \\pub const length = prefix.len;
        \\pub const prefix = [_]u8{ 1, 2 };
        \\pub const keyword = "nameserver";
        \\pub const seconds = 2.5;
        \\pub const Row = struct { bits: u8 };
        \\pub const size = std.base64.url_safe_no_pad.Encoder.calcSize(384);
        \\pub const named = @as(u16, 443);
        \\pub const kind = .label;
        \\pub const truth = 4 > 3;
        \\
    , &.{});
}

fn place(comptime constant: []const u8) []const u8 {
    return "const " ++ constant ++ " is a limit: name it in its module's limits.zig";
}

test "typed-constants reports a limit in a constants file and in any file that is no limits file" {
    try expect_findings("src/core/constants.zig",
        \\pub const header_bytes: usize = 12;
        \\pub const records_max: usize = 64;
        \\pub const port_ephemeral_min: u16 = 49152;
        \\pub const ndots_limit: usize = 15;
        \\pub const candidates_max: usize = search_max + 1;
        \\pub const timeout_ns_max_default: u64 = 5_000_000_000;
        \\pub const failure_seconds_least: u32 = 1;
        \\pub const seed_count: usize = 4096;
        \\
    , &.{
        place("records_max"),    place("port_ephemeral_min"),    place("ndots_limit"),
        place("candidates_max"), place("failure_seconds_least"),
    });
    try expect_findings("io/io_quic_plain.zig",
        \\const level_bytes_max: usize = 512;
        \\
    , &.{place("level_bytes_max")});
}

test "typed-constants passes a limit in a limits file, an alias of one, and a member of a type" {
    try expect_findings("src/core/limits.zig",
        \\pub const records_max: usize = 64;
        \\
    , &.{});
    try expect_findings("io/io_quic_limits.zig",
        \\pub const params_bytes_max: usize = 256;
        \\
    , &.{});
    try expect_findings("src/core/constants.zig",
        \\pub const records_max = limits.records_max;
        \\pub const servers_max = core.limits.servers_max;
        \\pub fn sweep_steps_max(slot_count: usize) usize {
        \\    const steps_max: usize = 2;
        \\    return slot_count * steps_max;
        \\}
        \\pub const Transport = struct {
        \\    pub const output_bytes_max: usize = 0;
        \\};
        \\
    , &.{});
}

fn unnamed(comptime constant: []const u8) []const u8 {
    return "const " ++ constant ++ " is in a limits file: end its name in _max, _min, _limit or _least";
}

test "typed-constants reports a constant of a limits file with no limit's name" {
    try expect_findings("io/io_doh_channel_limits.zig",
        \\const std = @import("std");
        \\const core = @import("cocuyo").core;
        \\const constants = @import("io_doh_channel_constants.zig");
        \\pub const chunk_bytes: usize = 2048;
        \\pub const window_bytes = chunk_bytes;
        \\pub const room = core.limits.message_bytes_max;
        \\pub const chunk_bytes_max: usize = 2048;
        \\pub const failure_seconds_least = core.limits.cache_failure_seconds_least;
        \\pub const fuzz_seed_count: usize = 4096;
        \\pub fn sweep_steps_max(slot_count: usize) usize {
        \\    const steps: usize = 2;
        \\    return slot_count * steps;
        \\}
        \\
    , &.{ unnamed("chunk_bytes"), unnamed("window_bytes"), unnamed("room") });
    try expect_findings("src/core/constants.zig",
        \\pub const chunk_bytes: usize = 2048;
        \\
    , &.{});
}

test "typed-constants reads the place of no limit in a test file or in the fixtures" {
    const source =
        \\const rounds_max: usize = 64;
        \\
    ;
    try expect_findings("io/io_quic_test.zig", source, &.{});
    try expect_findings("io/io_tcp_test_rig.zig", source, &.{});
    try expect_findings("src/wire/fixtures.zig", source, &.{});
    try expect_findings("io/io_tested.zig", source, &.{place("rounds_max")});
    try expect_findings("src/wire/fixtures_extra.zig", source, &.{place("rounds_max")});
}

fn reads(path: []const u8) bool {
    return reads_file(&config.scope, path);
}

test "typed-constants reads every Zig file of src/ and io/, and nothing else" {
    try testing.expect(reads("src/core/constants.zig"));
    try testing.expect(reads("src/core/limits.zig"));
    try testing.expect(reads("io/io_quic_constants.zig"));
    try testing.expect(reads("io/io_quic_limits.zig"));
    try testing.expect(reads("src/core/name.zig"));
    try testing.expect(reads("io/io_quic_plain.zig"));
    try testing.expect(reads("io/io_quic_test.zig"));
    try testing.expect(!reads("bench/end_to_end/constants.zig"));
    try testing.expect(!reads("tools/constants.zig"));
    try testing.expect(!reads("src/core/constants.md"));
}

test "typed-constants takes the pieces of a split limits file for limits files, and no other" {
    try testing.expect(is_limits_file("src/core/limits.zig"));
    try testing.expect(is_limits_file("src/core/limits_address.zig"));
    try testing.expect(is_limits_file("io/io_doh_channel_limits.zig"));
    try testing.expect(is_limits_file("io/io_quic_limits_server.zig"));
    try testing.expect(is_limits_file("src/core/limits/address.zig"));
    try testing.expect(!is_limits_file("src/core/constants.zig"));
    try testing.expect(!is_limits_file("src/core/limit.zig"));
    try testing.expect(!is_limits_file("io/io_delimits.zig"));
    try testing.expect(!is_limits_file("src/core/sublimits_check.zig"));
}
