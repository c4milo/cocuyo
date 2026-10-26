//! The shape of a value the typed-constants rule reads (`typed_constants.zig`): whether a `const`
//! is a `comptime_int` by its written type or by the shape of its value. The rule's header lists
//! the shapes, and its tests pin each one (docs/design.md §16 decisions 40 and 56).
const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const pepegrillo = @import("pepegrillo");
const ast = pepegrillo.lint.ast;

/// Whether a `const` is a `comptime_int`: its type is written as `comptime_int`, or no type is
/// written and its value is integer-shaped.
pub fn has_no_type(tree: *const Ast, declaration: Ast.full.VarDecl) bool {
    if (declaration.ast.type_node.unwrap()) |written| return names_comptime_int(tree, written);
    const value = declaration.ast.init_node.unwrap() orelse return false;
    return integer_shaped(tree, value, 0);
}

/// Whether `node` is the identifier `comptime_int`.
fn names_comptime_int(tree: *const Ast, node: Node.Index) bool {
    if (tree.nodeTag(node) != .identifier) return false;
    return std.mem.eql(u8, tree.tokenSlice(tree.nodeMainToken(node)), "comptime_int");
}

/// The builtins that give a `comptime_int` when their operands are comptime integers.
const comptime_int_builtins = [_][]const u8{
    "@sizeOf", "@bitSizeOf", "@alignOf",  "@offsetOf", "@bitOffsetOf",
    "@min",    "@max",       "@divExact", "@divFloor", "@divTrunc",
    "@mod",    "@rem",       "@shlExact", "@shrExact", "@abs",
};

/// The functions of `std.math` that give a `comptime_int`.
const comptime_int_functions = [_][]const u8{ "maxInt", "minInt" };

/// Whether `node` is a value the compiler holds as a `comptime_int`, by its shape alone.
pub fn integer_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    if (depth > ast.max_tree_depth) return false;
    return switch (tree.nodeTag(node)) {
        .number_literal => is_integer_literal(tree, node),
        .char_literal => true,
        .negation, .negation_wrap, .bit_not => integer_shaped(tree, tree.nodeData(node).node, depth + 1),
        .grouped_expression => integer_shaped(tree, tree.nodeData(node).node_and_token[0], depth + 1),
        .add, .sub, .mul, .div, .mod, .shl, .shr, .bit_and, .bit_or, .bit_xor => true,
        .add_wrap, .sub_wrap, .mul_wrap, .add_sat, .sub_sat, .mul_sat, .shl_sat => true,
        .builtin_call_two, .builtin_call_two_comma, .builtin_call, .builtin_call_comma => builtin_shaped(tree, node),
        .call_one, .call_one_comma, .call, .call_comma => calls_comptime_int(tree, node),
        .@"if", .if_simple => if_shaped(tree, node, depth),
        .@"switch", .switch_comma => switch_shaped(tree, node, depth),
        .block, .block_semicolon, .block_two, .block_two_semicolon => block_shaped(tree, node, depth),
        else => false,
    };
}

fn is_integer_literal(tree: *const Ast, node: Node.Index) bool {
    const literal = tree.tokenSlice(tree.nodeMainToken(node));
    return switch (std.zig.number_literal.parseNumberLiteral(literal)) {
        .int, .big_int => true,
        .float, .failure => false,
    };
}

/// Whether a builtin gives a `comptime_int`: one of `comptime_int_builtins`, or `@as` whose type
/// is `comptime_int`.
fn builtin_shaped(tree: *const Ast, node: Node.Index) bool {
    const builtin = tree.tokenSlice(tree.nodeMainToken(node));
    if (is_any(builtin, &comptime_int_builtins)) return true;
    if (!std.mem.eql(u8, builtin, "@as")) return false;
    var buffer: [2]Node.Index = undefined;
    const parameters = tree.builtinCallParams(&buffer, node).?;
    return parameters.len != 0 and names_comptime_int(tree, parameters[0]);
}

/// Whether a prong of a `switch` is integer-shaped: then the `switch` is a `comptime_int` too.
fn switch_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    const full = tree.fullSwitch(node).?;
    for (full.ast.cases) |case| {
        const prong = tree.fullSwitchCase(case).?;
        if (integer_shaped(tree, prong.ast.target_expr, depth + 1)) return true;
    }
    return false;
}

/// Whether a `break` in a block gives an integer-shaped value: then a labeled block is a
/// `comptime_int` too. It reads each `break` in the block, whatever its label.
fn block_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    var finder: BreakFinder = .{ .tree = tree, .depth = depth };
    ast.for_each_child(tree, node, &finder);
    return finder.found;
}

/// The walk of a block that looks for a `break` with an integer-shaped value.
const BreakFinder = struct {
    tree: *const Ast,
    depth: u32,
    found: bool = false,

    pub fn child(self: *BreakFinder, node: Node.Index) void {
        if (self.found or self.depth > ast.max_tree_depth) return;
        if (self.tree.nodeTag(node) == .@"break") {
            const value = self.tree.nodeData(node).opt_token_and_opt_node[1].unwrap() orelse return;
            self.found = integer_shaped(self.tree, value, self.depth + 1);
            return;
        }
        self.depth += 1;
        defer self.depth -= 1;
        ast.for_each_child(self.tree, node, self);
    }
};

/// Whether either branch of an `if` is integer-shaped: then the `if` is a `comptime_int` too.
fn if_shaped(tree: *const Ast, node: Node.Index, depth: u32) bool {
    const full = tree.fullIf(node).?;
    if (integer_shaped(tree, full.ast.then_expr, depth + 1)) return true;
    const otherwise = full.ast.else_expr.unwrap() orelse return false;
    return integer_shaped(tree, otherwise, depth + 1);
}

/// Whether a call names `maxInt` or `minInt` last: `std.math.maxInt(u16)` or `math.minInt(i8)`.
fn calls_comptime_int(tree: *const Ast, node: Node.Index) bool {
    var buffer: [1]Node.Index = undefined;
    const call = tree.fullCall(&buffer, node).?;
    return is_any(tree.tokenSlice(tree.lastToken(call.ast.fn_expr)), &comptime_int_functions);
}

fn is_any(text: []const u8, names: []const []const u8) bool {
    for (names) |candidate| {
        if (std.mem.eql(u8, text, candidate)) return true;
    }
    return false;
}
