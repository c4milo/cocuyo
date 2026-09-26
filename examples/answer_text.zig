//! What the engine examples share: a question read from its text, and an answer written out one
//! record to a line, which is what the live and interop checks read.
//!
//! A question is `name` or `name/TYPE`, the type spelled as `cocuyo.Kind` spells it, in either
//! case: `example.com/MX`. A name alone asks for A. An answer prints as
//!
//!     <name> <TYPE> <fields> (ttl <seconds>)
//!
//! for each address and each record kept, and `<name> canonical <target>` for the end of a CNAME
//! chain. A record kept as rdata prints through `cocuyo.wire.rdata`'s view of its type. A type
//! this file has no view for prints in RFC 3597 §5's generic form, `\# <length> <hex>`.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rdata = cocuyo.wire.rdata;

/// The longest type name a question may spell: `naptr`, and room to spare.
const type_text_bytes_max = 16;
/// SvcParamKeys the example writes by name (RFC 9460 §14.3.2): the rest as `key<number>`.
const svcb_key_alpn = 1;
const svcb_key_port = 3;
const svcb_params_max = 16;
const alpn_ids_max = 16;
const name_text_bytes_max = cocuyo.constants.name_text_bytes_max;

/// A question from `name` or `name/TYPE`.
pub fn question_of(text: []const u8) !cocuyo.Question {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return cocuyo.Question.from_text(text, .a);
    const type_text = text[slash + 1 ..];
    var lower: [type_text_bytes_max]u8 = undefined;
    if (type_text.len > lower.len) return error.UnknownType;
    const kind = std.meta.stringToEnum(cocuyo.Kind, std.ascii.lowerString(&lower, type_text)) orelse return error.UnknownType;
    if (!kind.queryable()) return error.UnknownType;
    return cocuyo.Question.from_text(text[0..slash], kind);
}

/// Writes every address, name and record the answer holds, under `label`. Fails when a record
/// kept is one its type's view refuses, which the lookup should never have kept.
pub fn report(label: []const u8, answer: *const cocuyo.Answer) !void {
    var text: [name_text_bytes_max]u8 = undefined;
    if (answer.canonical_name) |canonical| {
        std.debug.print("{s} canonical {s}\n", .{ label, text[0..canonical.write_text(&text)] });
    }
    for (answer.addresses) |address| address_line(label, &address, answer.ttl_seconds);
    for (answer.names) |name| {
        std.debug.print("{s} PTR {s} (ttl {d})\n", .{ label, text[0..name.write_text(&text)], answer.ttl_seconds });
    }
    const records = answer.records orelse return;
    for (0..answer.record_count) |index| try record_line(label, records.at(index));
}

/// An IPv4 address in dotted decimal, and an IPv6 one as eight groups of hexadecimal, none left
/// out.
fn address_line(label: []const u8, address: *const cocuyo.Address, ttl_seconds: u32) void {
    const octets = address.slice();
    if (address.family == .ipv4) {
        std.debug.print("{s} A {d}.{d}.{d}.{d} (ttl {d})\n", .{ label, octets[0], octets[1], octets[2], octets[3], ttl_seconds });
        return;
    }
    std.debug.print("{s} AAAA ", .{label});
    for (0..octets.len / 2) |group| {
        const value = std.mem.readInt(u16, octets[group * 2 ..][0..2], .big);
        std.debug.print("{s}{x}", .{ if (group == 0) "" else ":", value });
    }
    std.debug.print(" (ttl {d})\n", .{ttl_seconds});
}

fn record_line(label: []const u8, kept: cocuyo.wire.Kept) !void {
    var type_text: [type_text_bytes_max]u8 = undefined;
    const kind = cocuyo.Kind.from_code(kept.kind_code);
    const type_name = if (kind) |named| std.ascii.upperString(&type_text, @tagName(named)) else try std.fmt.bufPrint(&type_text, "TYPE{d}", .{kept.kind_code});
    std.debug.print("{s} {s} ", .{ label, type_name });
    try fields(kind, kept.rdata);
    std.debug.print(" (ttl {d})\n", .{kept.ttl_seconds});
}

fn fields(kind: ?cocuyo.Kind, octets: []const u8) !void {
    const named = kind orelse return generic_fields(octets);
    switch (named) {
        .mx => try mx_fields(octets),
        .txt => try txt_fields(octets),
        .svcb, .https => try svcb_fields(octets),
        .srv => try srv_fields(octets),
        .ns, .cname, .ptr => try name_field(try rdata.name.whole(octets)),
        else => generic_fields(octets),
    }
}

fn name_field(name: cocuyo.Name) !void {
    var text: [name_text_bytes_max]u8 = undefined;
    std.debug.print("{s}", .{text[0..name.write_text(&text)]});
}

fn mx_fields(octets: []const u8) !void {
    const mx = try rdata.Mx.parse(octets);
    std.debug.print("{d} ", .{mx.preference});
    try name_field(mx.exchange);
}

fn srv_fields(octets: []const u8) !void {
    const srv = try rdata.Srv.parse(octets);
    std.debug.print("{d} {d} {d} ", .{ srv.priority, srv.weight, srv.port });
    try name_field(srv.target);
}

/// Each character-string quoted, a space between two (RFC 1035 §5.1).
fn txt_fields(octets: []const u8) !void {
    var strings = try rdata.Txt.strings(octets);
    for (0..octets.len) |index| {
        const string = try strings.next() orelse return;
        std.debug.print("{s}\"{s}\"", .{ if (index == 0) "" else " ", string });
    }
}

/// The priority and the target, then each SvcParam: `alpn` and `port` with their values, as RFC
/// 9460 §7.1 and §7.2 write them, and any other key as `key<number>` alone.
fn svcb_fields(octets: []const u8) !void {
    const svcb = try rdata.Svcb.parse(octets);
    std.debug.print("{d} ", .{svcb.priority});
    try name_field(svcb.target);
    var params = svcb.params();
    for (0..svcb_params_max) |_| {
        const param = try params.next() orelse return;
        switch (param.key) {
            svcb_key_alpn => try alpn_value(param.value),
            svcb_key_port => std.debug.print(" port={d}", .{std.mem.readInt(u16, param.value[0..2], .big)}),
            else => std.debug.print(" key{d}", .{param.key}),
        }
    }
}

/// An alpn value's protocol ids, commas between them (RFC 9460 §7.1.1).
fn alpn_value(value: []const u8) !void {
    std.debug.print(" alpn=", .{});
    var at: usize = 0;
    for (0..alpn_ids_max) |index| {
        if (at == value.len) return;
        const id = try rdata.string.read(value, at);
        std.debug.print("{s}{s}", .{ if (index == 0) "" else ",", id.bytes });
        at = id.end;
    }
}

/// `\# <length> <hex>` (RFC 3597 §5).
fn generic_fields(octets: []const u8) void {
    std.debug.print("\\# {d} ", .{octets.len});
    for (octets) |octet| std.debug.print("{x:0>2}", .{octet});
}

// Tests.

const testing = std.testing;

test "a name asks for A, and a name with a type asks for that type, spelled in either case" {
    try testing.expectEqual(cocuyo.Kind.a, (try question_of("example.com")).kind);
    try testing.expectEqual(cocuyo.Kind.mx, (try question_of("example.com/MX")).kind);
    try testing.expectEqual(cocuyo.Kind.https, (try question_of("example.com/https")).kind);
    const question = try question_of("example.com/AAAA");
    try testing.expect(question.name.equal(&try cocuyo.Name.from_text("example.com")));
}

test "a type cocuyo does not name, or one that is never a question, is refused" {
    try testing.expectError(error.UnknownType, question_of("example.com/NOPE"));
    try testing.expectError(error.UnknownType, question_of("example.com/OPT"));
    try testing.expectError(error.UnknownType, question_of("example.com/" ++ "A" ** 20));
}
