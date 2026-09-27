//! One record against dnslib's line for it (`check.zig`). Every record's owner, TTL, class and type
//! are compared. Then its rdata is copied out with every name written in full
//! (`wire.record_copy`), and the copy is read through the view of its type, each field of which
//! must be the one dnslib printed in master-file form (RFC 1035 §5.1).
//!
//! A type cocuyo does not name has no view. dnslib prints such a record either in the generic form
//! of RFC 3597 §5, whose octets are compared, or by a mnemonic cocuyo does not know, in which case
//! the record is copied whole and nothing more. Either way the copy must be the rdata as it came,
//! since a type a receiver does not know carries no compressed name (RFC 3597 §4).
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const text = @import("check_text.zig");
const Name = core.Name;
const Kind = core.Kind;
const Record = wire.Record;
const rdata = wire.rdata;

/// Why a record and its line disagree.
pub const Mismatch = error{
    /// The line could not be read, or a field of it is not the kind of text its place holds.
    Text,
    /// cocuyo refused, or could not copy, octets dnslib read.
    Codec,
    Owner,
    Ttl,
    Class,
    Type,
    Rdata,
    /// A type cocuyo names that this check has no reading of: no response in dnslib's directory
    /// holds one, and a new one must bring its comparison with it.
    Unread,
};

/// How the records were compared.
pub const Tally = struct {
    records: usize = 0,
    /// Read through the view of a type cocuyo names.
    typed: usize = 0,
    /// Printed in RFC 3597 §5's generic form, and compared as octets.
    generic: usize = 0,
    /// Of a type cocuyo does not name, printed by a mnemonic it does not know: copied whole.
    copied: usize = 0,
};

/// The fields before the rdata: the owner, the TTL, the class and the type (RFC 1035 §5.1).
const head_fields = 4;
/// The room a line's quoted fields take once their escapes are undone: never more than the line.
const line_bytes_max = 1 << 16;
/// The room a copy takes. An rdata holds at most 65,535 octets (RFC 1035 §3.2.1), and writing its
/// names out in full can make it longer, so this is twice that. A copy that needs more is reported
/// rather than cut.
const copy_bytes_max = 1 << 17;
const decimal_base = 10;
const hex_base = 16;
const hex_digits = 2;

/// The class dnslib prints for IN, the Internet (RFC 1035 §3.2.4).
const class_internet_text = "IN";
/// "The word "TYPE" immediately followed by the decimal RR type number" (RFC 3597 §5).
const generic_type_prefix = "TYPE";
/// "The special token \#" that opens an rdata in the generic form (RFC 3597 §5).
const generic_token = "\\#";

pub fn check(message: []const u8, record: *const Record, line: []const u8, tally: *Tally) Mismatch!void {
    var scratch: [line_bytes_max]u8 = undefined;
    const fields = text.split(line, &scratch) catch return Mismatch.Text;
    const items = fields.slice();
    if (items.len < head_fields) return Mismatch.Text;
    try check_head(message, record, items[0..head_fields]);
    var copy_buffer: [copy_bytes_max]u8 = undefined;
    const written = wire.record_copy.copy_out(message, record, &copy_buffer) catch return Mismatch.Codec;
    const copy = copy_buffer[0 .. written orelse return Mismatch.Codec];
    const kind = Kind.from_code(record.kind_code);
    if (kind == null and !std.mem.eql(u8, copy, record.rdata)) return Mismatch.Codec;
    const rest = items[head_fields..];
    if (rest.len > 0 and std.mem.eql(u8, rest[0], generic_token)) {
        try check_generic(record.rdata, rest[1..]);
        tally.generic += 1;
    } else if (kind) |named| {
        try check_typed(named, record, copy, rest);
        tally.typed += 1;
    } else {
        tally.copied += 1;
    }
    tally.records += 1;
}

fn check_head(message: []const u8, record: *const Record, head: []const []const u8) Mismatch!void {
    std.debug.assert(head.len == head_fields);
    var owner: Name = .empty;
    record.owner_name(message, &owner) catch return Mismatch.Codec;
    const printed = try name_of(head[0]);
    if (!owner.equal(&printed)) return Mismatch.Owner;
    if (record.ttl_seconds != try number(u32, head[1])) return Mismatch.Ttl;
    if (!std.mem.eql(u8, head[2], class_internet_text)) return Mismatch.Class;
    if (record.class != core.constants.class_internet) return Mismatch.Class;
    if (!type_agrees(head[3], record.kind_code)) return Mismatch.Type;
}

/// Whether dnslib's mnemonic names the type the record carries. A type cocuyo names must be
/// printed by its name, and any type may be printed in the generic form (RFC 3597 §5). A mnemonic
/// cocuyo does not know is taken for what it says, as long as it is not one cocuyo knows.
fn type_agrees(mnemonic: []const u8, type_code: u16) bool {
    if (std.mem.startsWith(u8, mnemonic, generic_type_prefix)) {
        const digits = mnemonic[generic_type_prefix.len..];
        if (std.fmt.parseInt(u16, digits, decimal_base)) |printed| return printed == type_code else |_| {}
    }
    if (Kind.from_code(type_code)) |kind| return std.ascii.eqlIgnoreCase(@tagName(kind), mnemonic);
    for (std.enums.values(Kind)) |kind| {
        if (std.ascii.eqlIgnoreCase(@tagName(kind), mnemonic)) return false;
    }
    return true;
}

fn check_typed(kind: Kind, record: *const Record, copy: []const u8, fields: []const []const u8) Mismatch!void {
    return switch (kind) {
        .a, .aaaa => check_address(record, fields),
        .ns, .cname, .ptr => check_name(copy, fields),
        .mx => check_mx(copy, fields),
        .soa => check_soa(copy, fields),
        .txt => check_txt(copy, fields),
        .srv => check_srv(copy, fields),
        .naptr => check_naptr(copy, fields),
        .tlsa => check_tlsa(copy, fields),
        .hinfo, .sig, .opt, .svcb, .https, .any, .uri, .caa => Mismatch.Unread,
        _ => Mismatch.Unread,
    };
}

fn check_address(record: *const Record, fields: []const []const u8) Mismatch!void {
    try arity(fields, 1);
    const address = record.address() catch return Mismatch.Codec;
    const printed = core.Address.from_text(fields[0]) orelse return Mismatch.Text;
    if (!address.equal(&printed)) return Mismatch.Rdata;
}

fn check_name(copy: []const u8, fields: []const []const u8) Mismatch!void {
    try arity(fields, 1);
    const name = rdata.name.whole(copy) catch return Mismatch.Codec;
    try same_name(&name, fields[0]);
}

fn check_mx(copy: []const u8, fields: []const []const u8) Mismatch!void {
    try arity(fields, 2);
    const mx = rdata.Mx.parse(copy) catch return Mismatch.Codec;
    try same_number(mx.preference, fields[0]);
    try same_name(&mx.exchange, fields[1]);
}

fn check_soa(copy: []const u8, fields: []const []const u8) Mismatch!void {
    try arity(fields, 7);
    const soa = rdata.Soa.parse(copy) catch return Mismatch.Codec;
    try same_name(&soa.mname, fields[0]);
    try same_name(&soa.rname, fields[1]);
    try same_number(soa.serial, fields[2]);
    try same_number(soa.refresh, fields[3]);
    try same_number(soa.retry, fields[4]);
    try same_number(soa.expire, fields[5]);
    try same_number(soa.minimum, fields[6]);
}

/// Each character-string of the rdata against one quoted field, in order, and no string left over
/// on either side (RFC 1035 §3.3.14).
fn check_txt(copy: []const u8, fields: []const []const u8) Mismatch!void {
    var strings = rdata.Txt.strings(copy) catch return Mismatch.Codec;
    for (fields) |field| {
        const string = (strings.next() catch return Mismatch.Codec) orelse return Mismatch.Rdata;
        if (!std.mem.eql(u8, string, field)) return Mismatch.Rdata;
    }
    if ((strings.next() catch return Mismatch.Codec) != null) return Mismatch.Rdata;
}

fn check_srv(copy: []const u8, fields: []const []const u8) Mismatch!void {
    try arity(fields, 4);
    const srv = rdata.Srv.parse(copy) catch return Mismatch.Codec;
    try same_number(srv.priority, fields[0]);
    try same_number(srv.weight, fields[1]);
    try same_number(srv.port, fields[2]);
    try same_name(&srv.target, fields[3]);
}

fn check_naptr(copy: []const u8, fields: []const []const u8) Mismatch!void {
    try arity(fields, 6);
    const naptr = rdata.Naptr.parse(copy) catch return Mismatch.Codec;
    try same_number(naptr.order, fields[0]);
    try same_number(naptr.preference, fields[1]);
    try same_bytes(naptr.flags, fields[2]);
    try same_bytes(naptr.services, fields[3]);
    try same_bytes(naptr.regexp, fields[4]);
    try same_name(&naptr.replacement, fields[5]);
}

fn check_tlsa(copy: []const u8, fields: []const []const u8) Mismatch!void {
    if (fields.len < 4) return Mismatch.Rdata;
    const tlsa = rdata.Tlsa.parse(copy) catch return Mismatch.Codec;
    try same_number(tlsa.usage, fields[0]);
    try same_number(tlsa.selector, fields[1]);
    try same_number(tlsa.matching_type, fields[2]);
    try same_hex(tlsa.data, fields[3..]);
}

/// The length, then the octets in hexadecimal (RFC 3597 §5).
fn check_generic(octets: []const u8, fields: []const []const u8) Mismatch!void {
    if (fields.len == 0) return Mismatch.Text;
    if (octets.len != try number(u16, fields[0])) return Mismatch.Rdata;
    try same_hex(octets, fields[1..]);
}

fn arity(fields: []const []const u8, count: usize) Mismatch!void {
    if (fields.len != count) return Mismatch.Rdata;
}

fn number(comptime T: type, field: []const u8) Mismatch!T {
    return std.fmt.parseInt(T, field, decimal_base) catch Mismatch.Text;
}

fn same_number(value: anytype, field: []const u8) Mismatch!void {
    if (value != try number(@TypeOf(value), field)) return Mismatch.Rdata;
}

fn name_of(field: []const u8) Mismatch!Name {
    return Name.from_text(field) catch Mismatch.Text;
}

fn same_name(name: *const Name, field: []const u8) Mismatch!void {
    const printed = try name_of(field);
    if (!name.equal(&printed)) return Mismatch.Rdata;
}

fn same_bytes(bytes: []const u8, field: []const u8) Mismatch!void {
    if (!std.mem.eql(u8, bytes, field)) return Mismatch.Rdata;
}

/// Whether `octets` are what the hexadecimal `fields` write, which a master file may split into as
/// many words as it likes, each of an even number of digits (RFC 3597 §5).
fn same_hex(octets: []const u8, fields: []const []const u8) Mismatch!void {
    var at: usize = 0;
    for (fields) |field| {
        if (field.len % hex_digits != 0) return Mismatch.Text;
        for (0..field.len / hex_digits) |index| {
            const pair = field[index * hex_digits ..][0..hex_digits];
            const octet = std.fmt.parseInt(u8, pair, hex_base) catch return Mismatch.Text;
            if (at == octets.len or octets[at] != octet) return Mismatch.Rdata;
            at += 1;
        }
    }
    if (at != octets.len) return Mismatch.Rdata;
}

// Tests. Each builds a response with one answer, owned by `example.com` with TTL 300, and holds it
// against a line dnslib could have printed for it.

const testing = std.testing;
const rdata_fixtures = wire.rdata.fixtures;
const owner_line = "example.com. 300 IN ";

fn one_answer(comptime type_code: u16, comptime octets: []const u8) [wire.fixtures.answer_offset + 12 + octets.len]u8 {
    const header = [_]u8{ 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const type_octets = [_]u8{ type_code >> 8, type_code & 0xff };
    const question = rdata_fixtures.name_example ++ type_octets ++ [_]u8{ 0x00, 0x01 };
    const record = rdata_fixtures.name_pointer ++ type_octets ++ [_]u8{ 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c } ++
        [_]u8{ octets.len >> 8, octets.len & 0xff };
    return header ++ question ++ record ++ octets[0..octets.len].*;
}

fn check_one(message: []const u8, line: []const u8, tally: *Tally) Mismatch!void {
    var records = wire.record.Iterator.init(message, wire.fixtures.answer_offset, 1);
    const record = (records.next() catch unreachable).?;
    std.debug.assert(record.end == message.len);
    return check(message, &record, line, tally);
}

test "a record of each type dnslib's directory holds agrees with the line for it" {
    const cases = .{
        .{ one_answer(15, &rdata_fixtures.mx), "MX 10 mail.example.com." },
        .{ one_answer(33, &rdata_fixtures.srv), "SRV 10 20 5269 sip.EXAMPLE.com." },
        .{ one_answer(6, &rdata_fixtures.soa), "SOA ns1.example.com. hostmaster.example.com. 2026092201 7200 900 1209600 300" },
        .{ one_answer(35, &rdata_fixtures.naptr), "NAPTR 100 50 \"s\" \"SIP+D2U\" \"\" _sip._udp.example.com." },
        .{ one_answer(16, &rdata_fixtures.txt_two), "TXT \"hello\" \"w\\111rld\"" },
        .{ one_answer(52, &rdata_fixtures.tlsa), "TLSA 3 1 1 " ++ "AB" ** 16 ++ " " ++ "ab" ** 16 },
        .{ one_answer(2, &rdata_fixtures.name_example), "NS example.com." },
        .{ one_answer(28, &([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1})), "AAAA 2001:db8::1" },
    };
    var tally: Tally = .{};
    inline for (cases) |case| try check_one(&case[0], owner_line ++ case[1], &tally);
    try testing.expectEqual(@as(usize, cases.len), tally.typed);
    try testing.expectEqual(@as(usize, cases.len), tally.records);
}

test "a type cocuyo does not name is compared as generic octets, or copied whole" {
    const octets = [_]u8{ 0x0d, 0xd5, 0xc6, 0x00, 0x01 };
    var tally: Tally = .{};
    try check_one(&one_answer(65534, &octets), owner_line ++ "TYPE65534 \\# 5 0DD5C6 0001", &tally);
    try check_one(&one_answer(46, &octets), owner_line ++ "RRSIG A 8 2 300 20190412195152", &tally);
    try check_one(&one_answer(1, &.{ 192, 0, 2, 1 }), owner_line ++ "A \\# 4 C0000201", &tally);
    try testing.expectEqual(Tally{ .records = 3, .generic = 2, .copied = 1 }, tally);
    const cases = .{
        .{ "TYPE65534 \\# 5 0DD5C60002", Mismatch.Rdata },
        .{ "TYPE65534 \\# 4 0DD5C600", Mismatch.Rdata },
        .{ "TYPE65534 \\# 4 0DD5C60001", Mismatch.Rdata },
        .{ "TYPE65534 \\# 5 0DD5C6000", Mismatch.Text },
        .{ "TYPE65535 \\# 5 0DD5C60001", Mismatch.Type },
        .{ "MX \\# 5 0DD5C60001", Mismatch.Type },
    };
    inline for (cases) |case| {
        try testing.expectError(case[1], check_one(&one_answer(65534, &octets), owner_line ++ case[0], &tally));
    }
}

test "a line that differs from its record in any field is a mismatch" {
    const mx = one_answer(15, &rdata_fixtures.mx);
    const cases = .{
        .{ "www.example.com. 300 IN MX 10 mail.example.com.", Mismatch.Owner },
        .{ "example.com. 301 IN MX 10 mail.example.com.", Mismatch.Ttl },
        .{ "example.com. 300 CH MX 10 mail.example.com.", Mismatch.Class },
        .{ "example.com. 300 IN SRV 10 mail.example.com.", Mismatch.Type },
        .{ "example.com. 300 IN MX 20 mail.example.com.", Mismatch.Rdata },
        .{ "example.com. 300 IN MX 10 mail.example.net.", Mismatch.Rdata },
        .{ "example.com. 300 IN MX 10 mail.example.com. extra", Mismatch.Rdata },
        .{ "example.com. 300 IN MX ten mail.example.com.", Mismatch.Text },
        .{ "example.com. 300 IN", Mismatch.Text },
    };
    var tally: Tally = .{};
    inline for (cases) |case| try testing.expectError(case[1], check_one(&mx, case[0], &tally));
    try testing.expectEqual(Tally{}, tally);
}

test "strings, hexadecimal and names that differ are mismatches, and a type with no reading is unread" {
    var tally: Tally = .{};
    const txt = one_answer(16, &rdata_fixtures.txt_two);
    try testing.expectError(Mismatch.Rdata, check_one(&txt, owner_line ++ "TXT \"hello\"", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&txt, owner_line ++ "TXT \"hello\" \"world\" \"\"", &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&txt, owner_line ++ "TXT \"hello\" \"World\"", &tally));
    const tlsa = one_answer(52, &rdata_fixtures.tlsa);
    try testing.expectError(Mismatch.Rdata, check_one(&tlsa, owner_line ++ "TLSA 3 1 1 " ++ "AB" ** 31, &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&tlsa, owner_line ++ "TLSA 3 1 1 " ++ "AB" ** 33, &tally));
    try testing.expectError(Mismatch.Rdata, check_one(&tlsa, owner_line ++ "TLSA 3 1 2 " ++ "AB" ** 32, &tally));
    const naptr = one_answer(35, &rdata_fixtures.naptr);
    try testing.expectError(Mismatch.Rdata, check_one(&naptr, owner_line ++ "NAPTR 100 50 \"s\" \"SIP+D2T\" \"\" _sip._udp.example.com.", &tally));
    const soa = one_answer(6, &rdata_fixtures.soa);
    try testing.expectError(Mismatch.Rdata, check_one(&soa, owner_line ++ "SOA ns1.example.com. hostmaster.example.com. 2026092201 7200 901 1209600 300", &tally));
    const a = one_answer(1, &.{ 192, 0, 2, 1 });
    try testing.expectError(Mismatch.Rdata, check_one(&a, owner_line ++ "A 192.0.2.2", &tally));
    const caa = one_answer(257, &rdata_fixtures.caa);
    try testing.expectError(Mismatch.Unread, check_one(&caa, owner_line ++ "CAA 0 issue \"ca.example.net\"", &tally));
    try testing.expectEqual(Tally{}, tally);
}

test "a copy of a type cocuyo does not name that is not the rdata as it came is a mismatch" {
    const message = one_answer(65534, &.{ 0x0d, 0xd5, 0xc6, 0x00, 0x01 });
    var records = wire.record.Iterator.init(&message, wire.fixtures.answer_offset, 1);
    var record = (try records.next()).?;
    // The copy reads the message, so a record whose rdata says otherwise has been copied wrong.
    record.rdata = &.{ 0x0d, 0xd5, 0xc6, 0x00, 0x02 };
    var tally: Tally = .{};
    try testing.expectError(Mismatch.Codec, check(&message, &record, owner_line ++ "TYPE65534 \\# 5 0DD5C60002", &tally));
}
