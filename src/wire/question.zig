//! The question section: the qname, qtype and qclass a query carries (RFC 1035 §4.1.2), and the
//! comparison a response must pass.
//!
//! That comparison is byte-exact, case included, and it is check 5 of docs/design.md §7. The case
//! is not incidental: DNS-0x20 puts about one bit of entropy in every letter of the qname, and a
//! server must echo the question section unchanged, so comparing case-insensitively would throw
//! that entropy away. A response whose question came back folded is not our response. One that
//! came back in lowercase can still say that its server lowercases the name, which
//! `matches_lowercase` reads, and which never makes a response ours (§7, A server that changes
//! the case).
//!
//! The question name is never compressed. Compression points backwards to an earlier name
//! (RFC 1035 §4.1.4) and the question is the first name in the message, so a pointer there could
//! only point into the header.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const Kind = core.Kind;
const constants = @import("constants.zig");
const integer = @import("integer.zig");
const name_codec = @import("name.zig");

/// The octets a question section occupies: the name, then qtype and qclass.
pub fn section_bytes(name: *const Name) usize {
    assert(name.len >= 1);
    // A maximal name is 255 octets and the fixed part is four more, so the sum does not fit the
    // octet the length is held in.
    const length: usize = name.len;
    assert(length <= core.constants.name_bytes_max);
    return length + core.constants.question_fixed_bytes;
}

/// Writes one question section at the start of `out`, and returns the octets written. The name is
/// written exactly as it is held, so a name the caller has case-mixed goes out mixed.
pub fn write(name: *const Name, kind: Kind, out: []u8) usize {
    assert(kind.queryable());
    assert(out.len >= section_bytes(name));
    var offset = name_codec.encode(name, out);
    integer.write_u16(out, offset, kind.code());
    offset += constants.u16_bytes;
    integer.write_u16(out, offset, core.constants.class_internet);
    offset += constants.u16_bytes;
    assert(offset == section_bytes(name));
    return offset;
}

/// Whether `message`'s question section is byte-identical to the question that was asked: the same
/// name with the same case, the same type, and class IN.
///
/// This reads the message's own question area and compares it against what the lookup holds, so
/// no copy of the sent bytes has to be kept anywhere (docs/design.md §16 decision 3).
pub fn matches(message: []const u8, name: *const Name, kind: Kind) bool {
    return section_matches(message, name, kind, .exact);
}

/// Whether `message`'s question section is the question that was asked with every ASCII letter
/// of its name small: the same type and class IN, and the name as a server that lowercases it
/// echoes it (docs/design.md §7, A server that changes the case). Never a reason to accept a
/// response: check 5 is `matches`.
pub fn matches_lowercase(message: []const u8, name: *const Name, kind: Kind) bool {
    return section_matches(message, name, kind, .lowercase);
}

const Case = enum { exact, lowercase };

fn section_matches(message: []const u8, name: *const Name, kind: Kind, comptime case: Case) bool {
    assert(name.len >= 1);
    const start = core.constants.header_bytes;
    const end = start + section_bytes(name);
    if (message.len < end) return false;
    assert(end <= message.len);
    const echoed = message[start..][0..name.len];
    const same = switch (case) {
        .exact => std.mem.eql(u8, echoed, name.wire()),
        .lowercase => is_lowercase_of(echoed, name.wire()),
    };
    if (!same) return false;
    if (integer.read_u16(message, start + name.len) != kind.code()) return false;
    return integer.read_u16(message, start + name.len + constants.u16_bytes) ==
        core.constants.class_internet;
}

/// Whether `echoed` is `asked` with every capital made small. Only that spelling is taken, and no
/// mixed name has it (`name.mix_case`), so an echo of another mixed query never passes.
fn is_lowercase_of(echoed: []const u8, asked: []const u8) bool {
    assert(echoed.len == asked.len);
    for (echoed, asked) |echoed_octet, asked_octet| {
        // The same name: "a lookup string octet with a value in the inclusive range from 0x41 to
        // 0x5A, the uppercase ASCII letters, MUST match the identical value and also match the
        // corresponding value in the inclusive range from 0x61 to 0x7A" (RFC 4343 §3, clarifying
        // RFC 1035 §2.3.3). A length octet is at most 63, never a letter, and matches exactly.
        if (echoed_octet != std.ascii.toLower(asked_octet)) return false;
    }
    return true;
}

comptime {
    // Folding a length octet as a letter would let one label length pass for another.
    assert(core.constants.label_bytes_max < 'A');
}

/// The question section of `message`, for a reader that does not already know what was asked: the
/// fuzz target and the harness. The name is decompressed into `out`.
pub const Parsed = struct {
    kind_code: u16,
    class: u16,
    end: usize,
};

pub fn parse(message: []const u8, out: *Name) Error!Parsed {
    const start = core.constants.header_bytes;
    if (message.len < start) return Error.MalformedMessage;
    const after_name = try name_codec.decode(message, start, out);
    if (after_name + core.constants.question_fixed_bytes > message.len) {
        return Error.MalformedMessage;
    }
    assert(after_name >= start);
    const parsed: Parsed = .{
        .kind_code = integer.read_u16(message, after_name),
        .class = integer.read_u16(message, after_name + constants.u16_bytes),
        .end = after_name + core.constants.question_fixed_bytes,
    };
    if (parsed.class != core.constants.class_internet) return Error.UnsupportedClass;
    return parsed;
}

// Tests.

const testing = std.testing;

const query_message = @import("fixtures.zig").query_a;

test "a question section writes the name, the type and class IN" {
    const name = try Name.from_text("example.com");
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    const written = write(&name, .a, &out);
    try testing.expectEqual(section_bytes(&name), written);
    try testing.expectEqualStrings("\x07example\x03com\x00\x00\x01\x00\x01", out[0..written]);
}

test "matches accepts the question that was asked" {
    const name = try Name.from_text("example.com");
    try testing.expect(matches(&query_message, &name, .a));
}

test "matches refuses a different name, type or case" {
    const name = try Name.from_text("example.com");
    try testing.expect(!matches(&query_message, &try Name.from_text("example.net"), .a));
    try testing.expect(!matches(&query_message, &name, .aaaa));

    // The same name with one letter's case flipped: this is the DNS-0x20 check.
    var mixed = name;
    mixed.bytes[1] = 'E';
    try testing.expect(mixed.equal(&name));
    try testing.expect(!matches(&query_message, &mixed, .a));
}

test "matches_lowercase takes the name asked with every letter small, and nothing else" {
    var mixed = try Name.from_text("example.com");
    mixed.bytes[1] = 'E';
    mixed.bytes[9] = 'C';
    // The question asked was mixed and the echo is lowercase: equal but for the case.
    try testing.expect(!matches(&query_message, &mixed, .a));
    try testing.expect(matches_lowercase(&query_message, &mixed, .a));
    // An echo with a capital is not the lowercase spelling: the case asked, or another mixed one.
    var asked = query_message;
    asked[core.constants.header_bytes + 1] = 'E';
    asked[core.constants.header_bytes + 9] = 'C';
    try testing.expect(matches(&asked, &mixed, .a) and !matches_lowercase(&asked, &mixed, .a));
    var other_case = query_message;
    other_case[core.constants.header_bytes + 2] = 'X';
    try testing.expect(!matches_lowercase(&other_case, &mixed, .a));
    const other_label = try Name.from_text("example.net");
    const other_letter = try Name.from_text("examplf.com");
    try testing.expect(!matches_lowercase(&query_message, &other_label, .a));
    try testing.expect(!matches_lowercase(&query_message, &other_letter, .a));
    try testing.expect(!matches_lowercase(&query_message, &mixed, .aaaa));
    var chaos = query_message;
    chaos[chaos.len - 1] = 3; // class CH
    try testing.expect(!matches_lowercase(&chaos, &mixed, .a));
    const short = query_message[0 .. query_message.len - 1];
    try testing.expect(!matches_lowercase(short, &mixed, .a));
}

test "matches refuses a message too short to hold the question" {
    const name = try Name.from_text("example.com");
    try testing.expect(!matches(query_message[0 .. query_message.len - 1], &name, .a));
    try testing.expect(!matches(query_message[0..core.constants.header_bytes], &name, .a));
}

test "parse reads the question a message carries" {
    var name: Name = Name.empty;
    const parsed = try parse(&query_message, &name);
    try testing.expect(name.equal(&try Name.from_text("example.com")));
    try testing.expectEqual(@as(u16, 1), parsed.kind_code);
    try testing.expectEqual(@as(u16, 1), parsed.class);
    try testing.expectEqual(query_message.len, parsed.end);
}

test "parse refuses a class cocuyo does not query and a truncated section" {
    var name: Name = Name.empty;
    var chaos = query_message;
    chaos[chaos.len - 1] = 3; // class CH
    try testing.expectError(Error.UnsupportedClass, parse(&chaos, &name));
    try testing.expectError(
        Error.MalformedMessage,
        parse(query_message[0 .. query_message.len - 1], &name),
    );
}
