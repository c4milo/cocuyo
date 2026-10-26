//! The question section: the qname, qtype and qclass a query carries (RFC 1035 §4.1.2), and the
//! comparison a response must pass.
//!
//! That comparison is byte-exact, case included, and it is check 5 of docs/design.md §7. The case
//! is not incidental: DNS-0x20 puts about one bit of entropy in every letter of the qname, and a
//! server must echo the question section unchanged, so comparing case-insensitively would throw
//! that entropy away. A response whose question came back folded is not our response. One that
//! came back in lowercase can still say that its server lowercases the name, which
//! `matches_lowercase` reads, and which never makes a response to a mixed query ours (§7, A server
//! that changes the case). A query that mixed the case is checked by `matches_mixed`, which reads
//! the echo against the case its seed gives the name, in place, rather than against a cased copy.
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
    assert(length <= core.limits.name_bytes_max);
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
    return section_matches(message, name, kind, .exact, case_seed_none);
}

/// `matches` for a query whose name `wire.name.mix_case` cased from `entropy`: `name` is the name
/// as held, and the echo is read in place against the case that seed gives it
/// (`wire.name.is_mix_of`), so a response is checked without a cased copy of the name
/// (docs/design.md §7 check 5).
pub fn matches_mixed(message: []const u8, name: *const Name, kind: Kind, entropy: u64) bool {
    return section_matches(message, name, kind, .mixed, entropy);
}

/// Whether `message`'s question section is the question that was asked with every ASCII letter
/// of its name small: the same type and class IN, and the name as a server that lowercases it
/// echoes it (docs/design.md §7, A server that changes the case). Never a reason to accept a
/// response to a query that mixed the case, whose check 5 is `matches_mixed`. For a query asked in
/// lowercase it is check 5, read in place: that query's name is `name` with every letter small.
pub fn matches_lowercase(message: []const u8, name: *const Name, kind: Kind) bool {
    return section_matches(message, name, kind, .lowercase, case_seed_none);
}

/// How the echoed name is held to the name: byte for byte, in lowercase, or as a seed mixes it.
const Case = enum { exact, lowercase, mixed };

/// The seed a compare that mixes no case is passed, and never reads.
const case_seed_none: u64 = 0;

fn section_matches(
    message: []const u8,
    name: *const Name,
    kind: Kind,
    comptime case: Case,
    entropy: u64,
) bool {
    assert(name.len >= 1);
    // `usize`, not the `u8` a name's length is held in: the class of a question whose name is 242
    // octets or more lies past octet 255 of the message (12 + 242 + 2 = 256), and a name runs to
    // 255 octets (RFC 1035 §2.3.4).
    const start: usize = core.constants.header_bytes;
    const end = start + section_bytes(name);
    if (message.len < end) return false;
    assert(end <= message.len);
    // The type and the class first: two loads at the offset this name ends at. A question of a
    // name of another length seldom holds them there, so it is refused before its name is read
    // octet by octet.
    if (integer.read_u16(message, start + name.len) != kind.code()) return false;
    const class = integer.read_u16(message, start + name.len + constants.u16_bytes);
    if (class != core.constants.class_internet) return false;
    const echoed = message[start..][0..name.len];
    return switch (case) {
        .exact => std.mem.eql(u8, echoed, name.wire()),
        .lowercase => is_lowercase_of(echoed, name.wire()),
        .mixed => name_codec.is_mix_of(echoed, name, entropy),
    };
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
    assert(core.limits.label_bytes_max < 'A');
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
    var out: [core.limits.query_bytes_max]u8 = @splat(0);
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

/// `query_message` with its question's name replaced by `name`, of the same length.
fn with_name(name: *const Name) [query_message.len]u8 {
    var message = query_message;
    assert(name.len == query_name_bytes);
    @memcpy(message[core.constants.header_bytes..][0..name.len], name.wire());
    return message;
}

/// The octets of the name `query_message` asks, `example.com`, in wire form.
const query_name_bytes = "\x07example\x03com\x00".len;

test "matches_mixed takes the question a mixed query asked, and refuses what matches refuses" {
    const held = try Name.from_text("example.com");
    const entropy = 0x0123456789abcdef;
    var cased = held;
    name_codec.mix_case(&cased, entropy);
    const asked = with_name(&cased);
    try testing.expect(matches(&asked, &cased, .a));
    try testing.expect(matches_mixed(&asked, &held, .a, entropy));
    // Another seed's case, the name as held, the type AAAA, class CH, and a message cut short.
    try testing.expect(!matches_mixed(&asked, &held, .a, entropy + 1));
    try testing.expect(!matches_mixed(&query_message, &held, .a, entropy));
    try testing.expect(!matches_mixed(&asked, &held, .aaaa, entropy));
    var chaos = asked;
    chaos[chaos.len - 1] = 3; // class CH
    try testing.expect(!matches_mixed(&chaos, &held, .a, entropy));
    try testing.expect(!matches_mixed(asked[0 .. asked.len - 1], &held, .a, entropy));
    // A name of another length: the echo is read for the name's octets alone.
    try testing.expect(!matches_mixed(&asked, &try Name.from_text("example.co"), .a, entropy));
}

test "the lowercase compare reads the same against the name as held, mixed and folded" {
    // A response is held to `matches_lowercase` over the name as held: by `case_change` for the
    // name a mixed query sent, and by check 5 for a server asked in lowercase, which compares
    // with the folded name byte for byte (docs/design.md §7).
    const held = try Name.from_text("Example.COM");
    var cased = held;
    name_codec.mix_case(&cased, 0x0123456789abcdef);
    var folded = held;
    folded.fold_case();
    var upper = folded;
    for (upper.bytes[0..upper.len]) |*octet| octet.* = std.ascii.toUpper(octet.*);
    for ([_]Name{ held, cased, folded, upper, try Name.from_text("example.net") }) |echo| {
        const message = with_name(&echo);
        const lowercase = matches_lowercase(&message, &held, .a);
        try testing.expectEqual(lowercase, matches_lowercase(&message, &cased, .a));
        try testing.expectEqual(lowercase, matches(&message, &folded, .a));
    }
    try testing.expect(matches_lowercase(&with_name(&folded), &held, .a));
}

/// A name of `length` octets in wire form, of letters: labels of 63 octets, then one of the rest.
fn long_name(length: usize) !Name {
    const letters: [core.limits.label_bytes_max]u8 = @splat('x');
    var name: Name = Name.empty;
    var rest = length - 1; // the root's octet
    for (0..core.limits.labels_max) |_| {
        if (rest == 0) break;
        // `usize`: `@min` with 63 gives a `u6`, which its length octet's 1 overflows.
        const label: usize = @min(rest - 1, letters.len);
        try name.append_label(letters[0..label]);
        rest -= 1 + label;
    }
    try name.terminate();
    return name;
}

/// The question of `name` and type A after a header of zeros, written into `out`.
fn question_message(name: *const Name, out: *[long_message_bytes]u8) []const u8 {
    out.* = @splat(0);
    const written = write(name, .a, out[core.constants.header_bytes..]);
    return out[0 .. core.constants.header_bytes + written];
}

/// The octets a question of the longest name occupies, with the header before it.
const long_message_bytes: usize = core.constants.header_bytes + core.limits.name_bytes_max +
    core.constants.question_fixed_bytes;

test "a question of a name of 242 octets or more matches itself, its class past octet 255" {
    // Its class lies past octet 255 of the message, and from 244 octets its type too, where offsets
    // summed in the `u8` a name's length is held in overflowed; 241 is the longest that did not.
    const entropy = 0x0123456789abcdef;
    for ([_]usize{ 241, 242, 243, 244, core.limits.name_bytes_max }) |length| {
        const held = try long_name(length);
        try testing.expectEqual(length, @as(usize, held.len));
        var cased = held;
        name_codec.mix_case(&cased, entropy);
        var asked_buffer: [long_message_bytes]u8 = undefined;
        var mixed_buffer: [long_message_bytes]u8 = undefined;
        const asked = question_message(&held, &asked_buffer);
        const mixed = question_message(&cased, &mixed_buffer);
        try testing.expect(matches(asked, &held, .a) and !matches(asked, &held, .aaaa));
        try testing.expect(matches(mixed, &cased, .a) and !matches(mixed, &held, .a));
        // The name asked in lowercase, read against the name as held and as the mix cased it.
        try testing.expect(matches_lowercase(asked, &held, .a));
        try testing.expect(matches_lowercase(asked, &cased, .a));
        try testing.expect(!matches_lowercase(mixed, &held, .a));
        // Another name of the same length, its last letter another: refused by each compare.
        var other = held;
        other.bytes[held.len - 2] = 'y';
        try testing.expect(!matches(asked, &other, .a) and !matches_lowercase(asked, &other, .a));
    }
}

test "a question of the most labels a name holds is written, read back and matched" {
    // 127 labels of one letter are 254 octets, and the root's makes 255 (RFC 1035 §2.3.4).
    const most = try Name.from_text("a." ** 126 ++ "a");
    try testing.expectEqual(@as(usize, core.limits.name_bytes_max), most.len);
    var buffer: [long_message_bytes]u8 = undefined;
    const message = question_message(&most, &buffer);
    var read: Name = Name.empty;
    const parsed = try parse(message, &read);
    try testing.expectEqual(message.len, parsed.end);
    try testing.expectEqualSlices(u8, most.wire(), read.wire());
    try testing.expect(matches(message, &read, .a) and matches_lowercase(message, &read, .a));
    // One octet short of the class: refused, and not read.
    const short = message[0 .. message.len - 1];
    try testing.expectError(Error.MalformedMessage, parse(short, &read));
    try testing.expect(!matches(short, &most, .a) and !matches_lowercase(short, &most, .a));
}

/// Requires `matches_mixed` to take the question of `held` as `entropy` mixes its name, and to
/// refuse it as held, under another seed, of another type, cut short, with its last letter in
/// the other case, and with that letter another.
fn expect_mixed_in_place(held: *const Name, entropy: u64) !void {
    var cased = held.*;
    name_codec.mix_case(&cased, entropy);
    var asked_buffer: [long_message_bytes]u8 = undefined;
    var mixed_buffer: [long_message_bytes]u8 = undefined;
    const asked = question_message(held, &asked_buffer);
    const mixed = question_message(&cased, &mixed_buffer);
    try testing.expect(matches(mixed, &cased, .a) and matches_mixed(mixed, held, .a, entropy));
    try testing.expect(!matches_mixed(asked, held, .a, entropy));
    try testing.expect(!matches_mixed(mixed, held, .a, entropy + 1));
    try testing.expect(!matches_mixed(mixed, held, .aaaa, entropy));
    try testing.expect(!matches_mixed(mixed[0 .. mixed.len - 1], held, .a, entropy));
    // Its last letter in the other case: each letter has a bit of its own, in whichever word.
    const last_letter = core.constants.header_bytes + @as(usize, held.len) - last_letter_from_end;
    mixed_buffer[last_letter] ^= core.constants.ascii_case_bit;
    try testing.expect(!matches_mixed(mixed, held, .a, entropy));
    // That letter another: the type and the class are read, where they lie, and then the name.
    mixed_buffer[last_letter] = 'y';
    try testing.expect(!matches_mixed(mixed, held, .a, entropy));
}

/// Where a name's last letter lies before its end: the root's octet follows it.
const last_letter_from_end: usize = 2;

test "matches_mixed takes a question of a name of 241 octets or more, read in place" {
    // The type and the class are read before the name, past octet 255 of the message from names
    // of 244 and 242 octets on (the long-name test above). These names hold 236 to 250 letters,
    // so the compare draws their cases from four words.
    const entropy = 0x0123456789abcdef;
    for ([_]usize{ 241, 242, 243, 244, core.limits.name_bytes_max }) |length| {
        const held = try long_name(length);
        try testing.expectEqual(length, @as(usize, held.len));
        try expect_mixed_in_place(&held, entropy);
    }
    // The most labels a name holds: a length octet between every two of its 127 letters.
    const most = try Name.from_text("a." ** 126 ++ "a");
    try testing.expectEqual(@as(usize, core.limits.name_bytes_max), most.len);
    try expect_mixed_in_place(&most, entropy);
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
