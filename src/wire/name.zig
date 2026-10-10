//! Name decoding, and the DNS-0x20 case mixer.
//!
//! This is the file an attacker reaches first, so it is the file with the most bounds. A name in a
//! message may be a sequence of labels, or a compression pointer to a name earlier in the message,
//! or labels ending in such a pointer (RFC 1035 §4.1.4). Three rules bound it:
//!
//! 1. A pointer must point **strictly backwards**, at an offset below the pointer's own first
//!    octet. This alone makes a loop impossible, because every hop strictly decreases the offset.
//! 2. The hops are bounded by `compression_hops_max` anyway, so a long legal chain stays cheap.
//! 3. The name being built is bounded by `name_bytes_max` and `labels_max`, so the labels cannot
//!    grow without end between hops.
//!
//! Together those make the decode loop terminate: every iteration either appends a label, of
//! which there can be `labels_max`, or follows a pointer, of which there can be
//! `compression_hops_max`. Nothing recurses.
//!
//! Each of the three is a check that returns an error and an assertion that must not fire
//! (CLAUDE.md non-negotiable 6). The reserved label kinds `01` and `10` are refused rather than
//! ignored: RFC 6891 §6.1.1 retired the one experiment that used them.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const constants = @import("constants.zig");
const integer = @import("integer.zig");

/// Decodes the name encoded at `offset` into `out`, and returns the offset of the first octet
/// after that encoding: after the root octet, or after the first pointer, whichever ends it.
///
/// `out` holds an uncompressed copy, so the caller may reuse the message buffer the moment this
/// returns.
pub fn decode(message: []const u8, offset: usize, out: *Name) Error!usize {
    assert(message.len <= core.constants.message_bytes_max);
    assert(offset <= message.len);
    out.* = Name.empty;
    var walk: Walk = .{ .message = message, .cursor = offset };
    // Every step either appends a label or follows a pointer, and both are bounded, so the walk
    // ends whatever the message says.
    while (walk.labels <= core.constants.labels_max) {
        if (try walk.step(out)) |end| {
            assert(walk.hops <= core.constants.compression_hops_max);
            return end;
        }
    }
    assert(walk.labels > core.constants.labels_max);
    return Error.MalformedName;
}

/// What the octet at a cursor introduces (RFC 1035 §4.1.4).
const LabelKind = enum { label, pointer, reserved };

fn kind_of(length: u8) LabelKind {
    return switch (length & constants.label_kind_mask) {
        constants.label_kind_label => .label,
        constants.label_kind_pointer => .pointer,
        // `01` and `10`: RFC 6891 §5 retired the one experiment that used them.
        else => .reserved,
    };
}

/// One walk over one name. `end` is the offset after the name *as encoded where the walk started*,
/// which a pointer fixes at the pointer's own two octets however far the walk then jumps.
const Walk = struct {
    message: []const u8,
    cursor: usize,
    end: ?usize = null,
    hops: usize = 0,
    labels: usize = 0,

    /// One step. Returns the end offset when the name is complete, and null while it is not.
    fn step(self: *Walk, out: *Name) Error!?usize {
        if (self.cursor >= self.message.len) return Error.MalformedMessage;
        const length = self.message[self.cursor];
        return switch (kind_of(length)) {
            .pointer => try self.follow(),
            .label => try self.take(length, out),
            .reserved => return Error.MalformedName,
        };
    }

    /// Follows one compression pointer, which must point strictly backwards.
    fn follow(self: *Walk) Error!?usize {
        if (self.hops == core.constants.compression_hops_max) return Error.BadCompressionPointer;
        const target = try read_pointer(self.message, self.cursor);
        // Strictly backwards: a pointer at or ahead of itself is how a loop is built.
        if (target >= self.cursor) return Error.BadCompressionPointer;
        if (self.end == null) self.end = self.cursor + constants.pointer_bytes;
        self.cursor = target;
        self.hops += 1;
        assert(self.hops <= core.constants.compression_hops_max);
        return null;
    }

    /// Takes one label, or ends the name when the length octet is the root.
    fn take(self: *Walk, length: u8, out: *Name) Error!?usize {
        assert(length <= core.constants.label_bytes_max);
        if (length == 0) {
            try out.terminate();
            return self.end orelse self.cursor + 1;
        }
        try copy_label(self.message, self.cursor, length, out);
        self.cursor += 1 + length;
        self.labels += 1;
        return null;
    }
};

/// The offset after the name encoded at `offset`, without decompressing it. The record walk uses
/// this to reach a record's type before deciding whether the owner name is worth decoding
/// (docs/design.md §11).
///
/// A pointer ends the name here and is not followed, so this checks that the pointer's two octets
/// are inside the message and nothing more. A record the walk goes on to want has its owner name
/// decoded by `decode`, which is where a pointer is validated.
pub fn skip(message: []const u8, offset: usize) Error!usize {
    assert(message.len <= core.constants.message_bytes_max);
    assert(offset <= message.len);
    var cursor = offset;
    var labels: usize = 0;
    while (labels <= core.constants.labels_max) {
        if (cursor >= message.len) return Error.MalformedMessage;
        const length = message[cursor];
        switch (kind_of(length)) {
            .pointer => {
                if (cursor + constants.pointer_bytes > message.len) return Error.MalformedMessage;
                return cursor + constants.pointer_bytes;
            },
            .label => {
                if (length == 0) return cursor + 1;
                cursor += 1 + length;
                labels += 1;
            },
            .reserved => return Error.MalformedName,
        }
    }
    return Error.MalformedName;
}

/// Writes `name`'s wire bytes into `out` and returns the count. cocuyo compresses nothing it
/// sends: a query carries one question and has no earlier name to point at.
pub fn encode(name: *const Name, out: []u8) usize {
    assert(name.len >= 1);
    assert(out.len >= name.len);
    @memcpy(out[0..name.len], name.wire());
    return name.len;
}

/// Sets the case of every ASCII letter in `name` from `entropy`, one bit per letter: DNS-0x20
/// (RFC 5452 §9.2 recommends more entropy than the id alone, and this is where a stub finds it).
///
/// Only label octets are touched. A length octet is never a letter — a label is at most 63 and 'A'
/// is 65 — but this walks the labels rather than the bytes, so the invariant is structural and not
/// arithmetic.
///
/// A name with more letters than one word has bits re-mixes, so every letter gets its own bit
/// whatever the name's length.
///
/// A name with a letter comes back with a capital. A draw that leaves every letter small is drawn
/// again from the next word, up to `case_draws_max` draws, and then the first letter is made a
/// capital. So a name in lowercase is never the echo of a mixed one, which is how a lookup tells a
/// server that lowercases the name from an answer to another query of cocuyo's (docs/design.md §7,
/// A server that changes the case). A name of L letters takes one of 2^L - 1 cases, not 2^L.
pub fn mix_case(name: *Name, entropy: u64) void {
    assert(name.len >= 1);
    var word = entropy;
    var draws: usize = 0;
    while (draws < constants.case_draws_max) : (draws += 1) {
        const drawn = draw_case(name, word);
        if (drawn.capitals > 0 or drawn.letters == 0) return;
        word = drawn.word;
    }
    assert(draws == constants.case_draws_max);
    capitalize_first(name);
}

/// What one draw of `draw_case` did: the last word it read, and the letters it cased.
const Drawn = struct { word: u64, letters: usize, capitals: usize };

/// Cases every letter of `name` from its own bit of the words after `entropy`.
fn draw_case(name: *Name, entropy: u64) Drawn {
    var drawn: Drawn = .{ .word = core.mix.next(entropy), .letters = 0, .capitals = 0 };
    var used: usize = 0;
    var offset: usize = 0;
    var labels: usize = 0;
    while (labels <= core.constants.labels_max) {
        if (offset >= name.len) break;
        const length = name.bytes[offset];
        if (length == 0) break;
        assert(length <= core.constants.label_bytes_max);
        for (name.bytes[offset + 1 ..][0..length]) |*byte| {
            if (!is_letter(byte.*)) continue;
            if (used == core.mix.word_bits) {
                drawn.word = core.mix.next(drawn.word);
                used = 0;
            }
            byte.* = apply_case(byte.*, drawn.word >> @intCast(used));
            drawn.letters += 1;
            drawn.capitals += @intFromBool(is_capital(byte.*));
            used += 1;
        }
        offset += 1 + length;
        labels += 1;
    }
    assert(labels <= core.constants.labels_max);
    return drawn;
}

/// Makes the first letter of `name` a capital: the case `mix_case` falls back to.
fn capitalize_first(name: *Name) void {
    var offset: usize = 0;
    var labels: usize = 0;
    while (labels <= core.constants.labels_max) : (labels += 1) {
        if (offset >= name.len) break;
        const length = name.bytes[offset];
        if (length == 0) break;
        for (name.bytes[offset + 1 ..][0..length]) |*byte| {
            if (!is_letter(byte.*)) continue;
            byte.* = apply_case(byte.*, 0);
            assert(is_capital(byte.*));
            return;
        }
        offset += 1 + length;
    }
    unreachable; // `mix_case` drew a letter, or it would have returned
}

fn read_pointer(message: []const u8, cursor: usize) Error!usize {
    if (cursor + constants.pointer_bytes > message.len) return Error.MalformedMessage;
    assert(cursor + constants.u16_bytes <= message.len);
    return integer.read_u16(message, cursor) & constants.pointer_offset_mask;
}

fn copy_label(message: []const u8, cursor: usize, length: u8, out: *Name) Error!void {
    // The kind bits are `00` here, so the length cannot exceed the label limit.
    assert(length <= core.constants.label_bytes_max);
    assert(length != 0);
    const start = cursor + 1;
    if (start + length > message.len) return Error.MalformedMessage;
    try out.append_label(message[start..][0..length]);
}

fn is_letter(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

/// One letter, cased by the low bit of `bits`: a capital for 0, small for 1.
fn apply_case(byte: u8, bits: u64) u8 {
    assert(is_letter(byte));
    const upper = byte & ~@as(u8, core.constants.ascii_case_bit);
    return if (bits & 1 == 1) upper | core.constants.ascii_case_bit else upper;
}

/// Whether a letter is a capital: its case bit is clear.
fn is_capital(letter: u8) bool {
    assert(is_letter(letter));
    return letter & core.constants.ascii_case_bit == 0;
}

// Tests.

const testing = std.testing;

/// A message holding `example.com` at offset 12, then `www` followed by a pointer to it at 25.
/// The offsets are what a real query plus answer would produce, so the fixtures read like messages
/// rather than like arrays.
const compressed_message = [_]u8{0} ** core.constants.header_bytes ++
    "\x07example\x03com\x00".* ++ // offset 12, 13 octets
    "\x03www\xc0\x0c".*; // offset 25: one label then a pointer to offset 12
const name_example = "\x07example\x03com\x00";

test "a name of labels decodes and reports the octet after the root" {
    var name: Name = Name.empty;
    const end = try decode(&compressed_message, core.constants.header_bytes, &name);
    try testing.expectEqualStrings("\x07example\x03com\x00", name.wire());
    try testing.expectEqual(@as(usize, 25), end);
}

test "a name ending in a pointer decodes to the whole name and ends after the pointer" {
    var name: Name = Name.empty;
    const end = try decode(&compressed_message, 25, &name);
    try testing.expect(name.equal(&try Name.from_text("www.example.com")));
    try testing.expectEqual(@as(usize, compressed_message.len), end);
}

test "a pointer that does not point strictly backwards is refused" {
    // A pointer at offset 12 pointing at offset 12: the classic self-loop.
    const message = [_]u8{0} ** core.constants.header_bytes ++ "\xc0\x0c".*;
    var name: Name = Name.empty;
    try testing.expectError(Error.BadCompressionPointer, decode(&message, core.constants.header_bytes, &name));

    // A pointer pointing forwards, at a name later in the message.
    const forwards = [_]u8{0} ** core.constants.header_bytes ++ "\xc0\x10\x00\x00\x03www\x00".*;
    try testing.expectError(Error.BadCompressionPointer, decode(&forwards, core.constants.header_bytes, &name));
}

test "a chain of pointers longer than the hop bound is refused" {
    // Each pointer points at the one before it, so every hop is strictly backwards and legal; only
    // the hop bound stops the chain. Seventeen pointers: one more than compression_hops_max.
    const hops = core.constants.compression_hops_max + 1;
    var message: [core.constants.header_bytes + hops * constants.pointer_bytes]u8 = @splat(0);
    var index: usize = 0;
    while (index < hops) : (index += 1) {
        const at = core.constants.header_bytes + index * constants.pointer_bytes;
        const target = if (index == 0) 0 else at - constants.pointer_bytes;
        message[at] = constants.label_kind_pointer | @as(u8, @intCast(target >> constants.octet_bits));
        message[at + 1] = @intCast(target & 0xff);
    }
    // Start at the last pointer, so the walk chases every hop backwards.
    const last = core.constants.header_bytes + (hops - 1) * constants.pointer_bytes;
    var name: Name = Name.empty;
    try testing.expectError(Error.BadCompressionPointer, decode(&message, last, &name));
}

test "a name may chase as many pointers as the hop bound allows" {
    // Real servers point at a name that itself ends in a pointer: an MX exchange at the tail of the
    // one before it, which ends at the question. So the bound's own count of hops must decode.
    const hops = core.constants.compression_hops_max;
    const first = core.constants.header_bytes + name_example.len;
    var message: [first + hops * constants.pointer_bytes]u8 = @splat(0);
    @memcpy(message[core.constants.header_bytes..first], name_example);
    for (0..hops) |index| {
        const at = first + index * constants.pointer_bytes;
        const target = if (index == 0) core.constants.header_bytes else at - constants.pointer_bytes;
        message[at] = constants.label_kind_pointer | @as(u8, @intCast(target >> constants.octet_bits));
        message[at + 1] = @intCast(target & 0xff);
    }
    var name: Name = Name.empty;
    const end = try decode(&message, message.len - constants.pointer_bytes, &name);
    try testing.expectEqualStrings(name_example, name.wire());
    try testing.expectEqual(message.len, end);
}

test "a reserved label kind is refused" {
    for ([_]u8{ 0x40, 0x80 }) |kind| {
        const message = [_]u8{0} ** core.constants.header_bytes ++ [_]u8{ kind, 0x00 };
        var name: Name = Name.empty;
        try testing.expectError(Error.MalformedName, decode(&message, core.constants.header_bytes, &name));
    }
}

test "a label running past the end of the message is malformed" {
    const message = [_]u8{0} ** core.constants.header_bytes ++ "\x07exam".*;
    var name: Name = Name.empty;
    try testing.expectError(Error.MalformedMessage, decode(&message, core.constants.header_bytes, &name));
}

test "a name with no root octet is malformed rather than accepted at the end" {
    const message = [_]u8{0} ** core.constants.header_bytes ++ "\x03www".*;
    var name: Name = Name.empty;
    try testing.expectError(Error.MalformedMessage, decode(&message, core.constants.header_bytes, &name));
}

test "a pointer whose second octet is past the end is malformed" {
    const message = [_]u8{0} ** core.constants.header_bytes ++ [_]u8{constants.label_kind_pointer};
    var name: Name = Name.empty;
    try testing.expectError(Error.MalformedMessage, decode(&message, core.constants.header_bytes, &name));
}

test "skip reaches the octet after a name without decompressing it" {
    try testing.expectEqual(@as(usize, 25), try skip(&compressed_message, core.constants.header_bytes));
    try testing.expectEqual(@as(usize, compressed_message.len), try skip(&compressed_message, 25));
}

test "skip refuses a reserved kind and a truncated name" {
    const reserved = [_]u8{0} ** core.constants.header_bytes ++ [_]u8{0x40};
    try testing.expectError(Error.MalformedName, skip(&reserved, core.constants.header_bytes));
    const truncated = [_]u8{0} ** core.constants.header_bytes ++ "\x07exam".*;
    try testing.expectError(Error.MalformedMessage, skip(&truncated, core.constants.header_bytes));
}

test "encode writes the wire bytes and nothing else" {
    const name = try Name.from_text("example.com");
    var out: [core.constants.name_bytes_max]u8 = @splat(0xff);
    try testing.expectEqual(@as(usize, 13), encode(&name, &out));
    try testing.expectEqualStrings("\x07example\x03com\x00", out[0..13]);
}

test "mix_case changes only the case, and the same entropy gives the same case" {
    const original = try Name.from_text("example.com");
    var mixed = original;
    mix_case(&mixed, 0x0123456789abcdef);
    try testing.expect(mixed.equal(&original));
    try testing.expect(!std.mem.eql(u8, mixed.wire(), original.wire()));
    try testing.expectEqual(original.len, mixed.len);

    var again = original;
    mix_case(&again, 0x0123456789abcdef);
    try testing.expectEqualSlices(u8, mixed.wire(), again.wire());

    var different = original;
    mix_case(&different, 0x0123456789abcdee);
    try testing.expect(!std.mem.eql(u8, mixed.wire(), different.wire()));
}

test "mix_case leaves the length octets and the non-letters alone" {
    var name = try Name.from_text("a1-b.example");
    const lengths = [_]u8{ name.bytes[0], name.bytes[5] };
    mix_case(&name, 0xffff_ffff_ffff_ffff);
    try testing.expectEqual(lengths[0], name.bytes[0]);
    try testing.expectEqual(lengths[1], name.bytes[5]);
    try testing.expectEqual(@as(u8, '1'), name.bytes[2]);
    try testing.expectEqual(@as(u8, '-'), name.bytes[3]);
    try testing.expectEqual(@as(u8, 0), name.bytes[name.len - 1]);
}

test "mix_case gives every letter its own bit, past one word of entropy" {
    // 96 letters is more than the 64 bits one word holds, so the mixer must re-mix rather than
    // reuse or stop.
    var name = try Name.from_text("a" ** 48 ++ "." ++ "b" ** 48);
    mix_case(&name, 1);
    var upper: usize = 0;
    for (name.wire()) |byte| {
        if (byte >= 'A' and byte <= 'Z') upper += 1;
    }
    // Every letter is cased from one bit, so about half come back upper. A mixer that stopped
    // after 64 letters would leave the last 32 untouched and lowercase.
    try testing.expect(upper > 96 / 4);
    var last_word_upper: usize = 0;
    for (name.bytes[name.len - 33 .. name.len - 1]) |byte| {
        if (byte >= 'A' and byte <= 'Z') last_word_upper += 1;
    }
    try testing.expect(last_word_upper > 0);
}

test "every letter of every label can take either case, whichever position it sits in" {
    // W6 of docs/mutations.md: a mixer that walked the bytes from the length octet rather than
    // from the first label octet cased every letter but the last of each label, and passed every
    // other test in this file. A position that never changes over many seeds is that bug.
    const case_seed_count = 64;
    const original = try Name.from_text("ab.cd");
    var seen_upper: [core.constants.name_bytes_max]bool = @splat(false);
    var seed: u64 = 0;
    while (seed < case_seed_count) : (seed += 1) {
        var name = original;
        mix_case(&name, seed);
        try testing.expect(name.equal(&original));
        for (name.wire(), 0..) |byte, index| {
            if (byte >= 'A' and byte <= 'Z') seen_upper[index] = true;
        }
    }
    // Offsets 1 and 2 hold "ab", offsets 4 and 5 hold "cd".
    for ([_]usize{ 1, 2, 4, 5 }) |index| try testing.expect(seen_upper[index]);
    // Offsets 0 and 3 are length octets and offset 6 is the root: never touched.
    for ([_]usize{ 0, 3, 6 }) |index| try testing.expect(!seen_upper[index]);
}

/// Whether a name holds a capital. A length octet is never a letter, so the bytes are read whole.
fn has_capital(name: *const Name) bool {
    for (name.wire()) |byte| if (byte >= 'A' and byte <= 'Z') return true;
    return false;
}

test "a draw that leaves every letter small is drawn again, from the next word" {
    // `ab.cd` takes its four bits from the low end of the first word, and a set bit leaves its
    // letter small. Where all four are set, the name is cased as a seed one step on cases it.
    const seed_count = 256;
    const original = try Name.from_text("ab.cd");
    const all_small: u64 = 0b1111;
    var redrawn: usize = 0;
    var seed: u64 = 0;
    while (seed < seed_count) : (seed += 1) {
        var name = original;
        mix_case(&name, seed);
        try testing.expect(has_capital(&name));
        if (core.mix.next(seed) & all_small != all_small) continue;
        var next_draw = original;
        mix_case(&next_draw, core.mix.next(seed));
        try testing.expectEqualSlices(u8, next_draw.wire(), name.wire());
        redrawn += 1;
    }
    try testing.expect(redrawn > 0);
}

test "a name of one letter always comes out a capital, by the fallback when every draw is small" {
    const seed_count = 256;
    var fallen_back: usize = 0;
    var seed: u64 = 0;
    while (seed < seed_count) : (seed += 1) {
        var name = try Name.from_text("a");
        mix_case(&name, seed);
        try testing.expectEqual(@as(u8, 'A'), name.bytes[1]);
        // Each draw reads the low bit of the next word, and every draw small falls back.
        var word = seed;
        var small: u64 = 0;
        for (0..constants.case_draws_max) |_| {
            word = core.mix.next(word);
            small += word & 1;
        }
        fallen_back += @intFromBool(small == constants.case_draws_max);
    }
    try testing.expect(fallen_back > 0);
}

test "mix_case leaves a name without a letter as it was" {
    const original = try Name.from_text("192.0.2.1");
    var name = original;
    mix_case(&name, 0);
    try testing.expectEqualSlices(u8, original.wire(), name.wire());
}
