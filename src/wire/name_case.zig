//! DNS-0x20: the case mixer, and check 5's compare of an echoed name with the name the mixer
//! makes, read in place (docs/design.md §7). Split from `name.zig` by the file-length rule;
//! `name.zig` exports what this holds.
//!
//! The mixer and the compare share one bit stream, `Draw`: each letter takes its case from its own
//! bit of the words after a seed. `mix_case` writes the draw into the name, walking its labels as
//! it always has, and that walk is the reference. `is_mix_of` reads an echo against the draw octet
//! by octet, so no cased copy of the name is made; it walks the bytes, which meets the letters in
//! the same order since no length octet is a letter, and the tests hold it to the mixer.
//!
//! The draw `mix_case` keeps is usually its first. When the first leaves every letter small, with
//! chance 2^-L for a name of L letters, the mixer draws again, and `is_mix_of` builds the name with
//! `mix_case` itself and compares that: the reference, on the path it takes least.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Name = core.Name;
const constants = @import("constants.zig");
const limits = @import("limits.zig");

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
    while (draws < limits.case_draws_max) : (draws += 1) {
        const drawn = draw_case(name, word);
        if (drawn.stands()) return;
        word = drawn.word;
    }
    assert(draws == limits.case_draws_max);
    capitalize_first(name);
}

/// Whether `echoed` is byte for byte `name` as `mix_case(name, entropy)` cases it, without
/// building that name: check 5 for a query that mixed the case (docs/design.md §7). The echo is
/// read against the first draw as it is drawn. When `mix_case` did not keep that draw, the name it
/// built is built again and compared, the reference.
pub fn is_mix_of(echoed: []const u8, name: *const Name, entropy: u64) bool {
    return switch (read_first_draw(echoed, name, entropy)) {
        .same => true,
        .other => false,
        .later => is_mix_built(echoed, name, entropy),
    };
}

/// What an echo read against the first draw says.
const Reading = enum {
    /// The echo is the name as the first draw cased it, and `mix_case` kept that draw.
    same,
    /// The echo is not the name `mix_case` made: an octet differs in more than a letter's case, or
    /// the echo is the name in another case than the first draw's, which `mix_case` kept.
    other,
    /// The echo is the name in some case, and the first draw left every letter small, so the name
    /// went out from a later draw, or with its first letter made a capital: only that name says.
    later,
};

/// Reads `echoed` against the first draw of `mix_case(name, entropy)`, octet by octet. This walks
/// the bytes, where the mixer walks the labels, and the two give the same letters the same bits in
/// the same order because no length octet is a letter (the comptime check below). The mixer's walk
/// is the reference; the boundary-octets test below holds this one to it over short labels.
fn read_first_draw(echoed: []const u8, name: *const Name, entropy: u64) Reading {
    assert(name.len >= 1);
    assert(echoed.len == name.len);
    var drawn: Draw = .init(entropy);
    var exact = true;
    for (echoed, name.wire()) |echo, octet| {
        const expected = if (is_letter(octet)) drawn.case(octet) else octet;
        if (echo == expected) continue;
        // The same letter in the other case (RFC 1035 §2.3.3, as clarified by RFC 4343 §3) is the
        // name in a case this draw did not give; any other octet makes it another name.
        if (!is_letter(octet) or echo ^ expected != core.constants.ascii_case_bit) return .other;
        exact = false;
    }
    if (!drawn.stands()) return .later;
    return if (exact) .same else .other;
}

comptime {
    // `read_first_draw` reads a length octet as a byte that is not a letter: a label is at most 63
    // octets and 'A' is 65.
    assert(core.limits.label_bytes_max < 'A');
}

/// `is_mix_of` the long way: the name `mix_case` makes, compared byte for byte. Out of line, so
/// the copy of the name it makes is no cost to the path every response takes.
noinline fn is_mix_built(echoed: []const u8, name: *const Name, entropy: u64) bool {
    @branchHint(.cold);
    var cased = name.*;
    mix_case(&cased, entropy);
    return std.mem.eql(u8, echoed, cased.wire());
}

/// One draw: each letter's case from its own bit of the words after a seed, a capital for a clear
/// bit and small for a set one. The one bit stream `mix_case` writes from and `is_mix_of` reads.
const Draw = struct {
    /// The word the next letter's bit comes from, and the bits of it used.
    word: u64,
    used: usize,
    /// Whether the draw cased a letter.
    lettered: bool = false,
    /// The bits the draw read, ANDed: the low bit is 1 while every letter it cased came out small.
    small: u64 = 1,

    /// A draw from the words after `entropy`. The first is mixed at the first letter, as each
    /// later one is when the one before runs out, so a read that ends before a letter mixes none.
    fn init(entropy: u64) Draw {
        return .{ .word = entropy, .used = core.mix.word_bits };
    }

    /// `letter` in the case its own bit gives it.
    inline fn case(self: *Draw, letter: u8) u8 {
        if (self.used == core.mix.word_bits) {
            self.word = core.mix.next(self.word);
            self.used = 0;
        }
        const bits = self.word >> @intCast(self.used);
        self.used += 1;
        self.lettered = true;
        self.small &= bits;
        return apply_case(letter, bits);
    }

    /// Whether `mix_case` keeps the draw: it left a capital, or there was no letter to case.
    fn stands(self: *const Draw) bool {
        return self.small & 1 == 0 or !self.lettered;
    }
};

/// One draw, written into `name`: every letter of every label cased by `Draw`.
fn draw_case(name: *Name, entropy: u64) Draw {
    var drawn: Draw = .init(entropy);
    var offset: usize = 0;
    var labels: usize = 0;
    while (labels <= core.limits.labels_max) : (labels += 1) {
        if (offset >= name.len) break;
        const length = name.bytes[offset];
        if (length == 0) break;
        assert(length <= core.limits.label_bytes_max);
        for (name.bytes[offset + 1 ..][0..length]) |*byte| {
            if (is_letter(byte.*)) byte.* = drawn.case(byte.*);
        }
        offset += 1 + length;
    }
    assert(labels <= core.limits.labels_max);
    return drawn;
}

/// Makes the first letter of `name` a capital: the case `mix_case` falls back to.
fn capitalize_first(name: *Name) void {
    var offset: usize = 0;
    var labels: usize = 0;
    while (labels <= core.limits.labels_max) : (labels += 1) {
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
    var seen_upper: [core.limits.name_bytes_max]bool = @splat(false);
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
        for (0..limits.case_draws_max) |_| {
            word = core.mix.next(word);
            small += word & 1;
        }
        fallen_back += @intFromBool(small == limits.case_draws_max);
    }
    try testing.expect(fallen_back > 0);
}

test "mix_case leaves a name without a letter as it was" {
    const original = try Name.from_text("192.0.2.1");
    var name = original;
    mix_case(&name, 0);
    try testing.expectEqualSlices(u8, original.wire(), name.wire());
}

/// `name` as `mix_case` cases it from `entropy`: the reference `is_mix_of` is held to.
fn cased_by(name: *const Name, entropy: u64) Name {
    var cased = name.*;
    mix_case(&cased, entropy);
    return cased;
}

test "is_mix_of takes the name mix_case makes, and no other case and no other name" {
    const name = try Name.from_text("example.com");
    const entropy = 0x0123456789abcdef;
    const cased = cased_by(&name, entropy);
    try testing.expect(is_mix_of(cased.wire(), &name, entropy));
    // The name as held, and every letter flipped one at a time: the name, in another case.
    try testing.expect(!is_mix_of(name.wire(), &name, entropy));
    for (cased.wire(), 0..) |octet, at| {
        if (!is_letter(octet)) continue;
        var echo = cased;
        echo.bytes[at] ^= core.constants.ascii_case_bit;
        try testing.expect(!is_mix_of(echo.wire(), &name, entropy));
    }
    // The same echo is the name another seed makes, and the name with no letter is itself.
    try testing.expect(!is_mix_of(cased.wire(), &name, entropy + 1));
    const letterless = try Name.from_text("192.0.2.1");
    try testing.expect(is_mix_of(letterless.wire(), &letterless, entropy));
}

/// Requires `is_mix_of` to take the name `mix_case` made, and to refuse the first draw's case.
fn expect_later_draw(name: *const Name, entropy: u64) !void {
    const cased = cased_by(name, entropy);
    try testing.expect(is_mix_of(cased.wire(), name, entropy));
    var small = name.*;
    small.fold_case();
    try testing.expect(!std.mem.eql(u8, small.wire(), cased.wire()));
    try testing.expect(!is_mix_of(small.wire(), name, entropy));
}

/// Whether each of the first `draws` words after `seed` leaves small the letters `mask` names.
fn draws_small(seed: u64, mask: u64, draws: usize) bool {
    var word = seed;
    for (0..draws) |_| {
        word = core.mix.next(word);
        if (word & mask != mask) return false;
    }
    return true;
}

test "is_mix_of takes the name a later draw or the fallback made, for one, two and three letters" {
    // A first draw leaves L letters small with chance 2^-L, and the name goes out from a later
    // draw; a fallback seed leaves it small at every draw, so its first letter goes out a capital.
    const seed_count = 256;
    const Later = struct { text: []const u8, fallback_seed: u64 };
    const names = [_]Later{
        .{ .text = "a", .fallback_seed = 3 },
        .{ .text = "a1.b", .fallback_seed = 137 },
        .{ .text = "x-y.2.z", .fallback_seed = 8229 },
    };
    for (names, 1..) |later, letters| {
        const name = try Name.from_text(later.text);
        const mask = (@as(u64, 1) << @intCast(letters)) - 1;
        var redrawn: usize = 0;
        for (0..seed_count) |seed| {
            if (!draws_small(seed, mask, 1)) continue;
            try expect_later_draw(&name, seed);
            redrawn += 1;
        }
        try testing.expect(redrawn > 0);
        try testing.expect(draws_small(later.fallback_seed, mask, limits.case_draws_max));
        try expect_later_draw(&name, later.fallback_seed);
        var first_capital = name;
        first_capital.fold_case();
        first_capital.bytes[1] = std.ascii.toUpper(first_capital.bytes[1]);
        try testing.expect(is_mix_of(first_capital.wire(), &name, later.fallback_seed));
    }
}

test "the first draw reads an octet that differs in more than its case as another name" {
    // `a1.b`: offsets 1 and 4 hold its letters, 2 a digit, 0 and 3 its length octets, 5 the root.
    // A seed whose first draw left both small reads another case as `later`, another name `other`.
    const seed_count = 16;
    const name = try Name.from_text("a1.b");
    const both_small = 0b11;
    const Edit = struct { at: usize, octet: u8 };
    const case_bit = core.constants.ascii_case_bit;
    const edits = [_]Edit{
        .{ .at = 1, .octet = 'b' },          .{ .at = 2, .octet = '1' ^ case_bit },
        .{ .at = 0, .octet = 2 ^ case_bit }, .{ .at = 5, .octet = case_bit },
    };
    var later: usize = 0;
    for (0..seed_count) |seed| {
        const cased = cased_by(&name, seed);
        const small = draws_small(seed, both_small, 1);
        later += @intFromBool(small);
        try testing.expectEqual(if (small) Reading.later else .same, read_first_draw(cased.wire(), &name, seed));
        var flipped = cased;
        flipped.bytes[4] ^= case_bit;
        try testing.expectEqual(if (small) Reading.later else .other, read_first_draw(flipped.wire(), &name, seed));
        for (edits) |edit| {
            var echo = cased;
            echo.bytes[edit.at] = edit.octet;
            try testing.expectEqual(Reading.other, read_first_draw(echo.wire(), &name, seed));
        }
    }
    try testing.expect(later > 0);
}

/// The boundary octets of the letters and of the case bit: both ends of each case, the octets
/// either side of them, a digit, a hyphen, and octets past ASCII and zero.
const boundary_octets = [_]u8{ 'a', 'A', 'z', 'Z', 'm', '@', '[', '`', '{', '0', '-', '\x80', '\xff', '\x00' };

/// What one octet of an echo is made of the cased name's octet, in one of `echo_forms` forms.
const Form = enum { as_cased, case_flipped, small, capital, as_held, one_more, other_letter };
const echo_forms = @typeInfo(Form).@"enum".fields.len;

/// The echo of `cased` whose label octets take the forms `pick` spells in base `echo_forms`.
fn echo_of(cased: *const Name, held: *const Name, pick: usize) Name {
    var echo = cased.*;
    var rest = pick;
    for (echo.bytes[1 .. echo.len - 1], held.bytes[1 .. held.len - 1]) |*octet, original| {
        const value = octet.*;
        const form: Form = @enumFromInt(rest % echo_forms);
        octet.* = switch (form) {
            .as_cased => value,
            .case_flipped => value ^ core.constants.ascii_case_bit,
            .small => std.ascii.toLower(value),
            .capital => std.ascii.toUpper(value),
            .as_held => original,
            .one_more => value +% 1,
            .other_letter => 'q',
        };
        rest /= echo_forms;
    }
    return echo;
}

/// Requires `is_mix_of` to agree with the built name on every echo form of a one-label `name`.
fn expect_every_echo(name: *const Name, entropy: u64) !void {
    const cased = cased_by(name, entropy);
    const label_bytes = name.bytes[0];
    const echoes = std.math.pow(usize, echo_forms, label_bytes);
    for (0..echoes) |pick| {
        const echo = echo_of(&cased, name, pick);
        const reference = std.mem.eql(u8, echo.wire(), cased.wire());
        try testing.expectEqual(reference, is_mix_of(echo.wire(), name, entropy));
    }
}

/// A name of one label, the `length` octets of `boundary_octets` that `code` spells.
fn boundary_name(code: usize, length: usize) !Name {
    var label: [limits.case_boundary_label_bytes_max]u8 = undefined;
    var rest = code;
    for (label[0..length]) |*octet| {
        octet.* = boundary_octets[rest % boundary_octets.len];
        rest /= boundary_octets.len;
    }
    var name: Name = Name.empty;
    try name.append_label(label[0..length]);
    try name.terminate();
    return name;
}

test "is_mix_of agrees with the built name on every echo of every short label of boundary octets" {
    // The method's first-difference proof (docs/performance.md) over one- and two-octet labels,
    // sixteen seeds each: every path of the compare, the later draws and the fallback among them.
    const seed_count = 16;
    for (1..limits.case_boundary_label_bytes_max + 1) |length| {
        for (0..std.math.pow(usize, boundary_octets.len, length)) |code| {
            const name = try boundary_name(code, length);
            for (0..seed_count) |seed| try expect_every_echo(&name, core.mix.next(seed));
        }
    }
}
