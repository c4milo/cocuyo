//! `Name`: a domain name in uncompressed wire form, the root label included. A name is a sequence
//! of length-prefixed labels ending in a zero octet, at most `constants.name_bytes_max` octets
//! all told (RFC 1035 §2.3.4, §3.1).
//!
//! Wire form is what cocuyo stores, for two reasons. A parsed name never points into the datagram
//! it came from, so a caller can reuse its receive buffer the moment `on_response` returns. And
//! presentation form is up to four times longer once escapes are counted, so storing text would
//! cost four times the memory for a form nothing on the wire uses (docs/design.md §16 decision 8).
//!
//! The text side is name_text.zig and the reverse-lookup side is name_reverse.zig.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Error = @import("errors.zig").Error;
const name_text = @import("name_text.zig");

/// The zero octet that ends every name: the root label (RFC 1035 §3.1).
const root_label = 0;

comptime {
    // Case folding a whole name byte for byte is sound only while no length octet can be an ASCII
    // letter, which holds because a label is at most 63 octets and 'A' is 65.
    if (constants.label_bytes_max >= 'A') @compileError("a length octet could fold like a letter");
}

pub const Name = struct {
    bytes: [constants.name_bytes_max]u8,
    len: u8,

    /// The root, `.`: one zero octet. Zeroed rather than undefined, because nothing cocuyo does
    /// may read uninitialised memory (CLAUDE.md non-negotiable 4).
    pub const root: Name = .{ .bytes = @splat(0), .len = 1 };

    /// A name under construction, before any label. `append_label` fills it and `terminate` ends
    /// it; until then it is not a name and `wire` would report a prefix.
    pub const empty: Name = .{ .bytes = @splat(0), .len = 0 };

    /// The wire bytes of a terminated name, which is what a query carries and what a comparison
    /// reads.
    pub fn wire(self: *const Name) []const u8 {
        assert(self.len <= constants.name_bytes_max);
        return self.bytes[0..self.len];
    }

    pub fn is_root(self: *const Name) bool {
        assert(self.len >= 1);
        return self.len == 1 and self.bytes[0] == root_label;
    }

    /// Appends one label, leaving room for the terminating root octet. The label is not validated
    /// here: `from_text` validates what a caller spelled, and the codec appends bytes a server
    /// sent, which may be anything a length octet can describe.
    pub fn append_label(self: *Name, label: []const u8) Error!void {
        if (label.len == 0) return Error.MalformedName;
        if (label.len > constants.label_bytes_max) return Error.LabelTooLong;
        const length: usize = self.len;
        // The root octet is counted here: a label that fits only by leaving no room to terminate
        // the name does not fit.
        if (length + 1 + label.len + 1 > constants.name_bytes_max) return Error.NameTooLong;
        assert(length + 1 + label.len < constants.name_bytes_max);
        self.bytes[self.len] = @intCast(label.len);
        @memcpy(self.bytes[self.len + 1 ..][0..label.len], label);
        self.len += @intCast(1 + label.len);
        assert(self.len < constants.name_bytes_max);
    }

    /// Ends the name with the root octet. A name is only a name once this has been called.
    pub fn terminate(self: *Name) Error!void {
        const length: usize = self.len;
        if (length + 1 > constants.name_bytes_max) return Error.NameTooLong;
        assert(length < constants.name_bytes_max);
        self.bytes[self.len] = root_label;
        self.len += 1;
        assert(self.bytes[self.len - 1] == root_label);
    }

    /// The number of labels, the root not counted. Bounded by `constants.labels_max`, so a name
    /// whose length octets disagree with its length cannot spin here.
    pub fn label_count(self: *const Name) u8 {
        assert(self.len >= 1);
        var offset: usize = 0;
        var labels: u8 = 0;
        while (labels <= constants.labels_max) {
            if (offset >= self.len) break;
            const length = self.bytes[offset];
            if (length == root_label) break;
            assert(length <= constants.label_bytes_max);
            offset += 1 + length;
            labels += 1;
        }
        assert(labels <= constants.labels_max);
        return labels;
    }

    /// The dots the caller would have typed: one fewer than the labels, and none for the root.
    /// This is what `ndots` counts (docs/design.md §5).
    pub fn dot_count(self: *const Name) u8 {
        const labels = self.label_count();
        assert(labels <= constants.labels_max);
        return if (labels == 0) 0 else labels - 1;
    }

    /// Case-insensitive equality: two names are the same name whatever the case of their ASCII
    /// letters (`wire_equal`).
    ///
    /// This is never the check a response is matched with. That check compares the question
    /// section byte for byte, case included, because the case is entropy (docs/design.md §7).
    pub fn equal(self: *const Name, other: *const Name) bool {
        if (self.len != other.len) return false;
        assert(self.len == other.len);
        return wire_equal(self.wire(), other.wire());
    }

    /// Lowercases every label byte, leaving the length octets alone.
    ///
    /// This undoes cocuyo's own DNS-0x20 randomisation where it comes back. A server may compress
    /// a name in its answer to a pointer into the question it echoed, and the question carries the
    /// case cocuyo randomised, so a name decoded from such a pointer wears cocuyo's noise rather
    /// than the server's spelling. Case is insignificant either way (RFC 1035 §2.3.3), and a
    /// caller reading `github.cOm` would reasonably think something had gone wrong.
    pub fn fold_case(self: *Name) void {
        assert(self.len >= 1);
        var offset: usize = 0;
        var labels: usize = 0;
        while (labels <= constants.labels_max) {
            if (offset >= self.len) break;
            const length = self.bytes[offset];
            if (length == root_label) break;
            assert(length <= constants.label_bytes_max);
            for (self.bytes[offset + 1 ..][0..length]) |*byte| byte.* = fold(byte.*);
            offset += 1 + length;
            labels += 1;
        }
        assert(labels <= constants.labels_max);
    }

    /// `fold` over the eight octets of a word at once, so a hash can fold a name without copying
    /// it: an octet in `'A'..'Z'` gets its case bit, and a length octet, a digit, a hyphen or an
    /// octet past ASCII is left alone, as `fold_case` leaves them.
    pub fn fold_word(word: u64) u64 {
        const low = word & constants.word_low_bits;
        // No octet carries into the next: a low part is at most 0x7f and a bias at most 0x3f.
        const at_a = (low + constants.word_bias_at_a) & constants.word_high_bits;
        const past_z = (low + constants.word_bias_past_z) & constants.word_high_bits;
        const upper = at_a & ~past_z & ~(word & constants.word_high_bits);
        const folded = word | (upper >> constants.word_high_to_case_shift);
        // Nothing but case bits were set.
        assert((folded & ~word) & ~(constants.word_high_bits >> constants.word_high_to_case_shift) == 0);
        return folded;
    }

    /// `self` with `suffix` appended: `www` and `example.com` become `www.example.com`. This is
    /// how a search-list candidate is built (docs/design.md §5), so a candidate too long to encode
    /// is an error rather than a truncation.
    pub fn concat(self: *const Name, suffix: *const Name) Error!Name {
        assert(self.len >= 1);
        assert(suffix.len >= 1);
        if (self.is_root()) return suffix.*;
        if (suffix.is_root()) return self.*;
        const labels: usize = self.len - 1;
        const suffix_len: usize = suffix.len;
        if (labels + suffix_len > constants.name_bytes_max) return Error.NameTooLong;
        var joined: Name = .{ .bytes = @splat(0), .len = 0 };
        @memcpy(joined.bytes[0..labels], self.bytes[0..labels]);
        @memcpy(joined.bytes[labels..][0..suffix_len], suffix.bytes[0..suffix_len]);
        joined.len = @intCast(labels + suffix_len);
        assert(joined.bytes[joined.len - 1] == root_label);
        return joined;
    }

    /// Presentation form, written into the caller's buffer, which must hold
    /// `constants.name_text_bytes_max`. Returns the bytes written.
    pub fn write_text(self: *const Name, out: []u8) usize {
        assert(self.len >= 1);
        assert(out.len >= constants.name_text_bytes_max);
        return name_text.write(self.wire(), out);
    }

    /// A name from presentation form. A trailing dot is the mark of an absolute name and is not an
    /// empty label; every other empty label is a malformed name. Version one spells no escapes, so
    /// a label is printable ASCII (name_text.zig).
    pub fn from_text(text: []const u8) Error!Name {
        if (text.len == 0) return root;
        if (text.len == 1 and text[0] == name_text.separator) return root;
        var body = text;
        if (body[body.len - 1] == name_text.separator) body = body[0 .. body.len - 1];
        assert(body.len >= 1);
        var name: Name = empty;
        var labels: u8 = 0;
        var iterator = std.mem.splitScalar(u8, body, name_text.separator);
        while (iterator.next()) |label| {
            if (labels == constants.labels_max) return Error.NameTooLong;
            labels += 1;
            try name_text.validate_label(label);
            try name.append_label(label);
        }
        try name.terminate();
        // At least one label and the root: a name built from text is never the root, which the
        // two early returns above have already handled.
        assert(!name.is_root());
        return name;
    }
};

/// One byte, ASCII case folded: the only bytes that differ are the letters, and they differ in one
/// bit (`constants.ascii_case_bit`).
fn fold(byte: u8) u8 {
    return if (byte >= 'A' and byte <= 'Z') byte | constants.ascii_case_bit else byte;
}

/// Two names in wire form, compared with the case of their ASCII letters folded (RFC 1035
/// §2.3.3, clarified by RFC 4343). Every byte folds, length octets included, which is sound
/// because no length octet can be a letter (the comptime block at the top of this file).
/// `Name.equal` shares it with the hosts table, whose names sit in an arena rather than in a
/// `Name`.
pub fn wire_equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    assert(a.len <= constants.name_bytes_max);
    for (a, b) |mine, theirs| {
        if (fold(mine) != fold(theirs)) return false;
    }
    return true;
}

comptime {
    if (constants.word_high_bits >> constants.word_high_to_case_shift !=
        constants.word_low_bits & (constants.word_high_bits >> constants.word_high_to_case_shift))
        @compileError("the shifted high bit must land inside the low seven");
    if (constants.word_high_to_case_shift != @ctz(@as(u8, 0x80)) - @ctz(@as(u8, constants.ascii_case_bit)))
        @compileError("the shift must take the high bit to the case bit");
}

// Tests.

const testing = std.testing;

test "the word fold agrees with the octet fold for every octet value in every position" {
    var value: usize = 0;
    while (value <= std.math.maxInt(u8)) : (value += 1) {
        const byte: u8 = @intCast(value);
        var octets: [@sizeOf(u64)]u8 = @splat(byte);
        var expected: [@sizeOf(u64)]u8 = @splat(fold(byte));
        const folded = Name.fold_word(std.mem.readInt(u64, &octets, .little));
        try testing.expectEqual(std.mem.readInt(u64, &expected, .little), folded);
        // The octet alone in one position, the rest zero, so a fold that leaked between octets
        // would show.
        octets = @splat(0);
        expected = @splat(0);
        octets[3] = byte;
        expected[3] = fold(byte);
        try testing.expectEqual(
            std.mem.readInt(u64, &expected, .little),
            Name.fold_word(std.mem.readInt(u64, &octets, .little)),
        );
    }
}

test "the word fold leaves a length octet, a digit, a hyphen and a high octet alone" {
    const word = std.mem.readInt(u64, "\x07Ab-9Z@\xc1", .little);
    const folded = Name.fold_word(word);
    try testing.expectEqualSlices(u8, "\x07ab-9z@\xc1", std.mem.asBytes(&folded));
}

test "from_text encodes labels in wire form" {
    const name = try Name.from_text("example.com");
    try testing.expectEqualStrings("\x07example\x03com\x00", name.wire());
    try testing.expectEqual(@as(u8, 13), name.len);
    try testing.expectEqual(@as(u8, 2), name.label_count());
    try testing.expectEqual(@as(u8, 1), name.dot_count());
}

test "a trailing dot is absoluteness, not an empty label" {
    const absolute = try Name.from_text("example.com.");
    const relative = try Name.from_text("example.com");
    try testing.expectEqualStrings(absolute.wire(), relative.wire());
}

test "the empty text and a lone dot are the root" {
    try testing.expect(Name.root.is_root());
    try testing.expect((try Name.from_text("")).is_root());
    try testing.expect((try Name.from_text(".")).is_root());
    try testing.expectEqual(@as(u8, 0), Name.root.label_count());
    try testing.expectEqual(@as(u8, 0), Name.root.dot_count());
}

test "from_text refuses what cannot be encoded" {
    try testing.expectError(Error.MalformedName, Name.from_text("a..b"));
    try testing.expectError(Error.MalformedName, Name.from_text(".a"));
    try testing.expectError(Error.LabelTooLong, Name.from_text("a" ** 64));
    // Four labels of 63 bytes are 256 wire octets with the root, one over the limit.
    const long = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 63;
    try testing.expectError(Error.NameTooLong, Name.from_text(long));
}

test "a name at exactly the limit encodes" {
    // 63 + 63 + 63 + 61 bytes over four labels: 4 length octets, 250 bytes, one root octet.
    const at_limit = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61;
    const name = try Name.from_text(at_limit);
    try testing.expectEqual(@as(u8, 255), name.len);
}

test "equality is case-insensitive, per RFC 4343" {
    const lower = try Name.from_text("example.com");
    const mixed = try Name.from_text("ExAmPlE.CoM");
    const other = try Name.from_text("example.net");
    try testing.expect(lower.equal(&mixed));
    try testing.expect(mixed.equal(&lower));
    try testing.expect(!lower.equal(&other));
    try testing.expect(!lower.equal(&Name.root));
}

test "concat builds a search candidate and refuses one too long" {
    const host = try Name.from_text("www");
    const domain = try Name.from_text("example.com");
    const joined = try host.concat(&domain);
    try testing.expectEqualStrings("\x03www\x07example\x03com\x00", joined.wire());
    try testing.expect(joined.equal(&try Name.from_text("www.example.com")));
    try testing.expect((try Name.root.concat(&domain)).equal(&domain));
    try testing.expect((try domain.concat(&Name.root)).equal(&domain));

    const long = try Name.from_text("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63);
    try testing.expectError(Error.NameTooLong, long.concat(&long));
}

test "write_text round-trips a name the caller could have spelled" {
    var out: [constants.name_text_bytes_max]u8 = undefined;
    const name = try Name.from_text("www.example.com");
    const text = out[0..name.write_text(&out)];
    try testing.expectEqualStrings("www.example.com.", text);
    try testing.expect((try Name.from_text(text)).equal(&name));
}

test "append_label and terminate keep the length invariant" {
    var name: Name = Name.empty;
    try name.append_label("example");
    try testing.expectEqual(@as(u8, 8), name.len);
    try name.terminate();
    try testing.expectEqual(@as(u8, 9), name.len);
    try testing.expectError(Error.MalformedName, name.append_label(""));
    try testing.expectError(Error.LabelTooLong, name.append_label("a" ** 64));
}

test "a name at the limit refuses one more label and one more octet" {
    // Three labels of 63 and one of 61 is exactly 255 octets, the root included.
    var name = try Name.from_text("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61);
    try testing.expectEqual(@as(u8, constants.name_bytes_max), name.len);
    try testing.expectError(Error.NameTooLong, name.append_label("e"));
    try testing.expectError(Error.NameTooLong, name.terminate());

    // The same length reached without the root octet: terminating is the last thing that fits.
    var builder: Name = Name.empty;
    try builder.append_label("a" ** 63);
    try builder.append_label("b" ** 63);
    try builder.append_label("c" ** 63);
    try builder.append_label("d" ** 61);
    try testing.expectEqual(@as(u8, 254), builder.len);
    try testing.expectError(Error.NameTooLong, builder.append_label("e"));
    try builder.terminate();
    try testing.expectEqual(@as(u8, 255), builder.len);
}

test "a label that fits only by leaving no room for the root does not fit" {
    // 63 + 63 + 63 + 60 label octets and their four length octets are 253, so one more label needs
    // two octets and the root needs a third. The reservation in append_label is what makes this an
    // error here rather than a name that cannot be terminated.
    var builder: Name = Name.empty;
    try builder.append_label("a" ** 63);
    try builder.append_label("b" ** 63);
    try builder.append_label("c" ** 63);
    try builder.append_label("d" ** 60);
    try testing.expectEqual(@as(u8, 253), builder.len);
    try testing.expectError(Error.NameTooLong, builder.append_label("e"));
    try builder.terminate();
    try testing.expectEqual(@as(u8, 254), builder.len);
}

test "concat accepts a candidate of exactly the limit" {
    // 192 label octets and a 63-octet suffix are 255, the root included: the largest name there is.
    const prefix = try Name.from_text("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63);
    const suffix = try Name.from_text("d" ** 61);
    try testing.expectEqual(@as(u8, 193), prefix.len);
    try testing.expectEqual(@as(u8, 63), suffix.len);
    const joined = try prefix.concat(&suffix);
    try testing.expectEqual(@as(u8, constants.name_bytes_max), joined.len);
    try testing.expectEqual(@as(u8, 4), joined.label_count());
}

test "fold_case lowercases the labels and nothing else" {
    var name = try Name.from_text("Example.COM");
    const before = name;
    name.fold_case();
    try testing.expect(name.equal(&before));
    try testing.expectEqualStrings("\x07example\x03com\x00", name.wire());

    var root = Name.root;
    root.fold_case();
    try testing.expect(root.is_root());
}
