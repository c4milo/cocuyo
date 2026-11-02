//! Base64 with the standard alphabet and its padding, decoded one character at a time (RFC 4648
//! §4). A DNSKEY's public key in presentation form is Base64 that "Whitespace is allowed within"
//! (RFC 4034 §2.2), so the text of one key comes in pieces, and the decoder holds the bits
//! between them. It decodes only: cocuyo never writes a key.
const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{MalformedBase64};

/// The bits one character of the alphabet holds (RFC 4648 §4).
const bits_per_character: u4 = 6;
const bits_per_octet: u4 = @bitSizeOf(u8);
/// The characters of one quantum, which the padding completes (RFC 4648 §4).
const quantum_characters: usize = 4;
/// The pad characters a quantum ends with at most: two, after one octet (RFC 4648 §4).
const quantum_pads: u2 = 2;
const pad = std.base64.standard.pad_char.?;
const alphabet = std.base64.standard_alphabet_chars;

pub const Decoder = struct {
    accumulated: u16 = 0,
    held: u4 = 0,
    characters: usize = 0,
    pads: u2 = 0,

    /// Takes one character, and returns the octet it completes, if any.
    pub fn feed(self: *Decoder, character: u8) Error!?u8 {
        self.characters += 1;
        if (character == pad) {
            if (self.pads == quantum_pads) return Error.MalformedBase64;
            self.pads += 1;
            return null;
        }
        // Only padding follows padding (RFC 4648 §4).
        if (self.pads != 0) return Error.MalformedBase64;
        const value = value_of(character) orelse return Error.MalformedBase64;
        self.accumulated = (self.accumulated << bits_per_character) | value;
        self.held += bits_per_character;
        if (self.held < bits_per_octet) return null;
        self.held -= bits_per_octet;
        const octet: u8 = @truncate(self.accumulated >> self.held);
        self.accumulated &= (@as(u16, 1) << self.held) - 1;
        assert(self.held < bits_per_octet);
        return octet;
    }

    /// Whether the text ended on a whole quantum, with zero pad bits. RFC 4648 §3.5 lets a decoder
    /// refuse pad bits that are not zero, and this one does, so one key has one text.
    pub fn finished(self: *const Decoder) bool {
        assert(self.held < bits_per_octet);
        return self.characters != 0 and self.characters % quantum_characters == 0 and self.accumulated == 0;
    }
};

fn value_of(character: u8) ?u6 {
    const index = std.mem.indexOfScalar(u8, &alphabet, character) orelse return null;
    return @intCast(index);
}

// Tests.

const testing = std.testing;

fn decode(text: []const u8, out: []u8) Error![]u8 {
    var decoder: Decoder = .{};
    var written: usize = 0;
    for (text) |character| {
        const octet = try decoder.feed(character) orelse continue;
        out[written] = octet;
        written += 1;
    }
    if (!decoder.finished()) return Error.MalformedBase64;
    return out[0..written];
}

test "RFC 4648 §10's base64 vectors decode" {
    var out: [8]u8 = undefined;
    const vectors = [_][2][]const u8{
        .{ "Zg==", "f" },        .{ "Zm8=", "fo" },        .{ "Zm9v", "foo" },
        .{ "Zm9vYg==", "foob" }, .{ "Zm9vYmE=", "fooba" }, .{ "Zm9vYmFy", "foobar" },
    };
    for (vectors) |vector| try testing.expectEqualSlices(u8, vector[1], try decode(vector[0], &out));
}

test "a text that is not canonical base64 is refused" {
    var out: [8]u8 = undefined;
    // No padding, too much, data after it, a character outside the alphabet, pad bits set.
    const refused = [_][]const u8{ "", "Zg", "Zg=", "Z===", "Zg=a", "Zg=A", "Zm9-", "Zh==", "Zm9=" };
    for (refused) |text| try testing.expectError(Error.MalformedBase64, decode(text, &out));
}
