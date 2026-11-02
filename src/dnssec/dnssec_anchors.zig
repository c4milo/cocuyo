//! Trust anchors from text: DS and DNSKEY records in the master file format (RFC 1035 §5.1), their
//! rdata in presentation form (RFC 4034 §5.3, §2.2), for a key store's anchors (docs/design.md §25
//! step 15, §17 questions 101 and 104 to 107). It reads a part of the format:
//! - `;` comments, and parentheses across lines;
//! - an optional TTL and an optional class `IN`, in either order;
//! - absolute owner names, and an entry that begins with a blank, which the last owner owns.
//! It refuses the control entries and the algorithm mnemonics.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Kind = core.Kind;
const Name = core.Name;
const Anchor = @import("dnssec_store.zig").Anchor;
const base64 = @import("dnssec_base64.zig");
const constants = @import("constants.zig");
const limits = @import("limits.zig");

pub const Error = error{
    /// The text is not an anchor this parser reads.
    MalformedAnchor,
    /// The text holds no anchor.
    NoAnchors,
    /// The text holds more anchors than `anchors` or `limits.anchors_max`.
    TooManyAnchors,
    /// The anchors' rdata does not fit in `rdata`.
    RdataFull,
    /// One anchor's rdata is longer than `core.limits.rdata_bytes_max` (§17 question 107).
    AnchorTooLong,
};

/// Reads the anchors in `text` into `anchors`, their rdata into `rdata`, and returns the anchors
/// read. Each anchor's rdata is a slice of `rdata`, which must outlive the store.
pub fn parse(text: []const u8, anchors: []Anchor, rdata: []u8) Error![]Anchor {
    var lexer: Lexer = .{ .text = text };
    var out: Output = .{ .rdata = rdata };
    var owner: ?Name = null;
    var count: usize = 0;
    while (try lexer.begin()) |owner_stated| {
        // A store takes `anchors_max` (§17 question 105).
        if (count == @min(anchors.len, limits.anchors_max)) return Error.TooManyAnchors;
        if (owner_stated) owner = try owner_name(try lexer.need());
        // "If an entry for an RR begins with a blank, then the RR is assumed to be owned by the
        // last stated owner" (RFC 1035 §5.1). The first entry has none.
        anchors[count] = try record(&lexer, owner orelse return Error.MalformedAnchor, &out);
        count += 1;
    }
    if (count == 0) return Error.NoAnchors;
    assert(count <= limits.anchors_max);
    return anchors[0..count];
}

fn owner_name(word: []const u8) Error!Name {
    assert(word.len >= 1);
    // RFC 1035 §5.1's control entries, $ORIGIN and $INCLUDE, and RFC 2308 §4's $TTL.
    if (word[0] == constants.control_mark) return Error.MalformedAnchor;
    // "A relative name is an error when no origin is available" (RFC 1035 §5.1).
    if (word[word.len - 1] != constants.label_separator) return Error.MalformedAnchor;
    return Name.from_text(word) catch Error.MalformedAnchor;
}

/// One record after its owner: "[<TTL>] [<class>] <type> <RDATA>" or "[<class>] [<TTL>] <type>
/// <RDATA>" (RFC 1035 §5.1).
fn record(lexer: *Lexer, owner: Name, out: *Output) Error!Anchor {
    var seen: Seen = .{};
    var word = try lexer.need();
    if (try seen.take(word)) word = try lexer.need();
    if (try seen.take(word)) word = try lexer.need();
    const kind: Kind = if (std.ascii.eqlIgnoreCase(word, "DS"))
        .ds
    else if (std.ascii.eqlIgnoreCase(word, "DNSKEY"))
        .dnskey
    else
        return Error.MalformedAnchor;
    out.start = out.used;
    if (kind == .ds) try ds(lexer, out) else try dnskey(lexer, out);
    assert(out.used - out.start <= core.limits.rdata_bytes_max);
    return .{ .zone = owner, .kind = kind, .rdata = out.rdata[out.start..out.used] };
}

/// The optional fields before the type: a TTL once and the class once.
const Seen = struct {
    ttl: bool = false,
    class: bool = false,

    /// Whether `word` is the TTL or the class, each taken once.
    fn take(self: *Seen, word: []const u8) Error!bool {
        if (!self.ttl and digits(word)) {
            // "a maximum value of 2147483647" (RFC 2181 §8). The store keeps an anchor as long as
            // it lives, so the value is read and not kept.
            _ = try decimal(u31, word);
            self.ttl = true;
            return true;
        }
        // An anchor is of class IN (RFC 4034 §2, §5).
        if (!self.class and std.ascii.eqlIgnoreCase(word, "IN")) {
            self.class = true;
            return true;
        }
        return false;
    }
};

/// "Key Tag", "Algorithm", "Digest Type" as unsigned decimal integers, then "the Digest ... as a
/// sequence of case-insensitive hexadecimal digits. Whitespace is allowed within the hexadecimal
/// text" (RFC 4034 §5.3).
fn ds(lexer: *Lexer, out: *Output) Error!void {
    try out.put_int(u16, try decimal(u16, try lexer.need()));
    try out.put_int(u8, try algorithm(try lexer.need()));
    try out.put_int(u8, try decimal(u8, try lexer.need()));
    var high: ?u4 = null;
    var words: usize = 0;
    while (try lexer.word()) |word| : (words += 1) {
        for (word) |character| {
            const nibble: u4 = @intCast(std.fmt.charToDigit(character, constants.hex_radix) catch return Error.MalformedAnchor);
            if (high) |value| {
                try out.put((@as(u8, value) << @bitSizeOf(u4)) | nibble);
                high = null;
            } else high = nibble;
        }
    }
    if (words == 0 or high != null) return Error.MalformedAnchor;
}

/// "Flag", "Protocol" and "Algorithm" as unsigned decimal integers, then "the Public Key ... as a
/// Base64 encoding of the Public Key. Whitespace is allowed within the Base64 text" (RFC 4034
/// §2.2).
fn dnskey(lexer: *Lexer, out: *Output) Error!void {
    try out.put_int(u16, try decimal(u16, try lexer.need()));
    try out.put_int(u8, try decimal(u8, try lexer.need()));
    try out.put_int(u8, try algorithm(try lexer.need()));
    var decoder: base64.Decoder = .{};
    while (try lexer.word()) |word| {
        for (word) |character| {
            const octet = decoder.feed(character) catch return Error.MalformedAnchor;
            if (octet) |value| try out.put(value);
        }
    }
    if (!decoder.finished()) return Error.MalformedAnchor;
}

/// The algorithm "as an unsigned decimal integer or as an algorithm mnemonic as specified in
/// Appendix A.1" (RFC 4034 §2.2, §5.3). Only the integer is read: every mnemonic of Appendix A.1
/// names an algorithm the verifier does not check.
fn algorithm(word: []const u8) Error!u8 {
    return decimal(u8, word);
}

fn decimal(comptime T: type, word: []const u8) Error!T {
    // An unsigned decimal integer: digits alone, which `parseInt` alone does not require.
    if (!digits(word)) return Error.MalformedAnchor;
    return std.fmt.parseInt(T, word, constants.decimal_radix) catch Error.MalformedAnchor;
}

fn digits(word: []const u8) bool {
    if (word.len == 0) return false;
    for (word) |character| if (!std.ascii.isDigit(character)) return false;
    return true;
}

/// Where the rdata goes: the caller's memory, and the start of the anchor it now writes.
const Output = struct {
    rdata: []u8,
    used: usize = 0,
    start: usize = 0,

    fn put(self: *Output, octet: u8) Error!void {
        assert(self.start <= self.used);
        // One anchor's rdata stays within `rdata_bytes_max` (§17 question 107).
        if (self.used - self.start == core.limits.rdata_bytes_max) return Error.AnchorTooLong;
        if (self.used == self.rdata.len) return Error.RdataFull;
        self.rdata[self.used] = octet;
        self.used += 1;
    }

    /// An integer in network order (RFC 1035 §2.3.2).
    fn put_int(self: *Output, comptime T: type, value: T) Error!void {
        var octets: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &octets, value, .big);
        for (octets) |octet| try self.put(octet);
    }
};

/// The words of the text, entry by entry (RFC 1035 §5.1): "Any combination of tabs and spaces act
/// as a delimiter", a comment "starts with a ';'", and within parentheses "line terminations are
/// not recognized".
const Lexer = struct {
    text: []const u8,
    at: usize = 0,
    /// Within parentheses.
    open: bool = false,

    /// Moves to the next entry, past blank lines and lines of comment alone, and returns whether
    /// the entry begins with its owner. Null at the end of the text.
    fn begin(self: *Lexer) Error!?bool {
        assert(!self.open);
        while (self.at < self.text.len) {
            assert(self.at == 0 or self.text[self.at - 1] == '\n');
            const content = blank_end(self.text, self.at);
            const rest_blank = content == self.text.len or self.text[content] == '\n' or self.text[content] == ';';
            if (!rest_blank) return content == self.at;
            self.at = line_end(self.text, content);
        }
        return null;
    }

    /// The next word of the entry, or null at its end.
    fn word(self: *Lexer) Error!?[]const u8 {
        while (self.at < self.text.len) {
            self.at = blank_end(self.text, self.at);
            if (self.at == self.text.len) break;
            const character = self.text[self.at];
            if (delimiter(character)) {
                if (try self.mark(character)) return null;
                continue;
            }
            const start = self.at;
            while (self.at < self.text.len and !delimiter(self.text[self.at])) self.at += 1;
            assert(self.at > start);
            return self.text[start..self.at];
        }
        // A parenthesis that the text never closes.
        if (self.open) return Error.MalformedAnchor;
        return null;
    }

    /// Moves past a comment, a newline or a parenthesis, and returns whether the entry ended.
    fn mark(self: *Lexer, character: u8) Error!bool {
        assert(!blank(character));
        switch (character) {
            ';' => {
                self.at = newline_at(self.text, self.at);
                return false;
            },
            '\n' => {
                self.at += 1;
                return !self.open;
            },
            // Parentheses do not nest, and each closes once (RFC 1035 §5.1).
            '(', ')' => {
                if (self.open == (character == '(')) return Error.MalformedAnchor;
                self.open = !self.open;
                self.at += 1;
                return false;
            },
            else => unreachable,
        }
    }

    /// The next word, which the entry must have.
    fn need(self: *Lexer) Error![]const u8 {
        return try self.word() orelse Error.MalformedAnchor;
    }
};

fn blank(character: u8) bool {
    return character == ' ' or character == '\t' or character == '\r';
}

fn delimiter(character: u8) bool {
    return blank(character) or character == '\n' or character == ';' or character == '(' or character == ')';
}

fn blank_end(text: []const u8, from: usize) usize {
    var at = from;
    while (at < text.len and blank(text[at])) at += 1;
    return at;
}

/// The index of the newline that ends the line holding `from`, or the end of the text.
fn newline_at(text: []const u8, from: usize) usize {
    return std.mem.indexOfScalarPos(u8, text, from, '\n') orelse text.len;
}

/// The index after the end of the line that holds `from`.
fn line_end(text: []const u8, from: usize) usize {
    return @min(newline_at(text, from) + 1, text.len);
}
