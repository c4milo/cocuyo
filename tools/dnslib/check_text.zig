//! The text half of the dnslib check (`check.zig`). Each file of dnslib's test directory holds one
//! response a live server sent, in hexadecimal on its `;; RESPONSE:` line, and dnslib's reading of
//! it after that line, printed the way dig prints: each section's records in master-file form (RFC
//! 1035 §5.1), one record to a line. This file reads both out, and splits a record's line into its
//! fields. A field is a run of characters between spaces or tabs, or a quoted one, which takes what
//! RFC 1035 §5.1 lets a master file's character-string take: "\X where X is any character other
//! than a digit (0-9)" stands for X, and "\DDD where each D is a digit is the octet corresponding
//! to the decimal number described by DDD".
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");

pub const Error = error{Malformed};

/// The fields one line holds at most: the owner, the TTL, the class and the type, then a TXT's
/// strings, which dnslib's longest splits into a handful.
pub const fields_max = 64;

/// The digits of a `\DDD` escape (RFC 1035 §5.1).
const decimal_escape_digits = 3;
const decimal_base = 10;

/// The three sections a response's records sit in (RFC 1035 §4.1), in the order a file prints
/// them.
pub const Section = enum { answer, authority, additional };

/// What a file says: the response's octets in hexadecimal, and the record lines of each section.
pub const File = struct {
    response_hex: []const u8,
    sections: std.EnumArray(Section, []const []const u8),
};

const response_marker = ";; RESPONSE: ";
const section_markers = std.EnumArray(Section, []const u8).init(.{
    .answer = ";; ANSWER SECTION:",
    .authority = ";; AUTHORITY SECTION:",
    .additional = ";; ADDITIONAL SECTION:",
});
const comment = ';';

/// The response, and the record lines each section holds after it. A section runs from its marker
/// to a blank line or the next marker. A line that starts with a semicolon is a comment, which is
/// how dnslib prints the OPT pseudo-record (RFC 6891 §6.1.1), so it is not a record line. `lines`
/// holds the record lines found, each section's run of them in order.
pub fn read(bytes: []const u8, lines: [][]const u8) Error!File {
    const response_at = std.mem.indexOf(u8, bytes, response_marker) orelse return Error.Malformed;
    const after = bytes[response_at + response_marker.len ..];
    const hex_end = std.mem.indexOfScalar(u8, after, '\n') orelse after.len;
    var file: File = .{
        .response_hex = std.mem.trim(u8, after[0..hex_end], " \r"),
        .sections = .initFill(lines[0..0]),
    };
    var current: ?Section = null;
    var count: usize = 0;
    var rest = std.mem.splitScalar(u8, after[hex_end..], '\n');
    for (0..after.len + 1) |_| {
        const line = std.mem.trim(u8, rest.next() orelse return file, " \r");
        if (marked(line)) |section| {
            current = section;
            file.sections.set(section, lines[count..count]);
        } else if (line.len == 0) {
            current = null;
        } else if (line[0] != comment) {
            const section = current orelse continue;
            if (count == lines.len) return Error.Malformed;
            lines[count] = line;
            count += 1;
            const start = count - file.sections.get(section).len - 1;
            file.sections.set(section, lines[start..count]);
        }
    }
    return Error.Malformed;
}

/// The section `line` opens, or null when it opens none.
fn marked(line: []const u8) ?Section {
    for (std.enums.values(Section)) |section| {
        if (std.mem.eql(u8, line, section_markers.get(section))) return section;
    }
    return null;
}

/// The octets `hex` writes, into `out`.
pub fn octets(hex: []const u8, out: []u8) Error![]u8 {
    if (hex.len % 2 != 0 or hex.len / 2 > out.len) return Error.Malformed;
    return std.fmt.hexToBytes(out[0 .. hex.len / 2], hex) catch Error.Malformed;
}

/// The fields of one line, each a slice of the line or, for a quoted one, of `scratch`, where its
/// escapes are undone.
pub const Fields = struct {
    items: [fields_max][]const u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const Fields) []const []const u8 {
        return self.items[0..self.len];
    }
};

pub fn split(line: []const u8, scratch: []u8) Error!Fields {
    var fields: Fields = .{};
    var at: usize = 0;
    var used: usize = 0;
    for (0..line.len + 1) |_| {
        while (at < line.len and is_space(line[at])) at += 1;
        if (at == line.len) return fields;
        if (fields.len == fields_max) return Error.Malformed;
        if (line[at] == '"') {
            const quoted = try unquote(line, at + 1, scratch[used..]);
            fields.items[fields.len] = scratch[used..][0..quoted.len];
            used += quoted.len;
            at = quoted.end;
        } else {
            const start = at;
            while (at < line.len and !is_space(line[at])) at += 1;
            fields.items[fields.len] = line[start..at];
        }
        fields.len += 1;
    }
    return Error.Malformed;
}

fn is_space(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

/// The octets of the quoted field that starts after its quote at `start`, written into `out`, and
/// the offset after its closing quote.
fn unquote(line: []const u8, start: usize, out: []u8) Error!struct { len: usize, end: usize } {
    var at = start;
    var len: usize = 0;
    for (0..line.len) |_| {
        if (at >= line.len or len >= out.len) return Error.Malformed;
        const byte = line[at];
        if (byte == '"') return .{ .len = len, .end = at + 1 };
        if (byte != '\\') {
            out[len] = byte;
            at += 1;
        } else {
            const escaped = try escape(line, at + 1);
            out[len] = escaped.octet;
            at = escaped.end;
        }
        len += 1;
    }
    return Error.Malformed;
}

/// The octet an escape after a backslash at `start - 1` stands for, and the offset after it.
fn escape(line: []const u8, start: usize) Error!struct { octet: u8, end: usize } {
    if (start >= line.len) return Error.Malformed;
    if (!std.ascii.isDigit(line[start])) return .{ .octet = line[start], .end = start + 1 };
    if (start + decimal_escape_digits > line.len) return Error.Malformed;
    const value = std.fmt.parseInt(u8, line[start..][0..decimal_escape_digits], decimal_base) catch return Error.Malformed;
    return .{ .octet = value, .end = start + decimal_escape_digits };
}

// Tests.

const testing = std.testing;

test "a line splits into its fields, a quoted one with its escapes undone" {
    var scratch: [64]u8 = undefined;
    const fields = try split("he.net.\t 300  IN TXT \"a \\\"b\\\" \\065\" \"\"", &scratch);
    try testing.expectEqual(@as(usize, 6), fields.len);
    try testing.expectEqualStrings("he.net.", fields.items[0]);
    try testing.expectEqualStrings("TXT", fields.items[3]);
    try testing.expectEqualStrings("a \"b\" A", fields.items[4]);
    try testing.expectEqualStrings("", fields.items[5]);
}

test "a quote left open, or an escape cut short, is malformed" {
    var scratch: [64]u8 = undefined;
    try testing.expectError(Error.Malformed, split("x. 1 IN TXT \"open", &scratch));
    try testing.expectError(Error.Malformed, split("x. 1 IN TXT \"\\06\"", &scratch));
}

test "a file gives its response's hexadecimal and each section's record lines, comments apart" {
    const file_text =
        \\;; QUERY: 1234
        \\;; ADDITIONAL SECTION:
        \\query.example. 60 IN A 192.0.2.9
        \\;; RESPONSE: 12348180
        \\;; ANSWER SECTION:
        \\example.com.   60  IN  A  192.0.2.1
        \\example.com.   60  IN  A  192.0.2.2
        \\;; AUTHORITY SECTION:
        \\example.com.   60  IN  NS  ns.example.com.
        \\;; ADDITIONAL SECTION:
        \\;; OPT PSEUDOSECTION
        \\; EDNS: version: 0, flags: do; udp: 4096
        \\
        \\stray.example. 60 IN A 192.0.2.3
    ;
    var lines: [4][]const u8 = undefined;
    const file = try read(file_text, &lines);
    try testing.expectEqualStrings("12348180", file.response_hex);
    try testing.expectEqual(@as(usize, 2), file.sections.get(.answer).len);
    try testing.expectEqualStrings("example.com.   60  IN  A  192.0.2.2", file.sections.get(.answer)[1]);
    try testing.expectEqual(@as(usize, 1), file.sections.get(.authority).len);
    try testing.expectEqual(@as(usize, 0), file.sections.get(.additional).len);
    var out: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x81, 0x80 }, try octets(file.response_hex, &out));
}
