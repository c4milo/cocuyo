//! `<character-string>`: one length octet, then at most that many octets (RFC 1035 §3.3), which
//! is what `ares_expand_string` reads. `TXT` is one or more of them (§3.3.14) and `HINFO` exactly
//! two (§3.3.2).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");

pub const Read = struct { bytes: []const u8, end: usize };

/// The character-string at `offset`: its octets, and the offset after them.
pub fn read(rdata: []const u8, offset: usize) Error!Read {
    assert(offset <= rdata.len);
    if (offset >= rdata.len) return Error.MalformedMessage;
    const length: usize = rdata[offset];
    assert(length <= constants.character_string_bytes_max);
    const start = offset + 1;
    if (start + length > rdata.len) return Error.MalformedMessage;
    return .{ .bytes = rdata[start..][0..length], .end = start + length };
}

/// The strings of a `TXT` record in order (RFC 1035 §3.3.14). Every step consumes at least the
/// length octet, so the walk ends within the rdata's length; an rdata that ends inside a string
/// is malformed.
pub const Strings = struct {
    rdata: []const u8,
    offset: usize = 0,

    pub fn next(self: *Strings) Error!?[]const u8 {
        if (self.offset == self.rdata.len) return null;
        assert(self.offset < self.rdata.len);
        const string = try read(self.rdata, self.offset);
        self.offset = string.end;
        assert(self.offset <= self.rdata.len);
        return string.bytes;
    }
};

pub const Txt = struct {
    /// The strings of the record. A `TXT` holds one or more (RFC 1035 §3.3.14), so an empty rdata
    /// is malformed.
    pub fn strings(rdata: []const u8) Error!Strings {
        if (rdata.len == 0) return Error.MalformedMessage;
        assert(rdata.len >= 1);
        return .{ .rdata = rdata };
    }
};

/// The two strings of an `HINFO` record (RFC 1035 §3.3.2), which must fill the rdata exactly.
pub const Hinfo = struct {
    cpu: []const u8,
    os: []const u8,

    pub fn parse(rdata: []const u8) Error!Hinfo {
        const cpu = try read(rdata, 0);
        const os = try read(rdata, cpu.end);
        if (os.end != rdata.len) return Error.MalformedMessage;
        assert(cpu.end < os.end);
        return .{ .cpu = cpu.bytes, .os = os.bytes };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a TXT record's strings come back in order, and an empty rdata is malformed" {
    var strings = try Txt.strings(&fixtures.txt_two);
    try testing.expectEqualStrings("hello", (try strings.next()).?);
    try testing.expectEqualStrings("world", (try strings.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try strings.next());
    try testing.expectError(Error.MalformedMessage, Txt.strings(&.{}));
}

test "a string that runs past the rdata is malformed, wherever it sits" {
    var strings = try Txt.strings(&fixtures.txt_short);
    try testing.expectEqualStrings("hello", (try strings.next()).?);
    try testing.expectError(Error.MalformedMessage, strings.next());
    try testing.expectError(Error.MalformedMessage, read(&fixtures.txt_two, fixtures.txt_two.len));
}

test "an empty string is a string" {
    var strings = try Txt.strings(&fixtures.txt_empty_string);
    try testing.expectEqualStrings("", (try strings.next()).?);
    try testing.expectEqual(@as(?[]const u8, null), try strings.next());
}

test "HINFO is two strings that fill the rdata" {
    const hinfo = try Hinfo.parse(&fixtures.hinfo);
    try testing.expectEqualStrings("ARM64", hinfo.cpu);
    try testing.expectEqualStrings("Darwin", hinfo.os);
    try testing.expectError(Error.MalformedMessage, Hinfo.parse(&fixtures.hinfo_one_string));
    try testing.expectError(Error.MalformedMessage, Hinfo.parse(&fixtures.hinfo_trailing));
}
