//! `Kind` and `Question`: what a lookup asks, and the record type it asks for.
//!
//! A question carries one thing presentation form has and wire form does not: whether the caller
//! wrote the name as absolute. The wire encoding of `example.com` and `example.com.` is the same,
//! but the first is a name to try the search list against and the second is a name to try alone
//! (docs/design.md §5), so the trailing dot is recorded here where it is read.
const std = @import("std");
const assert = std.debug.assert;
const Error = @import("errors.zig").Error;
const constants = @import("constants.zig");
const Address = @import("address.zig").Address;
const Name = @import("name.zig").Name;
const name_text = @import("name_text.zig");
const name_reverse = @import("name_reverse.zig");

/// A record type. The named ones are every type c-ares parses (docs/design.md §19 step 9), each
/// with the RFC that defines its fields. The enum is open (decision 31): `Kind.of` is any code, a
/// question may name one cocuyo does not, and its records come back with their rdata raw (RFC 3597
/// §3), as does a record of such a type in any answer.
pub const Kind = enum(u16) {
    a = 1, // RFC 1035 §3.4.1
    ns = 2, // RFC 1035 §3.3.11
    cname = 5, // RFC 1035 §3.3.1
    soa = 6, // RFC 1035 §3.3.13
    ptr = 12, // RFC 1035 §3.3.12
    hinfo = 13, // RFC 1035 §3.3.2
    mx = 15, // RFC 1035 §3.3.9
    txt = 16, // RFC 1035 §3.3.14
    sig = 24, // RFC 2535 §4.1, kept in force by RFC 2931
    aaaa = 28, // RFC 3596 §2.2
    srv = 33, // RFC 2782
    naptr = 35, // RFC 3403 §4.1
    opt = 41, // RFC 6891 §6.1.2, a pseudo-record and never a question
    tlsa = 52, // RFC 6698 §2.1
    svcb = 64, // RFC 9460 §2.2
    https = 65, // RFC 9460 §9
    any = 255, // RFC 1035 §3.2.3, a question and never a record; RFC 8482 §4 says what answers it
    uri = 256, // RFC 7553 §4.5
    caa = 257, // RFC 8659 §4.1
    _,

    /// The type a code names, whether cocuyo names it or not.
    pub fn of(type_code: u16) Kind {
        return @enumFromInt(type_code);
    }

    /// Whether a caller may ask for this type (docs/design.md §19 step 9, Questions). ANY is the
    /// one query type cocuyo reads (RFC 8482); every other refusal is a code no record of which
    /// can be kept whole.
    pub fn queryable(self: Kind) bool {
        const type_code = self.code();
        if (self == .any) return true;
        // "must never be allocated for ordinary use" (RFC 6895 §3.1).
        if (type_code == constants.type_code_none) return false;
        // A pseudo-record of a message, not of a name (RFC 6891 §6.1.1).
        if (self == .opt) return false;
        // Kept for query and meta types (RFC 6895 §3.1), none of them a type whose rdata can be
        // kept whole (RFC 3597 §2).
        return type_code < constants.type_code_query_meta_first or type_code > constants.type_code_query_meta_last;
    }

    /// The type as it appears in a question or a record header.
    pub fn code(self: Kind) u16 {
        return @intFromEnum(self);
    }

    /// The type a record header names, when cocuyo names it too; `of` is any code.
    pub fn from_code(type_code: u16) ?Kind {
        const kind = of(type_code);
        return if (std.enums.tagName(Kind, kind) != null) kind else null;
    }

    /// Where a lookup keeps this type's records (docs/design.md §19 step 9): addresses and
    /// PTR names in their own storage, everything else as rdata with its names written out.
    pub const Storage = enum { addresses, names, rdata };

    pub fn storage(self: Kind) Storage {
        return switch (self) {
            .a, .aaaa => .addresses,
            .ptr => .names,
            else => .rdata,
        };
    }
};

pub const Question = struct {
    name: Name,
    kind: Kind,
    /// Whether the name was written absolute, with a trailing dot. An absolute name has one
    /// candidate: itself.
    absolute: bool = false,

    /// A question from presentation form, refused with `UnqueryableType` for a type never asked
    /// for (`Kind.queryable`). A question built as a literal must name a queryable type, which
    /// the codec and the cache assert.
    pub fn from_text(text: []const u8, kind: Kind) Error!Question {
        if (!kind.queryable()) return Error.UnqueryableType;
        const question: Question = .{
            .name = try Name.from_text(text),
            .kind = kind,
            .absolute = is_absolute(text),
        };
        assert(question.name.len >= 1);
        assert(question.kind.queryable());
        return question;
    }

    /// The reverse question for an address, which is always absolute: the name is built from the
    /// address and there is nothing for a search list to add.
    pub fn from_address(address: *const Address) Error!Question {
        const question: Question = .{
            .name = try name_reverse.from_address(address),
            .kind = .ptr,
            .absolute = true,
        };
        assert(question.kind == .ptr);
        assert(question.absolute);
        return question;
    }
};

/// Whether presentation form marks the name absolute. The root is absolute, and so is any name
/// whose text ends in the separator.
fn is_absolute(text: []const u8) bool {
    if (text.len == 0) return true;
    return text[text.len - 1] == name_text.separator;
}

// Tests.

const testing = std.testing;

test "a trailing dot makes the question absolute and the wire name identical" {
    const relative = try Question.from_text("example.com", .a);
    const absolute = try Question.from_text("example.com.", .a);
    try testing.expect(!relative.absolute);
    try testing.expect(absolute.absolute);
    try testing.expect(relative.name.equal(&absolute.name));
}

test "the root and the empty name are absolute" {
    try testing.expect((try Question.from_text("", .a)).absolute);
    try testing.expect((try Question.from_text(".", .aaaa)).absolute);
}

test "a reverse question is a PTR question and is absolute" {
    const question = try Question.from_address(&Address.from_v4(.{ 9, 9, 9, 9 }));
    try testing.expectEqual(Kind.ptr, question.kind);
    try testing.expect(question.absolute);
    try testing.expect(question.name.equal(&try Name.from_text("9.9.9.9.in-addr.arpa")));
}

test "every kind but OPT is queryable, and each has its registry code" {
    try testing.expect(Kind.a.queryable());
    try testing.expect(Kind.ptr.queryable());
    try testing.expect(Kind.cname.queryable());
    try testing.expect(Kind.any.queryable());
    try testing.expect(!Kind.opt.queryable());
    try testing.expectEqual(@as(u16, 1), Kind.a.code());
    try testing.expectEqual(@as(u16, 28), Kind.aaaa.code());
    try testing.expectEqual(@as(u16, 65), Kind.https.code());
    try testing.expectEqual(@as(u16, 257), Kind.caa.code());
}

test "a type code maps back to its kind, and an unknown one to nothing" {
    try testing.expectEqual(@as(?Kind, .mx), Kind.from_code(15));
    try testing.expectEqual(@as(?Kind, .uri), Kind.from_code(256));
    try testing.expectEqual(@as(?Kind, null), Kind.from_code(99));
    try testing.expectEqual(@as(?Kind, null), Kind.from_code(0));
    // Any code is a kind all the same, named or not.
    try testing.expectEqual(Kind.mx, Kind.of(15));
    try testing.expectEqual(@as(u16, 99), Kind.of(99).code());
}

test "a question may name any type but zero, OPT and the query and meta range, ANY apart" {
    // Refused: zero, OPT, and 128 to 254, AXFR (252) and TSIG (250) among them.
    for ([_]u16{ 0, 41, 128, 250, 252, 254 }) |refused| {
        try testing.expect(!Kind.of(refused).queryable());
        try testing.expectError(Error.UnqueryableType, Question.from_text("example.com", Kind.of(refused)));
    }
    // Asked as they are: ANY, the codes just past the range's ends, a DNSSEC type (DNSKEY, 48),
    // one cocuyo does not name (99), one reserved for future use and one for private use.
    for ([_]u16{ 255, 127, 256, 48, 99, 0xF000, 0xFF00, 0xFFFF }) |asked| {
        try testing.expect(Kind.of(asked).queryable());
        const question = try Question.from_text("example.com", Kind.of(asked));
        try testing.expectEqual(asked, question.kind.code());
    }
}

test "addresses, PTR names and everything else each have their storage" {
    try testing.expectEqual(Kind.Storage.addresses, Kind.a.storage());
    try testing.expectEqual(Kind.Storage.addresses, Kind.aaaa.storage());
    try testing.expectEqual(Kind.Storage.names, Kind.ptr.storage());
    try testing.expectEqual(Kind.Storage.rdata, Kind.mx.storage());
    try testing.expectEqual(Kind.Storage.rdata, Kind.any.storage());
    try testing.expectEqual(Kind.Storage.rdata, Kind.cname.storage());
}

test "a malformed name is an error before a question exists" {
    try testing.expectError(Error.MalformedName, Question.from_text("a..b", .a));
}
