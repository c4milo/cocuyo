//! `Kind` and `Question`: what a lookup asks, and the record type it asks for.
//!
//! A question carries one thing presentation form has and wire form does not: whether the caller
//! wrote the name as absolute. The wire encoding of `example.com` and `example.com.` is the same,
//! but the first is a name to try the search list against and the second is a name to try alone
//! (docs/design.md §5), so the trailing dot is recorded here where it is read.
const std = @import("std");
const assert = std.debug.assert;
const Error = @import("errors.zig").Error;
const Address = @import("address.zig").Address;
const Name = @import("name.zig").Name;
const name_text = @import("name_text.zig");
const name_reverse = @import("name_reverse.zig");

/// The record types cocuyo names: every type c-ares parses (docs/design.md §19 step 9), each
/// with the RFC that defines its fields. A record of a type not here is not an error: the record
/// walk keeps the type code, and a caller reads its rdata raw (RFC 3597 §3).
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

    /// Whether a caller may ask for this type. `opt` is a pseudo-record that belongs to a
    /// message, not to a name (RFC 6891 §6.1.1), so it is the one type that is never a question.
    pub fn queryable(self: Kind) bool {
        return self != .opt;
    }

    /// The type as it appears in a question or a record header.
    pub fn code(self: Kind) u16 {
        return @intFromEnum(self);
    }

    /// The type a record header names, when cocuyo names it too.
    pub fn from_code(type_code: u16) ?Kind {
        return std.enums.fromInt(Kind, type_code);
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

    /// A question from presentation form. The kind must be one version one queries.
    pub fn from_text(text: []const u8, kind: Kind) Error!Question {
        assert(kind.queryable());
        const question: Question = .{
            .name = try Name.from_text(text),
            .kind = kind,
            .absolute = is_absolute(text),
        };
        assert(question.name.len >= 1);
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
