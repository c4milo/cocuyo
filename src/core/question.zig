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

/// The record types cocuyo names. `a`, `aaaa` and `ptr` are the three a caller may ask for;
/// `cname` and `opt` appear in responses and are never a question (docs/design.md §1).
pub const Kind = enum(u16) {
    a = 1,
    soa = 6,
    cname = 5,
    ptr = 12,
    aaaa = 28,
    opt = 41,

    /// Whether a caller may ask for this type in version one. `soa` is read from an authority
    /// section for a negative answer's TTL (RFC 2308 §5) and is never a question.
    pub fn queryable(self: Kind) bool {
        return switch (self) {
            .a, .aaaa, .ptr => true,
            .soa, .cname, .opt => false,
        };
    }

    /// The type as it appears in a question or a record header.
    pub fn code(self: Kind) u16 {
        return @intFromEnum(self);
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

test "only three kinds are queryable, and each has its RFC code" {
    try testing.expect(Kind.a.queryable());
    try testing.expect(Kind.aaaa.queryable());
    try testing.expect(Kind.ptr.queryable());
    try testing.expect(!Kind.cname.queryable());
    try testing.expect(!Kind.opt.queryable());
    try testing.expect(!Kind.soa.queryable());
    try testing.expectEqual(@as(u16, 6), Kind.soa.code());
    try testing.expectEqual(@as(u16, 1), Kind.a.code());
    try testing.expectEqual(@as(u16, 28), Kind.aaaa.code());
    try testing.expectEqual(@as(u16, 12), Kind.ptr.code());
    try testing.expectEqual(@as(u16, 41), Kind.opt.code());
}

test "a malformed name is an error before a question exists" {
    try testing.expectError(Error.MalformedName, Question.from_text("a..b", .a));
}
