//! The records of a message the validator reads: the answer and the authority sections, the
//! place of each record kept once (docs/design.md §25 step 9). Nothing of the message is copied
//! but the canonical rdata of one record at a time, into a `Scratch` on the stack.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Kind = core.Kind;
const Name = core.Name;
const canonical_form = @import("dnssec_canonical.zig");
const Scratch = canonical_form.Scratch;

pub const Section = enum(u1) { answer, authority };

pub const Message = struct {
    bytes: []const u8,
    records: [core.limits.records_max]wire.Record,
    sections: [core.limits.records_max]Section,
    count: usize,

    /// Reads the answer and the authority sections of `bytes`, a message that passed the checks
    /// of docs/design.md §7, whose one question is `asked`. False when the two sections hold more
    /// than `records_max` records: a signature covers every record of its RRset, so one the walk
    /// cannot read whole cannot be verified (§25, New limits).
    pub fn read(self: *Message, bytes: []const u8, asked: *const Name) Error!bool {
        assert(asked.len >= 1);
        const header = try wire.header.parse(bytes);
        if (header.qdcount != 1) return Error.MalformedMessage;
        const answer_offset = wire.response.section_start(asked);
        if (answer_offset > bytes.len) return Error.MalformedMessage;
        if (@as(usize, header.ancount) + header.nscount > core.limits.records_max) return false;
        self.bytes = bytes;
        self.count = 0;
        const authority_offset = try self.walk(answer_offset, header.ancount, .answer);
        _ = try self.walk(authority_offset, header.nscount, .authority);
        assert(self.count <= core.limits.records_max);
        return true;
    }

    fn walk(self: *Message, offset: usize, promised: u16, section: Section) Error!usize {
        var records = wire.record.Iterator.init(self.bytes, offset, promised);
        while (try records.next()) |record| {
            assert(self.count < core.limits.records_max);
            self.records[self.count] = record;
            self.sections[self.count] = section;
            self.count += 1;
        }
        return records.offset;
    }

    /// Whether the record at `index` is in `section`, of `kind` and class IN, and owned by `owner`,
    /// letters compared in either case (RFC 1035 §2.3.3, as RFC 4343 clarifies it).
    pub fn holds(self: *const Message, index: usize, section: Section, kind: Kind, owner: *const Name) Error!bool {
        assert(index < self.count);
        const record = &self.records[index];
        if (self.sections[index] != section or !record.is_kind(kind)) return false;
        var name: Name = Name.empty;
        try record.owner_name(self.bytes, &name);
        return name.equal(owner);
    }

    /// The RRset of `kind` that `owner` holds in `section`, which may be empty.
    pub fn rrset(self: *const Message, section: Section, kind: Kind, owner: *const Name) Error!Rrset {
        var set: Rrset = .{ .message = self, .kind = kind, .indexes = undefined, .len = 0 };
        for (0..self.count) |index| {
            if (!try self.holds(index, section, kind, owner)) continue;
            set.indexes[set.len] = @intCast(index);
            set.len += 1;
        }
        assert(set.len <= self.count);
        return set;
    }
};

/// The records of one RRset in a message, by their place in it. It gives `canonical_form.signed_data`
/// the canonical rdata of each record, as `canonical_form.Written` does.
pub const Rrset = struct {
    message: *const Message,
    kind: Kind,
    indexes: [core.limits.records_max]u8,
    len: usize,

    pub fn count(self: *const Rrset) usize {
        return self.len;
    }

    pub fn record(self: *const Rrset, index: usize) *const wire.Record {
        assert(index < self.len);
        return &self.message.records[self.indexes[index]];
    }

    /// The canonical rdata of the record at `index`. A type whose names are lowered has them
    /// written in full into `scratch` first, since a message may compress them (RFC 4034 §6.2).
    /// Every other type's rdata is its canonical form as it came (RFC 3597 §7), read in place.
    pub fn canonical(self: *const Rrset, index: usize, scratch: *Scratch) Error![]const u8 {
        const at = self.record(index);
        if (!canonical_form.lowers(self.kind)) return at.rdata;
        const written = try wire.record_copy.copy_out(self.message.bytes, at, scratch) orelse
            return Error.MalformedMessage;
        assert(written <= scratch.len);
        try canonical_form.lower(self.kind, scratch[0..written]);
        return scratch[0..written];
    }

    /// The smallest TTL of the RRset's records, as received.
    pub fn ttl_seconds(self: *const Rrset) u32 {
        assert(self.len >= 1);
        var smallest: u32 = std.math.maxInt(u32);
        for (0..self.len) |index| smallest = @min(smallest, self.record(index).ttl_seconds);
        return smallest;
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "a message's answer and authority records are read, each with its section" {
    var builder = fixtures.Builder.init("example", .a, 0);
    builder.record("example", .a, 60, &.{ 192, 0, 2, 1 });
    builder.authority();
    builder.record("example", .ns, 60, "\x03ns1\x07example\x00");
    var message: Message = undefined;
    try testing.expect(try message.read(builder.message(), &try Name.parse("example")));
    try testing.expectEqual(@as(usize, 2), message.count);
    const owner = try Name.parse("EXAMPLE");
    try testing.expect(try message.holds(0, .answer, .a, &owner));
    try testing.expect(!try message.holds(0, .authority, .a, &owner));
    try testing.expect(try message.holds(1, .authority, .ns, &owner));
}

test "more records than records_max are refused, and so is a second question" {
    var builder = fixtures.Builder.init("example", .a, 0);
    for (0..core.limits.records_max / 2) |_| builder.record("example", .a, 60, &.{ 192, 0, 2, 1 });
    builder.authority();
    for (0..core.limits.records_max / 2 + 1) |_| builder.record("example", .a, 60, &.{ 192, 0, 2, 1 });
    var message: Message = undefined;
    const asked = try Name.parse("example");
    try testing.expect(!try message.read(builder.message(), &asked));
    var two = fixtures.Builder.init("example", .a, 0);
    const bytes = two.message();
    var changed: [64]u8 = undefined;
    @memcpy(changed[0..bytes.len], bytes);
    changed[5] = 2;
    try testing.expectError(Error.MalformedMessage, message.read(changed[0..bytes.len], &asked));
    try testing.expectError(Error.MalformedMessage, message.read(bytes[0 .. bytes.len - 1], &asked));
}
