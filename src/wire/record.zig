//! Walking the records of a message (RFC 1035 §4.1.3), and reading the rdata of the four types
//! cocuyo knows.
//!
//! A count field is never a reason to read (CLAUDE.md non-negotiable 6). `ancount` says how many
//! records the sender claims, and the walk believes nothing: every field is bounds-checked against
//! the end of the message before it is read, an rdata that runs past the end is an error, and the
//! walk stops at `records_max` however many the count promises.
//!
//! A count that promises more records than the message holds is malformed, because the message ran
//! out mid-record. A count above `records_max` is not: the walk stops early and says so through
//! `truncated`, so a large legitimate answer yields the records it can hold rather than an error.
//!
//! The owner name is skipped rather than decoded on the way past. Decoding it costs a copy into a
//! 256-octet name, and most records in a message are of a type the caller did not ask for
//! (docs/design.md §11), so the walk reaches the type first and the caller decodes the owner only
//! when the type says it matters. The skip follows the owner's pointers and measures the whole
//! name, so the walk refuses each owner a decode refuses (§8, Record walking).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const Address = core.Address;
const constants = @import("constants.zig");
const integer = @import("integer.zig");
const name_codec = @import("name.zig");

pub const Record = struct {
    /// Where the owner name starts. `owner_name` decodes it; the walk itself does not.
    owner_offset: usize,
    /// The type, as the octets say. Not a `core.Kind`: a record of a type cocuyo does not know is
    /// a record to skip, not a message to reject.
    kind_code: u16,
    class: u16,
    ttl_seconds: u32,
    /// The rdata, a slice into the message. It is valid as long as the message buffer is.
    rdata: []const u8,
    /// The offset after this record.
    end: usize,

    pub fn is_kind(self: *const Record, kind: core.Kind) bool {
        return self.kind_code == kind.code() and self.class == core.constants.class_internet;
    }

    /// The owner name, decompressed into `out`. Called only for a record the caller wants.
    pub fn owner_name(self: *const Record, message: []const u8, out: *Name) Error!void {
        assert(self.owner_offset < message.len);
        _ = try name_codec.decode(message, self.owner_offset, out);
    }

    /// The address an A or AAAA record carries. The rdata must be exactly the family's width:
    /// four octets for A (RFC 1035 §3.4.1) and sixteen for AAAA (RFC 3596 §2.2). Anything else is
    /// malformed, whatever else the record looks like.
    pub fn address(self: *const Record) Error!Address {
        if (self.is_kind(.a)) {
            if (self.rdata.len != core.constants.address_v4_bytes) return Error.MalformedMessage;
            return Address.from_v4(self.rdata[0..core.constants.address_v4_bytes].*);
        }
        assert(self.is_kind(.aaaa));
        if (self.rdata.len != core.constants.address_v6_bytes) return Error.MalformedMessage;
        return Address.from_v6(self.rdata[0..core.constants.address_v6_bytes].*);
    }

    /// The MINIMUM field of an SOA record, capped by the record's own TTL: what a negative answer
    /// is cached for (RFC 2308 §5). The rdata is two names, either of which may be compressed,
    /// then five four-octet fields of which MINIMUM is the last (RFC 1035 §3.3.13). The names are
    /// skipped rather than decoded, each measured through its pointers, and the fixed fields must
    /// fit inside the rdata exactly.
    pub fn soa_negative_ttl(self: *const Record, message: []const u8) Error!u32 {
        assert(self.is_kind(.soa));
        const start = self.end - self.rdata.len;
        const after_mname = try name_codec.skip(message, start);
        const after_rname = try name_codec.skip(message, after_mname);
        if (after_rname + constants.soa_fixed_bytes != self.end) return Error.MalformedMessage;
        assert(after_rname + constants.soa_fixed_bytes <= message.len);
        const minimum = integer.read_u32(message, after_rname + constants.soa_minimum_offset);
        return @min(minimum, self.ttl_seconds);
    }

    /// The name a CNAME or PTR record's rdata holds, decompressed into `out`.
    ///
    /// The decode must consume the rdata exactly. A name that ends before the rdata does leaves
    /// octets a reader would have to guess at, and one that runs past the rdata has read another
    /// record's bytes, so both are malformed (RFC 1035 §3.3).
    pub fn rdata_name(self: *const Record, message: []const u8, out: *Name) Error!void {
        assert(self.is_kind(.cname) or self.is_kind(.ptr));
        const start = self.end - self.rdata.len;
        assert(start + self.rdata.len == self.end);
        const consumed = try name_codec.decode(message, start, out);
        if (consumed != self.end) return Error.MalformedMessage;
    }
};

/// A walk over one section's records. `count` is what the header promised; the walk stops at the
/// count, at `records_max`, or at an error, whichever comes first.
pub const Iterator = struct {
    message: []const u8,
    offset: usize,
    promised: u16,
    walked: u16 = 0,
    /// Set when the walk stopped at `records_max` with records still promised.
    truncated: bool = false,

    pub fn init(message: []const u8, offset: usize, count: u16) Iterator {
        assert(offset <= message.len);
        assert(message.len >= core.constants.header_bytes);
        return .{ .message = message, .offset = offset, .promised = count };
    }

    pub fn next(self: *Iterator) Error!?Record {
        if (self.walked == self.promised) return null;
        if (self.walked == core.limits.records_max) {
            self.truncated = true;
            return null;
        }
        assert(self.walked < self.promised);
        const owner_offset = self.offset;
        const after_name = try name_codec.skip(self.message, owner_offset);
        if (after_name + core.constants.record_fixed_bytes > self.message.len) {
            return Error.MalformedMessage;
        }
        const rdlength = integer.read_u16(self.message, after_name + constants.record_rdlength_offset);
        const rdata_start = after_name + core.constants.record_fixed_bytes;
        if (rdata_start + rdlength > self.message.len) return Error.TruncatedMessage;
        const record: Record = .{
            .owner_offset = owner_offset,
            .kind_code = integer.read_u16(self.message, after_name + constants.record_kind_offset),
            .class = integer.read_u16(self.message, after_name + constants.record_class_offset),
            // All 32 bits, the high one read as positive: RFC 8767 §4 amends RFC 1035 §3.2.1 and
            // §4.1.3, and undoes RFC 2181 §8, which read it as zero. The cache caps what it keeps.
            .ttl_seconds = integer.read_u32(self.message, after_name + constants.record_ttl_offset),
            .rdata = self.message[rdata_start..][0..rdlength],
            .end = rdata_start + rdlength,
        };
        self.offset = record.end;
        self.walked += 1;
        assert(record.end <= self.message.len);
        assert(self.offset > owner_offset);
        return record;
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

fn first_record(message: []const u8, count: u16) !Record {
    var walk = Iterator.init(message, fixtures.answer_offset, count);
    return (try walk.next()).?;
}

test "a record walk reads the type, class, TTL and rdata of an A record" {
    const record = try first_record(&fixtures.answer_a, 1);
    try testing.expect(record.is_kind(.a));
    try testing.expectEqual(@as(u32, 300), record.ttl_seconds);
    try testing.expectEqual(@as(usize, 4), record.rdata.len);
    try testing.expectEqual(fixtures.answer_a.len, record.end);
    const address = try record.address();
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, address.slice());
}

test "a TTL is read in all 32 bits, the high one as positive" {
    // RFC 8767 §4: 0x80015180 is 2,147,570,048 seconds, where RFC 2181 §8 read it as zero. A real
    // TTL of a day, 86,400, already needs the third octet.
    var message = fixtures.answer_a;
    const ttl_at = fixtures.answer_offset + constants.pointer_bytes + constants.record_ttl_offset;
    std.mem.writeInt(u32, message[ttl_at..][0..@sizeOf(u32)], 0x8001_5180, .big);
    const record = try first_record(&message, 1);
    try testing.expectEqual(@as(u32, 0x8001_5180), record.ttl_seconds);
    // The largest TTL the field holds reads back whole.
    std.mem.writeInt(u32, message[ttl_at..][0..@sizeOf(u32)], std.math.maxInt(u32), .big);
    try testing.expectEqual(@as(u32, std.math.maxInt(u32)), (try first_record(&message, 1)).ttl_seconds);
}

/// Where the rdlength of `fixtures.answer_a`'s record sits, after its two-octet owner pointer.
const answer_a_rdlength_at: usize = fixtures.answer_offset + constants.pointer_bytes + constants.record_rdlength_offset;

test "an rdlength of 0xFFFF or 0xFFFE runs past the message, and the sum with its offset does not wrap" {
    // The two largest values of the field (RFC 1035 §4.1.3). The rdata starts at octet 41, so
    // each sum passes sixteen bits.
    for ([_]u16{ 0xffff, 0xfffe }) |rdlength| {
        var message = fixtures.answer_a;
        integer.write_u16(&message, answer_a_rdlength_at, rdlength);
        var walk = Iterator.init(&message, fixtures.answer_offset, 1);
        try testing.expectError(Error.TruncatedMessage, walk.next());
    }
}

test "a record whose rdata ends at the last octet of a message of 65535 is read" {
    // The longest message there is (RFC 1035 §4.2.2) and one record in it, whose rdata fills the
    // rest: 65494 octets after the question and a pointer owner.
    var message: [core.limits.message_bytes_max]u8 = @splat(0);
    @memcpy(message[0..fixtures.answer_a.len], &fixtures.answer_a);
    const rdata_start = answer_a_rdlength_at + constants.u16_bytes;
    integer.write_u16(&message, answer_a_rdlength_at, @intCast(message.len - rdata_start));
    const record = try first_record(&message, 1);
    try testing.expectEqual(message.len, record.end);
    try testing.expectEqual(message.len - rdata_start, record.rdata.len);
}

test "the owner name is decoded only when it is asked for, and decompresses" {
    const record = try first_record(&fixtures.answer_a, 1);
    var owner: Name = Name.empty;
    try record.owner_name(&fixtures.answer_a, &owner);
    try testing.expect(owner.equal(&try Name.from_text("example.com")));
}

test "a walk yields every record the count promises and then stops" {
    var walk = Iterator.init(&fixtures.answer_a_twice, fixtures.answer_offset, 2);
    const first = (try walk.next()).?;
    const second = (try walk.next()).?;
    try testing.expectEqual(@as(?Record, null), try walk.next());
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, (try first.address()).slice());
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, (try second.address()).slice());
    try testing.expect(!walk.truncated);
    try testing.expectEqual(@as(u16, 2), walk.walked);
}

test "a count that promises more records than the message holds is malformed" {
    var walk = Iterator.init(&fixtures.answer_lying_count, fixtures.answer_offset, 5);
    _ = try walk.next();
    try testing.expectError(Error.MalformedMessage, walk.next());
}

test "an rdlength that reaches past the end of the message is refused" {
    var walk = Iterator.init(&fixtures.answer_long_rdlength, fixtures.answer_offset, 1);
    try testing.expectError(Error.TruncatedMessage, walk.next());
}

test "an A record whose rdata is not four octets is malformed" {
    const record = try first_record(&fixtures.answer_short_address, 1);
    try testing.expect(record.is_kind(.a));
    try testing.expectEqual(@as(usize, 3), record.rdata.len);
    try testing.expectError(Error.MalformedMessage, record.address());
}

test "an AAAA record reads sixteen octets" {
    const record = try first_record(&fixtures.answer_aaaa, 1);
    try testing.expect(record.is_kind(.aaaa));
    const address = try record.address();
    try testing.expectEqual(core.Family.ipv6, address.family);
    try testing.expectEqual(@as(u8, 0x20), address.octets[0]);
    try testing.expectEqual(@as(u8, 0x01), address.octets[15]);
}

test "a CNAME's rdata name decodes and must consume the rdata exactly" {
    const record = try first_record(&fixtures.answer_cname_then_a, 2);
    try testing.expect(record.is_kind(.cname));
    var target: Name = Name.empty;
    try record.rdata_name(&fixtures.answer_cname_then_a, &target);
    try testing.expect(target.equal(&try Name.from_text("host.example.net")));
}

test "a record of a class cocuyo does not query is not the kind it claims" {
    var chaos = fixtures.answer_a;
    // The class field of the first record: after the two-octet owner pointer and the type.
    chaos[fixtures.answer_offset + 5] = 3; // class CH
    const record = try first_record(&chaos, 1);
    try testing.expectEqual(@as(u16, 1), record.kind_code);
    try testing.expect(!record.is_kind(.a));
}

test "a walk stops at records_max and says it was truncated" {
    // The count promises more than the walk will read. The fixture holds two records, so the walk
    // reads what is there and the bound is what stops it: a promise of records_max + 1 with a
    // message that ends is malformed, which is the other test. Here the bound is reached first.
    var walk = Iterator.init(&fixtures.answer_a_twice, fixtures.answer_offset, 2);
    walk.walked = core.limits.records_max;
    walk.promised = core.limits.records_max + 1;
    try testing.expectEqual(@as(?Record, null), try walk.next());
    try testing.expect(walk.truncated);
}

test "a walk over more records than records_max reads that many of them, and says so" {
    // One record more than the bound, each one real: the bound stops the walk, not the message.
    const more = core.limits.records_max + 1;
    const message = fixtures.answer_a ++ fixtures.record_a ** core.limits.records_max;
    var walk = Iterator.init(&message, fixtures.answer_offset, more);
    var read: usize = 0;
    for (0..more) |_| {
        if (try walk.next() == null) break;
        read += 1;
    }
    try testing.expectEqual(@as(usize, core.limits.records_max), read);
    try testing.expect(walk.truncated);
    try testing.expectEqual(@as(?Record, null), try walk.next());
}

test "a record whose fixed part runs past the end of the message is malformed" {
    const short = fixtures.answer_a[0 .. fixtures.answer_offset + 5];
    var walk = Iterator.init(short, fixtures.answer_offset, 1);
    try testing.expectError(Error.MalformedMessage, walk.next());
}

test "an rdata name must consume its rdata exactly, in both directions" {
    const padded = try first_record(&fixtures.answer_cname_padded_rdata, 1);
    var target: Name = Name.empty;
    try testing.expectError(
        Error.MalformedMessage,
        padded.rdata_name(&fixtures.answer_cname_padded_rdata, &target),
    );
    const short = try first_record(&fixtures.answer_cname_short_rdata, 1);
    try testing.expectError(
        Error.MalformedMessage,
        short.rdata_name(&fixtures.answer_cname_short_rdata, &target),
    );
}

test "an rdlength one octet past the end of the message is refused" {
    var walk = Iterator.init(&fixtures.answer_rdlength_one_past, fixtures.answer_offset, 1);
    try testing.expectError(Error.TruncatedMessage, walk.next());
}

test "an SOA's negative TTL is its minimum, capped by its own TTL" {
    // The fixture's SOA carries TTL 300 and MINIMUM 60.
    var walk = Iterator.init(&fixtures.answer_name_error_soa, fixtures.authority_offset_no_answers, 1);
    const soa = (try walk.next()).?;
    try testing.expect(soa.is_kind(.soa));
    try testing.expectEqual(@as(u32, 60), try soa.soa_negative_ttl(&fixtures.answer_name_error_soa));

    // The other way round: a TTL of 30 under a MINIMUM of 60 gives 30 (RFC 2308 §5).
    var short = Iterator.init(&fixtures.answer_no_data_soa_short, fixtures.authority_offset_no_answers, 1);
    const capped = (try short.next()).?;
    try testing.expectEqual(@as(u32, 30), try capped.soa_negative_ttl(&fixtures.answer_no_data_soa_short));
}

test "an SOA whose fixed fields do not fill its rdata exactly is malformed, either way" {
    // One octet short, and one octet over. A bound that only refused the short case would take
    // a trailing octet as part of the record and read the minimum from the wrong place.
    var short = Iterator.init(&fixtures.answer_soa_short_rdata, fixtures.authority_offset_no_answers, 1);
    const soa_short = (try short.next()).?;
    try testing.expectError(Error.MalformedMessage, soa_short.soa_negative_ttl(&fixtures.answer_soa_short_rdata));
    var long = Iterator.init(&fixtures.answer_soa_long_rdata, fixtures.authority_offset_no_answers, 1);
    const soa_long = (try long.next()).?;
    try testing.expectError(Error.MalformedMessage, soa_long.soa_negative_ttl(&fixtures.answer_soa_long_rdata));
}

/// A label of 63 octets, the longest, after its length octet.
const label_longest = [_]u8{core.limits.label_bytes_max} ++ [_]u8{'a'} ** core.limits.label_bytes_max;

/// `fixtures.answer_name_error_soa` with `labels` put before the SOA's MNAME, and the rdlength made
/// to hold them. The MNAME was `ns` and then a pointer to the question's name: 16 octets whole.
fn soa_mname_through_pointer(comptime labels: []const u8) [fixtures.answer_name_error_soa.len + labels.len]u8 {
    const message = fixtures.answer_name_error_soa;
    const fixed_at = fixtures.authority_offset_no_answers + constants.pointer_bytes;
    const rdata_at = fixed_at + core.constants.record_fixed_bytes;
    var out = message[0..rdata_at].* ++ labels[0..labels.len].* ++ message[rdata_at..].*;
    integer.write_u16(&out, fixed_at + constants.record_rdlength_offset, @intCast(out.len - rdata_at));
    return out;
}

test "an SOA's MNAME longer than 255 octets through its pointer is refused" {
    // "label octets and label length octets" count (RFC 1035 §3.1), those a pointer reaches too
    // (§4.1.4), in a name of "255 octets or less" (§2.3.4). Until 2026-10-14 the skip did not
    // follow the MNAME's pointer, so it read the MINIMUM after an MNAME of 256 octets too.
    // Labels of 239 octets, and the 16 of `ns.example.com`: 255 octets.
    const longest = soa_mname_through_pointer(&(label_longest ** 3 ++ [_]u8{46} ++ [_]u8{'b'} ** 46));
    var walk = Iterator.init(&longest, fixtures.authority_offset_no_answers, 1);
    try testing.expectEqual(@as(u32, 60), try (try walk.next()).?.soa_negative_ttl(&longest));
    // A label of one octet more: 256 octets.
    const one_past = soa_mname_through_pointer(&(label_longest ** 3 ++ [_]u8{47} ++ [_]u8{'b'} ** 47));
    var past = Iterator.init(&one_past, fixtures.authority_offset_no_answers, 1);
    try testing.expectError(Error.NameTooLong, (try past.next()).?.soa_negative_ttl(&one_past));
}
