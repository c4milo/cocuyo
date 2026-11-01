//! NSEC3: hash algorithm, flags, iterations and salt, then the next hashed owner name and the types
//! that exist at the owner (RFC 5155 §3.2). NSEC3PARAM: the first four alone (§4.2). cocuyo reads
//! the fields and hashes nothing (docs/design.md §25, step 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const constants = @import("../constants.zig");
const integer = @import("../integer.zig");
const TypeBitmaps = @import("rdata_bitmap.zig").TypeBitmaps;

/// What NSEC3 and NSEC3PARAM begin with, and where their rdata goes on.
const Head = struct { hash_algorithm: u8, flags: u8, iterations: u16, salt: []const u8, after: usize };

/// The hash algorithm, the flags, the iterations and the salt, each checked against the end of the
/// rdata before it is read.
fn head(rdata: []const u8) Error!Head {
    if (rdata.len < constants.nsec3_fixed_bytes) return Error.MalformedMessage;
    const salt_length: usize = rdata[constants.nsec3_salt_length_offset];
    if (rdata.len - constants.nsec3_fixed_bytes < salt_length) return Error.MalformedMessage;
    const after = constants.nsec3_fixed_bytes + salt_length;
    assert(after <= rdata.len);
    return .{
        .hash_algorithm = rdata[0],
        .flags = rdata[constants.nsec3_flags_offset],
        .iterations = integer.read_u16(rdata, constants.nsec3_iterations_offset),
        .salt = rdata[constants.nsec3_fixed_bytes..after],
        .after = after,
    };
}

pub const Nsec3 = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    /// The next hashed owner name, as binary octets and not as a name (RFC 5155 §3.2).
    next_hashed: []const u8,
    types: TypeBitmaps,

    pub fn parse(rdata: []const u8) Error!Nsec3 {
        const fields = try head(rdata);
        if (fields.after == rdata.len) return Error.MalformedMessage;
        const hash_length: usize = rdata[fields.after];
        const hash_at = fields.after + 1;
        if (rdata.len - hash_at < hash_length) return Error.MalformedMessage;
        const after_hash = hash_at + hash_length;
        assert(after_hash <= rdata.len);
        return .{
            .hash_algorithm = fields.hash_algorithm,
            .flags = fields.flags,
            .iterations = fields.iterations,
            .salt = fields.salt,
            .next_hashed = rdata[hash_at..after_hash],
            .types = try TypeBitmaps.parse(rdata[after_hash..]),
        };
    }

    /// The Opt-Out flag: the span may hold unsigned delegations (RFC 5155 §3.1.2.1).
    pub fn opt_out(self: Nsec3) bool {
        return self.flags & constants.nsec3_flag_opt_out != 0;
    }
};

pub const Nsec3Param = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,

    /// The rdata holds the four fields and nothing after them (RFC 5155 §4.2).
    pub fn parse(rdata: []const u8) Error!Nsec3Param {
        const fields = try head(rdata);
        if (fields.after != rdata.len) return Error.MalformedMessage;
        return .{ .hash_algorithm = fields.hash_algorithm, .flags = fields.flags, .iterations = fields.iterations, .salt = fields.salt };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "an NSEC3 reads back its hash, flags, iterations, salt, next hashed owner and types" {
    const nsec3 = try Nsec3.parse(&fixtures.nsec3);
    try testing.expectEqual(@as(u8, 1), nsec3.hash_algorithm);
    try testing.expect(nsec3.opt_out());
    try testing.expectEqual(@as(u16, 12), nsec3.iterations);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, nsec3.salt);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, nsec3.next_hashed);
    try testing.expect(nsec3.types.has(.ns) and nsec3.types.has(.ds) and !nsec3.types.has(.a));
}

test "an NSEC3 is malformed when its salt, its hash or its map runs past the rdata" {
    try testing.expectError(Error.MalformedMessage, Nsec3.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes - 1]));
    try testing.expectError(Error.MalformedMessage, Nsec3.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes + 2]));
    try testing.expectError(Error.MalformedMessage, Nsec3.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes + 4]));
    try testing.expectError(Error.MalformedMessage, Nsec3.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes + 6]));
    try testing.expectError(Error.MalformedMessage, Nsec3.parse(fixtures.nsec3[0 .. fixtures.nsec3.len - 1]));
}

test "an NSEC3PARAM is its four fields, and refused with an octet more or less" {
    const param = try Nsec3Param.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes + 4]);
    try testing.expectEqual(@as(u16, 12), param.iterations);
    try testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd }, param.salt);
    try testing.expectError(Error.MalformedMessage, Nsec3Param.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes + 5]));
    try testing.expectError(Error.MalformedMessage, Nsec3Param.parse(fixtures.nsec3[0 .. constants.nsec3_fixed_bytes + 3]));
}
