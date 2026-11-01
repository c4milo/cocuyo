//! The type bit maps of NSEC and NSEC3: which types exist at the owner name (RFC 4034 §4.1.2, RFC
//! 5155 §3.2.1). A block is a window number, a bitmap length of 1 to 32, and that many octets of
//! bitmap, and the windows come in increasing order. cocuyo reads the map and verifies nothing
//! (docs/design.md §25, step 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Kind = core.Kind;
const constants = @import("../constants.zig");
const limits = @import("../limits.zig");

pub const TypeBitmaps = struct {
    /// The blocks, checked whole: each fits, and each window is above the one before it.
    bytes: []const u8,

    /// The map in `bytes`, refused when the format cannot hold it: a block's length outside 1 to
    /// 32, a window not above the window before it, or a block that runs past the end. An empty
    /// block and trailing zero octets break a sender's rule and not the format, and read as no
    /// types (RFC 4034 §4.1.2).
    pub fn parse(bytes: []const u8) Error!TypeBitmaps {
        var at: usize = 0;
        var last_window: ?u8 = null;
        // Bounded: each pass reads one block of three octets at least.
        for (0..bytes.len) |_| {
            if (at == bytes.len) break;
            if (bytes.len - at < constants.bitmap_block_header_bytes) return Error.MalformedMessage;
            const window = bytes[at];
            const length: usize = bytes[at + 1];
            // "a single octet bitmap length (from 1 to 32)" (RFC 4034 §4.1.2).
            if (length == 0 or length > limits.bitmap_octets_max) return Error.MalformedMessage;
            // "Blocks are present in the NSEC RR RDATA in increasing numerical order" (§4.1.2).
            if (last_window) |last| if (window <= last) return Error.MalformedMessage;
            at += constants.bitmap_block_header_bytes;
            if (bytes.len - at < length) return Error.MalformedMessage;
            at += length;
            last_window = window;
        }
        assert(at == bytes.len);
        return .{ .bytes = bytes };
    }

    /// Whether the map says an RRset of `kind` exists. A bit for a pseudo-type reads as clear:
    /// "If encountered, they MUST be ignored upon being read" (RFC 4034 §4.1.2).
    pub fn has(self: TypeBitmaps, kind: Kind) bool {
        const type_code = kind.code();
        if (pseudo(type_code)) return false;
        return self.set(type_code);
    }

    /// Whether the map sets NXNAME, the one pseudo-type a reader takes: "There is one exception to
    /// this rule for Compact Denial of Existence" (RFC 9824 §7.1, which updates RFC 4034 §4.1.2).
    pub fn nxname(self: TypeBitmaps) bool {
        assert(pseudo(constants.nxname_type_code));
        return self.set(constants.nxname_type_code);
    }

    fn set(self: TypeBitmaps, type_code: u16) bool {
        const window: u8 = @intCast(type_code / constants.bitmap_window_types);
        const bit: usize = type_code % constants.bitmap_window_types;
        var at: usize = 0;
        // Bounded: each pass skips one block that `parse` checked, and one more pass ends the map.
        for (0..self.bytes.len + 1) |_| {
            if (at == self.bytes.len) return false;
            const length: usize = self.bytes[at + 1];
            const bitmap = self.bytes[at + constants.bitmap_block_header_bytes ..][0..length];
            if (self.bytes[at] == window) {
                const octet = bit / constants.bitmap_octet_bits;
                // "Trailing zero octets not specified MUST be interpreted as zero octets" (§4.1.2).
                if (octet >= bitmap.len) return false;
                const shift: u3 = @intCast(constants.bitmap_octet_bits - 1 - bit % constants.bitmap_octet_bits);
                return (bitmap[octet] >> shift) & 1 == 1;
            }
            at += constants.bitmap_block_header_bytes + length;
        }
        unreachable;
    }
};

/// A pseudo-type, which no zone holds: OPT, and the query and meta range (RFC 6895 §3.1).
fn pseudo(type_code: u16) bool {
    if (type_code == Kind.opt.code()) return true;
    return type_code >= core.constants.type_code_query_meta_first and type_code <= core.constants.type_code_query_meta_last;
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "RFC 4034 §4.3's map holds A, MX, RRSIG, NSEC and TYPE1234, and nothing else asked" {
    const map = try TypeBitmaps.parse(fixtures.nsec_example[fixtures.nsec_example_next_bytes..]);
    for ([_]Kind{ .a, .mx, .rrsig, .nsec, Kind.of(1234) }) |kind| try testing.expect(map.has(kind));
    for ([_]Kind{ .aaaa, .ns, .ds, Kind.of(1233), Kind.of(1235), Kind.of(4000) }) |kind| try testing.expect(!map.has(kind));
}

test "a map is refused when its format cannot hold it" {
    const cases = [_][]const u8{
        &.{0x00}, // a block cut inside its header
        &.{ 0x00, 0x00 }, // a bitmap of no octets
        &([_]u8{ 0x00, 0x21 } ++ [_]u8{0} ** 33), // a bitmap of 33 octets
        &.{ 0x00, 0x02, 0x40 }, // a bitmap cut short
        &.{ 0x01, 0x01, 0x40, 0x00, 0x01, 0x40 }, // windows out of order
        &.{ 0x00, 0x01, 0x40, 0x00, 0x01, 0x40 }, // a window twice
    };
    for (cases) |bytes| try testing.expectError(Error.MalformedMessage, TypeBitmaps.parse(bytes));
}

test "an empty block and trailing zero octets read as no types, and an empty map holds none" {
    // RFC 4034 §4.1.2 forbids both to a sender, and its reader takes missing octets as zero.
    const map = try TypeBitmaps.parse(&.{ 0x00, 0x02, 0x40, 0x00, 0x01, 0x01, 0x00 });
    try testing.expect(map.has(.a));
    try testing.expect(!map.has(Kind.of(256)));
    // Type 100 is past window 0's two octets, so it reads as absent.
    try testing.expect(!map.has(Kind.of(100)));
    try testing.expect(!(try TypeBitmaps.parse(&.{})).has(.a));
}

test "a bit for a pseudo-type reads as clear" {
    // OPT (41), and ANY (255) in the query and meta range: RFC 4034 §4.1.2 has them ignored.
    const bitmap: [limits.bitmap_octets_max]u8 = @splat(0xff);
    const block = [_]u8{ 0x00, limits.bitmap_octets_max } ++ bitmap;
    const map = try TypeBitmaps.parse(&block);
    try testing.expect(map.has(.a));
    try testing.expect(!map.has(.opt));
    try testing.expect(!map.has(.any));
    try testing.expect(!map.has(Kind.of(core.constants.type_code_query_meta_first)));
}

test "NXNAME is read from the map, though it is a pseudo-type, and only where its bit is set" {
    // RFC 9824 §3.1: "RRSIG NSEC NXNAME", type 128 in window 0, octet 16, the high bit.
    const compact = [_]u8{ 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80 };
    const map = try TypeBitmaps.parse(&compact);
    try testing.expect(map.nxname());
    try testing.expect(map.has(.rrsig) and map.has(.nsec));
    try testing.expect(!map.has(Kind.of(constants.nxname_type_code)));
    try testing.expect(!(try TypeBitmaps.parse(fixtures.nsec_example[fixtures.nsec_example_next_bytes..])).nxname());
}
