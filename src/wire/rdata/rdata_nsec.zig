//! NSEC: the next owner name in the zone's canonical order, which "MUST NOT" be compressed, then
//! the types that exist at the owner (RFC 4034 §4.1). cocuyo reads the fields and verifies nothing
//! (docs/design.md §25, step 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const rdata_name = @import("rdata_name.zig");
const TypeBitmaps = @import("rdata_bitmap.zig").TypeBitmaps;

pub const Nsec = struct {
    next: Name,
    types: TypeBitmaps,

    pub fn parse(rdata: []const u8) Error!Nsec {
        var next: Name = Name.empty;
        // As labels alone: "A sender MUST NOT use DNS name compression on the Next Domain Name
        // field" (RFC 4034 §4.1.1), so a pointer is malformed.
        const after_next = try rdata_name.read(rdata, 0, &next);
        assert(after_next <= rdata.len);
        return .{ .next = next, .types = try TypeBitmaps.parse(rdata[after_next..]) };
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "RFC 4034 §4.3's NSEC names host.example.com next, and A, MX, RRSIG, NSEC and TYPE1234" {
    const nsec = try Nsec.parse(&fixtures.nsec_example);
    try testing.expect(nsec.next.equal(&try Name.from_text("host.example.com")));
    try testing.expect(nsec.types.has(.mx));
    try testing.expect(nsec.types.has(core.Kind.of(1234)));
    try testing.expect(!nsec.types.has(.aaaa));
}

test "an NSEC whose next name is a compression pointer, or whose map is broken, is malformed" {
    try testing.expectError(Error.MalformedName, Nsec.parse(&.{ 0xc0, 0x0c, 0x00, 0x01, 0x40 }));
    try testing.expectError(Error.MalformedMessage, Nsec.parse(&.{ 0x00, 0x00, 0x00 }));
    try testing.expectError(Error.MalformedMessage, Nsec.parse(&.{ 0x03, 'c', 'o' }));
}
