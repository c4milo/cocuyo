//! Where the names sit in each type's rdata: what the collector must write out in full when it
//! copies a record out of a message, and what a typed view reads back (docs/design.md §19
//! step 9).
//!
//! A name may arrive compressed in the types RFC 1035 defines, and a receiver decompresses those
//! (RFC 3597 §4). SRV, NAPTR and SVCB forbid compression on the wire and SIG a receiver should
//! decompress anyway (§4), so their layouts name the name too: cocuyo writes a compressed one
//! out wherever it finds one, because decoding is bounded and safe and a message that broke the
//! sender's rule is otherwise readable (§16 decision 16).
const std = @import("std");
const core = @import("core");
const Kind = core.Kind;
const constants = @import("../constants.zig");

pub const Segment = union(enum) {
    /// This many octets, copied as they are.
    fixed: u8,
    /// A name: compressed on the wire, written out in full in the stored form.
    name,
    /// A `<character-string>`: a length octet and that many octets (RFC 1035 §3.3).
    character_string,
    /// Everything to the end of the rdata, copied as it is. Always the last segment.
    rest,
};

const name_only = [_]Segment{.name};
const mx = [_]Segment{ .{ .fixed = constants.mx_fixed_bytes }, .name };
const soa = [_]Segment{ .name, .name, .{ .fixed = constants.soa_fixed_bytes } };
const srv = [_]Segment{ .{ .fixed = constants.srv_fixed_bytes }, .name };
const naptr = [_]Segment{
    .{ .fixed = constants.naptr_fixed_bytes }, .character_string, .character_string, .character_string, .name,
};
const sig = [_]Segment{ .{ .fixed = constants.sig_fixed_bytes }, .name, .rest };
const svcb = [_]Segment{ .{ .fixed = constants.svcb_fixed_bytes }, .name, .rest };
const opaque_rest = [_]Segment{.rest};

/// The layout of a type's rdata. A type cocuyo does not name is copied as it is: a name in it is
/// never compressed (RFC 3597 §4), so there is nothing to write out.
pub fn of(type_code: u16) []const Segment {
    const kind = Kind.from_code(type_code) orelse return &opaque_rest;
    return switch (kind) {
        .ns, .cname, .ptr => &name_only,
        .mx => &mx,
        .soa => &soa,
        .srv => &srv,
        .naptr => &naptr,
        .sig => &sig,
        .svcb, .https => &svcb,
        .a, .aaaa, .hinfo, .txt, .opt, .tlsa, .uri, .caa, .any => &opaque_rest,
    };
}

/// Whether the layout holds a name, which decides whether a record is rewritten or copied.
pub fn has_name(layout: []const Segment) bool {
    for (layout) |segment| {
        switch (segment) {
            .name => return true,
            else => {},
        }
    }
    return false;
}

comptime {
    const all = [_][]const Segment{ &name_only, &mx, &soa, &srv, &naptr, &sig, &svcb, &opaque_rest };
    for (all) |layout| {
        if (layout.len > constants.layout_segments_max) @compileError("a layout is longer than the bound");
        for (layout, 0..) |segment, index| {
            switch (segment) {
                .rest => if (index != layout.len - 1) @compileError("rest must be the last segment"),
                else => {},
            }
        }
    }
}

// Tests.

const testing = std.testing;

test "the types with a name in their rdata say where it sits, and the rest are copied whole" {
    try testing.expectEqual(@as(usize, 1), of(Kind.ns.code()).len);
    try testing.expect(has_name(of(Kind.cname.code())));
    const layout_mx = of(Kind.mx.code());
    try testing.expectEqual(@as(usize, 2), layout_mx.len);
    try testing.expectEqual(@as(u8, constants.mx_fixed_bytes), layout_mx[0].fixed);
    try testing.expectEqual(@as(usize, 5), of(Kind.naptr.code()).len);
    try testing.expect(has_name(of(Kind.svcb.code())));
    try testing.expect(has_name(of(Kind.https.code())));
    try testing.expect(has_name(of(Kind.sig.code())));
    try testing.expect(!has_name(of(Kind.txt.code())));
    try testing.expect(!has_name(of(Kind.a.code())));
    try testing.expect(!has_name(of(Kind.caa.code())));
}

test "an unknown type is copied whole" {
    const layout = of(99);
    try testing.expectEqual(@as(usize, 1), layout.len);
    try testing.expect(!has_name(layout));
}
