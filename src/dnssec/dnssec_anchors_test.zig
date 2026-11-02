//! The anchor parser's tests, split from `dnssec_anchors.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const anchors_module = @import("dnssec_anchors.zig");
const parse = anchors_module.parse;
const Error = anchors_module.Error;
const Anchor = @import("dnssec_store.zig").Anchor;
const key_tag = @import("dnssec.zig").key_tag;
const limits = @import("limits.zig");

/// RFC 4034 §5.4's example, as the RFC prints it, but the entries start at the first column. The
/// RFC indents them, which RFC 1035 §5.1 reads as entries with no owner.
const rfc_example =
    \\dskey.example.com. 86400 IN DNSKEY 256 3 5 ( AQOeiiR0GOMYkDshWoSKz9Xz
    \\                                             fwJr1AYtsmx3TGkJaNXVbfi/
    \\                                             2pHm822aJ5iI9BMzNXxeYCmZ
    \\                                             DRD99WYwYqUSdjMmmAphXdvx
    \\                                             egXd/M5+X7OrzKBaMbCVdFLU
    \\                                             Uh6DhweJBjEVv5f2wwjM9Xzc
    \\                                             nOf+EPbtG9DMBmADjFDc2w/r
    \\                                             ljwvFw==
    \\                                             ) ;  key id = 60485
    \\
    \\dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A
    \\                                              98631FAD1A292118 )
    \\
;

const rfc_key_base64 = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ" ++
    "DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/r" ++
    "ljwvFw==";
const rfc_tag: u16 = 60485;

/// Room for one anchor past the store's limit, so the limit and not the room refuses it.
const Rig = struct {
    anchors: [limits.anchors_max + 1]Anchor = undefined,
    rdata: [limits.anchors_max * core.limits.rdata_bytes_max]u8 = undefined,

    fn read(self: *Rig, text: []const u8) Error![]Anchor {
        return parse(text, &self.anchors, &self.rdata);
    }
};

test "RFC 4034 §5.4's example reads to a DNSKEY whose tag its DS names" {
    var rig: Rig = .{};
    const read = try rig.read(rfc_example);
    try testing.expectEqual(@as(usize, 2), read.len);
    const owner = try core.Name.from_text("dskey.example.com.");
    for (read) |anchor| try testing.expect(anchor.zone.equal(&owner));
    const key = read[0];
    try testing.expectEqual(core.Kind.dnskey, key.kind);
    // The public key, as the standard library's decoder reads it.
    var public_key: [std.base64.standard.Decoder.calcSizeForSlice(rfc_key_base64) catch unreachable]u8 = undefined;
    try std.base64.standard.Decoder.decode(&public_key, rfc_key_base64);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 3, 5 }, key.rdata[0..4]);
    try testing.expectEqualSlices(u8, &public_key, key.rdata[4..]);
    try testing.expectEqual(rfc_tag, key_tag(key.rdata));
    const ds = read[1];
    try testing.expectEqual(core.Kind.ds, ds.kind);
    var digest: [20]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, "2BB183AF5F22588179A53B0A98631FAD1A292118");
    try testing.expectEqual(rfc_tag, std.mem.readInt(u16, ds.rdata[0..2], .big));
    try testing.expectEqualSlices(u8, &.{ 5, 1 }, ds.rdata[2..4]);
    try testing.expectEqualSlices(u8, &digest, ds.rdata[4..]);
}

test "the TTL and the class are optional, in either order, and comments and blank lines are skipped" {
    var rig: Rig = .{};
    const text =
        \\; The root's anchors.
        \\
        \\. DS 1 8 2 0A0B
        \\. 3600 IN DS 2 8 2 0a0b
        \\. in 3600 ds 3 8 2 0A ; a comment
        \\  IN DS 4 8 2 0A0B
        \\example. ( DNSKEY
        \\   257 3 13 Zm9v ) ; split
        \\
    ;
    const read = try rig.read(text);
    try testing.expectEqual(@as(usize, 5), read.len);
    for (read[0..4], 1..) |anchor, tag| {
        try testing.expect(anchor.zone.is_root());
        try testing.expectEqual(@as(u16, @intCast(tag)), std.mem.readInt(u16, anchor.rdata[0..2], .big));
    }
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x0b }, read[1].rdata[4..]);
    try testing.expectEqualSlices(u8, &.{0x0a}, read[2].rdata[4..]);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x01, 3, 13, 'f', 'o', 'o' }, read[4].rdata);
}

test "an entry outside the part of the format the parser reads is refused" {
    const refused = [_][]const u8{
        // A relative owner, a control entry, and a first entry with no owner.
        "example DS 1 8 2 0A",
        "$ORIGIN .\n. DS 1 8 2 0A",
        "$TTL 3600\n. DS 1 8 2 0A",
        "$ORIGIN. DS 1 8 2 0A",
        "  DS 1 8 2 0A",
        // Another class, another type, a TTL past RFC 2181 §8, a TTL or a class twice.
        ". CH DS 1 8 2 0A",
        ". IN A 192.0.2.1",
        ". 2147483648 DS 1 8 2 0A",
        ". 1 1 DS 1 8 2 0A",
        ". IN IN DS 1 8 2 0A",
        // A mnemonic, a sign, a field missing, a digest of odd length or none, base64 that ends
        // early.
        ". DS 1 RSASHA256 2 0A",
        ". DS +1 8 2 0A",
        ". DNSKEY 257 3 13",
        ". DS 1 8 2 0A0",
        ". DS 1 8 2",
        ". DNSKEY 257 3 13 Zm9",
        // Parentheses that nest, that close twice, and that never close.
        ". DS 1 8 2 ( ( 0A ) )",
        ". DS 1 8 2 0A )",
        ". DS 1 8 2 ( 0A\n",
    };
    for (refused) |text| {
        var rig: Rig = .{};
        try testing.expectError(Error.MalformedAnchor, rig.read(text));
    }
}

test "a text with no anchor, or more than the store takes, is refused" {
    var rig: Rig = .{};
    try testing.expectError(Error.NoAnchors, rig.read(""));
    try testing.expectError(Error.NoAnchors, rig.read("; nothing\n\n   \n"));
    const nine = ". DS 1 8 2 0A\n" ** (limits.anchors_max + 1);
    try testing.expectError(Error.TooManyAnchors, rig.read(nine));
    try testing.expectEqual(limits.anchors_max, (try rig.read(nine[0 .. nine.len / (limits.anchors_max + 1) * limits.anchors_max])).len);
    var one: [1]Anchor = undefined;
    try testing.expectError(Error.TooManyAnchors, parse(". DS 1 8 2 0A\n. DS 2 8 2 0A", &one, &rig.rdata));
}

test "rdata that does not fit is refused, and so is one anchor longer than rdata_bytes_max" {
    var rig: Rig = .{};
    var small: [5]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), (try parse(". DS 1 8 2 0A", &rig.anchors, &small)).len);
    try testing.expectError(Error.RdataFull, parse(". DS 1 8 2 0A\n. DS 1 8 2 0A", &rig.anchors, &small));
    // A key of `rdata_bytes_max` octets, behind the DNSKEY's four, is one octet too many.
    const prefix = ". DNSKEY 257 3 8 ";
    const key_text_bytes = comptime std.base64.standard.Encoder.calcSize(core.limits.rdata_bytes_max);
    var text: [prefix.len + key_text_bytes]u8 = undefined;
    @memcpy(text[0..prefix.len], prefix);
    var key: [core.limits.rdata_bytes_max]u8 = @splat(0x5a);
    _ = std.base64.standard.Encoder.encode(text[prefix.len..], &key);
    try testing.expectError(Error.AnchorTooLong, rig.read(&text));
    // Four octets fewer fit.
    const fits_text_bytes = comptime std.base64.standard.Encoder.calcSize(core.limits.rdata_bytes_max - 4);
    _ = std.base64.standard.Encoder.encode(text[prefix.len..][0..fits_text_bytes], key[0 .. key.len - 4]);
    const read = try rig.read(text[0 .. prefix.len + fits_text_bytes]);
    try testing.expectEqual(core.limits.rdata_bytes_max, read[0].rdata.len);
}
