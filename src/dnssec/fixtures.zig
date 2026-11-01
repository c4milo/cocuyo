//! Hand-written records and a recording `Hash` for the tests of `dnssec`. Exempt from the
//! magic-numbers rule by name, like every corpus (tools/lint/magic_numbers.zig), and test-only.
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Hash = @import("dnssec.zig").Hash;
const nsec = @import("dnssec_nsec.zig");

/// A `Hash` that keeps what it was fed, for a test to compare.
pub const Recorded = struct {
    octets: [recorded_bytes]u8 = undefined,
    len: usize = 0,

    pub fn hash(self: *Recorded) Hash {
        return .{ .context = self, .update = update };
    }

    fn update(context: *anyopaque, octets: []const u8) void {
        const self: *Recorded = @ptrCast(@alignCast(context));
        @memcpy(self.octets[self.len..][0..octets.len], octets);
        self.len += octets.len;
    }

    pub fn slice(self: *const Recorded) []const u8 {
        return self.octets[0..self.len];
    }
};

/// What a test records: an RRSIG's head and a few records, or a DS digest's input.
const recorded_bytes: usize = 1024;

/// An RRSIG over A, algorithm 13, 2 labels, original TTL 300, signed by `Example.COM`, with a
/// signature of four octets.
pub const rrsig_a = [_]u8{ 0x00, 0x01, 13, 2, 0x00, 0x00, 0x01, 0x2c, 0x5f, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00, 0x12, 0x34 } ++
    "\x07Example\x03COM\x00".* ++ [_]u8{ 0xde, 0xad, 0xbe, 0xef };

/// A type bit map of window 0 that sets the types of `codes`, each below 256 (RFC 4034 §4.1.2).
fn map(comptime codes: []const u8) [2 + octets_for(codes)]u8 {
    var bytes: [2 + octets_for(codes)]u8 = @splat(0);
    bytes[1] = octets_for(codes);
    for (codes) |code| bytes[2 + code / 8] |= @as(u8, 0x80) >> @intCast(code % 8);
    return bytes;
}

fn octets_for(comptime codes: []const u8) u8 {
    var highest: u8 = 0;
    for (codes) |code| highest = @max(highest, code);
    return highest / 8 + 1;
}

/// The maps of RFC 4035 Appendix A's zone, by what they hold. A 1, NS 2, CNAME 5, SOA 6, HINFO 13,
/// MX 15, AAAA 28, DNAME 39, DS 43, RRSIG 46, NSEC 47, DNSKEY 48, NXNAME 128.
pub const ns = map(&.{ 2, 46, 47 });
pub const apex = map(&.{ 2, 6, 15, 46, 47, 48 });
pub const address = map(&.{ 1, 46, 47 });
pub const alias = map(&.{ 5, 46, 47 });
pub const mail = map(&.{ 15, 46, 47 });
pub const secure_cut = map(&.{ 2, 43, 46, 47 });
pub const everything = map(&.{ 1, 13, 28, 46, 47 });
pub const redirect = map(&.{ 39, 46, 47 });
pub const compact = map(&.{ 46, 47, 128 });
pub const nothing = map(&.{ 46, 47 });

/// An NSEC record at `owner` of RFC 4035 Appendix A's zone, signed by `example.` over its own
/// labels, naming `next` and the types of `types`.
pub fn record(owner: []const u8, next: []const u8, types: []const u8) !nsec.Record {
    const owner_name = try Name.from_text(owner);
    const wildcard: u8 = if (owner[0] == '*') 1 else 0;
    return .{
        .owner = owner_name,
        .signer = try Name.from_text("example"),
        .labels = owner_name.label_count() - wildcard,
        .nsec = .{ .next = try Name.from_text(next), .types = try wire.rdata.TypeBitmaps.parse(types) },
    };
}

/// The name right after `text` in canonical order: a label of one zero octet in front (RFC 9824
/// §3.1).
pub fn epsilon(text: []const u8) !Name {
    var name: Name = Name.empty;
    try name.append_label(&.{0});
    try name.terminate();
    return name.concat(&try Name.from_text(text));
}
