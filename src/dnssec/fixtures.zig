//! Hand-written records and a recording `Hash` for the tests of `dnssec`. Exempt from the
//! magic-numbers rule by name, like every corpus (tools/lint/magic_numbers.zig), and test-only.
const Hash = @import("dnssec.zig").Hash;

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
