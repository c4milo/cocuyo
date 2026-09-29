//! The items of the twin's QUIC (`sim_quic.zig`) on a stream, as the twin's channel writes them on
//! a TCP link (docs/design.md §24, DoH over colibri's client): each framed by a two-octet length,
//! and the stream's octets read back into whole frames, whatever chunks they came in. What a frame
//! holds is what a datagram of the twin's QUIC holds, so the twin's servers read both alike.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

/// The octets a frame's length takes, as a DNS message's does over TCP (RFC 7766 §8).
pub const prefix_bytes = core.constants.tcp_prefix_bytes;

/// One frame at its longest: its length, then a datagram's worth of items.
pub const frame_bytes_max = prefix_bytes + constants.quic_datagram_bytes_max;

/// Writes `items` as one frame into `out`, and returns its length.
pub fn frame(items: []const u8, out: []u8) usize {
    assert(items.len <= constants.quic_datagram_bytes_max);
    assert(out.len >= prefix_bytes + items.len);
    std.mem.writeInt(u16, out[0..prefix_bytes], @intCast(items.len), .big);
    @memcpy(out[prefix_bytes..][0..items.len], items);
    return prefix_bytes + items.len;
}

/// The items of the first whole frame of `bytes`, and the octets it takes; null when no whole
/// frame is there yet.
pub fn unframe(bytes: []const u8) ?struct { items: []const u8, len: usize } {
    if (bytes.len < prefix_bytes) return null;
    const len: usize = std.mem.readInt(u16, bytes[0..prefix_bytes], .big);
    if (prefix_bytes + len > bytes.len) return null;
    return .{ .items = bytes[prefix_bytes..][0..len], .len = prefix_bytes + len };
}

// Tests.

const testing = std.testing;

test "a frame reads back whole, and not before its last octet has come" {
    var out: [frame_bytes_max]u8 = undefined;
    const len = frame("items", &out);
    const whole = unframe(out[0..len]).?;
    try testing.expectEqualStrings("items", whole.items);
    try testing.expectEqual(len, whole.len);
    try testing.expect(unframe(out[0 .. len - 1]) == null);
    try testing.expect(unframe(out[0..1]) == null);
}
