//! `Aliases`: the CNAME links a lookup followed, from the name it asked toward the chain's end
//! (docs/design.md §5, The chain a lookup keeps; §17 question 122).
//!
//! A link is a CNAME record: its owner, which is the name the chain had reached, and its TTL. Its
//! target is the next link's owner, and the last link's target is the chain's end, which the
//! lookup holds already. So only the owners are kept, in wire form, end to end in a buffer of
//! `chain_bytes_max` octets that is part of the caller's memory.
const std = @import("std");
const assert = std.debug.assert;
const limits = @import("limits.zig");
const Name = @import("name.zig").Name;

pub const Aliases = struct {
    /// The owners in wire form, end to end. Nothing past `ends[count - 1]` is read.
    bytes: [limits.chain_bytes_max]u8 = undefined,
    /// Where each owner ends in `bytes`.
    ends: [limits.cname_hops_max]u16 = undefined,
    ttls: [limits.cname_hops_max]u32 = undefined,
    count: u8 = 0,

    /// One link: its owner in wire form and the CNAME's TTL.
    pub const Link = struct { owner: []const u8, ttl_seconds: u32 };

    pub const none: Aliases = .{};

    comptime {
        assert(limits.cname_hops_max <= std.math.maxInt(u8));
        assert(limits.chain_bytes_max <= std.math.maxInt(u16));
    }

    /// Forgets every link: a new chain starts from a new name.
    pub fn clear(self: *Aliases) void {
        self.count = 0;
        assert(self.used() == 0);
    }

    /// Keeps a link whose owner is `owner`. False when the chain already holds `cname_hops_max`
    /// links, which the caller turns into `ChainTooLong`: a chain is never longer than that.
    pub fn append(self: *Aliases, owner: *const Name, ttl_seconds: u32) bool {
        if (self.count == limits.cname_hops_max) return false;
        const start = self.used();
        assert(start + owner.len <= limits.chain_bytes_max);
        @memcpy(self.bytes[start..][0..owner.len], owner.wire());
        self.ends[self.count] = @intCast(start + owner.len);
        self.ttls[self.count] = ttl_seconds;
        self.count += 1;
        assert(self.count <= limits.cname_hops_max);
        return true;
    }

    /// The link at `index`.
    pub fn at(self: *const Aliases, index: usize) Link {
        assert(index < self.count);
        const start: usize = if (index == 0) 0 else self.ends[index - 1];
        assert(self.ends[index] > start);
        return .{ .owner = self.bytes[start..self.ends[index]], .ttl_seconds = self.ttls[index] };
    }

    /// The target of the link at `index`, in wire form: the next link's owner, or `end` for the
    /// last link.
    pub fn target(self: *const Aliases, index: usize, end: *const Name) []const u8 {
        assert(index < self.count);
        if (index + 1 == self.count) return end.wire();
        return self.at(index + 1).owner;
    }

    /// Forgets the links past the first `count`: those a message added that the lookup then
    /// ignored.
    pub fn truncate(self: *Aliases, count: u8) void {
        assert(count <= self.count);
        self.count = count;
    }

    /// Folds the case of the owners from the link at `from` on. A name that came off the wire may
    /// carry the case pattern of cocuyo's own query (docs/design.md §5, DNS-0x20). In wire form
    /// a length octet is at most 63, below every capital letter, so only letters change.
    pub fn fold_case(self: *Aliases, from: u8) void {
        assert(from <= self.count);
        const start: usize = if (from == 0) 0 else self.ends[from - 1];
        for (self.bytes[start..self.used()]) |*byte| byte.* = std.ascii.toLower(byte.*);
        comptime assert(limits.label_bytes_max < 'A');
    }

    /// Copies `src` into `self`: the counts and the octets in use, and nothing past them.
    pub fn assign(self: *Aliases, src: *const Aliases) void {
        const length = src.used();
        @memcpy(self.bytes[0..length], src.bytes[0..length]);
        @memcpy(self.ends[0..src.count], src.ends[0..src.count]);
        @memcpy(self.ttls[0..src.count], src.ttls[0..src.count]);
        self.count = src.count;
        assert(self.used() == length);
    }

    fn used(self: *const Aliases) usize {
        assert(self.count <= limits.cname_hops_max);
        return if (self.count == 0) 0 else self.ends[self.count - 1];
    }
};

// Tests.

const testing = std.testing;

test "links keep their owners and TTLs, and each target is the next owner or the end" {
    var aliases: Aliases = .{};
    const first = try Name.parse("www.example.com");
    const second = try Name.parse("cdn.example.net");
    const end = try Name.parse("edge.example.org");
    try testing.expect(aliases.append(&first, 300));
    try testing.expect(aliases.append(&second, 60));
    try testing.expectEqual(@as(u8, 2), aliases.count);
    try testing.expectEqualSlices(u8, first.wire(), aliases.at(0).owner);
    try testing.expectEqual(@as(u32, 60), aliases.at(1).ttl_seconds);
    try testing.expectEqualSlices(u8, second.wire(), aliases.target(0, &end));
    try testing.expectEqualSlices(u8, end.wire(), aliases.target(1, &end));
    var copy: Aliases = .{};
    copy.assign(&aliases);
    try testing.expectEqualSlices(u8, second.wire(), copy.at(1).owner);
    aliases.clear();
    try testing.expectEqual(@as(u8, 0), aliases.count);
}

test "a chain holds cname_hops_max links of the longest names, and refuses one more" {
    var aliases: Aliases = .{};
    // A name of `name_bytes_max` octets: three labels of `label_bytes_max`, one label that takes
    // what is left but its length octet and the root's, then the root.
    const full_labels = 3;
    const last_label = limits.name_bytes_max - full_labels * (limits.label_bytes_max + 1) - 2;
    var text: [limits.name_bytes_max]u8 = undefined;
    var at: usize = 0;
    for (0..full_labels + 1) |label| {
        const length: usize = if (label < full_labels) limits.label_bytes_max else last_label;
        @memset(text[at..][0..length], 'a');
        at += length;
        if (label < full_labels) {
            text[at] = '.';
            at += 1;
        }
    }
    const longest = try Name.parse(text[0..at]);
    try testing.expectEqual(limits.name_bytes_max, longest.wire().len);
    for (0..limits.cname_hops_max) |_| try testing.expect(aliases.append(&longest, 1));
    try testing.expect(!aliases.append(&longest, 1));
    try testing.expectEqual(@as(u8, limits.cname_hops_max), aliases.count);
    try testing.expectEqual(longest.wire().len, aliases.at(limits.cname_hops_max - 1).owner.len);
}
