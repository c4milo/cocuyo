//! One entry of the cache: its hash, its place, and its removal (docs/design.md §18).
//!
//! These are what the files of the cache call of a `Cache`, and no consumer does. So they are
//! functions of this file and no declarations of the type (c4milo/cocuyo#65). Split out of
//! `cache.zig`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Name = core.Name;
const Question = core.Question;
const constants = @import("constants.zig");
const cache_keys = @import("cache_keys.zig");
const cache = @import("cache.zig");
const Cache = cache.Cache;
const none = cache.none;

/// Takes the entry at `index` out of the table. The hand, if it was there, moves on.
pub fn evict(self: *Cache, index: u16) void {
    const slot = &self.slots[index];
    assert(slot.occupied);
    const next = self.order.after(self.slots, index);
    cache_keys.remove(self.keys, slot.hash, index);
    self.order.unlink(self.slots, index);
    if (self.hand == index) self.hand = if (self.order.len == 0) none else next;
    slot.occupied = false;
    release(self, index);
}

/// The slot holding `question`, found through the key index and confirmed by the name.
pub fn find(self: *const Cache, question: *const Question, hash: u32) ?u16 {
    var candidates = cache_keys.Candidates.init(self.keys, hash);
    while (candidates.next()) |index| {
        const slot = &self.slots[index];
        assert(slot.occupied);
        if (slot.kind == question.kind and slot.absolute == question.absolute and
            slot.name.equal(&question.name)) return index;
    }
    return null;
}

/// The keyed hash of the question's folded name, its type and whether it was absolute. Two
/// questions that differ only in `absolute` can resolve differently through the search list,
/// so they are two keys. The name is folded eight octets at a time as it is read, so a hash
/// costs no copy and no per-octet loop. Its length is not mixed in: the last chunk is padded
/// with zeros, and a name ends at its root octet, so no name is another's zero padding
/// (mutation Q34 found the length redundant).
pub fn hash_of(self: *const Cache, question: *const Question) u32 {
    const prefix = self.seed ^
        (@as(u64, question.kind.code()) << constants.hash_kind_shift) ^
        (@as(u64, @intFromBool(question.absolute)) << constants.hash_absolute_shift);
    var word = core.mix.next(prefix);
    const bytes = question.name.wire();
    var offset: usize = 0;
    while (offset + @sizeOf(u64) <= bytes.len) : (offset += @sizeOf(u64)) {
        const chunk = std.mem.readInt(u64, bytes[offset..][0..@sizeOf(u64)], .little);
        word = core.mix.next(word ^ Name.fold_word(chunk));
    }
    var tail: [@sizeOf(u64)]u8 = @splat(0);
    @memcpy(tail[0 .. bytes.len - offset], bytes[offset..]);
    word = core.mix.next(word ^ Name.fold_word(std.mem.readInt(u64, &tail, .little)));
    assert(offset <= core.limits.name_bytes_max);
    return @truncate(word);
}

/// Gives the slot at `index` back to the free list.
pub fn release(self: *Cache, index: u16) void {
    assert(!self.slots[index].occupied);
    self.slots[index].links = .{ .newer = self.free };
    self.free = index;
}
