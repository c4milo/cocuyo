//! The limits the cache holds (docs/design.md §18).
const core = @import("core");

/// The most slots one cache may hold. A slot is named by a `u16` in the insertion-order chain and
/// in the key index, with room left for the sentinels, and nobody has asked for more.
pub const slots_max = 16384;

/// The key index holds at least this many entries per slot, so a bounded probe stays short.
pub const keys_per_slot_min = 2;

/// The longest chain a `get` walks before calling it a miss and a `put` before refusing. A peer
/// that chooses the names a process resolves cannot choose where they land, because the hash is
/// keyed by the caller's seed; this bound is what makes a run of collisions cost a miss and never
/// a walk.
pub const probe_max = 16;

/// The TTL cap when the caller sets none: an hour, which is c-ares's default (§18), so a consumer
/// replacing it sees the same ceiling. RFC 8767 §4 asks for a cap and recommends seven days at
/// most, so an hour is inside it.
pub const ttl_seconds_max_default = 3600;

/// Where the type and the flag sit in the word the hash starts from: the flag's one bit at 40,
/// the type's sixteen at 48, so the two never overlap whatever the seed.
pub const hash_absolute_shift = 40;
pub const hash_kind_shift = 48;

/// Nanoseconds in a second, spelled out because nothing under `src/` may name `std.time`
/// (CLAUDE.md non-negotiable 4).
pub const ns_per_s = 1_000_000_000;

/// The most steps one eviction sweep takes: one pass over every slot clears every visited bit,
/// and the next pass must then find an unvisited one.
pub fn sweep_steps_max(slot_count: usize) usize {
    return slot_count * 2;
}

comptime {
    if (slots_max * keys_per_slot_min > 1 << 16) @compileError("the key index cannot be indexed by a u16");
    if (slots_max >= 0xfffe) @compileError("a slot index would collide with a sentinel");
    if (probe_max < 2) @compileError("a probe of one entry is a hash lookup with no chain");
}
