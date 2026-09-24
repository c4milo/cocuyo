//! The limits this module holds. Everything the codec and the types share lives in
//! `core/constants.zig`; these are the table's own.
const core = @import("core");

/// The key table holds at least this many entries per slot. A load factor of one half is where
/// linear probing still finds an entry in a step or two, and the table is sized by the caller, so
/// the floor is checked rather than assumed (docs/design.md §11).
pub const keys_per_slot_min = 2;

/// The transactions a lookup draws for one name on one server in one pass: the query, the
/// retry without EDNS0 after FORMERR (RFC 6891 §6.2.2) and the retry with the server cookie
/// after BADCOOKIE (RFC 7873 §5.3). It bounds a transaction's `number` (docs/design.md §22).
pub const transactions_per_server_max = 3;

comptime {
    // Two entries per slot, at the largest table, must still be a count a power of two can cover.
    if (core.constants.lookup_slots_max * keys_per_slot_min > 1 << 16) {
        @compileError("the key table cannot be indexed by a sixteen-bit slot");
    }
}
