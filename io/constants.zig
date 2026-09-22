//! The limits of the I/O engine (docs/design.md §19 step 13): what one engine holds beside the
//! lookups and the cache its options size.
const core = @import("cocuyo").core;

/// The lookups an engine holds in flight, when the caller says nothing.
pub const lookups_default = 256;

/// The cache's slots, when the caller says nothing: §18's memory row.
pub const cache_slots_default = 1024;

/// The high sixteen bits of every `user_data` the engine submits, so a caller sharing the loop
/// tells the engine's events from its own. One by default; a caller with several engines on
/// one loop gives each its own.
pub const tag_default = 1;

/// Where the tag and the kind sit in a `user_data`, above the index in the low bits.
pub const tag_shift = 48;
pub const kind_shift = 40;
pub const index_mask = (1 << kind_shift) - 1;

/// The buffers the datagram group holds, and the octets of each: rotor's prefix plus the payload
/// cocuyo advertises, rounded up to a power of two the ring wants.
pub const group_buffers_default = 64;
pub const buffer_bytes = 2048;
pub const group_id = 0;

/// The most polls one drive of the table makes: one per slot, so a table full of lookups that
/// each want something is walked once.
pub const polls_per_drive_max = 4096;

/// The most operations and entries the loop is asked to hold for one engine: a receive per
/// server, a send per lookup, one timer, and slack for the closes.
pub const loop_operations_slack = 16;

comptime {
    if (buffer_bytes < core.constants.udp_payload_bytes_default + 192) {
        @compileError("a group buffer cannot hold the payload cocuyo advertises after rotor's prefix");
    }
}
