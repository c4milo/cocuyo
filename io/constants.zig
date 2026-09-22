//! The limits of the I/O engine (docs/design.md §19 step 13): what one engine holds beside the
//! lookups and the cache its options size.
const core = @import("cocuyo").core;

/// The lookups an engine holds in flight, when the caller says nothing.
pub const lookups_default = 256;

/// The cache's slots, when the caller says nothing: a thousand, which §18 measures at 2.7 MiB.
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

/// The most operations and entries the loop is asked to hold for one engine: a receive per
/// server, a send per lookup, one timer, and slack for the closes.
pub const loop_operations_slack = 16;

/// The TCP connections one engine keeps, when the caller says nothing. One: every lookup that
/// needs a stream to the same server pipelines onto it (RFC 7766 §6.2.1.1), and a caller that
/// asks several servers over TCP at once raises it. Each costs a message buffer.
pub const tcp_connections_default = 1;

/// The longest message a length prefix can describe (RFC 7766 §8), which is what one connection
/// assembles its chunks into. A stream exists for the answers a datagram cannot carry, so the
/// buffer is the whole of what one can say.
pub const tcp_message_bytes_max = core.constants.message_bytes_max;

/// The stream chunks arrive in a group of their own: a datagram group carries rotor's prefix
/// before every payload, and a stream has no peer to name.
pub const tcp_group_id = 1;

/// The most alignment a buffer group's storage may claim for itself. The loader keeps page
/// alignment and nothing larger, and the smallest page of any target cocuyo builds for is 4 KiB,
/// so a type that claims more makes a promise some platform breaks — and in ReleaseSafe the
/// optimizer believes the promise (docs/design.md §19 step 13). The ring's own 64 KiB is found at
/// run time inside the storage instead.
pub const storage_alignment_max = 4096;
pub const tcp_chunk_bytes = 2048;
pub const tcp_group_buffers_default = 8;

/// How long a connection nobody is using is kept. Ten seconds, chosen and not measured, which is
/// short by the standard RFC 7766 §6.2.3 sets a client.
pub const tcp_idle_ns_default = 10_000_000_000;

/// Where a receive's generation sits in its `user_data`, above the server's index: a socket
/// that has been replaced has a generation of its own, so the end of the receive it left behind
/// is told from the one now armed.
pub const receive_generation_shift = 8;
pub const receive_index_mask = (1 << receive_generation_shift) - 1;

/// What one connection asks of the loop: the connect, and then the receive that replaces it.
pub const loop_operations_per_connection = 2;

/// The most whole messages taken out of one chunk, which bounds the framing loop. A chunk is one
/// read, and a pipelined server can answer several queries in one.
pub const tcp_messages_per_chunk_max = 32;

comptime {
    if (buffer_bytes < core.constants.udp_payload_bytes_default + 192) {
        @compileError("a group buffer cannot hold the payload cocuyo advertises after rotor's prefix");
    }
}
