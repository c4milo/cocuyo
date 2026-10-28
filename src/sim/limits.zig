//! The limits of the twin (docs/design.md §19 step 13, §16 decision 56): what one simulated loop
//! and its network hold. Every table is static and every walk is bounded by one of these.
const std = @import("std");
const constants = @import("constants.zig");
const core = @import("core");

/// The most operations one loop holds in flight: its slot table.
pub const operations_max: usize = 4096;

/// The most events waiting to be delivered by a tick. An operation ends in one final event and a
/// multishot delivers many, so this is above the slot count.
pub const events_pending_max: usize = 8192;

/// The most sockets one network holds, datagram and stream together.
pub const sockets_max: usize = 64;

/// The most scripted servers one network answers for: the servers a configuration may name.
pub const servers_max = core.limits.servers_max;

/// The most datagrams waiting to be delivered, and the room each holds: a reply is at most the
/// UDP payload cocuyo advertises.
pub const datagrams_pending_max: usize = 256;
pub const datagram_bytes_max = core.constants.udp_payload_bytes_default;

/// The most stream connections open at once, and the octets each direction of one buffers.
pub const connections_max: usize = 16;
pub const stream_bytes_max: usize = 16384;

/// Buffer groups and the buffers each holds, as rotor bounds them.
pub const buffer_groups_max: usize = 4;
pub const buffers_per_group_max: usize = 256;

/// What a socket's kernel buffers may be sized to here. This is the shape rotor measured on macOS.
/// A request up to `socket_buffer_bytes_granted_max` gets what it asks for, and a larger one gets
/// that cap. A request above `socket_buffer_bytes_asked_max` is refused, because that kernel
/// refuses rather than caps once a socket is already large.
pub const socket_buffer_bytes_granted_max: usize = 1 << 20;
pub const socket_buffer_bytes_asked_max: usize = 1 << 28;

/// The longest one `tick` may wait: rotor's `wait_ns_max`, ten seconds, kept so a tick valid here
/// is valid there. A caller that waits longer ticks again, as a caller of rotor must.
pub const wait_ns_max: u64 = 10 * constants.ns_per_s;

/// The most events one `tick` may be handed room for: rotor's `batch_max`.
pub const batch_max: usize = 4096;

/// How many ticks `drain` runs before it gives up on an operation that will not end.
pub const drain_rounds_max: usize = 64;

/// The most octets one transfer moves, rotor's bound.
pub const transfer_bytes_max: usize = 1 << 30;

/// The most octets one scripted stream reply is split into per delivery, at the least: a chunk
/// is drawn between this and what the buffer holds, so framing is exercised.
pub const stream_chunk_bytes_min: usize = 1;

/// The most the twin's TLS carries in one record: a framed query at its longest, or a framed
/// answer the size of the twin's largest datagram.
pub const tls_payload_bytes_max: usize = core.constants.tcp_prefix_bytes + datagram_bytes_max;

/// What one call to the twin's session may make before the engine takes it out: one record at
/// its longest.
pub const tls_out_bytes_max: usize = constants.tls_record_header_bytes + tls_payload_bytes_max;

/// The longest datagram the twin's QUIC makes, which is what a pending datagram holds.
pub const quic_datagram_bytes_max = datagram_bytes_max;

/// The most items one datagram holds, which bounds every walk over one: a datagram of items with
/// nothing after their headers.
pub const quic_items_per_datagram_max: usize = quic_datagram_bytes_max / constants.quic_item_header_bytes;

/// What a client connection keeps to send, and how much of it a request may not take: room for
/// every short item it still owes, a cancel for each of the engine's streams among them.
pub const quic_pending_bytes_max: usize = 16384;
pub const quic_pending_reserve_bytes_min: usize = 2048;

/// The longest ALPN token a scripted server keeps from a client's hello (RFC 7301 §6).
pub const quic_alpn_bytes_max: usize = 16;

/// The exchanges the twin's channel holds at once, as colibri's channel holds 16
/// (sim_channel.zig): past them a request waits in the engine's queue (docs/design.md §24,
/// request rule 21).
pub const channel_exchanges_max: usize = 16;

/// The steps a test or the replay may queue on the twin's channel before it says them, one at
/// each of the engine's reads: the longest a test queues, chosen, not measured.
pub const channel_steps_max: usize = 16;

/// The octets the twin's channel writes on a link at once: one item of the twin's QUIC with
/// nothing after its header, framed over TCP as `sim_quic_stream.zig` frames one.
pub const channel_output_bytes_max: usize = core.constants.tcp_prefix_bytes + constants.quic_item_header_bytes;

/// The largest `bytes` that `set_buffer_bytes` carries (`sim_network.zig`), as rotor's is: not
/// a size any kernel grants.
pub const socket_buffer_bytes_max: u32 = std.math.maxInt(i32);

/// One frame of the twin's QUIC over a stream at its longest (`sim_quic_stream.zig`): its
/// length, then a datagram's worth of items.
pub const quic_frame_bytes_max: usize = core.constants.tcp_prefix_bytes + quic_datagram_bytes_max;

/// The most frames one stream send is cut into (`sim_loop_perform.zig`): a send holds at most
/// this many whole queries.
pub const frames_per_send_max: usize = 16;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
