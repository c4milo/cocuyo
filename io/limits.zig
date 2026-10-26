//! The limits of the I/O engine (docs/design.md §19 step 13, §16 decision 56): what one engine
//! holds beside the lookups its options size and the cache its caller hands it the memory of.
const std = @import("std");
const constants = @import("constants.zig");
const core = @import("cocuyo").core;
const rotor = @import("rotor");

/// The octets of each buffer the datagram group holds: rotor's prefix plus the payload cocuyo
/// advertises, rounded up to a power of two the ring wants.
pub const buffer_bytes: usize = 2048;

/// The most `Config.udp_payload_bytes` that the engine's `init` and `reinit` take. It is what one
/// buffer of the datagram group holds of a datagram: `buffer_bytes` less rotor's prefix, 1,856
/// octets. It follows from the buffer and the options, so a change of either changes it too. "The
/// requestor SHOULD place a value in this field that it can actually receive" (RFC 6891 §6.2.3). A
/// longer datagram arrives cut (docs/design.md §19 step 13, the datagram's rules 6 and 7).
pub const udp_payload_bytes_max: usize = rotor.datagram.payload_capacity(buffer_bytes, constants.group_options);

/// The most operations and entries the loop is asked to hold for one engine: a receive per
/// server, a send per lookup, one timer, and slack for the closes.
pub const loop_operations_slack: usize = 16;

/// The longest message a length prefix can describe (RFC 7766 §8), which is what one connection
/// assembles its chunks into. A stream exists for the answers a datagram cannot carry, so the
/// buffer is the whole of what one can say.
pub const tcp_message_bytes_max = core.limits.message_bytes_max;

/// The most alignment a buffer group's storage may claim for itself. The loader keeps page
/// alignment and nothing larger, and the smallest page of any target cocuyo builds for is 4 KiB,
/// so a type that claims more makes a promise some platform breaks — and in ReleaseSafe the
/// optimizer believes the promise (docs/design.md §19 step 13). The ring's own 64 KiB is found at
/// run time inside the storage instead.
pub const storage_alignment_max: usize = 4096;

/// The octets of each buffer the stream group holds: one chunk of a stream.
pub const tcp_chunk_bytes: usize = 2048;

/// The polls one drive makes for one lookup at most, which bounds the drive's loop: each server
/// and pass the lookup can fail over to within one drive costs two, one to ask for the
/// connection and one to send on it, and its end one more. A drive that stopped short of this
/// left a lookup on the ready list with its query unsent and nothing to wake it (the stream's
/// rule 8).
pub const drive_polls_per_lookup_max: usize = 2 * core.limits.servers_max * core.limits.attempts_max + 1;

/// What one connection asks of the loop: the connect, and then the receive that replaces it, and
/// over TLS a send of the session's own records (docs/design.md §21).
pub const loop_operations_per_connection: usize = 3;

/// What a connection's frame holds past its partial message in the clear: one chunk. A connection
/// takes a chunk whole before it hands over the messages the chunk ends. The chunk that ends one
/// message can start the next (docs/design.md §19 step 13, the stream's rule 11).
pub const tcp_frame_room_bytes: usize = tcp_chunk_bytes;

/// What a connection's frame holds past its partial message over TLS: the body of one record at
/// its longest. The session opens a whole record into the frame after the partial message.
/// colibri asks for room as long as the record's body (RFC 9846 §5.2; §21, TLS rule 7).
pub const tls_frame_room_bytes: usize = tls_record_body_bytes_max;

/// The most whole messages a connection's frame holds at once, which bounds the loop over it.
/// Each message is at least its two-octet prefix (RFC 1035 §4.2.2), and a frame over TLS is the
/// longest. So the loop hands over every whole message, and none waits for a chunk that may not
/// come (the stream's rule 11).
pub const tcp_messages_per_frame_max: usize = (core.constants.tcp_prefix_bytes + tcp_message_bytes_max +
    @max(tcp_frame_room_bytes, tls_frame_room_bytes)) / core.constants.tcp_prefix_bytes;

/// The longest record body a TLS 1.3 peer may send: 2^14 octets of plaintext, one of content type
/// and 255 of expansion (RFC 9846 §5.2).
pub const tls_record_body_bytes_max: usize = (1 << 14) + 256;

/// What a TLS connection keeps of the records it reads: one at its longest, header and all, and
/// one chunk. The chunk that ends a record can start the next one. The connection takes the whole
/// chunk before it hands the first record to the session (docs/design.md §21, TLS rule 7).
pub const tls_record_in_bytes: usize = constants.tls_record_header_bytes + tls_record_body_bytes_max + tcp_chunk_bytes;

/// The sealed records a TLS connection holds before they go: what the session stages at once, a
/// ClientHello at its longest among it, beside a query sealed at its longest. `io_chapulin.zig`
/// holds it to that sum at compile time. What is left, more than a thousand octets today, holds
/// the few of a KeyUpdate's answer and a `close_notify`. Past it the connection fails rather than
/// hold more (§21, TLS rule 3).
pub const tls_records_out_bytes: usize = 4096;

/// The entries of the session's own records one queue holds at once beside its queries: the one
/// in flight, and the one behind it, which every record made meanwhile joins (§21, TLS rule 2).
pub const tls_records_entries_max: usize = 2;

/// The most whole records a TLS connection's buffer holds at once, which bounds the loop over it.
/// Each record is at least its five-octet header (RFC 9846 §5.1). So the loop hands every whole
/// record to the session, and none waits for a chunk that may not come (TLS rule 7).
pub const tls_records_per_buffer_max: usize = tls_record_in_bytes / constants.tls_record_header_bytes;

/// A client MUST NOT use a ticket more than seven days after it was issued (RFC 9846 §4.7.1).
pub const tls_ticket_age_ns_max: u64 = 7 * 24 * 60 * 60 * 1_000_000_000;

/// What one QUIC connection asks of the loop: its receive, and the send of its datagram
/// (docs/design.md §24, request rules 1 and 8).
pub const loop_operations_per_quic_connection: usize = 2;

/// A channel's operations in the loop at once: its QUIC link's receive and send, and its TCP link's
/// connect, receive and send (docs/design.md §24, rule 19).
pub const loop_operations_per_channel: usize = 5;

/// What one read of a channel takes at most beside an end for each request: its links' opens and
/// closes, its tickets and its close, which bounds the loop over it. What a flood leaves unread is
/// read at the next read. Chosen, not measured, as `quic_connection_events_max` is.
pub const channel_events_max: usize = 16;

/// How near the idle timeout it negotiated a connection with no request stops taking one, and
/// closes instead (RFC 9250 §4.4, request rule 9): a query and its answer take less than a
/// second. Chosen, not measured.
pub const quic_idle_margin_ns: u64 = 1_000_000_000;

/// The `next` calls one datagram or one expiry is read with, beside one answer or reset for each
/// lookup: the handshake's end, a close and tickets. Chosen, not measured. What a flood leaves
/// unread is read with the next datagram (docs/design.md §24, New limits).
pub const quic_connection_events_max: usize = 16;

/// The most digits of a `dec-octet` in a template's host (`io_request_template.zig`): 255
/// (RFC 3986 §3.2.2).
pub const template_octet_digits_max: usize = 3;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
