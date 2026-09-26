//! The limits of the I/O engine (docs/design.md §19 step 13): what one engine holds beside the
//! lookups and the cache its options size.
const core = @import("cocuyo").core;

/// The lookups an engine holds in flight, when the caller says nothing.
pub const lookups_default = 256;

/// The cache's slots, when the caller says nothing: a thousand, which §18 measures at 2.9 MiB.
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
/// is told from the one now armed. The generation is thirty-two bits, which the index's forty
/// hold above the server's eight.
pub const receive_generation_shift = 8;
pub const receive_index_mask = (1 << receive_generation_shift) - 1;

/// Where a connection's incarnation sits in the `user_data` of its connect and its receive, above
/// the connection's slot, so the event of an opening of the slot that is gone is told from the
/// current one's (docs/design.md §19 step 13, the stream's rule 2). A slot fits in the octet
/// below it.
pub const tcp_incarnation_shift = 8;
pub const tcp_slot_mask = (1 << tcp_incarnation_shift) - 1;

/// The polls one drive makes for one lookup at most, which bounds the drive's loop: each server
/// and pass the lookup can fail over to within one drive costs two, one to ask for the
/// connection and one to send on it, and its end one more. A drive that stopped short of this
/// left a lookup on the ready list with its query unsent and nothing to wake it (the stream's
/// rule 8).
pub const drive_polls_per_lookup_max = 2 * core.constants.servers_max * core.constants.attempts_max + 1;

/// What one connection asks of the loop: the connect, and then the receive that replaces it, and
/// over TLS a send of the session's own records (docs/design.md §21).
pub const loop_operations_per_connection = 3;

/// The most whole messages taken out of one chunk, which bounds the framing loop. A chunk is one
/// read, and a pipelined server can answer several queries in one.
pub const tcp_messages_per_chunk_max = 32;

/// A TLS record's header: its content type, two octets of legacy version and two of length
/// (RFC 9846 §5.1), and where the length sits.
pub const tls_record_header_bytes = 5;
pub const tls_record_length_at = 3;

/// The longest record body a TLS 1.3 peer may send: 2^14 octets of plaintext, one of content type
/// and 255 of expansion (RFC 9846 §5.2).
pub const tls_record_body_bytes_max = (1 << 14) + 256;

/// What a TLS connection keeps of a record until the rest arrives: one at its longest, header and
/// all (docs/design.md §21, TLS rule 7).
pub const tls_record_in_bytes = tls_record_header_bytes + tls_record_body_bytes_max;

/// What sealing adds to a record: its header, the inner content type and the AEAD's 16-octet tag
/// (RFC 9846 §5.2).
pub const tls_record_overhead_bytes = tls_record_header_bytes + 1 + 16;

/// The sealed records a TLS connection holds before they go: what the session stages at once, a
/// ClientHello at its longest among it, beside a query sealed at its longest. `io_chapulin.zig`
/// holds it to that sum at compile time, against chapulin's own staging bound. What is left, more
/// than a thousand octets today, holds the few of a KeyUpdate's answer and a `close_notify`. Past
/// it the connection fails rather than hold more (§21, TLS rule 3).
pub const tls_records_out_bytes = 4096;

/// The entries of the session's own records one queue holds at once beside its queries: the one
/// in flight, and the one behind it, which every record made meanwhile joins (§21, TLS rule 2).
pub const tls_records_entries_max = 2;

/// The most whole records handed to the session from one chunk, which bounds the framing loop.
pub const tls_records_per_chunk_max = 32;

/// A client MUST NOT use a ticket more than seven days after it was issued (RFC 9846 §4.7.1).
pub const tls_ticket_age_ns_max = 7 * 24 * 60 * 60 * 1_000_000_000;

/// The reads one record may take from chapulin's session: one for its plaintext and one to hear
/// that no record follows, with room for plaintext longer than the frame's room.
pub const chapulin_reads_per_record_max = 4;

/// The staging a handshake step may drain from chapulin at once, in pieces of any size: a bound on
/// the loop that collects it, far past a flight's records.
pub const chapulin_out_pieces_max = 64;

/// What one QUIC connection asks of the loop: its receive, and the send of its datagram
/// (docs/design.md §24, request rules 1 and 8).
pub const loop_operations_per_quic_connection = 2;

/// What one request connection over TCP asks of the loop: its connect, its receive, and the send of
/// its octets (docs/design.md §24, request rules 14 and 15).
pub const loop_operations_per_h2_connection = 3;

/// Where a QUIC connection's incarnation sits in the `user_data` of its operations, above its
/// server's index, as a TCP connection's does above its slot. A server fits in the octet below.
pub const quic_incarnation_shift = 8;
pub const quic_server_mask = (1 << quic_incarnation_shift) - 1;

/// How long a QUIC connection with no request on it is kept: TCP's ten seconds. RFC 9250 §5.5.2
/// names no value; this one is chosen, not measured (docs/design.md §24, request rule 9).
pub const quic_idle_ns_default = tcp_idle_ns_default;

/// How near the idle timeout it negotiated a connection with no request stops taking one, and
/// closes instead (RFC 9250 §4.4, request rule 9): a query and its answer take less than a
/// second. Chosen, not measured.
pub const quic_idle_margin_ns = 1_000_000_000;

/// The `next` calls one datagram or one expiry is read with, beside one answer or reset for each
/// lookup: the handshake's end, a close and tickets. Chosen, not measured. What a flood leaves
/// unread is read with the next datagram (docs/design.md §24, New limits).
pub const quic_connection_events_max = 16;

/// The ALPN token of DoQ (RFC 9250 §4.1).
pub const quic_alpn_doq = "doq";

/// The ALPN token of HTTP/3, which DoH goes over (RFC 9114 §3.2).
pub const quic_alpn_h3 = "h3";

/// The ALPN token of HTTP/2 over TLS, which DoH goes over when HTTP/3 does not (RFC 9113 §3.2).
pub const alpn_h2 = "h2";

/// The port a DoH server's connection goes to when its template names none: "If the port
/// subcomponent is empty or not given, TCP port 443 ... is the default" (RFC 9110 §4.2.2), and
/// HTTP/3 goes to "the indicated port" over UDP (RFC 9114 §3.1).
pub const port_https_default = 443;

/// The successful status codes: "The 2xx (Successful) class of status code indicates that the
/// client's request was successfully received, understood, and accepted" (RFC 9110 §15.3), and a
/// DoH answer comes in one alone (RFC 8484 §4.2.1).
pub const http_status_success_first = 200;
pub const http_status_success_last = 299;

/// A second and a millisecond, in nanoseconds: chapulin's clock is Unix seconds, and a resumed
/// hello states a ticket's age in milliseconds (RFC 9846 §4.3.11.1).
pub const ns_per_second = 1_000_000_000;
pub const ns_per_millisecond = 1_000_000;

comptime {
    if (kind_shift - receive_generation_shift < 32) {
        @compileError("a receive's user_data has no room for a thirty-two-bit generation");
    }
    if (quic_incarnation_shift + 32 > kind_shift) {
        @compileError("a QUIC connection's user_data has no room for a thirty-two-bit incarnation");
    }
    if (buffer_bytes < core.constants.udp_payload_bytes_default + 192) {
        @compileError("a group buffer cannot hold the payload cocuyo advertises after rotor's prefix");
    }
}
