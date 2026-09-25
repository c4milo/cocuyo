//! The limits of `cocuyo_quic`, colibri under the engine's request interface (docs/design.md §24,
//! New limits). A module of its own, so its limits live apart from the engine's `constants.zig`.
const cocuyo = @import("cocuyo");

/// The idle timeout a connection advertises (RFC 9000 §18.2, `max_idle_timeout`): thirty seconds.
/// The server's may be shorter, and the smaller holds (RFC 9250 §4.4). Chosen, not measured.
pub const idle_timeout_ms = 30_000;

/// The Destination Connection ID a client's first Initial carries, and its own Source Connection
/// ID: "This Destination Connection ID MUST be at least 8 bytes in length" (RFC 9000 §7.2).
pub const connection_id_bytes = 8;

/// The largest datagram a connection reads, which it advertises (RFC 9000 §18.2,
/// `max_udp_payload_size`): an Ethernet frame's payload, which the engine's datagram group holds
/// after rotor's prefix.
pub const datagram_receive_bytes = 1500;

/// A DoQ answer at its longest, with its prefix (RFC 9250 §4.2). The engine reads a stream once all
/// of it has arrived, so a stream's receive window holds one whole.
pub const answer_bytes_max = cocuyo.constants.tcp_prefix_bytes + cocuyo.constants.message_bytes_max;

/// colibri's receive pool for a connection, by default: one answer at its longest, rounded up to
/// the pool's blocks of 1,024 octets. colibri adds two blocks for each stream it can hold.
pub const pool_block_bytes = 1024;
pub const receive_bytes_default = (answer_bytes_max + pool_block_bytes - 1) / pool_block_bytes * pool_block_bytes;

/// What a connection's transport parameters take when written (RFC 9000 §18): far past the dozen
/// it sends.
pub const params_bytes_max = 256;

/// A DoH request's slot: the HEADERS frame of its GET (docs/design.md §24, New limits). colibri's
/// bound on the frame is 317 octets beside `:authority` and `:path`, an authority takes 259 at
/// most (a 253-octet name and a port), and 960 are left for the path, whose `dns` value takes 512.
pub const doh_request_bytes_max = 1536;

/// A DoH connection's answer buffers when the consumer names none: one for each response in
/// flight, each holding an answer at its longest (docs/design.md §24, DoH over HTTP/3). Chosen,
/// not measured.
pub const answers_default = 4;

/// The unidirectional streams an HTTP/3 connection lets the server open, and each one's credit:
/// the endpoint "MUST allow its peer to create at least one unidirectional stream for the HTTP
/// control stream", QPACK needs two more, and it "SHOULD also provide at least 1,024 bytes of
/// flow-control credit to each unidirectional stream" (RFC 9114 §6.2). colibri's `h3` tracks 8.
pub const h3_peer_uni_streams = 8;
pub const h3_peer_uni_stream_bytes = 1024;

/// A piece of a response's content, which `h3` hands over as it arrives: a datagram's worth, since
/// it arrives a packet at a time.
pub const h3_chunk_bytes = datagram_receive_bytes;

/// The `h3` events one `next` reads before it lets the engine go on: each takes an octet of the
/// receive pool at least, so a pool's worth. What is left is read with the next datagram.
pub const h3_events_per_next_max = receive_bytes_default;

/// HTTP/3's error codes (RFC 9114 §8.1): H3_NO_ERROR for an idle close, and H3_REQUEST_CANCELLED
/// for a request the lookup left (§4.1.1).
pub const h3_no_error = 0x0100;
pub const h3_request_cancelled = 0x010c;

/// DoQ's error codes (RFC 9250 §4.3): DOQ_NO_ERROR for an idle close (§4.4), and
/// DOQ_REQUEST_CANCELLED for a request the lookup left (§4.3.1).
pub const doq_no_error = 0x0;
pub const doq_request_cancelled = 0x3;

/// The test server's (`io_quic_server.zig`): its receive pool, which holds the few queries a test
/// sends at once, and the longest answer it keeps, a datagram's worth after the prefix. Its
/// Source Connection ID is one octet repeated.
pub const server_receive_blocks = 16;
pub const server_receive_bytes = server_receive_blocks * pool_block_bytes;
pub const server_answer_bytes_max = cocuyo.constants.tcp_prefix_bytes + cocuyo.constants.udp_payload_bytes_default;
pub const server_id_octet = 0x5e;

/// The DoH test server's (`io_quic_server_h3.zig`): what goes before a response's content, an
/// interim HEADERS frame, the final one and a DATA frame's header, far past the few lines it
/// writes, and the digits of a content-length.
pub const server_prefix_bytes_max = 512;
pub const server_length_digits_max = 20;

/// The longest transport parameters a server may send that a session keeps (RFC 9000 §18): four
/// times what this end sends, as colibri's own chapulin adapter keeps. Chosen, not measured; a
/// longer body is dropped, and the handshake fails for want of it.
pub const peer_params_bytes_max = 1024;

/// A second and a millisecond, in nanoseconds: chapulin's clock is Unix seconds, and a resumed
/// hello states a ticket's age in milliseconds (RFC 9846 §4.3.11.1).
pub const ns_per_second = 1_000_000_000;
pub const ns_per_millisecond = 1_000_000;

/// chapulin's QUIC session keeps two bits for each level in `levels_ready`, read then write: its
/// quic.h, `CH_QUIC_LEVEL_BIT`, whose macro translate-c cannot call with values known only at run
/// time.
pub const chapulin_bits_per_level = 2;
