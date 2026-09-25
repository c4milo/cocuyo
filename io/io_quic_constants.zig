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
