//! The limits of `cocuyo_doh`, colibri's `client.Channel` under the engine's DoH interface
//! (docs/design.md §24, DoH over colibri's client, New limits). A module of its own, so its limits
//! live apart from the engine's `constants.zig`; the ones every DoH transport shares are `doh`'s.

/// A TLS record at its longest, header and all: a five-octet header, then at most 2^14 + 256
/// octets of `encrypted_record`, its plaintext and what protecting it adds (RFC 9846 §5.2).
pub const record_header_bytes = 5;
pub const record_plaintext_bytes_max = 16_384;
pub const record_expansion_bytes_max = 256;
pub const record_bytes_max = record_header_bytes + record_plaintext_bytes_max + record_expansion_bytes_max;

/// One chunk of the stream the engine reads at a time: its TCP chunk, `tcp_chunk_bytes` in
/// `io/constants.zig`, which this module cannot import.
pub const engine_chunk_bytes = 2048;

/// The octets of the stream a channel keeps until colibri takes them, `doh_stream_bytes`: a record
/// at its longest, which colibri takes only whole, and one chunk after it.
pub const stream_bytes = record_bytes_max + engine_chunk_bytes;

/// The datagram a channel keeps until colibri takes it, `doh_datagram_bytes`: the engine's datagram
/// buffer, `buffer_bytes` in `io/constants.zig`, which holds any datagram the engine reads.
pub const datagram_bytes = 2048;

/// Where a response's `content-type`, `content-encoding` and `age` are copied, `doh_values_bytes`.
/// A response whose values do not fit fails its request as too large. Chosen, not measured.
pub const values_bytes = 256;

/// The passes `next` takes at most: each takes octets of what the links read or says something, and
/// what colibri says that the engine does not hear, the version each of the two connections speaks,
/// comes once for each, then one pass says nothing.
pub const unheard_per_next_max = 2;
pub const next_passes_max = datagram_bytes + stream_bytes + unheard_per_next_max + 1;

/// What one output holds: a record at its longest. A QUIC datagram is shorter.
pub const output_bytes_max = record_bytes_max;

/// colibri's receive pool for the channel's QUIC connection: a DNS message at its longest with the
/// two-octet prefix DoQ gives it, rounded up to the pool's 1,024-octet blocks, `cocuyo_quic`'s
/// default. Every window the connection advertises follows it (RFC 9000 §4.1).
pub const receive_bytes = 66_560;

/// How long a channel gives QUIC's handshake before TCP opens beside it, `doh_fallback_delay_ns`:
/// the Connection Attempt Delay RFC 8305 §5 recommends, which that RFC sets between attempts at two
/// addresses, not two versions of HTTP. Taken from it, not measured.
pub const fallback_delay_ms = 250;
pub const fallback_delay_ns = fallback_delay_ms * ns_per_millisecond;

/// The 2xx statuses, "the request was successfully received, understood, and accepted" (RFC 9110
/// §15.3), the ones whose content a DoH answer is (RFC 8484 §4.2.1).
pub const status_success_first = 200;
pub const status_success_last = 299;

pub const ns_per_second = 1_000_000_000;
pub const ns_per_millisecond = 1_000_000;
