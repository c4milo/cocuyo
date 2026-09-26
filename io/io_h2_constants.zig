//! The limits of `cocuyo_h2`, colibri's HTTP/2 under the engine's request interface
//! (docs/design.md §24, DoH over HTTP/2, New limits). A module of its own, so its limits live apart
//! from the engine's `constants.zig`; the ones both HTTP transports share are `doh`'s.
const h2 = @import("h2");
const tls = h2.tls;

/// What one output holds: a record at its longest, header and all, which is the least colibri's
/// provider writes a handshake flight into (`tls.constants.record_write_len_min`).
pub const output_bytes_max = tls.constants.record_write_len_min;

/// The most octets one `receive` takes: the engine's TCP chunk, 2,048 octets in `io/constants.zig`,
/// doubled. Chosen, not measured.
pub const receive_bytes_max = 4096;

/// What a connection keeps of the stream until it makes whole records: a record at its longest,
/// short of an octet, and one receive after it.
pub const records_bytes = tls.constants.record_write_len_min + receive_bytes_max;

/// What a connection keeps of the plaintext colibri reads frames from: a record's plaintext, 2^14
/// octets at most (RFC 9846 §5.1), after the part of a frame the last record left, 16,392 octets
/// at most, since colibri advertises the smallest frame size, 2^14 octets and a 9-octet header
/// (RFC 9113 §4.2). docs/design.md §24 names it `h2_plaintext_bytes`.
pub const h2_plaintext_bytes = tls.constants.record_plaintext_len_max + h2.constants.frame_header_len + h2.constants.frame_size_max - 1;

/// The frames written and not yet sealed: the GETs and what colibri owes, one record's plaintext at
/// most, and what does not fit waits in colibri, or leaves its request waiting (request rule 4).
pub const outgoing_bytes = tls.constants.record_plaintext_len_max;

/// The frames and records `next` reads before it says nothing more: every frame of a full
/// plaintext buffer at its shortest, a header alone.
pub const events_per_next_max = h2_plaintext_bytes / h2.constants.frame_header_len;

comptime {
    // A record's plaintext fits after the longest part of a frame the last record left.
    if (h2_plaintext_bytes < tls.constants.record_plaintext_len_max + h2.constants.frame_size_max) {
        @compileError("the plaintext buffer cannot hold a record after a frame's part");
    }
}
