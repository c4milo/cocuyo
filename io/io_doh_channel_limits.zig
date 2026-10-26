//! The limits of `cocuyo_doh`, colibri's `client.Channel` under the engine's DoH interface
//! (docs/design.md §24, DoH over colibri's client, New limits; §16 decision 56). A module of its
//! own, so its limits live apart from the engine's `limits.zig`; the ones every DoH transport
//! shares are `doh`'s.
const std = @import("std");
const constants = @import("io_doh_channel_constants.zig");

/// A TLS record at its longest, header and all: a five-octet header, then at most 2^14 + 256
/// octets of `encrypted_record`, its plaintext and what protecting it adds (RFC 9846 §5.2).
pub const record_plaintext_bytes_max: usize = 16_384;
pub const record_expansion_bytes_max: usize = 256;
pub const record_bytes_max: usize = constants.record_header_bytes + record_plaintext_bytes_max + record_expansion_bytes_max;

/// One chunk of the stream the engine reads at a time: its TCP chunk, `tcp_chunk_bytes` in
/// `io/limits.zig`, which this module cannot import.
pub const engine_chunk_bytes: usize = 2048;

/// The octets of the stream a channel keeps until colibri takes them, `doh_stream_bytes`: a record
/// at its longest, which colibri takes only whole, and one chunk after it.
pub const stream_bytes: usize = record_bytes_max + engine_chunk_bytes;

/// The datagram a channel keeps until colibri takes it, `doh_datagram_bytes`: the engine's datagram
/// buffer, `buffer_bytes` in `io/limits.zig`, which holds any datagram the engine reads.
pub const datagram_bytes: usize = 2048;

/// Where a response's `content-type`, `content-encoding` and `age` are copied, `doh_values_bytes`.
/// A response whose values do not fit fails its request as too large. Chosen, not measured.
pub const values_bytes: usize = 256;

/// The passes `next` takes at most: each takes octets of what the links read or says something, and
/// what colibri says that the engine does not hear, the version each of the two connections speaks,
/// comes once for each, then one pass says nothing.
pub const unheard_per_next_max: usize = 2;
pub const next_passes_max: usize = datagram_bytes + stream_bytes + unheard_per_next_max + 1;

/// What one output holds: a record at its longest. A QUIC datagram is shorter.
pub const output_bytes_max = record_bytes_max;

/// colibri's receive pool for the channel's QUIC connection: a DNS message at its longest with the
/// two-octet prefix DoQ gives it, rounded up to the pool's 1,024-octet blocks, `cocuyo_quic`'s
/// default. Every window the connection advertises follows it (RFC 9000 §4.1).
pub const receive_bytes: usize = 66_560;

/// The test server's (`io_doh_channel_server.zig`): a response's field lines at most, its media
/// type, its length, a content coding and an `Age`; and the digits of a length at most, those
/// of the largest `u64`.
pub const server_response_fields_max: usize = 4;
pub const server_length_digits_max: usize = 20;

/// The longest value the test server keeps of what it heard (`io_doh_channel_server.zig`).
/// Chosen, not measured.
pub const server_heard_bytes_max: usize = 64;

/// The events the test server reads for one input at most (`io_doh_channel_server.zig`): each
/// takes octets of the input, or reports one of a request's events or the connection's.
pub const server_events_per_input_max: usize = stream_bytes + 1;

/// The answers that the test server holds at once while their content goes out
/// (`io_doh_channel_server.zig`): one for each request that a test has in flight.
pub const server_owed_max: usize = 2;

/// The connections the test server over QUIC holds at once (`io_doh_channel_server_quic.zig`): a
/// test's channel, and the one after it.
pub const server_connections_max: usize = 2;

/// The responses in flight at once on the test server over QUIC
/// (`io_doh_channel_server_quic.zig`), each with its content until it is done.
pub const server_responses_max: usize = 4;

/// The most a response of the raw test server holds (`io_doh_channel_server_raw.zig`): colibri's
/// longest head and a DNS message at its longest, each sealed in records with their overhead.
pub const server_response_bytes_max: usize = 131_072;

/// The request's plaintext the raw test server keeps until the end of its head
/// (`io_doh_channel_server_raw.zig`).
pub const server_request_bytes_max: usize = 4096;

/// Room for a ClientHello at its longest: a post-quantum key share, a ticket and a cookie.
pub const hello_bytes_max: usize = 4096;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
