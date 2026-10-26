//! The constants of `cocuyo_doh`, colibri's `client.Channel` under the engine's DoH interface,
//! that are no limit (docs/design.md §24, DoH over colibri's client). A module of its own, so its
//! constants live apart from the engine's `constants.zig`. Its limits are in
//! `io_doh_channel_limits.zig` (§16 decision 56).
const std = @import("std");
const limits = @import("io_doh_channel_limits.zig");

/// A TLS record's header: five octets (RFC 9846 §5.1). The longest record is in `limits`.
pub const record_header_bytes: usize = 5;

/// How long a channel gives QUIC's handshake before TCP opens beside it, `doh_fallback_delay_ns`:
/// the Connection Attempt Delay RFC 8305 §5 recommends, which that RFC sets between attempts at two
/// addresses, not two versions of HTTP. Taken from it, not measured.
pub const fallback_delay_ms: u64 = 250;
pub const fallback_delay_ns: u64 = fallback_delay_ms * ns_per_millisecond;

/// The 2xx statuses, "the request was successfully received, understood, and accepted" (RFC 9110
/// §15.3), the ones whose content a DoH answer is (RFC 8484 §4.2.1).
pub const status_success_first: u16 = 200;
pub const status_success_last: u16 = 299;

pub const ns_per_second: u64 = 1_000_000_000;
pub const ns_per_millisecond: u64 = 1_000_000;

// The paths a consumer reached these limits by before they moved into the limits file. Each
// is an alias, and no limit of its own. They stay until the owner rules on them (docs/design.md
// §16 decision 56, §17 question 76).
pub const record_plaintext_bytes_max = limits.record_plaintext_bytes_max;
pub const record_expansion_bytes_max = limits.record_expansion_bytes_max;
pub const record_bytes_max = limits.record_bytes_max;
pub const engine_chunk_bytes = limits.engine_chunk_bytes;
pub const stream_bytes = limits.stream_bytes;
pub const datagram_bytes = limits.datagram_bytes;
pub const values_bytes = limits.values_bytes;
pub const unheard_per_next_max = limits.unheard_per_next_max;
pub const next_passes_max = limits.next_passes_max;
pub const output_bytes_max = limits.output_bytes_max;
pub const receive_bytes = limits.receive_bytes;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
