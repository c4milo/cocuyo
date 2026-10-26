//! The constants of `cocuyo_quic`, colibri under the engine's request interface, that are no limit
//! (docs/design.md §24, New limits). A module of its own, so its constants live apart from the
//! engine's `constants.zig`. Its limits are in `io_quic_limits.zig` (§16 decision 56).
const std = @import("std");
const limits = @import("io_quic_limits.zig");
const cocuyo = @import("cocuyo");

/// The Destination Connection ID a client's first Initial carries, and its own Source Connection
/// ID: "This Destination Connection ID MUST be at least 8 bytes in length" (RFC 9000 §7.2).
pub const connection_id_bytes: usize = 8;

/// colibri's receive pool for a connection, by default: one answer at its longest, rounded up to
/// the pool's blocks of 1,024 octets. colibri adds two blocks for each stream it can hold.
pub const pool_block_bytes: usize = 1024;
pub const receive_bytes_default: usize = (limits.answer_bytes_max + pool_block_bytes - 1) / pool_block_bytes * pool_block_bytes;

/// DoQ's error codes (RFC 9250 §4.3): DOQ_NO_ERROR for an idle close (§4.4), and
/// DOQ_REQUEST_CANCELLED for a request the lookup left (§4.3.1).
pub const doq_no_error: u64 = 0x0;
pub const doq_request_cancelled: u64 = 0x3;

/// The test server's (`io_quic_server.zig`): its Source Connection ID is this octet repeated.
pub const server_id_octet: u8 = 0x5e;

/// A second and a millisecond, in nanoseconds: chapulin's clock is Unix seconds, and a resumed
/// hello states a ticket's age in milliseconds (RFC 9846 §4.3.11.1).
pub const ns_per_second: u64 = 1_000_000_000;
pub const ns_per_millisecond: u64 = 1_000_000;

// The paths a consumer reached these limits by before they moved into the limits file. Each
// is an alias, and no limit of its own. They stay until the owner rules on them (docs/design.md
// §16 decision 56, §17 question 76).
pub const idle_timeout_ms = limits.idle_timeout_ms;
pub const datagram_receive_bytes = limits.datagram_receive_bytes;
pub const answer_bytes_max = limits.answer_bytes_max;
pub const params_bytes_max = limits.params_bytes_max;
pub const server_receive_blocks = limits.server_receive_blocks;
pub const server_receive_bytes = limits.server_receive_bytes;
pub const server_answer_bytes_max = limits.server_answer_bytes_max;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
