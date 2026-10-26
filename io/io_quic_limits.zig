//! The limits of `cocuyo_quic`, colibri under the engine's request interface (docs/design.md §24,
//! New limits; §16 decision 56). A module of its own, so its limits live apart from the engine's
//! `limits.zig`.
const std = @import("std");
const constants = @import("io_quic_constants.zig");
const cocuyo = @import("cocuyo");

/// The idle timeout a connection advertises (RFC 9000 §18.2, `max_idle_timeout`): thirty seconds.
/// The server's may be shorter, and the smaller holds (RFC 9250 §4.4). Chosen, not measured.
pub const idle_timeout_ms: u64 = 30_000;

/// The largest datagram a connection reads, which it advertises (RFC 9000 §18.2,
/// `max_udp_payload_size`): an Ethernet frame's payload, which the engine's datagram group holds
/// after rotor's prefix.
pub const datagram_receive_bytes: usize = 1500;

/// A DoQ answer at its longest, with its prefix (RFC 9250 §4.2). The engine reads a stream once all
/// of it has arrived, so a stream's receive window holds one whole.
pub const answer_bytes_max: usize = cocuyo.constants.tcp_prefix_bytes + cocuyo.limits.message_bytes_max;

/// What a connection's transport parameters take when written (RFC 9000 §18): far past the dozen
/// it sends.
pub const params_bytes_max: usize = 256;

/// The test server's (`io_quic_server.zig`): its receive pool, which holds the few queries a test
/// sends at once, and the longest answer it keeps, a datagram's worth after the prefix.
pub const server_receive_blocks: usize = 16;
pub const server_receive_bytes: usize = server_receive_blocks * constants.pool_block_bytes;
pub const server_answer_bytes_max: usize = cocuyo.constants.tcp_prefix_bytes + cocuyo.constants.udp_payload_bytes_default;

/// The longest transport parameters either side of `Plain` sends, and the longest ALPN token it
/// keeps (`io_quic_plain.zig`).
pub const plain_params_bytes_max: usize = 256;
pub const plain_alpn_bytes_max: usize = 16;

/// What one level of `Plain` holds of messages, both ways (`io_quic_plain.zig`): a hello at its
/// longest, with room over.
pub const plain_level_bytes_max: usize = 512;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
