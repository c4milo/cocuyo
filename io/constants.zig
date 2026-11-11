//! The constants of the I/O engine that are no limit (docs/design.md §19 step 13): its defaults,
//! the layout of a `user_data` and of an operation's id, and the protocol sizes it reads. The limits of one
//! engine are in `limits.zig` (§16 decision 56).
const std = @import("std");
const limits = @import("limits.zig");
const core = @import("core");
const rotor = @import("rotor");

/// The lookups an engine holds in flight, when the caller says nothing.
pub const lookups_default: usize = 256;

/// The slots of the cache a caller with no number of its own hands an engine: a thousand, which
/// §18 measures at 2.9 MiB, and at 49% to 60% of a real log's questions answered with no packet.
/// The README and the examples declare this many. It is no default the engine takes: an engine
/// holds no cache memory, and has the cache it is handed the memory of, or none (docs/design.md
/// §19 step 13, the cache's memory; §16 decision 37).
pub const cache_slots_default: usize = 1024;

/// The high sixteen bits of every `user_data` the engine submits, so a caller sharing the loop
/// tells the engine's events from its own. One by default; a caller with several engines on
/// one loop gives each its own.
pub const tag_default: u16 = 1;

/// Where the tag sits in a `user_data`. The low 32 bits hold the operation's id, and the bits
/// between the two are zero (docs/design.md §26, The decision, point 5).
pub const tag_shift: u6 = 48;
pub const operation_id_mask: u64 = std.math.maxInt(u32);

/// Where the generation sits in an `OperationId`, above the slot in the low bits.
pub const operation_generation_shift: u5 = 24;
pub const operation_slot_mask: u32 = (1 << operation_generation_shift) - 1;

/// The buffers the datagram group holds. The octets of each buffer are `limits.buffer_bytes_max`.
/// The group's id is the one the loop reserves for it (rotor decision 29).
pub const group_buffers_default: usize = 64;

/// The options the engine provides its datagram group with: rotor's own, whose prefix before each
/// payload is 192 octets.
pub const group_options: rotor.datagram.GroupOptions = .{};

/// The TCP connections one engine keeps, when the caller says nothing. One: every lookup that
/// needs a stream to the same server pipelines onto it (RFC 7766 §6.2.1.1), and a caller that
/// asks several servers over TCP at once raises it. Each costs a message buffer.
pub const tcp_connections_default: usize = 1;

/// The request slots over DoH and DoQ for each lookup, when the caller says nothing: its current
/// request and one earlier try's (docs/design.md §24, request rule 3). The pool is shared, so a
/// lookup with no earlier request leaves a slot to one with two.
pub const requests_per_lookup_default: usize = 2;

/// The buffers the stream group holds. The octets of each buffer are `limits.tcp_chunk_bytes_max`.
pub const tcp_group_buffers_default: usize = 8;

/// How long a connection nobody is using is kept. Ten seconds, chosen and not measured, which is
/// short by the standard RFC 7766 §6.2.3 sets a client.
pub const tcp_idle_ns_default: u64 = 10_000_000_000;

/// Where a connection's incarnation sits in the origin's index of its connect and its receive, above
/// the connection's slot, so the event of an opening of the slot that is gone is told from the
/// current one's (docs/design.md §19 step 13, the stream's rule 2). A slot fits in the octet
/// below it.
pub const tcp_incarnation_shift: u6 = 8;
pub const tcp_slot_mask: usize = (1 << tcp_incarnation_shift) - 1;

/// A TLS record's header: its content type, two octets of legacy version and two of length
/// (RFC 9846 §5.1), and where the length sits.
pub const tls_record_header_bytes: usize = 5;
pub const tls_record_length_at: usize = 3;

/// What sealing adds to a record: its header, the inner content type and the AEAD's 16-octet tag
/// (RFC 9846 §5.2).
pub const tls_record_overhead_bytes: usize = tls_record_header_bytes + 1 + 16;

/// Where a QUIC connection's incarnation sits in the origin's index of its operations, above its
/// server's index, as a TCP connection's does above its slot. A server fits in the octet below.
pub const quic_incarnation_shift: u6 = 8;
pub const quic_server_mask: usize = (1 << quic_incarnation_shift) - 1;

/// How long a QUIC connection with no request on it is kept: TCP's ten seconds. RFC 9250 §5.5.2
/// names no value; this one is chosen, not measured (docs/design.md §24, request rule 9).
pub const quic_idle_ns_default = tcp_idle_ns_default;

/// The ALPN token of DoQ (RFC 9250 §4.1).
pub const quic_alpn_doq = "doq";

/// The port a DoH server's connection goes to when its template names none: "If the port
/// subcomponent is empty or not given, TCP port 443 ... is the default" (RFC 9110 §4.2.2), and
/// HTTP/3 goes to "the indicated port" over UDP (RFC 9114 §3.1).
pub const port_https_default: u16 = 443;

/// A second and a millisecond, in nanoseconds: chapulin's clock is Unix seconds, and a resumed
/// hello states a ticket's age in milliseconds (RFC 9846 §4.3.11.1).
pub const ns_per_second: u64 = 1_000_000_000;
pub const ns_per_millisecond: u64 = 1_000_000;

comptime {
    // The shifts are `u6`. Each check adds in `comptime_int` and subtracts nothing, so a wrong
    // shift reaches its message and does not overflow first.
    if (@as(comptime_int, quic_incarnation_shift) + 32 > @bitSizeOf(u64)) {
        @compileError("a QUIC connection's origin has no room for a thirty-two-bit incarnation");
    }
    if (limits.udp_payload_bytes_max < core.constants.udp_payload_bytes_default) {
        @compileError("a group buffer cannot hold the payload cocuyo advertises after rotor's prefix");
    }
    if (!@import("cache").Cache.slot_count_valid(cache_slots_default)) {
        @compileError("the cache size the README and the examples declare is one no cache takes");
    }
    // The chunk that ends one item can start the next, and the connection takes the whole chunk
    // first. So each buffer holds a chunk past its partial item (§19 step 13, the stream's rule
    // 11; §21, TLS rule 7).
    if (limits.tls_record_in_bytes_max < tls_record_header_bytes + limits.tls_record_body_bytes_max + limits.tcp_chunk_bytes_max) {
        @compileError("a TLS connection's record buffer has no room for a chunk past a record");
    }
    if (limits.tcp_frame_room_bytes_max < limits.tcp_chunk_bytes_max or limits.tls_frame_room_bytes_max < limits.tls_record_body_bytes_max) {
        @compileError("a frame has no room for what one take adds past its partial message");
    }
}

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
