//! The constants of the twin that are no limit (docs/design.md §19 step 13): rotor's shapes, the
//! addresses and the formats of its scripted servers, and its defaults. The limits of one
//! simulated loop and its network are in `limits.zig` (§16 decision 56).
const std = @import("std");
const core = @import("core");
const limits = @import("limits.zig");

/// The alignment rotor asks of a buffer ring and of the loop's memory, and the octets one ring
/// entry takes, so a caller's arrays are sized and aligned the same for the twin and for rotor.
///
/// The ring's alignment was 64 here until 2026-09-22, when rotor asks 64 KiB on both of its
/// backends. A twin that asks for less cannot catch a caller whose memory is not aligned enough,
/// and it did not: `IORING_REGISTER_PBUF_RING` refuses a ring that is not page-aligned, and the
/// engine met that refusal on Linux with every test on the twin green.
pub const buffer_ring_alignment: usize = 64 * 1024;
pub const buffer_ring_entry_bytes: usize = 16;
pub const memory_alignment: usize = 64;

/// The prefix rotor puts before a datagram's payload in a group buffer: a head, then room for
/// the addresses and the control data. 16 + 32 + 144.
pub const prefix_head_bytes: usize = 16;
pub const name_reserve_default: usize = 32;
pub const control_reserve_default: usize = 144;

/// The generation a handle starts at; zero is `Handle.none`.
pub const generation_first: u32 = 1;

/// The address the scripted servers sit at: the documentation range of RFC 5737, one octet per
/// server, on port 53.
pub const server_prefix = [_]u8{ 192, 0, 2 };
pub const server_octet_first: u8 = 53;
pub const server_port = core.constants.port_dns_default;

/// The port a scripted server also accepts streams on, so a `Server.tcp_port` of its own is a
/// thing a test can set (docs/design.md §19 step 11).
pub const server_tcp_port: u16 = 5353;

/// The address a client socket bound to no address gets, and the range of ports handed out.
pub const client_address = [_]u8{ 192, 0, 2, 1 };
pub const client_port_first: u16 = 40000;

/// The prefix of a scripted AAAA answer: the documentation prefix of RFC 3849, `2001:db8::`.
pub const answer_v6_prefix = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 };

/// The default TTL of a scripted answer.
pub const answer_ttl_seconds: u32 = 300;

/// The server cookie every scripted server hands out, sixteen octets as RFC 9018 §4 has it.
pub const server_cookie_bytes: usize = 16;

/// One second, spelled out because nothing under `src/` names `std.time` (CLAUDE.md
/// non-negotiable 4).
pub const ns_per_s: u64 = 1_000_000_000;

/// The octets of one draw the scripted server reads its decisions from: one chance per octet,
/// and the delay from the high half.
pub const dice_drop_shift: u6 = 0;
pub const dice_servfail_shift: u6 = 8;
pub const dice_nxdomain_shift: u6 = 16;
pub const dice_truncate_shift: u6 = 24;
pub const dice_delay_shift: u6 = 32;

/// The port a scripted server speaks the twin's TLS on, and nothing else: RFC 7858 §3.1 keeps it
/// for DNS over TLS alone.
pub const server_tls_port = core.constants.port_dns_tls_default;

/// The port a scripted server hears the twin's QUIC on over TCP, as a channel's TCP link writes it:
/// TCP's 443, which is where a DoH template that names no port goes (RFC 9110 §4.2.2).
pub const server_https_port: u16 = 443;

/// The twin's TLS records keep the shape of a real one (RFC 9846 §5.1): a content type, two
/// octets of legacy version, and a two-octet length, then that many octets unsealed.
pub const tls_record_header_bytes: usize = 5;
pub const tls_content_alert: u8 = 21;
pub const tls_content_handshake: u8 = 22;
pub const tls_content_application: u8 = 23;
pub const tls_legacy_version: u16 = 0x0303;
/// Where the version and the length sit in the header.
pub const tls_record_version_at: usize = 1;
pub const tls_record_length_at: usize = 3;

/// A `close_notify` alert: level warning, description `close_notify` (RFC 9846 §6).
pub const tls_close_notify = [_]u8{ 1, 0 };
/// An alert's level octet when it is fatal (RFC 9846 §6).
pub const tls_alert_fatal: u8 = 2;
/// The fatal alert the twin's session sends for a handshake it refuses: level fatal, description
/// `handshake_failure` (RFC 9846 §6, §6.2).
pub const tls_alert_handshake_failure = [_]u8{ tls_alert_fatal, 40 };
/// The description `record_overflow` (RFC 9846 §6.2), the one the engine names to a session.
pub const tls_alert_record_overflow: u8 = 22;

/// The port a scripted server speaks the twin's QUIC on: UDP's 853, which RFC 9250 §4.1.1 names
/// for DoQ. It is TCP's 853 for DoT as well, and the socket's kind tells them apart.
pub const server_quic_port = core.constants.port_dns_tls_default;

/// A QUIC item of the twin's: one octet naming what happened, four naming the stream it happened
/// on, and two giving the length of the octets after them (sim_quic.zig).
pub const quic_item_header_bytes: usize = 7;
pub const quic_item_stream_at: usize = 1;
pub const quic_item_length_at: usize = 5;

/// The distance between two of a client's bidirectional streams: 0, 4, 8, and on (RFC 9000 §2.1).
pub const quic_stream_step: u64 = 4;

/// The ALPN token a scripted server names when its script says to negotiate another protocol than
/// the one offered: HTTP/1.1's, which no connection of the engine's offers (RFC 7301 §6).
pub const quic_alpn_other = "http/1.1";

// rotor names these limits in its own `constants`, and the twin keeps rotor's surface. So code
// that reads `rotor.constants.wait_ns_max` reads the twin's limit on the twin (docs/design.md §16
// decision 56).
pub const operations_max = limits.operations_max;
pub const batch_max = limits.batch_max;
pub const wait_ns_max = limits.wait_ns_max;
pub const transfer_bytes_max = limits.transfer_bytes_max;
pub const drain_rounds_max = limits.drain_rounds_max;
pub const buffer_groups_max = limits.buffer_groups_max;
pub const buffers_per_group_max = limits.buffers_per_group_max;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
