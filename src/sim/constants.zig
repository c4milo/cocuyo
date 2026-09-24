//! The limits of the twin (docs/design.md §19 step 13): what one simulated loop and its network
//! hold. Every table is static and every walk is bounded by one of these.
const core = @import("core");

/// The most operations one loop holds in flight: its slot table.
pub const operations_max = 4096;

/// The most events waiting to be delivered by a tick. An operation ends in one final event and a
/// multishot delivers many, so this is above the slot count.
pub const events_pending_max = 8192;

/// The most sockets one network holds, datagram and stream together.
pub const sockets_max = 64;

/// The most scripted servers one network answers for: the servers a configuration may name.
pub const servers_max = core.constants.servers_max;

/// The most datagrams waiting to be delivered, and the room each holds: a reply is at most the
/// UDP payload cocuyo advertises.
pub const datagrams_pending_max = 256;
pub const datagram_bytes_max = core.constants.udp_payload_bytes_default;

/// The most stream connections open at once, and the octets each direction of one buffers.
pub const connections_max = 16;
pub const stream_bytes_max = 16384;

/// Buffer groups and the buffers each holds, as rotor bounds them.
pub const buffer_groups_max = 4;
pub const buffers_per_group_max = 256;

/// What a socket's kernel buffers may be sized to here, which is the shape rotor measured on
/// macOS: what is asked for up to the cap, the cap above it, and a refusal above the second
/// bound, because that kernel refuses rather than caps once a socket is already large.
pub const socket_buffer_bytes_cap = 1 << 20;
pub const socket_buffer_bytes_refuse_above = 1 << 28;

/// The alignment rotor asks of a buffer ring and of the loop's memory, and the octets one ring
/// entry takes, so a caller's arrays are sized and aligned the same for the twin and for rotor.
///
/// The ring's alignment was 64 here until 2026-09-22, when rotor asks 64 KiB on both of its
/// backends. A twin that asks for less cannot catch a caller whose memory is not aligned enough,
/// and it did not: `IORING_REGISTER_PBUF_RING` refuses a ring that is not page-aligned, and the
/// engine met that refusal on Linux with every test on the twin green.
pub const buffer_ring_alignment = 64 * 1024;
pub const buffer_ring_entry_bytes = 16;
pub const memory_alignment = 64;

/// The prefix rotor puts before a datagram's payload in a group buffer: a head, then room for
/// the addresses and the control data. 16 + 32 + 144.
pub const prefix_head_bytes = 16;
pub const name_reserve_default = 32;
pub const control_reserve_default = 144;

/// The longest a wait may be, and the longest an operation's own timeout may be: rotor's
/// bounds, kept so an operation valid there is valid here.
pub const wait_ns_max = 60 * ns_per_s;

/// How many ticks `drain` runs before it gives up on an operation that will not end.
pub const drain_rounds_max = 64;

/// The generation a handle starts at; zero is `Handle.none`.
pub const generation_first = 1;

/// The most octets one transfer moves, rotor's bound.
pub const transfer_bytes_max = 1 << 30;

/// The address the scripted servers sit at: the documentation range of RFC 5737, one octet per
/// server, on port 53.
pub const server_prefix = [_]u8{ 192, 0, 2 };
pub const server_octet_first = 53;
pub const server_port = core.constants.port_dns_default;

/// The port a scripted server also accepts streams on, so a `Server.tcp_port` of its own is a
/// thing a test can set (docs/design.md §19 step 11).
pub const server_tcp_port = 5353;

/// The address a client socket bound to no address gets, and the range of ports handed out.
pub const client_address = [_]u8{ 192, 0, 2, 1 };
pub const client_port_first = 40000;

/// The prefix of a scripted AAAA answer: the documentation prefix of RFC 3849, `2001:db8::`.
pub const answer_v6_prefix = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 };

/// The default TTL of a scripted answer.
pub const answer_ttl_seconds = 300;

/// The server cookie every scripted server hands out, sixteen octets as RFC 9018 §3 has it.
pub const server_cookie_bytes = 16;

/// The most octets one scripted stream reply is split into per delivery, at the least: a chunk
/// is drawn between this and what the buffer holds, so framing is exercised.
pub const stream_chunk_bytes_min = 1;

/// One second, spelled out because nothing under `src/` names `std.time` (CLAUDE.md
/// non-negotiable 4).
pub const ns_per_s = 1_000_000_000;

/// The octets of one draw the scripted server reads its decisions from: one chance per octet,
/// and the delay from the high half.
pub const dice_drop_shift = 0;
pub const dice_servfail_shift = 8;
pub const dice_nxdomain_shift = 16;
pub const dice_truncate_shift = 24;
pub const dice_delay_shift = 32;

/// The port a scripted server speaks the twin's TLS on, and nothing else: RFC 7858 §3.1 keeps it
/// for DNS over TLS alone.
pub const server_tls_port = core.constants.port_dns_tls_default;

/// The twin's TLS records keep the shape of a real one (RFC 9846 §5.1): a content type, two
/// octets of legacy version, and a two-octet length, then that many octets unsealed.
pub const tls_record_header_bytes = 5;
pub const tls_content_alert = 21;
pub const tls_content_handshake = 22;
pub const tls_content_application = 23;
pub const tls_legacy_version = 0x0303;
/// Where the version and the length sit in the header.
pub const tls_record_version_at = 1;
pub const tls_record_length_at = 3;

/// A `close_notify` alert: level warning, description `close_notify` (RFC 9846 §6).
pub const tls_close_notify = [_]u8{ 1, 0 };

/// The most the twin's TLS carries in one record: a framed query at its longest, or a framed
/// answer the size of the twin's largest datagram.
pub const tls_payload_bytes_max = core.constants.tcp_prefix_bytes + datagram_bytes_max;

/// What one call to the twin's session may make before the engine takes it out: one record at
/// its longest.
pub const tls_out_bytes_max = tls_record_header_bytes + tls_payload_bytes_max;
