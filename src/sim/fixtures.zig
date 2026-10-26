//! The sizes, tags and ids the twin's scenario tests build their rig with. Exempt from the
//! magic-numbers rule by name, like every corpus; test-only.

/// A small loop, one group of a few buffers of a size that holds a reply after rotor's prefix.
pub const operations: usize = 16;
pub const group_id: u16 = 0;
pub const group_buffers: usize = 4;
pub const buffer_bytes: usize = 2048;

/// The `user_data` each operation of a scenario carries.
pub const receive_tag: u64 = 1;
pub const send_tag: u64 = 2;
pub const timer_tag: u64 = 3;
pub const connect_tag: u64 = 4;
/// A timer that fills the one event a tick has room for, so another waits in the loop.
pub const filler_tag: u64 = 5;

/// How long a scenario waits on a send to a peer that stopped reading: a second, with nothing due.
pub const stall_wait_ns: u64 = 1_000_000_000;

/// The ids the scenarios' queries carry, over UDP and over the stream.
pub const query_id: u16 = 0x4242;
pub const stream_query_id: u16 = 0x0707;

/// The trace scenario: how many datagrams it sends, the wait it gives each, and its script.
pub const trace_sends: usize = 8;
pub const trace_wait_ns: u64 = 2000;
pub const trace_delay_ns_min: u64 = 100;
pub const trace_delay_ns_max: u64 = 900;
pub const trace_drop_per_256: usize = 64;

const types = @import("sim_types.zig");

/// The first scripted server's address, as the server tests spell it.
pub const server_address = types.Address.ipv4(.{ 192, 0, 2, 53 }, 53);

/// The id the server tests' queries carry, and the octet their client cookie is filled with.
pub const server_query_id: u16 = 0x1234;
pub const client_cookie_fill: u8 = 0xab;

/// When the echo responder's deadline comes, and how long its echo takes: the deadline first, so
/// the twin wakes it before anything is due.
pub const echo_deadline_ns: u64 = 500;
pub const echo_delay_ns: u64 = 1000;
