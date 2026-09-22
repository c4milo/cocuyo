//! The sizes, tags and ids the twin's scenario tests build their rig with. Exempt from the
//! magic-numbers rule by name, like every corpus; test-only.

/// A small loop, one group of a few buffers of a size that holds a reply after rotor's prefix.
pub const operations = 16;
pub const group_id = 0;
pub const group_buffers = 4;
pub const buffer_bytes = 2048;

/// The `user_data` each operation of a scenario carries.
pub const receive_tag = 1;
pub const send_tag = 2;
pub const timer_tag = 3;
pub const connect_tag = 4;

/// The ids the scenarios' queries carry, over UDP and over the stream.
pub const query_id = 0x4242;
pub const stream_query_id = 0x0707;

/// The trace scenario: how many datagrams it sends, the wait it gives each, and its script.
pub const trace_sends = 8;
pub const trace_wait_ns = 2000;
pub const trace_delay_ns_min = 100;
pub const trace_delay_ns_max = 900;
pub const trace_drop_per_256 = 64;

const types = @import("sim_types.zig");

/// The first scripted server's address, as the server tests spell it.
pub const server_address = types.Address.ipv4(.{ 192, 0, 2, 53 }, 53);

/// The id the server tests' queries carry, and the octet their client cookie is filled with.
pub const server_query_id = 0x1234;
pub const client_cookie_fill = 0xab;
