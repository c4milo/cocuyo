//! The sizes the engine's tests build their rig with. Exempt from the magic-numbers rule by
//! name, like every corpus; test-only.

/// A small engine: enough lookups for the many-in-flight scenario, a cache the same size, and
/// a group of a few buffers so the buffers run out under load.
pub const lookups = 64;
pub const cache_slots = 64;
pub const group_buffers = 16;

/// The scripted servers the rig configures: the twin's first two.
pub const servers = 2;

/// The lookups the many-in-flight scenario starts, and the rounds it gives them.
pub const many_lookups = 48;
pub const rounds_max = 4096;
pub const until_rounds_max = 512;

const rotor = @import("rotor");

/// How many events one tick of the rig may hand back.
pub const events_max = 32;

/// The wait a tick is given when the rig runs until a result: long enough for any timeout.
pub const wait_ns = 60 * 1_000_000_000;

/// The many-in-flight scenario's servers: lossy and slow, one of them saying NXDOMAIN now and
/// then, under a short timeout.
pub const lossy_scripts = [servers]rotor.server.Script{
    .{ .drop_per_256 = 64, .delay_ns_min = 1_000_000, .delay_ns_max = 50_000_000 },
    .{ .drop_per_256 = 128, .delay_ns_min = 1_000_000, .delay_ns_max = 20_000_000, .nxdomain_per_256 = 32 },
};
pub const lossy_timeout_ns = 200_000_000;
pub const lossy_step_ns = 1_000_000_000;

/// Room for a scenario's generated names, and how a result folds into the trace: the address's
/// last octet, shifted above the handle's index.
pub const name_text_bytes = 24;
pub const trace_code_shift = 32;

/// Every query truncated, which is what sends a lookup to the stream (RFC 7766 §5), and the
/// wait that carries a connection past the idle close.
pub const always = 256;
pub const tcp_idle_jump_ns = 11 * 1_000_000_000;

/// A stream scenario slow enough to outlast the idle close, under a timeout that outlasts it in
/// turn: the answer comes at `stream_delay_ns` over each of UDP and TCP.
pub const stream_delay_ns = 12 * 1_000_000_000;
pub const stream_timeout_ns = 25 * 1_000_000_000;

/// A send buffer shorter than any frame the twin's transport over TCP writes, the first of which
/// holds an 11-octet hello: every send goes short (docs/design.md §24, request rule 15).
pub const short_send_bytes = 4;

/// A connect that outlasts an idle wait cut short, under a timeout it does not reach: the
/// connection goes idle while it connects (request rules 14 and 16).
pub const idle_connect_ns = 1_000_000_000;
pub const short_idle_ns = 10_000_000;

/// A connect slower than the lookup's wait, which strands a lookup that has moved on by the
/// time the connection comes up.
pub const slow_connect_ns = 3 * 1_000_000_000;
pub const slow_connect_timeout_ns = 2 * 1_000_000_000;
/// What the next server takes: longer than the connect has left to run, so the lookup is still
/// waiting on it when the connection comes up, and shorter than its own wait.
pub const slow_answer_ns = 1_500_000_000;

/// The local address a socket is asked to bind to: the documentation range (RFC 5737).
pub const local_octets = [_]u8{ 192, 0, 2, 200 };
pub const unspecified_v4 = [_]u8{ 0, 0, 0, 0 };

/// A buffer size the twin's kernel grants, one it caps, and one it refuses outright, which is
/// the shape rotor measured on macOS.
pub const socket_bytes_granted = 64 * 1024;
pub const socket_bytes_capped = 1 << 24;
pub const socket_bytes_refused = 1 << 29;
pub const local_v6_octets = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{9};

/// A send buffer so small that every query goes out on a stream in several sends: the twin moves
/// no more than it a send.
pub const socket_send_bytes_short = 5;

/// A connection that can assemble only a small message, so an ordinary answer will not fit.
pub const tiny_message_bytes = 64;

/// A stream group of two buffers, so a chunk finds none and the multishot ends.
pub const tcp_group_buffers_small = 2;

/// A small engine whose group runs dry under its own lookups: more replies at once than buffers.
pub const small_lookups = 6;
pub const small_group_buffers = 2;

/// When a test makes a QUIC connection's own timer due: a millisecond on, before any lookup's
/// deadline.
pub const quic_timer_ns = 1_000_000;

/// The colibri servers one scripted server keeps for the engine's connections to it: the one open,
/// and the one a reopening makes. And the datagrams a colibri server sends at most in one go.
pub const quic_servers_per_side = 2;
pub const quic_pump_max = 64;

/// The client's datagrams a colibri server drops before it hears any: its first Initial and the
/// one colibri sends again after its first probe timeout.
pub const quic_datagrams_lost = 2;

/// Lookups cancelled in turn on one connection: past the 128 streams colibri holds at once.
pub const quic_cancelled_streams = 140;

/// A DoH connection's answer buffers in the tests over colibri's HTTP/3: fewer than the engine's
/// lookups, so some requests wait for one.
pub const doh_answers = 2;
