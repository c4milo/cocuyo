//! The sizes the engine's tests build their rig with. Exempt from the magic-numbers rule by
//! name, like every corpus; test-only.

/// A small engine: enough lookups for the many-in-flight scenario, and a group of a few buffers
/// so the buffers run out under load. A rig hands its engine a cache of as many slots as the
/// engine has lookups (`io_sim_test.zig`).
pub const lookups: usize = 64;
pub const group_buffers: usize = 16;

/// The scripted servers the rig configures: the twin's first two.
pub const servers: usize = 2;

/// The lookups the many-in-flight scenario starts, and the rounds it gives them.
pub const many_lookups: usize = 48;
pub const rounds_max: usize = 4096;
pub const until_rounds_max: usize = 512;

const rotor = @import("rotor");

/// How many events one tick of the rig may hand back.
pub const events_max: usize = 32;

/// The wait a tick is given when the rig runs until a result: long enough for any timeout.
pub const wait_ns: u64 = 60 * 1_000_000_000;

/// The many-in-flight scenario's servers: lossy and slow, one of them saying NXDOMAIN now and
/// then, under a short timeout.
pub const lossy_scripts = [servers]rotor.server.Script{
    .{ .drop_per_256 = 64, .delay_ns_min = 1_000_000, .delay_ns_max = 50_000_000 },
    .{ .drop_per_256 = 128, .delay_ns_min = 1_000_000, .delay_ns_max = 20_000_000, .nxdomain_per_256 = 32 },
};
pub const lossy_timeout_ns: u64 = 200_000_000;
pub const lossy_step_ns: u64 = 1_000_000_000;

/// Room for a scenario's generated names, and how a result folds into the trace: the address's
/// last octet, shifted above the handle's index.
pub const name_text_bytes: usize = 24;
pub const trace_code_shift: u6 = 32;

/// Every query truncated, which is what sends a lookup to the stream (RFC 7766 §5), and the
/// wait that carries a connection past the idle close.
pub const always: usize = 256;
pub const tcp_idle_jump_ns: u64 = 11 * 1_000_000_000;

/// A stream scenario slow enough to outlast the idle close, under a timeout that outlasts it in
/// turn: the answer comes at `stream_delay_ns` over each of UDP and TCP. A configured wait may
/// not pass the cap, so each scenario raises the cap to the timeout, past its 5-second default
/// (docs/design.md §5).
pub const stream_delay_ns: u64 = 12 * 1_000_000_000;
pub const stream_timeout_ns: u64 = 25 * 1_000_000_000;

/// A send buffer shorter than any frame the twin's transport over TCP writes, the first of which
/// holds an 11-octet hello: every send goes short (docs/design.md §24, request rule 15).
pub const short_send_bytes: usize = 4;

/// A connect that outlasts an idle wait cut short, under a timeout it does not reach: the
/// connection goes idle while it connects (request rules 14 and 16).
pub const idle_connect_ns: u64 = 1_000_000_000;
pub const short_idle_ns: u64 = 10_000_000;

/// A connect slower than the lookup's wait, which strands a lookup that has moved on by the
/// time the connection comes up.
pub const slow_connect_ns: u64 = 3 * 1_000_000_000;
pub const slow_connect_timeout_ns: u64 = 2 * 1_000_000_000;
/// What the next server takes: longer than the connect has left to run, so the lookup is still
/// waiting on it when the connection comes up, and shorter than its own wait.
pub const slow_answer_ns: u64 = 1_500_000_000;
/// A connect that hangs past each wait of a lookup, and past the idle close of a connection that a
/// lookup left (docs/design.md §19 step 13, the stream's rule 12).
pub const hung_connect_ns: u64 = 30 * 1_000_000_000;
/// Two connection slots: one that is pending while the other is free or connects (the same rule).
pub const tcp_slots_pair: usize = 2;

/// A server whose each reply takes a second: its connect, each step of its handshake and each
/// answer. So a refused connection begins to close a second after its connect (docs/design.md §16
/// decision 49).
pub const slow_step_ns: u64 = 1_000_000_000;
/// Half a slow step. A test drives the engine this long before an instant that it must not reach
/// yet. It is less than a slow step, so no reply of a slow server comes in that time.
pub const half_step_ns: u64 = 500_000_000;

/// The local address a socket is asked to bind to: the documentation range (RFC 5737).
pub const local_octets = [_]u8{ 192, 0, 2, 200 };
pub const unspecified_v4 = [_]u8{ 0, 0, 0, 0 };

/// A buffer size the twin's kernel grants, one it caps, and one it refuses outright, which is
/// the shape rotor measured on macOS.
pub const socket_bytes_granted: usize = 64 * 1024;
pub const socket_bytes_capped: usize = 1 << 24;
pub const socket_bytes_refused: usize = 1 << 29;
pub const local_v6_octets = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{9};

/// A send buffer so small that every query goes out on a stream in several sends: the twin moves
/// no more than it a send.
pub const socket_send_bytes_short: usize = 5;

/// A connection that can assemble only a small message, so an ordinary answer will not fit.
pub const tiny_message_bytes: usize = 64;

/// A name of 255 octets in wire form, the longest (RFC 1035 §2.3.4): three labels of 63 letters
/// and one of 61, each with its length octet, and the root's.
pub const longest_name_text = ("x" ** 63 ++ ".") ** 3 ++ "x" ** 61 ++ ".";

/// The seed of the first of the rigs that ask it.
pub const longest_name_seed: u64 = 90;

/// Names whose answer from a scripted server that sends no cookie is exactly `tiny_message_bytes`
/// long, and one octet longer: 12 of header, the name and 4 of question, 16 of A record and 11 of
/// OPT record are 43 and the name, which is 21 octets in wire form, and 22.
pub const tiny_name_fits = "aaaaaaaaaaa.example.";
pub const tiny_name_over = "aaaaaaaaaaaa.example.";

/// The longest message whose length and the two octets of its prefix still sum within sixteen
/// bits: 65533 and 2 are 65535 (RFC 1035 §4.2.2). One octet more overflowed the sum.
pub const message_bytes_unsummed: usize = 65533;

/// Lookups on one connection when it fails: one whose query is being sent, one whose waits.
pub const queued_lookups: usize = 2;

/// A stream group of two buffers, so a chunk finds none and the multishot ends.
pub const tcp_group_buffers_small: usize = 2;

/// A small engine whose group runs dry under its own lookups: more replies at once than buffers.
pub const small_lookups: usize = 6;
pub const small_group_buffers: usize = 2;

/// When a test makes a QUIC connection's own timer due: a millisecond on, before any lookup's
/// deadline.
pub const quic_timer_ns: u64 = 1_000_000;

/// A wait that lets the engine's timer fire for a step a channel of the twin's says at once
/// (`io_channel_test.zig`).
pub const channel_read_ns: u64 = 1_000_000;

/// The colibri servers one scripted server keeps for the engine's connections to it: the one open,
/// and the one a reopening makes. And the datagrams a colibri server sends at most in one go.
pub const quic_servers_per_side: usize = 2;
pub const quic_pump_max: usize = 64;

/// The client's datagrams a colibri server drops before it hears any: its first Initial and the
/// one colibri sends again after its first probe timeout.
pub const quic_datagrams_lost: usize = 2;

/// Lookups cancelled in turn on one connection: past the 128 streams colibri holds at once.
pub const quic_cancelled_streams: usize = 140;

/// A DoH connection's answer buffers in the tests over colibri's HTTP/3: fewer than the engine's
/// lookups, so some requests wait for one.
pub const doh_answers: usize = 2;

/// The cache's memory in the tests of `io_lifecycle_cache_test.zig`: a cache of two names, which
/// a third evicts one of, and the least there is, one slot and the two keys it takes.
pub const cache_two_slots: usize = 2;
pub const cache_least_slots: usize = 1;
pub const cache_least_keys: usize = 2;

/// A TTL past the default cap of an hour, which a scripted server gives its answers so that the
/// cap shows; a cap under it and one over it, which a configuration sets; and the two caps a
/// configuration and the one that replaces it at a `reinit` set.
pub const long_ttl_seconds: u32 = 7200;
pub const hour_seconds: u32 = 3600;
pub const cap_under_seconds: u32 = 60;
pub const cap_over_seconds: u32 = 86_400;
pub const cap_before_seconds: u32 = 600;
pub const cap_after_seconds: u32 = 30;

/// What a test writes over memory the engine was told to let go of, to see it left alone.
pub const memory_mark: u8 = 0xa5;

/// The body of a full TLS record under AES-GCM: 2^14 octets of plaintext, the inner content type
/// and the AEAD's 16-octet tag (RFC 9846 §5.2). A server that sends a long answer sends these.
pub const full_record_body_bytes: usize = (1 << 14) + 1 + 16;

/// The most plaintext a TLS record carries: 2^14 octets (RFC 9846 §5.1).
pub const record_plaintext_bytes_max: usize = 1 << 14;

/// Records a server sends back to back in a test: the first ends in the chunk that starts the
/// second.
pub const records_back_to_back: usize = 2;

/// The body of a record after a long one. It is longer than the part of it that comes with the
/// end of the long one. Its length is another, so the two headers differ.
pub const short_record_body_bytes: usize = 4000;

/// The octets of the next message that come in the same chunk as the end of a message. Then the
/// length its prefix says, shorter than the first message, so the two prefixes differ.
pub const next_message_octets: usize = 3;
pub const next_message_bytes: u16 = 32;

/// The seed whose twin hands a message of `tiny_message_bytes`, its prefix and
/// `next_message_octets` to the tiny engine as one chunk.
pub const one_chunk_seed: u64 = 36;

/// A wait short enough that seven servers that are down cost the twin's clock little, one try
/// each (`io_sim_servers_test.zig`).
pub const down_server_timeout_ns: u64 = 1_000_000_000;

/// A jump past the least time a cache keeps a resolution failure, 1 s (RFC 9520 §3.2), so the
/// entry has expired after it.
pub const failure_expiry_jump_ns: u64 = 2 * 1_000_000_000;
