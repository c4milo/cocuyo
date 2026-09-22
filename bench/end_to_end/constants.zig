//! The numbers the end-to-end comparison runs with (docs/design.md §19 step 15). Exempt from the
//! magic-numbers rule by name, like every corpus.
const cocuyo = @import("cocuyo");

/// How many lookups are kept in flight in each run, the most of them, and how many lookups each
/// run makes in all.
pub const in_flight_counts = [_]u32{ 1, 16, 128 };
pub const in_flight_max = 128;
pub const lookups_total = 20_000;

/// The key table cocuyo's resolver asks for: a power of two at twice the slots.
pub const keys_per_slot = 2;

/// The responder: where it listens, what it answers, and the TTL it gives.
pub const loopback_v4 = [_]u8{ 127, 0, 0, 1 };
pub const answer_v4 = [_]u8{ 192, 0, 2, 1 };
pub const answer_ttl_seconds = 300;
pub const datagram_bytes_max = cocuyo.constants.udp_payload_bytes_default;

/// The A record the responder appends: a pointer to the question's name at offset 12, type A,
/// class IN, then the TTL and the four octets.
pub const record_head = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
pub const record_rdlength = [_]u8{ 0x00, 0x04 };

/// The header's second octet with QR set, and the third with RA: the reply's flags are the
/// query's with those two on and the rcode zero.
pub const flag_response_octet = 0x80;
pub const flag_recursion_available_octet = 0x80;
pub const rcode_clear_mask = 0xf0;

/// The room a name takes as text: `h20000.example.` and its terminator.
pub const name_bytes = 32;

/// The wait the loop hands `poll(2)` at most, and the units the clock is converted with.
pub const poll_timeout_ms_max = 1000;
pub const ns_per_ms = 1_000_000;
pub const ns_per_us = 1_000;
pub const ns_per_s = 1_000_000_000;

/// The percentile the table reports beside the median.
pub const percentile = 99;
pub const percent = 100;

/// The engine over rotor: the buffers of its datagram group, deep enough for every lookup in
/// flight to have a reply waiting; what the loop is told to hold beyond the engine's operations;
/// how many events one tick may hand back; the longest one tick waits; and the seed the engine
/// draws its ids and ports from, fixed so a run is a run.
pub const group_buffers = 256;
pub const events_max = 64;
pub const tick_wait_ns_max = 1_000_000_000;
pub const engine_seed = 0x5eed_c0c0;

/// The runs the comparison's own tests make: small, so they end in a moment.
pub const test_in_flight = 4;
pub const test_total = 20;

/// What one lookup over the loopback may take before the run has stopped measuring the stacks
/// and started measuring a wait: a quarter of `tick_wait_ns_max`. A driver that leaves nothing
/// in flight waits that cap out once per lookup, which is what this catches; a lookup that is
/// answered takes under a millisecond.
pub const latency_ns_max = 250 * ns_per_ms;

/// The run that holds one lookup at a time, which is the first row of the table and the shape a
/// driver's own mistake shows up in: with one in flight there is nothing else to keep the loop
/// busy, so a lookup that is not started until the tick under it has waited out shows as a
/// latency of a whole `tick_wait_ns_max`.
pub const test_total_one = 5;

/// What the responder's queue holds: the c-ares side and cocuyo's each send one datagram per
/// lookup in flight, so this is the most that can be waiting.
pub const socket_buffer_bytes = 4 * 1024 * 1024;
