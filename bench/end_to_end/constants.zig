//! The numbers the end-to-end comparison runs with (docs/design.md §19 step 15). Exempt from the
//! magic-numbers rule by name, like every corpus.
const cocuyo = @import("cocuyo");

/// The loads the rows offer, in lookups a second, each lookup sent when it is due whether or not
/// the stack has answered (`schedule.zig`). Chosen against what the machine of docs/design.md §11
/// measured on 2026-09-22 with a number of lookups kept in flight: one, cocuyo 45,199 a second
/// and c-ares 36,304; sixteen, 110,194 and 87,306; 128, 122,089 and 82,554. 10,000 is under both
/// stacks one at a time, 40,000 over c-ares's one at a time, 80,000 under both at sixteen, and
/// 160,000 over both at 128, so its row gives the most each can do.
pub const rates = [_]u32{ 10_000, 40_000, 80_000, 160_000 };
/// The most lookups out at once, and how many lookups each row makes in all.
pub const in_flight_max = 128;
pub const lookups_total = 20_000;
/// Lookups run before the first row and not measured, which bring the responder and the
/// cores up to speed. The first run in a process spent its first 200 lookups at one in flight at
/// about 95 microseconds, against 22 after them, measured on 2026-09-26 on the machine of
/// docs/design.md §11: whether or not the engine's memory was touched first, and not on a second
/// run in the same process. So the warm-up was the process's, and fell on whichever stack ran
/// first: cocuyo, in every row until then (c4milo/cocuyo#5). Ten times those 200.
pub const warm_up_lookups = 2_000;

/// The responder: where it listens, what it answers, and the TTL it gives.
pub const loopback_v4 = [_]u8{ 127, 0, 0, 1 };
pub const answer_v4 = [_]u8{ 192, 0, 2, 1 };
pub const answer_ttl_seconds = 300;
pub const datagram_bytes_max = cocuyo.constants.udp_payload_bytes_default;

/// The A record the responder appends: a pointer to the question's name at offset 12, type A,
/// class IN, then the TTL and the four octets.
pub const record_head = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
pub const record_rdlength = [_]u8{ 0x00, 0x04 };

/// The room a name takes as text: `h20000.example.` and its terminator.
pub const name_bytes = 32;

/// The units the clock is converted with.
pub const ns_per_ms = 1_000_000;
pub const ns_per_us = 1_000;
pub const ns_per_s = 1_000_000_000;

/// The latencies the table reports, in thousandths of a row's lookups sorted: the median, the
/// 99th and the 99.9th percentile. 20,000 lookups put the 99.9th at the twentieth slowest.
pub const permille_median = 500;
pub const permille_p99 = 990;
pub const permille_p999 = 999;
pub const permille = 1000;

/// The names the row of cache hits asks in turn: half the 129 slots of the engine's cache here,
/// so each one it asked stays, and far fewer than a row's lookups, so every name is asked again
/// hundreds of times.
pub const hit_names = 64;

/// The kernel's counts are printed per lookup with two decimals.
pub const hundredths = 100;

/// The engine over rotor: the buffers of its datagram group, deep enough for every lookup in
/// flight to have a reply waiting; what the loop is told to hold beyond the engine's operations;
/// how many events one tick may hand back; the longest one tick waits; and the seed the engine
/// draws its ids and ports from, fixed so a run is a run.
pub const group_buffers = 256;
pub const events_max = 64;
pub const tick_wait_ns_max = 1_000_000_000;
pub const engine_seed = 0x5eed_c0c0;

/// The runs the comparison's own tests make: small, so they end in a moment, and one lookup a
/// millisecond, so each is answered long before the next is due.
pub const test_in_flight = 4;
pub const test_total = 20;
pub const test_period_ns = ns_per_ms;
/// The names the tests of cache hits repeat: fewer than a test's lookups, so each is asked again.
pub const test_hit_names = 4;
/// The exchanges the test of the responder's own process makes: enough that the two calls each
/// one costs stand clear of whatever else the process does meanwhile.
pub const test_exchanges = 100;

/// What one lookup over the loopback may take before the run has stopped measuring the stacks
/// and started measuring a wait: a quarter of `tick_wait_ns_max`. A loop that waits past a due
/// time with nothing in flight waits that cap out, which is what this catches; a lookup that is
/// answered takes under a millisecond.
pub const latency_ns_max = 250 * ns_per_ms;

/// The longest the c-ares side waits for its queue to empty before it gives the row up. c-ares
/// is driven by its own event thread, and that thread has been seen parked in `kevent` with a
/// query still queued and no timer armed for it, on the loopback at 128 in flight; an unbounded
/// `ares_queue_wait_empty` then never returns. A bounded one ends the row and says so, which is
/// a measurement that failed rather than a run that hangs.
pub const cares_wait_ms_max = 60_000;

/// How often a waiting responder looks whether the process that started it is still there, so
/// that one left behind by a test that crashed exits within a tenth of a second.
pub const responder_poll_ms = 100;
/// How long `start` waits for the responder to reach its receive loop before giving it up.
pub const responder_start_ns_max = 10 * ns_per_s;
pub const ms_per_s = 1_000;
pub const us_per_ms = 1_000;

/// What the responder's queue holds: the c-ares side and cocuyo's each send one datagram per
/// lookup in flight, so this is the most that can be waiting.
pub const socket_buffer_bytes = 4 * 1024 * 1024;
