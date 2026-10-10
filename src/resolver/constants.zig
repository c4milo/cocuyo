//! The limits this module holds. Everything the codec and the types share lives in
//! `core/constants.zig`; these are the table's own.
const core = @import("core");

/// The key table holds at least this many entries per slot. A load factor of one half is where
/// linear probing still finds an entry in a step or two, and the table is sized by the caller, so
/// the floor is checked rather than assumed (docs/design.md §11).
pub const keys_per_slot_min = 2;

/// The transactions a lookup draws for one name on one server in one pass: the query, the
/// retry without EDNS0 after FORMERR (RFC 6891 §6.2.2) and the retry with the server cookie
/// after BADCOOKIE (RFC 7873 §5.3), which is the server's once, over UDP or over a stream. It
/// bounds a transaction's `number` (docs/design.md §22).
pub const transactions_per_server_max = 3;

/// How long queries to a server carry no COOKIE option once it answered a client cookie without
/// one, having given no server cookie: five minutes, the period RFC 9018 §3 gives as an example
/// ("for a certain period (for example, five minutes)"). After it, a fresh client cookie again
/// (docs/design.md §19 step 10). Spelled in nanoseconds, as `core/constants.zig` says why:
/// 5 * 60 * 1_000_000_000.
pub const cookie_silence_ns = 300_000_000_000;

/// A server's wait, once it has been measured, is its average latency times this: 5, c-ares's,
/// read from its features page, not measured (docs/design.md §5).
pub const latency_wait_multiplier = 5;

/// The samples a server needs since its table was built before its wait comes from them, and the
/// samples a window needs before the wait reads it: 3, c-ares's, read from its features page, not
/// measured. Until then the server waits `Config.timeout_ns` (docs/design.md §5).
pub const latency_samples_min = 3;

/// The span of the shortest of the five windows a server's samples are kept in: a minute,
/// c-ares's, read from its features page, not measured (docs/design.md §5). 60 * 1_000_000_000.
pub const latency_window_minute_ns = 60_000_000_000;
/// The span of the second window: fifteen minutes, c-ares's, read from its features page, not
/// measured (docs/design.md §5). 15 * 60 * 1_000_000_000.
pub const latency_window_quarter_hour_ns = 900_000_000_000;
/// The span of the third window: an hour, c-ares's, read from its features page, not measured
/// (docs/design.md §5). 60 * 60 * 1_000_000_000.
pub const latency_window_hour_ns = 3_600_000_000_000;
/// The span of the fourth window: a day, c-ares's, read from its features page, not measured
/// (docs/design.md §5). The fifth has no span. 24 * 60 * 60 * 1_000_000_000.
pub const latency_window_day_ns = 86_400_000_000_000;

/// Every window's span, shortest first, which is the order the wait reads them in. The fifth,
/// null, has no span: it holds every sample since the table was built.
pub const latency_window_spans_ns = [_]?u64{
    latency_window_minute_ns,
    latency_window_quarter_hour_ns,
    latency_window_hour_ns,
    latency_window_day_ns,
    null,
};
pub const latency_windows = latency_window_spans_ns.len;

comptime {
    // Two entries per slot, at the largest table, must still be a count a power of two can cover.
    if (core.constants.lookup_slots_max * keys_per_slot_min > 1 << 16) {
        @compileError("the key table cannot be indexed by a sixteen-bit slot");
    }
    // The wait reads the windows shortest first, and the last holds every sample.
    for (latency_window_spans_ns[1 .. latency_windows - 1], 0..) |span, index| {
        if (span.? <= latency_window_spans_ns[index].?) @compileError("the windows are out of order");
    }
    if (latency_window_spans_ns[latency_windows - 1] != null) @compileError("no window keeps every sample");
}
