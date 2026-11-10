//! The time of day, as the caller reads it (docs/design.md §24, the wall clock; §25, Time).

/// The time of day at an instant of the caller's monotonic clock: `unix_seconds` holds at `now_ns`.
/// One value holds both, so the two cannot change places in a call (c4milo/cocuyo#65). No field
/// has a default, since a caller reads both clocks.
pub const Clock = struct {
    /// The wall clock, in seconds since the Unix epoch. A caller that corrects its clock passes a
    /// new value, so it may go backwards.
    unix_seconds: u64,
    /// The caller's monotonic clock at that instant, in nanoseconds. It never decreases.
    now_ns: u64,
};
