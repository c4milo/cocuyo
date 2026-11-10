//! The time of day, as the caller reads it (docs/design.md §24, the wall clock; §25, Time).

/// Two readings of one instant: `unix_seconds` holds at `monotonic_ns`. std's `Io.Timestamp` holds
/// one reading, of one clock. One value holds both here, so the two cannot change places in a
/// call (c4milo/cocuyo#65). No field has a default, since a caller reads both clocks.
pub const Timestamp = struct {
    /// The wall clock, in seconds since the Unix epoch. A caller that corrects its clock passes a
    /// new value, so it may go backwards.
    unix_seconds: u64,
    /// The caller's monotonic clock at that instant, in nanoseconds: the `now_ns` of each entry
    /// point. It never decreases.
    monotonic_ns: u64,
};
