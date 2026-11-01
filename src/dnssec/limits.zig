//! The bounds of `dnssec` (CLAUDE.md non-negotiable 5), as docs/design.md §25 names them.

/// The NSEC3 iterations past which a denial reads as `insecure`, once its signature verified (RFC
/// 9276 §3.2). RFC 9276 Appendix A: a limit of 100 for this "is interoperable without significant
/// problems". The count of 2026-10-03 in §25 found 20 at most.
pub const nsec3_iterations_max: u16 = 100;

/// The NSEC3 hashes one proof computes: a closest encloser proof hashes one name for each label it
/// tries, and a wildcard one more. RFC 4035 §5.4 asks that the work be bounded. Chosen, not
/// measured: a name 30 labels below its zone fits.
pub const nsec3_hashes_per_message_max: usize = 32;
