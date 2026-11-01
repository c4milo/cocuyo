//! The bounds of `dnssec` (CLAUDE.md non-negotiable 5), as docs/design.md §25 names them.

/// The NSEC3 iterations past which a denial reads as `insecure`, once its signature verified (RFC
/// 9276 §3.2). RFC 9276 Appendix A: a limit of 100 for this "is interoperable without significant
/// problems". The count of 2026-10-03 in §25 found 20 at most.
pub const nsec3_iterations_max: u16 = 100;

/// The NSEC3 hashes one proof computes: a closest encloser proof hashes one name for each label it
/// tries, and a wildcard one more. RFC 4035 §5.4 asks that the work be bounded. Chosen, not
/// measured: a name 30 labels below its zone fits.
pub const nsec3_hashes_per_message_max: usize = 32;

/// The keys one zone's set holds in the store, and that a DNSKEY set may hold to enter it. The
/// count of 2026-10-03 in docs/design.md §25 found 6 at most.
pub const zone_keys_max: usize = 8;

/// The RRSIGs tried for one RRset (RFC 4035 §5.4 asks that the work be bounded). Chosen, not
/// measured: a zone that rolls its keys signs with two, and a zone with two algorithms with two
/// more.
pub const signatures_per_rrset_max: usize = 4;

/// The keys tried for one RRSIG, when their tags collide: a tag "is not a unique identifier" (RFC
/// 4034 Appendix B). Chosen, not measured.
pub const keys_per_signature_max: usize = 2;

/// The verifications one message costs at most (RFC 4035 §5.4, RFC 4033 §12). A chain of
/// `cname_hops_max` links and its end take 9, and a denial three more. Chosen, not measured.
pub const verifications_per_message_max: usize = 16;

/// The octets of keys one store entry keeps (docs/design.md §25). The count of 2026-10-03 found
/// 1,824 at most, in a set of 6 keys.
pub const zone_keys_bytes_max: usize = 2048;

/// The trust anchors a store takes: more than one, as RFC 4035 §4.4 asks, for the root's keys while
/// one replaces another, and for a zone of the caller's own. Chosen, not measured.
pub const anchors_max: usize = 8;

/// The DS records read from one DS set, which the store keeps as its entry. The count of
/// 2026-10-03 in docs/design.md §25 found 3 at most.
pub const ds_records_max: usize = 8;

/// The DS and DNSKEY questions one walk asks (§25, walk rule 10). Chosen, not measured: a walk
/// asks two for each zone cut, and a name 15 cuts below its anchor fits.
pub const chain_questions_max: u8 = 32;

/// The walks one validator runs at once (§25 step 12). Chosen, not measured: a table of 64 lookups
/// for names of four zones the store does not hold yet. §17 question 95 asks the owner.
pub const walks_max: u8 = 4;

comptime {
    // A DS set enters the store as one entry.
    if (ds_records_max > zone_keys_max) @compileError("a DS set must fit a store entry");
}
