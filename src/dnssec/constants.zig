//! The protocol sizes of `dnssec` (CLAUDE.md non-negotiable 5).

/// The bits of the serial number space a signature's times live in (RFC 1982 §2, RFC 4034
/// §3.1.5), and half of it, past which a later time reads as an earlier one.
pub const serial_bits: u6 = 32;
pub const serial_half: u32 = 1 << (serial_bits - 1);

/// The key tag's sum: the rdata as 16-bit groups, the first octet of each the high one, then the
/// sum's carry above 16 bits added once (RFC 4034 Appendix B).
pub const key_tag_high_shift: u5 = 8;
pub const key_tag_carry_shift: u5 = 16;
pub const key_tag_mask: u32 = 0xffff;
