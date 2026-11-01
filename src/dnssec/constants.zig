//! The protocol sizes of `dnssec` (CLAUDE.md non-negotiable 5).

/// The bits of the serial number space a signature's times live in (RFC 1982 §2, RFC 4034
/// §3.1.5), and half of it, past which a later time reads as an earlier one.
pub const serial_bits: u6 = 32;
pub const serial_half: u32 = 1 << (serial_bits - 1);

/// The fixed part of a record in the signed data: type and class, 16 bits each, the original TTL,
/// 32 bits, and the rdata length, 16 bits (RFC 4035 §5.3.2).
pub const record_fixed_bytes: usize = 10;
pub const record_class_offset: usize = 2;
pub const record_ttl_offset: usize = 4;
pub const record_length_offset: usize = 8;

/// The label a wildcard's owner begins with (RFC 4592 §2.1.1).
pub const wildcard_label = "*";

/// The key tag's sum: the rdata as 16-bit groups, the first octet of each the high one, then the
/// sum's carry above 16 bits added once (RFC 4034 Appendix B).
pub const key_tag_high_shift: u5 = 8;
pub const key_tag_carry_shift: u5 = 16;
pub const key_tag_mask: u32 = 0xffff;
