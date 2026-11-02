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

/// NSEC3's one hash algorithm, SHA-1 (RFC 5155 §11), and its 160 bits as octets, which a hashed
/// owner label holds in 32 characters of base32hex (RFC 5155 §10.1).
pub const nsec3_hash_sha1: u8 = 1;
pub const nsec3_hash_bytes: usize = 20;

/// The room for the longest canonical rdata of a type whose names are lowered, which is NAPTR's: ORDER and
/// PREFERENCE, 16 bits each, three character-strings of 256 octets at most, and a name of 255
/// (RFC 3403 §4.1, RFC 1035 §3.3, §3.1). SIG and RRSIG are longer, and no RRSIG signs an RRset of
/// either (RFC 4035 §2.2).
pub const canonical_rdata_bytes: usize = 2 + 2 + 3 * (1 + 255) + 255;

/// The room for the longest DS digest of a type cocuyo knows: SHA-384's 48 octets (RFC 6605 §2). SHA-1 has 20
/// (RFC 4034 §5.1.4) and SHA-256 32 (RFC 4509 §2.1).
pub const digest_bytes: usize = 48;

/// The nanoseconds in a second, which turn a `now_ns` into the seconds a signature's dates count.
pub const ns_per_second: u64 = 1_000_000_000;

/// The DS digest types RFC 4509 §3 weighs against each other: SHA-1 (RFC 4034 Appendix A.2) and
/// SHA-256 (RFC 4509 §5).
pub const digest_sha1: u8 = 1;
pub const digest_sha256: u8 = 2;

/// The master file format's marks (RFC 1035 §5.1): a control entry begins with `$`, and an
/// absolute name ends with the label separator.
pub const control_mark: u8 = '$';
pub const label_separator: u8 = '.';

/// The bases of the integers and the digest in presentation form (RFC 4034 §2.2, §5.3).
pub const decimal_radix: u8 = 10;
pub const hex_radix: u8 = 16;
