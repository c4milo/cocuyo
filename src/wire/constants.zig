//! Every number the wire format fixes: the offsets of the header fields, the flag bits, the
//! response codes, and the two bits that tell a label from a compression pointer. Each is named
//! here and never written at the use site (CLAUDE.md non-negotiable 5), with the RFC section that
//! fixes it.
const std = @import("std");

/// Two octets, the width of every count and every integer in the header (RFC 1035 §4.1.1).
pub const u16_bytes = @sizeOf(u16);

/// Four octets, the width of a TTL and of the OPT record's flag field (RFC 1035 §4.1.3).
pub const u32_bytes = @sizeOf(u32);

/// The bits in an octet, so a shift by a whole octet names what it shifts by.
pub const octet_bits = @bitSizeOf(u8);

// The header, RFC 1035 §4.1.1: six two-octet fields in this order.
pub const header_id_offset = 0;
pub const header_flags_offset = 2;
pub const header_qdcount_offset = 4;
pub const header_ancount_offset = 6;
pub const header_nscount_offset = 8;
pub const header_arcount_offset = 10;

// A record's fixed part after the owner name, RFC 1035 §4.1.3: type, class, TTL, rdlength.
pub const record_kind_offset = 0;
pub const record_class_offset = 2;
pub const record_ttl_offset = 4;
pub const record_rdlength_offset = 8;

/// An SOA's rdata after its two names: SERIAL, REFRESH, RETRY, EXPIRE and MINIMUM, four octets
/// each (RFC 1035 §3.3.13). MINIMUM is the last, and is the negative-caching TTL (RFC 2308 §5).
pub const soa_fixed_bytes = 20;
pub const soa_minimum_offset = 16;
pub const soa_refresh_offset = 4;
pub const soa_retry_offset = 8;
pub const soa_expire_offset = 12;

/// MX: a 16-bit preference, then the exchange name (RFC 1035 §3.3.9).
pub const mx_fixed_bytes = 2;

/// SRV: priority, weight and port, 16 bits each, then the target name (RFC 2782).
pub const srv_fixed_bytes = 6;
pub const srv_weight_offset = 2;
pub const srv_port_offset = 4;

/// NAPTR: order and preference, 16 bits each, then three character-strings and the replacement
/// name (RFC 3403 §4.1).
pub const naptr_fixed_bytes = 4;
pub const naptr_preference_offset = 2;

/// SIG: type covered (16), algorithm (8), labels (8), original TTL (32), expiration (32),
/// inception (32) and key tag (16), then the signer's name and the signature (RFC 2535 §4.1).
pub const sig_fixed_bytes = 18;
pub const sig_algorithm_offset = 2;
pub const sig_labels_offset = 3;
pub const sig_original_ttl_offset = 4;
pub const sig_expiration_offset = 8;
pub const sig_inception_offset = 12;
pub const sig_key_tag_offset = 16;

/// SVCB and HTTPS: a 16-bit priority, the uncompressed target name, then parameters of a 16-bit
/// key, a 16-bit length and a value (RFC 9460 §2.2).
pub const svcb_fixed_bytes = 2;
pub const svcb_param_fixed_bytes = 4;
pub const svcb_param_length_offset = 2;
/// The parameter keys RFC 9460 §7 defines, whose values have a format a client checks (§2.2).
pub const svcb_key_mandatory = 0;
pub const svcb_key_alpn = 1;
pub const svcb_key_no_default_alpn = 2;
pub const svcb_key_port = 3;
pub const svcb_key_ipv4hint = 4;
pub const svcb_key_ech = 5;
pub const svcb_key_ipv6hint = 6;

/// TLSA: certificate usage, selector and matching type, one octet each, then the association
/// data (RFC 6698 §2.1).
pub const tlsa_fixed_bytes = 3;
pub const tlsa_selector_offset = 1;
pub const tlsa_matching_type_offset = 2;

/// URI: priority and weight, 16 bits each, then the target, which must not be empty
/// (RFC 7553 §4.5).
pub const uri_fixed_bytes = 4;
pub const uri_weight_offset = 2;

/// CAA: flags and a tag length, one octet each, then the tag, at least one octet, then the
/// value (RFC 8659 §4.1).
pub const caa_fixed_bytes = 2;
pub const caa_tag_length_offset = 1;
pub const caa_tag_bytes_min = 1;
/// The issuer-critical flag, bit 0 in RFC 1035's numbering, which is the high bit (RFC 8659 §4.1).
pub const caa_flag_critical = 0x80;

/// A `<character-string>`: one length octet, then at most that many octets (RFC 1035 §3.3).
pub const character_string_bytes_max = 255;

/// An OPT option: a 16-bit code and a 16-bit length, then the data (RFC 6891 §6.1.2).
pub const opt_option_fixed_bytes = 4;
pub const opt_option_length_offset = 2;

/// The EDNS0 options cocuyo reads, by the code IANA assigned each: the name server's identifier
/// (RFC 5001 §2.3), the client subnet (RFC 7871 §6), the padding (RFC 7830 §3) and the extended
/// error (RFC 8914 §2). The state machine acts on the cookie alone; the rest are read for the
/// caller (docs/design.md §19 step 10).
pub const nsid_option_code = 3;
pub const client_subnet_option_code = 8;
pub const padding_option_code = 12;
pub const extended_error_option_code = 15;

/// The client subnet option's fixed part: the family and the two prefix lengths, before the
/// address (RFC 7871 §6), and where each sits.
pub const client_subnet_fixed_bytes = 4;
pub const client_subnet_source_offset = 2;
pub const client_subnet_scope_offset = 3;

/// The two families RFC 7871 §6 defines a format for, by their IANA Address Family Number.
pub const client_subnet_family_ipv4 = 1;
pub const client_subnet_family_ipv6 = 2;

/// The extended error's fixed part: the info code, before the text (RFC 8914 §2).
pub const extended_error_fixed_bytes = 2;

/// The bits of an octet, for the prefix arithmetic of RFC 7871 §6.
pub const bits_per_octet = 8;

/// The COOKIE option's code (RFC 7873 §4), and the two lengths the option may have: a client
/// cookie alone, or a client cookie and a server cookie of 8 to 32 octets.
pub const cookie_option_code = 10;
pub const cookie_option_short_bytes = 8;
pub const cookie_option_long_bytes_min = 16;
pub const cookie_option_long_bytes_max = 40;

/// The rcode's high eight bits sit above the header's four (RFC 6891 §6.1.3).
pub const extended_rcode_low_bits = 4;

/// The most segments a record layout has: NAPTR's fixed part, three strings and a name
/// (`rdata/rdata_layout.zig`).
pub const layout_segments_max = 5;

/// QR: set in a response (RFC 1035 §4.1.1).
pub const flag_response = 0x8000;

/// OPCODE, four bits (RFC 1035 §4.1.1).
pub const opcode_mask = 0x7800;
pub const opcode_shift = 11;

/// The only opcode cocuyo sends or accepts: a standard query (RFC 1035 §4.1.1).
pub const opcode_query = 0;

/// AA: the answer is authoritative.
pub const flag_authoritative = 0x0400;

/// TC: the message was truncated, which is what sends a lookup to TCP (RFC 1035 §4.1.1).
pub const flag_truncated = 0x0200;

/// RD: recursion desired, which every query cocuyo builds sets, because a stub asks a recursive
/// server to do the walking (RFC 1035 §4.1.1).
pub const flag_recursion_desired = 0x0100;

/// RA: recursion available.
pub const flag_recursion_available = 0x0080;

/// RCODE, the low four bits (RFC 1035 §4.1.1).
pub const rcode_mask = 0x000f;

/// The response codes cocuyo reads. The rest are reported as a malformed message rather than
/// guessed at (RFC 1035 §4.1.1, RFC 6895 §2.3).
pub const Rcode = enum(u8) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
    name_error = 3,
    not_implemented = 4,
    refused = 5,
    /// The responder does not implement the EDNS version asked (RFC 6891 §6.1.3).
    bad_vers = 16,
    /// The server cookie was missing or wrong (RFC 7873 §8, the IANA entry).
    bad_cookie = 23,

    /// The code `bits` names, or null when cocuyo does not know it. A code cocuyo does not know is
    /// a malformed message to its caller rather than a code to guess the meaning of. The header
    /// holds four bits and an OPT record's TTL eight more above them (RFC 6891 §6.1.3), so a
    /// code is twelve bits wide.
    pub fn from_bits(bits: u16) ?Rcode {
        inline for (@typeInfo(Rcode).@"enum".fields) |field| {
            if (field.value == bits) return @enumFromInt(field.value);
        }
        return null;
    }
};

/// The two high bits of a length octet say what follows: `00` a label, `11` a pointer. `01` and
/// `10` are reserved and make a message malformed (RFC 1035 §4.1.4).
pub const label_kind_mask = 0xc0;
pub const label_kind_label = 0x00;
pub const label_kind_pointer = 0xc0;

/// The low fourteen bits of a pointer are the offset it points at (RFC 1035 §4.1.4).
pub const pointer_offset_mask = 0x3fff;

/// A pointer is two octets (RFC 1035 §4.1.4).
pub const pointer_bytes = 2;

/// The longest `dns` variable a DoH GET carries (RFC 8484 §6): the largest query without the TCP
/// length prefix, 384 octets, in base64url without padding, four characters for three octets,
/// which is 512 (docs/design.md §22).
pub const dns_variable_bytes_max = std.base64.url_safe_no_pad.Encoder.calcSize(
    @import("core").constants.query_bytes_max - @import("core").constants.tcp_prefix_bytes,
);

comptime {
    const core = @import("core");
    // The header's fields must tile the header exactly, or a parser would read past one of them.
    if (header_arcount_offset + u16_bytes != core.constants.header_bytes) {
        @compileError("the header fields do not tile the header");
    }
    if (label_kind_label | label_kind_pointer != label_kind_mask) {
        @compileError("the label kinds do not cover the kind bits");
    }
    if (pointer_offset_mask | label_kind_mask << octet_bits != 0xffff) {
        @compileError("a pointer's kind bits and offset bits do not cover its two octets");
    }
    // The record's fixed fields must tile its fixed part, or a walk would read past one of them.
    if (record_rdlength_offset + u16_bytes != core.constants.record_fixed_bytes) {
        @compileError("the record fields do not tile the fixed part");
    }
}
