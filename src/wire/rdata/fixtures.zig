//! Hand-written rdata, byte for byte, for the decoders of this directory. Where an RFC gives a
//! vector, the vector is used: SVCB's are RFC 9460 Appendix D. Exempt from the magic-numbers
//! rule by name, like every corpus (tools/lint/magic_numbers.zig), and test-only.

// Names, in the uncompressed form the collector stores.

pub const name_example = "\x07example\x03com\x00".*;
pub const name_root = [_]u8{0x00};
pub const name_pointer = [_]u8{ 0xc0, 0x0c };
pub const name_short_label = "\x07exam".*;
pub const name_unterminated = "\x07example\x03com".*;
pub const name_trailing = name_example ++ [_]u8{0x00};
/// 128 one-octet labels: 256 octets before the root, more than a name may hold.
pub const name_too_long = (("\x01a" ** 128) ++ "\x00").*;

// Character-strings (RFC 1035 §3.3), TXT (§3.3.14) and HINFO (§3.3.2).

pub const txt_two = "\x05hello\x05world".*;
pub const txt_short = "\x05hello\x05wor".*;
pub const txt_empty_string = "\x00".*;
pub const hinfo = "\x05ARM64\x06Darwin".*;
pub const hinfo_one_string = "\x05ARM64".*;
pub const hinfo_trailing = hinfo ++ [_]u8{0x00};

/// MX (RFC 1035 §3.3.9): preference 10, `mail.example.com`.
pub const mx = [_]u8{ 0x00, 0x0a } ++ "\x04mail\x07example\x03com\x00".*;
pub const mx_short = [_]u8{0x00};
pub const mx_trailing = mx ++ [_]u8{0x00};

/// SRV (RFC 2782): priority 10, weight 20, port 5269, `sip.example.com`.
pub const srv = [_]u8{ 0x00, 0x0a, 0x00, 0x14, 0x14, 0x95 } ++ "\x03sip\x07example\x03com\x00".*;
pub const srv_short = [_]u8{ 0x00, 0x0a, 0x00, 0x14, 0x14 };
pub const srv_trailing = srv ++ [_]u8{0x00};

/// SOA (RFC 1035 §3.3.13): `ns1.example.com`, `hostmaster.example.com`, then the five counters.
pub const soa = "\x03ns1\x07example\x03com\x00".* ++ "\x0ahostmaster\x07example\x03com\x00".* ++ [_]u8{
    0x78, 0xc3, 0xb6, 0xa9, // serial 2026092201
    0x00, 0x00, 0x1c, 0x20, // refresh 7200
    0x00, 0x00, 0x03, 0x84, // retry 900
    0x00, 0x12, 0x75, 0x00, // expire 1209600
    0x00, 0x00, 0x01, 0x2c, // minimum 300
};
pub const soa_short = soa[0 .. soa.len - 1].*;
pub const soa_trailing = soa ++ [_]u8{0x00};

/// NAPTR (RFC 3403 §4.1): order 100, preference 50, flags `s`, services `SIP+D2U`, an empty
/// regexp, replacement `_sip._udp.example.com`.
pub const naptr = [_]u8{ 0x00, 0x64, 0x00, 0x32 } ++ "\x01s\x07SIP+D2U\x00".* ++
    "\x04_sip\x04_udp\x07example\x03com\x00".*;
/// Ends inside the services string.
pub const naptr_short = naptr[0..8].*;
pub const naptr_trailing = naptr ++ [_]u8{0x00};

/// SIG (RFC 2535 §4.1): type covered 0, which is SIG(0) (RFC 2931), algorithm 13, two labels,
/// original TTL 0, an expiration and an inception, key tag 0x1234, signer `example.com`, and
/// four octets of signature.
pub const sig = [_]u8{
    0x00, 0x00, // type covered
    0x0d, // algorithm
    0x02, // labels
    0x00, 0x00, 0x00, 0x00, // original TTL
    0x5f, 0x00, 0x00, 0x00, // expiration
    0x5e, 0x00, 0x00, 0x00, // inception
    0x12, 0x34, // key tag
} ++ name_example ++ [_]u8{ 0xde, 0xad, 0xbe, 0xef };
pub const sig_short = sig[0..17].*;
pub const sig_no_signature = sig[0 .. sig.len - 4].*;

// SVCB and HTTPS (RFC 9460 Appendix D): the vectors, then the malformed shapes of §2.2 and §7.

const svcb_target_foo = "\x03foo\x07example\x03com\x00".*;

/// D.1, AliasMode: `HTTPS 0 foo.example.com.`
pub const svcb_alias = [_]u8{ 0x00, 0x00 } ++ svcb_target_foo;
/// D.2, figure 3: `SVCB 1 .`
pub const svcb_root = [_]u8{ 0x00, 0x01, 0x00 };
/// D.2, figure 4: `SVCB 16 foo.example.com. port=53`
pub const svcb_port = [_]u8{ 0x00, 0x10 } ++ svcb_target_foo ++ [_]u8{ 0x00, 0x03, 0x00, 0x02, 0x00, 0x35 };
/// D.2, figure 5: `SVCB 1 foo.example.com. key667=hello`
pub const svcb_generic = [_]u8{ 0x00, 0x01 } ++ svcb_target_foo ++ [_]u8{ 0x02, 0x9b, 0x00, 0x05 } ++ "hello".*;
/// D.2, figure 7: two ipv6hint addresses.
pub const svcb_ipv6hint = [_]u8{ 0x00, 0x01 } ++ svcb_target_foo ++ [_]u8{
    0x00, 0x06, 0x00, 0x20,
    0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x20, 0x01, 0x0d, 0xb8,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x53, 0x00, 0x01,
};
/// D.2, figure 9: `SVCB 16 foo.example.org. alpn=h2,h3-19 mandatory=ipv4hint,alpn ipv4hint=192.0.2.1`,
/// sorted on the wire: mandatory, alpn, ipv4hint.
pub const svcb_mandatory = [_]u8{ 0x00, 0x10 } ++ "\x03foo\x07example\x03org\x00".* ++ [_]u8{
    0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, // mandatory: keys 1 and 4
    0x00, 0x01, 0x00, 0x09, 0x02, 'h', '2', 0x05, 'h', '3', '-', '1', '9', // alpn
    0x00, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, // ipv4hint
};
/// ipv4hint before port: keys out of order.
pub const svcb_keys_out_of_order = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{
    0x00, 0x04, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x35,
};
pub const svcb_duplicate_key = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{
    0x00, 0x03, 0x00, 0x02, 0x00, 0x35, 0x00, 0x03, 0x00, 0x02, 0x00, 0x36,
};
/// A length of five with two octets left.
pub const svcb_ends_inside_param = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x03, 0x00, 0x05, 0x00, 0x35 };
/// A key with no length after it.
pub const svcb_param_header_cut = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x03, 0x00 };
pub const svcb_port_three_octets = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x03, 0x00, 0x03, 0x00, 0x35, 0x00 };
pub const svcb_alpn_empty_id = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x01, 0x00, 0x01, 0x00 };
pub const svcb_alpn_no_ids = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x01, 0x00, 0x00 };
pub const svcb_no_default_alpn_with_value = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x02, 0x00, 0x01, 0x00 };
pub const svcb_ipv4hint_odd = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x04, 0x00, 0x03, 0xc0, 0x00, 0x02 };
pub const svcb_ipv6hint_empty = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x06, 0x00, 0x00 };
pub const svcb_mandatory_lists_itself = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{ 0x00, 0x00, 0x00, 0x02, 0x00, 0x00 };
pub const svcb_mandatory_out_of_order = [_]u8{ 0x00, 0x01 } ++ name_root ++ [_]u8{
    0x00, 0x00, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,
};
pub const svcb_short = [_]u8{0x00};

/// TLSA (RFC 6698 §2.1): usage 3, selector 1, matching type 1, then thirty-two octets.
pub const tlsa = [_]u8{ 0x03, 0x01, 0x01 } ++ [_]u8{0xab} ** 32;
pub const tlsa_short = [_]u8{ 0x03, 0x01 };

/// URI (RFC 7553 §4.5): priority 10, weight 1.
pub const uri = [_]u8{ 0x00, 0x0a, 0x00, 0x01 } ++ "https://example.com/".*;
pub const uri_empty_target = [_]u8{ 0x00, 0x0a, 0x00, 0x01 };
pub const uri_short = [_]u8{ 0x00, 0x0a, 0x00 };

/// CAA (RFC 8659 §4.1): flags 0, tag `issue`, value `ca.example.net`.
pub const caa = [_]u8{ 0x00, 0x05 } ++ "issue".* ++ "ca.example.net".*;
/// The critical flag set, an empty value.
pub const caa_critical = [_]u8{ 0x80, 0x05 } ++ "issue".*;
pub const caa_tag_zero = [_]u8{ 0x00, 0x00 } ++ "abc".*;
pub const caa_tag_past_end = [_]u8{ 0x00, 0x09 } ++ "issue".*;
pub const caa_tag_bad_char = [_]u8{ 0x00, 0x05 } ++ "is-ue".* ++ "x".*;
pub const caa_short = [_]u8{0x00};

/// OPT options (RFC 6891 §6.1.2): a COOKIE of eight octets (RFC 7873 §4), then an empty NSID.
pub const opt_options = [_]u8{ 0x00, 0x0a, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8, 0x00, 0x03, 0x00, 0x00 };
/// An empty NSID alone: no cookie.
pub const opt_nsid_only = [_]u8{ 0x00, 0x03, 0x00, 0x00 };
pub const opt_option_short = [_]u8{ 0x00, 0x0a, 0x00, 0x08, 1, 2 };
pub const opt_option_header_only = [_]u8{ 0x00, 0x0a, 0x00 };
