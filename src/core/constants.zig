//! Every limit cocuyo holds, each with the reason it is that number (CLAUDE.md non-negotiable 5).
//! A limit is named here and never written at the use site, so a change to one reads as a diff
//! that changes a constant. docs/design.md §12 is the same table in prose.
//!
//! Durations are spelled out in nanoseconds rather than built from `std.time.ns_per_s`, because
//! nothing under `src/` may name a clock (non-negotiable 4) and `std.time` is flagged whole. The
//! arithmetic is in each doc comment.

/// The DNS header: id, flags, and four section counts, two octets each (RFC 1035 §4.1.1).
pub const header_bytes = 12;

/// The question section's fixed part after the qname: qtype and qclass, two octets each
/// (RFC 1035 §4.1.2).
pub const question_fixed_bytes = 4;

/// A record's fixed part after the owner name: type, class, TTL and rdlength (RFC 1035 §4.1.3).
pub const record_fixed_bytes = 10;

/// The largest message that can be framed: the TCP length prefix is two octets (RFC 7766 §8).
pub const message_bytes_max = 65535;

/// The TCP length prefix itself, which precedes every message on a stream (RFC 7766 §8).
pub const tcp_prefix_bytes = 2;

/// The UDP payload size cocuyo advertises in OPT by default. 1232 is the widely recommended value
/// that keeps a response inside the smallest IPv6 MTU without fragmenting; recalled, not measured.
pub const udp_payload_bytes_default = 1232;

/// The smallest payload size a requestor may advertise: 512 is the pre-EDNS0 limit every server
/// already honours (RFC 6891 §6.2.3).
pub const udp_payload_bytes_min = 512;

/// The largest query cocuyo builds: the header, a maximal qname, qtype and qclass, an OPT record
/// carrying the largest COOKIE option, and the TCP length prefix. 12 + 255 + 4 + 55 + 2.
pub const query_bytes_max = 328;

/// The OPT pseudo-record's fixed part: the root owner name, type, class, TTL and the rdlength.
/// 1 + 2 + 2 + 4 + 2 (RFC 6891 §6.1.2).
pub const opt_record_bytes = 11;

/// The OPT record with the one option cocuyo writes, a COOKIE at its longest (RFC 7873 §4):
/// the fixed part, the option's code and length, a client cookie and a 32-octet server cookie.
pub const opt_record_bytes_max = opt_record_bytes + cookie_option_bytes_max;

/// A COOKIE option at its longest: a 4-octet option header, then 8 + 32 octets of cookie.
pub const cookie_option_bytes_max = 4 + cookie_client_bytes + cookie_server_bytes_max;

/// The client cookie is fixed at eight octets; the server's is eight to thirty-two
/// (RFC 7873 §4).
pub const cookie_client_bytes = 8;
pub const cookie_server_bytes_min = 8;
pub const cookie_server_bytes_max = 32;

/// A name in wire form, counting every length octet and the root (RFC 1035 §2.3.4).
pub const name_bytes_max = 255;

/// One label (RFC 1035 §2.3.4).
pub const label_bytes_max = 63;

/// The most labels a name can hold: a name is 255 octets and a label costs at least two of them,
/// one length octet and one byte.
pub const labels_max = 128;

/// A name in presentation form, which escapes: four bytes per wire byte at worst, `\255`.
pub const name_text_bytes_max = 1020;

/// The most compression pointers one name may chase. A legal encoder needs none, every hop must
/// point strictly backwards, and 16 is slack over any real one (RFC 1035 §4.1.4).
pub const compression_hops_max = 16;

/// The most CNAMEs one lookup may follow, across messages as well as inside one. Matches the chain
/// length BIND allows; recalled, not measured.
pub const cname_hops_max = 8;

/// The most records one message walk reads, whatever the count fields claim. A count is never a
/// reason to read (non-negotiable 6).
pub const records_max = 64;

/// The most addresses one lookup keeps. A larger round-robin name sets `Answer.truncated`;
/// docs/design.md §17.4 records that this number is not measured.
pub const addresses_max = 16;

/// The most names a reverse lookup keeps. One, because that is what a PTR lookup returns in
/// practice, and `Answer.truncated` says when more existed (docs/design.md §17.2).
pub const ptr_names_max = 1;

/// The most records of one type a lookup keeps in its rdata buffer, for every type that is not an
/// address or a PTR name: half `records_max`, which is what one answer section holds of one type
/// in practice, with `truncated` set past it (docs/design.md §19 step 9).
pub const records_kept_max = 32;

/// The rdata buffer of one lookup: one UDP payload of `udp_payload_bytes_default` with room for
/// the names written out in full on the way in, each of which can grow from a two-octet pointer
/// to `name_bytes_max`. A TCP answer that does not fit sets `truncated` (docs/design.md §19).
pub const rdata_bytes_max = 2048;

/// The most servers a configuration may name. glibc's MAXNS is 3; 8 leaves room and still bounds
/// every loop over the list.
pub const servers_max = 8;

/// The sources a name is looked up in, the hosts file and DNS, so an order names each at most
/// once (docs/design.md §19 step 11).
pub const lookup_sources_max = 2;

/// The hosts table (`hosts.zig`): the most entries kept, the most names on one line (the
/// official name and its aliases), and the octets of wire names one storage holds, a `u16`
/// offset each. More lines than a machine that is not a blocklist has; past them, dropped and
/// said so (docs/design.md §19 step 11).
pub const hosts_entries_max = 1024;
pub const hosts_names_per_entry_max = 8;
pub const hosts_names_bytes_max = 65536;

/// Server failover (docs/design.md §19 step 12): a server that failed to answer is asked last,
/// and asked first again one query in `failover_retry_chance_default` once
/// `failover_retry_delay_ns_default` has passed since it failed. Both are c-ares's defaults.
/// A chance of zero never retries.
pub const failover_retry_chance_default = 10;
pub const failover_retry_delay_ns_default = 5_000_000_000;

/// The most search-list entries a configuration may name. glibc's MAXDNSRCH; recalled, not
/// measured.
pub const search_max = 6;

/// The most candidates one lookup tries: every search entry, plus the name as it was asked.
pub const candidates_max = search_max + 1;

/// The default number of passes over the server list (`resolv.conf` attempts).
pub const attempts_default = 2;

/// The most passes a configuration may ask for, which bounds the retry loop.
pub const attempts_max = 5;

/// The default dot count that decides whether the name or the search list is tried first
/// (`resolv.conf` ndots).
pub const ndots_default = 1;

/// The default wait for one server on the first pass: 5 seconds, as `resolv.conf` timeout.
/// 5 * 1_000_000_000.
pub const timeout_ns_default = 5_000_000_000;

/// The cap on the doubling of `timeout_ns` per pass: 30 seconds. 30 * 1_000_000_000.
pub const timeout_ns_max = 30_000_000_000;

/// The IANA Dynamic port range, which the source-port hint is drawn from (RFC 6335 §6).
pub const port_ephemeral_min = 49152;
pub const port_ephemeral_max = 65535;

/// The port a DNS server listens on (RFC 1035 §4.2.1).
pub const port_dns_default = 53;

/// An IPv4 address, in octets: the "32 bit Internet address" an A record carries
/// (RFC 1035 §3.4.1).
pub const address_v4_bytes = 4;

/// An IPv6 address, in octets (RFC 3596 §2.2 gives the AAAA rdata this length).
pub const address_v6_bytes = 16;

/// An address in text (`address_text.zig`): the dotted quad's octet count (RFC 1035 §3.4.1) and
/// the decimal digits one octet may hold.
pub const address_v4_octets = address_v4_bytes;
pub const address_v4_octet_digits_max = 3;

/// The groups an IPv6 address holds in text (RFC 4291 §2.2 form 1), the hexadecimal digits one
/// group may hold, and the octets one group covers.
pub const address_v6_groups = 8;
pub const address_v6_group_digits_max = 4;
pub const address_v6_group_bytes = 2;

/// The groups a trailing dotted quad fills (RFC 4291 §2.2 form 3), and the `::` of a compressed
/// address in octets (form 2).
pub const groups_per_quad = 2;
pub const double_colon_bytes = 2;

/// The bases the text is written in: decimal for an octet, and hexadecimal for a group as a
/// shift of one digit's bits, with the value the letter `a` stands for.
pub const decimal_base = 10;
pub const hex_digit_bits = 4;
pub const hex_alpha_value = 10;

/// The bits in an octet, so a shift by a whole octet names what it shifts by.
pub const octet_bits = @bitSizeOf(u8);

comptime {
    if (address_v6_groups * address_v6_group_bytes != address_v6_bytes) {
        @compileError("the IPv6 groups do not cover the address");
    }
}

/// The most lookup slots one resolver table may hold, which bounds a handle's index.
pub const lookup_slots_max = 1024;

/// The bit that tells an ASCII letter's cases apart. A case-insensitive comparison clears it
/// (RFC 4343) and DNS-0x20 sets it at random (docs/design.md §7), which is the same bit twice.
pub const ascii_case_bit = 0x20;

/// `Name.fold_word` folds eight octets at once. Each octet's low seven bits, plus a bias, put the
/// octet's high bit on when the octet is at or past `'A'` (`0x80 - 'A'`) and when it is past
/// `'Z'` (`0x80 - ('Z' + 1)`); the high bit, shifted down, is the case bit.
pub const word_low_bits: u64 = 0x7f7f7f7f7f7f7f7f;
pub const word_high_bits: u64 = 0x8080808080808080;
pub const word_bias_at_a: u64 = 0x3f3f3f3f3f3f3f3f;
pub const word_bias_past_z: u64 = 0x2525252525252525;
pub const word_high_to_case_shift = 2;

/// The class every query cocuyo sends carries: IN, the internet class (RFC 1035 §3.2.4).
pub const class_internet = 1;

comptime {
    // The query bound must hold every part it is the sum of, or a maximal query would not fit the
    // buffer the caller is asked to provide.
    const parts = header_bytes + name_bytes_max + question_fixed_bytes + opt_record_bytes_max +
        tcp_prefix_bytes;
    if (query_bytes_max != parts) @compileError("query_bytes_max is not the sum of its parts");
    if (name_text_bytes_max != name_bytes_max * 4) @compileError("the escape bound is wrong");
    if (udp_payload_bytes_default < udp_payload_bytes_min) @compileError("payload below the floor");
    if (timeout_ns_default > timeout_ns_max) @compileError("the default timeout exceeds the cap");
    if (port_ephemeral_min >= port_ephemeral_max) @compileError("the port range is empty");
}
