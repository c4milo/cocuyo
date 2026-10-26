//! Every protocol size, protocol value and default cocuyo names, each with the reason it is that
//! number (CLAUDE.md non-negotiable 5). A number is named here and never written at the use site,
//! so a change to one reads as a diff that changes a constant. The limits are in `limits.zig`
//! (docs/design.md §16 decision 56), and docs/design.md §12 is the same table in prose.
//!
//! Durations are spelled out in nanoseconds rather than built from `std.time.ns_per_s`, because
//! nothing under `src/` may name a clock (non-negotiable 4) and `std.time` is flagged whole. The
//! arithmetic is in each doc comment.
const std = @import("std");
const limits = @import("limits.zig");

/// The DNS header: id, flags, and four section counts, two octets each (RFC 1035 §4.1.1).
pub const header_bytes: usize = 12;

/// The question section's fixed part after the qname: qtype and qclass, two octets each
/// (RFC 1035 §4.1.2).
pub const question_fixed_bytes: usize = 4;

/// A record's fixed part after the owner name: type, class, TTL and rdlength (RFC 1035 §4.1.3).
pub const record_fixed_bytes: usize = 10;

/// The TCP length prefix itself, which precedes every message on a stream (RFC 7766 §8).
pub const tcp_prefix_bytes: usize = 2;

/// The UDP payload size cocuyo advertises in OPT by default. 1232 is the widely recommended value
/// that keeps a response inside the smallest IPv6 MTU without fragmenting; recalled, not measured.
pub const udp_payload_bytes_default: usize = 1232;

/// A query to a TLS server is padded to a multiple of this many octets: "Clients SHOULD pad
/// queries to the closest multiple of 128 octets" (RFC 8467 §4.1).
pub const padding_block_bytes: usize = 128;

/// An EDNS(0) option's header: its code and its length, two octets each (RFC 6891 §6.1.2).
pub const opt_option_header_bytes: usize = 4;

/// The OPT pseudo-record's fixed part: the root owner name, type, class, TTL and the rdlength.
/// 1 + 2 + 2 + 4 + 2 (RFC 6891 §6.1.2).
pub const opt_record_bytes: usize = 11;

/// The client cookie is fixed at eight octets (RFC 7873 §4).
pub const cookie_client_bytes: usize = 8;

/// Server failover (docs/design.md §19 step 12): a server that failed to answer is asked last,
/// and asked first again one query in `failover_retry_chance_default` once
/// `failover_retry_delay_ns_default` has passed since it failed. Both are c-ares's defaults.
/// A chance of zero never retries.
pub const failover_retry_chance_default: usize = 10;
pub const failover_retry_delay_ns_default: u64 = 5_000_000_000;

/// The default number of passes over the server list (`resolv.conf` attempts).
pub const attempts_default: usize = 2;

/// The default dot count that decides whether the name or the search list is tried first
/// (`resolv.conf` ndots).
pub const ndots_default: usize = 1;

/// The default wait for a server that has not been measured yet: 2 seconds, the default of
/// `ARES_OPT_TIMEOUTMS`, c-ares's, read from its features page, not measured. A server waits it
/// until it has 3 samples (docs/design.md §5). It was 5 seconds, the `resolv.conf` default,
/// until 2026-10-09. 2 * 1_000_000_000.
pub const timeout_ns_default: u64 = 2_000_000_000;

/// The default cap on every wait, measured or doubled per pass: 5 seconds, the ceiling
/// `ARES_OPT_MAXTIMEOUTMS` changes, c-ares's, read from its features page, not measured
/// (docs/design.md §5). 5 * 1_000_000_000.
pub const timeout_ns_max_default: u64 = 5_000_000_000;

/// The default cap on every TTL a cache keeps, `Config.cache_ttl_seconds_max`: an hour, which is
/// c-ares's default (docs/design.md §18), so a consumer replacing it sees the same ceiling.
/// "Values SHOULD be capped on the order of days to weeks, with a recommended cap of 604,800
/// seconds (7 days)" (RFC 8767 §4), so an hour is inside it. Here because `Config` and the cache
/// both read it (§16 decision 37). 60 * 60.
pub const cache_ttl_seconds_max_default: u32 = 3600;

/// The port a DNS server listens on (RFC 1035 §4.2.1).
pub const port_dns_default: u16 = 53;

/// The port a DNS-over-TLS server listens on, unless client and server agree on another
/// (RFC 7858 §3.1).
pub const port_dns_tls_default: u16 = 853;

/// An SPKI pin is the SHA-256 of a DER SubjectPublicKeyInfo (RFC 7858 §4.2).
pub const spki_pin_bytes: usize = 32;

/// An IPv4 address, in octets: the "32 bit Internet address" an A record carries
/// (RFC 1035 §3.4.1).
pub const address_v4_bytes: usize = 4;

/// An IPv6 address, in octets (RFC 3596 §2.2 gives the AAAA rdata this length).
pub const address_v6_bytes: usize = 16;

/// The prefix of an IPv4-mapped IPv6 address, `::ffff:0:0/96` (RFC 4291 §2.5.5.2): how an IPv4
/// address is handed back under `v4_mapped`, and how the policy table of RFC 6724 §2.1 reads one
/// (its §3.2).
pub const v4_mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

/// An address in text (`address_text.zig`): the dotted quad's octet count (RFC 1035 §3.4.1).
pub const address_v4_octets = address_v4_bytes;

/// The groups an IPv6 address holds in text (RFC 4291 §2.2 form 1), and the octets one group
/// covers.
pub const address_v6_groups: usize = 8;
pub const address_v6_group_bytes: usize = 2;

/// The groups a trailing dotted quad fills (RFC 4291 §2.2 form 3), and the `::` of a compressed
/// address in octets (form 2).
pub const groups_per_quad: usize = 2;
pub const double_colon_bytes: usize = 2;

/// The bases the text is written in: decimal for an octet, and hexadecimal for a group as a
/// shift of one digit's bits, with the value the letter `a` stands for.
pub const decimal_base: u8 = 10;
pub const hex_digit_bits: u4 = 4;
pub const hex_alpha_value: u8 = 10;

/// The bits in an octet, so a shift by a whole octet names what it shifts by.
pub const octet_bits: u4 = @bitSizeOf(u8);

comptime {
    if (address_v6_groups * address_v6_group_bytes != address_v6_bytes) {
        @compileError("the IPv6 groups do not cover the address");
    }
}

/// The bit that tells an ASCII letter's cases apart. A case-insensitive comparison clears it
/// (RFC 4343) and DNS-0x20 sets it at random (docs/design.md §7), which is the same bit twice.
pub const ascii_case_bit: u8 = 0x20;

/// `Name.fold_word` folds eight octets at once. Each octet's low seven bits, plus a bias, put the
/// octet's high bit on when the octet is at or past `'A'` (`0x80 - 'A'`) and when it is past
/// `'Z'` (`0x80 - ('Z' + 1)`); the high bit, shifted down, is the case bit.
pub const word_low_bits: u64 = 0x7f7f7f7f7f7f7f7f;
pub const word_high_bits: u64 = 0x8080808080808080;
pub const word_bias_at_a: u64 = 0x3f3f3f3f3f3f3f3f;
pub const word_bias_past_z: u64 = 0x2525252525252525;
pub const word_high_to_case_shift: u6 = 2;

/// The class every query cocuyo sends carries: IN, the internet class (RFC 1035 §3.2.4).
pub const class_internet: u16 = 1;

/// Type code zero, which "must never be allocated for ordinary use" (RFC 6895 §3.1).
pub const type_code_none: u16 = 0;
/// The codes RFC 6895 §3.1 keeps for query types and meta types, 128 to 255. A record of one of
/// them is not a type whose rdata can be kept whole (RFC 3597 §2).
pub const type_code_query_meta_first: u16 = 0x80;
pub const type_code_query_meta_last: u16 = 0xFF;

/// The scopes RFC 6724 §3.1 compares, numbered as RFC 4291 §2.7 numbers a multicast address's
/// scope field, with unicast link-local, site-local and global on the same values.
pub const scope_link_local: u8 = 0x2;
pub const scope_site_local: u8 = 0x5;
pub const scope_global: u8 = 0xe;

/// The prefixes a scope is read from: link-local unicast `fe80::/10` (RFC 4291 §2.5.6),
/// site-local unicast `fec0::/10` (§2.5.7), both under a ten-bit mask; multicast `ff00::/8`,
/// whose scope is the low four bits of its second octet (§2.7); and for IPv4, `169.254/16` and
/// `127/8`, which RFC 6724 §3.2 makes link-local.
pub const v6_link_local_prefix = [_]u8{ 0xfe, 0x80 };
pub const v6_site_local_prefix = [_]u8{ 0xfe, 0xc0 };
pub const v6_ten_bit_mask = [_]u8{ 0xff, 0xc0 };
pub const v6_multicast_first_octet: u8 = 0xff;
pub const v6_multicast_scope_mask: u8 = 0x0f;
pub const v4_link_local_prefix = [_]u8{ 169, 254 };
pub const v4_loopback_first_octet: u8 = 127;

/// One row of RFC 6724 §2.1's default policy table: a prefix written in full, its length in
/// bits, and the precedence and label a longest-prefix match hands back.
pub const PolicyRow = struct { prefix: [address_v6_bytes]u8, bits: u8, precedence: u8, label: u8 };

/// RFC 6724 §2.1's default policy table, its nine rows in the RFC's order: `::1/128`, `::/0`,
/// `::ffff:0:0/96`, `2002::/16`, `2001::/32`, `fc00::/7`, `::/96`, `fec0::/10`, `3ffe::/16`.
pub const address_policy_rows: usize = 9;
pub const address_policy_table = [address_policy_rows]PolicyRow{
    .{ .prefix = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .bits = 128, .precedence = 50, .label = 0 },
    .{ .prefix = @splat(0), .bits = 0, .precedence = 40, .label = 1 },
    .{ .prefix = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 }, .bits = 96, .precedence = 35, .label = 4 },
    .{ .prefix = .{ 0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .bits = 16, .precedence = 30, .label = 2 },
    .{ .prefix = .{ 0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .bits = 32, .precedence = 5, .label = 5 },
    .{ .prefix = .{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .bits = 7, .precedence = 3, .label = 13 },
    .{ .prefix = @splat(0), .bits = 96, .precedence = 1, .label = 3 },
    .{ .prefix = .{ 0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .bits = 10, .precedence = 1, .label = 11 },
    .{ .prefix = .{ 0x3f, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .bits = 16, .precedence = 1, .label = 12 },
};

/// The bits of one octet, for walking a prefix bit by bit.
pub const bits_per_octet: usize = 8;

comptime {
    // The query bound must hold every part it is the sum of, or a maximal query would not fit the
    // buffer the caller is asked to provide.
    const unpadded = header_bytes + limits.name_bytes_max + question_fixed_bytes + limits.opt_record_bytes_max +
        opt_option_header_bytes;
    const blocks = (unpadded + padding_block_bytes - 1) / padding_block_bytes;
    const parts = blocks * padding_block_bytes + tcp_prefix_bytes;
    if (limits.query_bytes_max != parts) @compileError("query_bytes_max is not the sum of its parts");
    if (limits.name_text_bytes_max != limits.name_bytes_max * 4) @compileError("the escape bound is wrong");
    if (udp_payload_bytes_default < limits.udp_payload_bytes_min) @compileError("payload below the floor");
    if (timeout_ns_default > timeout_ns_max_default) @compileError("the default timeout exceeds the cap");
    if (timeout_ns_max_default > limits.timeout_ns_max) @compileError("the default cap exceeds the most");
    if (limits.timeout_ns_min > timeout_ns_default) @compileError("the floor is above the default wait");
    if (cache_ttl_seconds_max_default < 1) @compileError("the default TTL cap caches nothing");
    if (cache_ttl_seconds_max_default > limits.cache_ttl_seconds_max) @compileError("the default TTL cap exceeds the most");
    if (limits.port_ephemeral_min >= limits.port_ephemeral_max) @compileError("the port range is empty");
}

// The paths a consumer reached these limits by before they moved into the limits file. Each
// is an alias, and no limit of its own. They stay until the owner rules on them (docs/design.md
// §16 decision 56, §17 question 76).
pub const message_bytes_max = limits.message_bytes_max;
pub const udp_payload_bytes_min = limits.udp_payload_bytes_min;
pub const query_bytes_max = limits.query_bytes_max;
pub const opt_record_bytes_max = limits.opt_record_bytes_max;
pub const cookie_option_bytes_max = limits.cookie_option_bytes_max;
pub const cookie_server_bytes_min = limits.cookie_server_bytes_min;
pub const cookie_server_bytes_max = limits.cookie_server_bytes_max;
pub const name_bytes_max = limits.name_bytes_max;
pub const label_bytes_max = limits.label_bytes_max;
pub const labels_max = limits.labels_max;
pub const name_text_bytes_max = limits.name_text_bytes_max;
pub const compression_hops_max = limits.compression_hops_max;
pub const cname_hops_max = limits.cname_hops_max;
pub const records_max = limits.records_max;
pub const addresses_max = limits.addresses_max;
pub const address_lookup_addresses_max = limits.address_lookup_addresses_max;
pub const ptr_names_max = limits.ptr_names_max;
pub const records_kept_max = limits.records_kept_max;
pub const rdata_bytes_max = limits.rdata_bytes_max;
pub const servers_max = limits.servers_max;
pub const lookup_sources_max = limits.lookup_sources_max;
pub const hosts_entries_max = limits.hosts_entries_max;
pub const hosts_names_per_entry_max = limits.hosts_names_per_entry_max;
pub const hosts_names_bytes_max = limits.hosts_names_bytes_max;
pub const search_max = limits.search_max;
pub const candidates_max = limits.candidates_max;
pub const attempts_max = limits.attempts_max;
pub const timeout_ns_max = limits.timeout_ns_max;
pub const timeout_ns_min = limits.timeout_ns_min;
pub const cache_ttl_seconds_max = limits.cache_ttl_seconds_max;
pub const port_ephemeral_min = limits.port_ephemeral_min;
pub const port_ephemeral_max = limits.port_ephemeral_max;
pub const spki_pins_max = limits.spki_pins_max;
pub const address_v4_octet_digits_max = limits.address_v4_octet_digits_max;
pub const address_v6_group_digits_max = limits.address_v6_group_digits_max;
pub const lookup_slots_max = limits.lookup_slots_max;
pub const common_prefix_bits_v6_max = limits.common_prefix_bits_v6_max;
pub const common_prefix_bits_v4_max = limits.common_prefix_bits_v4_max;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
