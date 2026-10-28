//! Every limit cocuyo holds, each with the reason it is that number (CLAUDE.md non-negotiable 5,
//! docs/design.md §16 decision 56). A limit is a bound the code holds or checks: a most, a least, a
//! count of slots or the size of a buffer cocuyo chooses. It is named here and never written at
//! the use site, so a change to one reads as a diff that changes a limit. docs/design.md §12 is
//! the same table in prose. The protocol sizes and the defaults are in `constants.zig`.
//!
//! Durations are spelled out in nanoseconds rather than built from `std.time.ns_per_s`, because
//! nothing under `src/` may name a clock (non-negotiable 4) and `std.time` is flagged whole. The
//! arithmetic is in each doc comment.
const std = @import("std");
const constants = @import("constants.zig");

/// The largest message that can be framed: the TCP length prefix is two octets (RFC 7766 §8).
pub const message_bytes_max: usize = 65535;

/// The smallest payload size a requestor may advertise: 512 is the pre-EDNS0 limit every server
/// already honours (RFC 6891 §6.2.3).
pub const udp_payload_bytes_min: usize = 512;

/// The largest query cocuyo builds: the header, a maximal qname, qtype and qclass, an OPT record
/// carrying the largest COOKIE option and a Padding option, padded to a whole block, and the TCP
/// length prefix. 12 + 255 + 4 + 55 + 4 is 330, padded to 384, and 2 more (docs/design.md §21).
pub const query_bytes_max: usize = 386;

/// The OPT record with a COOKIE at its longest (RFC 7873 §4), before any padding: the fixed
/// part, the option's code and length, a client cookie and a 32-octet server cookie.
pub const opt_record_bytes_max: usize = constants.opt_record_bytes + cookie_option_bytes_max;

/// A COOKIE option at its longest: a 4-octet option header, then 8 + 32 octets of cookie.
pub const cookie_option_bytes_max: usize = constants.opt_option_header_bytes + constants.cookie_client_bytes + cookie_server_bytes_max;

/// The server cookie is eight to thirty-two octets (RFC 7873 §4).
pub const cookie_server_bytes_min: usize = 8;
pub const cookie_server_bytes_max: usize = 32;

/// A name in wire form, counting every length octet and the root (RFC 1035 §2.3.4).
pub const name_bytes_max: usize = 255;

/// One label (RFC 1035 §2.3.4).
pub const label_bytes_max: usize = 63;

/// The most labels a name can hold: a name is 255 octets and a label costs at least two of them,
/// one length octet and one byte.
pub const labels_max: usize = 128;

/// A name in presentation form, which escapes: four bytes per wire byte at worst, `\255`.
pub const name_text_bytes_max: usize = 1020;

/// The most compression pointers one name may chase. A legal encoder needs none, every hop must
/// point strictly backwards, and 16 is slack over any real one (RFC 1035 §4.1.4).
pub const compression_hops_max: usize = 16;

/// The most CNAMEs one lookup may follow, across messages as well as inside one. Matches the chain
/// length BIND allows; recalled, not measured.
pub const cname_hops_max: usize = 8;

/// The most records one message walk reads, whatever the count fields claim. A count is never a
/// reason to read (non-negotiable 6).
pub const records_max: usize = 64;

/// The most addresses one lookup keeps. A larger round-robin name sets `Answer.truncated`;
/// docs/design.md §17.4 records that this number is not measured.
pub const addresses_max: usize = 16;

/// The most addresses one `AddressLookup` keeps: both families' `addresses_max`, bounded the way
/// one answer is, with `truncated` past it (docs/design.md §19 step 14). It is also the most the
/// ordering of step 15 sorts.
pub const address_lookup_addresses_max: usize = 2 * addresses_max;

/// The most names a reverse lookup keeps. One, because that is what a PTR lookup returns in
/// practice, and `Answer.truncated` says when more existed (docs/design.md §17.2).
pub const ptr_names_max: usize = 1;

/// The most records of one type a lookup keeps in its rdata buffer, for every type that is not an
/// address or a PTR name: half `records_max`, which is what one answer section holds of one type
/// in practice, with `truncated` set past it (docs/design.md §19 step 9).
pub const records_kept_max: usize = 32;

/// The rdata buffer of one lookup: one UDP payload of `udp_payload_bytes_default` with room for
/// the names written out in full on the way in, each of which can grow from a two-octet pointer
/// to `name_bytes_max`. A TCP answer that does not fit sets `truncated` (docs/design.md §19).
pub const rdata_bytes_max: usize = 2048;

/// The most servers a configuration may name. glibc's MAXNS is 3; 8 leaves room and still bounds
/// every loop over the list.
pub const servers_max: usize = 8;

/// The sources a name is looked up in, the hosts file and DNS, so an order names each at most
/// once (docs/design.md §19 step 11).
pub const lookup_sources_max: usize = 2;

/// The hosts table (`hosts.zig`): the most entries kept, the most names on one line (the
/// official name and its aliases), and the octets of wire names one storage holds, a `u16`
/// offset each. More lines than a machine that is not a blocklist has; past them, dropped and
/// said so (docs/design.md §19 step 11).
pub const hosts_entries_max: usize = 1024;
pub const hosts_names_per_entry_max: usize = 8;
pub const hosts_names_bytes_max: usize = 65536;

/// The most search-list entries a configuration may name. glibc's MAXDNSRCH; recalled, not
/// measured.
pub const search_max: usize = 6;

/// The most candidates one lookup tries: every search entry, plus the name as it was asked.
pub const candidates_max: usize = search_max + 1;

/// The most passes a configuration may ask for, which bounds the retry loop. A lookup still sends
/// one server three queries of a name over one transport at most, whatever the passes say
/// (RFC 9520 §3.1; `resolver.limits.queries_per_transport_max`, docs/design.md §16 decision 58).
pub const attempts_max: usize = 5;

/// The most a configuration's cap on the wait may be: 30 seconds, which is `resolv.conf(5)`'s
/// cap on `timeout:` too, so any wait a file asks for fits under it. It was the default cap
/// until 2026-10-09. 30 * 1_000_000_000.
pub const timeout_ns_max: u64 = 30_000_000_000;

/// The floor under every wait, measured or configured: 250 milliseconds, c-ares's, read from its
/// features page, not measured. The page gives it as roughly a round trip to the far side of the
/// world, which leaves an upstream server time to recurse. A configuration's cap below it wins,
/// since the cap is the caller's (docs/design.md §5). 250 * 1_000_000.
pub const timeout_ns_min: u64 = 250_000_000;

/// The most `Config.cache_ttl_seconds_max` may be, and the longest cap a cache takes: seven days.
/// "Values SHOULD be capped on the order of days to weeks, with a recommended cap of 604,800
/// seconds (7 days)" (RFC 8767 §4), so no configuration keeps an answer longer than the cap the
/// RFC recommends. The owner's ruling of 2026-10-11 (docs/design.md §16 decision 37).
/// 7 * 24 * 60 * 60.
pub const cache_ttl_seconds_max: u32 = 604_800;

/// The least `Config.cache_failure_seconds_min` may be, and the least time a cache keeps a
/// resolution failure: "Resolvers MUST cache resolution failures for at least 1 second" (RFC 9520
/// §3.2). Here because `Config` and the cache both hold the minimum to it (docs/design.md §16
/// decision 60).
pub const cache_failure_seconds_least: u32 = 1;

/// The most `Config.cache_failure_seconds_min` may be, and the longest time a cache keeps a
/// resolution failure, where the backoff stops: "resolution failures MUST NOT be cached for
/// longer than 5 minutes" (RFC 9520 §3.2, docs/design.md §16 decision 60). 5 * 60.
pub const cache_failure_seconds_max: u32 = 300;

/// The IANA Dynamic port range, which the source-port hint is drawn from (RFC 6335 §6).
pub const port_ephemeral_min: u16 = 49152;
pub const port_ephemeral_max: u16 = 65535;

/// The pins one TLS server may carry: a primary pin and the backup RFC 7858 §4.2 asks to deploy
/// with it, each with room to rotate. It is also chapulin's own bound (docs/design.md §21).
pub const spki_pins_max: usize = 4;

/// An address in text (`address_text.zig`): the decimal digits one octet of the dotted quad may
/// hold (RFC 1035 §3.4.1).
pub const address_v4_octet_digits_max: usize = 3;

/// The hexadecimal digits one group of an IPv6 address in text may hold (RFC 4291 §2.2 form 1).
pub const address_v6_group_digits_max: usize = 4;

/// The most lookup slots one resolver table may hold, which bounds a handle's index.
pub const lookup_slots_max: usize = 1024;

/// The most bits `CommonPrefixLen` counts (RFC 6724 §2.2): up to the source's prefix, which for
/// IPv6 stops before the interface identifier of RFC 4291 §2.5.1, 64 bits, and for IPv4 is the
/// whole address.
pub const common_prefix_bits_v6_max: usize = 64;
pub const common_prefix_bits_v4_max: usize = 32;

/// The most digits one octet needs in decimal in a reverse name (`name_reverse.zig`): 255.
pub const reverse_octet_digits_max: usize = 3;

/// The printable ASCII range a label may hold on input (`name_text.zig`): `!` through `~`.
/// Anything below is a control byte and anything above is not ASCII.
pub const text_printable_min: u8 = 0x21;
pub const text_printable_max: u8 = 0x7e;

// A constant with no type is a `comptime_int`, which takes the type of a narrow runtime value it
// meets in a sum. The lint rule reads the shape of each value, and this reads the type, so an
// alias or a call that gives a `comptime_int` is caught here (docs/design.md §16 decision 40).
test "each integer constant here has a type" {
    inline for (@typeInfo(@This()).@"struct".decls) |declaration| {
        const untyped = @TypeOf(@field(@This(), declaration.name)) == comptime_int;
        try std.testing.expectEqualStrings("", if (untyped) declaration.name else "");
    }
}
