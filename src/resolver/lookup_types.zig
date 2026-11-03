//! The values a lookup hands its caller, and the flags it carries (docs/design.md §5). Split
//! from `lookup.zig` by the file-length rule.
const core = @import("core");
const wire = @import("wire");
const Endpoint = core.Endpoint;
const Address = core.Address;
const Name = core.Name;
const Kind = core.Kind;
const failure_module = @import("lookup_failure.zig");
const Failure = failure_module.Failure;

/// What the caller should do next.
pub const Action = union(enum) {
    /// Send these bytes to this server over UDP. `local_port_hint` is a port in the Dynamic range
    /// the caller may bind; a caller that reuses one socket keeps the id and case entropy and
    /// loses the port entropy (docs/design.md §7).
    send_udp: struct { server: Endpoint, local_port_hint: u16, message_bytes: []const u8 },
    /// Open a TCP connection to this server, then call `on_tcp_connected` or `on_tcp_failed`.
    connect_tcp: Endpoint,
    /// Write these bytes to the connection. The two-octet length prefix is included
    /// (RFC 7766 §8). Then read two octets, call `wire.message_len`, read that many, and hand
    /// them to `on_response`.
    send_tcp: struct { message_bytes: []const u8 },
    /// Send these bytes to this server as one request, the server being
    /// `config.servers[server_index]`. Over DoH it is an HTTP request, whose GET carries
    /// `wire.doh.dns_variable` of the bytes (docs/design.md §22). Over DoQ it is a new QUIC
    /// stream, ended with FIN, and the bytes carry their length prefix (RFC 9250 §4.2, §23). Then
    /// call `on_sent`, and hand the answer to `on_request_answer` with `transaction`, the number
    /// of the lookup's transaction, or say the request failed with `on_request_failed`.
    send_request: struct { server_index: u8, message_bytes: []const u8, transaction: u16 },
    /// Nothing to do until this instant, in the caller's own monotonic nanoseconds.
    wait: u64,
    done: Answer,
    failed: Failure,
    /// A walk's lookup of a validating table ended: the walk has its message or its failure.
    /// Drop what is held for the handle, then call `Resolver.release`. No lookup the caller
    /// started ends so (docs/design.md §25 step 15, §17 question 100).
    walked,
};

/// Whether a datagram belonged to this lookup. Either way the caller polls afterwards.
pub const Verdict = enum { accepted, ignored };

pub const Answer = struct {
    kind: Kind,
    /// Slices into the lookup. Valid until the next call on it.
    addresses: []const Address,
    names: []const Name,
    /// The records kept for a question of any type but A, AAAA and PTR, `records.?.at(index)`
    /// for `index` below `record_count`, each readable through `wire.rdata`; null for the three
    /// (docs/design.md §19 step 9).
    records: ?*const wire.Records,
    record_count: u8,
    /// The end of the CNAME chain, when one was followed.
    canonical_name: ?*const Name,
    /// The CNAME links that reached `canonical_name`, from the name asked on, in the lookup's
    /// own storage: `aliases.at(index)` for `index` below `aliases.count` (docs/design.md §5).
    /// None when no CNAME was followed.
    aliases: *const core.Aliases = &core.Aliases.none,
    /// The smallest TTL over the records used, for a cache above cocuyo, no larger than the CNAMEs
    /// that reached them and no larger than the negative TTL of any search candidate before the
    /// one that answered. The answer is kept under the name as asked, and once that negative
    /// "MUST NOT be used again" (RFC 2308 §5) a new walk may stop at its candidate; zero when one
    /// of them carried no SOA (docs/design.md §5). An answer the table's memory recalled reports
    /// what the memory says is left of the life it gave the answer, which may be less than every
    /// record's own when the memory capped that life (docs/design.md §20). Each record's own
    /// `ttl_seconds` in `records` is bounded by neither the chain nor the walk, so a cache that
    /// keeps the records one by one under the name as asked keeps none longer than this TTL.
    ttl_seconds: u32,
    /// Whether records may be missing: the response held more than the lookup has room for, or
    /// it had TC set and was read all the same: over a stream, where there is no larger channel
    /// to ask over, or over UDP under `Config.ignore_truncation`. A cache keeps no answer marked
    /// so (RFC 1035 §7.4).
    truncated: bool,
    /// Whether the servers said they validated it: `authenticated` when the configuration relies
    /// on the AD bit and every message the lookup acted on had it set (docs/design.md §25).
    security: core.Security,
};

/// The flags one lookup carries, packed into an octet so the hot block stays inside a cache line.
/// Whether a server failed the lookup is not one of them: the lookup's `cause` says it
/// (docs/design.md §5, The cause of a failure).
pub const Flags = packed struct(u8) {
    /// Whether the query carries an OPT record. Cleared for one server that answers FORMERR, and
    /// set again when the lookup moves to another server or another name: that a server does
    /// not speak EDNS0 is a fact about that server (RFC 6891 §6.2.2).
    edns_enabled: bool,
    /// Whether the qname's case may be randomised (DNS-0x20): `Config.mix_case`, and never over
    /// DoH or DoQ (docs/design.md §7, §22, §23).
    mix_case: bool,
    /// Whether any candidate answered NOERROR with no record of this type.
    had_no_data: bool,
    /// Whether a CNAME was followed, which makes the current name the canonical one.
    aliased: bool,
    /// Whether a BADCOOKIE was already answered with a retry on this server (RFC 7873 §5.3),
    /// over UDP or over a stream: the server's one retry, whichever transport took it.
    cookie_retried: bool,
    /// Whether `order` has been computed, which the first poll does with the clock in hand
    /// (docs/design.md §19 step 12).
    ordered: bool,
    /// Whether the query last built mixed the case of its name: `mix_case`, unless its server
    /// lowercases the name, and then the query carried the name in lowercase. What check 5
    /// compares a response with, whatever another lookup taught the server since
    /// (docs/design.md §7, A server that changes the case).
    query_mixed: bool,
    /// Whether a reply to the query last sent marked its server as one that lowercases the name.
    /// The reply shows that the server answered this try in time. So the try is no sample when it
    /// runs out (docs/design.md §5, §16 decision 50). `on_sent` clears it.
    reply_marked: bool,
};
