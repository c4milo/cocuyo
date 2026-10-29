# cocuyo — DNS resolver design document

cocuyo is a DNS resolver library in Zig. It builds query bytes and parses response bytes. It owns
no socket, no file descriptor, no thread, no timer and no allocator. The caller does the sending
and the receiving; cocuyo says what to do next.

The name is the Colombian word for the firefly, and for a car's hazard lights: a small light that
shows the way while somebody else does the walking.

cocuyo is a standalone library. It names no consumer, and it takes no decision that only makes
sense inside one.

This document is the plan. Nothing in `src/` exists yet. Sections are cited by number in commits
and comments ("§5 step 3").

## 1. Scope, and agreement with the split

The split asked for is the right one, and it is the whole design: the protocol is a value-in,
value-out state machine, and I/O belongs to the caller. c-ares conflates the two, which is why
embedding it means bolting `ARES_OPT_SOCK_STATE_CB` and `ares_process` onto whatever loop you
already have. A resolver is a parser of hostile input; a parser that can only be tested against a
live network cannot be tested.

I am not proposing a different split. I am proposing four refinements inside it, each with the
alternative it beat recorded in §16.

1. **Two layers, not one.** `Lookup` is one lookup's state machine. `Resolver` is a bounded table
   of `Lookup` slots plus the code that decides which lookup an inbound datagram belongs to. The
   second layer exists because that decision is security-critical (§7) and every caller would
   otherwise write it again.
2. **The caller owns the send buffer.** `poll` builds the query into a buffer the caller passes,
   rather than into a buffer inside each slot. A query is rebuilt on each retransmission and is
   byte-identical, because the transaction id and the case pattern are stored.
3. **The caller owns the receive buffer, and frames the TCP stream.** cocuyo hands the caller the
   two-byte length prefix rule and a helper to read it, instead of holding a 64 KiB reassembly
   buffer per lookup.
4. **Time and entropy enter as values.** `now_ns` is a parameter on every entry point. Entropy
   enters once as a `u64` seed per lookup and drives a small internal generator, so a CNAME
   re-query can draw a fresh transaction id without a round trip to the caller.

### What version one does

- `A`, `AAAA` and `PTR` lookups, one question per lookup.
- Query construction and response parsing: RFC 1035, with RFC 3596 for `AAAA`.
- Name compression on parse, RFC 1035 §4.1.4, bounded and iterative (§8).
- CNAME chains, bounded, with owner-name checking inside the message.
- EDNS0, RFC 6891, including the FORMERR fallback that real servers need.
- TCP fallback on a truncated reply, RFC 7766, including the two-byte length prefix.
- Retry and timeout as state. cocuyo says how long to wait and what to do when the wait expires.
- `resolv.conf` parsing as a separate module the state machine cannot import (§10).

### What version one does not do

Each of these is out of scope on purpose, with the place it would attach.

- **A cache, since 2026-09-22, and above the library.** Version one was planned without one:
  `Answer.ttl_seconds` is reported and `Lookup` touches no socket, so a cache wraps
  `Resolver.start` from above without changing the state machine. What decided it was that
  **c-ares caches by default.** Its `ares_init_options(3)` says the query cache has been on since
  c-ares 1.31.0 with a one-hour ceiling, caching successful and NXDOMAIN results and flushing on
  a server configuration change, so a consumer swapping c-ares for a cocuyo without one would
  send every query it used to answer from memory. §17 asked; the owner answered yes; §18 is the
  design, and the `cache` module of §2 is the one place the answer touched, with `Failure`
  gaining the negative TTL a cache needs.
- **No DNSSEC validation.** What a validator would build on: EDNS0 exists, the DO bit is a flag cocuyo never sets, and the
  record iterator hands out rdata unread, so a validator sits above the codec. Since 2026-09-26 a
  question may name a DNSSEC type, DS or DNSKEY among them, as it may name any type (decision
  31). Its records come back as rdata, unread and unvalidated, as any type cocuyo does not name.
  The owner ruled that out of scope means validating, not fetching.
- **DNS over TLS and DNS over HTTPS, since 2026-09-23.** Out of version one; the owner brought
  both in on 2026-09-23, with three rulings. DoT (RFC 7858) is the engine's: rotor carries the
  TCP, chapulin, the owner's TLS 1.3 client, carries the TLS through its non-blocking record
  transport, and the library itself stays without TLS, since the stream path already produces
  the length-prefixed messages DoT sends. Authentication is strict by default (RFC 8310): a
  server whose name does not verify fails the lookup rather than falling back to plaintext.
  DoH (RFC 8484) is split: cocuyo supplies its DNS half, and colibri's HTTP/2 or HTTP/3 carries
  it. The first ruling put that HTTP in colibri's driver. Since 2026-09-25 the engine drives it,
  because colibri owns no I/O, and colibri's library never uses cocuyo (§24). The owner added DoH
  over HTTP/3 the same day. RFC 8484 names HTTP/2 as the least
  version it recommends (§5.2), so HTTP/3 carries DoH as it is: the HTTP stays colibri's, and
  cocuyo's DNS half is the same for both. Since 2026-09-26 a DoH server is tried over HTTP/3
  first and over HTTP/2 when that fails (RFC 9114 §3.1, decision 30). §21 is DoT's plan and the rulings that shape it, and
  §22 is DoH's DNS half.
- **DNS over QUIC, since 2026-09-23.** The owner put DoQ (RFC 9250) after DoT and DoH's DNS
  half, and split it as DoH is: cocuyo supplies the DNS half, and colibri's QUIC carries it,
  driven by the engine since 2026-09-25 (§24). §23 is its plan and the rulings that shape it.
- **No mDNS and no zone transfers.** Out: neither is a stub resolver's.
- **Record types beyond `A`, `AAAA`, `PTR` and `CNAME`; `/etc/hosts`; A-plus-AAAA in one call;
  TCP reuse and pipelining; DNS cookies; server failover.** Out of version one, and in since
  2026-09-22 by §19's plan, which says where each lands: the record types, the cookies and the
  failover in the core, the hosts file in `config`, the joined lookup and the TCP pool in the
  engine of §19 step 13. nsswitch and NIS stay out.

## 2. Module graph

`build.zig` declares each module with its imports listed, so the dependency direction is enforced
by the build rather than by review.

| Module | Imports | Holds |
| --- | --- | --- |
| `core` | nothing | types, limits, errors, `Name`, `Address`, `Config` |
| `wire` | `core` | the codec: build a query, parse a response |
| `resolver` | `core`, `wire` | `Lookup`, `Resolver`, retry policy, entropy |
| `config` | `core` | the `resolv.conf` parser |
| `cache` | `core`, `wire` | the answer cache of §18, above the state machine and never inside it |
| `sim` | `core`, `wire`, `resolver` | the scripted server and the virtual clock, test-only |
| `io` | `cocuyo`, `rotor`, and colibri's `quic` and `h3` from §24 | the engine of §19 step 13: sockets, timers and connections over a loop with rotor's surface, in `io/`; compiled against `sim` for the gate and against rotor for the comparison of step 15, and exported into the caller's loop by §24 |

`resolver` cannot import `config`. That is the split between the state machine and the config
parser, made structural: `Config` is a `core` type, the parser is one producer of it, and the
state machine cannot reach the parser even by accident.

The library root, `src/cocuyo.zig`, re-exports `core`, `wire`, `resolver`, `config` and `cache`,
so a consumer writes `cocuyo.Lookup`, `cocuyo.resolv_conf.parse` and `cocuyo.Cache`. `sim` is
never packaged.

### What the build depends on

The library in `src/` depends on nothing. Each other dependency is of one part of the build.
`build.zig.zon` pins each by hash, as a lazy dependency that only the root build requests:

- pepegrillo, of the tools (§17 question 1).
- rotor, of the examples and of the comparison with c-ares (§17 question 8).
- colibri, of the engine's DoT, DoQ and DoH, and of the tools (§16 decisions 29, 32 and 33).
  No module rooted in `src/` reaches it.
- stdx, of the DoT, DoQ and DoH examples alone, for the probe that the word `cpu` turns on (§16
  decision 48, as amended on 2026-10-20). No module rooted in `src/` reaches it. A module rooted
  in `io/` reaches it only through colibri, whose `tls` and `client` import stdx.

`zig build graph-check` reads the module graph that the build made, at any depth. It fails when a
module rooted in `src/` reaches a module of stdx or of colibri. It also fails when a module rooted
in `io/` reaches a module of stdx other than through a module of colibri.

### File layout

```text
src/cocuyo.zig                 the public surface, re-exports only
src/core/     core.zig constants.zig limits.zig address.zig name.zig name_text.zig config.zig
              errors.zig address_text.zig hosts.zig address_order.zig (§19 steps 14 and 15)
src/wire/     wire.zig wire_header.zig wire_name.zig wire_question.zig wire_record.zig
              wire_query.zig wire_response.zig wire_edns.zig wire_fuzz.zig constants.zig
              limits.zig
src/resolver/ resolver.zig lookup.zig lookup_poll.zig lookup_response.zig lookup_policy.zig
              entropy.zig constants.zig limits.zig address_lookup.zig (§19 step 14)
src/config/   resolv_conf.zig resolv_conf_options.zig constants.zig limits.zig
src/cache/    cache.zig cache_keys.zig cache_chain.zig cache_sweep.zig cache_storage.zig
              constants.zig limits.zig
src/sim/      sim.zig sim_types.zig sim_loop.zig sim_loop_perform.zig sim_network.zig
              sim_server.zig sim_buffers.zig constants.zig limits.zig fixtures.zig
              sim_scenarios_test.zig
io/           io.zig io_drive.zig io_events.zig io_udp.zig io_results.zig constants.zig
              limits.zig fixtures.zig io_sim_test.zig
examples/udp_blocking.zig examples/udp_rotor.zig
bench/
docs/design.md docs/decisions.md docs/mutations.md
```

Rules that hold everywhere: no file in `src/` names an allocator; every file stays at or under 500
lines with its tests; tests live in the file they test; four or more files sharing a prefix move
into a directory named for it, each piece keeping its full name and the original name staying as
the entry point.

## 3. What the caller supplies

| Thing | How it arrives | Note |
| --- | --- | --- |
| Lookup storage | `var slots: [N]cocuyo.Lookup = undefined;` | §9 gives the size |
| Match keys | `var keys: [2*N]cocuyo.MatchKey = undefined;` | power-of-two length, §11 |
| Cache memory | `var cache_memory: cocuyo.cache.Storage(M) = undefined;` | optional; §18 gives the size, the bounds and the form for a count read at run time |
| Send buffer | `poll(now_ns, out)` | `out.len >= query_bytes_max` |
| Receive buffer | the caller's own | at least `config.udp_payload_bytes` |
| Servers and search list | `Config`, caller-owned slices | must outlive the lookups |
| Time | `now_ns` on every entry point | monotonic, non-decreasing, asserted |
| Entropy | a `u64` seed per lookup | must come from a CSPRNG; §7 says why |
| Sockets, connects, reads, writes | the caller performs them | cocuyo makes no syscall |

## 4. The public API

```zig
/// Every type c-ares parses, since §19 step 9; the full list with each type's RFC is there. Open
/// since 2026-09-26 (decision 31): `Kind.of(code)` is any type, named or not.
pub const Kind = enum(u16) { a = 1, ns = 2, cname = 5, soa = 6, ptr = 12, hinfo = 13, mx = 15, txt = 16,
    sig = 24, aaaa = 28, srv = 33, naptr = 35, opt = 41, tlsa = 52, svcb = 64, https = 65, any = 255,
    uri = 256, caa = 257, _ };
pub const Family = enum(u8) { ipv4, ipv6 };
/// An `extern struct`, because the answers' union holds it (decision 34).
pub const Address = extern struct { family: Family, octets: [16]u8 };
pub const Endpoint = struct { address: Address, port: u16 };

/// A name in uncompressed wire form, root label included. An `extern struct`, because the answers'
/// union holds it (decision 34).
pub const Name = extern struct {
    bytes: [name_bytes_max]u8,
    len: u8,

    pub const root: Name;  // "."
    pub const empty: Name; // a builder: no label yet, not a name until terminated

    pub fn from_text(text: []const u8) Error!Name;
    pub fn write_text(self: *const Name, out: []u8) usize; // out.len >= name_text_bytes_max
    pub fn equal(self: *const Name, other: *const Name) bool; // case-insensitive, per RFC 4343
    pub fn wire(self: *const Name) []const u8;
    pub fn is_root(self: *const Name) bool;
    pub fn label_count(self: *const Name) u8;
    pub fn dot_count(self: *const Name) u8;               // what ndots counts
    pub fn concat(self: *const Name, suffix: *const Name) Error!Name; // a search candidate
    pub fn append_label(self: *Name, label: []const u8) Error!void;   // the codec builds with
    pub fn terminate(self: *Name) Error!void;                         // these two
};

pub const Question = struct {
    name: Name,
    kind: Kind,
    /// Whether the name was written absolute, with a trailing dot. Wire form cannot record it and
    /// the search-list policy of §5 turns on it, so the question carries it.
    absolute: bool = false,

    /// `Error.UnqueryableType` for a type never asked for (§19 step 9, Questions).
    pub fn from_text(text: []const u8, kind: Kind) Error!Question;
    /// The reverse question: the in-addr.arpa or ip6.arpa name for an address, always absolute.
    pub fn from_address(address: *const Address) Error!Question;
};

/// One server: its UDP endpoint, and a TCP port of its own when it has one (§19 step 11).
pub const Server = struct { endpoint: Endpoint, tcp_port: u16 = 0 };
/// Where the engine looks a name up, in `Config.lookups` order: `.file` is the hosts file.
pub const Source = enum { file, dns };

pub const Config = struct {
    servers: []const Server,      // none when a resolv.conf named none and the default was refused
    search: []const Name,
    ndots: u8 = ndots_default,
    attempts: u8 = attempts_default,
    timeout_ns: u64 = timeout_ns_default,         // 2 s: a wait before 3 samples (§5)
    timeout_ns_max: u64 = timeout_ns_max_default, // 5 s: the cap on every wait (c-ares maxtimeout)
    udp_payload_bytes: u16 = udp_payload_bytes_default, // in OPT; the engine takes udp_payload_bytes_max at most
    mix_case: bool = true,        // DNS-0x20, but lowercase to a server that lowercases (§7)
    rotate: bool = false,
    use_tcp: bool = false,        // every query over TCP (use-vc, ARES_FLAG_USEVC)
    ignore_truncation: bool = false, // a truncated UDP answer taken, marked so (ARES_FLAG_IGNTC)
    recursion_desired: bool = true,  // the RD bit (ARES_FLAG_NORECURSE clears it)
    check_response: bool = true,  // off: SERVFAIL, REFUSED and NOTIMP end the lookup as its answer
    primary: bool = false,        // the first server alone (ARES_FLAG_PRIMARY)
    lookups: []const Source = &.{ .file, .dns },
    failover_retry_chance: u8 = 10,          // one query in this many retries a failed server first
    failover_retry_delay_ns: u64 = 5 s,      // once this long has passed since it failed
    local_address: ?Address = null,          // what the engine binds its sockets to (ARES_OPT_LOCAL_IP4/6)
    socket_receive_bytes: u32 = 0,           // what the kernel is asked for on each socket; 0 leaves its own
    socket_send_bytes: u32 = 0,              // the same for the send buffer
    udp_queries_per_port: u32 = 0,           // queries one source port carries (udp_max_queries); 0 keeps it
    cache_ttl_seconds_max: u32 = 3600,       // the cap on every TTL the engine's cache keeps (qcache_max_ttl)
    cache_failure_seconds_min: u32 = 5,      // the first time a cache keeps a resolution failure (RFC 9520 §3.2)
};
```

`cache_ttl_seconds_max` joined on 2026-10-11 (§16 decision 37). Like `local_address` and the
socket sizes, the engine reads it and a lookup never does: the engine hands it to the cache it
builds, at `init` and at each `reinit` (§19 step 13). A caller that builds a `Cache` of its own
hands `Cache.init` this field, or a cap of its own (§18). `assert_valid` requires at least 1 and
at most seven days, `cache_ttl_seconds_max`, the cap RFC 8767 §4 recommends (decision 37).

`cache_failure_seconds_min` joined on 2026-10-27 (§16 decision 60). It is the first time a cache
keeps a resolution failure of a name. The engine hands it to the cache it builds, as it hands
the cap. A caller that builds a `Cache` of its own sets `Cache.failure_seconds_min` from it after
`init`. `assert_valid` requires 1 s to 300 s, `cache_failure_seconds_least` and
`cache_failure_seconds_max` (RFC 9520 §3.2).

### One lookup

```zig
/// Per-server state every lookup of a caller shares: the DNS cookies of §19 step 10, the failover
/// counters of step 12, the latency samples a server's wait comes from (§5), and whether a server
/// lowercases the name (§7). `Resolver` holds one; a caller driving a `Lookup` alone builds one.
pub const Servers = struct {
    pub fn init(config: *const Config, seed: u64) Servers;
};

pub const Lookup = struct {
    pub fn init(config: *const Config, servers: *Servers, question: Question, seed: u64) Lookup;
    /// `init` into memory the caller owns, which is what `Resolver` does with its slots (§11).
    pub fn init_in_place(self: *Lookup, config: *const Config, servers: *Servers, question: Question, seed: u64) void;
    pub fn poll(self: *Lookup, now_ns: u64, out: []u8) Action;
    pub fn on_sent(self: *Lookup, now_ns: u64) void;
    pub fn on_send_failed(self: *Lookup, now_ns: u64) void;
    pub fn on_response(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict;
    /// Since 2026-10-14: a datagram longer than the caller's buffer, which the kernel cut and
    /// marked (§7, A datagram that the buffer cut).
    pub fn on_datagram_cut(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict;
    pub fn on_tcp_connected(self: *Lookup, now_ns: u64) void;
    /// Since 2026-10-21 with the reason the connection failed (§5, The cause of a failure).
    pub fn on_tcp_failed(self: *Lookup, reason: Reason, now_ns: u64) void;
    /// Over DoH or DoQ (§22, §23): the answer to the transaction `send_request` named, and its
    /// `Age` over DoH; or the request ended without one, and why.
    pub fn on_request_answer(self: *Lookup, transaction: u16, message: []const u8, age_seconds: u32, now_ns: u64) Verdict;
    pub fn on_request_failed(self: *Lookup, transaction: u16, reason: Reason, now_ns: u64) void;
    pub fn cancel(self: *Lookup) void;
};

pub const Action = union(enum) {
    send_udp: struct { server: Endpoint, local_port_hint: u16, message_bytes: []const u8 },
    connect_tcp: Endpoint,
    send_tcp: struct { message_bytes: []const u8 }, // length prefix included
    // One request to `config.servers[server_index]`: an HTTP request over DoH (§22), whose GET
    // carries the bytes' `wire.doh.dns_variable`, or a QUIC stream over DoQ (§23), whose bytes
    // carry the length prefix. The answer names `transaction`.
    send_request: struct { server_index: u8, message_bytes: []const u8, transaction: u16 },
    wait: u64,                                      // absolute deadline, monotonic nanoseconds
    done: Answer,
    failed: Failure,
};

pub const Verdict = enum { accepted, ignored };

pub const Answer = struct {
    kind: Kind,
    addresses: []const Address,   // slices into the lookup's own storage
    names: []const Name,          // PTR results; addresses, names and records share storage
    records: ?*const wire.Records, // every other type (§19 step 9): `records.?.at(i)` for i below
    record_count: u8,             // `record_count`, each a `wire.Kept` the views of `wire.rdata` read
    canonical_name: ?*const Name, // the end of the CNAME chain, when there was one
    ttl_seconds: u32,             // the minimum TTL over the records used, bounded by the chain and
                                  // the search walk's negatives (§5); on a hit, what is left; each
                                  // record's own TTL is bounded by neither
    truncated: bool,              // records may be missing: no room for them, or TC set
};

/// One kept record: the type as the octets said it, the TTL, and self-contained rdata with every
/// name written out in full, so `wire.rdata.Mx.parse(kept.rdata)` and the others need no message.
pub const Kept = struct { kind_code: u16, ttl_seconds: u32, rdata: []const u8 };

pub const Failure = struct {
    err: Error,
    server_index: u8,
    attempts_made: u8,
    negative_ttl_seconds: u32, // NameNotFound, NoData: the SOA minimum (§18), else zero; the
                               // smallest of a lookup's walk (§5); for AddressLookup and
                               // NameLookup, the last lookup's that failed (§19 step 14)
    cause: ?Cause,             // since 2026-10-17: the last server failure the lookup met, null
                               // when none did; never null for AllServersFailed, always for Timeout
};

/// What made a server fail a lookup, and that server (§5, The cause of a failure; §16 decisions
/// 45 and 51). Since 2026-10-21 a struct of three octets, which leaves `Failure` at 12.
pub const Cause = struct {
    server_index: u8, // the server that gave the cause, in `config.servers`; `Failure.server_index`
                      // is the one the lookup was on at its end, after the last pass the first
    what: What,

    pub const What = union(enum) {
        rcode: wire.Rcode, // SERVFAIL, REFUSED, NOTIMP or BADVERS; FORMERR without EDNS0; a
                           // BADCOOKIE that advances the server
        reason: Reason,    // what the caller passed on_tcp_failed or on_request_failed
    };
};

/// Why a transport failed a lookup: what the caller passes on_tcp_failed and on_request_failed
/// (§5, The cause of a failure; §16 decision 51).
pub const Reason = enum(u8) {
    connect,   // the connect failed; before on_tcp_connected, or over DoH
    handshake, // the TLS handshake failed, or over DoQ the QUIC handshake; before on_tcp_connected
    local,     // no server took part: no socket, no slot, no TCP, nothing the loop took
    closed,    // a connection that was up failed, or a send on it; the one reason after
               // on_tcp_connected
    status,    // over DoH, a response that holds no DNS message: a status that is not 2xx, and more
    reset,     // over DoH or DoQ, a stream that the server reset or refused
};
```

`cancel` is for a lookup that has not ended, and cancelling one that is done is a programmer
error. `Resolver.cancel` is the one to call with a handle whose lookup may have ended: it leaves
that lookup's end standing.

`on_response` never changes what the caller does next: the caller always calls `poll` afterwards.
`ignored` exists for counters and tests. A response that arrives after `.done`, for a cancelled
lookup, or from the wrong place, is `ignored` in any state — a stray late datagram is normal for a
caller with one socket, so it is an operational event, not a programmer error.

### Many lookups

```zig
pub const MatchKey = packed struct(u32) { transaction_id: u16, slot: u16 };
pub const Handle = packed struct(u32) { index: u16, generation: u16 };

/// One slot: a lookup, and the few octets the table keeps beside it.
pub const Slot = struct {
    lookup: Lookup,
    generation: u16,
    occupied: bool,
    keyed_id: u16,
    next_free: u16,
};

pub const Resolver = struct {
    pub fn init(slots: []Slot, keys: []MatchKey, config: *const Config, seed: u64) Resolver;
    pub fn start(self: *Resolver, question: Question) error{NoSlot}!Handle;
    /// Null when there is nothing to do now. Each lookup is offered once for each thing it has
    /// to do, and offered again when an event gives it something new, so a caller acts on what
    /// it is given rather than polling again to be reminded (§11, §16 decision 20).
    pub fn poll(self: *Resolver, now_ns: u64, out: []u8) ?Event;
    /// A bound on the soonest deadline, never later than it: the timer can fire early and the
    /// poll that follows finds the soonest again.
    pub fn next_deadline_ns(self: *const Resolver) ?u64;
    pub fn on_datagram(self: *Resolver, message: []const u8, from: Endpoint, now_ns: u64) Verdict;
    /// Since 2026-10-14: a datagram that the kernel cut and marked, as `Lookup.on_datagram_cut`
    /// takes it (§7).
    pub fn on_datagram_cut(self: *Resolver, message: []const u8, from: Endpoint, now_ns: u64) Verdict;

    // Every event goes through the table rather than through the lookup, because each one can
    // move the instant the table is waiting for, and the timer it hands out has to follow.
    pub fn on_sent(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_send_failed(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_tcp_connected(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_tcp_failed(self: *Resolver, handle: Handle, reason: Reason, now_ns: u64) void;
    // Over DoH or DoQ (§22, §23) an answer comes by handle: HTTP or QUIC paired it with its query.
    pub fn on_request_answer(self: *Resolver, handle: Handle, transaction: u16, message: []const u8, age_seconds: u32, now_ns: u64) Verdict;
    pub fn on_request_failed(self: *Resolver, handle: Handle, transaction: u16, reason: Reason, now_ns: u64) void;

    pub fn cancel(self: *Resolver, handle: Handle) void;
    /// Frees the slot. Every slice an answer handed out points into it and dies here.
    pub fn release(self: *Resolver, handle: Handle) void;
    pub fn lookup_of(self: *Resolver, handle: Handle) *Lookup;
    pub fn in_flight(self: *const Resolver) usize;
};

pub const Event = struct { handle: Handle, action: Action };
```

A caller that has its own table of in-flight requests uses `Lookup` directly and skips `Resolver`.
It then owns the matching rules of §7, and the documentation says so in those words.

### The `getaddrinfo` shape (§19 step 14)

```zig
pub const AddressFlags = packed struct {
    canonical_name: bool = false, // ai_canonname: the chain's end, or the hosts entry's official name
    numeric_host: bool = false,   // the name must be an address: no file, no query (AI_NUMERICHOST)
    v4_mapped: bool = false,      // with family .ipv6: A addresses as ::ffff:a.b.c.d when no AAAA came
    all: bool = false,            // with v4_mapped: AAAA and the mapped A both
    no_sort: bool = false,        // the order received, not §19 step 15's (ARES_AI_NOSORT)
};

/// Two lookups joined the way getaddrinfo(3) joins them, above the table (§16 decision 18).
pub const AddressLookup = struct {
    pub fn init(resolver: *Resolver, hosts: ?*const Hosts, name: []const u8, family: ?Family,
        flags: AddressFlags) error{ NoSlot, NameTooLong, LabelTooLong }!AddressLookup;
    /// A `.done` or `.failed` event of the resolver. True when the handle was this lookup's, and
    /// then the slot is released here; the consumer releases only what this refused.
    pub fn on_event(self: *AddressLookup, event: Event) bool;
    pub fn outcome(self: *const AddressLookup) ?AddressOutcome; // null while lookups are in flight
    pub fn cancel(self: *AddressLookup) void;
};

pub const AddressOutcome = union(enum) { answered: AddressInfo, failed: Failure };

/// The reverse: an address in, the name that answers for it out (§19 step 14). The hosts table
/// and DNS in the `lookups` order, and one PTR question, whose name the address builds.
pub const NameLookup = struct {
    pub fn init(resolver: *Resolver, hosts: ?*const Hosts, address: *const Address) InitError!NameLookup;
    pub fn on_event(self: *NameLookup, event: Event) bool;
    pub fn outcome(self: *const NameLookup) ?NameOutcome; // null while the lookup is in flight
    pub fn cancel(self: *NameLookup) void;
};
pub const NameOutcome = union(enum) { answered: NameInfo, failed: Failure };
pub const NameInfo = struct { name: *const Name, ttl_seconds: u32, from_hosts: bool };

/// The EDNS0 options of a response, read for the caller rather than for the state machine
/// (§19 step 10). Each takes the OPT record's rdata, which `response_opt.find` gives.
pub const edns_options = struct {
    pub fn nsid(rdata: []const u8) Error!?[]const u8;          // RFC 5001 §2.3
    pub fn padding(rdata: []const u8) Error!?[]const u8;        // RFC 7830 §3, at most once
    pub fn client_subnet(rdata: []const u8) Error!?ClientSubnet; // RFC 7871 §6
    pub fn extended_error(rdata: []const u8) Error!?ExtendedError; // RFC 8914 §2
};

pub const AddressInfo = struct {
    addresses: []const Address,   // into the lookup's own storage: valid for its lifetime
    canonical_name: ?*const Name,
    ttl_seconds: u32,             // the answers' smallest, with no walk bound (§19 step 14)
    truncated: bool,
    partial: ?Error,              // one family answered and the other failed with this
};

/// What the consumer knows about reaching one address (§19 step 15): the source its host would
/// use, learned by connecting a datagram socket or read from a routing table, and the flags.
pub const Route = struct {
    source: ?Address = null,
    known_unreachable: bool = false,
    deprecated: bool = false,
    home: bool = false,
    care_of: bool = false,
    encapsulated: bool = false,
};
/// RFC 6724 §6 over `addresses`, in place and stable. `routes[i]` describes `addresses[i]`;
/// null applies the rules that need no source.
pub fn order(addresses: []Address, routes: ?[]const Route) void;
```

## 5. The state machine

```text
            init
              |  poll
              v
        query_ready ---------------- on_send_failed ---> (next server) query_ready | failed
              |  poll -> send_udp
              |  on_sent
              v
        awaiting_udp --- poll at deadline ---> (next server or attempt) query_ready | failed
              |      \
              |       \-- on_response accepted, chain continues --> query_ready
              |        \- on_response accepted, answer complete --> done
              |  TC=1
              v
        tcp_needed --poll--> connecting_tcp --on_tcp_connected--> tcp_ready
                                   |                                  | poll -> send_tcp
                                   | on_tcp_failed                    | on_sent
                                   v                                  v
                            (next server)                       awaiting_tcp --> done | failed
```

Eight states: `query_ready`, `awaiting_udp`, `tcp_needed`, `connecting_tcp`, `tcp_ready`,
`awaiting_tcp`, `done`, `failed`. `init` is `query_ready` with nothing built yet.

### Transitions

| State | Event | Next state | Effect |
| --- | --- | --- | --- |
| `query_ready` | `poll` | `query_ready` | build the query into `out`, return `send_udp` |
| `query_ready` | `on_sent` | `awaiting_udp` | arm the deadline |
| `query_ready` | `on_send_failed` | `query_ready` or `failed` | advance the server |
| `awaiting_udp` | `poll` before the deadline | unchanged | return `wait` |
| `awaiting_udp` | `poll` at or past it | `query_ready` or `failed` | a sample as long as the wait, unless a reply to the try marked its server (§7), then advance the server, then the attempt |
| `awaiting_udp` | `on_response` unmatched | unchanged | return `ignored`, the wait stands |
| `awaiting_udp` | `on_response` with TC=1 | `tcp_needed`, or `query_ready` or `failed` | keep the same server; when it has no query left on a stream, advance the server and keep no cause |
| `awaiting_udp` | `on_datagram_cut` that passes the checks of a cut datagram (§7) | `tcp_needed`, or `query_ready` or `failed` | keep the same server, and take no sample; when it has no query left on a stream, advance the server and keep no cause |
| `awaiting_udp` | `on_response` with a CNAME and no answer | `query_ready` | new transaction, hop count up |
| `awaiting_udp` | `on_response` with an answer | `done` | copy the records out |
| `awaiting_udp` | `on_response` NXDOMAIN or NODATA | `query_ready` or `failed` | keep the smaller negative TTL, advance the search candidate |
| `awaiting_udp` | `on_response` YXDOMAIN | `failed` | `NameTooLong`, with no next server and no next candidate (§16 decision 57) |
| `awaiting_udp` | `on_response` SERVFAIL, REFUSED, NOTIMP | `query_ready` or `failed` | keep the rcode as the cause, advance the server |
| `awaiting_udp` | `on_response` FORMERR and EDNS0 was on | `query_ready` or `failed` | same server, EDNS0 off; when it has no query left over the transport the lookup starts on, keep the rcode as the cause and advance the server |
| `awaiting_udp` | `on_response` FORMERR and EDNS0 was off | `query_ready` or `failed` | keep the rcode as the cause, advance the server, as SERVFAIL does |
| `awaiting_udp` | `on_response` BADCOOKIE, the first from this server | `query_ready` or `failed` | same server, the fresh cookie; when it has no query left over UDP, keep the rcode as the cause and advance the server |
| `awaiting_udp` | `on_response` BADCOOKIE again | `tcp_needed`, or `query_ready` or `failed` | same server, over TCP; when it has no query left on a stream, keep the rcode as the cause and advance the server |
| `tcp_needed` | `poll` | `connecting_tcp` | return `connect_tcp`, arm the deadline |
| `connecting_tcp` | `on_tcp_connected` | `tcp_ready` | re-arm the deadline |
| `connecting_tcp` | `on_tcp_failed` with `connect`, `handshake` or `local` | `query_ready` or `failed` | keep the reason as the cause, advance the server, as SERVFAIL does |
| `connecting_tcp` | deadline | `query_ready` or `failed` | advance the server |
| `tcp_ready` | `poll` before the deadline | `tcp_ready` | build with the length prefix, return `send_tcp` |
| `tcp_ready` | `on_sent` | `awaiting_tcp` | arm the deadline |
| `tcp_ready` | `poll` at or past the deadline | `query_ready` or `failed` | no sample, since no query went out whole, then advance the server, then the attempt (§16 decision 52) |
| `tcp_ready`, `awaiting_tcp` | `on_tcp_failed` with `closed` | `query_ready` or `failed` | keep the reason as the cause, advance the server, as SERVFAIL does |
| `awaiting_tcp` | `on_response` | as the UDP rows | TC=1 sends the lookup nowhere, so the message is read as if it were clear, and an answer it gives is marked `truncated` |
| `awaiting_tcp` | `on_response` BADCOOKIE, the first from this server | `tcp_needed`, or `query_ready` or `failed` | same server, a new transaction on the stream, the fresh cookie; when it has no query left on a stream, keep the rcode as the cause and advance the server |
| `awaiting_tcp` | `on_response` BADCOOKIE again | `query_ready` or `failed` | keep the rcode as the cause, advance the server, as SERVFAIL does |
| `awaiting_tcp` | `poll` at or past the deadline | `query_ready` or `failed` | a sample as long as the wait, unless a reply to the try marked its server (§7), then advance the server, then the attempt |
| `done`, `failed` | any | unchanged | `poll` returns the same value; `on_response` is `ignored` |

Since 2026-10-27 no server gets more than three queries of one name over one transport (§16
decision 58). "A resolver MUST NOT retry a given query to a server address over a given DNS
transport more than twice (i.e., three queries in total)" (RFC 9520 §3.1). The rules:

- The lookup counts the queries that it sent for the current name, for each position in its order
  and for each transport. The transports are the datagram, over UDP or as a DoH or DoQ request,
  and the stream, over TCP or TLS. A query counts at `on_sent`. A send that failed does not count.
- To advance the server is to move to the next position with a query left. The transport is the
  one the lookup starts on: the stream under `use_tcp` or TLS, and the datagram otherwise. The
  walk passes over each other position, and the next pass and the end come as before. So when no
  server is left, the lookup ends as the last pass ends.
- A retry on the same server goes only when that server has a query left over the retry's
  transport. Each retry row of the table says what the lookup does when it has none.
- A new name, the next search candidate or a CNAME's target, is another query. Its counts start
  at zero. The pass and the order do not change.
- To pass over a server records no failure and no sample of it. The lookup sent it nothing.

Every row that accepts a response first takes a sample of its server's latency, which the next
deadline armed for that server reads (retry and timeout policy, below). So does a deadline that
passes in `awaiting_udp` or `awaiting_tcp`, with a sample as long as the wait that try used. A
response the lookup ignores, unmatched or malformed, takes none, and neither does a deadline that
passes in `connecting_tcp`, since no query went out. Since 2026-10-20 a deadline that passes
after a reply to the try marked its server takes none either (below).

Since 2026-10-24 a deadline ends `tcp_ready` too (§16 decision 52). `on_tcp_connected` arms it,
and the send of the query does not stop it. So a peer that stops reading holds a lookup until its
deadline, and no longer until the caller cancels it. The deadline counts a failure of the server,
as in `connecting_tcp`, and takes no sample: the query's send did not end, so no wait for an
answer began. The lookup moves on, and leaves its connection (§19 step 13, the stream's rule 3).
When it was the last lookup on the connection, the engine then shuts the connection at once, and
the shut cancels the send (§16 decision 53).

The row of a cut datagram is the one exception, since 2026-10-14. It accepts the datagram and
takes no sample, and it tells the server's state nothing (§7, A datagram that the buffer cut). A
cut datagram is `ignored` in each other state, over DoH or DoQ, and under
`Config.ignore_truncation`.

An unmatched response moves the lookup to no other state, and the wait stands. One that echoes a
mixed query's question in lowercase can mark its server, in the `Servers` table, as one that
lowercases the name. The next query built for that server carries the name in lowercase (§7, A
server that changes the case). Since 2026-10-20 such a reply also sets the flag `reply_marked` of
the lookup, which marks its own try. A try so marked is no sample when it runs out (§16 decision
50). The flag changes the effect of a deadline's row alone, and the next state of no row.

Over DoH or DoQ (§22, §23) the lookup keeps the UDP states, and three rows change. `poll` in
`query_ready` returns `send_request`. An answer comes through `on_request_answer`, and only for
the transaction the lookup waits on; it is read as one over TCP is, so TC=1 sends the lookup
nowhere and marks an answer `truncated`. BADCOOKIE advances the server, the first as well: such a
query carries no cookie (§22, §23), so there is no fresh server cookie to retry with. And one row
is added:

| State | Event | Next state | Effect |
| --- | --- | --- | --- |
| `awaiting_udp` | `on_request_failed` for the current transaction | `query_ready` or `failed` | keep the reason as the cause, advance the server, as SERVFAIL does |

After `send_tcp` the caller reads two bytes, calls `wire.message_len(prefix)`, reads that many
bytes and passes them to `on_response`. There is no `read` action: the `wait` deadline already
governs the read, and the framing rule is three lines in the example (§15 step 6). The length is
a `u16`, and a caller who adds the prefix's two octets to it widens it first. A sum made in
sixteen bits overflows from a prefix of 65534, which a server chooses: the engine and the twin
each had that panic until 2026-10-10 (docs/mutations.md, Sums at the most their operands reach).
Since 2026-10-13 `constants.tcp_prefix_bytes` is a `usize`, so a sum with it is a `usize` (§16
decision 40). A sum with a literal `2` is still a `u16`.

### Retry and timeout policy

- Each server's wait comes from its measured latency, as the owner ruled on 2026-10-09 (decision
  36). A sample is the time from a transaction's `on_sent` to a response the lookup accepts for
  that transaction, whatever its rcode: over UDP, over TCP or TLS once the connection is up, or
  as a DoH or DoQ request. When the transaction's deadline passes first, the sample is the wait
  that try used, from `on_sent` to the deadline (below). The engine says a DoH or DoQ request
  went out when it takes it onto its connection, before the connection's handshake ends (§24,
  request rule 3), so a request that opened a connection carries the handshake in its sample. A
  response the lookup ignores, an answer from the memory of §20, a send that failed, a connect
  that ran out, a connection or a handshake that failed, a request that failed and a lookup
  cancelled give none. Since 2026-10-24 a deadline in `tcp_ready` gives none either (decision
  52). Since 2026-10-20 a try that runs out after a reply to it marked its
  server gives none too (below). A response is accepted only for the current transaction, and each
  transaction has an id of its own (§7), so no sample pairs a response with the send of a query
  sent again. A datagram that fails §7's checks is no sample, so it moves no server's wait
  (decision 10). An attacker who can make a server's answers go missing moves it all the same,
  with no datagram that passes a check (What the rule costs, below). A sample longer than the
  constant `timeout_ns_max`, 30 seconds, counts as 30 seconds, which bounds what one sample adds
  to a sum.
- `Servers` keeps each server's samples, their count and their sum, in five windows: a minute,
  fifteen minutes, an hour, a day, and since the table was built. A window starts at its first
  sample. Once its span has passed it holds nothing the wait reads, and its next sample starts
  it again empty. `now_ns` is the caller's, so no window reads a clock. A window whose sum would
  pass 2^64 halves its count and its sum first, which keeps its average.
- Until a server has 3 samples since the table was built, its wait is `config.timeout_ns`. From
  the third sample on, it is 5 times the average of the shortest window that holds at least 3
  samples. Either way it is clamped to at least `timeout_ns_min`, 250 ms, and at most
  `config.timeout_ns_max`. The cap is the caller's and the floor a constant, so a cap below the
  floor wins.
- A deadline is `now_ns + min(wait << round, config.timeout_ns_max)`, where `round` counts
  completed passes over the server list, so the next try at the same server waits about twice
  as long. Doubling per round rather than per try is what glibc does; this is recalled, not
  measured. `on_sent`, `poll` in `tcp_needed` and `on_tcp_connected` arm it, each from the wait
  of the server the lookup is on at that instant.
- The numbers are c-ares's, read on 2026-10-09 from its features page under "Dynamic Server
  Timeout Calculation", and not from its source. The page names the five windows, the factor of
  5, the 3 queries a timeout needs before it is calculated, the 2000 ms default of
  `ARES_OPT_TIMEOUTMS`, the 250 ms floor, the 5000 ms ceiling that `ARES_OPT_MAXTIMEOUTMS`
  changes, and a retry to the same server whose wait about doubles. It does not say which window
  a timeout reads. Reading the shortest one with 3 samples is cocuyo's own choice: a busy server's
  wait follows its last minute, and a quiet one's its longer record. The page also keeps a prior
  span beside each window's current one, and cocuyo keeps the current one alone.
  `ares_init_options(3)` says the same of `ARES_OPT_TIMEOUTMS` in fewer words, that after the
  first successful query to a server "the timeout is automatically calculated based on prior
  query history". Of `ARES_OPT_MAXTIMEOUTMS` it says "The upper bound for timeout between
  sequential retry attempts". cocuyo takes the page's 3 queries rather than the manual's one.
- This follows one sentence of RFC 1035 §4.2.1 and departs from the next. "The retransmission
  interval should be based on prior statistics if possible", which the samples are. "The minimum
  retransmission interval should be 2-5 seconds", and the 250 ms floor is below it. The owner
  ruled for c-ares's numbers on 2026-10-09. A wait scaled to the server's own latency, rather
  than a fixed one, moves on from a silent server that usually answers in 20 ms after a quarter
  of a second rather than after five seconds, and still gives a slow server five times what it
  usually takes. Until then a deadline was `now_ns + (config.timeout_ns << round)`, capped at
  `config.timeout_ns_max`, with 5 and 30 seconds as their defaults, the `resolv.conf` default
  and its cap.
- A new table, the engine's `reinit` among them (§19 step 13), forgets every sample, so each
  server waits `config.timeout_ns` again until it has 3.
- A try that runs out is a sample as long as the wait it used, as the owner ruled on 2026-10-09
  in answer to §17 question 26. When the deadline passes in `awaiting_udp`, which holds DoH and
  DoQ requests too, or in `awaiting_tcp`, the server the lookup waited on takes one sample, from
  the send to the deadline. It takes it at the instant the expiry counts the server's failure,
  before the lookup moves on. A try on a later pass waited the doubled wait, and counts as that.
  A connect that ran out sent no query, and a failed send, a failed connection or handshake, a
  failed request and a lookup cancelled measured no wait for an answer, so none of them is a
  sample. No RFC states this rule; it is the owner's. RFC 1035 §7.2 keeps two histories of each
  server address, its response time and how often it "responded at all", and under it a try
  that ran out would count in the second alone. A try that a reply to it marked is the one
  exception (below).
- Before that ruling only an answer that came in time was a sample, and a server whose latency
  rose past its wait gave no sample after that. An answer after the deadline answers a
  transaction the lookup has left, so the lookup ignores it. The window since the table was
  built never passes, so the wait stayed where the server's old record left it until the table
  was built again. Take a server whose record averages 50 ms, so that its wait is the 250 ms
  floor, under the default 2 attempts, and that comes to answer in 600 ms. Every try at it ran
  out, at 250 ms and then at 500 ms, and with no other server every lookup ended in `Timeout`.
  Now each try that runs out raises the server's average, and its wait, five times the average
  up to `config.timeout_ns_max`, rises with it until its answers come in time again. With a
  record of 3 such samples, the first lookup's first try runs out at 250 ms, its second waits 1
  second and is answered, and the next lookup is answered on its first try. With a record of
  100, the first two lookups end in `Timeout`, every lookup from the third on is answered, and
  from the eleventh on at its first try (`src/resolver/lookup_latency_test.zig`). A server that
  never answers has its wait rise to the cap and stay there, by the third lookup from that
  record of 3. Failover already asks it last (§19 step 12), though each probe of it then waits
  the cap (below).
- What the rule costs. A timeout says the answer took at least the wait, not how long it took.
  So a slowed server's wait rises in steps, a try at a time, rather than to its true latency at
  once, and the more samples its record holds the more tries that takes. For a client that
  gives the server 3 samples within a minute, the minute's window bounds that delay at about a
  minute and three samples. The window starts again at its first sample a minute after its last
  start, and from its third sample on the wait reads only samples taken since. Each of those is
  a try that ran out, as long as its wait, or an answer slower than the wait before the server
  slowed, so each is 250 ms or more, and the wait 1.25 seconds or more. Take a record of 1,000
  answers in 1 ms, which a minute of tries that run out does not outweigh, and a server that
  comes to answer in 600 ms. The first 80 lookups end in `Timeout`, the minute's window starts
  again at the 79th's second try, and every lookup from the 81st on is answered, at its first
  try while the minute's window holds 3 samples (`src/resolver/lookup_latency_test.zig`). A
  quieter client reads a longer window, the shortest that holds 3 samples, and the wait stays
  low until the tries outweigh what that window holds of the old record.
- A datagram lost on a fast path is a sample as long as its wait, and it weighs most when the
  window the wait reads holds few samples. Three answers in 20 ms give a wait of the 250 ms
  floor. One lost query adds a sample of 250 ms, the average becomes 77.5 ms, and the wait
  387.5 ms (`src/resolver/lookup_latency_test.zig`). A query lost on a later pass adds its
  doubled wait. Each answer after it brings the average down again.
- An attacker who can make a server's answers go missing raises its wait without passing any
  check of §7: by flooding the path until the answers are dropped, or by sending the server
  queries in the client's name until it limits how fast it answers that client. Each answer
  lost is a try that ran out, a sample as long as its wait, so the wait rises to
  `config.timeout_ns_max`, and from then on each answer lost costs a lookup that cap. The wait
  stays raised after the attack ends: for about a minute at a client that gives the server 3
  samples a minute, whose minute's window starts again and fills with answers, and longer at a
  quieter one, which reads a longer window. Before the ruling each answer lost cost a lookup a
  wait too, but the wait stayed at what the server's record gave.
- Failover asks a server that failed last, and asks it first again one query in
  `failover_retry_chance` once `failover_retry_delay_ns` has passed (§19 step 12). That query is
  a real one, and while the server stays down its try runs out, a sample as long as its wait.
  So each probe of a server that stays down waits longer than the one before, up to
  `config.timeout_ns_max`, 5 seconds by default, and from then on each probe costs its query
  that cap before the query moves to a server that answers. From a record of three answers in
  20 ms, the try that first ran out waited 250 ms and the seventh probe after it waits the cap
  (`src/resolver/lookup_failover_test.zig`). Before the ruling every one of those probes waited
  250 ms.
- Over DoH and DoQ a server that never answers, not even the handshake, is a sample at each
  try, and over TCP and TLS it is none. The engine says a request went out when it takes it
  onto its connection, before the handshake ends (§24, request rule 3), so such a request waits
  in `awaiting_udp` until its deadline passes, and its try has run out. Over TCP or TLS the same
  server holds the lookup in `connecting_tcp`, and a connect that ran out is no sample. So that
  server's wait rises to the cap over DoH and DoQ, as over UDP, and over TCP and DoT it stays
  where its record left it. A connection that fails is no sample over any of them. The lookup
  cannot tell a request that waited on its handshake from one that waited on its answer, since
  it does not see the handshake. §17 question 28 asks whether it should.
- A reply the lookup ignores leaves its try to run out, though the server answered in time.
  Two kinds of server answer so (§7, A server that changes the case). A server that lowercases
  the name has one reply ignored, the one that marks it. That reply marks its own try too, and
  since 2026-10-20 a try so marked is no sample when it runs out (§16 decision 50).
- Take such a server that answers in 10 ms, on a fresh table, under the defaults. The first
  lookup's first try runs out at 2 seconds with no sample, and its second pass is answered. The
  next two lookups are answered at their first try, so the first three samples are each 10 ms.
  Each first try waits the configured 2 seconds until the third sample, and the fourth lookup's
  waits the 250 ms floor (`src/resolver/lookup_case_test.zig`). Before the ruling that try was a
  sample of 2 seconds, and its average with the next two was 673 ms. So the third lookup waited
  3.37 seconds, above the configured 2.
- A server that changes the case another way has every reply ignored and no try marked, so it is
  sampled as one that never answers. Before 2026-10-09, with one server and 2 passes, each lookup
  to it ended in `Timeout` after 6 seconds, a wait of 2 and then 4. Since then the second
  ends after 7, and every one from the third on after 10, the 5-second cap twice
  (`src/resolver/lookup_case_test.zig`).
- `Config.assert_valid` requires `timeout_ns` at or under `timeout_ns_max`. A configuration built
  by hand that sets `timeout_ns` above 5 seconds was valid before 2026-10-09, when the default
  cap was 30. It must now raise `timeout_ns_max` as far, or it trips that assertion when a table
  is built. `resolv.conf` and `RES_OPTIONS` raise the cap themselves (§10).
- On expiry: `server_index += 1`. On wrap: `server_index = 0`, `round += 1`. A position whose
  server has had its three queries of the name over the transport the lookup starts on is passed
  over the same way (RFC 9520 §3.1, §16 decision 58). When
  `round == config.attempts` the lookup fails with `Timeout`, or with `AllServersFailed` if any
  server answered SERVFAIL, REFUSED or NOTIMP, FORMERR without EDNS0, BADCOOKIE over TCP after
  its retry, or BADCOOKIE over DoH or DoQ, or refused the lookup: a connection or a handshake
  that failed, or a DoH or DoQ request that ended without an answer (§16 decision 25). So
  `Timeout` means that every try went unanswered.
  A failed send is not a refusal: the loop or the local stack refused it, and the server said
  nothing. Since 2026-10-17 the lookup keeps the cause of each such failure in place of a flag,
  and fails with `AllServersFailed` when it holds a cause (below).
- EDNS0 is off for the server that answered FORMERR, and on again at the next server and the
  next name. RFC 6891 §6.2.2 makes a server's lack of EDNS0 a fact about that server, and a
  lookup that kept it off would ask every later server without a cookie and with a 512-octet
  limit.
- `rotate` starts the first try at a server the seed picks among those with the fewest failures
  (§19 step 12), instead of the first of them, so a process with many lookups does not aim all
  of them at one server.
- `Config.attempts` counts passes, and since 2026-10-27 it no longer bounds the queries to one
  server alone (§16 decision 58). Each pass sends a server a query, and FORMERR and BADCOOKIE each
  add a retry inside a pass. So before, `attempts:5` sent one server five queries of one name over
  one transport, and the default 2 could send it four: the query and two retries in one pass, and
  one query in the next. The bound `queries_per_transport_max`, 3, now holds RFC 9520 §3.1 for
  any `attempts`, and `attempts_max` stays 5. A move to TCP after TC=1 is another transport, and
  RFC 9520 §3.1 lets it go.

### The cause of a failure

The owner ruled on 2026-10-17 that a lookup that fails keeps the last cause a server gave (§16
decision 45). On 2026-10-18 the owner ruled that the cause names the server that gave it. The
owner also ruled that the two calls of a failed transport carry a reason (§16 decision 51). The
lookup holds `cause`, `none` until a server fails it, and `Failure.cause` reports it, null for
`none`. A server fails a lookup at each event that the retry policy counts against `Timeout`:

| Event | What the cause keeps |
| --- | --- |
| `on_response` SERVFAIL, REFUSED, NOTIMP or BADVERS, `check_response` on | `.{ .rcode = ... }`, that code |
| `on_response` FORMERR, EDNS0 off | `.{ .rcode = .format_error }` |
| `on_response` BADCOOKIE that advances the server: over a stream after its retry, or over DoH or DoQ | `.{ .rcode = .bad_cookie }` |
| `on_response` FORMERR with EDNS0 on, or BADCOOKIE, whose retry the bound of RFC 9520 §3.1 forbids (§16 decision 58) | `.{ .rcode = ... }`, that code |
| `on_tcp_failed` | `.{ .reason = ... }`, the reason of the call |
| `on_request_failed` for the current transaction | `.{ .reason = ... }`, the reason of the call |

- Each of these replaces the cause that the lookup holds. Its `server_index` is the server that the
  lookup is on, an index into `config.servers`.
- Nothing else changes the cause. Nothing clears it before the lookup ends: not the next server,
  the next pass, the next candidate or a CNAME hop.
- `Failure.server_index` names the server that the lookup was on at its end. After the last pass
  that is the first server of the order, so it does not name the server of the cause.
- FORMERR with EDNS0 on and a first BADCOOKIE keep no cause while the bound lets the retry go.
  TC=1, a deadline that passes, a failed send and a cancel keep no cause. A TC=1 whose stream the
  bound forbids keeps none either: the server answered, and it failed nothing.
- A server error that `check_response` off takes as the answer keeps no cause either. It is the
  answer, in `err`, and the server's state counts it as an answer.

The lookup holds its cause in three octets, where a `?Cause` takes four. So a `Lookup` stays at
3,072 octets (§9), and `failure_of` gives the `?Cause`.

Each reason says what failed, and each comes at some calls alone. A reason that does not fit its
call is a programmer error, and an assertion stops it:

| `Reason` | What failed | `on_tcp_failed` | `on_request_failed` |
| --- | --- | --- | --- |
| `connect` | the connect | before `on_tcp_connected` | over DoH |
| `handshake` | the TLS handshake, or over DoQ the QUIC handshake | before `on_tcp_connected`, over TLS | yes |
| `local` | no server took part | before `on_tcp_connected` | yes |
| `closed` | a connection that was up, or a send on it | after `on_tcp_connected` | yes |
| `status` | over DoH, a response that holds no DNS message | never | over DoH |
| `reset` | a stream that the server reset or refused | never | yes |

After `on_tcp_connected` each failure is `closed`, whatever failed. The owner put a connection that
failed after it was up and a send on it in one reason. So a send that the loop refuses there is
`closed` too. A consumer that owns its sockets passes a reason too. When it cannot tell what
failed, it passes `connect` before `on_tcp_connected`, `closed` after it, and `closed` for a
request.

The engine gives each reason for these failures:

- `connect`:
  - a connect that failed;
  - over DoH, an exchange that ended while no connection of its channel was up, when no server
    took part in one.
- `handshake`:
  - over TLS, a handshake that the session refused and that did not resume. A resumed handshake
    that fails is no failure (§21, TLS rule 8);
  - over TLS, a peer that closed, a receive or a send that failed, or a record longer than TLS
    allows, while the handshake ran;
  - over DoQ, a failure of the connection before its handshake ended, and a handshake that ended
    on an ALPN other than `doq` (RFC 9250 §4.1);
  - over DoH, an exchange that ended while no connection of its channel was up, after a server
    took part in one. colibri ends an exchange so when each connection that it tried failed. A
    certificate that the check refuses is one such failure.
- `local`:
  - an engine that keeps no TCP connection, as one built for DoQ alone does;
  - no free connection slot, and none that frees with no lookup leaving it. Since 2026-10-18 a
    lookup waits for such a slot (§19 step 13, the stream's rule 12). So this comes in the clear
    alone, when each slot holds a lookup;
  - a socket that the system refused, and a connect that the loop refused;
  - over TLS, a session that could not start;
  - over TLS, a records buffer with no room, or a send that the loop refused, while the handshake
    ran;
  - over DoQ, a connection that could not open: the system refused its socket, or its transport
    could not start;
  - over DoH, a template that the engine cannot read, a channel that could not start, and a
    request that colibri refuses to send.
- `closed`:
  - a connection that was up and that the server closed or reset;
  - a send or a receive on it that failed, and a send that the loop refused;
  - a message whose prefix says more than the connection assembles (the stream's rule 11);
  - over TLS, a record that the session refused once up, the peer's `close_notify`, and a query
    that the session could not seal;
  - over DoQ, a failure of the connection once up, and a stream that could not open;
  - over DoQ, an answer that breaks RFC 9250 §4.2, or that is longer than the engine's buffer;
  - over DoH, a connection that came up and ended before the response was whole.
- `status`, over DoH:
  - a response whose status is not 2xx (RFC 8484 §4.2.1);
  - a response whose content is not a DNS message, or has a coding;
  - a response that colibri refused as malformed;
  - a response that colibri refused as too large. Its content passed 65,535 octets, the largest
    DNS message (RFC 8484 §6), or a field that the engine reads passed `doh_values_bytes_max`.
- `reset`:
  - a stream that the server reset (RFC 9250 §4.3.2, RFC 9113 §6.4);
  - over DoH, an exchange that colibri ends as refused after a connection came up. The server
    refused its stream (RFC 9113 §8.7), a GOAWAY left it unprocessed (§6.8), or an HTTP/1.1
    connection closed before the request went out. The server processed none of the request.

Over DoH, colibri says how an exchange ended, but not on which connection. So the engine's channel
reads two facts while the exchange is live. One is whether a connection of the channel came up.
The other is whether a server took part in one: a TCP link that connected, or a QUIC datagram that
came. An exchange can move to a second connection after its first one came up. It keeps the
reason of a connection that came up (§16 decision 51).

Two paths that no drive reaches give no cause. Each is an assertion since 2026-10-24: a lookup
ready to send on a connection that is not up, and a query with no room in the records buffer
(§17 question 66).

So each error carries this cause:

| `Failure.err` | `Failure.cause` |
| --- | --- |
| `Timeout` | null: every try went unanswered, or the memory of §20 recalled the failure |
| `AllServersFailed` | the last server failure; null when the memory of §20 recalled the failure (§17 question 89) |
| `NameNotFound`, `NoData` | the last server failure, or null; null when the memory of §20 recalled the negative |
| `ServerFailure`, `Refused`, `NotImplemented`, with `check_response` off | a server failure before the answer, or null |
| `ChainTooLong`, `NameTooLong`, `Canceled` | the last server failure, or null |
| `NoServers` | null |

A `NameNotFound` can carry the SERVFAIL of a server before the one that answered NXDOMAIN. The
memory of §20 keeps no cause, and a negative or a failure that it recalls asked no server. Since
2026-10-28 it recalls a resolution failure too (§16 decision 61). Such a failure has
`attempts_made` of zero, and a lookup that goes out ends `AllServersFailed` with `Config.attempts`.

`AddressLookup` and `NameLookup` hand on the `Failure` of the lookup whose end they report, its
cause with it. A negative end reports the walk's error on the fields of the last lookup that
failed (§19 step 14). So does a cancel after a lookup failed. Since 2026-10-21 a lookup's own
`Canceled` end is such a failure too, when the consumer cancelled the walk and the end carries a
cause. So both walks hand on that cause. An `Answer` carries no cause, so a server failure before
an answer does not reach the walk.

### Search list policy

`ndots` decides the order, not whether the search list is used.

- A name ending in a dot is absolute: one candidate, the name itself, no search list.
- A name with at least `ndots` dots: the name itself first, then `name + "." + search[i]` for each
  entry in order.
- A name with fewer: the search entries first, then the name itself.
- NXDOMAIN or NODATA advances to the next candidate and resets the server and round counters.
  Exhausting the candidates fails with `NameNotFound`, or `NoData` if any candidate returned
  NOERROR with no record of the wanted type.
- Every negative on the way bounds the walk's end. RFC 1034 §3.1 completes a relative name
  against a search list and leaves how to read that list to each implementation; the order here
  comes from `resolv.conf`'s `search` and `ndots` (§10). The walk's end is kept under the name
  as asked, and that end rests on each earlier candidate's NXDOMAIN or NODATA. Each of those
  "MUST NOT be used again" once its TTL reaches zero (RFC 2308 §5), and from then on a new walk
  may stop at that candidate. So the lookup's `Failure.negative_ttl_seconds` is the smallest of
  the candidates' negative TTLs, not the last one's. `Answer.ttl_seconds` is no larger than the
  negative TTL of any candidate before the one that answered. A negative with no SOA has a TTL
  of zero, which is not cached (RFC 2308 §5), so it makes the walk's end uncacheable too. The
  chain's bound (CNAME policy) and DoH's `Age` (§22) apply to each candidate's TTL first, as
  they did. Each bound is a TTL as its response carried it: the time between that response and
  the walk's end is not taken off, and the chain's bound takes none off either. Each record's
  own TTL is bounded by neither. Until 2026-10-08 each negative replaced the one before, and an
  answer kept its own TTL (c4milo/cocuyo#38). This is one `Lookup`'s walk. `AddressLookup`
  walks with one absolute lookup per candidate, and the bound does not reach its outcome
  (§19 step 14).
- SERVFAIL, REFUSED or NOTIMP moves to the next server, not to the next candidate. When every
  server has failed the lookup fails with `AllServersFailed`, and the walk stops there.
- YXDOMAIN ends one `Lookup`'s walk with `NameTooLong`, and the next candidate is not tried (§16
  decision 57). A DNAME substitution made the candidate longer than a name can be (RFC 6672
  §2.2). In `AddressLookup`, an NXDOMAIN from the other family moves on to the next candidate
  (§19 step 14, rule 5).

Measured on 2026-09-22 by `tools/search_order/run.sh`. A recorder that writes down every question
it is asked, and answers NXDOMAIN unless a case says otherwise, sits in front of four resolvers
asked the same names with the search list `a.test b.test`: glibc 2.39's `getaddrinfo`
(Ubuntu 24.04's 2.39-0ubuntu8.9, in a container), musl 1.2.5's (as Zig 0.16 links it, in a
container), c-ares 1.34.8's `ares_getaddrinfo` given the same list and `ndots` as options, and
cocuyo's `examples/udp_blocking.zig`. Each is watched on the wire, not read. The questions each
asked, in order:

| Case | glibc | musl | c-ares | cocuyo |
| --- | --- | --- | --- | --- |
| `host`, ndots 1 | search list, then the name | the same | the same | the same |
| `host.sub`, ndots 2 | search list, then the name | the same | the same | the same |
| `host.sub`, ndots 1 | the name, then the search list | the name alone | the name, then the search list | the name, then the search list |
| `host.sub.`, absolute | the name alone | the same | the same | the same |
| NODATA for the first candidate | walks on, fails as no data | stops there | walks on, fails as no data | walks on, fails `NoData` |
| SERVFAIL for the first candidate | walks on, fails as not found | asks it three times, fails to try again | stops there, fails as a server failure | stops there, fails `AllServersFailed` |
| an answer for the second candidate | stops there | the same | the same | the same |

cocuyo walks as glibc and c-ares do in every case but SERVFAIL, and there it does what c-ares
does, on purpose. glibc treats a server failure on one candidate as a reason to try the next,
and reports the name as not found: the failure is hidden, and a name under the second search
domain can answer for one the first domain would have held. cocuyo stops and says the servers
failed, as c-ares, the library it replaces, does. musl differs in two places a consumer on a
musl system will see from its own resolver: it searches only names with fewer dots than `ndots`,
and it stops at NODATA.

### CNAME policy

- Inside one message, follow at most `cname_hops_max` CNAMEs, and only a CNAME whose owner name
  equals the current name in the chain. A record whose owner is not in the chain is dropped, not
  rejected: unsolicited extra records are common, and so is the attempt to inject them.
- If the message resolves the chain and carries records of the wanted type for the chain's end,
  finish without another query. This is the common case and takes one pass.
- If the chain ends in a CNAME with no record of the wanted type, start a new transaction for the
  target on the same server with a fresh id, port hint and case pattern. The server just answered,
  so it is the healthy one.
- `cname_hops_max` counts hops across messages as well as inside them. Exceeding it fails with
  `ChainTooLong`, and so does a loop inside one message: RFC 1034 §3.6.2 and §5.2.2 have alias
  loops signalled as an error to the client. The message passed every check of §7, so it is the
  server's answer and not a malformed one, and §16 decision 10 does not apply.
- The chain's CNAMEs bound what its end is kept for, across messages as well as inside one. The
  end is cached under the name asked, which reaches it through them, and each may be kept no
  longer than its own TTL (RFC 1035 §3.2.1). So the answer's TTL, and the negative TTL of an
  NXDOMAIN or NODATA at the chain's end, is no larger than the smallest alias on the way. Until
  2026-09-24 a chain that spanned messages kept only the last message's TTLs (issue #2), and a
  record with a TTL of zero lost it to any record after it (issue #1).

### The model

spec/ holds a model of this section in Lean 4, written from the table and the RFCs rather than from
the code, and proofs of what the table promises: an ended lookup stays ended, a lookup under
`use_tcp` never asks for a datagram, a lookup over DoH or DoQ never asks for a datagram or a
stream (§22, §23), its counters stay inside the configuration, and every send lowers a measure in a
well-founded order, so no sequence of answers makes a lookup retry forever. Since 2026-10-17 the
model holds the cause of a failure in place of a flag, and proves that `AllServersFailed` has a
cause and `Timeout` has none (The cause of a failure, above). Since 2026-10-21 the cause names the
position of its server in the order. A failed connection or request carries its reason (§16
decision 51). The proof shows too that a cause names a server of the configuration. Since
2026-10-27 the model counts the queries each server got for the current name over each
transport, and passes over a server with no query left (§16 decision 58). Its proof
`sends_bounded` shows that no count passes three, whatever the caller tells the lookup. `zig build
spec` builds the proofs, then walks every state the model reaches under 84 configurations and
replays each of the 38.8 million transitions against `Lookup`. It compares the answer, the whole
state and the cause after every event. The counts are not printed, so the replay checks them
through the moves they cause. `zig build test` replays a committed slice of 32,386 of them
without Lean.
spec/README.md says what the model abstracts and why. Time is one of those things: a poll comes
before the deadline or at it. So when a server's wait came to be measured, on 2026-10-09, no
transition changed, and neither did the model. Since 2026-10-24 a poll at the deadline ends
`tcp_ready` too, in the model first (§16 decision 52). Its proof `tcpReady_expires` shows that the
deadline ends that state, at every lookup in it.

Building the model and the replay found two defects in the code, fixed on 2026-09-23. A chain
past `cname_hops_max` was ignored, so the lookup timed out instead of failing with
`ChainTooLong`. EDNS0 stayed off for the rest of the lookup after one FORMERR, where the flag's
own comment and RFC 6891 §6.2.2 have it off for one server. It also found this table wrong in
one row: TC=1 over TCP, which the code reads as if the bit were clear rather than ignoring the
message. And the table lacked rows the code already had: FORMERR without EDNS0, BADCOOKIE, and a
connection that fails after it opened.

## 6. Errors and assertions

Operational failures return errors. Programmer errors assert, roughly two assertions per function,
covering positive and negative space.

```zig
pub const Error = error{
    NameNotFound, NoData, ServerFailure, Refused, NotImplemented, FormatError,
    Timeout, AllServersFailed, ChainTooLong,
    MalformedMessage, MalformedName, BadCompressionPointer, NameTooLong, LabelTooLong,
    TruncatedMessage, UnsupportedClass, UnsupportedEdnsVersion,
};
```

Assertions cover: `now_ns` never decreasing; `out.len >= query_bytes_max`; `on_sent` only in a
state that asked for a send; `slots.len` within `lookup_slots_max`; `keys.len` a power of two and
at least twice `slots.len`; a `Handle` generation matching its slot; every decoded name at or
under `name_bytes_max`; every read offset inside the message.

A malformed response is not an assertion. It is the expected case.

## 7. Security

cocuyo parses unauthenticated input from the network. These are the rules, and §13 lists the
mutation that proves each one is live.

### Response matching

A response is considered only if all of these hold, checked in this order:

1. `message.len` is at least `header_bytes` (12) and at most `message_bytes_max`.
2. The transaction id equals the one sent. This is the most selective check and so it is first.
3. `from` equals the endpoint the query was sent to: family, every address octet, and the port.
4. QR is 1 and the opcode is QUERY.
5. QDCOUNT is 1 and the question section is byte-identical to the one sent, case included.
   Since 2026-10-09 a response that fails this check because it echoes, in lowercase, the name a
   mixed query sent, and that passes check 6, marks its server as one that lowercases the name.
   It is ignored all the same (A server that changes the case, below). By the owner's ruling of
   the same day the check reads the echo in place, against the case the transaction's seed gives
   the name held, without building the name the query sent, and the check that the name built is
   the name held in another case runs where the query is built (A server that changes the case,
   below).
6. The cookie (RFC 7873 §5.3, since §19 step 10): when the query carried a COOKIE option, a
   COOKIE option in the response must echo the client cookie that query carried, which the lookup
   recorded when it built the query, whatever another lookup taught the server since. A response
   without one is a discard when the query carried the server's cookie, or the server has given
   one since; an OPT record that is malformed — a version cocuyo does not speak, an owner that is
   not the root, a cookie of a length neither form allows — is a discard too. Before a server has
   given a cookie, a response without one is a server without them: it stands, and once the
   lookup takes it as its answer, the next queries to that server carry no COOKIE option for a
   while (§19 step 10). A response the lookup then ignores starts no such while. A query that
   carried no COOKIE option expects none back.
7. Only then is the answer section walked.

Matching on the transaction id alone is the textbook cache-poisoning hole. Checking the source
address without the port is the same hole with one extra step. The question compare is exact
because of the next rule, not case-insensitive.

### A datagram that the buffer cut

Written on 2026-10-14, from the owner's answer to §17 question 40 (§16 decision 43). A caller
receives each datagram into a buffer. When a datagram is longer than the buffer, the kernel keeps
the octets that fit and marks the datagram as truncated. The rest is gone. rotor gives the mark
as `Received.flags.truncated`. The engine's buffer holds 1,856 octets (§19 step 13, the
datagram's rule 6). A query advertises 1,232 octets by default, "the largest UDP payload" that
cocuyo takes (RFC 6891 §6.2.3). A server that obeys it sends no datagram that the buffer cuts.
Since 2026-10-14 the engine refuses a `Config.udp_payload_bytes` above 1,856 (§16 decision 44).
So only a forger or a broken server sends a datagram that the buffer cuts.

Until 2026-10-14 the engine did not read the mark. The table read the cut octets as a whole
message. A check or the record walk refused them, and the lookup waited until its deadline.

A caller gives a cut datagram to `on_datagram_cut`, and not to `on_datagram`. The lookup takes it
by these rules:

1. The lookup reads a cut datagram only in `awaiting_udp`. It ignores the datagram in each other
   state. It also ignores it over DoH or DoQ, where no answer comes as a datagram (§22, §23).
   Under `Config.ignore_truncation` it ignores it too. That caller asked to read a truncated
   answer and not to ask over TCP, and no whole message is left to read.
2. The checks of a cut datagram are checks 1 to 6 of Response matching, with check 6 as rule 3
   gives it. Checks 1 to 5 read the cut octets. The header and the question come first in a
   message. A buffer of 271 octets or more holds them whole: the header, a name of 255 octets,
   the type and the class. A datagram that fails a check is ignored, as each such datagram is.
3. Check 6 reads a cut datagram as a message with no COOKIE option. The OPT record is in the
   additional section (RFC 6891 §6.1.1), the last section of a message (RFC 1035 §4.1). The cut
   took the end of the message, so the lookup does not look for the OPT record in it. RFC 7873
   §5.3 says that a response that does not have the COOKIE option that the client expects "MUST
   be discarded". The lookup expects one when its query carried the server's cookie. It also
   expects one when the server has given a cookie since. In each of these cases the lookup
   ignores a cut datagram. An answer with TC set and no OPT record gets the same check 6.
4. A cut datagram that passes the checks of a cut datagram moves its lookup to `tcp_needed`, on
   the same server. That is what an answer with TC set does over UDP. No RFC states this rule.
   RFC 7766 §5 gives the permission to ask over TCP: a stub may send a query over TCP "depending
   on local operational reasons". A buffer too short for the answer is such a reason.
5. The cut datagram tells the server's state nothing. It takes no latency sample, and it counts
   no success and no failure. It teaches no cookie, starts no silence, and marks no server that
   lowercases the name. Each of these needs check 6 on a whole message.

This rule has a cost. An attacker can match the id, the source port and the question with its
case. When the lookup expects no COOKIE option, that attacker can send one long datagram. That
datagram moves the lookup to TCP. Before 2026-10-14 such a datagram changed nothing. But an
answer with TC set and no OPT record did the same then, and it gets the same checks. The attacker
gets no answer into the lookup.

Where the lookup goes next depends on TCP:

- Usually the lookup asks the same server over a connection. An off-path attacker cannot race an
  answer there. The attacker costs the caller one connection.
- An engine of no TCP connection fails the stream at once. So does an engine whose connection
  slots are all in use (§19 step 13). A server that refuses TCP fails the connect. In each case the
  lookup asks the next server over UDP, and the attacker can race that retry.

So decision 10 holds as it held before: a cut datagram moves a lookup only where a forged answer
with TC set could move it already.

### Entropy: four fields, one seed

- **Transaction id**, 16 bits, drawn per transaction. A CNAME re-query is a new transaction and
  draws a new one.
- **Client cookie**, 64 bits drawn per transaction since 2026-10-08 (§19 step 10). A query to a
  server whose server cookie is not known carries a client cookie made from it, so none goes out
  twice without a server cookie (RFC 9018 §8.1).
- **DNS-0x20**, RFC 5452 and the DNS-0x20 draft: the case of each ASCII letter in the query's
  qname is randomised, and the response's question section must come back with the same case. This
  is in v1, on by default, and `Config.mix_case` turns it off for every server. Since 2026-10-09
  a server that answers a mixed name in lowercase loses it alone (below). Roughly one bit per
  letter, so it is the largest entropy source available to a stub. Since the same day a mixed name
  always carries a capital: a draw that leaves every letter small is drawn again, up to
  `case_draws_max` draws, and then the first letter is made a capital. A name of L letters so takes
  one of 2^L - 1 cases rather than 2^L, which costs log2(2^L / (2^L - 1)) bits: 0.42 for two
  letters, 0.09 for four, 0.0014 for the ten of `example.com`, and the whole bit of a name with one
  letter, which always goes out a capital.
- **Source port**, RFC 5452: cocuyo owns no socket, so it cannot bind a port. `send_udp` carries
  a `local_port_hint` drawn from `[port_ephemeral_min, port_ephemeral_max]` and the caller may bind
  it. A caller that sends every query from one socket keeps the id and case entropy and loses the
  port entropy. The README says that in those words; the alternative, demanding a socket per query,
  would mean owning sockets.

All four come from a per-lookup generator seeded by the caller's `u64`. That keeps the state
machine replayable from a seed, which is the point of the determinism rule, and it puts the quality
of the defence in the caller's hands where it is visible. The docs say, in bold, that the seed must
come from a CSPRNG and never from the clock.

### A server that changes the case

Some servers and forwarders do not echo the question as it was sent: they lowercase the name, for
one. Until 2026-10-09 every response from such a server failed check 5, and every lookup to it
waited out its deadline, unless the caller turned `Config.mix_case` off for every server. The
owner ruled on 2026-10-09 that 0x20 stays on by default (decision 5), and that it falls back for
each server on its own. The review of the same day narrowed the mark to a server that lowercases
the name, before any of it was committed (below). No RFC states 0x20, so no RFC states this
fallback either: the rules are the owner's ruling and its review.

- A response marks its server as one that changes the case when all of these hold. It passes
  checks 1 to 4. Its question section is the one asked with every letter of the name small: the
  same name, since names compare without regard to the case of their ASCII letters (RFC 1035
  §2.3.3, as clarified by RFC 4343 §3), in the one spelling no mixed name has. The type and the
  class compare exactly. The query this transaction sent mixed the case. And check 6 passes for
  it, as it must for an answer: a wrong client cookie, a missing cookie the server owes, or a
  malformed OPT record marks nothing.
- A mixed name always carries a capital (Entropy, above). So no echo of a mixed query cocuyo sent
  is in lowercase, and none can mark a server. That covers two lookups of one name and type to one
  server whose transactions drew one id, where the table offers one's answer to the other, and a
  late answer to a lookup's own earlier query that reaches a retry which drew the same id. Neither
  needs an attacker, and both would mark a server that echoes the case as sent if any case marked.
- The response is ignored all the same, and the wait stands. A datagram that fails a check never
  cuts the wait short (decision 10): an off-path attacker could send one to force a retry they can
  race. The lookup moves on at its deadline, as it would have. The response marks its own try
  too, and since 2026-10-20 a try so marked is no sample when it runs out (§5, §16 decision 50).
  The reply shows that the server answered in time. On a fresh table, each first try at a server
  that answers in 10 ms waits the configured 2 seconds until the third sample (§5).
- From then on every query built for that server carries the name in lowercase, without case
  mixing, for the life of the `Servers` table, and its response's question must be byte-identical
  to the name as sent. So a name the caller wrote with capitals, or a chain name, is answered too.
  Every other server keeps 0x20. Over DoH and DoQ nothing changes, since no query there mixes the
  case (§22, §23).
- A lookup records whether the query it built mixed the case, as it records the cookie the query
  carried (§19 step 10), and check 5 compares a response with the name as that query sent it. A
  mark another lookup makes between the send and the answer changes nothing for a query already
  sent: a reply to it in lowercase is still ignored. That reply marks its own try all the same,
  so the try is no sample when it runs out (§16 decision 50).
- Check 5 reads the echo in place, by the owner's ruling of 2026-10-09 on what building the name
  cost every datagram offered to a lookup. The lookup holds the name without its case. Each branch
  of the compare is a branch of the name the query was built with: mixed from the seed, in lowercase
  for a marked server, or as held. For a mixed query the compare draws each letter's case from the
  transaction's seed as it reads the echo, octet by octet, with the bit stream the mixer draws with
  (`wire.name.is_mix_of`, `wire.question.matches_mixed`). They are new public declarations of
  `wire`, which the owner allowed the same day, since `wire` is public through `src/cocuyo.zig`. The
  mixer walks the labels, and that walk is the reference; the compare walks the bytes, which meets
  the letters in the same order because no length octet is a letter. Its tests hold it to the mixer
  over every label of one and of two octets drawn from fourteen octets at the edges of the letters
  and of the case bit, each octet echoed in seven forms, under sixteen seeds, and the codec's fuzz
  target holds it to the mixer over every question it writes, names of 192 to 255 octets among
  them (§13). When the first draw left every letter small, with chance 2^-L for a name of L
  letters, the name went out from a later draw or with its first letter a capital, and the compare
  builds it with the mixer and compares that. A lowercase echo of a mixed query, about to mark its
  server, builds the name too, to assert that the echo is not it.
- The compare reads the type and the class first, at the offset where the name held ends, and
  then the name. A question of a name of another length seldom holds them there, so it is refused
  before its name is read octet by octet. All three compares read in that order: the exact one,
  the lowercase one and the mixed one. The offsets are summed in `usize`, as the fix of 2026-10-10
  left them (§13; docs/mutations.md, Sums at the most their operands reach). Read first, a sum
  made in the octet a name's length is held in would panic on every reply that reached check 5
  for a name of 242 octets or more and was long enough, and not only on the one whose echoed name
  matched (docs/mutations.md, CP14 to CP16).
- The owner's ruling of the same day moved the check that the cased name is the held name in another
  case, which ran on every datagram the lookup was offered, to the build of the query alone. While a
  lookup waits, the held name, the case seed and the record of whether the query mixed are what the
  build had, so the name a reply would have built is the one the build built and checked: building
  it again per reply re-ran a deterministic function on the same inputs. On the reply path the check
  no longer runs. Nothing past check 5 reads the case the query carried: the OPT record, the
  sections and the negative TTL take the name for its length alone, which says where the question
  ends, and the answer walk compares names with `current` without regard to case.
- A chain name that the answer compressed into the question decodes in the case the question was
  echoed in, so with 0x20 on every chain name is folded to lowercase, as it has been since the
  example of §15 step 6 met cocuyo's own case in one. That holds whatever the query carried, so a
  server asked in lowercase is asked for a target it spelled with capitals in lowercase too.

The cost is plain. An attacker who already matches the transaction id and the source port, and
the client cookie where the query carried one, can echo the question in lowercase and switch 0x20
off for that one server until the table is built again: by the engine's `reinit`, or by a new
`Servers` table. That attacker has already passed checks 2 and 3. What they take away is the case's
entropy from the queries that follow, to that server alone. A server that changes the case some
other way, to capitals or to a spelling of its own, is not marked: one reply cannot tell its case
from a mix cocuyo drew, so every lookup to it waits out its deadline as before. Each try that
does is a sample as long as its wait (§5), so the server's wait rises to `config.timeout_ns_max`:
with one server and 2 passes, every lookup to it from the third on ends in `Timeout` after 10
seconds, where each took 6 before. A caller who meets one turns `Config.mix_case` off, for every
server. The capital every mixed name carries costs the entropy the Entropy rule above counts.
And the guarantee holds among lookups that mix: every lookup of a `Resolver` shares its `Config`,
but a caller who drives lookups alone against one `Servers` table under two configurations, one
with `mix_case` off, can mark a server through the lowercase echo of its own unmixed query.

Rejected:

- 0x20 off by default, as c-ares has it. The owner kept decision 5: the case is the only entropy a
  stub adds when the caller sends every query from one socket.
- Asking the server again at once, without mixing, on the response that changed the case. That is
  a datagram that failed a check cutting the wait short, which decision 10 forbids.
- Turning 0x20 off for every server once one changes the case. One forwarder that lowercases would
  cost every other server its entropy.
- A mark on any other case, as the ruling first had it. The table's own lookups mark through a
  shared id, and a lookup through its own late answer, so a busy caller turns 0x20 off for a server
  that echoes the case as sent, with no attacker.
- A table that marks only when none of its lookups accepts the datagram. It cannot see a late or a
  repeated answer that no lookup waits for any more, nor a lookup's own earlier transaction.
- A mark on lowercase alone, with the mix left as it was. A draw leaves a name of L letters all
  small with chance 2^-L, so the same false mark stays, only rarer, and most often for short names.

### Parsing

- Every length is checked against the end of the message before the bytes are read.
- A name is at most `name_bytes_max` octets: "names 255 octets or less" (RFC 1035 §2.3.4). Its
  labels, their length octets and the root count (§3.1), and so do the labels that a pointer
  reaches (§4.1.4). The decode of §8 refuses a longer name. Since 2026-10-14 the skip of the
  record walk follows each pointer as the decode does. It refuses the names that the decode
  refuses, with the same errors (§8, Record walking; §16 decision 42).
- No recursion anywhere in the parser. Compression is a loop with two bounds.
- A count field is never a reason to read. `ancount` says how many records the sender claims;
  the walk stops at the end of the message or at `records_max`, whichever comes first, and a count
  that disagrees with what was walked makes the message malformed.
- An unmatched or malformed datagram never disturbs the wait. An attacker who floods the socket
  costs the caller one bounded pass per datagram and changes no state, which is what makes the
  birthday attack of RFC 5452 §4 not worth running against a lookup that keeps listening until its
  deadline. The one exception since 2026-10-09 is a datagram that matches the id, the port and
  the cookie and echoes a mixed question in lowercase: it marks its server and its own try, and
  still leaves the wait as it was (A server that changes the case, above). A try so marked is no
  sample when it runs out (§5, §16 decision 50). Since 2026-10-14 a datagram that the
  buffer cut and that passes the checks of a cut datagram ends the wait. It moves the lookup to
  TCP, as an answer with TC set does. Usually an off-path attacker cannot race the answer there.
  With no connection to have, the lookup asks the next server over UDP (A datagram that the
  buffer cut, above).

## 8. The wire codec

The codec is pure: byte slices in, values out, no state beyond an offset. It is the half of the
library that faces an attacker, so it is the half with the fuzz target and most of the mutations.

| File | Holds |
| --- | --- |
| `wire_header.zig` | the 12-byte header, the flag bits, the rcode, `message_len` for TCP |
| `wire_name.zig` | name encode and decode, compression, the case mixer and the case compare |
| `wire_question.zig` | question encode, and the byte-exact compare of §7 |
| `wire_record.zig` | the record iterator: owner, type, class, TTL, rdlength, bounded rdata |
| `wire_query.zig` | build a query: header, question, OPT |
| `wire_response.zig` | the answer walk: chain following, record collection, rcode mapping |
| `wire_edns.zig` | the OPT pseudo-record, build and parse |
| `wire_fuzz.zig` | the seeded generator and the fuzz gate |

### Name decoding

One loop, two bounds, no recursion. The decode and the skip of the record walk share the loop.
The decode copies each label into a `Name`. The skip counts the octets of each label, and copies
nothing (Record walking, below).

- Read one length byte. The top two bits select the form: `00` is a label of that length, which
  must be at most `label_bytes_max`; `11` is a pointer whose low 14 bits are an offset; `01` and
  `10` are reserved and make the message malformed.
- A pointer offset must be **strictly less** than the offset of the pointer's own first byte. A
  pointer that points forwards or at itself is malformed. So is a pointer past the end of the
  message, since it points forwards. This rule does not make a loop impossible. A pointer can
  point back at labels that lead to the same pointer again. Each hop of that loop points
  backwards, so the next two bounds end it. Until 2026-10-14 this section said that the rule
  alone made a loop impossible. That was not true.
- `compression_hops_max` bounds the hops, asserted as well as checked. A chain or a loop of more
  than 16 pointers fails with `BadCompressionPointer` at the seventeenth pointer. So a long legal
  chain is cheap, and a pathological one is cheaper.
- The reconstructed name, counting length octets and the root, must be at most `name_bytes_max`.
  The labels that a pointer reaches count too (RFC 1035 §3.1, §4.1.4). A loop through labels of
  63 octets fails with `NameTooLong` in its fourth round, before the hop bound.
- Decoding writes an uncompressed copy into a caller-provided `*Name`, so no caller ever holds a
  pointer into a datagram buffer it is about to reuse.

Both bounds are checks that return errors and assertions that must never fire, because a check
that returns and an assertion that holds are different claims: the first says the input was
hostile, the second says the code that already rejected the hostile input did its job.

### Record walking

For each record:

1. Skip the owner name, without a copy.
2. Read the type, the class, the TTL and the rdlength.
3. Check `offset + rdlength <= message.len`.
4. Hand out the rdata slice.

The owner name is decompressed into a `Name` only when the type is one the lookup wants (§11).
Type-specific rules:

- `A`: rdlength is exactly 4. `AAAA`: exactly 16. Anything else is malformed.
- `CNAME` and `PTR`: an rdata name, decompressed, and the decode must consume exactly `rdlength`
  bytes. Trailing bytes inside an rdata name make the message malformed.
- `OPT`: the owner must be the root, the class is the sender's UDP payload size, the TTL's high
  byte extends the rcode, and the version must be 0.

The skip walks the name as the decode does, through each pointer, and counts its octets. It
copies nothing (§16 decision 42). It refuses each name that the decode refuses, with the decode's
error:

- a name longer than `name_bytes_max` octets, with the labels that a pointer reaches counted
  (RFC 1035 §2.3.4, §3.1, §4.1.4): `NameTooLong`;
- a pointer that does not point strictly backwards, or a pointer past the end of the message:
  `BadCompressionPointer`;
- a chain or a loop of more than `compression_hops_max` pointers: `BadCompressionPointer`;
- a label or a pointer whose octets go past the end of the message: `MalformedMessage`;
- a reserved label kind: `MalformedName`.

The skip returns the offset that the decode returns: the octet after the root, or the octet after
the first pointer. That is where the name ends in the message, so the record walk continues where
it did before. A pointer loop ends in the skip as it ends in the decode (Name decoding, above). A
pointer at itself or ahead of itself fails at its first hop. A pointer back at labels that lead to
it again fails at the seventeenth pointer, or earlier when the labels pass 255 octets.

Until 2026-10-14 the skip stopped at a pointer, and did not follow it. From 2026-10-13 it refused
a name whose labels before the pointer, with a root after them, passed `name_bytes_max`. Before
that date it counted labels alone, so it took a name of 128 labels, up to 8,193 octets. Each name
that the skip took and the decode refused passed every walk that decodes nothing at that place.
One such name is a compressed name whose labels fit and whose whole name does not. A pointer
forward, a loop and a pointer past the end of the message are such names too. The walks are:

- the owner of a record of a type the lookup does not want, in `response.collect`;
- the owners of the records that the search for the OPT record passes (§7, check 6);
- the owners of the records that the negative TTL steps over;
- an SOA's MNAME and RNAME, from which a negative answer takes the TTL that the cache keeps.

So the type of the record that held the fault decided whether a lookup took the message. Now
`record.Iterator.next` and `Record.soa_negative_ttl` return the decode's error for such a name.
What the lookup then does depends on where the name is:

- An owner before the OPT record, or in a message with no OPT record: the search for the OPT
  record walks that owner and fails. So check 6 of §7 fails, and the lookup ignores the message
  and keeps its wait. It does not learn the server cookie from the message. Before, a record that
  the lookup wanted with such an owner passed check 6. Then `response.collect` failed, and the
  lookup ignored the message after it had learned the server cookie.
- An SOA's MNAME or RNAME: they are in the rdata, which check 6 does not read. Only the negative
  TTL reads them, and it reads the error as a TTL of 0, as for any malformed authority section
  (`lookup_response.zig`). So the lookup takes the negative answer, and the cache keeps nothing of
  it.
- An owner after the OPT record, in the additional section: no walk reads it, as before.

The fuzz target holds the skip to the decode at each offset where it aims both: the same end, or
the same error. It also decodes each owner that the record walk passes, and each such owner must
decode (§13).

## 9. Memory the caller provides

Byte counts are hand-computed from the field list; a test pins `@sizeOf` so a layout change shows
up as a diff rather than as a surprise. The pins that exist are in `src/core/core.zig`: `Name` is
256 bytes, `Address` 17, `Endpoint` 20 and `Question` 260, all measured.

| Part of `Lookup` | Bytes | Note |
| --- | --- | --- |
| the scalars | 115 | state, flags, four indices, the server order, the queries sent to each server of it (§16 decision 58), the transaction with its client cookie's draw, three instants, the generator, the failure and its cause with its server in three octets (§5), the negative TTL, the chain's TTL, the config pointer, the servers pointer, and the COOKIE option the last query carried with its client cookie (§19 step 10) |
| `question` | 260 | the name as asked, its type, and whether it was absolute |
| `current` | 256 | the current candidate, or where the CNAME chain has reached |
| `answers` | 2448 | an extern union: `[addresses_max]Address` is 272, `[ptr_names_max]Name` is 256, and the records of §19 step 9 are 2436 — 32 references of 12 and a buffer of `rdata_bytes_max` — plus the question's type (decision 34), the count, the TTL, the hop count and two flags |
| total | 3080, measured | pinned by a test in `src/resolver/lookup_init_test.zig`; 3072 until the counts of RFC 9520 §3.1 on 2026-10-27, whose four octets took eight with the padding (§16 decision 58, §17 question 83); the cause's server of 2026-10-21 took no octet more, since the lookup keeps the cause in three octets, where a `?Cause` takes four (§16 decision 51); the cause of a failure on 2026-10-17 took three octets of the padding (§5); 3064 until the instant of the send, which a latency sample is measured from, on 2026-10-09 (§5), and 3048 until the cookies of 2026-10-08 (§19 step 10) |

The total is larger than the parts because Zig chooses a struct's field order and pads accordingly.
It also means a declaration order cannot be relied on for locality: the measurement that pinned
the first total, 856, also found `state` sitting past both names, so §11's demultiplexer earns its
keep through the side table and not through this layout. The lookup was 864 octets until the
records of §19 step 9 landed on 2026-09-22 and the union grew to hold an rdata buffer; every
caller pays it, an address lookup included, because a union is the size of its largest member.
The caller-provided buffer §19 keeps as the fallback is what would take it back.

| Caller allocation | Size | For |
| --- | --- | --- |
| `[N]Resolver.Slot` | 3096 bytes each, measured, 3088 until 2026-10-27 | one per concurrent lookup: a lookup plus the table's own octets, the ready list's two links and its flag among them (§11) |
| `[2N]MatchKey` | 4 bytes each | the id-to-slot table, power-of-two length |
| send buffer | `query_bytes_max`, 386 | shared by the whole table |
| receive buffer | `config.udp_payload_bytes`, 1232 by default | the caller's, per socket |
| `[M]AddressLookup` | 1184 bytes each, measured | one per `getaddrinfo`-shaped lookup in flight: the name, the canonical name, 32 addresses, two handles, the failure of each lookup and the walk's scalars, beside the two slots it takes; pinned by a test in `src/resolver/address_lookup_test.zig`; 1152 until the cause of a failure on 2026-10-17 (§16 decision 45) |

So 1024 concurrent lookups cost 3096 KiB of slots plus 8 KiB of keys. Nothing else is allocated,
ever, by anybody. `Resolver` itself holds the `Servers` table, 1488 octets, measured and pinned
by a test in `src/resolver/servers.zig`: 184 for each of `servers_max` servers, 120 of them the
five windows of latency samples of §5, which 2026-10-09 added. The flag of the same day that marks
a server as one that changes the case (§7) took an octet of the padding, and the size stayed.

## 10. The config parser

`resolv_conf.parse` turns bytes into a `core.Config` and a storage struct the caller owns. It is a
separate module, it cannot be reached from the state machine, and it is independently testable
because it takes bytes rather than a path: the caller reads the file.

```zig
pub const Storage = struct {
    servers: [servers_max]Server,
    search: [search_max]Name,
};

pub fn parse(bytes: []const u8, storage: *Storage) Config;
/// `parse` with `default_server` false: a file naming no server gives none (NO_DFLT_SVR).
pub fn parse_with(bytes: []const u8, storage: *Storage, options: ParseOptions) Config;
/// The RES_OPTIONS and LOCALDOMAIN environment variables, applied over a parsed configuration.
pub fn apply_options(text: []const u8, config: *Config) void;
pub fn apply_search(text: []const u8, storage: *Storage, config: *Config) void;

/// The hosts file (hosts(5)), parsed into the caller's storage: entries of one address and up
/// to hosts_names_per_entry_max names, the names kept in wire form in one arena of the storage.
/// The table is a core type (§19 step 14), so resolver can consult it; this is its one producer.
pub const hosts = struct {
    pub fn parse(bytes: []const u8, storage: *core.hosts.Storage) core.Hosts;
};

/// core.Hosts, flattened as cocuyo.Hosts.
pub const Hosts = struct {
    pub fn find(self: *const Hosts, name: *const Name, family: ?Family, out: []Address) usize;
    pub fn canonical(self: *const Hosts, name: *const Name) ?Name;
    pub fn reverse(self: *const Hosts, address: *const Address) ?Name;
};
```

Recognised, and nothing else: `nameserver`, `search`, `domain`, `options ndots:`,
`options timeout:`, `options attempts:`, `options rotate`, `options use-vc`. `domain` is `search`
with one entry, and the last of the two wins. An unrecognised line, a malformed address or an option cocuyo does not
know is skipped, not an error — that is what every stub resolver does, and a config file with one
bad line must not stop a program from resolving. Counts above `servers_max` or `search_max` are
truncated, and the returned `Config` says so through the slice lengths.

`attempts:N` sets the passes, a value over 5 read as 5 and zero as 1. Since 2026-10-27 a value of
4 or 5 sends no server more than three queries of one name over one transport. The lookup holds
that bound whatever the file says (§5, §16 decision 58).

`timeout:N` sets `timeout_ns` to N seconds, a value over 30 read as 30 and zero as 1. The wait
must fit under `timeout_ns_max` (§5), whose default is 5 s, so a longer `timeout:` raises the cap
to it, and a shorter one leaves the cap as it was. The cap is never lowered, so `RES_OPTIONS`
applied over a file, or over a cap the caller raised, keeps the larger. Before 2026-10-09 the
default cap was 30 s, and no `timeout:` could pass it.

No line and no option sets `Config.cache_ttl_seconds_max`, so a parsed configuration keeps the
default, an hour. macOS's `resolver(5)`, read on 2026-10-11, names no option for a cache, and
Linux's `resolv.conf(5)` names none as recalled. c-ares takes its cap from the options a program
fills in, and `ares_init_options(3)` names no line of `resolv.conf` for it (§19 step 13). A
consumer that keeps the cap in a configuration file of its own sets the field after the parse.
No line sets `Config.cache_failure_seconds_min` either, for the same reasons (§16 decision 60).

`parse` cannot fail. It returns the default `Config` for empty input, which is the localhost
nameserver, matching the historical behaviour of the platform stubs.

The hosts file (§19 step 11) is the same shape: bytes in, the caller's storage filled, nothing
that can fail. Its source is `hosts(5)`, because no RFC states the format, and the code says so.
A line is an address, an official name and aliases; a comment runs from `#`; a line whose
address will not parse, or that names nothing, is skipped. Names compare with their case folded
(RFC 1035 §2.3.3). The engine consults it before a query goes out, in the order
`Config.lookups` gives.

## 11. Performance

The hints in <https://abseil.io/fast/hints> are the discipline here. Four of them change the
design rather than the prose.

**Estimate before optimising.** The costs were first estimated by hand from the operation counts:
building a query writes about 300 bytes and takes a few dozen branches; parsing a response is one
pass over at most 1232 bytes with no allocation; matching a datagram to a lookup is one probe.
Against a network wait of roughly 1 to 50 milliseconds, every one of those is noise. The single
structure that can matter is matching an inbound datagram when many lookups are in flight, because
that is the one cost that grows with the table. So that is the one thing designed for a constant,
and everything else is written for clarity first and measured afterwards.

**Measured.** `zig build bench` on 2026-09-22, Zig 0.16.0, ReleaseSafe, native target with no
`-Dtarget` or `-Dcpu`, on an Apple M1 Pro — eight performance cores with a 128 KiB first-level data
cache and a 12 MiB second level, two efficiency cores — with 32 GiB under macOS 26.6.2, on mains
power, a laptop in ordinary use and not quiesced. The clock is `CLOCK_UPTIME_RAW`, which the host
reports as stepping 42 ns; `CLOCK_MONOTONIC` on this macOS steps a whole microsecond, and the first
version of this table was quantised by it. Twenty-one samples per case after one untimed warm-up,
each sample 200,000 iterations, after one second of spinning so the machine has finished whatever
ran before the bench. Two runs back to back; every median below is from the second, and every one
of them sits within 5% of the first, 15 of the 24 within 2%. The harness overhead, the first
row, is included in every other row and not subtracted. The numbers are cocuyo's alone: nothing
here is measured against c-ares or any other resolver, so the table supports no claim about speed
relative to what cocuyo replaces. Nanoseconds per operation, from the commit that answered §17
question 13 and grew the cache slot by the chain's end; the table was first measured by the
commit that added it, and is re-measured whole whenever a change moves a row, because the rows
move together (below):

| Case | Fastest | Median |
| --- | --- | --- |
| harness overhead, an empty call through the same function pointer | 1.5 | 1.6 |
| query build, `example.com`, EDNS0, no cookie | 8.6 | 8.8 |
| query build, a 255-octet name, over TCP | 10.5 | 10.9 |
| name decode, two labels | 16.0 | 16.5 |
| name decode, through a compression pointer | 17.6 | 18.4 |
| response parse, one A record | 49.9 | 51.8 |
| response parse, a CNAME then its A record, with a 256-octet restore of the chain | 190.2 | 192.3 |
| response parse, 17 A records, 16 kept | 598.3 | 606.5 |
| datagram match, an id nobody holds, 1 in flight | 3.2 | 3.3 |
| datagram match, an id nobody holds, 1024 in flight | 3.2 | 3.3 |
| datagram match, right id and wrong question, 1 in flight | 36.8 | 37.7 |
| datagram match, right id and wrong question, 64 in flight | 37.6 | 38.1 |
| datagram match, right id and wrong question, 1024 in flight | 37.8 | 38.5 |
| datagram match, right id and wrong question, rotating over all 1024 slots | 56.6 | 58.3 |
| slot restore, a 3048-octet copy the accepted case pays and a caller does not | 42.3 | 43.0 |
| datagram match, accepted, 1024 in flight, with the slot restore | 142.8 | 144.3 |
| lookup round trip: `init_in_place`, `poll`, `on_sent`, `on_response` | 223.9 | 225.5 |
| `resolv.conf` parse, three lines | 340.8 | 348.6 |
| cache hit, one entry, hot | 33.0 | 33.8 |
| cache hit, rotating over 1024 entries | 46.1 | 47.3 |
| cache miss, 1024 entries, a young index | 12.4 | 12.7 |
| cache miss, 1024 entries, after churn | 36.4 | 37.5 |
| cache put, replacing an entry in place | 35.3 | 36.1 |
| cache put, evicting, 1024 entries and the table full | 91.6 | 93.5 |

The table and the notes below are older than §16 decision 42 (2026-10-14). Since that decision
the skip of each owner follows its pointers. So each record walked costs more than these rows
show.

What the table says, against the estimates:

- The estimates hold, and were pessimistic. A query builds in 9 ns. A response with one record
  parses in 52 ns, and one with seventeen records, sixteen of them kept, in 607 ns: about 35 ns for
  each record walked beyond the first — (607 − 52) / 16, the seventeenth walked and its owner
  decoded before it is refused — which is a skip, an owner name decoded through a pointer at 18 ns,
  and the address copied. A CNAME chain resolved in one message costs 192 ns: the chain moves
  once, the section is walked twice, five names are decoded on the way (the two owners on each of
  the two passes, and the CNAME's target once), three 256-octet copies move the chain, and the row
  carries the restore its name says.
- The demultiplexer is the constant it was designed to be. An id nobody holds is refused in 3 ns
  whether 1 or 1024 lookups are in flight, and a real id with the wrong question — the probe plus
  every check of §7 short of the answer walk — costs 38 ns at 1 in flight and at 1024.
  Accepting one at 1024 in flight costs 144 ns, of which 43 is the slot the harness puts back after
  each iteration, so 101 ns is the match, check 6 and the answer walk.
- Those rows aim every iteration at one slot, which sits in the first-level cache from the second
  iteration on. The rotating row aims each iteration at a different one of the 1024, whose 3 MiB
  do not fit the 128 KiB first level and do fit the 12 MiB second: the same path costs 58 ns there,
  so a slot read cold out of the first level adds 20 ns. A datagram arriving from the kernel finds
  its slot at least that cold.
- A whole lookup, minus the network — made in its slot, its query built with its cookie, the
  send heard, the answer read and its OPT record sought — is 226 ns. Against the shortest round
  trip the estimate considered, one millisecond, that is 0.023%: the network is about 4,400 times
  the library.
- The cookies of §19 step 10 cost 17 ns a lookup: the round trip read 185 ns before them and
  201 after, the accepted match 80 and 97 net of the restore. That is the COOKIE option written
  into every query, a 41-octet cookie copied out of the server table on the way, and the OPT
  record sought across the three sections of every accepted response for check 6. The slot
  restore row fell from 52 to 41 while the slot grew from 3032 octets to 3040, and rose to 54
  again at 3048: a copy of a size that is a multiple of 32 is the faster one, which is the layout
  effect below in another form. The table above reads 43 at the same 3048, so the size was not
  the whole of it: the layout of the binary moves this row as it moves the others.
- The failover of §19 step 12 costs 10 ns a lookup: the round trip read 201 ns before it and
  211 after. That is the order computed at the first poll — a sort of one server, the draw that
  decides a retry — and every read of the current server going through the order.
- The rdata buffer of §19 step 9 costs what is written, not what is held. With `collect` building
  a whole `Answers` per response, one A record parsed in 79 ns, a lookup started in 302 and a cache
  put in place took 60; with `reset` and `assign` touching only the storage a kind uses, and
  `init_in_place` building a lookup in its slot instead of in a local that is then copied, the
  three rows read 51, 185 and 38, which is below where two of them stood before the buffer
  existed, because the copy `init_in_place` removes was there at 864 octets too.
- The cache of §18 answers a hot hit in 34 ns — the keyed hash over the name, one probe, the
  folded compare and the division that turns the expiry into seconds — and a miss in 13 ns when
  the index is young, because the walk stops at the first empty entry. After churn, when every
  entry the evictions freed is a tombstone the walk steps over, a miss walks to the probe bound and
  costs 38 ns; that is the bound doing what §18 says, and `flush` is what resets it. A hit read
  cold over 1024 entries, 2.9 MiB of slots, costs 47 ns, 13 ns over the hot one. A put that
  replaces an entry in place costs 36 ns; one that has to evict, with the hand meeting an
  unvisited entry at once, 94 ns: the miss, the eviction's unlink and key removal, the key insert,
  and the answer's live storage written.
- The rows move with the binary they are built into, and by more than the run-to-run band. On
  the day the cache landed, the parse of one A record measured 45.0 ns in the binary before it,
  52.7 ns in the binary with it, and 42.8 ns in a binary holding only the three parse rows, and
  the code on that path was the same in all three: stubbing the two functions the change added
  moved nothing, and the row that walks seventeen records did not move either. That is the
  layout of the text and nothing else, and it puts a fifth on any single row. So a comparison
  reads within one table, built once, and never across two builds; and the run-to-run band of 2%
  is the harness's precision, not the number's.

What the table does not say: a slot evicted to memory, and not only out of the first level, costs
more than the rotating row shows. A memory access on this machine is on the order of a hundred
nanoseconds, a figure recalled and not measured, because the largest table there is fits the
second-level cache and the harness cannot build one that does not. It is still nothing against a
millisecond, but it is an estimate where the rest of this section is not.

**Against c-ares.** `zig build bench-cares` on 2026-09-22, the same machine and clock as the
table above: cocuyo ReleaseSafe against the Homebrew build of c-ares 1.34.8, which is its
shipping build, optimised, with its assertions compiled out. Five runs back to back; each cell is
the median of the five, and every one of them sits within 2% of the slowest run of its own row.
The cocuyo rows here are the same code as above measured in a different binary, and sit a tenth
below the table above — 7.7 ns against 8.6 for the query build — so a comparison reads within one
table and never across two. Nanoseconds per operation:

| Case | cocuyo | c-ares | c-ares over cocuyo |
| --- | --- | --- | --- |
| query build, `example.com`, EDNS0: cocuyo from a name it holds into the caller's buffer; c-ares from a prepared record into a buffer it allocates and the caller frees | 7.7 | 958.4 | 124 |
| the same, with c-ares building the record as well: create, question, OPT, write, both freed | 7.7 | 1,293.9 | 168 |
| response parse, one A record: cocuyo checks owners and copies the address out; c-ares parses to a record tree, the address is read, the tree is freed | 49.3 | 693.4 | 14 |
| response parse, a CNAME then its A record, the same two ways | 185.1 | 1,084.1 | 5.9 |
| response parse, 17 A records: cocuyo keeps sixteen and says so, c-ares keeps all seventeen | 583.5 | 4,157.7 | 7.1 |

What the comparison says, and what it does not:

- Before either side is timed, the step's own tests show the two are looking at the same thing.
  For the same id, name, type and OPT record, c-ares writes the query bytes cocuyo writes, octet
  for octet: two implementations of RFC 1035 and RFC 6891, written apart, agreeing — a check on
  cocuyo's builder that no fixture of its own could be. And c-ares reads from the corpus the
  records cocuyo reads, seventeen A records where cocuyo keeps sixteen and says so.
- The gap is the record model and the allocator, not the arithmetic. c-ares builds a heap object
  per message and per record and frees it; cocuyo copies into memory the caller sized once. That
  is what each library's caller pays per query, so it is the honest row, and it is not a claim
  that c-ares reads bytes slowly.
- The datagram match has no row. c-ares decides whose datagram it is inside `ares_process`, with
  its own sockets and its readiness callbacks, and there is no way to hand it one datagram and
  time the decision alone. That entanglement is what §1 exists to avoid, and it is also why the
  one operation cocuyo designed for a constant cannot be compared here.
- Every number here is against a round trip of a millisecond or more. c-ares's 1.3 µs to build
  a query is 0.13% of that. The comparison says which library does less work per query; it does
  not say a caller of c-ares would notice, and it does not claim c-ares is slow.

**Place frequently accessed fields together, and reduce the cache lines touched.** A naive
demultiplexer scans the slots, touching 856 bytes per candidate. Instead `Resolver` keeps a side
table of `MatchKey`, four bytes each, sixteen to a cache line, indexed by the low bits of the
transaction id with open addressing. Because the id is drawn from the generator it is uniform, so
one probe finds the slot, and only that slot is touched.

The hint's other half, grouping the fields a hot path reads, is **not** applied. Zig orders a
struct's fields as it likes, and the pinned measurement of §9 shows it reordering a lookup's
scalars across the names, so the state and the transaction id are not one cache line however they
are declared. Grouping them in a sub-struct would fix that and cost every use site a level of
naming. The rotating row of the table above is the one measurement that can see the effect,
because the rows that aim at one hot slot cannot: a slot read cold out of the first-level cache
costs 15 ns more than a hot one, and the grouping could recover at most a line or two of those
15 ns, next to a round trip of a million or more. It stays unmade, and that row is why.

**Bulk APIs.** `Resolver.poll` returns the next action for any slot, so the caller never loops
over the table. `next_deadline_ns` returns one deadline for the whole table, so the caller arms
one timer rather than one per lookup. `on_datagram` is one call per datagram.

**What one event costs does not grow with the table.** `poll` took the next slot in rotation and
walked the table to find one with something to do, and `next_deadline_ns` rescanned whenever an
event had invalidated its cache. Both are O(n) in the lookups in flight, and a caller driving a
completion loop polls after every event, so the work per event grew with the table: the
end-to-end comparison below held at about 26,000 lookups a second whether 16 or 128 were in
flight, with the latency growing in step. Two structures fix it, and neither changes what a
caller calls:

- **A ready list**, threaded through the caller's own slots (`table_ready.zig`): two links and a
  flag in each slot, the lookups with something to do in the order they got it. `start`, every
  event entry point and an expiry put a lookup on it; `poll` takes from the head. A lookup is
  offered once for each thing it has to do, which is the one visible change: a send whose
  completion has not arrived, and an answer the caller has been handed and not freed, are not
  offered twice. A caller must act on what it is given.
- **A deadline bound** in place of the cached minimum. A deadline that moves earlier lowers it; a
  lookup that stops waiting leaves it where it was. So the bound is never later than the true
  soonest, the caller's timer can fire early, and the poll that follows finds the exact minimum
  again with the one scan of the table. Firing early costs a wakeup; firing late would cost an
  answer. A poll that starts a wait, as `connect_tcp` does, puts that deadline in the bound as
  well as one that reports a wait. Until 2026-09-23 it did not, and with every query over TCP no
  timer was armed for a connection, so a connect that never completed waited for the kernel's
  own timeout; the engine's model found it (§19 step 13).

The slot grew by eight octets for the links and the flag, which §9 records.

**Do the cheap rejection first, and no unnecessary work.** The id compare precedes the endpoint
compare, which precedes the question compare, which precedes the answer walk. The security order
and the fast order are the same order, which is a pleasant accident worth writing down. In the
record walk the owner name is skipped without a copy until the type says the record is wanted.
Since 2026-10-14 the skip measures the whole name through its pointers (§16 decision 42). The
fast path — one server, no search expansion, the answer in the first datagram — makes one pass
and rebuilds nothing.

Two hints applied by refusing a feature: **thread-compatible, not thread-safe** (a `Lookup` is
touched only by its owner and cocuyo contains no lock or atomic), and **no promises that constrain
the implementation** (no iterator stability, no stable addresses for answers, which is why
`Answer` hands out slices into the slot and documents their lifetime as until the next call).

Not applied, on purpose: no hand-unrolling, no inline attributes, no specialised memcpy. They
waited for `bench/`, and `bench/` says none of them would buy anything a caller could see. A
change to any of these carries a new table, or it does not land.

### End to end against c-ares

§19 step 15's comparison, `zig build bench-cares` after its table: one responder, a process of its
own on the loopback, answers every query with one A record, and each stack resolves 20,000 distinct
absolute names against it, so neither's cache answers. Each row offers a load: 10,000, 40,000,
80,000 or 160,000 lookups a second, each sent when it is due whether or not the stack has answered
the ones before it, with at most 128 out (`bench/end_to_end/schedule.zig`). A lookup's latency runs
from when it was due to its result, so a stall shows in every lookup it held back. cocuyo's side is
the engine of §19 step 13 over rotor, built privately for the bench and run on this thread,
ReleaseSafe with its assertions on, and rotor ReleaseSafe as well; its loop waits until the next
lookup is due or an event comes.
c-ares's side is the Homebrew build of the version the binary prints, with its event thread, which
gives it a second thread of its own; this thread sleeps until a lookup is due and sends it with
`ares_query_dnsrec`. The responder and the kernel are in every latency and are the same for both. A
row gives lookups per second over the wall time; the median, the 99th and the 99.9th percentile and
the slowest latency, in microseconds; how late the 99th percentile of lookups went out, which is the
driver's part of the latency and not the stack's; the most out at once; and the system calls and
context switches of the stack's process per lookup, which the responder's process keeps out of.
macOS counts both for a process; Linux counts the switches, and system calls only for a tracer, so a
row there gives none.

A last row asks for what each stack's cache holds: 64 names, each asked and answered once before the
row, then asked in turn 20,000 times, one at a time and back to back. cocuyo's engine answers such a
lookup inside `start`, and c-ares inside `ares_query_dnsrec`, so a lookup answered before its start
returns is a hit, and the row counts them. A hit waits on no I/O, so the row is timed as the
microbenchmarks are: lookups per second, and each lookup's time from its start to its result, in
microseconds to the nanosecond. The rows above ask a new name every time, so neither cache answers
any of them, and their tests require it.

On Linux both benchmark programs export a `memset` of their own (`bench/memset.zig`). Every
`memset` a Zig 0.16 program calls there is compiler_rt's, which stores one byte at a time, and
cocuyo's rows would carry a loop that Zig's master has replaced. c-ares's calls keep glibc's
`memset`, as any C program's do. macOS programs call libSystem's, and export none.

The table below is from the driver before that one. It kept 1, 16 or 128 lookups in flight and
started one when another ended, c-ares's next from its callback. A driver like that sends nothing
while a stack stalls, so its percentiles leave the stall out (pepegrillo's method, step 1). The
table stands until a quiet machine measures the rows above (c4milo/cocuyo#5).

Measured on 2026-09-22, five runs back to back on the machine above, on the driver as it stood
after the fixes listed below. Each cell is the median of the runs that produced its row, and the
last column says how many did: four of the fifteen c-ares rows never finished, for the reason
below. Lookups per second, and microseconds:

| Stack | In flight | Lookups/s | Median | p99 | Failures | Runs |
| --- | --- | --- | --- | --- | --- | --- |
| cocuyo | 1 | 45,199 | 20 | 78 | 0 | 5 |
| c-ares | 1 | 36,304 | 27 | 42 | 0 | 2 |
| cocuyo | 16 | 110,194 | 128 | 409 | 0 | 5 |
| c-ares | 16 | 87,306 | 178 | 272 | 0 | 5 |
| cocuyo | 128 | 122,089 | 1,023 | 1,724 | 0 | 5 |
| c-ares | 128 | 82,554 | 1,498 | 2,038 | 0 | 4 |

What the rows say, and what they do not:

- cocuyo resolves 1.24 times as many lookups a second as c-ares at one in flight, 1.26 at
  sixteen and 1.48 at 128, and its median latency is lower on every row. That is a far smaller
  ratio than the decoder table above, and it is the honest one: the responder, two system calls
  per lookup and the kernel's loopback are in every number and are the same for both, so what is
  left to differ is the library and the loop around it.
- c-ares has the better tail at one in flight and at sixteen — 42 microseconds against 78, and
  272 against 409 — and cocuyo the better tail at 128. cocuyo's p99 at sixteen is also its least
  steady cell: two runs put it near 190 microseconds and three near 420.
- On 2026-09-26 the gap at one in flight was traced to the order of the runs (c4milo/cocuyo#5).
  The first run in a process spent its first 200 lookups at about 95 microseconds, against 22
  after them: 1% of the run, enough to fill the p99 alone. It did so whether or not the engine's
  memory was touched first, and a second run in the same process did not, so the warm-up was the
  process's, the responder's thread and the cores coming up to speed, and it fell on whichever
  stack ran first, which was cocuyo in every row. Warm, cocuyo's p99 at one in flight came out 57
  to 64 microseconds. The comparison now runs 2,000 lookups unmeasured before its first row. Two
  runs after that change, on a machine busy with other work, put the two tails at one in flight
  within each other's noise, and cocuyo's at or below c-ares's at sixteen. The table above stands
  until a quiet machine measures it again.
- From sixteen in flight to 128, cocuyo gains 11% and c-ares loses 5%, while latency grows about
  eightfold for both. The responder is one thread, and past sixteen in flight it is much of what
  the run measures.
- c-ares at one in flight rests on two runs. Four more runs of that row alone, taken to diagnose
  the stall below, finished three times at 35,876, 36,326 and 36,561: within 1% of the cell.
- Nothing here says anything about Linux, about a real network, or about a working set that a
  cache would answer: the names are distinct, so neither cache is ever asked twice.
- cocuyo's side ran over a Debug rotor. A rotor asked for no mode builds Debug, and until
  2026-10-01 the build asked for none, so every lookup of cocuyo's also paid for rotor's loop
  unoptimized. Nothing measured how much, so the rows overstate cocuyo's latencies and understate
  its throughput by an amount not known (docs/performance.md, the first pitfall).

**This table replaced one measured earlier the same day, and was not averaged with it.** The
earlier driver lost a lookup's start when c-ares answered while the slot was being let go, and
held row one's first queries until the responder's thread began reading. Both stacks measured
faster here at sixteen and at 128 — c-ares by about a fifth, cocuyo by more — while the ratios
at one and at sixteen stayed within 0.04 of the earlier ones. The lost starts could have held
c-ares back, but nothing measured says how much of the common rise they explain, so the claim is
the ratio within this table and not a gain across the two.

**Four c-ares rows did not finish, and c-ares had the reply each time it was asked.** When a
row gives up, the driver prints the lookups it claimed and those c-ares answered, and the
responder the queries it answered. A stalled row at one in flight read: 5,215 claimed, 5,214
answered by c-ares, 5,215 answered by the responder. So the driver lost nothing — every claim was
issued — and c-ares sent the last query, was sent its reply, and neither handed the reply to the
callback nor timed the query out in the sixty seconds the driver waited. A stack sample of an
earlier stall showed c-ares's event thread parked in `kevent` and the responder idle. It happened
in three of five rows at one in flight, once at 128, and once more at 128 on Linux. Every lookup
after the first is started from inside the previous one's callback, which c-ares allows; whether
that is what exposes it is not measured.

**Five defects in the comparison's own driver had to go first**, and each of them would have
made a row a lie: one second of wait per lookup at one in flight (K1), a stack overflow from
starting the next lookup inside c-ares's callback (K2), a panic from starting one on a channel
being destroyed (K3), a lost start when an answer landed while the slot was let go (R1 to R4,
with the handoff now checked in every order it can run), and the responder's start-up delay in
row one. Separately, the engine's buffer group claimed an alignment no loader keeps, and the
bench aborted in ReleaseSafe until it stopped (N1). A harness is code, and until it is proved
it measures itself.

What the first run found. The engine's `drive` polled the table up to 4,096 times per call, and a
lookup that has ended and waits for `take` answers every poll with its end again, so every drive
spun through 4,096 polls over it: cocuyo did 221 lookups a second at one in flight, 4.5 ms each,
all of it that spin. A drive is now one rotation over the engine's slots, and the row became
what the table shows. That is what an end-to-end number is for: no unit test on the twin could
see a cost that changes nothing observable, and no microbenchmark row ran a drive over a settled
lookup.

## 12. Named limits

Each limit lives in its module's `limits.zig` with a doc comment saying why that number, and is
never written at the use site. Shared limits live in `src/core/limits.zig`. The protocol sizes
and the defaults live in `constants.zig` the same way (§16 decision 56). The table holds all
three. Each integer constant carries the type of what it names. The typed-constants rule of
`zig build lint` and a test in each constants file and limits file hold it. A length, an offset
or a count is a `usize`, so its sum with a narrow value is a `usize` too (§16 decision 40).

| Constant | Value | Why |
| --- | --- | --- |
| `header_bytes` | 12 | RFC 1035 §4.1.1 |
| `message_bytes_max` | 65535 | the TCP length prefix is 16 bits |
| `udp_payload_bytes_default` | 1232 | the widely recommended EDNS0 size that avoids IPv6 fragmentation; recalled, not measured |
| `query_bytes_max` | 386 | 12 header + 255 qname + 4 type and class + 55 OPT + 4 Padding option header, padded to 384 (§21), + 2 TCP prefix |
| `name_bytes_max` | 255 | RFC 1035 §2.3.4; §3.1 counts the labels, their length octets and the root |
| `name_text_bytes_max` | 1020 | four bytes per wire byte, the `\DDD` escape worst case |
| `label_bytes_max` | 63 | RFC 1035 §2.3.4 |
| `labels_max` | 128 | 255 bytes at two bytes minimum per label |
| `compression_hops_max` | 16 | a legal name needs none; 16 is slack over any real encoder |
| `cname_hops_max` | 8 | matches the chain length BIND allows; recalled, not measured |
| `records_max` | 64 | bounds the walk whatever the count fields claim |
| `addresses_max` | 16 | §17 asks whether this is enough for large round-robin names |
| `ptr_names_max` | 1 | a reverse lookup returns one name in practice, and `truncated` says when more existed |
| `cookie_client_bytes` | 8 | RFC 7873 §4 |
| `cookie_server_bytes_max` | 32 | RFC 7873 §4; a server cookie is 8 to 32 octets, 16 under RFC 9018 |
| `cookie_silence_ns` | 5 min | RFC 9018 §3's example of how long a server without cookies is sent none; `src/resolver/constants.zig` |
| `case_draws_max` | 4 | the draws of one name's case before its first letter is made a capital (§7): two letters fall back once in 256 names; chosen, not measured; `src/wire/limits.zig` |
| `opt_record_bytes_max` | 55 | the OPT record with the largest COOKIE option, before any padding |
| `padding_block_bytes` | 128 | RFC 8467 §4.1: a query to a TLS server is a whole number of these |
| `records_kept_max` | 32 | the records of one type a lookup keeps for every other type (§19 step 9); `truncated` past it |
| `lookup_sources_max` | 2 | the hosts file and DNS, each named at most once in `Config.lookups` |
| `failover_retry_chance_default` | 10 | c-ares's default: one query in ten retries a failed server first (§19 step 12) |
| `failover_retry_delay_ns_default` | 5 s | c-ares's default: how long a failed server stays last |
| `hosts_lines_max` | 4096 | the most lines read from a hosts file; a blocklist is longer, and past it is dropped and said so |
| `hosts_entries_max` | 1024 | the most entries kept from one |
| `hosts_names_per_entry_max` | 8 | the official name and its aliases on one line |
| `hosts_names_bytes_max` | 65536 | the wire names of one hosts storage, a `u16` offset each |
| `rdata_bytes_max` | 2048 | one UDP payload with room for the names written out in full (§19 step 9); `truncated` when a TCP answer does not fit |
| `servers_max` | 8 | glibc's MAXNS is 3; 8 leaves room and still bounds the loop |
| `search_max` | 6 | glibc's MAXDNSRCH; recalled, not measured |
| `attempts_default` | 2 | the `resolv.conf` default |
| `attempts_max` | 5 | bounds the retry loop; the passes past the third find each server with no query left (§16 decision 58) |
| `queries_per_transport_max` | 3 | the queries one lookup sends one server for one name over one transport: "A resolver MUST NOT retry a given query to a server address over a given DNS transport more than twice" (RFC 9520 §3.1); `src/resolver/limits.zig`, since 2026-10-27 (§16 decision 58) |
| `ndots_default` | 1 | the `resolv.conf` default |
| `ndots_limit` | 15 | `resolv.conf(5)`'s cap on `ndots:`, which reads a larger value as 15; in `src/config/limits.zig` since 2026-10-26, in `src/config/constants.zig` from 2026-10-13, and in the parser's own file before |
| `timeout_seconds_limit` | 30 | `resolv.conf(5)`'s cap on `timeout:`, in seconds, and `timeout_ns_max` in seconds, so the parser can raise the cap to any timeout it reads; in `src/config/limits.zig` since 2026-10-26, and in `src/config/constants.zig` from 2026-10-13 |
| `timeout_ns_default` | 2 s | a server's wait until it has 3 samples (§5): c-ares's `ARES_OPT_TIMEOUTMS` default, read from its features page, not measured; 5 s, the `resolv.conf` default, until 2026-10-09 |
| `timeout_ns_max_default` | 5 s | the default cap on every wait, measured or doubled: c-ares's, read from its features page, not measured |
| `timeout_ns_max` | 30 s | the most a configuration's cap may be, and `resolv.conf(5)`'s cap on `timeout:`; the default cap until 2026-10-09 |
| `timeout_ns_min` | 250 ms | the floor under every wait, which a lower cap overrides: c-ares's, read from its features page, not measured |
| `latency_wait_multiplier` | 5 | a measured wait is the average latency times this: c-ares's, read from its features page, not measured; `src/resolver/constants.zig` |
| `latency_samples_min` | 3 | the samples a server needs, and a window needs, before a wait is read from them: c-ares's, read from its features page, not measured; `src/resolver/limits.zig` |
| `latency_window_minute_ns`, `_quarter_hour_ns`, `_hour_ns`, `_day_ns` | 1 min, 15 min, 1 h, 1 day | the spans of four of the five windows of samples, the fifth being since the table was built: c-ares's, read from its features page, not measured; `src/resolver/constants.zig` |
| `port_ephemeral_min`, `_max` | 49152, 65535 | the IANA ephemeral range |
| `lookup_slots_max` | 1024 | bounds a `Handle` index and the key table |
| `cache_ttl_seconds_max_default` | 3600 s | the default of `Config.cache_ttl_seconds_max`, the cap on every TTL a cache keeps: c-ares's default (§18), and inside the seven days RFC 8767 §4 recommends; in `core` since 2026-10-11, because `Config` and the cache both read it, and `cache.constants.ttl_seconds_max_default` is the same constant by its older name |
| `cache_ttl_seconds_max` | 604800 s | the most `Config.cache_ttl_seconds_max` may be, and the most `Cache.init` takes: seven days, "a recommended cap of 604,800 seconds (7 days)" (RFC 8767 §4); the owner's ruling of 2026-10-11 (§16 decision 37) |
| `cache_failure_seconds_min_default` | 5 s | the default of `Config.cache_failure_seconds_min`, the first time a cache keeps a resolution failure: the example of RFC 9520 §3.2; `cache.constants.failure_seconds_min_default` is the same constant (§16 decision 60) |
| `cache_failure_seconds_least` | 1 s | the least `Config.cache_failure_seconds_min` may be: "at least 1 second" (RFC 9520 §3.2); `cache.limits.failure_seconds_least` is the same limit (§16 decision 60) |
| `cache_failure_seconds_max` | 300 s | the most `Config.cache_failure_seconds_min` may be, and where the backoff stops: "not longer than 5 minutes" (RFC 9520 §3.2); `cache.limits.failure_seconds_max` is the same limit (§16 decision 60) |

## 13. Tests, mutation and fuzzing

Tests live in the file they test. `sim` is a scripted server and a virtual clock: a script is a
table of what each server does on each try — answer, NXDOMAIN, SERVFAIL, FORMERR, truncated,
malformed, silence, or a spoof from the wrong port — and the seed drives both the script and the
lookup's generator. One seed replays byte-identically, because the query bytes are a function of
the seed and the answers are a function of the script.

A test must fail when the code it covers is broken. Every check lands with its mutation, the
result is reported as `CAUGHT` or `NOT CAUGHT`, and `NOT CAUGHT` means a test is missing and gets
written. `docs/mutations.md` is the table; the result goes in the body of the commit that adds the
check. The starting list:

| # | Mutation | Expected to be caught by |
| --- | --- | --- |
| 1 | accept a compression pointer that points forwards | the crafted-loop message test |
| 2 | drop the strictly-backwards rule, keep the hop bound | the pointer-loop and name-length tests |
| 3 | match on transaction id alone | the spoofed-question test |
| 4 | skip the source endpoint compare | the off-path spoof test |
| 5 | compare the question case-insensitively | the 0x20 test |
| 6 | trust `ancount` past the end of the message | the lying-count test |
| 7 | accept an `A` whose owner is not in the chain | the injected-record test |
| 8 | off-by-one in the rdlength bound | the truncated-rdata test |
| 9 | remove the CNAME hop bound | the chain-loop script |
| 10 | re-arm the deadline on an ignored datagram | the flood-does-not-extend-the-wait test |
| 11 | keep the same transaction id across a CNAME re-query | the re-query entropy test |
| 12 | advance the search candidate on SERVFAIL | the policy table test |

The state machine is also checked against a model. spec/ states §5 in Lean 4, proves what §5
promises of it, and writes every transition the model can reach under a set of small
configurations; `tools/spec_replay/` drives `Lookup` down the same transitions and compares the
whole state after each (§5, The model). The engine's streams are checked the same way, against a
model of their rules, over walks the model chooses and orders of completion the network never
produces (§19 step 13). A test above pins the cases someone thought of, and a replay pins what
the model reaches.

The fuzz target drives the parser from a seeded generator that mixes pure random bytes with
structured hostility: valid headers over lying counts, pointers at every offset, labels that run
past the end, rdata lengths one byte too long, names at exactly 255 and 256 bytes. The invariants:
the parser never reads outside the message, always terminates, and never returns a name longer
than `name_bytes_max`.

Until 2026-10-10 two of those did not hold. The one question name that parsed as a question of
class IN was `example.com`, 13 octets, so the gate never ran check 5 of §7 over a long name. Check
5 summed the offsets of the type and the class in the octet a name's length is held in, and a name
of 242 octets or more overflowed it: a panic on the answer to such a name (docs/mutations.md,
Sums at the most their operands reach). And a pointer maze lost the high bits of each target, so
no pointer aimed past offset 255. The generator now writes questions whose names are 192 to 255
octets long, of types cocuyo asks, and a maze's pointers aim anywhere in the message. A test pins
each: the gate's seeds reach every one of those lengths, and most mazes aim past offset 255. The
target runs check 5 over each such question, and `matches_lowercase` over its echo in lowercase,
since the two compares share the reads that overflowed.

Since check 5 reads a mixed query's echo in place (§7, A server that changes the case), the target
holds that compare to the one it replaced, over every question that parses, the long ones among
them. With the name parsed as the name held and a seed the header's octets give, `matches_mixed`
must say what `matches` says of the name `mix_case` builds: of the message itself, and of the
question a query mixed from that seed sends.

Since 2026-10-13 the generator also writes the length fields that the readers of several types
share, at their most. A record's rdlength, an EDNS option's length and an SVCB parameter's length
are 0xFFFF or 0xFFFE, and each runs past what holds it. A TXT string, a CAA tag and an alpn-id have
255 octets, and a name has labels of 63 octets. A COOKIE option has 8, 16, 40 or 41 octets, and its
data ends at the end of its OPT record. The target reads the OPT record's options as a lookup reads
them. A long strategy writes messages of up to 65,535 octets. A copy of the question's name is at
offset 16,383, the farthest offset that a pointer names. A pointer to it is the owner of the last
answer, which ends the message. Tests pin that the gate's seeds reach each value, and that each
value reaches its reader (docs/mutations.md, Tests at the named limits). That day the target
moved to `src/wire/fuzz/`.

Since 2026-10-14 the target holds the skip of the record walk to the decode. At each offset where
it aims both, the two give the same end or the same error. Before, it compared the two only where
the decode took the name. The target also decodes each owner that the record walk passes, and each must
decode. The long-question strategy now writes the first answer's owner as labels and a pointer to
the question's name, 255 octets whole or 256. Before that day no strategy wrote such a name on
purpose. Over the gate's 4096 seeds, noise held 2,415 names longer than 255 octets that the old
skip took. The target compared no two walks where the decode refused, and the record walk passed
none of those names as an owner. A test pins that the seeds reach an owner of 255 octets and one
of 256. The skip and the decode end the first, and refuse the second (§16 decision 42).

A second target, since 2026-09-26, reads what the caller hands in rather than what the network
sends (`src/config/fuzz/`): an address, a name, a `resolv.conf`, a hosts file and an SPKI pin.
Each text is written whole from values the generator chose, and must read back as those; or has
one byte changed, and may be taken or refused; or is a near miss the grammar refuses, and must be
refused, which for a file is a whole file with one bad line that must be skipped; or is noise.
Whatever a parser takes, it reads the same way twice, and gives back: an accepted name written
out reads back as itself, and an accepted pin encodes to the text it came from, since a pin has
one spelling. A DoH template, which lives in the engine's `doh` module, has a seeded test of the
same kind beside its splitter.

Line coverage is measured by kcov over every module's tests and the model replays' (`zig build
coverage`, since 2026-09-26), with test code left out and `src/sim/`, the twin, apart. It measured
96.3% of the library's and the engine's 6,805 lines that day, on arm64 Linux in a container, and
96.9% once the replays and the tests the unrun lines asked for were in. A function nothing
references has no code to count, so the figure says nothing of it. A report with a part of the
tree that counted no line is refused: kcov's paths missed the tree, and the part did not all run.
CI measured 97.5% of 6,807 lines the same day on x86_64 Linux, whose line tables differ. The
report refuses a total under 96.5% (`floor_percent` in `tools/coverage.zig`), under both figures,
so a change that takes tests away fails CI's coverage job. `zig build test` runs the report over two
reports it writes, one that runs no line and one with no line at all, and requires both refused.

Each target's gate runs 4,096 seeds in `zig build test`, and prints the seed of a failure. `zig
build fuzz -- [--text] --seed <hex>` runs one seed and prints what it built, and `zig build
fuzz-gate -- [--text] [<count> [<first>]]` runs a range, a million seeds unless told otherwise,
ReleaseSafe with every check on. Until 2026-09-26 this paragraph named both steps and neither
existed.

## 14. What cocuyo sees, and what the platform resolver sees

This belongs in the README in full, because a consumer has to choose deliberately.

cocuyo sends DNS queries to the servers it is given. That is all it does. It is not the system
resolver, and on a Mac it is not even close to it.

- **macOS.** `/etc/resolv.conf` is a partial, legacy view. The system resolves through per-interface
  configuration held by `SCDynamicStore` and read by `res_getservers`, and through mDNSResponder
  for `.local` and for split-DNS domains routed to a VPN. A program calling
  `DNSServiceGetAddrInfo` or `getaddrinfo` sees all of that. cocuyo reading `resolv.conf` sees
  none of it: no per-interface resolver, no VPN split DNS, no mDNS.
- **Linux with systemd-resolved.** `/etc/resolv.conf` usually points at the 127.0.0.53 stub, which
  does re-expand into per-link routing, so a cocuyo caller gets closer to parity there. Where
  `resolv.conf` is instead a static list, per-link domains are invisible.
- **Everywhere.** cocuyo reads the hosts file only when the caller parses it with
  `config.hosts` and hands over the table (§19 step 11). It does not consult nsswitch, and does
  not know about NIS, LDAP or mDNS. A name that resolves for every other program on the box can
  fail here, and that is by design, not a bug.

Choose cocuyo when you want a resolver that is explicit, testable and identical on every host: a
server, a proxy, a container. Choose `getaddrinfo` on a thread when you need exactly what the rest
of the machine sees.

## 15. Build plan

Each step is a commit or a few, and each names the check that proves it. Nothing moves to the next
step until `zig build test` passes.

- **Step 0.** `build.zig`, the module graph with its enforced direction, `CLAUDE.md`, the lint
  rules, `.gitignore`. Gate: `zig build lint` clean on an empty tree.
- **Step 1.** `core`: types, limits, `Name` between text and wire form, the escape rules. Gate:
  unit tests and the `@sizeOf` pins.
- **Step 2.** `wire`: header, name decode, question, records, query build, EDNS0. Gate: hand-written
  golden messages, byte for byte, plus the fuzz gate, plus mutations 1, 2, 6 and 8.
- **Step 3.** `Lookup`: every state and every transition of §5. Gate: the scripted harness covering
  each row of the transition table, plus mutations 3, 4, 5, 7, 9, 10, 11 and 12.
- **Step 4.** `Resolver`: the slot table, the key table, the deadline cache. Gate: many concurrent
  lookups under one script, including cross-talk — a datagram carrying lookup A's id but lookup B's
  question must be ignored, and A's real answer must still land.
- **Step 5.** `config`: the `resolv.conf` parser. Gate: table tests over real files and malformed
  ones.
- **Step 6.** `examples/udp_blocking.zig`, about 50 lines over a blocking socket, and the README
  including §14 in full.
- **Step 7.** `bench/`: query build, response parse, datagram match, in nanoseconds per operation.
  Every estimate in §11 is then either confirmed or corrected in place. Done: §11 carries the
  table, the machine and the command, and the harness's own tests run under `zig build test`.
- **Step 8.** `cache`: the SIEVE cache of §18 with the negative TTL of RFC 2308 under it. Done
  on 2026-09-22; §11 carries its rows.
- **Steps 9 to 15.** The gap with c-ares, §19: every record type (9), DNS cookies (10),
  configuration parity and the hosts file (11), server failover (12), the engine over rotor
  with its deterministic twin first (13), the `getaddrinfo` shape (14), RFC 6724 ordering and
  the end-to-end comparison (15). Each names its gate there.
- **Step 16.** The package a consumer gets, §20: the cache under the table as a `Memory` the
  caller supplies, so every lookup shape is cached and the policy of RFC 2308 §5 is written
  once; the module surface closed to `cocuyo` alone; and a dependent build the gate compiles.
  Asked for by colibri's driver on 2026-09-22. Its gate is §20's list of checks.

## 16. Decisions, with the alternatives they beat

1. **Two layers, `Lookup` and `Resolver`.** Rejected: only `Resolver`, which forces our table on a
   caller that has one; and only `Lookup`, which makes every caller rewrite the matching rules of
   §7, which is the one piece of this library that must not be rewritten casually.
2. **`poll` returns an action; the caller confirms with `on_sent`.** Rejected: a readiness callback
   in the shape of `ARES_OPT_SOCK_STATE_CB`, which is the thing this library exists to avoid; and
   inferring that the send happened, which is wrong on a completion-based loop where the send
   completes later and can fail.
3. **The caller owns the send buffer; queries are rebuilt, not stored.** Rejected: a 284-byte query
   buffer per slot, which is a quarter of the slot for bytes that are a pure function of state.
4. **The caller frames the TCP stream, with `wire.message_len`.** Rejected: a reassembly buffer in
   the slot, which would be up to 64 KiB for the rare path.
5. **DNS-0x20 in v1, on by default.** Rejected: deferring it. The entropy plumbing exists for the
   transaction id anyway, the case mixer is small, and it is the only entropy a stub can add when
   the caller reuses one socket. Amended by the owner on 2026-10-09: a server that answers a mixed
   name in another case is asked without mixing from then on, for the life of the `Servers` table,
   and every other server keeps 0x20. The response that shows it is ignored, and the wait stands.
   The review of the same day narrowed it before it was committed: only an echo in lowercase
   marks, a marked server is asked in lowercase, and a mixed name always carries a capital, so no
   echo of cocuyo's own mixed queries marks a server, as two lookups that drew one id, or a late
   answer to a lookup's earlier query, would otherwise do with no attacker. The cost is that an
   attacker who matches the id and the source port, and the cookie where the query carried one,
   can switch 0x20 off for that one server until the table is built again; that a server that
   changes the case some other way still waits out every deadline; and that a name of L letters
   takes one of 2^L - 1 cases rather than 2^L. Rejected: 0x20 off by default, as c-ares has it,
   which gives up what this decision chose; asking the server again at once without mixing, which
   lets a datagram that failed a check cut the wait short (decision 10); turning it off for every
   server, which costs every server its entropy for one server's fault; a mark on any case, which
   the table's own lookups make; a table that marks only when no lookup accepted the datagram,
   which a late answer escapes; and a mark on lowercase with the mix left as it was, which keeps
   the false mark at a rate of 2^-L. §7, A server that changes the case. Amended by the owner
   on 2026-10-09 again, on what check 5 cost: a reply is read against the case the seed gives the
   held name in place, and the cased name is built only when the first draw left every letter
   small, or to assert that a lowercase echo about to mark its server is not the name sent. The
   check that the cased name is the held name in another case runs where the query is built, and
   no longer on each reply: while the lookup waits, the held name, the case seed and the record
   of whether the query mixed are what the build had, so a rebuild per reply re-ran a
   deterministic function the build had checked. `wire` gains the public declarations that carry
   it, which the owner allowed the same day, since `wire` is public through `src/cocuyo.zig`.
   Rejected: building the cased name for every datagram offered to a lookup, which was the
   cost the ruling removed; and restating that check per octet inside the compare, which says
   only what the compare computes.
6. **Port randomisation is the caller's duty, with a hint offered.** Rejected: requiring a socket
   per query, which would mean owning sockets.
7. **`Config` lives in `core`; the parser is a module the state machine cannot import.** Rejected:
   a parser that returns its own type, which would make the state machine depend on the file format.
8. **Names are stored in wire form; text conversion writes into the caller's buffer.** Rejected:
   storing presentation form, which is up to 1020 bytes per name and four times the size for the
   escapes almost nobody uses.
9. **One question per lookup.** Rejected: an A-plus-AAAA compound lookup, which doubles the state
   machine to save the caller one `start` call.
10. **A malformed or unmatched datagram never disturbs the wait.** Rejected: treating a malformed
    reply as this attempt's failure, which hands an off-path attacker a cheap way to cut the wait
    short and force a retry they can race. Amended on 2026-10-14 by decision 43. A datagram that
    the buffer cut can move its lookup to TCP, as an answer with TC set does (§7). Over a
    connection the attacker cannot race that retry. With no connection to have, the lookup asks
    the next server over UDP, and the attacker can race that retry. A forged answer with TC set
    could do the same before.
11. **Sequential servers with rotation.** Rejected: querying every server at once, which multiplies
    load on the resolvers for a latency win that belongs to the caller's policy, not ours.
12. **Assertions and checks both, on the same bound.** Rejected: one or the other. They are
    different claims, and §8 says which is which.
13. **The engine is a second module of this repository, over rotor, outside `src/`.** Rejected:
    the engine in every consumer, a third repository, or the engine under `src/`, which
    non-negotiable 1 forbids. §19 step 13.
14. **Records are copied into a fixed rdata buffer per lookup, names written out in full.** Rejected:
    a view of the message during `on_response`, the whole message per slot, and a
    caller-provided buffer, which stays the fallback. §19 step 9.
15. **Per-server state lives in a `Servers` table the caller owns and `Resolver` holds.**
    Rejected: in `Config`, which is shared and constant, or in `Lookup`, which is per question.
    §19 step 10.
16. **A compressed name is decoded wherever it appears in rdata.** Rejected: refusing the types
    whose RFC forbids compression as malformed, which fails a lookup for a server's fault. §19
    step 9.
17. **Failover retries a failed server with a real query.** Rejected: c-ares's probe with a copy
    of the query, which is a second transaction §7's defences do not bind. §19 step 12.
18. **The `getaddrinfo` shape is a composition above the table.** Rejected: an A-plus-AAAA state
    machine, which decision 9 refused and still does; the join in the engine, which is held
    back; leaving it to the consumer, which then owns the lockstep search walk and the
    `v4_mapped` rule, the two things a `getaddrinfo` caller gets wrong. §19 step 14.
19. **RFC 6724 ordering is a pure function over routes the consumer supplies.** Rejected:
    learning a source per destination by connecting sockets, which is I/O; dropping the rules
    that need a source, which would deny them to a consumer that knows its routes. §19 step 15.
20. **The table hands out work from a ready list, and offers each thing once.** Rejected: the
    rotation that walked the table, which made one event's cost grow with the lookups in flight;
    a ready list that keeps offering a lookup until the caller acts, which is the same walk by
    another name for a caller that cannot act yet; and a caller-provided queue, which is memory
    the caller would have to size. The links live in the slots the caller already provides. §11.
21. **`next_deadline_ns` is a bound, not the minimum.** Rejected: invalidating it on every event,
    which is a rescan per event; and keeping it exact by tracking every deadline that moves,
    which is a heap in the table for a timer that costs nothing to re-arm. §11.
22. **The cache reaches the table as a `Memory` the caller supplies.** Rejected: `Resolver`
    importing `cache`, which §3's graph forbids and for good reason; `Resolver` generic over its
    cache, which changes every signature that names it; and leaving the policy in each consumer,
    which is two readings of RFC 2308 §5 for a rule that belongs with the DNS. §20.
23. **A cache hit is a lookup that is already over.** Rejected: a synchronous hit returned by
    `start`, which saves a slot and a 3 KiB copy and makes `AddressLookup` and `NameLookup` each
    learn a second control path, consuming an answer inside their own `init`. The copy is 53 ns
    against a round trip of a millisecond, and it buys every lookup shape a cache. §20.
24. **The engine model is TLA+, checked by TLC; the lookup's stays Lean.** Ruled by the owner on
    2026-09-24 (issue #9). The engine model is only ever checked, never proved, and TLC is made
    for checking: symmetry, fingerprints in place of whole states, worker threads, and liveness.
    The Lean walker it replaces holds every state whole on one thread, and before it sorted its
    states its TLS graph at four operations and one failure did not finish in an hour. Rejected: extending that walker, which
    rebuilds TLC by hand; and a TLA+ model beside the Lean one, two models of one set of rules
    that can drift. The lookup's model carries proofs no bounded check gives, so it stays in
    Lean. pepegrillo's `tla` and `lean` tools run both, from `spec/tla/` and `spec/lean/`.
    §19 step 13.
25. **A server that refuses a lookup has failed it, as one that answers SERVFAIL has.** Ruled
    by the owner on 2026-09-24 (issue #11). A connection or a handshake that fails, or a DoH or
    DoQ request that ends without an answer, makes a lookup whose passes run out end in
    `AllServersFailed`, and `Timeout` means that every try went unanswered. Before, only an
    answer counted: a lookup every server refused, strict DoT's refusal of each certificate
    included, ended in `Timeout`, as one no server answered does, and `Timeout`'s own comment
    said every pass ran out of time. Rejected: a new error for strict mode's refusal, which
    needs the lookup to learn why a stream failed, a second change to the API in a call every
    consumer that owns its sockets makes; and the engine reporting each server's last failure
    beside the result, which leaves `Timeout` saying time ran out to every consumer outside it.
    A socket the system refuses reaches the lookup as a failed connection too, and counts,
    though the server said nothing: the call carries no reason. A failed send stays silence.
    The lookup model proves that a lookup any server refused never ends in `Timeout`. §5.

    Since 2026-10-21 both calls carry a reason, and the cause reports it (decision 51). A local
    failure still counts against the server, as this decision says. The text above is the record
    of 2026-09-24.
26. **DoH and DoQ are the engine's, over colibri's HTTP/3 and QUIC.** Ruled by the owner on
    2026-09-25 (issue #10). colibri declined the driver §22 and §23 gave it: it owns no I/O,
    rotor is test-only there, and it has no TLS of its own. Rejected: a package of its own over
    colibri, chapulin and rotor, which rebuilds the engine's loop, table, timers, idle close,
    tickets, twin, model and replay; and colibri owning the driver, against colibri's rules. The
    library in `src/` still depends on nothing, the engine may use colibri, and colibri's library
    never uses cocuyo. It reverses the first rulings of §22 and §23. §24.
27. **The engine runs in the caller's loop, and is exported.** Ruled by the owner on 2026-09-25.
    Embedded, it runs on the consumer's rotor loop beside the consumer's own work; on its own,
    on a loop of its own. The consumer binds the engine's `rotor`, and colibri, so an image holds
    one of each. Rejected: an engine that owns its loop, which puts a second loop, and a second
    thread, in every consumer that has one. It replaces the ruling of 2026-09-22 that held the
    engine back until a consumer asked. §24.
28. **A thread per core, and nothing shared between cores.** Ruled by the owner on 2026-09-25.
    One loop on each core and one engine on each loop, each with its own table, cache,
    connections and seeds. Rejected: an engine or a cache shared across threads, which needs a
    lock or atomics in the lookup's path. The cost is a cache on each core, and a connection
    from each core to each encrypted server. §24.
29. **The gate runs the engine over two QUIC transports: the twin's, and colibri's.** Ruled by
    the owner on 2026-09-25. The twin's `sim.quic` carries the model's replay and the failure
    paths, since the replay needs each step of the model when the walk names it: a handshake on
    another protocol, a stream reset, a QUIC timer due at a chosen instant. colibri's QUIC runs
    on the twin as an integration test, with a TLS provider of cocuyo's that encrypts nothing,
    and colibri is pinned by hash as a lazy dependency. Rejected: colibri alone, which makes
    those steps from packets and loss timers, never on demand; and the twin alone, which leaves
    real QUIC to the live check that runs once a day. §24.

    Since colibri v0.8.0, pinned on 2026-10-20, the suite names the QUIC version of each packet
    (colibri's decision 108). A client lists version 2 first, and a server may switch it to
    version 2, as colibri's server does by default (its decision 111). The suite that encrypts
    nothing refuses that switch, and colibri then drops the packet that asked for it. No packet on
    the twin asks for it, because the test server never asks colibri to choose a version. So
    colibri's QUIC on the twin speaks version 1 alone, 0x00000001 (RFC 9000 §15).

    Over chapulin, DoQ and DoH on HTTP/3 may run on version 2, and a ticket names the version of
    its connection. A session that resumes with such a ticket starts in that version. So since
    2026-10-20 each connection of `cocuyo_quic` starts in the version that its session names
    (§24, chapulin under colibri). §17 question 57 asks about the call that names it.
30. **A DoH server is tried over HTTP/3 first, and over HTTP/2 when that fails.** Ruled by the
    owner on 2026-09-26. RFC 9114 §3.1 asks for it: a network that blocks UDP fails the QUIC
    connection, and "clients SHOULD attempt to use TCP-based versions of HTTP in this case". So
    the engine holds both transports and races them, and `Config` does not change. It lands in
    two parts: HTTP/2 alone (§24 step 7a), then the race (7b). Rejected: a version chosen when the
    engine is built, which leaves the consumer to know whether the network blocks UDP; and a
    version for each server in `Config`, which changes the public API and still does not fall
    back. Since decision 33, on 2026-09-28, colibri's `client.Channel` runs the race, and step 7b
    is the engine over it. §24.
31. **A question may name any type, and `Kind` is open.** Ruled by the owner on 2026-09-26
    (c4milo/cocuyo#25). c-ares's `ares_query` takes any type code, and the codec already kept the
    records of a type it does not name whole (RFC 3597 §3). So `Kind` gained a `_` and a question
    may name any code but those §19 step 9 refuses. A DNSSEC type comes back as rdata, unvalidated
    (§1). Rejected: a raw code beside a closed `Kind`, which gives one type two spellings every
    reader must reconcile and breaks every `Question` a consumer writes; and naming types one at a
    time as consumers ask, where each is still an API change and never reaches any code.
32. **DoT, DoQ and DoH on HTTP/3 run over colibri's `tls`.** Ruled by the owner on 2026-09-27
    (c4milo/cocuyo#30). colibri's `tls` module holds chapulin's sessions for both of its modes,
    and links chapulin's TCP object whether or not a program uses record mode. On 2026-09-27 a
    program that linked cocuyo's own TCP object beside it failed to link, on 14 symbols both
    objects define. So the DoT session runs over `tls.record.Client`, the DoQ session over
    `tls.quic.Client`, and cocuyo pins no chapulin of its own. Rejected: DoT over chapulin's Zig
    API beside DoQ over colibri's `tls`, which cannot share a program; colibri splitting `tls` so
    that its QUIC half links one object, which still clashes with any consumer that speaks HTTPS
    through colibri; and DoQ over an object made from a chapulin checkout, which every build of
    DoQ had to make first. §21, §24.

    Since colibri v0.8.0, pinned on 2026-10-20, each TLS value takes `cpu` (colibri's decision 97,
    as amended for chapulin 0.2.0). It holds what a probe found of the CPU, and the timing mode of
    the thread that drives the session. A session runs the AES instructions only where the program
    states a data-independent timing, and only the program knows that mode. Until then colibri
    chose AES-GCM from the build target. At the pin each session of the engine stated nothing, so
    it offered TLS_CHACHA20_POLY1305_SHA256 alone and ran the portable multiply. Since decision 48,
    of the same day, each session states what the consumer put in its context.
33. **colibri's `client.Channel` carries DoH, and chooses between HTTP/3 and HTTP/2.** Ruled by
    the owner on 2026-09-28 (c4milo/cocuyo#18, c4milo/colibri#70). colibri's channel holds a QUIC
    connection and a TCP connection to one origin, and runs decision 30's race: QUIC first, TCP
    when QUIC fails or a delay passes, and the first to come up takes the requests. It opens no
    socket and resolves no name, so the engine opens what it asks for, at the addresses the
    configuration gives. The engine holds one channel for each DoH server, in a fixed array of
    `servers_max`, and takes the version the channel comes up on, HTTP/1.1 among them. Rejected:
    the race in the engine, step 7b as planned, which writes again what colibri's channel holds
    and colibri's model checks; failing a channel that comes up on HTTP/1.1, which RFC 8484 §5.2
    does not ask for, since it recommends HTTP/2 for speed alone, and which makes a slow server a
    failed one; and channels the caller hands `init`, which changes `init` where every other
    connection set is a fixed array. §24.

    Since colibri v0.8.0, pinned on 2026-10-20, the channel takes one `client.Config` with one TLS
    value. It builds the TLS configuration of each transport itself, and its `versions` name the
    protocols of each ALPN list (colibri's decision 120). It draws QUIC's grease value and
    connection IDs from the stream the link hands it. A request is a `client.Request`, and its
    answer goes into a `client.Response` (colibri's decision 124). The test servers run on
    `server.Endpoint`, and route each GET through `server.router` (colibri's decisions 119, 121 and
    122). §24.

    colibri v0.8.0 also sends a GET again, once, on another connection (its decision 124, ruling 3).
    It does so when the connection closes or fails before any octet of the response arrives. A GET
    is idempotent (RFC 9110 §9.2.2), so the server may process one query twice before the engine
    fails the request over. The resend and the move after a GOAWAY share one move, and a resend that
    is refused ends `closed`. §24, request rules 21 and 22.
34. **The answers keep the type of the question they answer, and change lists without writing their
    storage.** Ruled by the owner on 2026-09-30 (c4milo/cocuyo#34). ReleaseSafe writes 0xAA over
    memory assigned `undefined`, and a bare union changes its member only by being assigned whole.
    So the answers' storage, 2,436 octets for the records, was written where nothing read it: when a
    lookup started, when a response was collected, when the cache kept an answer and when it handed
    one back. On Linux every one of those writes stores a byte at a time. The answers' union is now
    an `extern union`, which lets any member be read, and `Answers` carries `kind`, the type of the
    question it answers, which decides the member in use (`Kind.storage`). `reset` and `assign`
    write `kind` and none of the storage, and every read asserts it, which is the check the build's
    hidden tag made. `Address`, `Name`, `Records` and `Ref` are `extern struct`s so that the union
    can hold them, with their fields and sizes as they were. `Lookup.init_in_place` sets every field
    but `answers`, and then resets the answers, so the octets of the slot's last lookup are left and
    never read; `Cache.put_negative` resets the slot's answers in place instead of filling a local.
    Two fills stay: `Lookup.init`, which builds a lookup whole and hands it back by value, and the
    zeros of the EDNS padding (RFC 7830 §3). Rejected: runtime safety off around the switch, an
    exception the owner rules on (pepegrillo's method, step 3) for a cost the representation can
    avoid; the storage as bytes read through pointer casts, which loses every member's type; a field
    for each list, which adds 2.4 KiB to every lookup and every cache slot; and leaving it, which on
    Linux writes about 2,700 octets a byte at a time at every A lookup's start. §9, §19 step 9.
35. **Every cryptographic operation is chapulin's.** Ruled by the owner on 2026-10-03, on the
    DNSSEC plan of §25, which had taken its hashes and signatures from Zig's `std.crypto`. The
    TLS under DoT, DoQ and DoH is chapulin's already, through colibri's `tls` (decision 32). So
    is the verification DNSSEC would need, if §25 is ruled in: `dnssec` names a verifier, and a
    module outside `src/` fills it in from chapulin through colibri, so the library still
    depends on nothing. chapulin gains what §25 lists before cocuyo can use it. Rejected:
    `std.crypto`, which has every algorithm the plan verifies but Ed448 and needs no dependency,
    and is a second implementation of SHA-2, P-256, P-384 and RSA in an image that already
    carries chapulin's, outside what chapulin proves and tests; and both at once, chapulin
    under the engine and `std.crypto` for a consumer with no colibri, which keeps two. §25.
36. **A server's wait comes from its measured latency.** Ruled by the owner on 2026-10-09, with
    c-ares's numbers: five times the average of the shortest window that holds 3 samples,
    `timeout_ns` until a server has 3, at least 250 ms and at most `timeout_ns_max`, doubled per
    pass. RFC 1035 §4.2.1 asks for a wait based on prior statistics. Rejected: the fixed wait,
    doubled per pass, that cocuyo had, which waits as long for a server 20 ms away as for one
    500 ms away; a floor at RFC 1035 §4.2.1's minimum of 2 to 5 seconds, which would hold a
    server 20 ms away to a wait of 2 seconds or more, where five times its latency is 100 ms;
    and a wait from the first sample, as `ares_init_options(3)` describes, which one slow or
    fast answer would set. Amended by the owner on 2026-10-09, in answer to §17 question 26: a
    try that ran out counts as a sample as long as the wait it used, so a server whose latency
    rises past its wait has its wait rise with it, where before it gave no more samples and its
    wait stayed where its old record left it until the table was built again. Rejected with it:
    reading the window since the table was built only while a window with a span holds 3
    samples, which would still have left such a server's wait where it was until its day's
    window had passed. Decision 50 makes one exception, on §17 question 27: a try that a reply to
    it marked is no sample. §5.
37. **The engine's cache is built over memory the caller hands `init` and `reinit`, or there is
    none, and its TTL cap is `Config.cache_ttl_seconds_max`.** Ruled by the owner on 2026-10-11,
    in two answers: the caller hands the engine its cache memory at init, as the library's
    `Cache.init` takes it, so the size can come from a configuration file; and the cap is a
    `Config` field, 3,600 s by default, which the engine passes to its cache at `init` and
    `reinit`. The engine builds the `Cache` itself, keyed by the seed of the call and capped by
    its configuration, and an engine handed no memory has no cache. `init` and `reinit` change
    signature, `Options.cache_slots` goes, and the engine no longer owns that memory. Rejected:
    - The comptime option alone, which is what was. The size is fixed when the engine's type is
      built, so no number read at run time reaches it. A size of zero trips `Cache.init`'s
      assertion, so the cache cannot be turned off. And the cap was a constant.
    - A built-in cache with a run-time override beside it. That is two ways to do one thing, and
      a caller that hands over its own memory still holds the built-in arrays for nothing, 2.9
      MiB at 1,024 slots.
    - The caller handing over a built `Cache`. The engine keys its cache with each seed it is
      given and caps it with its configuration, so it would build the caller's cache again at
      `init` and at every `reinit`, and a cache built with another seed or cap in between would
      be one more thing to get wrong.

    What the ruling left open, chosen by whoever built it, each the smallest thing found:
    - The sizing lives in the library's `cache` module, as `Slices`, `Storage`, `keys_for` and
      `slot_count_valid` (§18, Sizing the memory), and the engine takes a `?cache.Slices`. The
      rule is the cache's, `Cache.init` asserts it, and a caller of the library alone sizes the
      same memory. The other place was the engine, which would have left that caller working
      the key index out by hand. `Cache.init` keeps its signature.
    - The cap is at most seven days, `cache_ttl_seconds_max`. "Values SHOULD be capped on the
      order of days to weeks, with a recommended cap of 604,800 seconds (7 days)" (RFC 8767 §4),
      and the owner ruled on 2026-10-11 that cocuyo follows it. `assert_valid` and `Cache.init`
      refuse a longer cap, and `cache.ttl_seconds_max_valid` says whether a cap read at run time
      is one a cache takes. Rejected: no upper bound, this change's first shape, on the ground
      that any `u32` is a TTL and a cap only lowers one, as c-ares's cap does. That left the
      RFC's SHOULD to each caller, and let one configuration keep an answer for 136 years.
    - A cap of zero is refused, where c-ares reads zero as the cache turned off. Handing over no
      memory is the one way to turn it off (§19 step 13).
    - `engine_cache_slots_default` stays, as the size the README and the examples use and no
      default the engine takes (§19 step 13).
    - `cache_memory` sits after the configuration and before the seed, in both functions.
    - A `reinit` that fails at its sockets has taken the memory it was handed, with the
      configuration and the seed of that call. The memory it held before is the caller's
      (§19 step 13, rule 5). Since 2026-10-14 a `reinit` refused with `UdpPayloadTooLarge` takes
      nothing (decision 44). Before the ruling `reinit` already built its table and then
      opened its sockets, and the cache follows the table. The other choice was a failed
      `reinit` that leaves the engine with no cache, so that it holds neither memory and a
      caller's `errdefer` may free what it just got. That changes what `reinit` does, so it is
      §17 question 33 and not built.

    §4, §18, §19 step 13, §20, §24.
38. **`cocuyo_quic`'s `Options.Session` has no default, and a consumer names its TLS.** Ruled by
    the owner on 2026-10-11. The option names the TLS one of the module's connections runs:
    colibri's provider and its packet suite at once (§24, colibri under the request interface).
    Since 8b9fa5b, of 2026-09-25, in v0.2.0 to v0.5.0, it defaulted to `Plain`, the wrapper of
    the plain session of `io/io_quic_plain.zig`, which the gate runs colibri over (decision 29).
    That session encrypts nothing and authenticates nobody, and a consumer that left the option
    unset ran it. What came of that depended on who answered (§24, the session a connection
    names). A server that speaks DoQ opened nothing in the session's packets: "Initial packets
    apply the packet protection process" (RFC 9001 §5.2), and the session's apply none. So no
    handshake ended, no query left, and every lookup that server was asked failed. A peer that
    sends the session's made-up messages completed the handshake on `doq`. Such a peer is
    cocuyo's own test server, or an attacker who answers in the server's place. Each query
    then went to it in the clear, and its answers were taken, where "DoQ stubs SHOULD use a
    Strict usage profile" (RFC 9250 §5.1). Now a consumer that names no session does not
    compile. That breaks the build of every consumer that relied on the default, as the owner
    asked. Rejected:
    - The plain session as the default, which is what was. It saved each of the gate's tests
      one field. It cost a consumer every protection DoQ is chosen for, and the build never
      said so. The run said so against a DoQ server, where every lookup failed. Against an
      attacker it said nothing: the handshake ended, on `doq`, and the attacker's answers came.
    - A default that refuses at run time: a session whose `start` fails, as the engine's
      `quic.None` refuses a DoQ configuration at `init`. The mistake then shows when the first
      connection starts, in whatever process runs it, which is later than the compiler finds
      it. It also keeps in every such image a connection type that can never be up.

    What the ruling left open, chosen by whoever built it, each the smallest thing found:
    - `Plain`, `plain` and `server` stay exported under the names they had, since the ruling
      changes nothing else of the public API, and a consumer's own tests may run the engine
      over colibri's QUIC with them, as the gate's do. Their comments, §24 and the README say
      what they are: they encrypt nothing, authenticate nobody, and are never for a network.
    - The compiler's own words tell the consumer: `missing struct field: Session`. A message of
      cocuyo's would need the option to be a `?type` that defaults to null, with a
      `@compileError` where a connection reads it. That is a default again. The check below
      reads the fields, and a field that defaults to null reads the same there whether a
      connection then stops the build or runs the plain session.
    - The check reads the fields of `Options` when it compiles: `Session` carries no default
      value, and its type is `type`, so the options hold no value that means no session.

    §24.

    **Amended by the owner on 2026-10-17, on §17 question 34: register it.** The build registers
    a module for the session over chapulin, `chapulin_quic`, rooted at `io/io_chapulin_quic.zig`.
    Its `quic` and `tls` imports are left for the consumer to bind, as `cocuyo_doh`'s `client`
    and `tls` are. Before the ruling the package shipped the file, and no registered module
    named it. So each consumer's build made the module itself, and no check of the gate built
    such a consumer. The change was built on 2026-10-20.

    Choices the ruling did not make, made here:

    - The name is `chapulin_quic`. The build registers `io/io_chapulin_hooks.zig` as
      `chapulin_hooks`. So a module for a file of `io/` that holds chapulin's session or hooks
      takes the file's name without `io_`. The DoQ example imported the session under this name
      already, and `zig build test-chapulin-quic` runs its tests. A consumer that copied the
      example keeps its import.
    - The module links libc, which chapulin's object needs. The module of chapulin's C headers
      links libc too, so no program changes without the flag (docs/mutations.md, the session
      module). The build binds the session's `cocuyo`, `cocuyo_quic` and `chapulin_hooks` to the
      modules that it registers under those names. So the session reads the `cocuyo_quic` that
      the consumer binds colibri's `quic` into.
    - The DoQ example and the session's tests use the registered module. `build/doq.zig` binds
      colibri into it and into `cocuyo_quic`, as a consumer does. Before the change it made a
      module of its own for both.
    - `test/consumer/` depends on colibri, at the pin of `build.zig.zon`, and builds a third
      program, `doq`. The program names the session in the options of its connection, and
      states its CPU through `Session.Cpu` (decision 48). It runs the resolver over DoQ on its
      own loop. `zig build consumer-check` builds the program, and does not run it.
    - The check compares the package's pins of rotor and colibri with the pins of
      `build.zig.zon`, before it builds. At another pin the package builds cocuyo against a
      package that cocuyo does not pin. Before the change nothing compared the pin of rotor.
    - A dependent of colibri fetches chapulin and stdx too, since colibri requires both. The root
      build fetches all three for its own tests, so the check fetches nothing more. It compiles
      colibri's `quic` and `tls`, and chapulin's objects, a second time, in the cache of the
      nested build. §17 question 65 asks the owner about that cost.

    Rejected:

    - The name `cocuyo_doq`. Beside `cocuyo_doh` it reads as the DoQ transport, which is
      `cocuyo_quic`. The module holds only the TLS that a connection of `cocuyo_quic` names.
    - A second module of the session for this build alone, as `io_doh_channel` is to
      `cocuyo_doh`. The session's tests import nothing that a consumer does not bind. A second
      module keeps the gate's builds of the session apart from the build of a consumer.
    - The check in a package of its own beside `test/consumer/`. It compiles the same colibri,
      and it adds a second manifest and a second build to keep.

    The checks are the build of `doq` and the comparison of the pins. Seven mutations break the
    module or the check, and the checks catch each (docs/mutations.md, the session module). The
    public API changes: the package exports one more module. No named limit changes. No model
    changes either: no transition of §5 and no rule of §19 steps 13 and 14 reads the build.

    §17 questions 34, 64 and 65, §24 (the session a connection names).

    **Amended by the owner on 2026-10-20, on §17 question 64: register the DoT session too.**
    The build registers a module for the DoT session over chapulin, `chapulin`, rooted at
    `io/io_chapulin.zig`. Its `io` import is `cocuyo_rotor`. Its `tls` and `tls_provider` imports
    are left for the consumer to bind, as `chapulin_quic`'s `quic` and `tls` are. Before the
    ruling each consumer's build made the module itself, as `build/dot.zig` did. The change was
    built on 2026-10-24.

    Choices the ruling did not make, made here:

    - The module links libc, as `chapulin_quic` does. The build binds the session's `cocuyo`,
      `io` and `chapulin_hooks` to the modules that it registers as `cocuyo`, `cocuyo_rotor` and
      `chapulin_hooks`. So the session reads the limits of the engine that the consumer binds
      its rotor into.
    - The DoT example and the session's tests use the registered module. `build/dot.zig` binds
      colibri's `tls` and `tls_provider` into it, and rotor's `rotor` into `cocuyo_rotor`, as a
      consumer does. Before the change it made a module of the session and an engine of its own
      for the example, and a second module of the session over the twin's engine for the tests.
    - `build/dot.zig` is the only place where the root build binds a `rotor` into
      `cocuyo_rotor`. `addImport` replaces a binding and says nothing, so a second binding would
      change the engine of the session. An assertion in `build/dot.zig` stops a binding made
      before its own. A file that binds one later must add the same assertion.
    - The session's tests need rotor now, as the example did. The session reads only the
      engine's constants, and the twin's engine and `cocuyo_rotor` hold the same ones. The root
      build fetches rotor for its examples, so the gate fetches nothing more.
    - `test/consumer/` builds a fourth program, `dot`. It names the session in the options of
      `cocuyo_rotor`'s resolver, states its CPU through `Session.Cpu` (decision 48), and runs
      the resolver over DoT on its own loop. `zig build consumer-check` builds the program, and
      does not run it. The program uses the fixture's colibri and rotor, at their pins.

    Rejected:

    - A second module of the session for this build's tests, over the twin's engine, as before.
      It keeps the gate's build of the session apart from the build of a consumer, as the
      amendment for question 34 says of `chapulin_quic`.
    - A name with `dot` in it, as `chapulin_dot`. §17 question 64 named the module `chapulin`,
      and the example imported the session under that name already.

    The checks are the builds of `dot` and of the DoT example. Five mutations break the module,
    and the consumer check catches each. A sixth binds a second `rotor` into `cocuyo_rotor`, and
    the assertion stops the build (docs/mutations.md, the DoT session module). The public
    API changes: the package exports one more module. No named limit changes. No model changes:
    no transition of §5 and no rule of §19 steps 13 and 14 reads the build.

    §17 question 64, §21 (the session interface), §24 (colibri as a dependency).
39. **The engine holds no default context, and a lookup whose transport's context was never set
    stops it.** Ruled by the owner on 2026-10-11, on a finding of the same day: "No default
    context. An engine asked to open a DoT, DoQ or DoH session whose context was never set
    stops with an assertion, since forgetting it is a programmer error. Tests name their test
    contexts on purpose." A context is what every session of one transport starts from: the
    anchors, the wall clock, and the stream chapulin and the QUIC connection IDs draw from
    (§21, the session interface; §24, the context a session starts from). A consumer hands the
    engine one with `use_tls`, `use_quic` or `use_doh`. Until the ruling `init` set all three
    to defaults, and nothing checked that a consumer replaced them. A default held values for
    tests: no anchor, a wall clock of zero, and a stream seeded with zeros for DoQ and DoH and
    left undefined for DoT. An engine whose consumer skipped the call refused a server known
    by a name alone, for want of an anchor, and with a server known by pins it ran the
    handshake over those values.
    Now the engine holds no context until its consumer sets one, the context types carry no
    default, and `start` asserts that the transport its configuration speaks has its context.
    A consumer that skipped a call stops at its first lookup, and one that wrote a context with
    a field left out does not compile, as the owner asked. Rejected:
    - The defaults, which is what was. A consumer that skipped a call ran a handshake over
      values meant for tests, and neither the build nor the run said so.
    - `init` and `reinit` taking the contexts as arguments. The compiler would hold the rule,
      where an assertion holds it now. It changes two signatures that this release already
      changed once, for the cache's memory (decision 37), and a consumer that speaks plain DNS
      would write three arguments for transports it never uses.

    What the ruling left open, chosen by whoever built it, each the smallest thing found:
    - The engine holds each context as an optional, null until its `use_` call. A flag beside
      the value was the other way, and it leaves a value that code can read without asking the
      flag. One file reads the three, `io/io_context.zig`, and hands a session its context
      only after asserting there is one.
    - The assertion is in `start`, the first call that can reach a server, and again where a
      session takes its context. `init` cannot hold it: a consumer calls `use_` after `init`,
      as the three examples do, and `init` starts no session.
    - The predicate the assertion reads is public, `has_context`: whether the transport the
      engine's configuration speaks has its context, which is always so for plain DNS. The
      tests call it, and a consumer may before a lookup (§17 question 35).
    - `init` leaves the engine with no context, where it left the defaults, so a consumer that
      closes an engine and starts it again names its contexts again. `reinit` keeps the
      contexts as they are, as it did: it never reset one, and drops only the tickets.
    - A context handed to the engine again is built from a new draw of its seed, as `reinit`
      takes a new seed (§19 step 10). The `use_` functions take a context by value, so one
      built again from the octets of a context before it starts its stream where that one
      started. The engine cannot see this either, and §24 states it as the consumer's rule.
    - The engine checks that a context was set, which is the programmer error it can see. It
      cannot tell a seed drawn from a CSPRNG from any other 32 octets, or a wall clock that is
      right from one that is not. Those stay the consumer's, and the doc comments and the
      README say so.
    - The helpers that build a context for a test are the tests' own, and none is exported:
      the ruling changes nothing else of the public API.
    - The contexts of the twin's three types, of `cocuyo_quic.Plain`, and of the three types
      that refuse a transport are structs of no fields. None carries a default, since none
      carries a value, and an engine over the twin still has no context until its test names
      one.

    §21, §24.
40. **Every integer constant of a constants file has a type, and a lint rule and a test hold it.**
    Ruled by the owner on 2026-10-13 for four constants: "Type header_bytes, tcp_prefix_bytes and
    the two fixed-size constants as usize, so a sum with a narrow value widens instead of
    overflowing." This change reads the two fixed sizes as `question_fixed_bytes` and
    `record_fixed_bytes`. It also extends the ruling to every integer constant of every constants
    file of `src/` and `io/`. The extension is this change's own reading of the ruling, and the
    owner can overrule it (§17 question 36).

    The cause. An integer constant with no type is a `comptime_int`. A `comptime_int` added to a
    runtime integer takes that integer's type. So `header_bytes + name.len` was a sum in the `u8`
    that holds a name's length, and it overflowed from a name of 244 octets. A stream's prefix of
    65534 overflowed a `u16` the same way. 1765131, of 2026-10-10, fixed each sum it found with a
    local of type `usize` (docs/mutations.md, Sums at the most their operands reach). The cause
    stayed: 343 of the 349 integer constants of the constants files were a `comptime_int`. The
    owner's session read the aim of the ruling as the removal of that cause for the whole class.

    The type of a constant is the type of what it names:

    - A length, an offset, a size in octets, an alignment or a count of items is a `usize`. Its
      sum with a narrow runtime value is then a `usize`. A default of an option is a `usize` too
      when it is a length or a count. A field of a narrower type takes it at compile time.
    - A time is a `u64`, in nanoseconds or in milliseconds. A TTL in seconds is a `u32`, the
      width of a record's TTL (RFC 1035 §4.1.3).
    - A value of a protocol field, a mask or a bit pattern has the type the code reads that field
      into. A port is a `u16`, and `opcode_query` is a `u16` because `Header.opcode` gives one.
    - A shift amount has the shift type of the integer the library shifts with it: `octet_bits`
      shifts a `u16`, so it is a `u4`. Its value is known at compile time, so it can also shift
      a wider integer.
    - Any other value has the type of the value it meets at run time.
    - An alias, a constant whose value is another constant, has no type written. It has the
      type of what it names.

    Of the 349 integer constants, 225 are now a `usize`, 45 a `u16`, 36 a `u64`, 20 a `u8`, 13
    a `u6`, 5 a `u4` and 5 a `u32`. 336 have their type written, 2 get it from their value, and
    11 are aliases. The value of each stays as it was, and no named limit changed.

    Where the rule did not settle a type, this change chose it:

    - `udp_payload_bytes_default` and `udp_payload_bytes_min` are sizes of a payload and the
      value of a 16-bit OPT field. They are a `usize`, since the tree uses the default as a
      buffer length and two aliases name it.
    - `attempts_default`, `ndots_default`, `failover_retry_chance_default`, the engine's
      `lookups_default`, `group_buffers_default`, `tcp_connections_default`,
      `tcp_group_buffers_default` and `answers_default`, and the twin's `name_reserve_default` and
      `control_reserve_default`, are counts or lengths. Each is a `usize`, and not the type of
      the narrower field it is the default of.
    - `scope_link_local`, `scope_site_local` and `scope_global` are a `u8`, as `scope_of` gives
      one. RFC 4291 §2.7 makes the field four bits wide.
    - `common_prefix_bits_v6_max`, `common_prefix_bits_v4_max` and both `bits_per_octet` count
      bits, so each is a `usize`. Both `octet_bits` are a shift amount, so each is a `u4`.
    - `decimal_base` multiplies a `u16` and `hex_alpha_value` is added to an octet. Each is a
      `u8`, so neither widens the value it meets.
    - `latency_wait_multiplier` multiplies a `u64` average, so it is a `u64`. So is the twin's
      `quic_stream_step`, the step between two stream ids.
    - The engine's three index shifts, `receive_generation_shift`, `tcp_incarnation_shift` and
      `quic_incarnation_shift`, are a `u6`, and its three index masks are a `usize`.
    - `group_id` and `tcp_group_id` are a `u16`, rotor's group id. The twin's
      `generation_first` is a `u32`, as its loop's generation is.
    - `hosts_comment_start`, a character, and `server_id_octet` are a `u8`.
    - `idle_timeout_ms` and `fallback_delay_ms` are a `u64`, the type colibri reads them into.

    What changed with the types:

    - Four sites stopped compiling. Two shifts of a `u8` constant by `octet_bits`, each known at
      compile time, now shift a `u16`. `fill_quad` in `src/core/address_text.zig` and
      `prefix_bytes` in the twin now narrow their sum with `@intCast`, after the check or the
      assertion that bounds it.
    - Thirteen sites now compute in a `usize` where they computed in a narrower type. At the
      named limits no value changed. No sum became narrower: a sum of two types has the wider
      of the two, and a `comptime_int` took the type of the runtime value.
    - The engine's comptime checks of its index shifts now add in `comptime_int`. A `u6` shift
      too large for its room then stops the build with the check's message, and not with an
      overflow of the `u6`.
    - `Resolver.loop_operations` has its type written, `u32`, as it was. A `usize` limit in its
      sum would have made it a `usize`.
    - The constants are public, so a consumer's code that stores a narrow value and a constant
      in a narrow place no longer compiles. The ruling makes this change to the API. Two
      aliases outside the constants namespaces changed with their constants, from a
      `comptime_int` to a `usize`: `request_bytes_max` of `cocuyo_quic`'s `Connection`, and
      `output_bytes_max` of `cocuyo_doh`'s channel.
    - Six locals of type `usize` that 1765131 wrote are now redundant: their constant widens the
      sum. They stay, with their comments. Three are not redundant: their sum has a literal or a
      constant outside a constants file.

    Two checks hold the rule. The lint rule reads the syntax, and the test reads the types.

    - The lint rule `typed-constants` (`tools/lint/typed_constants.zig`) reads each Zig file of
      `src/` and `io/` whose name holds `constants`, and each Zig file under a directory named
      `constants`. So it also reads the pieces that CLAUDE.md's split rule makes of a constants
      file, with no list to update. It reads each constant that is a member of a container. It
      reports such a constant when its written type is `comptime_int`.
    - The lint rule also reports a constant with no type when its value is integer-shaped. An
      integer or character literal is integer-shaped. So is an operator, a builtin that gives a
      `comptime_int`, `@as(comptime_int, ...)` and a call of `maxInt` or `minInt`. So is an
      `if` or a `switch` with an integer-shaped value in a branch, and a block with one in a
      `break`. A branch of another type can make a false report. A written type then ends it.
    - The lint rule does not report an alias. The canary tree of `zig build lint` holds one
      constant that the rule reports.
    - A test in each of the ten constants files reads the types. It reads the public
      declarations of its file, and it fails on a `comptime_int` with the name of the constant.
      It sees through an alias and a call, which the lint rule cannot do.

    The lint rule is cocuyo's own, and the only rule of `tools/lint/` that is not pepegrillo's. A
    rule in pepegrillo needs a commit there and a new pin, and this change made neither.

    What the two checks do not catch:

    - A sum of two narrow runtime values with no constant in it. Its type is the type of its
      operands, and no constant widens it. docs/mutations.md lists each such sum found on
      2026-10-13, with the bound that keeps it inside its type.
    - A literal in a sum, as in `1 + label.len`. A literal is a `comptime_int` too.
    - Some values that are a `comptime_int` have a shape that the lint rule does not read. These
      are a call of another function, such as `std.math.log2(4096)`, an `orelse`, a `catch`, an
      index into a tuple, and an alias of a constant with no type in a file the rule does not
      read. The test catches each of these in a public constant. A private constant of such a
      shape passes both checks. On 2026-10-13 the constants files hold no private integer
      constant outside a `comptime` block, and a constant cannot leave that block.
    - The test reads the public declarations at the top of its file. Only the lint rule reads a
      constant in a container inside the file. Only the lint rule reads a new constants file,
      until that file gets a test of its own.
    - An integer constant outside a constants file. The lint rule, with its scope widened to
      every Zig file of `src/` and `io/`, reports 210 such constants, test files apart. 85 of
      them are in fixtures. The rule reads the shape, and not the type, so some of them have a
      type already, from a typed constant in their value: `port_span` of
      `src/resolver/entropy.zig` is a `u16`. `frame_bytes` of `io/io_quic_plain.zig` has no
      type (§17 question 37). `bench/end_to_end/constants.zig` is outside both checks too: nothing
      of it is linked into the library, and the gate does not compile it.

    Rejected:

    - Constants with no type, and a local of type `usize` at each sum, which is what 1765131
      did. Each new sum needs its own local, and the next sum forgets it. After the first fix,
      the audits of 2026-10-10 found the same fault in the engine, the plain QUIC session and
      the twin.
    - A lint rule over sums. A rule reads the syntax and not the types. In `start + name.len` it
      cannot see that a variable holds a `u8`.
    - A `comptime` block in each constants file, in place of the test. It stops the build at a
      constant with no type. But `zig build mutations` reads a compile error as a mutation whose
      text no longer applies. A row that takes the type off a constant then reports "did not
      compile", and no row can show that the check works.
    - The test alone, with no lint rule. The test reads public declarations alone, and it fails
      only when the module's tests run. The lint rule reads each constant of the file, and it
      names the line.
    - The four constants the ruling names, and no others. The twin's `tls_record_header_bytes`
      and `quic_item_header_bytes` had the same fault (docs/mutations.md, QO14 and QO15), and
      they are in no list of four.

    §5, §12, §13.
41. **A stream's buffers hold one chunk past their longest item, and every whole item leaves
    them with the chunk that made it whole.** Ruled by the owner on 2026-10-13, who approved the
    four limits and the two public names of §17 question 38. A survey of the named limits found
    four faults in the engine's streams, and each was shown on the twin:

    - A TLS connection's record buffer held one record at its longest and nothing more. It
      refused a chunk that did not fit beside the partial record, before it handed a whole record
      to the session. The chunk that ends one record often starts the next, so a sound
      connection failed.
    - A connection's frame had the same fault, with a message in place of a record.
    - The session opens a whole record into the frame after the partial message. The frame had no
      room for it after a long partial message, so a sound DoT connection failed.
    - The loops over the frame and over the record buffer stopped after 32 items. The rest
      waited for a chunk that may not come, and their lookups waited for their deadlines.

    Now each buffer holds its longest item and what one take adds after a partial item. That is
    one chunk, or one record's body for the frame over TLS. Every whole item leaves the buffer
    before the chunk's event ends. Each item is at least its prefix or its header, so the
    buffer's length bounds the loop, and the bound never stops the loop early. The loop moves the
    rest of the buffer once, after the last whole item. So a chunk of empty messages costs moves
    in proportion to the chunk, and not to its square. A prefix that says more than
    `tcp_message_bytes` fails the connection when it arrives. Over TLS the peer is still there, so
    the session says `close_notify` first (§21, TLS rule 5).

    Checked on 2026-10-17 at the DoH channel's buffer, `doh_stream_bytes_max` (c4milo/cocuyo#44).
    The issue said that whole records could stay there when the next chunk comes. Then they and the
    chunk count against one room. It named two causes:

    - The bound of the engine's read of a channel. This cause cannot happen with colibri v0.6.0,
      nor with v0.8.0. A sound channel says less than the bound at each read: an end for each
      request at most, and a few events of its own. The bound gives it `channel_events_max`, 16,
      of those (`io/limits.zig`).
    - Records that colibri keeps for want of room. colibri opens a record only into room for its
      body. Its connection has room for a partial HTTP/2 frame and one record more. In v0.6.0 a
      pass that opened a record could find no room for the next one. That pass took octets, so
      the read made one more pass, and the record fitted then. Since v0.8.0 the protocol reads
      what a record held before the next record opens, so one pass opens each whole record. So
      over HTTP/2 each whole record opens in the read after the chunk that made it whole. After a
      pass that took octets the read still makes one more pass. The type holds a datagram and the
      stream apart, and hands colibri the datagram first.

    Over HTTP/1.1 the second cause could happen with colibri v0.6.0 (§17 question 52). colibri
    reads a head or a trailer section only when it is whole. It accepts a head of up to 32,768
    octets, and a trailer section of up to 24,576. In v0.6.0 its room was 33,033 octets. When more
    than 16,632 octets of either waited, no room was left for a record of 2^14 octets of plaintext.
    colibri then opened no more records, so the head or the trailer section never became whole.
    The next chunks passed the buffer and ended the link. No size of the buffer helped, because
    colibri never took the record.

    Since colibri v0.8.0, pinned on 2026-10-20, the room holds 49,407 octets (colibri's decision
    124, ruling 7). That is a head at its longest less one octet, and one record more. So the
    record after a long partial head opens, and the head becomes whole.

    A test sends whole records back to back over HTTP/2 and HTTP/1.1, with heads of a usual length
    (`io_doh_channel_read_test.zig`). After each read the buffer holds a partial record at most, as
    the engine's own buffers do. A second test sends heads of 20,000 and 32,768 octets over
    HTTP/1.1. Then 17,384 or 32,767 octets of a head wait in colibri before a full record comes.
    Each exchange ends with its answer. On colibri v0.6.0 the second test fails: a whole record
    stays in the buffer after a read. A third test sends a trailer section of 24,000 octets over
    HTTP/1.1. Then 17,000 octets of it wait before a full record, which the next response fills.
    Both exchanges end with their answers. A fourth test hands the type a datagram before each
    chunk, so each read makes its second pass over the stream. Neither the buffer nor its check
    changed.

    Before v0.8.0 colibri opened no record after a KeyUpdate that asked for a reply. It waited
    until the engine next asked the channel for octets to send (§17 question 51). Since v0.8.0 it
    opens records while the reply is owed, and writes the reply before its next record of data
    (RFC 9846 §4.7.3). It owes two replies at most, `tls.constants.key_update_replies_max`. A
    third request fails the read, and the link ends. A sound server never sends that third
    request: it asks for no second reply until the first has come (RFC 9846 §4.7.3).

    In three states colibri still opens no record, and the type keeps what comes:

    - Over HTTP/2, while h2 owes a reply that has no room in colibri's output. Such a reply is the
      acknowledgment of a SETTINGS or a PING (RFC 9113 §6.5.3, §6.7). h2 reads nothing more until
      it writes the reply (colibri's `connection_h2.zig`, as in v0.6.0). The output frees when
      the engine next asks the channel for octets, after the link's send ends. Only a peer that
      fills the output with such frames while the send is busy meets this state.
    - After the connection stopped: it failed, or its last exchange ended after a shutdown. No
      exchange is left on it. The octets go when the link closes, or sooner at an overrun.
    - After the server's `close_notify`. The server sends no more messages after it, and data
      after it is ignored (RFC 9846 §6.1).

    Rejected:

    - No memory added: copy what fits, hand over the whole items, and copy the rest. It needs more
      code at both sites. Also, the session opens a whole record into the frame. So the frame over
      TLS needs room for a record after the partial message in any case.
    - A bound of 32 kept, and the rest handed over at the next drive. A drive follows an event,
      and on a quiet stream the next event is the lookup's deadline. The rest would need a timer
      of its own.
    - A bound of one answer for each lookup, as `quic_connection_events_max` sets for QUIC. A
      stream also carries the answers to queries that lookups left, so its whole messages have no
      tie to the lookups.
    - Over TLS, a close at once with no `close_notify` when a prefix is too long, as for a peer
      that has gone. The peer is still there, and RFC 9846 §6.1 asks for the alert.

    §19 step 13, §21, §24.
42. **The skip of the record walk follows each pointer, and measures the whole name.** Ruled by
    the owner on 2026-10-14, on c4milo/cocuyo#46: close it. The skip walks a name as the decode
    does, through each pointer. `compression_hops_max` bounds the hops and `name_bytes_max` the
    octets, as in the decode. The skip counts the octets, the labels that a pointer reaches among
    them (RFC 1035 §3.1, §4.1.4), and copies nothing. It refuses a name longer than 255 octets
    (§2.3.4), and each other name that the decode refuses, with the same error. It still returns
    the octet after the first pointer, where the name ends in the message.

    The decode and the skip share one loop in `src/wire/name.zig`. The decode gives it a `Name`,
    which copies each label. The skip gives it a `Measure`, which counts the octets of each label
    and refuses where `Name` refuses. So the two agree by construction. The fuzz target holds them
    to one result at each offset where it aims both (§13).

    The cost was measured on 2026-10-14, on an Apple M1 Pro, by single step: a count of each
    instruction that one operation runs. The program is `bench/count.zig`, built ReleaseSafe at
    the baseline CPU, as `zig build instructions` builds it, at 05567b7 and with the change. CI
    counts the x86-64 Linux build under cachegrind. That build does not run under single step on
    this machine, so two other builds were counted:

    - aarch64 Linux, in a container, under `ptrace`. The CPU is the baseline with LSE atomics, so
      that no exclusive-load loop stops the single step. cocuyo has no atomics, so its code is
      the baseline's.
    - x86-64 macOS, under Rosetta 2, with lldb.

    What the counts show:

    - One call of the skip, on x86-64 macOS. An owner that is one pointer to `example.com` took
      39 instructions, and takes 172. The root, the owner of an OPT record, took 35 and takes 51.
      `host.example.net` took 131 and takes 174, so each label took 32 and takes 41.
    - One call of the decode, on x86-64 macOS. A name through one pointer takes 7 instructions
      fewer. A name of labels alone takes as many as before.
    - One operation of each case that walks records, before and after, on each build:
      - `parse-one`: 730 to 817 on aarch64 Linux (+11.9%), 1,077 to 1,183 on x86-64 macOS (+9.8%).
      - `parse-cname`: 2,795 to 2,981 (+6.7%), and 4,195 to 4,445 (+6.0%).
      - `parse-sixteen`: 8,537 to 10,160 (+19.0%), and 11,660 to 13,672 (+17.3%).
      - `match-accept`: 2,736 to 2,922 (+6.8%), and 3,128 to 3,367 (+7.6%).
      - `round-trip`: 3,748 to 3,938 (+5.1%), and 4,992 to 5,247 (+5.1%).
    - The other cases walk no record. On aarch64 Linux each of the nine was counted, and none
      changed. On x86-64 macOS `match-wrong` and `query-build` were counted, and neither changed.

    The x86-64 Linux build was not counted. Its code is a little different from the macOS build.
    Its five cases will likely grow by 5% to 20% too. Each change is over the 2% threshold of `zig
    build instructions`. So CI's Linux job fails on those five cases until a commit writes the
    counts again, as e36416a did after 356eeb7.

    Mutation W5 held the old contract, that the skip ends at a pointer. It is written again to
    break the new one the way the old code did (docs/mutations.md, The skip follows each pointer).

    Rejected:

    - A cheap skip, and the gap kept. Some names then passed each walk that decodes nothing at
      that place. They are a compressed owner longer than 255 octets, a pointer forward, a loop,
      and a pointer past the end. The type of the record that held the fault decided whether a
      lookup took the message.
    - A decode of each owner in the walk. It refuses the same names. It also copies each label
      into a 256-octet name, through a call to `memcpy` for each label.
    - A loop of its own for the skip, apart from the decode's. To give the same errors it does the
      same work. But the two loops can come to disagree, and only the fuzz target would see it.

    §7, Parsing; §8; §11; §13.
43. **A datagram that the buffer cut moves its lookup to TCP once the checks of a cut datagram
    pass.** Ruled by the owner on 2026-10-14, in answer to §17 question 40. A datagram longer than
    the caller's buffer arrives cut, and the kernel marks it. The engine reads the mark and gives
    such a datagram to `on_datagram_cut`. The lookup runs checks 1 to 5 of §7 on it, since the
    header and the question are whole. Check 6 reads it as a message with no COOKIE option. When
    the checks pass, the lookup moves to `tcp_needed` on the same server, as an answer with TC set
    does (RFC 7766 §5). A cut datagram that fails a check is ignored, as each such datagram is.

    Choices the ruling did not make, made here:

    - Two new entry points, `Lookup.on_datagram_cut` and `Resolver.on_datagram_cut`, beside
      `on_response` and `on_datagram`. A flag on `on_datagram` would change every caller. A TC bit
      that the engine writes into the cut octets would send them through check 6 on a whole
      message. That check walks the sections to the OPT record, which the cut took. The owner
      approved this shape of the public API on 2026-10-14 (§17 question 46).
    - Check 6 runs, on a message with no COOKIE option. The ruling named checks 1 to 5. But RFC
      7873 §5.3 says that a response without the COOKIE option that the client expects "MUST be
      discarded". The review of 2026-10-14 found that the cut path did not run check 6. Then a
      forger with no client cookie could move a lookup that a forged TC answer could not move. Now
      a lookup that expects a cookie ignores a cut datagram, and waits until its deadline, as
      before. A lookup that expects none takes it, as it takes an answer with TC set and no OPT
      record.
    - The cut datagram tells the server's state nothing: no latency sample, no success, no cookie,
      no silence and no mark. It did not pass check 6 on a whole message, so nothing in it is the
      server's word. The answer over TCP gives the sample.
    - Only `awaiting_udp` takes a cut datagram. Over DoH or DoQ, and under
      `Config.ignore_truncation`, the lookup ignores it. The caller who sets
      `ignore_truncation` asked not to go to TCP, and the cut left no whole message to read.

    Rejected:

    - The cut datagram ignored, which is what the engine did before. Its lookup waited until its
      deadline, then asked the next server over UDP. An answer longer than the buffer never
      reached the lookup, from any server.
    - The cut datagram dropped before the table sees it. The lookup still waits until its
      deadline, and nothing tells it that its answer came and was too long.
    - Buffers that hold each datagram whole, as c-ares reads one. At 65,536 octets each, the
      group of 64 takes 4 MiB, against 128 KiB. The owner kept the cut on 2026-10-14, after a
      probe of that day. No TLD server, public resolver or name server of 56 large domains sent
      more than the query advertised. The servers that broke the 512-octet limit of a query
      without EDNS sent 867 octets at most. APNIC reported in 2020 that about 11% of fragmented
      answers over IPv4 are lost, and 15% over IPv6.

    Not decided here: the engine could refuse a `Config.udp_payload_bytes` above its room of 1,856
    octets. RFC 6891 §6.2.3 says that a requestor "SHOULD place a value in this field that it can
    actually receive". Then only a forger or a broken server could send a datagram that the buffer
    cuts. The rule above is still needed for those. The refusal changes what the engine's `init`
    takes, so it was §17 question 47. The owner answered it the same day, and decision 44 holds
    the refusal.

    The engine model holds the rule in two configurations of its own. The replay runs the engine
    down the walks of one of them (§19 step 13, Checked on 2026-10-14). The machine code
    of `bench/count.zig`, built as CI counts it, did not change. So its instruction counts will
    likely not move. Nobody counted them under cachegrind (docs/mutations.md, The owner's answers
    of 2026-10-14).

    §5, §7, §19 step 13 (the datagram's rule 6).
44. **The engine refuses a `Config.udp_payload_bytes` that passes the room of a buffer of its
    datagram group.** Ruled by the owner on 2026-10-14, in answer to §17 question 47. RFC 6891
    §6.2.3 says that a requestor "SHOULD place a value in this field that it can actually
    receive". The engine receives each datagram into a buffer of its datagram group. The room of
    that buffer is `udp_payload_bytes_max`, 1,856 octets. `init` and `reinit` return
    `error.UdpPayloadTooLarge` for a configuration that advertises more. Then a server that obeys
    the query sends no datagram that the buffer cuts. A forger or a broken server still can, and
    decision 43 still takes such a datagram.

    Choices the ruling did not make, made here:

    - The limit follows from the buffer. `udp_payload_bytes_max` in `io/limits.zig` is what
      rotor's `payload_capacity` gives for `buffer_bytes_max` under `group_options`. The datagram
      group gets the same options when the engine provides it. So a change of the buffer, of the
      options or of rotor's prefix changes the limit too. A comptime check in `io/constants.zig`
      requires the default payload to fit the limit. A test compares the limit with the room of
      the loop's group.
    - The check comes before the call changes anything. A refused `init` writes nothing into the
      engine, provides no buffer and opens no socket. A refused `reinit` keeps the configuration,
      the tables, the cache and the memory of the cache. It also keeps the sockets and the
      connections, each with its receive. The memory that the call was handed is the caller's
      again at once. A `reinit` that fails at its sockets is not like it (§19 step 13, the
      cache's memory, rule 5). Until this rule, the old memory was the caller's whatever
      `reinit` returned. The owner accepted this change to the contract on 2026-10-14 (§17
      question 49).
    - The rule holds for each transport, as the owner ruled on 2026-10-14 (§17 question 50).
      Over TCP, TLS, DoQ and DoH no answer comes to a server's socket as a datagram. A
      configuration of TLS, DoQ or DoH opens no such socket (§21, TLS rule 9; §24, request rule
      1). But each query with EDNS carries the same size in its OPT record over each transport.
      One check of the configuration is one rule, and a check for each transport is more.
    - An error, as the owner ruled, and an assertion after it. `assert_valid` asserts each rule of
      a configuration, since the caller builds it (CLAUDE.md non-negotiable 3). No line of a
      `resolv.conf` and no option of `RES_OPTIONS` sets `udp_payload_bytes`. Only the caller's
      code sets it. That argues for an assertion. But a size up to 65,535 octets is valid for the
      library, whose caller holds the receive buffer (§3). The bound is the engine's own.
      Non-negotiable 3 keeps assertions for programmer errors. It does not ask each programmer
      error to assert, so no rule forbids the error. `reset_tables` asserts the bound after the
      check, as non-negotiable 6 asks.
    - The error is `UdpPayloadTooLarge`, in `InitError` beside `SocketFailed` and `ReceiveFailed`.
      The limit and the options are public in `cocuyo_rotor.constants`. So a caller can compare a
      size that it reads at run time with the limit before it calls `init`. CLAUDE.md asks the
      owner before the public API or a named limit changes. The owner approved the three names
      on 2026-10-14 (§17 question 48).

    Rejected:

    - A refused `reinit` that takes the configuration, as one that fails at its sockets does. The
      engine then holds a configuration that it refuses, and its next query advertises the size.
    - A refused `reinit` that keeps the configuration and lets go of the cache's memory. The old
      contract then holds, but a refusal changes the engine.
    - A check of a configuration that asks over UDP alone. That is two rules where one does.
    - A clamp of the advertised size to the room. The engine then sends a size that the caller did
      not set, and the caller does not learn of it.

    Neither model changes. The Lean models hold one lookup and the `getaddrinfo` walks, and no
    size of a payload. The TLA+ model of the engine starts from an engine that `init` built. It
    holds no `reinit` and no octets. Each replay and example of the tree advertises 1,232 octets,
    the default. So does each test of the engine but the two of this rule. So none of them
    changes.

    §7, §19 step 13 (the datagram's rule 7; the cache's memory, rule 5), §24.
45. **A failure keeps the last cause a server gave.** Ruled by the owner on 2026-10-17. On
    2026-10-11 a run of the DoT live check failed once at Quad9 with `AllServersFailed`, and nobody
    could say why. A dispatch started that run, 38168653502. Until 2026-10-18 this decision named
    the daily check of 2026-10-12, but the run's record says otherwise. The lookup kept the flag
    `had_server_failure` and no reason, and the example printed `failure.err` alone. Now
    `Failure` has a field `cause: ?Cause`. It is null when no server failed the lookup. Otherwise
    it holds the last failure of a server that the lookup met: the rcode of a response, or the
    transport that failed (§4, §5).

    Since 2026-10-21 decision 51 replaces three of the choices below. The cause names its server,
    and the two calls of a transport carry a reason. `AddressLookup` hands on the cause of a
    lookup's own `Canceled` end. The text below is the record of 2026-10-17.

    Choices the ruling did not make, made here:

    - The cause replaces the flag. Each place that set `had_server_failure` keeps a cause, and
      the end of the passes reads whether the lookup holds one. A flag beside the cause would
      keep one fact twice.
    - The lookup reads the cause of a transport from its own state. `on_tcp_failed` while it
      connects is `connect`, and after `on_tcp_connected` it is `stream`. A lookup on a TLS
      connection is told that it is up only after the handshake (§21, TLS rule 1), so a
      handshake that fails is `connect`. `on_request_failed` is `request`. No entry point
      changes.
    - Each server failure replaces the cause, and nothing clears it. `AllServersFailed` rests on
      each failure on the way, so it always has a cause, and `Timeout` never has one.
    - Each error carries the cause, not `AllServersFailed` alone. A `NameNotFound` can carry the
      SERVFAIL of a server before the one that answered NXDOMAIN. One rule for each error is
      simpler than a rule for one of them.
    - The rcode is `wire.Rcode`, the codec's own type. A second enum of the same codes gives two
      names to one thing. `no_error` and `name_error` never come, and an assertion holds that.
    - A failed send keeps no cause. It is silence, as decision 25 says, and `Timeout` still means
      that every try went unanswered.
    - A server error that `check_response` off takes as the answer keeps no cause. The answer is
      in `err`, and the server's state counts it as an answer.
    - A negative that the memory recalls has no cause. The memory keeps the negative and its TTL
      alone (§20), and no server was asked.
    - `AddressLookup` ends a walk on a failure but `NoData` with the `Failure` of the lookup that
      failed so, whole. Until 2026-10-17 it took the error from that lookup and the other fields
      from the last lookup that failed. Then an `AllServersFailed` could carry the null cause of
      a `Timeout`, or the negative TTL of a NODATA. A negative end still takes the fields of the
      last lookup that failed (§19 step 14).
    - `NameLookup` ends a negative walk, and a cancel after its lookup failed, on the fields of
      that lookup's `Failure`, as `AddressLookup` does. Until 2026-10-17 it built a `Failure` of
      zeros for these ends, so the cause of its lookup was lost (§19 step 14).
    - `connect` covers three local failures as well: no socket, no free connection slot, and an
      engine that keeps no TCP connection. The lookup cannot tell them from a server's refusal
      without the reason of §17 question 54.

    Rejected:

    - A flat enum of the causes, `server_failure`, `refused` and the others beside `connect`.
      Each of its values can come, but each rcode gets a second name.
    - A reason in `on_tcp_failed` and `on_request_failed`, which would tell a connect from a
      handshake. Decision 25 counted it against another alternative: "a second change to the API
      in a call every consumer that owns its sockets makes". §17 question 54 asks for it.
    - The cause beside the engine's result alone, which decision 25 rejected. A consumer that
      drives `Lookup` or `Resolver` itself gets nothing from it.
    - The first cause in place of the last. The owner ruled the last. A failure later in the
      walk is nearer to the end that the caller sees.
    - The extended DNS error of the response (RFC 8914 §2) in the cause. It adds a read of the
      OPT record at each failure, and two octets. §17 question 18 asks it for DNSSEC.
    - The server that the cause came from. One octet fits in the padding of `Failure`, but the
      ruling named one field. §17 question 53 lists it.

    `Failure` grows from 8 octets to 12. `Action`, `Event` and the engine's `Result` keep their
    size, since an `Answer` is larger. The Lean model of the lookup holds the cause in place of
    its flag. It proves that `AllServersFailed` has a cause and `Timeout` has none, and its
    replay compares the cause at each event. The engine model keeps its flag, since which cause
    a lookup holds changes no transition of the engine. The model of the walks holds no
    `Failure`, so it does not change.

    The x86-64 code of `init_in_place`, `heard`, `next_server`, `Resolver.poll` and
    `Resolver.on_datagram` changed, as the fill check's assembly shows. So the counts of
    `bench/count.zig` for the round trip and the datagram matches can move. On 2026-10-17 the
    review of the change counted them under cachegrind 3.22.0 on arm64 Linux, not on the x86-64
    of the baseline. `round-trip` went from 3,948 instructions to 3,970, and `match-wrong` from
    258 to 255. The other twelve cases did not move. Both moves are under the 2% floor of
    `tools/instructions.zig` (docs/mutations.md, The cause of a failure).

    §4, §5 (The cause of a failure), §19 step 14, §20.
46. **A pass waits for a slot that frees with no lookup leaving it.** Ruled by the owner on
    2026-10-18: fix the engine's defect now. Over TLS a lookup's second pass could find no free
    connection slot. The connection of its first pass still held the slot, and closed once its
    alert had gone (§21, TLS rules 4 and 5). The engine failed the pass at once with `connect`.
    That local failure replaced the cause that the server gave (§5, The cause of a failure). Now
    the stream's rule 12 holds: a lookup that finds no free slot waits while a slot is pending.

    The sequence over TLS, with one server, one slot and two passes:

    1. The first pass opens a connection in the slot, and the handshake starts.
    2. The session refuses the server's handshake record. The lookup hears `on_tcp_failed` before
       `on_tcp_connected`, keeps `connect`, and goes on to its second pass. The connection seals
       its fatal alert, and closes once that has gone.
    3. In the drive of the same event, the lookup asks for a stream for its second pass. `find`
       passes over a connection that closes. `free_slot` finds the slot closing, and over TLS it
       closes no slot to make room. So the open fails.
    4. The engine calls `on_tcp_failed` again, and the lookup ends in `AllServersFailed` with
       `connect`. No second query reached the server, and its count of failures rose twice.

    A record that the session refuses once the connection is up leaves it closing in the same way,
    after `stream`. The second pass then replaced `stream` with `connect`. In the clear no
    connection closes after an alert: a failed connection closes at once, and its slot is free.
    But a connect that outlasts its lookup's wait holds its slot until its event (the stream's rule
    10). With one slot, the lookup at the next server found none, and failed at once with
    `connect`.

    Choices the ruling did not make, made here:

    - The lookup waits in `connecting_tcp`, on no connection, and its deadline bounds the wait. The
      lookup model does not change: that state waits for `on_tcp_connected`, `on_tcp_failed` or
      its deadline already. A wait that runs out is a connect that ran out. It keeps no cause and
      takes no sample, and it counts a failure of the server (§5, §19 step 12).
    - A slot is pending when it frees with no lookup leaving it. Its connection closes, or the
      loop holds its memory while it is closed. A slot that a lookup uses is not pending.
    - In the clear, when no slot is pending, the lookup closes the first connection with no
      lookups whose connect is in flight. The idle close cancels such a connect too, after
      `tcp_idle_ns` (the stream's rule 4). The slot frees at the cancelled connect's event, about
      one turn of the loop later, and the lookup waits for it. So a connect that hangs does not
      keep the lookup from the next server. A lookup that finds each slot held by a lookup fails
      at once (the stream's rule 1).
    - The lookup closes such a connection only when no slot is pending. A slot that is pending
      frees as soon, and the connection may still serve a later lookup of its server.
    - The drive admits the lookups that wait at its end, after the idle close. That one place
      covers each way a slot frees: an event before the drive, a send refused in the drive, and
      the idle close.
    - A refusal at admission leaves the lookup waiting, and so does a slot that it cannot have
      then. A failure there would leave the lookup ready after the drive's polls.
    - The engine keeps a flag for each lookup and a count of the lookups that wait. The count lets
      a drive with no wait skip the scan.

    Rejected:

    - The slot of a closing connection freed at once, with its close kept elsewhere. The alert
      waits in the slot's records buffer, which the loop holds until its send ends (TLS rule 3).
      So the close needs a second slot.
    - A spare slot, beside each one or for the engine. A slot holds a frame of 67,585 octets in the
      clear and of 82,177 over TLS, and over TLS 22,789 octets of records beside it. A spare also
      changes the bound that TLS rule 6 asserts, by which a caller sizes `tcp_connections`. And two
      connections that close at once fill one spare slot.
    - The alert dropped when a lookup needs the slot. RFC 9846 §6.2 asks for it: "Whenever an
      implementation encounters a fatal error condition, it SHOULD send an appropriate fatal
      alert". The loop also holds the records buffer until the send's event, so the lookup still
      waits.
    - Admission inside each event that frees a slot. `free_slot` closes a slot to make room inside
      an open, so an admission there opens a connection inside another's open. The model would
      need admission at each of those events too.
    - A local failure that keeps no cause. The pass still never reaches the server. §17 question 54
      asks about a reason in place of the cause.
    - In the clear, a wait for the connect of an earlier try until its event. This decision chose
      it first, and its review on the same day found its cost. The engine has one slot by default
      (`tcp_connections_default`), a wait of 2 seconds, and an idle close at 10 seconds. A connect
      that hangs then holds the slot past each wait. So the lookup at the next server waited out
      each pass and never reached that server. It ended in `Timeout`, in about twice the time
      that the engine took before to end in `AllServersFailed`. The stream's rule 10 does not
      forbid the cancel. It keeps the slot closed until the connect's event, and the idle close
      cancels such a connect already.
    - In the clear, a connection with no lookups whose connect is in flight closed while a slot
      is pending. That cancels a connect that a later lookup of its server could join, and the
      lookup gets no slot sooner.

    The engine model in TLA+ holds the rule (spec/README.md). Each slot of the table says whether
    its lookup waits. `Want` waits while a slot is pending. In the clear `FreeConn` closes a
    connection with no lookups whose connect is in flight, when no slot is pending. The drive's
    end runs `Admit`. The trace writes a lookup that waits as `cw` in place of `c-`, so a walk with
    no wait is written as before. No named limit and no entry point change. The engine grows by
    an octet for each lookup and two more.

    Amended on 2026-10-25 by decision 54. A lookup joins no marked connection. A lookup that finds
    no slot in the ways above waits for the slot of a marked connection, which frees once the
    lookups on it leave.

    §5 (The cause of a failure), §17 questions 54 and 55, §19 step 13 (the stream's rules 1, 4, 10
    and 12), §21 (TLS rule 6).
47. **A query's send lends its connection's records buffer.** Ruled by the owner on 2026-10-18:
    prove the defect that the review of decision 46 found, and fix it if it is real. It is real.
    Over TLS a query is sealed into its connection's records buffer, and its send reads the
    sealed records there (§21, TLS rule 2). Until now only a send of the session's own records
    marked that buffer as the loop's. A query's send marked only the lookup's send buffer, which
    the loop does not read over TLS. So a connection that failed during a query's send left its
    slot free while the loop could still read the buffer.

    The sequence over TLS, with one server and one slot:

    1. The connection is up. A lookup's query is sealed into the records buffer at its start, and
       the query's send is in flight from there.
    2. The peer resets the connection before that send ends. The connection fails, and closes at
       once (TLS rule 5). Nothing marks its slot as borrowed.
    3. The lookup hears the failure, and its second pass asks for a stream. `free_slot` takes the
       closed slot, and a new opening connects there.
    4. At the connect's event the new session starts. Its hello goes into the records buffer at
       its start, over the query's sealed records.
    5. The query's send has not ended. The loop may read its octets until the send's final event
       (rotor decision 5, rule 3). From now it reads the hello's record and then the rest of the
       query's record.

    A test of the twin showed step 4. The query's record was 135 octets. Its first five, an
    application data header, became the header of a handshake record of one octet. The twin's send
    takes its octets when it is submitted, so no wrong octet reached the twin's server. rotor's
    contract does not promise that.

    Over plain TCP a query's send reads the lookup's own send buffer, which stays lent until the
    send's event (the stream's rule 6). A new opening of the connection slot does not write that
    buffer, so plain TCP has no such defect.

    Choices the ruling did not make, made here:

    - Each send from the records buffer marks the slot: one of the session's own records, and a
      query's. The mark names the send, by the query's table slot or by `ring.records`. It
      outlives the opening, as a connect's mark does (the stream's rule 10). Only the send's final
      event clears it.
    - A query's send keeps its `user_data`, which names its table slot. So its event still gives
      the lookup's send buffer back and tells the attempt (the stream's rules 6 and 7). The event
      finds the slot whose buffer it read by the mark, after its connection closed too.
    - The event clears the mark whatever the engine speaks then. A `reinit` closes each connection
      as a new opening does, and keeps the mark. So after a `reinit` from TLS to the clear, the
      slot stays closed until the event of a send that the old configuration made.
    - A slot whose buffer is lent is not free. A closed one is pending, and a lookup that finds no
      free slot waits for it (the stream's rule 12). That wait ends at the send's event.
    - The records buffer is written only while no send reads it, or while the head's send of the
      same opening does. That send reads sealed octets in front of the room that a write takes.
      Assertions hold both parts at each write. Another holds that records move to the buffer's
      start only while no send reads them.

    Nothing in the engine bounds how long such a slot stays pending. A send keeps no handle, and
    `shut` cancels only a connect or a receive. So a send that stalls after its connection failed
    keeps its slot pending until the loop ends the send. Each lookup that finds no other slot free
    waits for that event, or until its own deadline (§5). A send of the session's own records held
    a closed slot in the same way before this decision. §17 question 55 asks about a time bound on
    a slot of the same kind, a connection that closes.

    Amended on 2026-10-20 by decision 49: `shut` cancels the send too. So a closed slot that a send
    holds frees at the cancel's event, about one turn of the loop after the shut. Since 2026-10-21
    `cancel_all` cancels it as well. So after a `reinit` the slot frees at the cancel's event, not
    at the end of a send that may never end.

    Rejected:

    - The sealed query copied into the lookup's send buffer, and sent from there. That buffer holds
      `query_bytes_max` octets of plaintext, and the sealed record is longer by its header and its
      tag. Records sealed after the query wait in the records buffer anyway, in the order they
      were sealed (TLS rule 2).
    - A second records buffer for each slot, which a new opening writes. That is
      `tls_records_out_bytes_max`, 4,096 octets, more for each slot. A failure while both buffers
      are lent still needs the wait.
    - A query's send named by its connection slot, as a send of the session's records is. Its event
      must still give the lookup's send buffer back and tell the attempt. So the connection slot
      must keep the table slot after its connection closed, as the mark does. The model and the
      replay also name a query's send by its table slot.
    - A mark for each lookup, of the connection slot whose buffer its send reads. A connection
      carries one send at a time (the stream's rule 9), so one mark for each connection slot is
      enough. A table holds up to `lookup_slots_max` lookups.
    - A failed connection kept in its `closing` state until its send ends. A connection that fails
      has no peer to send to, so it closes at once (TLS rule 5). The mark keeps its slot closed and
      pending with no new state, as a connect's mark does.
    - A send's event that looks for its mark only over TLS. It saves a scan of the connection slots
      in the clear. But a `reinit` from TLS to the clear may come while a send is in flight. Its
      mark would then stay for ever, and the slot would never free.

    The engine model in TLA+ holds the rule (spec/README.md). Each operation names the connection
    slot whose records buffer it reads: over TLS a query's send and a send of the session's
    records. `Borrowed` reads that name, beside a connect. The check "records lent" holds TLS rule
    3 in two parts:

    - A slot's records buffer is lent to one send at most. A query's send that reads it is its
      connection's head, or the slot is closed.
    - Each operation names the buffer that it reads. Over TLS a send of the session's records names
      its own connection. A query's send names the connection that its query heads, or a closed
      slot. In the clear no operation names one.

    The mutant TB5 puts back `Borrowed` as it was, and TLC finds that check broken. The mutant TB8
    puts back `Pump` as it was, where a query's send names no buffer. The review of this decision
    found that the first part alone did not catch TB8, so the second part came then. No named
    limit and no entry point change.

    §17 question 55, §19 step 13 (the stream's rule 12, and `reinit`), §21 (TLS rule 3).
48. **Each context carries the consumer's statement of its CPU.** Ruled by the owner on
    2026-10-20, on §17 question 56: the second way. The `init` of the DoT, DoQ and DoH contexts
    takes a `tls.Cpu`, which the consumer fills. Each TLS value of colibri v0.8.0 takes one, with
    no default (decision 32). It holds what the program's one probe found of the CPU, and the
    timing mode of the thread that drives the session. Until the ruling each session built its TLS
    value from a constant that stated nothing.

    The value decides the suites of each hello. colibri v0.8.0 reads it in its
    `src/tls/config.zig`, and the host object of chapulin 0.2.0 chooses the suites in its
    `suite.h`:

    - `timing` is `data_independent`, and `probe.aes_clmul` is `yes`. The hello offers
      TLS_AES_256_GCM_SHA384, then TLS_AES_128_GCM_SHA256, then TLS_CHACHA20_POLY1305_SHA256. A
      session whose server selects AES-GCM runs it on the AES instructions. Each session runs the
      native multiply.
    - `timing` is `data_independent`, and `aes_clmul` is `no` or `not_known`. The hello offers
      TLS_CHACHA20_POLY1305_SHA256 alone, and the session runs the native multiply.
    - `timing` is `not_stated`, whatever the probe found. The hello offers
      TLS_CHACHA20_POLY1305_SHA256 alone, and the session runs the portable multiply. RFC 9846
      §9.1 makes TLS_AES_128_GCM_SHA256 the suite to implement, so a server that holds only
      AES-GCM refuses this hello.

    colibri builds chapulin's host object for arm64 and x86-64 (its decision 97, as amended for
    chapulin 0.2.0). On any other target the device object holds TLS_CHACHA20_POLY1305_SHA256
    alone, and the value changes no suite.

    **What a consumer passes.** A consumer that depends on stdx fills `probe` from
    `platform.probe()` once, at its start. It pins stdx at the commit colibri pins, with the options
    colibri gives it (colibri's decision 97, as amended on 2026-09-30). It states `data_independent`
    only for a thread that runs in that mode. On arm64 that is a thread that set PSTATE.DIT on a
    core with FEAT_DIT. On x86-64 it is a thread on a part of Intel's DOIT list, whose operating
    system set DOITM.

    A consumer that cannot state its thread's mode passes `not_stated` as the timing. Its probe
    goes beside it, or `not_known` for each answer. That is the value of the first way, and its
    hello offers TLS_CHACHA20_POLY1305_SHA256 alone. colibri's guide and its examples pass
    `not_stated` with the probe.

    Choices the ruling did not make, made here:

    - The context keeps the value whole, in a field `cpu` with no default (decision 39). The DoT
      and DoQ sessions hand it to the TLS value that each `start` builds. The DoH channel hands it
      to its one TLS value, from which colibri builds the TLS of each transport.
    - `init` takes the value after the anchors. What the consumer states comes first, then the
      seed, then the clock.
    - The DoT and DoQ sessions export the type as `Session.Cpu`, beside `Session.Anchor`. A DoH
      consumer binds colibri's `tls` itself, so it names `tls.Cpu`. The ruling named the
      argument and not this name, so §17 question 59 asked the owner about it. The owner kept the
      name on 2026-10-20.
    - cocuyo exports no value that states nothing. The consumer writes the value, as colibri asks
      of each program.
    - No assertion holds the value. colibri checks neither statement, and the engine cannot read
      the thread's mode either.
    - The examples stated nothing. The probe colibri names is stdx's, which no build of cocuyo
      depended on, and neither colibri nor chapulin exports a probe. §17 question 58 asked the
      owner about it, and the amendment below records the answer.
    - The tests name each value in a constant of their own. The test servers state nothing, as
      before. So no test of cocuyo completes a handshake under AES-GCM. colibri's own tests cover
      those sessions and their SHA-384 tickets (its `record_aes_test.zig` and
      `quic_aes_test.zig`). Since the amendment below, an example with the word completes
      handshakes under AES-GCM against servers that cocuyo did not write.

    Rejected:

    - As built: the sessions state nothing. Each server must take ChaCha20-Poly1305, and no
      consumer can change that.
    - cocuyo probes the CPU through stdx's `platform`. This adds a dependency and a system call in
      `io/`, and the engine still cannot state the timing mode.
    - The value as one more argument of `use_tls`, `use_quic` and `use_doh`. The context is what
      each session starts from (decision 39), and the value is a part of it.
    - The value in each server's `Tls`. It describes the consumer's thread, not a server. `Tls` is
      also a type of `src/`, which names no type of colibri's.
    - Two booleans, one for each claim chapulin reads. colibri refused that form for its own
      values (its decision 97, as amended for chapulin 0.2.0). Each consumer would then work out
      the claims from its probe and its mode.

    The checks are tests of the three sessions. Each reads the suites of a hello under five
    values:

    - the AES instructions, and a data-independent timing;
    - nothing, the value of a consumer that cannot state its thread's mode;
    - a probe that found the AES instructions, and no timing mode;
    - a probe that did not find them, and a data-independent timing;
    - a probe that did not answer, and a data-independent timing.

    The DoH channel's tests read the hello of each link. Twenty-four mutations break the rule, and
    the tests catch each (docs/mutations.md, the CPU a context states).

    The public API changes: the three `init` functions take one more argument, and the DoT and
    DoQ sessions export `Session.Cpu` (§17 question 59). No named limit changes. No model changes
    either: no transition of §5 and no rule of §19 steps 13 and 14 reads the value.

    **Amended by the owner on 2026-10-20, on §17 question 58: the third way.** stdx is a ruled
    dependency of the DoT, DoQ and DoH examples alone, and never of the library or the engine. A
    word on each example's command line turns the statement on. Each live check and the interop
    check then run each server twice, once without the word and once with it.

    - The word is `cpu`. It comes first, before the names. Only the first argument can be the
      word, and only when it is `cpu` exactly. A lookup of the one-label name `cpu` is written
      `cpu.`, with the root's dot.
    - Without the word, each example states nothing, as before: `not_known` for each answer of
      the probe, and `not_stated` for the timing. Each hello offers TLS_CHACHA20_POLY1305_SHA256
      alone.
    - With the word, each example calls stdx's `platform.probe()` once, at its start, on the one
      thread that drives the engine. On arm64, where the probe found FEAT_DIT, the example sets
      PSTATE.DIT with an MSR to the DIT register. It then reads the bit back with an MRS.
    - Where the bit reads as set, the example states `data_independent` and the probe's answers.
      Where the probe also found the AES instructions, each hello offers TLS_AES_256_GCM_SHA384
      and TLS_AES_128_GCM_SHA256 first.
    - Elsewhere the example states nothing, as the ruled way says. That is arm64 without FEAT_DIT,
      arm64 where the bit does not read as set, and each other CPU. On x86-64 the mode is DOITM.
      The operating system sets it, and no program can read it. So each hello there offers
      TLS_CHACHA20_POLY1305_SHA256 alone.
    - The example states `data_independent` only for a thread that it put in that mode itself.
      That is the rule colibri's guide gives each program, and an example is a model that a
      consumer copies. colibri's test programs state the mode on each core. Their header says that
      a program for real peers must not do this (§17 question 58).
    - The word is off by default for the same reason. `not_stated` is the one value that each
      program can state truthfully.
    - Each example prints what it states before its first turn, on the line `cpu: timing
      <timing>, aes_clmul <answer>, dit <answer>`. After each turn it prints the suite that the
      handshake chose, on the line `<turn>: suite <name>`.
    - The DoT example reads the suite from colibri's record provider. The DoQ example reads it
      from chapulin's QUIC session in colibri's `tls`. The DoH example reads it from the link that
      the channel came up on.
    - The examples pin stdx at `5fd03aa`, the commit that colibri v0.9.0 pins. The build requests
      it with colibri's options, the target and `release`. So the build holds one `platform`
      module, and the probe's `Cpu` is the type that `tls.Cpu` holds. The examples' compile proves
      it: a second stdx would give a second type, and `tls.Cpu` would refuse it.
    - Only the root build requests stdx, once it has rotor and colibri. A build that depends on
      cocuyo stops before that request, so it never fetches stdx.
    - `examples/cpu_text.zig` holds what the three examples share of the word. Its `command` reads
      the word and states the CPU in one call, the first of each example's `main`.

    How each check runs both ways:

    - The DoT, DoQ and DoH live checks resolve the two names of each resolver in two runs, first
      without the word and then with it. The refusals, the pins, the record types and the report
      of Google's chain run once, without the word.
    - The interop check resolves its four names in two runs over DoT, over DoQ, and over DoH on
      HTTP/3 and on HTTP/2. The refusals, the record types and the pins run once, without the
      word.
    - Each run without the word must state nothing. Each of its handshakes must run
      TLS_CHACHA20_POLY1305_SHA256.
    - A run with the word on a host whose system reports FEAT_DIT must state `data_independent`.
      Each of its handshakes must run AES-GCM where the system also reports FEAT_AES and
      FEAT_PMULL, and ChaCha20-Poly1305 where it does not.
    - A run with the word on a host whose system does not report FEAT_DIT must state nothing. Each
      of its handshakes must run TLS_CHACHA20_POLY1305_SHA256. On x86-64 no system reports
      FEAT_DIT.
    - On arm64 macOS each run with the word fails where `sysctl` does not report FEAT_AES,
      FEAT_PMULL and FEAT_DIT as 1. Each Apple arm64 CPU has all three, so such a host hides one,
      and no run there can reach AES-GCM.
    - The check reads the host from the system itself: `sysctl` on macOS, and `/proc/cpuinfo` on
      Linux. It never reads the host from the example, since an example whose probe broke would
      then lower what its run must reach. `tools/cpu_word/suite.sh` holds the rule, and each of
      the four checks sources it.
    - Each run keeps each other requirement that it had, the resumption among them. So each check
      makes twice as many handshakes for its resolutions.

    Choices the amendment did not make, made here:

    - The word comes first. The roots are the last arguments, and their count is not fixed, so a
      word after them would be the path of a root.
    - The example reads PSTATE.DIT back, and does not take the MSR on trust. An MSR that did not
      set the bit would otherwise state a mode the thread does not run in.
    - The example names the DIT register as S3_3_C4_C2_5, by its op0, op1, CRn, CRm and op2
      fields. So an assembler that targets a CPU without FEAT_DIT takes the instructions too.
      Only a CPU whose probe found FEAT_DIT runs them.
    - Where the example states no mode, it states nothing, and not its probe beside `not_stated`.
      The ruled way says so, and the hello is the same either way. colibri's guide shows the probe
      beside `not_stated`, and both values are true.
    - On arm64 macOS a check fails each run with the word where `sysctl` hides a feature. A check
      that passed there would never reach AES-GCM, which is what the ruling asks the checks to
      reach. stdx's CI read all three as 1 on GitHub's `macos-26` arm64 runner (stdx design §8,
      2026-09-30).
    - The check does not take the build target's answer where the system gives none, as stdx's
      probe does. On arm64 macOS that case fails. On Linux the check and the probe both read the
      AT_HWCAP word, which `/proc/cpuinfo` lists.
    - `zig build graph-check` gains a second part, `build/graph_check_packages.zig`. It reads each
      module that a compile step of the build reaches. From each module rooted in `src/` or `io/`,
      it walks each module that the module reaches, at any depth.
    - No module rooted in `src/` may reach a module of stdx or of colibri. No module rooted in
      `io/` may reach a module of stdx, except below a module of colibri. colibri's `tls` imports
      stdx's `platform`, its `client` imports stdx's decoders, and the engine imports both by
      right.
    - Three controls make that part fail when it did not read the graph. The walk must reach a
      module rooted in each directory that a rule names. Each canary must get the verdict that it
      expects, and no compile step reaches a canary. Each package that the graph holds must have
      its canaries.
    - A canary reaches the package directly, through a module of this tree outside the rule's
      directory, or below colibri's `tls`. Each rule for `src/` must flag each of its canaries.
      The rule of stdx for `io/` must flag the first two, and pass the third.

    Rejected, with the other ways of §17 question 58:

    - As built: no check against a server that cocuyo did not write runs AES-GCM.
    - stdx with no word: a server then picks from three suites, and no check is sure to reach
      ChaCha20-Poly1305.
    - A probe of the examples' own: a second probe that must stay the same as stdx's. A consumer
      that copies an example copies that probe too.
    - The graph check over the text of each file. A line scanner sees an `@import` that a file
      writes. The module graph shows what the build gives each module, and the compiler refuses
      the import of a name that the build did not give.
    - The graph check over the direct imports of each module alone. A module of `src/` could then
      reach stdx through a module of `examples/`, or colibri through a module of `io/`, and the
      check would pass.

    The checks are the tests of `examples/cpu_text.zig`, and the second part of the graph check.
    The tests read the word, the statement that each value gives, and the set and the read of
    PSTATE.DIT. They also read `command`, the one call that each example makes for the word. `zig
    build test-examples` runs them alone. No test reads two lines of each example: the report of
    `command.cpu`, and the context's `init` that takes it. The live checks and the interop check
    run those lines. docs/mutations.md, the CPU an example states, records the rows.

    No named limit changes, and no public API either: the change is in the examples and the build.
    No model changes. No transition of §5 and no rule of §19 steps 13 and 14 reads the value.

    §17 questions 56, 58 and 59, §21 (the session interface), §24 (the context a session starts
    from).
49. **A connection that closes is shut once it has closed for `tcp_idle_ns`.** Ruled by the owner
    on 2026-10-20, on §17 question 55: the idle close's wait bounds a connection that closes, with
    no new limit. Until then a TLS connection that closed freed its slot only at the end of its
    last send. That send held its alert or its `close_notify` (§21, TLS rules 4 and 5). The idle
    close passed over the connection. A send kept no handle, and `shut` cancelled only a connect or
    a receive.

    The sequence over TLS, with one server, one slot and two passes:

    1. The session refuses the server's handshake record. The connection seals its alert, and
       begins to close (TLS rule 4).
    2. The peer has stopped reading, and keeps its side open. So the alert's send takes nothing,
       and does not end.
    3. The lookup's second pass finds the slot closing, and waits for it (§19 step 13, the stream's
       rule 12).
    4. Until 2026-10-20 nothing ended that send. The lookup ended at its deadline, and the slot
       stayed closing. Each later connection to that server took another slot, so in time the
       server could hold each slot.
    5. Now the first drive after `tcp_idle_ns` shuts the connection, and the shut cancels the send.
       At the cancel's event the slot is free, and the drive's end admits the lookup.

    Choices the ruling did not make, made here:

    - A connection that closes is idle from the instant it began to close. No lookup is on it, and
      no lookup joins it (TLS rule 5). It has no query to send and no answer to wait for, so it is
      idle (RFC 7766 §3). The idle close shuts it after `tcp_idle_ns`, as it shuts each idle
      connection (the stream's rule 4).
    - The connection keeps that instant in its `idle_since_ns`, a `u64` of 8 octets that each
      connection holds already. `refuse` and `close` in `io/io_tls.zig` set it as the connection
      begins to close. Nothing else reads the field of such a connection, since no lookup joins it.
    - So a `close_notify` gets a wait of its own. The connection that says it was idle for
      `tcp_idle_ns` already, and the instant of the idle close starts the wait again.
    - `shut` cancels each operation in flight on the connection: its connect or its receive, and
      now its send. A connection carries one send at a time (the stream's rule 9), so one handle
      names it. The connection keeps it in `send_handle`, an optional `rotor.Handle` of 16 octets.
      With the default options a connection grows from 68,728 to 68,744 octets in the clear, and
      from 107,368 to 107,384 over the twin's TLS.
    - The slot frees at the cancel's event, not at the shut. The loop may read the records buffer
      until the send's final event (rotor decision 5, rule 3). The slot is pending until then (TLS
      rule 3).
    - Each way that ends a connection cancels its send, not only the shut of the idle close. Each
      failure and each close calls `shut`. A resumed handshake that fails calls `retry_full` before
      the connection connects again in full (TLS rule 8). `deinit` and `reinit` call `cancel_all`.
      Each of the three cancels the send.
    - So a connection that fails during a send frees its slot at the cancel's event too, and so
      does one that a `reinit` drops. The wait that decision 47 left with no bound has one now. In
      the clear the cancel gives the lookup's send buffer back at that event (the stream's rule 6).
      After `deinit` the loop drains, since no send waits for ever (rotor decision 5, rule 7).
    - No timer is armed for the bound. The first drive at or after the bound shuts the connection,
      as the idle close of rule 4 does. A lookup's default wait, 2 seconds, ends before
      `tcp_idle_ns_default`, 10 seconds. So a timer would seldom serve the lookup that waits, and
      the start of each later lookup runs a drive.

    In the clear no connection closes slowly. It has no `closing` state: the idle close and each
    failure shut it at once. Its slot is free at once, unless a cancelled connect still borrows its
    address (the stream's rule 10). A query's send in the clear reads its lookup's own buffer, not
    the slot's. So a send that stalls there holds the lookup's buffer and no slot. The shut now
    cancels that send as well.

    What the peer sees: the engine closes its socket after the cancel. A part of the alert or the
    `close_notify` may wait in the kernel's send buffer, and the kernel may still try to send it.
    The rest never goes. So the peer sees its stream end after all of that record, a part of it, or
    none of it. RFC 9846 §6.1 says that a peer that sees the transport close before a
    `close_notify` cannot know that all the data reached it. No lookup is on the connection, so no
    query of the engine's is lost.

    Rejected:

    - As built: the slot frees at the end of the send, or when the peer closes. A peer that never
      reads then holds the slot for ever.
    - A new named limit, `tcp_closing_ns`. It is one more number for a caller to size, and the
      owner ruled against it.
    - A field of its own for the instant a connection began to close, 8 octets more for each
      connection. The idle instant is free from that instant on, and the wait is the same one.
    - The slot freed at the shut, before the cancel's event. The loop may still read the records
      buffer then (TLS rule 3), and a new opening writes its hello there (decision 47).
    - The socket closed, and the send not cancelled. A cancel is what makes the loop let an
      operation go (rotor decision 5, rule 1), and a close is no cancel. A send that waits to write
      could then stay in flight for ever.
    - A timer at the bound, armed while a connection closes. It costs a submit and a cancel at each
      idle close of a TLS connection, whose `close_notify` goes at once in the usual case. And the
      lookup that waits seldom outlasts the bound.
    - The bound only while a lookup waits for a slot. The server can still come to hold each slot
      with no lookup that waits, one connection that closes after another.

    The engine model in TLA+ holds the rule (spec/README.md). `CloseIdle` shuts a connection that
    closes, as it shuts each connection that no lookup is on. `Refuse`, and the idle close of a
    connection that is up, mark the connection idle at that instant. So the trace writes the instant
    a connection began to close as the code does. The check "closing bounded" holds the rule: after
    the clock moves, no connection that closed before it still closes. The mutant CL5 puts back
    `CloseIdle` as it was, and TLC finds that check broken.

    The model holds no cancel. It may end each operation at each event already, so the cancel's
    event is one that it holds. It holds no `deinit` and no `reinit`. Its `RetryFull` already
    leaves each operation of the connection to the loop, the send of the session's records among
    them. No named limit and no entry point change. `Connection` is the engine's own type, and no
    consumer reads its fields.

    The review of this decision found on 2026-10-21 that `cancel_all` and `retry_full` cancelled no
    send. Each dropped the handle, and after that nothing could cancel the send. A test of the
    review stalled a `close_notify`, then called `reinit`. A later lookup waited for that slot, and
    failed with `Timeout`. After `deinit` the loop could not drain the send.

    A resumed connection whose last send stalled could never connect again in the same way. Each of
    the two functions now cancels the send, and a test shows each path. The review also found two
    waits that no time bounds, older than this decision and outside question 55. §17 questions 60
    and 61 ask about them. Decision 52 builds the answer to question 60, and decision 55 builds the
    answer to question 61.

    §17 question 55, §19 step 13 (the stream's rules 4 and 12), §21 (TLS rules 3, 5 and 8).

50. **A try that a reply to it marked is no sample.** Ruled by the owner on 2026-10-17, on §17
    question 27: yes, no sample. A server that lowercases the name answers in time, and the
    lookup ignores the reply that marks it (§7, A server that changes the case). Until the ruling
    that try ran out and was a sample as long as its wait (decision 36, as amended). On a fresh
    table that sample was 2 seconds for a server that answers in 10 ms.

    Since 2026-10-20 the reply that marks the server marks its own try too, in the flag
    `reply_marked` of the lookup. A try so marked is no sample when its deadline passes. No RFC
    states DNS-0x20, so none states this rule either: it is the owner's.

    Choices the ruling did not make, made here:

    - A try is one send of a query: from its `on_sent` to its deadline, or to the answer that
      ends it. `on_sent` clears the flag, and a reply to that send sets it. A query sent again
      over TCP after TC=1 keeps its transaction, and is a try of its own.
    - A try is marked when a reply to it marks its server. That reply echoes in lowercase the name
      that the try's query mixed, and passes checks 1 to 4 and check 6. It marks the try whether
      the server was marked before it or not. So a query that went out mixed before another
      lookup marked the server has its try marked by its own reply, when that reply comes.
    - A mark that another lookup makes during the wait of this try does not mark this try. With
      no reply of its own, the try does not show that the server answered it. A reply lost on the
      path leaves a try that ran out, and §5 counts it as one. §17 question 62 asks the owner
      about this choice.
    - A marked try gives no sample at all when it runs out. The reply that marked it gives none
      either: it failed check 5, and a datagram that fails a check moves no server's wait
      (decision 10).
    - The deadline reads the flag of the try alone, and never the mark of the table. A caller
      that drives lookups alone can build a new `Servers` table over the old one while a try
      waits (§19 step 10). The new table holds no mark, and the marked try is still no sample.
      So no assertion at the deadline reads the table's mark. `mark` asserts it at the instant of
      the reply alone.
    - The deadline of a marked try still counts the server's failure, as before. The ruling is on
      the sample alone, and failover takes a response that the lookup ignores as never received
      (§19 step 12). §17 question 63 asks the owner about this choice.
    - An answer that the lookup accepts after the mark, in the same try, is still a sample. It
      measures the time to an answer that the lookup took. A server that lowercases the name
      never echoes a mixed name, so only an attacker who passes checks 2, 3 and 6 can send both.
    - Over DoH and DoQ no query mixes the case, so no reply marks a try (§22, §23). A cut datagram
      marks no server (§7, A datagram that the buffer cut), so it marks no try either.

    What it costs. An attacker who matches the id, the port and the client cookie takes away the
    sample of each try whose reply they echo in lowercase. That attacker can send an answer too,
    which is a sample of any length they choose, so the rule gives them nothing new. Only a try
    whose query mixed the case can be marked. Once its server is marked, each query to it goes in
    lowercase. So at most the tries in flight to it at the mark lose their sample, until the table
    is built again.

    Rejected:

    - As built: a marked try is a sample as long as its wait. It raises the wait of a server that
      answers in time. The third lookup to a server that answers in 10 ms waited 3.37 seconds,
      above the configured 2.
    - The mark of the table, read at the deadline: no sample for a try whose query mixed the case
      and whose server is marked when it runs out. This needs no flag. It also takes the sample
      away from a try whose own reply never came, when another lookup's reply marked the server.
      Nothing showed that the server answered that try. And a table built again during the wait
      holds no mark, so a try that its reply marked is a sample again.
    - A sample from the send to the reply that marked the try. That reply failed check 5, and
      decision 10 lets no such datagram move a server's wait.
    - No failure for a marked try either. The ruling made one exception to decision 10, for the
      sample, and this would make a second, which the owner did not rule on.

    The checks are the tests of a marked try in `src/resolver/lookup_case_test.zig` and
    `src/resolver/lookup_latency_test.zig`. The rows LS1 to LS12 break them (docs/mutations.md, A
    try whose server was marked).

    No named limit changes. The public API does not change either: `Lookup.Flags` gains one field,
    as it did for `query_mixed`, and stays one octet, so a `Lookup` stays 3,072 octets. No model
    changes. The Lean model of the lookup leaves out time and samples, and reads a reply in
    lowercase as its unmatched reply (spec/README.md). The TLA+ model of the engine holds no
    latency. The rows of a deadline in §5 change their effect, and no next state.

    §5 (retry and timeout policy), §7 (A server that changes the case), §17 questions 27, 60 and
    61.

51. **A cause names its server, and a failed transport its reason.** Ruled by the owner on
    2026-10-18, on §17 questions 53 and 54 and on the rule of a cancel. On question 53 the owner
    chose to add the server, and on question 54 a reason on both calls. On the cancel the owner
    chose that both walks hand on the cause. Until the ruling a cause was an rcode, `connect`,
    `stream` or `request`. The lookup read the cause of a transport from its state (decision 45).
    That cause could not tell a connect from a handshake, or a server's failure from a local one.

    Now:

    - `Cause` is `struct { server_index: u8, what: What }`, and `What` is `union(enum) { rcode:
      wire.Rcode, reason: Reason }` (§4).
    - `server_index` names the configured server that gave the cause, as `Failure.server_index`
      counts. `Failure.server_index` names the server that the lookup was on at its end. After the
      last pass that is the first server of the order, so it does not name the server of the cause.
    - `Reason` has six values: `connect`, `handshake`, `local`, `closed`, `status` and `reset`.
    - `on_tcp_failed` and `on_request_failed` take a `Reason`, on `Lookup` and on `Resolver`. The
      cause reports it in place of `connect`, `stream` and `request`.
    - `AddressLookup` hands on the cause that a lookup's own `Canceled` end carries, as
      `NameLookup` does (§19 step 14).

    `Failure` stays at 12 octets: the server takes the octet of padding that was free. A `?Cause`
    takes four octets, and a `Lookup` has no octet free for the fourth. So the lookup holds its
    cause as `Held`, three octets: the server, and a union of the two values of `What` and a third,
    `none`. A `Lookup` stays at 3,072 octets, and a slot of the table at 3,088 (§9). `failure_of`
    gives the `?Cause`. `wire.Kept` names a record that an answer keeps, so this type is `Held`.
    An `AddressLookup` stays at 1,184 octets.

    Choices the ruling did not make, made here:

    - The six reasons. The ruling named the failures to tell apart, at least. Over a stream these
      are a connect, a TLS handshake, a local failure, and a connection that failed once up or a
      send on it. Over DoH and DoQ they are an HTTP status, a stream that the server reset, and a
      connection that failed. One reason serves the connection in both, and one serves a local
      failure in both.
    - A reason must fit its call. Before `on_tcp_connected` it is `connect`, `handshake` or
      `local`, and `handshake` comes over TLS alone. After it the reason is `closed`, whatever
      failed. The owner put a send on a connection that is up with the connection's failure. So a
      send that the loop refuses there is `closed` too, though no server took part.
    - A request takes any reason but two: `connect` and `status` come over DoH alone. QUIC has no
      connect of its own, and DoQ has no HTTP status. An assertion holds each of these rules.
    - `status` covers each response over DoH that holds no DNS message. That is a status that is
      not 2xx (RFC 8484 §4.2.1), or content of another type or coding. It is also a response that
      colibri refused as malformed or too large. In each the server answered with HTTP that the
      engine cannot read as a DNS message. A response is too large when its content passes 65,535
      octets, the largest DNS message (RFC 8484 §6), or a field value passes `doh_values_bytes_max`.
    - Over DoQ an answer longer than the engine's buffer is `closed`, not `status`. It breaks the
      stream's framing, so the engine fails the whole connection (§24, request rule 5). Over DoH
      colibri ends that exchange alone, and the connection stays up.
    - Over TLS and over DoQ the engine reads the stage of the connection where a failure can come
      in either stage. A failure while the handshake runs is `handshake`, and one after it is
      `closed`. A failure that no server took part in is `local` until the connection is up.
    - Over DoH colibri says how an exchange ended, but not on which connection. Its channel tries
      QUIC and TCP, and ends a waiting exchange as refused when each connection failed. So the
      engine's channel keeps two facts for each exchange, from its request to its end. One is
      whether a connection of the channel came up. The other is whether a server took part in a
      connection: a TCP link that connected, or a QUIC datagram that came.
    - An exchange over DoH that ends refused or closed with no connection up is `handshake` when
      a server took part, and `connect` when none did. One that ends refused after a connection
      came up is `reset`. colibri's refused covers three ends. The server refused the stream (RFC
      9113 §8.7), a GOAWAY left it unprocessed (§6.8), or an HTTP/1.1 connection closed before
      the request went out. In each the server processed none of the request.
    - An exchange that moved to a second connection after its first came up keeps the reason of a
      connection that came up. colibri moves it without an event, so the engine cannot see it.
    - The engine's reason at each of its failures is the list of §5, The cause of a failure.
    - Two failure paths of the engine that no drive reaches were checks, each with `closed`. §17
      question 66 asked whether each becomes an assertion. Since 2026-10-24 each is one.
    - A consumer that owns its sockets passes the reason too. When it cannot tell what failed, it
      passes `connect` before `on_tcp_connected`, `closed` after it, and `closed` for a request.
      The consumer made the call `on_tcp_connected` itself, so it always knows which of the two
      applies.
    - The DoH channel of the engine tells the reason of an exchange that ends without an answer.
      Only colibri and the channel know it, so `Finished.result` holds the answer or the reason.
      `cocuyo_doh` is an exported module, so this changes its `Channel.Finished`, and `Result` is
      new. The twin's `sim.Channel` changes the same way. The approval named the two calls and the
      cause alone, so §17 question 67 asked the owner about this shape. The owner kept it on
      2026-10-24, with the words `result` and `Result` in place of `outcome` and `Outcome`.
    - A lookup's `Canceled` end counts as its last failure when the consumer cancelled the walk
      and the end carries a cause. A `Canceled` end that the walk caused itself does not count, so
      a negative end keeps the negative TTL of the lookup that said it.

    Why decision 25's rejection no longer holds. Decision 25 counted a reason on these calls as "a
    second change to the API in a call every consumer that owns its sockets makes". The cost is
    real, and it is paid now: every caller of the two calls changes. The owner ruled that the
    reason is worth that cost. A live check must tell a connection that never came up from one
    that failed under the lookup. It must tell both from a local failure. The lookup cannot read
    that from its state.

    Rejected:

    - `struct { server_index: u8, kind: Cause }`, the shape question 53 named. `kind` names the
      type of a record across the API, in `Question.kind` and `Answer.kind`, and one word keeps
      one meaning.
    - A flat union of an rcode and the six reasons. Then the calls take a type that holds an rcode,
      or a second enum gives the six names again.
    - The reason beside the engine's result, outside `Failure`, as question 54 listed it. A
      consumer that drives `Lookup` or `Resolver` itself gets nothing from it.
    - A value `unknown` for a consumer that cannot tell. Each stage has a reason that is true when
      nothing more is known: `connect` before the connection is up, and `closed` after it.
    - `local` after `on_tcp_connected`. The owner put a send on a connection that is up with its
      connection's failure.
    - The cause read from the lookup's state, as decision 45 had it, with the call's reason only
      where the state says nothing. That gives one fact two sources.
    - The server's position in the order in place of its index in the configuration. The order is
      the lookup's own, and `Failure.server_index` counts the configuration already.
    - A `?Cause` in the lookup. It took the `Lookup` to 3,080 octets and a slot to 3,096, which
      the review of 2026-10-21 measured. Every slot pays those 8 octets, and the ruling counted on
      the padding.
    - `none` in the public `What`. Then `Failure.cause` holds a value that no failure gives, and a
      consumer reads two ways to say "no cause".
    - Over DoH, `reset` for each exchange that colibri ends as refused. A certificate that the
      check refuses then reads as a stream that the server reset. That is the end the live check
      of DoH meets most, and a local test with colibri's server showed it.

    The model. The Lean model of the lookup carries the reason in its events `tcp_failed` and
    `request_failed`, and the cause holds the position of its server. The model holds no TLS, so
    its streams take no `handshake`. `failure_cause` proves too that the cause names a server of
    the configuration. The proof `keep_server` reads no more of `keep` than the bound of its
    server, so an edit of `keep` reaches the replay's check. The transcript grew from 7,530,842
    transitions to 19,921,682, 183 deep, and the committed slice from 6,696 to 13,694. The slice
    gained two servers and one pass over DoQ, where a cause can name a server that is not the
    lookup's at its end. The TLA+ model of the engine does not change. Which reason the engine
    gives changes no transition of the engine, and its walks spell a lookup without its cause
    (spec/README.md). The tests of `io/` check each reason. The model of the walks holds no
    `Failure`, so it does not change either.

    The instruction counts. No counted case of `bench/count.zig` fails a server, so `keep`,
    `fits_stream` and `fits_request` run in none of them. Of the counted cases, `round-trip` alone
    runs `init_in_place`, which writes `Held`'s three octets where it wrote a `?Cause` of three.
    `match-accept` copies a slot back, and a slot keeps its size. So `round-trip` can move by a few
    instructions at most, and the other thirteen should not move. That is an estimate, not a
    measurement: the counts need valgrind, which runs on Linux alone. `zig build fill-check`
    passes, so no hot path gained or lost a fill.

    The checks are the tests of each reason, in `src/resolver/lookup_failure.zig` and in `io/`.
    The tests of a cancel in `src/resolver/address_lookup_walk.zig` and `name_lookup.zig`, and the
    replay, are checks too. The rows RS1 and after break them (docs/mutations.md, A cause with its
    server and its reason).

    §4, §5 (The cause of a failure), §9, §17 questions 53, 54, 66 and 67, §19 step 14, §21, §24.

52. **A deadline ends `tcp_ready`.** Ruled by the owner on 2026-10-21, on §17 question 60: the
    second way. Until the ruling a lookup in `tcp_ready` waited for the event of its query's send.
    That state waited for no instant, so no deadline ended it (`is_waiting`). A peer that stops
    reading and keeps its side open never ends the send. So the lookup stayed on its connection
    until the caller cancelled it, and the idle close passed over the connection. Over TLS the
    lookup also held the server's slot.

    Now:

    - `tcp_ready` waits for the deadline that `on_tcp_connected` arms, as `awaiting_tcp` waits for
      the one that `on_sent` arms. `Lookup.is_waiting` holds `tcp_ready` (§5).
    - A poll at or past the deadline moves the lookup to the next server, then to the next pass, or
      fails it, as in `connecting_tcp`.
    - The drive then takes the lookup off its connection (the stream's rule 3). When the last
      lookup leaves, the connection is idle (rule 4). The idle close shuts it, and the shut cancels
      the send (decision 49).

    The sequence in the clear, with one server, one pass and the default options:

    1. The connection comes up, and the lookup's deadline is 2 seconds away.
    2. The peer stops reading. The query's send takes nothing, and does not end.
    3. At the deadline the lookup fails with `Timeout`, and leaves its connection. The connection
       is idle from that instant.
    4. After `tcp_idle_ns`, 10 seconds, the first drive shuts the connection. The shut cancels the
       send, and the lookup's send buffer comes back at the cancel's event.

    Choices the ruling did not make, made here:

    - The deadline counts a failure of the server. The server took the connection, and did not
      read the query in the wait. Failover moves away from it, as from a connect that ran out
      (§19 step 12).
    - The deadline takes no sample. A sample starts at `on_sent` (decision 36), and the query's
      send never ended. So the deadline in `tcp_ready` is as the deadline in `connecting_tcp`.
    - The deadline keeps no cause, as no deadline keeps one. A lookup whose every try ran out so
      ends in `Timeout` (§5, The cause of a failure).
    - The send's buffer. The query has started, so it stays at the head of its connection's queue
      until its send ends (rule 9). The lookup's send buffer stays lent until the send's final
      event (rule 6). That event is the cancel's, after the shut. A query that waits in the queue
      and has not started leaves the queue, and its buffer comes back at once.
    - The lookup's next send. A connect needs no send buffer. A send that the lookup asks for
      while its buffer is lent is held until the buffer comes back (rule 6). The buffer comes back
      at the cancel's event, after the idle close, and no timer is armed for that close (decision
      49). So:
      - A try on a stream at the next server waits in `tcp_ready` with its query held. Its
        deadline comes before the idle close, and ends it. That server then counts a failure that
        it did not earn. With one pass the lookup ends in `Timeout`, though the server is up. Over
        TLS each server has a slot of its own (TLS rule 6), so this comes with each second server.
        In the clear it comes when a free slot is there. With none, the lookup closes the idle
        connection to make room (rule 1), and that shut gives the buffer back at once.
      - A try by datagram at the next server, after a TC=1 answer, waits in `query_ready`. No
        deadline bounds that state, so the datagram waits for the first drive at or after
        `tcp_idle_ns` from the instant the last lookup left the connection.
      - A new lookup that takes the same table slot has the same buffer, and waits in the same
        way.

      §17 question 70 asks the owner about these waits. The twin test "a send never ends, and the
      try at the next server waits for its buffer, as built" records the first.
    - The connection's other lookups. Each keeps its own state and its own deadline. A lookup in
      `awaiting_tcp` waits for its answer, as before. A lookup whose query waits in the queue
      behind the send is in `tcp_ready`, and its deadline ends it in the same way. Its query
      leaves the queue then, and its buffer comes back at once. A lookup that joins the
      connection later waits in the queue too, and its deadline bounds it. Each lookup that joins
      also puts off the idle close, since the connection is idle only while no lookup is on it.
    - A later pass to the same server joins the same connection while it is up (rule 1). Its
      query waits behind the send that never ends, and its deadline ends it too.
    - Over TLS the connection is up, so the idle close first makes its `close_notify` (TLS rule
      5). That record waits in the queue behind the send. The connection is closing, and the
      idle close shuts it once it has closed for `tcp_idle_ns` (decision 49). So the slot frees at
      the cancel's event, after the first drive at or after twice `tcp_idle_ns` from the instant
      the last lookup left.
    - The table offers a lookup in `tcp_ready` for its send, and holds its deadline in the bound.
      `settle` does both for that state alone. The poll also puts the deadline in the bound. But
      the bound is never later than the soonest deadline (§11), between an event and the next poll
      too. A connection can come up while the bound is empty and the lookup waits on the ready
      list. `wake_expired` offers it again at its deadline.
    - A caller that drives `Lookup` or `Resolver` itself. The deadline can now pass while a
      `send_tcp` is in flight. Then the lookup draws a new transaction, and the next send it asks
      for is a new try. The caller gives `on_sent` and `on_send_failed` only to the try that asked
      for the send, as the engine does (the stream's rule 7). No signature changes.

    Rejected:

    - As built: the lookup waits until its send ends, or until the caller cancels it. A peer that
      stops reading holds it for ever, and over TLS holds the slot too.
    - The third way of question 60: the engine fails a connection whose query's send has not ended
      at that lookup's deadline. §5 does not change. But each lookup on the connection hears a
      failure that it did not cause, and the drive must find each such send at each deadline.
    - A deadline for the send alone, under a new named limit. It is one more number for a caller to
      size, and the lookup's deadline bounds the same wait.
    - A sample as long as the wait. No query went out whole, so the wait says nothing of the time
      that the server takes to answer.
    - No failure for the deadline. A server that does not read the query fails the lookup as one
      that does not answer it does.
    - The connection shut at the deadline, at once, when its last lookup leaves during a send. The
      held send would then go sooner, and the next server would count no failure that it did not
      earn. The ruling named the idle close, so question 70 asks.

    The model. The Lean model of the lookup holds `tcpReady` in `waiting`, so the deadline is an
    event of that state. The proof `tcpReady_expires` shows that the deadline is enabled in
    `tcpReady`, and that the lookup leaves the state. A reply in `tcpReady` is still the unmatched
    reply alone (spec/README.md). The TLA+ model of the engine holds `tcpReady` in `Waiting`.
    `LookupEvent` arms the deadline at `tcpConnected`, and `Settle` offers a lookup in `tcpReady`
    as before. Two checks hold the rule. "ready armed": a lookup in `tcpReady` has a deadline
    armed. "ready bounded": after the clock reaches its deadline, it is not in `tcpReady` on the
    same try. The mutant RD1 puts back the old `Waiting`, and TLC finds "ready armed" broken. The
    mutant RD13 arms the wait again at the deadline and keeps the lookup in `tcpReady`. TLC finds
    "ready bounded" broken, and "ready armed" holds.

    No named limit changes, and no entry point changes. A `Lookup` keeps its size.

    Amended on 2026-10-25 by decision 53. When the last lookup leaves a connection while a query's
    send is in flight, the drive shuts the connection at once. So the three held sends above go
    out at the cancel's event, and the next server counts no failure that it did not earn. Over TLS
    no `close_notify` goes then, and the slot frees at the cancel's event.

    §5, §17 questions 60 and 70, §19 step 13 (the stream's rules 1, 3, 4, 6 and 9), §21 (TLS rule
    5).

53. **The last lookup to leave during a query's send shuts the connection at once.** Ruled by the
    owner on 2026-10-25, on §17 question 70: the second way. Since decision 52 a deadline ends
    `tcp_ready`, and the lookup leaves its connection. Until the ruling the query's send still held
    the lookup's send buffer, until the idle close shut the connection. That came at or after
    `tcp_idle_ns` from the leave, at a drive for which no timer is armed. Each send that the slot
    asked for in that time was held (the stream's rule 6).

    Now, when the last lookup leaves a connection while a query's send is in flight on it, the
    drive shuts the connection at once. The shut cancels the send (decision 49). The cancel's event
    gives the send buffer back, and a held send goes out at that event. Over TLS no `close_notify`
    goes, since the peer does not read.

    The sequence in the clear, with two servers, a slot for each and one pass:

    1. The connection to the first server comes up. The peer stops reading, and the query's send
       does not end.
    2. At the deadline the lookup moves to the second server, and leaves its connection. No lookup
       is on it, and the query's send is in flight. So the drive shuts it, and the shut cancels the
       send.
    3. In the clear the shut frees the first slot at once. The lookup opens it again, to the
       second server, and the other slot stays closed.
    4. On the next loop step the cancel's event gives the send buffer back.
    5. The second connection comes up, and the lookup's query goes out at once. The server answers
       it, and counts no failure.

    Until the ruling the query of step 5 was held. The second deadline came first, and the second
    server counted a failure. The lookup ended in `Timeout`.

    Choices the ruling did not make, made here:

    - What decides that a query's send is in flight. A connection carries one send at a time, the
      send of its queue's head (the stream's rule 9). The rule holds when that head is a query and
      its send is in flight. Over TLS the head can be the session's own records too: a flight, the
      answer to a KeyUpdate, or a `close_notify`. That send reads the slot's records buffer, and no
      lookup's send buffer. So it holds no lookup's send, and the leave does not shut the
      connection. The idle close ends it as before (TLS rule 5, decision 49). A query behind that
      send has not started. So it leaves the queue at its lookup's leave, and its buffer comes back
      at once (rule 9).
    - The last lookup only, as the ruling says. While another lookup stays on the connection, the
      drive does not shut it. That lookup waits for its send or its answer, and its deadline bounds
      the wait. §17 question 71 asked about a send held in that time. Since decision 54 no lookup
      joins that connection, and the last leave ends it.
    - Which leaves shut. Each way that the drive takes a lookup off its connection: its deadline, a
      move to the next server or the next name, its end, and a cancel by the caller (the stream's
      rule 3). A connection that fails, or whose record the session refuses, is not a leave. It
      tells each lookup on it, and takes each off. A failure shuts the connection at once already
      (the stream's rule 5). A refusal keeps TLS rule 4: the sealed records go out first, and the
      alert after them. §17 question 72 asks about the wait there.
    - A send that would end a moment later. The drive cannot tell a peer that reads slowly from a
      peer that does not read. So it shuts that connection too. The cancel and the send's end race,
      and the event says either one (rotor decision 5, rule 2). Each way the buffer comes back, and
      the event tells nobody, since the lookup moved on (the stream's rule 7). The connection is
      gone, and the next lookup to that server opens a new one. Over TLS that is a new handshake.
      The peer sees the stream end, after all of the query, a part of it, or none of it.
    - The slot. In the clear a query's send reads its lookup's buffer, and no memory of the slot.
      So the slot is free at once, and the same drive may open it again. Over TLS the send reads the
      slot's records buffer. So the slot is pending until the cancel's event (TLS rule 3, the
      stream's rule 12). Each server over TLS has a slot of its own (TLS rule 6). So the try at the
      next server does not wait for that slot.
    - No timer is armed. The cancel's event comes from the loop, on its next step on the twin. The
      held send needs no drive and no timer: it goes out at that event.

    The three held sends of question 70 now:

    - A try on a stream at the next server. Its query goes out at the cancel's event, or at once
      when its connection comes up after that event. The server counts no failure that it did not
      earn.
    - A try by datagram at the next server, after a TC=1 answer. Its datagram goes out at the
      cancel's event, and no drive needs to come.
    - A new lookup that takes the same table slot. Its first send goes out at the cancel's event in
      the same way. The old connection to its server is gone, so a stream opens a new one.

    Rejected:

    - As built: each held send waits for the first drive at or after `tcp_idle_ns` from the leave.
      Over TLS the slot frees after twice that wait. The try on a stream at the next server counts
      a failure that the server did not earn, and a datagram can wait for ever.
    - The third way of question 70. The lookup's next send goes out from octets that the engine
      holds for it, while its buffer is lent. A slot then has two sends in flight, which the
      stream's rules 6 and 7 do not allow.
    - A shut at each leave during each send, the session's records among them. That send holds no
      lookup's buffer. And the `close_notify` of TLS rule 5 still has a peer that may read it.
    - A shut only at a leave at the deadline. A cancel by the caller and a move to the next name
      leave the same send in flight, and it holds the same buffer.
    - A timer at the idle close's bound, armed while a connection with no lookup has a query's send
      in flight. The held send then waits for `tcp_idle_ns`, and the next server's deadline comes
      first.

    The engine model in TLA+ holds the rule (spec/README.md). `Release` shuts the connection when
    its last lookup leaves while its head is a query whose send is in flight. The check "held
    bounded" holds the rule: a query's send on a connection that is up has a lookup on that
    connection. Otherwise the drive shut the connection, and the send's next event gives the buffer
    back. The model holds no cancel (decision 49), so the check reads the shut, not the event. It
    has no peer that stops reading either. The twin tests of `io/` show the event: the held send
    goes out on the next loop step. The mutant SH1 puts back `Release` as it was, and TLC finds
    that check broken.

    The code asserts the same rule. At each drive, after the polls, no connection that is up and
    that no lookup is on has a query's send in flight. A later path that takes the last lookup off
    and does not shut fails that assertion.

    No named limit and no entry point changes. The checks are the tests of `io/` that the rows SH1
    and after break (docs/mutations.md, A send held behind a stalled one).

    §17 questions 70, 71 and 72, §19 step 13 (the stream's rules 3, 4, 6 and 9), §21 (TLS rules 3,
    4 and 5).

54. **No lookup joins a connection that a lookup left during its query's send.** Ruled by the owner
    on 2026-10-25, on §17 question 71: the third way. Decision 53 shuts a connection when its last
    lookup leaves while a query's send is in flight. While another lookup stays, that send stays in
    flight, and the lookup that left keeps its buffer lent. Until the ruling each new lookup to that
    server joined the connection. So each new lookup delayed the shut, and the held send could wait
    past its own deadline.

    Now, when a lookup leaves a connection while its own query's send is in flight, and another
    lookup stays, the drive marks the connection. No lookup joins a marked connection. The lookups
    on it end by their answers or by their own deadlines. The last leave ends the connection at
    once. A new lookup to that server opens a new connection, in a free slot, or it waits for a
    slot (decision 46).

    The sequence in the clear, with one server, two slots and one pass:

    1. Lookup A's connection comes up. The peer stops reading, and A's query's send does not end.
    2. Lookup B joins the connection later. Its query waits behind A's query in the queue.
    3. At A's deadline A ends in `Timeout`, and leaves. B stays, and A's query's send is in flight.
       So the drive marks the connection.
    4. Lookup C asks the same server. It does not join the marked connection. It opens a new
       connection in the second slot, and the server answers it there.
    5. At B's deadline B ends in `Timeout`, and leaves. It is the last lookup, and A's send is in
       flight. So the drive shuts the connection, and the cancel's event gives A's buffer back.

    Until the ruling C joined the first connection. Its query waited behind A's send, and C ended in
    `Timeout`.

    Choices the ruling did not make, made here:

    - The mark. It is a flag of the connection. The drive sets it at a leave when the lookup that
      leaves has its query at the head of the queue, with that send in flight, and a lookup stays.
      That is the leave of decision 53, with a lookup that stays. A leave while another lookup's
      query is in flight sets no mark. The query of the lookup that leaves has not started. So it
      leaves the queue, and its buffer comes back at once (the stream's rule 9).
    - When the mark clears. Never: the connection ends with it. A send that ends after the mark
      does not clear it. The drive cannot tell a peer that reads slowly from a peer that stops
      (decision 53). A peer that stopped once can stop again.
    - The last leave. It ends a marked connection at once, since no lookup may join it again. While
      a query's send is in flight, the drive shuts it (decision 53). Otherwise it closes as the idle
      close closes it, with no wait. In the clear the drive shuts it. Over TLS it makes its
      `close_notify`, since the peer reads (RFC 9846 §6.1). Then it is closing, and the idle close's
      wait bounds it (TLS rule 5, decision 49).
    - A slot when every slot is taken. A lookup that finds no free slot waits while a slot is
      pending, or in the clear closes a connect that no lookup is on, as decision 46 says. When
      neither is so, and a marked connection holds a slot, the lookup waits for that slot too. The
      lookups on the marked connection leave by their deadlines, and the last leave ends it. In the
      clear its slot is then free at once. Over TLS it is pending until the cancel's event, or until
      its `close_notify` has gone. The drive's end admits the lookup that waits, as before. Over
      TLS the wait keeps TLS rule 6. The ruling did not name the wait in the clear, where decision
      46 told the lookup `local`. §17 question 73 asked it, and the owner ruled: as built.
    - Over TLS. Each server has at most one connection that a lookup may join, and a marked
      connection is not one (TLS rule 6). So a server can have two connections: the marked one and
      a new one. A TLS configuration has a slot for each server. Take a lookup whose server has no
      connection that it may join, with no free slot and no pending slot. Then a marked connection
      holds a slot, since each other slot holds the one connection of another server. So the lookup
      waits, and over TLS no lookup is told that its connection failed for want of a slot.
    - What the connection's lookups see. Nothing changes for them. Their queries wait in the queue,
      their answers come as before, and their deadlines bound them. A failure of the connection
      tells each of them, as before. A refusal over TLS sends its alert first (§17 question 72).
    - The mark is the engine's own. No entry point and no named limit changes.

    Rejected:

    - As built: the shut waits for the last lookup to leave, and each new lookup can join. With a
      steady flow of lookups to that server, the held send can wait past its own deadline.
    - The second way of question 71: the drive shuts the connection at the leave, whatever lookups
      stay. Each lookup on it then hears a failure that it did not cause, and the server counts it.
    - A mark at each leave during each send, the session's records among them. That send holds no
      lookup's buffer (decision 53).
    - A mark that clears when the held send ends. The next stall then needs a new mark, and a
      lookup that joined in that time waits behind it.
    - A marked slot that is pending in the clear before a connect that no lookup is on is closed.
      The marked slot frees at the last leave, up to a deadline later. A cancelled connect frees its
      slot about one turn of the loop later.
    - A marked connection closed to make room over TLS. Its lookups would hear a failure that they
      did not cause, as in the second way.
    - The last leave of a marked connection whose sends ended left for the idle close. No lookup may
      join it, so it holds its slot for nobody. No timer is armed for that drive (decision 49).
    - A shut at each last leave of a marked connection, over TLS too. A peer that read each query
      then gets no `close_notify` (RFC 9846 §6.1).

    The engine model in TLA+ holds the rule (spec/README.md). `Release` marks the connection when
    the lookup that leaves has its query's send in flight there, and a lookup stays. `FindConn`
    passes over a marked connection, and `Want` waits for its slot as above. `Leave` ends a marked
    connection at its last leave, through `EndMarked`. Four checks hold the rule:

    - "joins no marked": no lookup joins a marked connection;
    - "left marked": a connection that is up, whose head is a query whose send is in flight, and
      whose lookup has left it, is marked;
    - "marked held": a marked connection is up with a lookup on it, or it closes;
    - "marked said": over TLS the last leave of a marked connection leaves it closing, with its
      `close_notify`, unless the loop refused the send.

    "slot waited for" holds the wait. A lookup told that its connection failed, while a marked
    connection holds a slot, breaks it.

    The mutant NJ1 lets a lookup join a marked connection, and TLC finds "joins no marked" broken.
    NJ2 sets no mark, and TLC finds "left marked" broken. NJ3 leaves a marked connection up at its
    last leave, and TLC finds "marked held" broken. NJ16 and NJ17 tell the lookup that its
    connection failed in place of the wait, in the clear and over TLS. TLC finds "slot waited for"
    broken. NJ18 shuts a marked connection over TLS at its last leave, and TLC finds "marked said"
    broken. `Engine_tls_2_1_bound_2_1`, which CI checks on each push, reaches a mark over TLS.

    The code asserts the same rule. At each drive, after the polls, each marked connection is up
    with a lookup on it, or it closes. And each connection that is up, whose head is a query whose
    send is in flight and whose lookup has left it, is marked.

    The checks are the tests of `io/` and the walks that the rows NJ1 and after break
    (docs/mutations.md, A connection no lookup may join).

    §17 questions 71 and 72, §19 step 13 (the stream's rules 1, 3 and 12), §21 (TLS rules 5 and 6).

55. **A link that closes is shut after `quic_idle_ns`, and each end of a link cancels its send.**
    Ruled by the owner on 2026-10-21, on §17 question 61: the second way, with
    a test on the twin first. It is the rule of decision 49 for a channel's link. Until 2026-10-26
    the send of a link kept no handle. So neither the link's `shut` nor its `cancel_all` could
    cancel that send (`io/io_channel_link.zig`). A link that closed waited for that send to end
    (§24, request rule 19). A new opening of the link sent nothing until that send ended.

    The sequence over a channel's TCP link, with one server:

    1. The TCP link runs. The peer stops reading, and keeps its side open.
    2. The channel owes octets, and the link sends them. The send takes nothing, and does not end.
    3. The channel closes the link. A send is in flight, so the link closes, and waits for that
       send (request rule 19).
    4. Until 2026-10-26 nothing ended that send, and the link stayed closing. A new opening of the
       link connected, and its octets waited for the buffer of the old send. So a later request on
       that link waited until its deadline. After `deinit` the loop could not drain.
    5. Now the first drive after `quic_idle_ns` shuts the link, and the shut cancels the send. A
       new opening that comes first shuts the old one, and cancels the send then. At the cancel's
       event the buffer comes back, and the new opening sends.

    Choices the ruling did not make, made here:

    - The link keeps the handle of its send in `send_handle`, an optional `rotor.Handle` of 16
      octets in `LinkState`. A link has one send in flight at most (request rules 8 and 15), so one
      handle names it. The QUIC link keeps the handle of its datagram's send too.
    - The link keeps the instant it began to close in `closing_since_ns`, a `u64` of 8 octets. No
      field of the link is free at that instant. The channel's `idle_since_ns` does not serve: a
      channel that holds exchanges can close one link.
    - Each way that ends a link cancels its send, since each calls `shut`. These are the bound, a
      failure, a close with nothing to send, and the end of a closing link's last send. A new
      opening calls `shut` first too. `deinit` and `reinit` call `cancel_all`, which
      cancels the send as well.
    - `cancel_all` keeps the handle, as the connections' `cancel_all` does (decision 49). The
      fields of the link stay for the send's event or for `close_all`.
    - The buffer frees at the cancel's event, not at the shut. The loop may read the buffer until
      the send's final event (rotor decision 5, rule 3). So a new opening sends nothing until then.
      It connects in that time, and the cancel's event comes at the next turn of the loop.
    - No timer is armed for the bound. The first drive at or after the bound shuts the link, as
      decision 49 does for a connection. A lookup's deadline, a channel's instant, and the start
      of each later lookup each run a drive. §17 question 75 asks about a link with none of them.
    - The shut at the bound tells the channel nothing. The channel closed the link itself, and its
      connection on that link writes and reads nothing more (request rule 19).
    - The shut at the bound reads the channel. The cancelled send's event reads the channel no
      more, since its opening has ended. But the channel may hold an end while that send is in
      flight (request rule 17). So the read at the shut tells that end.
    - The drive shuts such a link first, before its polls. So the polls of the same drive take
      what the channel told, and the lookup hears it at once. An end that the channel told there
      reaches its lookup before the polls find that lookup's deadline. §17 question 74 asks
      about this order.

    What the peer sees: the engine closes the socket of the link after the cancel. A part of the
    last octets may wait in the kernel's send buffer, and the kernel may still try to send them.
    The rest never goes. Those octets end the connection that the channel closed, such as a GOAWAY
    or a `close_notify`. RFC 9846 §6.1 says that a peer that sees the transport close before a
    `close_notify` cannot know that all the data reached it. The channel closed the link, so no
    exchange of the engine's is lost.

    Rejected:

    - As built: a link that closes waits for its send for ever, and a new opening waits with it.
    - A new named limit for a link that closes. The owner ruled for `quic_idle_ns`, as decision 49
      ruled for `tcp_idle_ns`.
    - The channel's `idle_since_ns` as the instant. A channel with exchanges can close one link, and
      the instant of the channel then says nothing of the link.
    - The buffer freed at the shut, before the cancel's event. A new opening would write its octets
      into a buffer that the loop may still read.
    - A shut at once when the channel closes a link with a send in flight. The channel closes a
      link after its last octets, and a peer that reads takes them.
    - A timer at the bound. It costs a submit and a cancel at each close of a link, whose last send
      goes at once in the usual case.

    The engine model in TLA+ holds the rule (spec/README.md). Each move of the clock first shuts
    each link that closes, since a tick is the idle wait (`ShutLapsed`). Then it reads the link's
    channel, and only then do the deadlines pass. The clock can move while a link closes.

    The check "link closing bounded" holds the rule: after the clock moves, no link that closed
    before it still closes. The mutant DL1 puts back the drive as it was, and TLC finds that check
    broken. A first form of the model read no channel at the shut, and TLC found "channel held
    while sending" broken.

    The model holds no cancel, as decision 49 says. `ShutLink` leaves each operation of the link
    to the loop, and each may end at each event. So the cancel's event is one that the model holds.
    It holds no `deinit` and no `reinit`. No named limit and no entry point change. `LinkState` is
    the engine's own type, and no consumer reads its fields.

    The tests of `io/io_channel_link_test.zig` and the walks are the checks (docs/mutations.md, A
    DoH link whose send never ends).

    §17 question 61, §24 (request rules 8, 14, 15, 19 and 24), decision 49.
56. **Every limit lives in a `limits.zig` of its module, and every other integer constant has a type
    where it is.** Ruled by the owner on 2026-10-17, on §17 question 37: "every limit moves into a
    `limits.zig` of its module, the limits of each `constants.zig` too. Each `constants.zig` keeps
    the protocol sizes and the defaults. Each constant that is not a limit gets a type where it is.
    CLAUDE.md's non-negotiable 5 and the lint rules change with it." Built on 2026-10-26. Amended
    on 2026-10-28 for the 0.7.0 release: the aliases are gone (§17 question 76), and each limit has
    a suffix (§17 question 78). "At 0.7.0" below says what changed.

    The classification test. Each constant of a constants file, and each integer constant of the
    other files of `src/` and `io/`, takes the first class that fits:

    1. A limit by its name. A name that ends in `_max`, `_min` or `_limit` names a limit. This holds
       also when an RFC fixes the number, as for `name_bytes_max`, since the code checks a value
       against it.
    2. A default: a value that a caller can change, or that a caller declares. Its name ends in
       `_default` in most cases. It stays in `constants.zig`.
    3. A protocol size or value: a number that an RFC or the format of a peer fixes. The code reads
       or writes it as it is. `header_bytes`, 12, is one (RFC 1035 §4.1.1). It stays in
       `constants.zig`.
    4. A limit with no such suffix: a bound that the code holds or checks. A count of slots and the
       size of a buffer that cocuyo chooses are limits. `buffer_bytes` of the engine was one. Since
       0.7.0 each such limit has a suffix, and `buffer_bytes` is `buffer_bytes_max`.
    5. Any other constant: a unit, a base, a mask, a shift, a code or a parameter of an estimate. It
       is no limit. In a constants file it stays there, and in another file it stays where it is.

    A limit moves into the limits file beside its constants file, with its doc comment as it was.
    The modules of `src/` each have a `limits.zig`, and so does the engine in `io/`. The three
    modules of `io/` with a constants file of their own have a limits file of their own:
    `io_quic_limits.zig`, `io_doh_limits.zig` and `io_doh_channel_limits.zig`. A limit two modules
    share lives in `src/core/limits.zig`. A comptime check of a constants file stays there, and
    reads the limits through `limits.`.

    What moved, and what got a type:

    - 139 constants of the ten constants files are limits, and moved. 23 of them have no suffix, and
      the inventory names each one (docs/mutations.md, Every limit in a limits file).
    - 32 limits of other files moved, from 20 files. Each got a name in its limits file that says
      its place. `printable_min` of `name_text.zig` is `text_printable_min`. The bounds of the DoH
      test servers start with `server_`. A limit with no doc comment got one.
    - 287 integer constants of other files got a type where they are. The rule of decision 40 chose
      each type. 142 are a `usize`, 57 a `u64`, 37 a `u8`, 17 a `u16` and 17 a `u32`. 10 are a
      `u21`, 4 a `u6`, 2 a `u5` and 1 a `u3`. A code point of a DoH template is a `u21`, as `within`
      reads one.
    - No value changed, and no named limit changed. The tree compiled with each type at the first
      try. A constant that meets a narrow runtime value now widens the sum, as decision 40 says.
      `zig build fill-check` finds the same fills.

    The public paths. A consumer reached a limit as `cocuyo.constants.query_bytes_max`, and as
    `cocuyo_rotor.constants.udp_payload_bytes_max`. Until 0.7.0, no path was lost:

    - Each module root exports `limits` beside `constants`: `cocuyo.limits`, `cocuyo.wire.limits`,
      `cocuyo.cache.limits`, `cocuyo_rotor.limits`, `cocuyo_quic.limits`, `cocuyo_doh.limits` and
      the others. These names are new.
    - Each public `constants.zig` kept an alias of each limit that left it, in a block at its end.
      An alias is no limit of its own, and the lint rule passes it. `name_text.printable_min`,
      `printable_max` and the two `fuzz.seed_count` kept an alias too.
    - The tree reads the new paths: the library, the examples, the benchmarks, the tools and the
      README. §17 question 76 asked whether the aliases stay. The owner ruled that they go at 0.7.0.
    - `zig build consumer-check` built one old path from outside the package, for each of the two
      roots: `cocuyo.constants.query_bytes_max` and `cocuyo_rotor.constants.buffer_bytes`. Each
      had to equal its new path. Since 0.7.0 the package reads the new paths alone.
    - The twin keeps an alias of each limit whose name rotor's own `constants` has: `wait_ns_max`,
      `operations_max`, `batch_max` and four more. The engine's tests read `rotor.constants`, which
      is the twin there, and rotor's own surface elsewhere.

    The checks:

    - The lint rule `typed-constants` reads each Zig file of `src/` and `io/`, and not the constants
      files alone. It reports each container's `const` with no type, as before.
    - The rule also reads the place of each limit. It reads each `const` at the top level of a file
      that is no limits file. It reports one whose name ends in `_max`, `_min` or `_limit` and whose
      value is no alias. A constants file is such a file. A limits file is a Zig file whose stem
      has the word `limits` between its underscores, or a file under a directory named `limits`.
      So a piece of a split one counts, and `io_delimits.zig` does not.
    - The rule reads the place of no limit in a test file or in a `fixtures.zig`. A test's bound is
      the test's own choice (§17 question 77). It reads the top level alone: a member of a type,
      such as `output_bytes_max` of a transport, is part of that type's interface.
    - The rule `unbounded-loop` takes a chain through `limits` for a named limit, and not a chain
      through `constants`: a constants file holds no limit. A name that ends in `_max` is a limit
      on either chain. So `limits.tcp_chunk_bytes_max` bounds a loop, and `constants.header_bytes`
      does not. The rule's finding names `limits.zig` as the place of the bound.
    - The rule `magic-numbers` exempts `limits.zig` by its basename, as it exempts `constants.zig`.
      It takes a literal that a `const` names wherever the `const` is, so the place is the
      typed-constants rule's check.
    - The canary tree of `zig build lint` holds a limit in a constants file and a limit in another
      file. The lint must report each one by its name. Since 0.7.0 it also holds a limits file with
      a constant that has no limit's suffix.
    - Each limits file has the test of decision 40 that reads the types of its public constants.

    What the checks do not catch:

    - A limit with no suffix outside a limits file. The rule reads names, and a count of slots has
      no name it can read. Since 0.7.0 a limits file holds no such name, so the author of a new
      limit names it with a suffix. The rule then keeps it in its limits file (§17 question 78).
    - A limit in a test file, in a `fixtures.zig`, or inside a type.
    - A limit in `bench/`, `tools/` or `examples/`. Nothing of them is linked into the library.

    Rejected:

    - The first way of question 37: limits and protocol sizes stay mixed in each constants file, and
      the lint rule reads each file. A reader then cannot tell a bound that cocuyo chose from a size
      that an RFC fixed.
    - A rename of each limit with no suffix, so that the rule reads every limit. It changes public
      names, which needs the owner (CLAUDE.md, Ask before). §17 question 78 asked it. The owner
      ruled it for 0.7.0.
    - The limits files with no aliases. The public API then loses each old path, which needs the
      owner too. The owner ruled it for 0.7.0 (§17 question 76).
    - A rule of its own for the place. CLAUDE.md names the rules of the lint, and the ruling changes
      its non-negotiable 5 alone. The two checks read the same files with one walk.
    - A list of the limits in the rule. A list goes stale at the next limit, and a name does not.

    At 0.7.0. The owner ruled on 2026-10-26 that the aliases go at the 0.7.0 release (§17 question
    76), and on 2026-10-28 to do it now (c4milo/cocuyo#54):

    - Each public `constants.zig` lost its block of aliases: 111 names in eight files. These are
      `cocuyo.constants` (38), `cocuyo.wire.constants` (15), `cocuyo.resolver.constants` (3),
      `cocuyo.resolv_conf.constants` (11), `cocuyo.cache.constants` (4), `cocuyo_rotor.constants`
      (22), `cocuyo_doh.constants` (11) and `cocuyo_quic.constants` (7). `cocuyo.core.constants`
      is `cocuyo.constants`.
    - `cocuyo.core.name_text.printable_min` and `printable_max` are gone, and so are
      `cocuyo.wire.fuzz.seed_count` and `cocuyo.resolv_conf.fuzz.seed_count`.
    - A consumer reads each of them at `limits` of the same module, except the two seed counts.
      Each of these is `fuzz_seeds_default` of `constants` since §17 question 90. No value changed.
    - The twin keeps its aliases of rotor's own `constants` names. The engine's tests read
      `rotor.constants.wait_ns_max`, and the twin is `rotor` there. The twin is no public module.
    - The cache keeps `failure_seconds_least` and `failure_seconds_max` in its `limits.zig`, and
      `failure_seconds_min_default` in its `constants.zig`. Each is the cache's own name for a
      value of `core`, as `ttl_seconds_max_default` is (decision 60, decision 37). None is a path
      that a move left behind, and each is in the file of its class. So they stay.

    The owner ruled on 2026-10-26 that each limit with no suffix gets one at 0.7.0 (§17 question
    78). The 23 limits of the inventory each got the suffix of their meaning. No value changed, no
    limit came or went, and no other name changed:

    - `_max` for a size or a count that cocuyo holds at most: the engine's ten, `buffer_bytes_max`
      and `tcp_chunk_bytes_max` among them, `cocuyo_doh`'s five and `cocuyo_quic`'s four.
    - `_min` for a room that a check keeps at least: `quic_idle_margin_ns_min` of the engine, and
      `quic_pending_reserve_bytes_min` of the twin.
    - The twin's `socket_buffer_bytes_cap` is `socket_buffer_bytes_granted_max`, and its
      `socket_buffer_bytes_refuse_above` is `socket_buffer_bytes_asked_max`. Each of the two names
      says what it bounds, since `socket_buffer_bytes_max` of the twin is a third bound.
    - 20 of the 23 are public. The twin's three are not.

    The rule `typed-constants` then reads every limit by its name:

    - It reports a `const` at the top level of a limits file whose name ends in none of `_max`,
      `_min`, `_limit` and `_least`. An alias is no exception there. An import is: a bare
      `@import(...)`, or a chain of fields after it whose names have no `_`, such as
      `@import("cocuyo").core`. A field with a `_` names a constant of the other file, so it must
      have a limit's name too. So a new limit with no suffix fails the lint in its limits file, and
      with a suffix it fails the lint in any other file.
    - `_least` is a limit's suffix on both checks. `cache_failure_seconds_least` of `core` and the
      cache's `failure_seconds_least` are the least time of RFC 9520 §3.2, beside
      `Config.cache_failure_seconds_min`, which is no limit (decision 60). No other name ends in
      `_least` at the top level of a file. The owner accepted `_least` as a limit's suffix on
      2026-10-28.
    - The two `fuzz_seed_count` were the count of seeds that a fuzz gate runs. Each is a default,
      not a bound, and the owner ruled on 2026-10-28 that each is `fuzz_seeds_default` of its
      module's `constants.zig` (§17 question 90). So the check of a limits file passes no other
      ending.
    - The canary's limits file holds `canary_chunk_bytes`, which the lint must report.

    §12, §16 decision 40, §17 questions 37, 76, 77, 78, 79 and 90.

57. **YXDOMAIN ends the lookup with `NameTooLong`.** Ruled by the owner on 2026-10-27, on
    c4milo/cocuyo#49: the lookup ends at once with the error `NameTooLong`, with no failover and no
    new member of `Error` or `Failure`. Built on 2026-10-27.

    Until the ruling `wire.Rcode` had no member for 6. `Rcode.from_bits` returned null, and the
    lookup ignored the response. It waited until its deadline and asked the next server. A server
    answers YXDOMAIN when a DNAME substitution makes the name longer than 255 octets (RFC 6672
    §2.2). Each server gives the same answer, so the wait and the failover gained nothing.

    Now:

    - `wire.Rcode` has `yxdomain`, 6 (RFC 6895 §2.3).
    - `lookup_policy.rcode_action` gives `name_too_long` for it, whatever `check_response` and
      EDNS0 say. The lookup fails at once with `NameTooLong` (§5).
    - The response comes from a server that works. It takes a sample of the server's latency and
      counts the server up, as NXDOMAIN does. It keeps no cause. A cause from an earlier server
      stays, as the table of The cause of a failure says for `NameTooLong`.
    - The lookup reads no section past the question. It does not require the DNAME record that RFC
      6672 §2.2 puts in the answer section, as it does not require the SOA of an NXDOMAIN.

    Choices the ruling did not make, made here:

    - The search walk of one `Lookup` ends, and does not try the next candidate as NXDOMAIN does.
      The server found a DNAME at an ancestor of the candidate, in a zone it serves, and replaced
      the suffix of the candidate (RFC 6672 §2.2). So the walk reached a zone that holds the
      candidate, as an answer does, and a later candidate names another host. The ruling says "at
      once" too.
    - The cache keeps nothing. RFC 2308 §5 gives a TTL to NXDOMAIN and NODATA alone, and its §7 says
      that no RFC covers the cache of other negative responses. The memory of §20 keeps an answer,
      `NameNotFound` and `NoData` alone. `Failure.negative_ttl_seconds` is zero for `NameTooLong`.
      So the next lookup of the name asks a server again, which is correct when the DNAME changes.
    - `AddressLookup` keeps its rules (§19 step 14). `NameTooLong` from one family is a failure that
      is not `NameNotFound` and not `NoData`. So rule 4 does not cancel the other family. By rule
      5 an answer from the other family ends the walk answered, with `partial` set to
      `NameTooLong`. When both families end with `NameTooLong`, the walk ends with `NameTooLong`.
      A DNAME substitution reads the QTYPE only when it is DNAME (RFC 6672 §2.2), so in most
      cases both families get YXDOMAIN. The two queries go at once, so the second end comes at
      about the same time. `NameLookup` ends with `NameTooLong` by its rule for any other failure.
      The Lean model of the walks does not change.
    - In `AddressLookup`, an NXDOMAIN from the other family wins, and the walk tries the next
      candidate. Rule 5 reads `NameNotFound` before any other failure. Rule 4 makes that order
      necessary: an NXDOMAIN that comes first cancels the other family, so its YXDOMAIN never
      arrives. With this order the walk moves on whichever end comes first, as rule 3 requires.
      So the end of one `Lookup`'s walk at YXDOMAIN does not reach the walk of `AddressLookup`
      here.
    - The transition is a row of `awaiting_udp` in §5's table, after NXDOMAIN and NODATA.
      `awaiting_tcp` reads it as the UDP rows, and so does a lookup over DoH or DoQ. The Lean model
      of `Lookup` has the reply `yxdomain` and the error `nameTooLong`. The TLA+ engine model does
      not change. Its NXDOMAIN already ends a lookup of one candidate, and the engine treats each
      end of a lookup the same way.

    Rejected:

    - A new member of `Error` or of `Failure`, such as `NameExists`. The ruling refused it. Each
      consumer that switches over `Error` must change for it.
    - A failover, as for a server failure. Each server applies the same DNAME, so each gives the
      same answer. The failover sends a query to each server on each pass, then ends with
      `AllServersFailed`, which hides the reason.
    - The next candidate, as for NXDOMAIN. That reads a name that exists as a name that does not.
    - A rule 4 for `NameTooLong` in `AddressLookup`, which cancels the other family. It changes the
      model of the walks for a rare case, and gains little time.

    §5, §19 step 14, §25, docs/mutations.md (YXDOMAIN ends the lookup).

58. **A lookup sends one server at most three queries of a name over one transport.** Ruled by the
    owner on 2026-10-27, on c4milo/cocuyo#50: keep `attempts_max` as it is, and add a check that no
    server address gets more than three queries of one lookup over one transport, whatever
    `Config.attempts` says. The bound is a new named limit, `queries_per_transport_max` in
    `src/resolver/limits.zig`, which the owner approved. "A resolver MUST NOT retry a given query
    to a server address over a given DNS transport more than twice (i.e., three queries in total)"
    (RFC 9520 §3.1). A `resolv.conf` with `options attempts:4` or more stays accepted, since the
    bound now holds the rule.

    What counts as one query. Each query the lookup sends counts at `on_sent`, against the
    position of its server in the order and against its transport:

    - The first query of each pass counts.
    - The retry without EDNS0 after FORMERR counts. RFC 6891 §6.2.2 asks for it, but it asks the
      same server the same question, so it is a retry of the given query.
    - The retry after BADCOOKIE counts, over UDP and on a stream (RFC 7873 §5.3).
    - The query again after a reply that the checks of §7 ignored counts. A reply in another case
      is one such reply (§7, A server that changes the case): the try runs out, and the next pass
      asks again.
    - A query to the next search candidate is another query, not a retry: its name is another.
      So is a query to a CNAME's target. Each new name starts its counts at zero.
    - A send that failed does not count: no query reached the server.
    - The transports are two: the datagram, over UDP or as a DoH or DoQ request, and the stream,
      over TCP or TLS. A move to TCP after TC=1 is another transport, so it does not count against
      UDP. "A resolver MAY retry a given query over a different DNS transport to the same server"
      (RFC 9520 §3.1).

    What the lookup does at the bound:

    - A server with no query left over the transport the lookup starts on is passed over. The walk
      goes on to the next server, and to the next pass. When no server is left, the lookup ends as
      today's last pass ends: `Timeout`, or `AllServersFailed` when it holds a cause.
    - A retry that the bound forbids moves the lookup to the next server. FORMERR and BADCOOKIE
      keep their rcode as the cause, as a server failure does, since the server failed the
      query and no retry is left. TC=1 keeps no cause: the server answered, and only the stream is
      spent.
    - To pass over a server records no failure and no sample of it in `Servers`. The lookup sent it
      nothing, so it learned nothing of its health or its latency.

    How it meets failover (§19 step 12). The order is the lookup's, computed at its first poll, and
    the counts follow the positions of that order. A server that failover promoted to the front,
    one query in `failover_retry_chance`, takes its three queries as any other does. The counts
    belong to one lookup and one name, and `Servers` keeps none of them. So a server that one
    lookup passed over gets queries again: the next lookup asks it in the order that failover gives
    it. A pass over a server counts no failure, so the bound does not move a server later in that
    order.

    The cost. The lookup holds the counts in four octets, two bits for each of `servers_max`
    positions and each transport. Zig pads the lookup to eight octets more, from 3,072 to 3,080,
    and a slot from 3,088 to 3,096 (§9). §17 question 83 asked whether that stays, and the owner ruled: as built.

    The model and the checks. §5 changed first, then the Lean model, then the code. The model's
    state holds the counts. `advanceServer` passes over a spent server, and a retry the bound
    forbids moves on through `retry`. Its proof `sends_bounded` shows that no count passes three,
    whatever events come. The counts split states that differ in them alone, over UDP most, where
    the walks of two servers over several passes grew 25 to 45 times. So over several passes, the
    full walk takes two servers over UDP with one name alone. It takes three servers over two
    passes alone, with one name and no UDP. One server reaches each rule, and two servers reach a
    server passed over in a pass and at the start of the next. The walk holds 38,759,600
    transitions under 84 configurations, from 21,444,698 under 109. §17 question 84 asked whether
    the 25 that it drops stay out, and the owner ruled: as built. Each new check is a check and an assertion: `Sends.add` asserts
    the count is under the bound.

    Rejected:

    - `attempts_max` lowered to 3. It holds RFC 9520 §3.1 for the passes alone, and not for the
      retries inside a pass: the default 2 could still send four queries. It also refuses a
      `resolv.conf` that glibc and c-ares take, and changes a named limit.
    - Leaving it. A configuration of 5 passes sends one server five queries, against a MUST of RFC
      9520 §3.1.
    - Counts in `Servers`, across lookups. RFC 9520 §3.1 bounds the retries of "a given query",
      which is one lookup's. A count across lookups would need the time that §3.2's cache of
      failures holds, and that is c4milo/cocuyo#51.
    - Counts by the server's address rather than by its position. A configuration that names one
      address twice then shares one count. §17 question 82 asked it, and the owner
      ruled: as built.

    §5, §9, §10, §12, §19 step 12, §17 questions 82 and 83.

59. **A name that compact denial says does not exist ends as `NoData`.** Written on 2026-10-27. The
    owner ruled on c4milo/cocuyo#52: keep `NoData`, record the reason here, and close the issue.

    Under compact denial of existence (RFC 9824), a server answers a name that does not exist with
    NOERROR and no data. An NSEC record at the name tells the truth: its type bitmap holds NXNAME
    (128). A stub can read that record only if the record comes back to it, and it does not:

    - cocuyo never sets the DO bit. A server must not return DNSSEC records to a query with DO
      clear (RFC 3225 §3).
    - A recursive server sets DO on its own queries, and removes the authenticating DNSSEC
      records from its answer to a query with DO clear (RFC 4035 §3.2.1). The NSEC goes with them.
    - RFC 9824 §5 lets a resolver change NOERROR to NXDOMAIN for a querier that did not set DO.
      That change is the recursive server's to make, since it sees the NSEC and the stub does not.

    So a lookup of such a name ends `NoData`, and the cache keeps a NODATA entry with the SOA's
    TTL (§18). `AddressLookup` does not cancel the other family, as its rule 4 does for
    `NameNotFound` (§19 step 14). A recursive server that applies RFC 9824 §5 gives NXDOMAIN, and
    the lookup then ends `NameNotFound`, as for any server.

    Rejected:

    - cocuyo reads an NSEC whose bitmap holds NXNAME as a name error, without validation. Only a
      server that breaks RFC 3225 §3 would return that record, so the code would never run against
      a server that keeps the RFCs.
    - cocuyo sets DO, then reads NXNAME. This reverses the rule that cocuyo never sets DO
      (`flag_dnssec_ok`, `src/wire/edns.zig`). Answers grow by their RRSIG records, which the
      codec must skip, and more of them come truncated, which moves lookups to TCP. DNSSEC stays
      out of scope (§17 question 16).
    - cocuyo also sends the CO flag of RFC 9824 §5.1. That flag applies to a query with DO set,
      and cocuyo never sets DO.

    §18, §19 step 14, §17 question 16.

60. **The cache keeps a resolution failure, with a backoff to five minutes.** Ruled by the owner on
    2026-10-27 for c4milo/cocuyo#51. "Resolvers MUST implement a cache for resolution failures"
    (RFC 9520 §3.2), and RFC 9520 §2 names a stub with several servers as a resolver it covers.
    The cache module keeps the entry, under the key of its other entries, in a slot of the table
    the caller sizes (decision 37). `src/resolver` does not change, and a consumer without the
    cache gets no failure cache. The rest of this entry is the record that RFC 9520 §3.2 asks for:
    "Developers should document their implementation choices".

    What the cache keeps, `Cache.put_failure`:

    - The errors that are resolution failures, `cache.resolution_failure`: `Timeout`,
      `AllServersFailed`, and the server errors that `check_response` off takes as the end,
      `ServerFailure`, `Refused`, `NotImplemented` and `FormatError`. In each, no server gave a
      useful response (RFC 9520 §2, §2.1, §2.2, §2.3, §2.7).
    - `ChainTooLong` too. The chain bound is how a lookup sees an alias loop, which RFC 9520 §2.5
      names. The answer holds no data of the type asked for, so no server gave a useful response.
    - Not `NameNotFound` or `NoData`. They are useful responses, which `put_negative` keeps for the
      SOA's TTL (RFC 9520 §2, RFC 2308 §5).
    - Not `NameTooLong`, by cocuyo's choice: RFC 9520 §2 does not name YXDOMAIN. A lookup ends
      with it at YXDOMAIN, and a server that says YXDOMAIN answered. No RFC gives it a time
      (decision 57). A name too long to ask ends before any query, and an entry saves nothing.
    - Not `Canceled`. The caller ended the lookup, and no server failed.
    - Not `NoServers`. No server was asked. The configuration is the cause, and an entry would
      hide a configuration that the caller then corrects.
    - Not a codec error. A malformed response moves the lookup to the next server, so the end is
      `Timeout` or `AllServersFailed`.

    The time of an entry:

    - The first failure of a name is kept for `Cache.failure_seconds_min`: 5 s by default
      (`constants.failure_seconds_min_default`), and 1 s to 300 s (`limits.failure_seconds_least`
      and `limits.failure_seconds_max`). RFC 9520 §3.2 asks for at least 1 s, at most 5 minutes,
      and a minimum that the operator can set. The operator sets it in
      `Config.cache_failure_seconds_min`.
    - Each later failure of the same name after the entry expired doubles the time, up to 300 s
      (RFC 9520 §3.2, the exponential backoff). A failure while the entry is live changes nothing:
      a lookup that started before the entry ends after it, and only a failure after the expiry
      is a new try.
    - The cache's TTL cap, `ttl_seconds_max`, also caps a failure, as it caps every entry. A cap
      under the minimum keeps a failure for the cap, which is 1 s at least.

    Where the minimum is set: the cache takes no options struct, and `Cache.init` keeps its
    signature (decision 37). `Config` already carries the cache's cap, `cache_ttl_seconds_max`,
    so it carries the minimum too, as `cache_failure_seconds_min`, and `assert_valid` holds it to
    1 s to 300 s. The engine copies it to `Cache.failure_seconds_min` at `init` and at each
    `reinit`. A caller with a cache of its own copies it after `Cache.init`.
    `failure_seconds_min_valid` says what a reader of a configuration file must refuse, and
    `put_failure` asserts it. The bounds and the default are in `core`, since `Config` and the
    cache both read them. `cache.limits` and `cache.constants` name them again, as the cap's
    default is named (decision 37).

    The slot keeps the failure as a four-bit `Failure` and its count in four more bits, one octet
    in padding the slot had, so a slot stays 2,984 octets. The count stops at 9, from 1 s.

    How the backoff is remembered: an expired failure entry stays in its slot, with its count of
    doublings, as an expired answer stays (§17 question 14). The next failure renews it in place
    and doubles its time. An answer or a negative answer for the name replaces the entry and so
    ends the backoff. A put that the cache refuses, a TTL of zero or a truncated answer, is still
    an answer: it evicts the failure entry, and the next failure starts at the minimum again. A
    failure does not replace a live answer or a live negative, since each is a useful response.

    Eviction: SIEVE treats a failure entry as any other entry (§18). A hit sets its visited bit.
    The hand evicts it on sight once it expired, and its count goes with it. So a name whose
    failure entry the hand took starts at the minimum again. That is the cost of the bound.

    Resource exhaustion: "resolvers SHOULD implement measures to mitigate resource exhaustion
    attacks on the failed resolution cache" (RFC 9520 §3.2). The table is bounded already. A
    failure entry takes one slot of the caller's count, the probe is bounded by `probe_max`, a
    `get` or a `put_failure` does a bounded amount of work, and the hash is keyed by the caller's
    seed. A peer that makes many names fail can push answers out of the table, as a peer that
    makes many names resolve can.

    A hit: `get` returns `Outcome.failed`, with the error in `Hit.failure` and the time left in
    `ttl_seconds`. The caller ends its lookup with that error, and sends no query: "the resolver
    MUST NOT send any corresponding outgoing queries until after the cache entries expire"
    (RFC 9520 §3.2).

    The engine in `io/` did not use failure entries at first. It reaches its cache through the
    table's `Memory` (§20), and `Remembered` carried RFC 2308's two negatives alone. That
    interface is in `src/resolver`, which the ruling kept as it was. `remembered_by` recalled a
    failure entry as a miss, since `Remembered` could not carry it. §17 question 85 asked the
    owner, who ruled on 2026-10-28 for a variant `failed` of `Remembered`, in a change of its own.
    Decision 61 builds it.

    Rejected:

    - A server time-out in `Servers`, by address, which RFC 9520 §3.2 offers as an example. It
      changes `src/resolver`, which the ruling keeps as it is, and it keeps a server out of every
      name, not one name out of every server.
    - The minimum as a field of `Cache` alone, which a caller sets after `init`. The operator
      could not set it through `Config`, where the cap already is, and RFC 9520 §3.2 asks that
      the operator can set it.
    - A separate table or a quota for failure entries. It is one more piece of memory and one more
      field to size, and the shared table is bounded already.
    - An entry that keeps its count after the hand takes it. The count needs a slot, and a slot
      kept after it expired is a slot that a live answer cannot use.
    - A linear backoff, which RFC 9520 §3.2 also allows. Doubling from 5 s reaches the 5-minute bound at
      the seventh failure, so a name that stays down costs few queries.
    - Out of scope, by the ruling: a failure cache in `src/resolver` for a consumer without the
      cache.

    §17 question 85, §18, §20.

61. **The table recalls a resolution failure through its memory.** Ruled by the owner on
    2026-10-28, on §17 question 85, the second way. Before it, an engine with a cache sent every
    try again for a name whose servers all failed. RFC 9520 §3.2 says that "the resolver MUST
    NOT send any corresponding outgoing queries until after the cache entries expire".

    What changed:

    - `Remembered` has a third variant, `failed`, which carries the error alone. A consumer that
      switches over `Remembered` adds the arm.
    - `remember_end` writes each resolution failure as `failed`. The errors are those that
      `cache.resolution_failure` counts (decision 60).
    - `recall_into` ends the lookup with the recalled error at its first poll. No query is built,
      and the poll returns `.failed`. The lookup does not write the failure back.
    - `remembered_by` maps `failed` to `Cache.put_failure` and a failed hit to `failed`. The
      cache sets the time of the entry and its backoff, as decision 60 says.
    - The engine does not change. It hands the table `remembered_by` already, so it gets the
      failure cache at once.

    Where the rule lives: `resolver` cannot read `cache` (§3), so `table_memory.zig` holds its own
    list, `resolution_failure`, beside `negative_of`. `src/cocuyo.zig` reads both modules. A test
    there requires the two lists to agree on each error of `core.Error`, and `remembered_by`
    asserts that each failure it gets is one the cache keeps.

    What a recalled failure carries: the error, `negative_ttl_seconds` of zero, `attempts_made` of
    zero and no cause. The memory keeps no cause, as for a recalled negative (§5, The cause of a
    failure). So a recalled `AllServersFailed` has no cause, which §5 did not allow before. §17
    question 89 asked the owner about that, and the owner ruled on 2026-10-28: as built.

    The models: the Lean model of §5 has no memory, and the replay never gives `Lookup` one. The
    TLA+ engine model holds no cache, and each walk of the replay asks a new name, so no walk
    reaches a failure entry. Neither model changes.

    Rejected:

    - The list of resolution failures in `core`, read by `cache` and `resolver`. It adds a public
      name to `core`, which the ruling does not cover. The test in `src/cocuyo.zig` keeps the two
      lists equal.
    - `remember_end` writes every failure but the two negatives, and the memory chooses. Each
      consumer's memory then holds the rule, which §20 rejected ("Leave the policy in each
      consumer").
    - `failed` with a TTL. The cache sets the time, and `Failure` has no field for a failure's
      time: `negative_ttl_seconds` is zero for every failure but the two negatives.
    - The first and the third ways of question 85, which the ruling did not take.

    §17 questions 85 and 89, §18, §20.

## 17. Questions for the owner

### Settled on 2026-09-21

1. **pepegrillo for the tooling.** Yes. Lint, the commit-message linter and the complexity scorer,
   pinned by hash as a lazy dependency, requested only when cocuyo is the root build, never linked
   into the library.
2. **`ptr_names_max` is 1.** A reverse lookup returns one name in practice, `Answer.truncated` says
   when more existed, and the slot drops from about 1064 bytes to about 824.
3. **`Resolver` ships in v1.** It is where the matching rules of §7 live, and it is what makes one
   socket with many lookups safe.

### Still open

4. **`addresses_max = 16`.** Unanswered, so it stands. Some large round-robin names return more,
   and `Answer.truncated` says so when they do. I have not measured it. Answered on 2026-10-17: it
   stands.
5. **TCP reuse.** Answered on 2026-09-22 by §19: the engine keeps one pipelined connection per
   server, and `connect_tcp` is unchanged.
6. **`/etc/hosts`.** Answered on 2026-09-22 by §19: a parser beside `resolv_conf.zig` in
   `config`, and the engine consults it first.
7. **Search-list order.** Answered on 2026-09-22 by measurement: §5 records glibc 2.39, musl
   1.2.5, c-ares 1.34.8 and cocuyo walking the same search lists on the wire. cocuyo walks as
   glibc and c-ares do, but for SERVFAIL, where it stops as c-ares does and glibc walks on.
   macOS's `getaddrinfo` is not in it: it reads no `resolv.conf` (§14), and changing its search
   domains takes an administrator.
8. **A second example.** Answered: `examples/udp_rotor.zig` drives the same lookup over rotor's
   completion-based loop, cleared by the owner on 2026-09-22 as a dependency of that example
   alone. It is lazy, `zig build graph-check` still shows cocuyo's own modules cannot name it, and
   rotor must never depend on cocuyo. It is pinned by commit and content hash, which became
   possible when rotor went public on 2026-09-22: Zig's fetcher speaks the git protocol
   anonymously, so a private repository cannot be pinned that way at all.

9. **Does version one need a cache after all?** Answered on 2026-09-22: yes, and §18 is its
   design. c-ares caches by default and has since 1.31.0 (§1), so a consumer replacing it would
   otherwise lose that. What c-ares does, read from `src/lib/ares_qcache.c` that day, and what
   §18 keeps and drops of it, is recorded there.
10. **The limits §19 proposes.** `rdata_bytes_max` at 2048 and `tcp_idle_ns_default` at ten
    seconds are chosen, not measured, and stand unless overruled; the table in §19 says why each.
    Answered on 2026-10-17: both stand.
11. **Service names.** §19 leaves `/etc/services` to the consumer, so `AddressLookup` takes no
    port and the reverse recipe returns no service. If a consumer needs `getservbyname`, a
    parser in `config` is the place. Answered on 2026-10-17: as written. The consumer keeps
    `/etc/services`.
12. **Does `name_info` need an entry point?** Answered on 2026-09-22: yes. `NameLookup` sits
    beside `AddressLookup`, because the recipe left the `lookups` order to every consumer that
    wrote it out, and that order is configuration the library already holds.
13. **Should the cache keep the chain end?** Answered on 2026-09-22: yes. A cache keyed by the
    question that stored only the answers lost the canonical name of any answer reached through
    a CNAME, so `AddressLookup`'s `canonical_name` came back filled from a lookup that went out
    and empty from one the cache answered; per §18's reading, c-ares keeps the whole response,
    chain included. The slot now keeps the chain's end: one `Name`, 256 octets, 2728 to 2984 a
    slot, and a thousand slots cost 2.9 MiB where they cost 2.7.
14. **Should a get renew an expired entry in place?** Answered on 2026-09-22: yes. A get that
    found its entry expired evicted it, and the put after the miss inserted the name as new, at
    the newest end. The get now misses and leaves the entry, and the put renews it where it
    stands. On the synthetic trace that is 3.0 points more hits at 1024 slots and
    1.0 fewer at 4096 (§18). An expired entry holds its slot until its name is asked again or
    the hand meets it. The public surface is unchanged.
15. **Should a port be replaced under load?** Answered on 2026-09-23: yes. A port that had
    carried `udp_queries_per_port` queries was replaced only once no lookup waited on its
    server, so under steady load it was never replaced, and the setting did nothing when it
    mattered most; the engine model showed nothing made a retiring port rotate. Now a new socket
    takes every query at once and the old one drains, as c-ares does as recalled rather than
    read (§19 step 13, the datagram's rule 4). A server holds two sockets at most while one
    drains.

### Asked on 2026-10-03, for DNSSEC

§25 is a plan with no ruling behind it. These are the rulings it needs. Each says what the plan
recommends, and none is taken until the owner answers.

16. **Does DNSSEC come into scope, and how far?** §1 says no validation, and CLAUDE.md lists it
    under "Ask before". §25 has two stages: A relies on the server's AD bit over a channel that
    authenticates the server, and B validates in cocuyo. Recommended: A, then B, each off by
    default. Answered on 2026-10-17: not now. DNSSEC stays out of scope, and §25 stays a plan.
    Questions 17 to 20, 22 and 23 wait for a later answer to this one.
17. **Stage A's public API.** `Config.authenticated_data`, the type `Security`, a `security`
    field on `Answer` and on `Failure`, and `options trust-ad` read from a `resolv.conf`.
    Recommended as §25 writes them, with one type for both stages.
18. **Should `Failure` carry the extended error code?** Under Stage A a server reports bogus
    data as SERVFAIL, and the extended error option says why (RFC 8914). The codec reads the
    option, and `Failure` does not carry it. Recommended: yes, as one optional field.
19. **Stage B's shape.** A validator the table is handed, keys fetched under the table, and a
    question asked again when its keys have come, in place of a response kept. §25 ends with
    the decision in §16's form and what it would reject. It adds a state to §5, a module to §2,
    and `Error.Bogus`.
20. **Trust anchors.** Recommended: the caller supplies every anchor, and `src/` ships none,
    since a root key that changes would make a release of cocuyo expire. The engine's example
    and the live check read IANA's file (RFC 9718). And which anchor a name under two of them
    uses: the closest (RFC 6840 Appendix C.1), which the walk does, or any that succeeds (C.2),
    which §5.10 suggests.
21. **Whose cryptography.** Answered on 2026-10-03: chapulin's, for all of it (§16 decision 35).
    `dnssec` names a verifier, and a module outside `src/` fills it in from chapulin through
    colibri's `tls`. Still to settle is what chapulin gains and who adds it, which §25 lists:
    public calls, SHA-1, RSA over SHA-512, RSA keys it refuses today, and Ed25519, asked of
    chapulin in c4milo/chapulin#189. §25's count of 2026-10-03 gives the order and the bounds:
    RSA from 1024 bits, with the key's own exponent. Ed448 is in neither library, and no
    top-level domain signs with it. Recommended: left unsupported, so a zone signed with it
    alone is read as unsigned.
22. **SHA-1.** Algorithms 5 and 7 written, and off unless a configuration turns them on, which
    is how §25 reads RFC 9905 §2.
23. **The limits §25 proposes.** All are chosen, not measured, but those an RFC fixes or the
    count of 2026-10-03 bears out. Three are worth a word: `clock_skew_seconds_default` at
    zero, `nsec3_iterations_max` at 100, and `records_max` left at 64, which fails a lookup
    under a signed zone when a message holds more records than that.
24. **More sources.** May RFC 1982, RFC 3110, RFC 8017, RFC 8032, RFC 4470 and RFC 2181 be
    downloaded into `docs/rfcs/`? §25 step 1 names them, and `docs/rfcs/README.md` says what
    each is for. Answered on 2026-10-17: yes, all six. `docs/rfcs/` holds them, with their sums.
25. **What the reading found.** §25 ends with five things in the code as it stands that are not
    DNSSEC's: a citation, RCODE 6, `attempts_max` against RFC 9520 §3.1, no cache of failures
    against RFC 9520 §3.2, and compact denial without validation. Should each become an issue?
    Answered on 2026-10-17: yes, one issue each: c4milo/cocuyo#48 to c4milo/cocuyo#52.

### Asked on 2026-10-09, for the measured wait

26. **A server whose latency rises past its wait.** Answered on 2026-10-09: the first way. A
    try that ran out counts as a sample as long as the wait it used, from the send to the
    deadline, so the server's average rises with each silent try until its answers come in time
    again (§5, §16 decision 36). The question was that such a server gave no more samples once
    its latency rose past its wait, so its wait stayed where its old record left it until the
    table was built again. The second way, reading the window since the table was built only
    while a window with a span holds 3 samples and waiting `timeout_ns` otherwise, would have
    left the wait where it was until the server's day's window had passed. A connect that ran
    out, a failed send, a failed connection or handshake, a failed request and a lookup cancelled
    are still no sample, since none of them measured a wait for an answer.
27. **A try whose answer the lookup ignored.** A server that lowercases the name answers in
    time, and the lookup ignores the reply that marks it, so that try runs out and counts as a
    sample as long as its wait: 2 seconds for a server that answers in 10 ms, on a fresh table
    (§5, What the rule costs; §7). Should a try whose server was marked during it be no sample?
    The lookup knows when a reply marks its server, so this is one flag per try. Recommended:
    yes. The reply that marks it shows the server answered in time, so the try's wait says
    nothing of its latency. A server that changes the case another way is not marked, and stays
    sampled as one that never answers, which is what it is to every lookup that mixes the case.
    Answered on 2026-10-17: yes, no sample. Built on 2026-10-20: §5, §16 decision 50.
28. **A DoH or DoQ server that never completes the handshake.** The engine says a DoH or DoQ
    request went out before its connection's handshake ends (§24, request rule 3), so a try at
    a server that never answers the handshake runs out as a sent one and is a sample as long as
    its wait. Over TCP and DoT the same server holds the lookup in `connecting_tcp`, and a
    connect that ran out is no sample (§5, What the rule costs). Should a request whose
    connection never came up be no sample too? The lookup would need the engine to say when
    the handshake ended, a change to the request interface of §24. Recommended: no change. Each
    DoH and DoQ sample already carries the handshake of a connection the request opened,
    failover asks a server that does not answer last, and its wait rises to the cap as a silent
    server's does over UDP. Answered on 2026-10-17: no change.

### Asked on 2026-10-11, for the cache's memory

§16 decision 37 records the ruling and six choices the ruling did not cover. These are the
ones that touch the public surface, a limit or what a call does, which CLAUDE.md asks the owner
about.

29. **The sizing in the library.** `cocuyo.cache` gains `Slices`, `Storage`, `keys_for` and
    `slot_count_valid`, and the engine's `init` and `reinit` take a `?cocuyo.cache.Slices`.
    Should the names, or their place, be other than these? Recommended: as built. The rule is
    the cache's, and a caller of the library alone needs it too. Answered on 2026-10-17: as built.
30. **No upper bound on `Config.cache_ttl_seconds_max`.** Answered on 2026-10-11: follow the
    RFC. A cap is at most seven days, the cap RFC 8767 §4 recommends, under the named limit
    `cache_ttl_seconds_max`. `assert_valid` and `Cache.init` hold it (§16 decision 37).
31. **A cap of zero.** c-ares reads `qcache_max_ttl = 0` as the cache turned off, and cocuyo
    asserts against it: no memory is the way to turn the cache off. Should zero be taken, and
    mean off? Recommended: no, since it would be a second way that still holds the memory. What
    that costs a consumer: a zero read from its own configuration file is input, and it reaches
    `assert_valid` and stops the program unless the consumer turns it into no memory first. A
    slot count has `slot_count_valid` for that, and since the answer to question 30 the cap has
    `ttl_seconds_max_valid`, which refuses a zero and a cap past seven days. Answered on 2026-10-17:
    no. The assertion stays.
32. **`engine_cache_slots_default`.** It stays at 1,024, named, as the size the README and the
    examples hand an engine. Should it go, or move to the `cache` module's constants, where a
    caller of the library alone would find it? Recommended: as built, since the name and the
    place are the ones consumers already read. Answered on 2026-10-17: as built.
33. **What a `reinit` that fails at its sockets holds.** It holds the memory that call handed
    it, with that call's configuration and seed, until a later `reinit` or `close` (§19 step
    13, rule 5). So a caller that got memory for the call must not free it on the error. Should
    such a `reinit` leave the engine with no cache instead, so that it holds neither the old
    memory nor the new? Recommended: as built. The engine has taken the new configuration by
    then. A cache that follows the table is one rule, where a cache dropped on one path is
    two. Since 2026-10-14 a `reinit` refused with `UdpPayloadTooLarge` holds what it held before
    (§16 decision 44, question 49). Answered on 2026-10-17: as built.

### Asked on 2026-10-11, for the session a connection names

§16 decision 38 records the ruling. It left one question that touches the public surface.

34. **A module for the session over chapulin.** `cocuyo_quic` exports no session that protects
    anything. The one over chapulin is `io/io_chapulin_quic.zig`, which the package ships and
    no registered module names, so a consumer's build makes the module itself (§24, the session
    a connection names). A consumer the compiler stops for want of a session finds only `Plain`
    among the module's exports. Should the build register a module for the session, with its
    `quic` and `tls` imports left for the consumer to bind, as `cocuyo_doh`'s `client` and
    `tls` are? Recommended: yes, since it is the session every consumer on a network names.
    Not built: it adds a name to the public surface, which is the owner's to rule. Until then
    no check of the gate builds a consumer that makes the module, since `test/consumer/` binds
    no colibri. Answered on 2026-10-17: yes, register it. Built on 2026-10-20: the module is
    `chapulin_quic`, and `test/consumer/` builds a program over it (§16 decision 38, as amended).

### Asked on 2026-10-11, for the context a session starts from

§16 decision 39 records the ruling. It left one question that touches the public surface.

35. **`has_context`.** The engine gains one public function, the predicate `start` asserts:
    whether the transport its configuration speaks has its context. The ruling asked for the
    assertion and for no other change to the API. A predicate is what lets a test break the
    rule and see a test fail (CLAUDE.md non-negotiable 10), and it lets a consumer ask before
    its first lookup, where it could otherwise learn of a missing call only by stopping.
    Should it be public, and under this name? Recommended: as built. It was built before the
    owner answered, where question 34 left its name unbuilt, because the tests and the
    assertion need the predicate either way and only its being public is in question. If the
    answer is no, the method, the README's sentence and the doc comments' mentions of it go,
    `start` asserts `held` of `io/io_context.zig`, and the tests ask `held`: the mutation rows
    stand, since each edits `held` or what it reads. Answered on 2026-10-17: as built. It stays
    public under this name.

### Asked on 2026-10-13, for the constants with a type

§16 decision 40 records the ruling and this change's reading of it. Two questions stay open.

36. **The extension.** The ruling named four constants. This change gave a type to every integer
    constant of the constants files of `src/` and `io/`, and a lint rule holds it. Should the
    extension stand? Recommended: yes. The twin's two header constants had the fault the four
    had, and a list of four leaves the next such constant with no type. If the answer is no,
    the rule and its rows go, and each constant but the four loses its type again. Answered on
    2026-10-17: yes, the extension stands.
37. **The constants outside the constants files.** The lint rule, with its scope widened to every
    Zig file of `src/` and `io/`, reports 210 integer constants of the other files, test files
    apart. It reads their shape, so some of them have a type already, from a typed constant in
    their value. One of them, `frame_bytes` of `io/io_quic_plain.zig`, has no type and is in a
    sum that overflowed until 2026-10-10. Some are limits, which CLAUDE.md's non-negotiable 5
    puts in a constants file: `ndots_limit` of `src/config/resolv_conf_options.zig`, the bounds
    of `src/core/name_text.zig` and the code-point bounds of `io/io_doh_template.zig`. Should the
    rule read every Zig file of `src/` and `io/`, or should those constants move into the constants
    files? Recommended: move each limit into its module's constants file, as CLAUDE.md's
    non-negotiable 5 asks. Give the rest a type where they are. The 32 of
    `bench/end_to_end/constants.zig` are a third choice, since nothing of `bench/` is linked
    into the library. On 2026-10-13 two of the limits took that path: `ndots_limit` and
    `timeout_seconds_limit` moved into `src/config/constants.zig`, each with a type (§12). The
    rest of the question stays open. Answered on 2026-10-17: every limit moves into a `limits.zig`
    of its module, the limits of each `constants.zig` too. Each `constants.zig` keeps the protocol
    sizes and the defaults. Each constant that is not a limit gets a type where it is. CLAUDE.md's
    non-negotiable 5 and the lint rules change with it. Built on 2026-10-26 (§16 decision 56).

### Asked on 2026-10-13, for the stream's buffers

§16 decision 41 records the change. CLAUDE.md asks the owner before a named limit or the public
API changes. This change does both, and the owner has not ruled on it yet.

38. **Four named limits, and two public names.** `tls_record_in_bytes` grew from 16,645 to
    18,693 octets. A connection's frame grew by `tcp_frame_room_bytes`, 2,048 octets, or over TLS
    by `tls_frame_room_bytes`, 16,640. `tcp_messages_per_chunk_max` and
    `tls_records_per_chunk_max`, 32 each, gave way to `tcp_messages_per_frame_max` and
    `tls_records_per_buffer_max`, which follow from the buffers. The two old names were public in
    `cocuyo_rotor.constants`. Answered on 2026-10-13: the change stands. Without it a sound stream
    fails, or an answer in memory waits for its deadline (§19 step 13, the stream's rule 11; §21,
    TLS rule 7). The cost is 2,048 octets for each connection in the clear, and 18,688 for each
    connection over TLS.

### Asked on 2026-10-13, for the tests at the named limits

docs/mutations.md, Tests at the named limits, gives the tests behind each question.

39. **The slack of the drive's bound.** `drive_polls_per_lookup_max` is 81. A test gives one
    lookup the most polls that a run gives it in one drive: 49, at eight servers and five passes.
    That 49 is the most comes from a read of the drive. Should the bound be
    `servers_max * (attempts_max + 1) + 1`, 49? Recommended: no. The slack costs no poll that a
    run makes, and a bound that is exact breaks when the drive changes. Answered on 2026-10-14:
    no. The bound stays at 81, with its slack.
40. **A datagram longer than the room of a buffer.** A buffer of the datagram group holds 1,856
    octets. The kernel cuts a longer datagram and marks it as truncated, and the engine reads no
    such mark. The table reads the cut octets, the message fails a check, and the lookup waits out
    its try. Should the engine drop the datagram, or take it as truncated and ask over TCP?
    Recommended: take it as truncated once checks 1 to 5 of §7 pass, since its header and
    question are whole. Answered on 2026-10-14: as recommended. Once checks 1 to 5 pass, the
    lookup asks over TCP, as for an answer with TC set. A cut datagram that fails a check of §7 is
    ignored, as each such datagram is. §7 (A datagram that the buffer cut), §16 decision 43 and
    §19 step 13 (the datagram's rule 6) hold the rule. The review of the change added check 6, on
    a message with no COOKIE option, as RFC 7873 §5.3 asks (decision 43).
41. **The bound of a DoH request.** The comment of `doh_request_bytes_max` and §24 give the bound
    to the HEADERS frame of the GET, with 960 octets for the path. The code gives it to the path
    alone, 1,536 octets. A test sends the longest GET that the code allows, and colibri sends it
    over HTTP/2. Which is correct? Recommended: the code; then the comment and §24 change.
    Answered on 2026-10-14: the code. The bound is on the path, 1,536 octets. The comment of the
    constant and §24 now say so, and the code did not change.
42. **A template's slash.** `doh.template.expand` keeps the first octet of its output for a slash,
    also for a path that starts with one. So such a template gets one octet less of the buffer,
    and `start` refuses it at exactly 1,536 octets. Recommended: fix it, with the test that shows
    it. Answered on 2026-10-14: fix it. A path that starts with a slash now gets the whole buffer
    (§24, the path).
43. **`Options.lookups` over `lookup_slots_max`.** An engine of more lookups than the table holds
    compiles, then stops at an assertion in `init`. `tcp_connections` has a comptime check of its
    own. Recommended: give `lookups` one too. Answered on 2026-10-14: yes, with a message that
    names the limit. An engine of more lookups than `lookup_slots_max` now does not compile.
    Neither does an engine of none, which `init` refused at the same assertion (§19 step 13).
44. **The codec's fuzz target in the public API.** `cocuyo.wire.fuzz` is public, and grew. Its
    `Message` is 64 KiB, with `most` and `most_at`, and it has two strategies more and
    `strategy_of`. The codec's constants gained `fuzz_long_answers`. Recommended: keep it public,
    as `wire.fixtures` is, since the fuzz tool reads it. Answered on 2026-10-14: it stays public,
    as `wire.fixtures` is.
45. **CLAUDE.md's path to the target.** The target moved to `src/wire/fuzz/` by the layout rule.
    CLAUDE.md names `src/wire/fuzz.zig` under Commands. Recommended: name `src/wire/fuzz/` there.
    Answered on 2026-10-17: as recommended. CLAUDE.md names `src/wire/fuzz/`.

### Asked on 2026-10-14, for a datagram that the buffer cut

§16 decision 43 records the rule that the answer to question 40 gave. Its review asked these two.

46. **Two public entry points for a cut datagram.** Decision 43 adds `Lookup.on_datagram_cut` and
    `Resolver.on_datagram_cut` to the public API (§4). The answer to question 40 ruled on the
    behaviour, and not on this shape. CLAUDE.md asks the owner before the public API changes.
    Answered on 2026-10-14: keep the two. A flag on `on_datagram` changes every caller. A TC bit
    that the engine writes into the cut octets sends them to check 6. That check walks to the OPT
    record, which the cut took.
47. **A payload that the engine cannot receive.** `Config.udp_payload_bytes` may be up to 65,535
    octets, and a buffer of the engine's datagram group holds 1,856. RFC 6891 §6.2.3 says that a
    requestor "SHOULD place a value in this field that it can actually receive". Above 1,856, a
    server that obeys the query can send a datagram that the buffer cuts. Should the engine's
    `init` and `reinit` refuse such a configuration, with an error? Recommended: yes. Then only a
    forger or a broken server sends a cut datagram, and decision 43 still takes theirs. Answered
    on 2026-10-14: yes, with an error. `init` and `reinit` return `UdpPayloadTooLarge` for a
    configuration above `udp_payload_bytes_max`, 1,856 octets, and change nothing. §16 decision
    44 and §19 step 13 (the datagram's rule 7) hold the rule.

### Asked on 2026-10-14, for a payload that the engine cannot receive

§16 decision 44 records the rule that the answer to question 47 gave. The answer left three
choices to the build. Each changes the public API, so each is a question here.

48. **An error and a limit in the public API.** `cocuyo_rotor.InitError` gains
    `UdpPayloadTooLarge`. `cocuyo_rotor.constants` gains `udp_payload_bytes_max` and
    `group_options`. The answer to question 47 ruled on the error, and not on these names.
    CLAUDE.md asks the owner before the public API or a named limit changes. Recommended: keep
    the three. A caller that reads a size at run time compares it with the limit before `init`, as
    it checks a slot count with `cocuyo.cache.slot_count_valid`. Answered on 2026-10-14: keep the
    three.
49. **The memory after a refused `reinit`.** Until 2026-10-14, the memory that the engine held
    was the caller's once `reinit` returned, whatever it returned (§19 step 13, the cache's
    memory, rule 5). A `reinit` refused with `UdpPayloadTooLarge` changes nothing, so the engine
    keeps that memory. A consumer that frees the old memory on each error of `reinit` now frees
    memory that the engine still uses. The other choice keeps the old contract: a refused `reinit`
    keeps the configuration and lets go of the cache's memory. Then the refusal changes the
    engine. Recommended: as built. The error says that nothing changed, and rule 5, the doc
    comment of `reinit`, the README and §24 say so too. Answered on 2026-10-14: as built.
50. **The refusal over each transport.** The engine receives a server's datagram over plain UDP
    alone. A `use_tcp` configuration asks over TCP. A configuration of DoT, DoQ or DoH opens no
    UDP socket for a server. `init` and `reinit` still refuse such a configuration when its
    `udp_payload_bytes` passes the limit. Each query with EDNS carries that size over each
    transport. Should the check refuse only a configuration that asks over UDP? Recommended: as
    built. One check of the configuration is one rule. A size that the engine cannot receive over
    UDP is wrong in each query that carries it. Answered on 2026-10-14: as built.

### Asked on 2026-10-17, for the DoH channel's stream buffer

§16 decision 41 records the check of c4milo/cocuyo#44. It found two ways in which a sound stream
still ends the TCP link of a DoH channel.

51. **A KeyUpdate while the TCP link's send buffer is busy.** A server may send a KeyUpdate that
    asks for a reply at any time after its Finished (RFC 9846 §4.7.3). That section asks for the
    reply before the receiver's next Application Data record. colibri v0.6.0 also opens no record
    until its next `send` writes the reply (its `connection_tls.zig`). The RFC does not ask for
    that hold. It does not ask a receiver to stop its reads either.

    The engine asks the channel for octets only when the link's send buffer is free (§24, request
    rule 15). The buffer is busy in two cases:

    - A send is in flight.
    - The buffer holds octets not yet sent: the rest of a short send, or a send that the loop
      refused.

    Meanwhile each chunk after the KeyUpdate stays in the type's buffer. The held records open at
    the first read after `output`: the read after the next send ends, or after the next chunk.
    When more than 16,645 such octets wait, the next full chunk ends the link (request rule 7).
    The link's requests fail, and their lookups fail over. No size of the buffer bounds this,
    because the network sets how many chunks come before the send ends. The ways:

    - colibri writes the reply into its connection's output at once, and opens the records after
      the KeyUpdate. That output holds records before the protocol's octets already, for the
      handshake's flight. cocuyo then changes only its pin of colibri.
    - The type keeps a small buffer for what colibri owes. When a whole record waits, the type has
      colibri write into that buffer, and `output` hands it over first. This adds memory and a
      named limit.
    - The engine stops the TCP link's receive while the type holds a whole record that colibri
      does not take. This changes the DoH interface and the engine model.
    - The link ends, as now. A KeyUpdate is rare, and the send buffer is busy for a short time.

    Recommended: the first. The hold is colibri's, and colibri can remove it with no new memory.
    Answered on 2026-10-17: the first. colibri writes the reply at once, and cocuyo moves its pin.
    Done on 2026-10-20: colibri v0.8.0 opens records while the reply is owed, and writes the reply
    before its next record of data (its commit 5368f5b). cocuyo pins v0.8.0. No test of cocuyo's
    shows a KeyUpdate: chapulin's record mode starts none, so neither colibri's server nor its
    `tls` can send one. colibri's own tests show it, in `connection_records_test.zig` of its
    client and of its server, over a provider that protects nothing. One bound stays: colibri owes
    two replies at most (`tls.constants.key_update_replies_max`), and a third request ends the
    link. RFC 9846 §4.7.3 forbids a server that third request, because it asks for no second reply
    before the first has come (§16 decision 41).
52. **A long head or trailer section over HTTP/1.1.** colibri v0.6.0 reads a head or a trailer
    section only when it is whole. Its h11 accepts a head of up to 32,768 octets (`head_len_max`).
    Whitespace around a value and the reason phrase count in that length, and not in the size of
    the field section (RFC 9112 §4, §5.1). The room of a connection, `plaintext_in_len`, is 33,033
    octets: a frame of HTTP/2 at its longest, and one record more. colibri opens a record only
    into room for its body. So a long head holds the link:

    - When more than 16,632 octets of a head wait, no room is left for a record of 2^14 octets of
      plaintext. colibri then opens no more records, and the head never becomes whole.
    - The next chunks pass `doh_stream_bytes_max` and end the link (request rule 7). If no chunk
      comes, the request waits for its deadline. Either way its lookup fails over.
    - No size of the type's buffer helps, because colibri never takes the record.

    A probe showed the hold and the end of the link (docs/mutations.md, The DoH channel's stream
    buffer). The ways:

    - colibri sizes the room for h11's longest head and one record more: 32,768 and 16,640
      octets, 16,375 more than now in each connection. cocuyo then changes only its pin of
      colibri.
    - colibri's client refuses a head or a trailer section longer than its room holds beside a
      record. The request then fails at once, and not at the overrun or the deadline.
    - The link ends, as now. No measurement shows how often a DoH server sends a head that long.

    Recommended: the first. The hold is colibri's, and only colibri can remove it. Answered on
    2026-10-17: the first. colibri sizes its room for h11's longest head and one record more, and
    cocuyo moves its pin. Done on 2026-10-20: colibri v0.8.0 sizes the room at 49,407 octets (its
    decision 124, ruling 7), and cocuyo pins v0.8.0. A test of `io_doh_channel_read_test.zig` sends
    heads of 20,000 and 32,768 octets, whose records leave a long partial head before a full record.
    Each exchange ends with its answer, and on v0.6.0 the test fails (docs/mutations.md, colibri
    v0.8.0). A second test does the same with a trailer section of 24,000 octets, and a second
    response after it.

### Asked on 2026-10-17, for the cause of a failure

§16 decision 45 records the ruling of the day: a lookup that fails keeps the last cause a server
gave. The ruling approved a change to the public API, and did not name the field or its type.

53. **The name and the type of the cause.** As built, `Failure.cause: ?Cause`, where `Cause` is
    `union(enum) { rcode: wire.Rcode, connect, stream, request }`. It is null when no server
    failed the lookup (§5, The cause of a failure). `Failure` grows from 8 octets to 12. The
    ways:

    - As built. The rcode keeps the codec's type, and the three causes of a transport name the
      entry point and the state that gave them.
    - A flat enum: `server_failure`, `refused`, `not_implemented`, `bad_vers`, `format_error`,
      `bad_cookie`, `connect`, `stream` and `request`. Each value can come, but five codes get
      a second name beside `wire.Rcode`.
    - The cause with the server that gave it: `struct { server_index: u8, kind: Cause }`.
      `Failure.server_index` names the server that the lookup was on at its end, which after
      the last pass is the first of the order. One octet more fits in the padding, and
      `Failure` stays at 12 octets.
    - Another name for the field: `reason`, or `last_failure`.

    Recommended: as built. The server is the first addition to make if a failure with many
    servers needs it. Answered on 2026-10-18: add the server, in the shape the design finds best,
    in the padding of `Failure`. Built on 2026-10-21 as `struct { server_index: u8, what: What }`,
    and `Failure` stays at 12 octets (§16 decision 51).
54. **A reason from the caller.** The lookup cannot tell a connect that failed from a TLS
    handshake that failed: `on_tcp_failed` carries no reason, and both are `connect`. Three
    local failures are `connect` too, and no server took part in them:

    - a socket that the system refused;
    - no free connection slot, which since 2026-10-18 means each slot held by a lookup, in the
      clear alone;
    - an engine that keeps no TCP connection.

    The last cause wins, so a local failure on a later pass replaces the cause that a server
    gave before it. Until 2026-10-18 the second pass over TLS could find no free slot while the
    connection of the first pass still closed. Since then it waits for that slot (§16 decision 46).
    Over DoH and DoQ every failure is `request`. A parameter on `on_tcp_failed` and on
    `on_request_failed` would let the engine name each failure:

    - a connect, a handshake or a local failure;
    - a connection that failed after it was up, or a send on it;
    - an HTTP status, or a stream that the server reset.

    §16 decision 25 counted that parameter against an alternative that it rejected. Its words
    are "a second change to the API in a call every consumer that owns its sockets makes". The
    ways:

    - As built: the lookup reads the cause from its own state, and no entry point changes.
    - A reason on each of the two calls, which the engine sets at each of its failures, and
      which `Cause` reports in place of `connect`, `stream` and `request`.
    - A reason that the engine keeps beside its result, outside `Failure`. A consumer that owns
      its sockets has the reason already.

    Recommended: as built until a live failure needs more. The DoT check then tells a
    connection that never came up from one that failed under the lookup, and both from a
    server's rcode. Answered on 2026-10-18: a reason on each of the two calls. The engine sets it
    at each of its failures, and a consumer that owns its sockets passes it too. Built on
    2026-10-21 with six reasons (§5, The cause of a failure; §16 decision 51).

### Asked on 2026-10-18, for a connection slot

§16 decision 46 records the ruling of the day: fix the engine's defect now. A lookup with no free
slot waits for one that frees with no lookup leaving it (§19 step 13, the stream's rule 12). The
review of the change found that nothing bounds how long such a slot takes.

55. **A time bound on a connection that closes.** A TLS connection that closes frees its slot at
    the end of its last send, its alert or its `close_notify` (§21, TLS rules 4 and 5). The idle
    close passes over it. Take a peer that stops reading and keeps its side open. Its send never
    ends, so the slot never frees. Each lookup that waits for that slot waits until its deadline.
    Each later connection to that server takes another slot, so in time the server can hold each
    slot. Until 2026-10-18 such lookups failed at once with `connect`. Neither is a break of
    safety, and each wait has its deadline. The ways:

    - As built: the slot frees at the end of the send, or when the peer closes.
    - A new named limit, `tcp_closing_ns`: the drive shuts a connection that has closed for that
      long. The shut cancels the send, and the slot frees at the cancel's event (TLS rule 3).
    - The idle close's wait, `tcp_idle_ns`, as that bound, with no new limit.

    Recommended: the idle close's wait. No lookup is on a connection that closes, and the session
    has said its last record. So the connection is idle, and the idle close's wait fits it. A
    second limit beside it is one more number for a caller to size.

    Answered on 2026-10-20: the idle close's wait, `tcp_idle_ns`, bounds a connection that closes,
    with no new limit. Built on 2026-10-20: §16 decision 49.

### Asked on 2026-10-20, for colibri v0.8.0

The owner ruled on 2026-10-20 that cocuyo moves its pin of colibri from v0.6.0 to v0.8.0. §16
decisions 29, 32, 33 and 41 record what the move changed.

56. **What a session states of the CPU.** Each TLS value of colibri v0.8.0 takes `cpu`, which has
    no default (colibri's decision 97, as amended for chapulin 0.2.0). It holds what the program's
    one probe found of the CPU, and the timing mode of the thread that drives the session. A
    session runs the AES instructions only where the probe found them and the program states
    `data_independent`. Otherwise it offers TLS_CHACHA20_POLY1305_SHA256 alone, and runs the
    portable multiply. Only the program knows its thread's mode, so the engine cannot state it.

    As built, the DoT, DoQ and DoH sessions state nothing. RFC 9846 §9.1 asks a TLS-compliant
    application to implement TLS_AES_128_GCM_SHA256. It makes TLS_CHACHA20_POLY1305_SHA256 a
    SHOULD, so a server that holds only the first refuses each handshake. The spike of 2026-09-24
    found that each server it tried took ChaCha20-Poly1305. The ways:

    - As built: the sessions state nothing. No public API changes. Each server must take
      ChaCha20-Poly1305, and each handshake runs the portable multiply.
    - A `tls.Cpu` in each context. The `init` of the DoT, DoQ and DoH contexts takes one more
      argument. The consumer fills it from stdx's `platform.probe()` and its word on the timing
      mode. This changes the public API. A consumer that states nothing passes the value of the
      first way.
    - cocuyo probes the CPU itself, through stdx's `platform`. This adds a dependency and a system
      call in `io/`, and the engine still cannot state the timing mode.

    Recommended: the second. The consumer is the program that probes the CPU and knows its
    thread's mode, as colibri's guide asks of a program. Until the owner rules, the first.

    Answered on 2026-10-20: the second. The `init` of the DoT, DoQ and DoH contexts takes a
    `tls.Cpu`, which the consumer fills. The change that builds it follows the pin. Built on
    2026-10-20: §16 decision 48. The examples state nothing, and question 58 asks about them.
57. **The QUIC version a session names.** Since colibri v0.8.0 a DoQ connection may run on QUIC
    version 2, and its ticket then names version 2 (§16 decision 29). A session that resumes with
    that ticket starts in version 2. colibri seals each packet in the connection's version, and
    chapulin asserts that the two versions agree. With the connection in version 1, the first
    send stops the program.

    So `cocuyo_quic`'s `Options.Session` gains a call, `original_version`, and the connection starts
    in what it returns (§24, the session a connection names). The session of
    `io/io_chapulin_quic.zig` returns colibri's choice, and `Plain` returns version 1. A consumer's
    own session must now add the call. The ways:

    - As built: the call is part of the interface, and a session that lacks it does not compile.
    - The call is optional, and a session that lacks it starts in version 1. Such a session
      still stops the program when it resumes with a ticket of version 2.
    - No new call: the session refuses a ticket whose version is not 1, and starts without it.
      Then no DoQ connection resumes with a server that switched it to version 2.

    Recommended: as built. The compiler finds each session that lacks the call, and resumption
    still works on version 2.
    Answered on 2026-10-20: as built.

### Asked on 2026-10-20, for the CPU a session states

§16 decision 48 records the ruling of the day: each context carries a `tls.Cpu`, which the
consumer fills. The examples do not fill it from a probe, and the sessions name its type.

58. **What the examples state of the CPU.** `examples/dot_rotor.zig`, `doq_rotor.zig` and
    `doh_rotor.zig` state nothing: `not_known` for each answer of the probe, and `not_stated` for
    the timing. The probe colibri names is stdx's `platform`, and no build of cocuyo depends on
    stdx. colibri does not export `platform` (its decision 97, as amended on 2026-09-30), and
    chapulin probes nothing (its `cpu_cfg.h`).

    So each hello of an example offers TLS_CHACHA20_POLY1305_SHA256 alone. The live checks and
    the interop check run the examples. So no check against a server that cocuyo did not write
    runs AES-GCM. The ways:

    - As built: the examples state nothing.
    - stdx as a ruled dependency of the examples alone, never linked into the library. Each
      example probes once, at its start. On arm64 it sets PSTATE.DIT where the probe finds
      FEAT_DIT, and then states `data_independent`. Elsewhere it states nothing. A server then
      picks from three suites, and no check is sure to reach ChaCha20-Poly1305.
    - As the second way, with a word on each example's command line that turns the statement on.
      Each live check and the interop check then run each server twice, once with each value. So
      each check makes twice as many handshakes.
    - No dependency: each example probes the CPU itself, as stdx's `platform` does. On arm64 it
      reads FEAT_AES, FEAT_PMULL and FEAT_DIT: with `sysctlbyname` on macOS, and from the
      AT_HWCAP word on Linux. It sets PSTATE.DIT itself, with Arm's `MSR DIT, #1`. On x86-64 it
      states nothing, since no program can read DOITM. The cost is a second probe, which must
      stay the same as stdx's. A consumer that copies an example copies that probe too.

    The second way and the third are not what colibri's test programs do (its
    `src/testing/cpu.zig`). Those state `data_independent` on each arm64 and x86-64 core, with
    FEAT_DIT or without it. Their header says that a program for real peers must not do this. So
    colibri's test programs are no model for an example.

    Recommended: the third. The checks then reach AES-GCM, the suite that RFC 9846 §9.1 says each
    application MUST implement. They still reach ChaCha20-Poly1305 too. Until the owner rules, the
    first.

    Answered on 2026-10-20: the third. stdx is a ruled dependency of the examples alone, and the
    word `cpu` turns the statement on. Each live check and the interop check run each server
    twice. Built on 2026-10-20: §16 decision 48, as amended.
59. **The name a DoT or DoQ consumer gives the type.** The sessions of `io/io_chapulin.zig` and
    `io/io_chapulin_quic.zig` export `Session.Cpu`, which is colibri's `tls.Cpu`. Each already
    exports `Session.Anchor`, which is `tls.Anchor`. So a consumer that copies an example names
    each type through the session, and its root module needs no `tls` import.

    The owner's ruling names the argument, not this name. The DoH channel exports neither name,
    and its consumer names `tls.Cpu`. The ways:

    - As built: `Session.Cpu`, beside `Session.Anchor`.
    - No new name. A DoT or DoQ consumer imports colibri's `tls` in its root module, and names
      `tls.Cpu`. The examples' builds add that import.

    Recommended: the first. It is the form `Session.Anchor` already has. Until the owner rules, the
    first.

    Answered on 2026-10-20: as built. `Session.Cpu` stays, beside `Session.Anchor`.

### Asked on 2026-10-21, for a send that never ends

The review of §16 decision 49 found two more waits that no time bounds. Each is older than the
decision, and outside question 55. Each needs a peer that stops reading and keeps its side open.

60. **A query's send that never ends.** A lookup in `tcp_ready` waits for the event of its query's
    send (§5). That state does not wait for an instant, so no deadline ends it (`is_waiting`). The
    lookup stays on its connection, so the idle close passes over the connection. Over TLS such a
    lookup also holds the server's slot. The caller's `cancel` still ends it.

    A test of the review stalled the peer before the query went, in the clear. After 18 minutes of
    the twin's clock the lookup was still in `tcp_ready`. The ways:

    - As built: the lookup waits until its send ends, or until the caller cancels it.
    - `tcp_ready` waits for the deadline too, as `awaiting_tcp` does. At the deadline the lookup
      moves on, and leaves its connection (the stream's rule 3). The connection then has no
      lookup, and the idle close shuts it, which cancels the send (decision 49). This changes §5's
      table, the Lean model of the lookup and the engine model.
    - The engine fails a connection whose query's send has not ended at that lookup's deadline.
      §5 does not change, and each lookup on the connection hears the failure.

    Recommended: the second. The deadline bounds each other state that waits on a server, and the
    connection then ends as decision 49 ends an idle one. Until the owner rules, as built.
    Answered on 2026-10-21: the second way. Built on 2026-10-24: §5, §16 decision 52. The test of
    the review now ends at the lookup's deadline, and the idle close shuts the connection.
61. **A DoH link whose send never ends.** The send of a channel's TCP link keeps no handle, so
    neither the link's `shut` nor its `cancel_all` can cancel it (`io/io_channel_link.zig`). A link
    that closes waits for that send to end (§24, request rule 19). A new opening of the link sends
    nothing until an earlier opening's send has ended. So a peer that stops reading may hold each
    later request to that server until its deadline. After `deinit` the loop may not drain.

    The review read this path, and no test shows it yet. The ways:

    - As built.
    - The rule of decision 49 for a link. The link keeps its send's handle, and each way that ends
      the link cancels the send. `quic_idle_ns` bounds a link that closes, as `tcp_idle_ns` bounds
      a connection (request rule 24).

    Recommended: the second, with a test on the twin first. It is the same wait, and the same rule
    bounds it. Until the owner rules, as built.

    Answered on 2026-10-21: the second way, with a test on the twin first. Built on 2026-10-26:
    §16 decision 55, and request rules 19 and 24. The tests on the twin failed first. A link that
    closed stayed closing for ever, and a new opening sent nothing. A later request to that server
    was not sent before its deadline, and the loop did not drain. Questions 74 and 75 ask about
    two choices of the build.

### Asked on 2026-10-20, for a try whose server was marked

§16 decision 50 builds the answer to question 27: a try that a reply to it marked is no sample.
The ruling did not make two of the choices that decision 50 makes.

62. **A mark that another lookup makes during a try.** The ruling says that a try whose server was
    marked during it is no sample. As built, only a reply to the try marks the try. So a try whose
    own reply never comes is a sample, even when another lookup marked the server during its
    wait. The ways:

    - As built: the try's own reply marks it. A try with no reply of its own is a sample as long
      as its wait.
    - The mark of the table, read at the deadline. A try whose query mixed the case, and whose
      server is marked when it runs out, is no sample. This needs no flag. It takes the sample
      from a try whose reply was lost, and nothing shows that the server answered that try. A
      table built again during the wait holds no mark, so a try that its reply marked is a
      sample again.

    Recommended: as built. The question asked for one flag per try, and the ruling's reason is
    the reply that shows the server answered in time. A try with no reply shows nothing of the
    kind. Until the owner rules, as built. Answered on 2026-10-20: as built.
63. **The failure of a marked try.** As built, a marked try that runs out counts a failure of its
    server, as each try that runs out does. Failover takes a response that the lookup ignores as
    never received (§19 step 12), and the ruling was on the sample alone. With two servers or
    more, the next lookups ask the marked server after each server with fewer failures. A retry
    of failover gives it the first place again, and its answer then clears the count (§16
    decision 17). The ways:

    - As built: the failure counts. The lookup could not take the reply, so it waited out the
      try as for a server that did not answer.
    - No failure for a marked try. The server answered in time, so its deadline counts neither a
      sample nor a failure. This is a second exception to decision 10, and a change to failover.

    Recommended: as built. Once marked, the server is asked in lowercase, and its answers come
    in time. So only the tries in flight to it at the mark count this failure. Until the owner
    rules, as built. Answered on 2026-10-20: as built.

### Asked on 2026-10-20, for the session module

§16 decision 38, as amended, records the ruling on question 34. The change left two questions.

64. **A module for the DoT session.** The DoT session over chapulin, `io/io_chapulin.zig`, has
    the shape that the DoQ session had before question 34. The package ships the file, and no
    registered module names it, so a consumer's build makes the module itself, as
    `build/dot.zig` does. The module imports `cocuyo` and `chapulin_hooks`, colibri's `tls` and
    `tls_provider`, and `io`, the engine whose limits it reads. Should the build register it too,
    as `chapulin`? Its `io` would then be `cocuyo_rotor`, and colibri's two modules would be left
    for the consumer to bind.

    Recommended: yes, for the reason question 34 gave. Not built: it adds a name to the public
    surface, which is the owner's to rule, and question 34 named the DoQ session alone. Answered
    on 2026-10-20: yes, register it. Built on 2026-10-24: the module is `chapulin`, and
    `test/consumer/` builds a program over it (§16 decision 38, as amended for this question).
65. **colibri in the consumer fixture.** `test/consumer/` depends on colibri since question 34
    was built, so that the gate builds a consumer of `chapulin_quic`. The check fetches nothing
    more, since the root build fetches colibri, chapulin and stdx for its own tests. But it
    compiles colibri's `quic` and `tls`, and chapulin's objects, a second time.

    Measured on 2026-10-20 on an Apple M1 Pro, one build of the package with its cache empty
    took 33 seconds before the change. After the change the same build took 61 to 63 seconds.
    With the cache full the whole check takes 2 seconds. The ways:

    - As built: the fixture depends on colibri, and the gate builds `doq`.
    - The fixture as before, with no colibri. No check of the gate then builds a consumer of the
      session, and the registration can break while the gate passes.

    Recommended: the first. Row SM1 removes the registration, and only the build of `doq`
    catches it. Until the owner rules, the first. Answered on 2026-10-21: the first. The owner
    asked why a fixture needs colibri. It needs colibri's `quic` and `tls`, which a consumer of
    `chapulin_quic` binds, and not colibri's HTTP client.

### Asked on 2026-10-21, for the reason of a failure

§16 decision 51 builds the answers to questions 53 and 54. Its review found two paths of the engine
that no run reaches, and one change to an exported module that the approval did not name.

66. **Two failures that no drive reaches.** Each path is older than decision 51, and each now
    gives `closed`:

    - `send` in `io/io_tcp_queue.zig`: a lookup ready to send on a connection that is not up. A
      lookup is in `tcp_ready` only after `on_tcp_connected`. A connection that fails fails each
      lookup on it at once. So a drive never finds such a lookup, and the test of row RS28 makes
      one by hand.
    - `seal` in `io/io_tls.zig`: a query with no room in the records buffer. A query is sealed
      when nothing else is sealed and no send is in flight, so the whole buffer is room. The
      handshake needed more room than a query does. No test reaches it, so row RS41 is gone.

    Non-negotiable 3 keeps assertions for programmer error. The ways:

    - As built: each is a check, and the connection fails with `closed`.
    - Each is an assertion. A drive that reaches one stops, as for any other programmer error.
      The TLA+ model of the engine is read first, and it changes first if it holds either path.

    Recommended: the second, since each path is a programmer error if the reading holds. Until
    the owner rules, as built. Answered on 2026-10-24: assertions. Built the same day:

    - The engine model asserts that a lookup ready to send finds its connection up, where `Send`
      puts the query on the stream. TLC held it over the five configurations of a stream that
      `zig build tla` checks, with the state counts of before. The model had failed such a
      lookup with `tcpFailed` before.
    - `send` asserts that the lookup is on the stream and that its connection is up. The test of
      row RS28 made the state by hand, and is gone with the row.
    - `seal` asserts that nothing sealed is left in the records buffer, and that `take_out` found
      room. A query that the session cannot seal still fails the connection with `closed`.
    - The doc comment beside each assertion gives the reason that the state is unreachable.
67. **The end of an exchange in the DoH interface.** The engine's DoH type tells the reason of an
    exchange that ends without an answer (decision 51). As built, `Finished` is `struct { index:
    u16, outcome: Outcome }`, and `Outcome` is `union(enum) { answer: Answer, failed: Reason }`.
    `cocuyo_doh` is an exported module, and a consumer that writes a DoH type of its own writes
    this shape. The twin's `sim.Channel` has it too. The ways:

    - As built: one field holds the answer or the reason.
    - `answer: ?Answer` as before, and `reason: Reason` beside it, read when `answer` is null. Two
      fields then hold one fact, and a reason beside an answer means nothing.

    Recommended: as built. Until the owner rules, as built. Answered on 2026-10-24: as built, but
    with the word `result` in place of `outcome`. Built the same day: `Finished` is `struct {
    index: u16, result: Result }`, and `Result` is `union(enum) { answer: Answer, failed: Reason
    }`, in `cocuyo_doh` and in the twin's `sim.Channel`. colibri's own `Response.outcome` keeps
    its name, and so does the local name in `result_of` that reads it.

### Asked on 2026-10-24, for the deadline of a ready lookup

70. **A send held behind a send that never ends.** Since decision 52 a deadline ends
    `tcp_ready`. The query's send still holds the lookup's send buffer until the send's final
    event (the stream's rule 6). That event is the cancel's, after a drive shuts the connection, at
    or after `tcp_idle_ns` from the instant the last lookup left it. No timer is armed for that
    drive (decision 49). Each send that the slot asks for in that time is held:

    - A try on a stream at the next server. Its connection comes up, and its query is held. Its
      deadline comes before the idle close. So that server counts a failure that it did not earn,
      and with one pass the lookup ends in `Timeout`. The twin test "a send never ends, and the try
      at the next server waits for its buffer, as built" shows this in the clear, with a slot for
      each server. Over TLS each server always has a slot of its own (TLS rule 6). So each setup of
      two or more servers over TLS has this wait. That is read from the code, and no test ran it.
    - A try by datagram at the next server, after a TC=1 answer. It waits in `query_ready`, where
      no deadline bounds it. A probe on the twin, which left the tree, showed two cases. With a
      drive at the bound, the datagram went 10 seconds after the first deadline, and the answer
      came then. With no other event, the clock ran 1,020 seconds past the deadline, and the
      datagram was still held.
    - A new lookup that takes the same table slot. It has the same buffer, and waits in the same
      way.

    The same drive also frees the slot over TLS. That comes at or after twice `tcp_idle_ns`, since
    the connection first closes with `close_notify` (TLS rule 5, decision 49). In an engine that
    has no other event, no drive comes, and the slot does not free. Each lookup that joins the
    connection also puts off the idle close, since a connection is idle only while no lookup is on
    it.

    The ways:

    - As built: each such send waits for a drive after the idle close's wait.
    - The drive shuts a connection at once when its last lookup leaves while a query's send is in
      flight. The cancel's event then gives the buffer back on the next loop step. The drive does
      not wait for the idle close, and over TLS no `close_notify` goes, since the peer does not
      read. Mutation RD15 builds this way, and the twin test above catches it.
    - The lookup's next send goes out from the octets that the engine holds for it, while the
      send buffer is lent. A slot then has two sends in flight, which the stream's rules 6 and 7
      do not allow.

    Recommended: the second. A connection whose send did not end for a whole wait has a peer that
    does not read, and no other lookup gains from it. The next server then counts no failure that
    it did not earn, and no held send waits for a drive. Until the owner rules, as built.
    Answered on 2026-10-25: the second way. Built on 2026-10-25: §16 decision 53. The twin test of
    the next server now ends in its answer, and that server counts no failure.

### Asked on 2026-10-25, for a send held behind a stalled one

Decision 53 builds the answer to question 70. Two waits of the same kind stay outside the ruling.
Each needs a peer that stops reading during a query's send.

71. **A held send while another lookup stays on the connection.** Decision 53 shuts a connection
    when its last lookup leaves during a query's send. While another lookup stays on it, the send
    stays in flight. The lookup that left keeps its buffer lent, and its next send is held. Each
    lookup on the connection has a deadline of its own. But each lookup that joins the connection
    puts the shut off, since it stays until its own deadline. So with a steady flow of lookups to
    that server, the held send can wait past its own deadline. That is read from the code, and no
    test ran it. The ways:

    - As built: the shut waits for the last lookup to leave.
    - The drive shuts the connection at the leave of the lookup whose query's send is in flight,
      whatever lookups stay. Each lookup on it hears that its connection failed, and moves on.
    - After such a leave, no lookup joins the connection. The lookups on it end by their own
      deadlines, and the last leave shuts it. A new lookup to that server opens a new connection.

    Recommended: the third. No lookup hears a failure that it did not cause, and the wait is at
    most one deadline of the lookups on the connection. Until the owner rules, as built.
    Answered on 2026-10-25: the third way. Built on 2026-10-25: §16 decision 54. A new lookup to
    that server opens a new connection, in a free slot, or it waits for a slot.
72. **A refused connection whose query's send is in flight.** Over TLS a record that the session
    refuses once the connection is up fails it (TLS rule 4). So does a prefix that says more than
    `tcp_message_bytes` (the stream's rule 11), with a `close_notify` in place of the alert (TLS
    rule 5). The sealed records go out first, the query's send among them, and then the alert. The
    lookups hear the failure at once, and move on. The lookup whose query's send is in flight keeps
    its buffer lent until that send ends. With a peer that stops reading, that is the shut of
    decision 49, at or after `tcp_idle_ns`. So the try of that lookup at the next server is held,
    as in question 70. That is read from the code, and no test ran it. The ways:

    - As built: the held send waits for the shut of decision 49.
    - The rule of decision 53 here too. A refusal while a query's send is in flight shuts the
      connection at once, and no alert goes.

    Recommended: as built. The peer sent a record just then, so it reads in the usual case. RFC
    9846 §6.2 asks for the alert, and that peer can read it. Until the owner rules, as built.
    Answered on 2026-10-25: as built. A refused record still sends its alert (RFC 9846 §6.2), and
    the code does not change.

### Asked on 2026-10-25, for a connection no lookup may join

73. **A wait for a marked connection's slot in the clear.** The ruling on question 71 says that a
    new lookup opens a new connection in a free slot, or waits for a pending slot. Decision 54
    also lets the lookup wait for the slot of a marked connection. Over TLS that wait keeps TLS rule
    6: no lookup is told that its connection failed for want of a slot. In the clear decision 46
    told such a lookup `local`, when no connect could be closed. The lookup then failed over to its
    next server at once.

    The ways:

    1. As built: the lookup waits for the marked slot, in the clear as over TLS. The last leave of
       the marked connection frees the slot, at most one deadline of its lookups later.
    2. In the clear the lookup is told `local`, as decision 46 said, and fails over at once. Over
       TLS it waits, as TLS rule 6 needs.

    Recommended: as built. One rule holds for both transports, and the lookup keeps its server.
    The second way reaches another server sooner, but a single server has no other. Until the owner
    rules, as built. Answered on 2026-10-27: as built.

### Asked on 2026-10-26, for a DoH link's send

§16 decision 55 builds the answer to question 61: `quic_idle_ns` bounds a link that closes, and
each end of a link cancels its send. The ruling did not make two of the choices that decision 55
makes.

74. **The order of the shut at the bound and a lookup's deadline.** The drive shuts each link at
    the bound first, before its polls (`shut_lapsed` in `io/io_drive.zig`). The shut reads the
    channel, and the channel may tell an end that it held. So that end reaches its lookup, even
    when the lookup's deadline came at the same instant. A connection's idle close runs after the
    polls (`tcp.close_idle`). The ways:

    - As built: the shut at the bound comes first. A lookup whose end the channel held takes that
      end, not its deadline. The TLA+ model shuts the link before `Pass` too, and the walks agree.
    - The shut at the bound after the polls, as the idle close of a connection. A lookup whose
      deadline came at that instant fails at its deadline, and the end that the channel held comes
      too late for it. The model, the walks and the picks change with it.

    Recommended: as built. The channel held a real end, and the lookup gets it. A shut after the
    polls loses that end for an instant of the clock. Until the owner rules, as built.
    Answered on 2026-10-26: as built.
75. **A link that closes with no drive to shut it.** No timer is armed for the bound. A drive
    comes at a lookup's deadline, at a channel's instant, or at the start of a lookup. A channel
    that closed has no instant (`next_deadline` in `io/io_channel.zig` passes over its slot). So a
    link of a closed channel, with no lookup in the table, keeps its socket and its lent buffer.
    It keeps them until the caller starts the next lookup, or calls `deinit` or `reinit`. The
    ways:

    - As built: the next drive shuts the link. Nothing is lost, and `deinit` cancels the send.
    - The engine's timer counts the bound of each link that closes, as a channel's instant. The
      drive at the bound then shuts the link with no lookup in the table.

    Recommended: as built, as decision 49 ruled for a connection. The link holds one socket and
    one buffer of its own server's slot, and no other server waits for them. Until the owner rules,
    as built.
    Answered on 2026-10-26: as built.

### Asked on 2026-10-26, for the limits files

§16 decision 56 builds the answer to question 37. CLAUDE.md asks the owner before the public API
changes. The ruling did not make four of the choices that decision 56 makes.

76. **The public paths of the limits.** Each public namespace has a `limits` now, beside its
    `constants`. These are `cocuyo.limits`, `cocuyo_rotor.limits`, `cocuyo_quic.limits` and
    `cocuyo_doh.limits`, and one for each module of `src/`. These names are new. Each public
    `constants.zig` keeps an alias of each limit that left it, so `cocuyo.constants.query_bytes_max`
    still compiles. The ways:

    - As built: both paths. Each old path stays, and a consumer moves to the new one at its own
      time. One limit then has two names, and a reader can take the alias for a limit.
    - The new paths alone. Each old path goes, and a consumer's build stops at each one. The public
      API loses names.

    Recommended: as built until the next release, 0.7.0, then the new paths alone. The tree reads
    the new paths already, so the aliases go with no other change. Until the owner rules, as built.
    Answered on 2026-10-26: as recommended. The aliases go at 0.7.0. Built on 2026-10-28: §16
    decision 56, At 0.7.0.
77. **The limits of the tests.** The place check reads no test file and no `fixtures.zig`. So 20
    bounds of the tests stay where they are, each with a type: `rounds_max` of
    `io/io_doh_channel_test.zig`, `events_max` of `io/fixtures.zig`, and others. The ways:

    - As built: a test's bound stays in the test. The test chose it, and no code of the library
      reads it.
    - Each test's bound moves into its module's limits file too. A limits file then holds bounds
      that no code of the library reads.

    Recommended: as built. Until the owner rules, as built. Answered on 2026-10-26: as built.
78. **The limits with no suffix.** The place check reads a limit by its name. 23 limits have a name
    with no `_max`, `_min` or `_limit`, such as `buffer_bytes`, `tcp_chunk_bytes` and
    `idle_timeout_ms`. Each moved, and docs/mutations.md names each one. But no check keeps such a
    limit in its limits file. The ways:

    - As built: the names stay, and the inventory holds them.
    - A rename of each one with a suffix, such as `buffer_bytes_max`. The check then holds every
      limit. 20 of the 23 are public, so the rename changes public names.

    Recommended: the rename, at the release that drops the aliases of question 76, so a consumer
    changes its paths once. Until the owner rules, as built. Answered on 2026-10-26: the rename, at
    0.7.0, with the aliases of question 76. Built on 2026-10-28: §16 decision 56, At 0.7.0.
79. **The constants at the border of a class.** The test of decision 56 puts four constants in a
    constants file, but another reader can put each in a limits file:

    - `cookie_silence_ns` of `src/resolver/constants.zig`: five minutes, the example period of
      RFC 9018 §3. The code holds it as a wait, not as a bound on input. Class: other.
    - `fallback_delay_ms` of `io/io_doh_channel_constants.zig`: 250 ms, taken from RFC 8305 §5.
      It is a delay, not a bound. Class: other.
    - `connection_id_bytes` of `io/io_quic_constants.zig`: RFC 9000 §7.2 sets a floor of eight
      octets, and cocuyo uses the floor. Class: protocol size. Rule 4 of the test can take it as a
      size that cocuyo chose.
    - `padding_block_bytes` of `src/core/constants.zig`: the block of 128 octets that RFC 8467
      §4.1 recommends. Class: protocol size.

    The ways:

    - As built: the four stay in their constants files.
    - Each moves into its module's limits file, with an alias on the old path as question 76 says.

    Recommended: as built. None of the four is a bound that the code checks against input. Until
    the owner rules, as built. Answered on 2026-10-26: as built.

### Asked on 2026-10-27, for the bound on the queries to one server

§16 decision 58 builds the owner's ruling on c4milo/cocuyo#50. The ruling did not make two of its
choices, questions 82 and 83. The change also made the full walk smaller, which question 84 asks
about.

82. **One address named twice.** RFC 9520 §3.1 bounds the queries to "a server address". The
    lookup counts by the position of a server in its order. A configuration that names one address
    twice, with one port or two, then sends that address up to three queries for each entry. The
    ways:

    - As built: one count for each configured server. A configuration with a duplicate is the
      caller's choice, and `resolv.conf` with two equal `nameserver` lines is rare.
    - One count for each address: the lookup compares each server's address with the others' at
      each count, or the configuration drops a duplicate when it is built.

    Recommended: as built. A check at each count costs a walk over the servers on the hot path,
    and a configuration that drops a duplicate changes what a caller configured. Until the owner
    rules, as built. Answered on 2026-10-27: as built.
83. **Eight octets more for each lookup.** The counts take four octets, and Zig pads the lookup
    from 3,072 octets to 3,080, and a slot from 3,088 to 3,096 (§9). The ways:

    - As built: a field of four octets, `Lookup.sends`.
    - The counts in the spare bits of `Lookup.order`. Each entry of the order is a server's index,
      under 8, so five bits of each octet are free. The lookup stays at 3,072 octets, but one field
      then holds two things.

    Recommended: as built. A field that holds one thing is easier to read and to check, and 8 KiB
    for 1,024 lookups is small. Until the owner rules, as built. Answered on 2026-10-27: as built.
84. **The configurations the full walk drops.** The counts made some walks too large, so
    `configsAll` in `spec/lean/Main.lean` walks 84 of its 109 configurations. A smaller walk is a
    weaker check. The 25 that it drops:

    - two servers over two or three passes, with two or three names, over UDP: 4;
    - three servers over two passes, with two or three names, over each transport: 8;
    - three servers over two passes, with one name, over UDP: 1;
    - three servers over three passes, with each name count, over each transport: 12.

    The cost was measured for one of them alone. Two servers, three passes and three names over
    UDP grew from 843,711 transitions to 35,067,338. The others were not measured. A walk of three
    servers is probably larger than a walk of two. The ways:

    - As built: the walk drops the 25, and spec/README.md lists them as a known gap.
    - A tighter key: more of the counts that the lookup does not read again stay out of what makes
      a state new. That makes the key harder to show correct, and it may not save enough.
    - A nightly job that walks all 109, as the `tla-nightly` workflow checks every TLA+
      configuration. Its cost is a CI job of some hours, an estimate from the one measured walk.
    - Walk all 109 in `zig build spec`. By the same estimate, each run then takes hours, not 21
      minutes.

    Recommended: as built. One server reaches each rule of the bound, and two servers reach a
    server passed over in a pass and at the start of the next. So the 84 walk each rule of the
    bound. Until the owner rules, as built. Answered on 2026-10-27: as built.

### Asked on 2026-10-27, for the failure cache of the engine

§16 decision 60 builds the owner's ruling on c4milo/cocuyo#51 in the cache module. The ruling
keeps `src/resolver` as it is, so the engine's cache, which the table reaches through `Memory`,
gets no failure entry. Question 85 asks about that.

85. **The engine and the failure cache.** The engine puts and reads its cache through the table's
    `Memory` (§20). `Remembered` carries an answer and RFC 2308's two negatives, and
    `remember_end` writes no other failure. So an engine with a cache sends every try again for
    a name whose servers all fail, and RFC 9520 §3.2 says it "MUST NOT". The ways:

    - As built: the engine gets no failure cache. `remembered_by` recalls a failure entry as a
      miss.
    - A third variant of `Remembered`, `failed`, with the error. `remember_end` writes each
      resolution failure, and `recall_into` ends the lookup with the recalled error. This changes
      `src/resolver` and the public `Remembered`, and the Lean model of §5 if the recall is in it.
    - The engine asks the cache itself before `Resolver.start`, and puts each failed end. The
      table stays as it is, but the engine then reads the cache in two places, and a hit must
      become a result that `take` hands back with no lookup. The TLA+ engine model changes.

    Recommended: the second way, in a change of its own. The rule then lives in `remembered_by`
    with the other rules of what may be remembered, and every consumer of the table gets it. Until
    the owner rules, as built, since the ruling keeps `src/resolver` as it is. Answered on
    2026-10-28: the second way, `Remembered.failed`, in a change of its own. Built on 2026-10-28
    (§16 decision 61).

### Asked on 2026-10-27, for the alert of a record that is too long

c4milo/cocuyo#45 asks for a `record_overflow` alert before the close on a record that is too long.
RFC 9846 §5.2 caps the length at 2^14 + 256 octets: "An endpoint that receives a record that
exceeds this length MUST terminate the connection with a "record_overflow" alert". The owner
ruled on 2026-10-27 for a session call that stages an alert with a description the engine names.
The ruling said to stop before the code if colibri cannot write such an alert. It cannot, so
this change builds no part of the ruling.

88. **A session call for an alert that the engine names.** The DoT session drives colibri's
    `tls.record.Client` at the commit that `build.zig.zon` pins (v0.8.0, `7496cdc`). These facts
    come from that source, and from chapulin's source at the commit colibri pins (`e6e3c1e`):

    - colibri's record provider (`tls_provider.VTable`) has no member that writes an alert. It has
      `send_close_notify` alone. `tls.record.Client` has no such call either.
    - `encrypt_record` seals application data alone. So cocuyo's session cannot seal an alert
      record itself from colibri's sealing call.
    - chapulin's public C interface (`tls.h`, `tcp_nonblocking.h`) has no call that fails a
      session with an alert of a chosen description. Its internal `tlsi_fail` does this.
    - chapulin checks the length itself. Before the handshake completes, `ch_record_in` refuses a
      header over 2^14 + 256 with `record_overflow`, and colibri's `failure_written` counts that
      alert.
    - Once the connection is up, `ch_read` refuses the same header with `decode_error`, not
      `record_overflow` (chapulin's `io.c` and `tls.c`).

    The ways:

    - A chapulin call and a colibri call. chapulin makes public a call that fails a session with a
      named alert, over `tlsi_fail`. colibri adds a call on `tls.record.Client`, or a provider
      member, that writes it. Then the session gets `stage_alert(description)` as ruled. Both are
      changes to other repositories, and the owner must approve each and a new colibri pin.
    - The header to the session. The engine hands the five octets of the header to the session's
      `handshake` or `open`, and the session refuses it with chapulin's own alert. This needs no
      new call. But once the connection is up, the alert is `decode_error`, which RFC 9846 §5.2
      does not allow, until chapulin changes `ch_read`.
    - `close_notify` in its place, through `close` as `quit` does. RFC 9846 §6.1 makes
      `close_notify` a closure alert, not the fatal alert that §5.2 asks for.
    - Leave it. The connection closes at once, with no alert, as today.

    DoQ has no such case. RFC 9001 §4 carries the TLS handshake in QUIC CRYPTO frames, with no
    TLS records, so no record length exists to check.

    Recommended: the chapulin call and the colibri call, then the ruling as written. The other ways
    send a wrong alert or none. Until the owner rules, cocuyo builds none of it, and the connection
    closes with no alert as today. Answered on 2026-10-28: the chapulin call and the colibri call.
    cocuyo builds the ruling after a colibri release that carries them: c4milo/chapulin#207,
    c4milo/chapulin#208 and c4milo/colibri#114.

### Asked on 2026-10-28, for the cause of a recalled failure

§16 decision 61 builds the ruling on question 85. The memory keeps no cause, so a recalled
failure has none. §5 says that `AllServersFailed` always has a cause. `Lookup`, `AddressLookup`
and `NameLookup` assert it, and the doc comment of `Failure.cause` says it. The ruling does not
say which of the two gives way.

89. **The cause of a recalled `AllServersFailed`.** The ways:

    - The rule gets an exception. A recalled failure has no cause and `attempts_made` of zero. A
      lookup that goes out ends `AllServersFailed` only after its last pass, so its
      `attempts_made` is `Config.attempts`, which is 1 at least. The three assertions accept
      `AllServersFailed` with no cause when `attempts_made` is zero. No type changes.
    - `Failure` gets a field `recalled`, and the assertions read it. This changes a public type
      that the ruling does not name.
    - The cache keeps the cause, and `failed` carries it. The slot grows. The cause names a server
      by its position in the configuration, which `reinit` can change. And no server failed the
      recalled lookup, so the cause would say what is not true.
    - The memory recalls `AllServersFailed` as `Timeout`. The lookup then ends with an error that
      it did not have.

    Recommended: the exception. It changes no type, and `attempts_made` tells the two cases
    apart. A recalled negative already has no cause. Until the owner rules, cocuyo builds the
    recommendation. Answered on 2026-10-28: as built.

### Asked on 2026-10-28, for the count of a fuzz gate

§16 decision 56 builds the rename of question 78. The rule `typed-constants` then reports each
constant of a limits file with no limit's suffix. Two limits outside the inventory have none:
`fuzz_seed_count` of `src/wire/limits.zig` and of `src/config/limits.zig`. Each is public, as
`cocuyo.wire.limits.fuzz_seed_count` and `cocuyo.resolv_conf.limits.fuzz_seed_count`. Each is the
count of seeds that `zig build test` runs, and `zig build fuzz-gate` runs another count when told.

90. **The count of seeds of a fuzz gate.** The ways:

    - As built: the names stay, and the check of a limits file passes a name that ends in `_count`.
      The place check does not read `_count`, so such a limit can live in any file.
    - A rename, such as `fuzz_seeds_max`. The gate runs that count and no fewer, so `_max` says
      what is not true.
    - A move into each constants file as a default, `fuzz_seeds_default`. The gate is the caller
      that can change it. This changes a public path again.

    Recommended: the move, at the next release that changes public names. Until the owner rules,
    as built. Answered on 2026-10-28: the move, now, with the names of 0.7.0. The rule then passes
    no name that ends in `_count`. Built on 2026-10-28: §16 decision 56, At 0.7.0.

## 18. The cache

A cache above `Resolver.start`, in a module of its own that imports `core` and `wire` and never
the state machine (§2). The state machine stays cache-free: a caller asks the cache, starts a
lookup on a miss, and puts the answer in when the lookup ends. Nothing in `Lookup` or `Resolver`
changes shape for it, which is what §1 promised when it put the cache above the library.

### What c-ares does, and what this keeps

c-ares (`src/lib/ares_qcache.c`, read 2026-09-22): a string-keyed hash table compared
case-insensitively, keyed by the opcode, the RD and CD flags, and each question's type, class and
name; each entry a duplicate of the whole parsed response; a skip list ordered by expiry, drained
on every fetch; the TTL the smallest over every record with OPT, SOA and SIG skipped, or the SOA
minimum for NXDOMAIN (RFC 2308), capped at an hour by default, and zero not cached; NOERROR and
NXDOMAIN cached, everything else and anything truncated not; TTLs decremented by age on a hit; no
bound on the entry count; the whole cache flushed when the servers change.

Kept: the key by folded name and type; the TTL rules, with the cap; TTLs decremented on a hit; a
flush. Dropped: the entry count, which is unbounded there and cannot be here; the skip list, which
exists to find expired entries and is not needed when eviction walks the entries anyway; and one
behaviour, that a NODATA answer — NOERROR with no records and an SOA in the authority section —
takes the cap rather than the SOA minimum, because the walk that finds the smallest TTL skips SOA
and then finds nothing. RFC 2308 §2.2 and §5 have NODATA use the SOA minimum as NXDOMAIN does,
and this cache does.

### The policy: SIEVE, with expiry folded into the hand

A fixed table has to answer "full, and nothing has expired", which c-ares never has to. Three
policies were weighed in the conversation that decided this (2026-09-22):

- LRU moves an entry to the head on every hit: pointer writes on the read path.
- SIEVE (Zhang et al., NSDI 2024) keeps insertion order, one visited bit per entry, and a hand. A
  hit sets the bit. Eviction walks the hand from the oldest entry toward the newest, clears the bit
  on anything visited and leaves it in place, and evicts the first unvisited entry it meets. New
  entries go in at the newest end, apart from the hand, which is what separates it from CLOCK.
- S3-FIFO (Yang et al., SOSP 2023): a small probation queue, a main queue with a two-bit counter,
  and a ghost queue of evicted keys. Its edge is a workload dominated by one-hit objects and scans,
  at the price of three queues and a ghost.

SIEVE is the one built: the simplest policy whose hit path is a single bit write, deterministic
with no seed, and whose worst case is one bounded pass. S3-FIFO stays the one alternative to
measure it against, because the two share every line but the eviction, and a replayed trace
through `bench/` is what decides between them, not this page. The argument for SIEVE is the
papers' and the structural fit; no DNS trace was measured to make it, and §11's rule applies.

The one thing neither paper models is that a DNS entry dies on its own. The hand evicts an
expired entry on sight, visited or not: a free eviction, which is what c-ares spends its skip list
finding.

### Shape

The shape `Resolver` already has: a caller-sized array of slots, an open-addressed key index, and
the policy's own few words.

```zig
pub const Outcome = enum { answered, name_not_found, no_data, failed }; // failed: §16 decision 60

pub const Slot = struct {
    name: Name,             // folded: the key, and what a hit hands back
    answers: wire.Answers,  // the records, for an answered entry
    expires_ns: u64,
    hash: u32,
    links: Links,           // older and newer: the insertion-order chain, oldest to newest
    kind: Kind,
    outcome: Outcome,
    kept: Kept,             // a failed entry's error and count of doublings, one octet (§16 decision 60)
    absolute: bool,         // part of the key: the search list makes `foo` and `foo.` two questions
    visited: bool,
    occupied: bool,
};

pub const Key = packed struct(u64) { hash: u32, slot: u16, state: u16 };

pub const Hit = struct {
    outcome: Outcome,
    answers: *const wire.Answers, // valid until the next call on the cache
    name: *const Name,
    ttl_seconds: u32,             // what is left, not what was put
    failure: ?Error,              // the error, on a failed entry alone
};

pub const Cache = struct {
    pub fn init(slots: []Slot, keys: []Key, seed: u64, ttl_seconds_max: u32) Cache;
    pub fn get(self: *Cache, question: *const Question, now_ns: u64) ?Hit;
    pub fn put(self: *Cache, question: *const Question, answers: *const wire.Answers, now_ns: u64) void;
    pub fn put_negative(self: *Cache, question: *const Question, outcome: Outcome, ttl_seconds: u32, now_ns: u64) void;
    // Since 2026-10-27 (§16 decision 60): 5 s by default, 1 s to 300 s, from Config.cache_failure_seconds_min.
    failure_seconds_min: u32 = constants.failure_seconds_min_default,
    pub fn put_failure(self: *Cache, question: *const Question, err: Error, now_ns: u64) void;
    pub fn flush(self: *Cache) void;
    pub fn len(self: *const Cache) usize;
};

// Since 2026-10-11 (§16 decision 37, Sizing the memory below):

/// The memory a cache is built over, as `Cache.init` takes it: slices into memory the caller owns.
pub const Slices = struct {
    slots: []Slot,
    keys: []Key,
    pub fn valid(self: Slices) bool; // what `Cache.init` asserts of the two
};
/// The same memory as arrays, for a caller that knows the slot count when it compiles.
pub fn Storage(comptime slot_count: usize) type; // `slots`, `keys`, and `slices()`
/// Whether a cache takes `slot_count` slots: 1 to `slots_max`.
pub fn slot_count_valid(slot_count: usize) bool;
/// Whether a cache takes this cap on its TTLs: 1 second to seven days (RFC 8767 §4).
pub fn ttl_seconds_max_valid(ttl_seconds_max: u32) bool;
/// The least key index `slot_count` slots take: `keys_per_slot_min` a slot, at a power of two.
pub fn keys_for(slot_count: usize) usize;
```

- The key is the folded name, the type, and whether the name was absolute, which is what a
  `Question` holds: `foo` may resolve through the search list and `foo.` may not, so they are two
  entries. The hash is a keyed one, seeded by the caller's `u64` the way the transaction ids are,
  so a peer that chooses the names a process resolves cannot choose where they land. The probe is bounded by `cache_probe_max`; a chain longer than that is
  a miss on `get` and a refusal on `put`, never more work.
- A `get` that finds an expired entry misses and leaves it where it is, bit and all: the put
  after the miss renews it in place, and the hand takes it on sight if no put comes (§17
  question 14). A `get` that hits sets the visited bit and returns the remaining TTL, which is
  the expiry less `now_ns`, rounded down to a second.
- The answers a hit points at hold, as their own TTL, the life the entry was given. That TTL less
  the remaining one is the time the entry has spent in the cache, rounded up to a second. A
  lookup the cache answers lowers every TTL in the answers by that much, never below zero, since
  the TTLs of cached data count down (RFC 1035 §6.1.3). Before c4milo/cocuyo#39 only the
  answer's smallest TTL was set to what was left. A record kept with a TTL of its own, an MX or a
  TXT, came back with the TTL it was stored with.
- A `put` for a question the cache holds replaces the entry in place and sets the bit; it does not
  move it in the order. A `put` of a TTL of zero, or of an answer marked truncated, is refused.
  An answer is marked truncated when records were dropped for want of room, or when the message
  it came in had TC set: a resolver "should not cache a possibly partial set of RRs" (RFC 1035
  §7.4). TC says the message was cut to fit its channel (RFC 1035 §4.1.1), and every channel has
  a limit, a stream's being 65535 octets (RFC 9250 §4.6). Over DoH it can also say the server
  could not get the full answer (RFC 8484 §10). The lookup reads such a message over UDP only
  under `ignore_truncation`, and over TCP, DoT, DoH and DoQ always, since there is no larger
  channel to ask over. The TTL is capped at `ttl_seconds_max`, and the entry keeps the capped
  TTL as its answers' own.
- A NODATA or an NXDOMAIN read from a message with TC set is still cached for its SOA's TTL.
  Truncation "should start at the end of the response and work forward" (RFC 1035 §6.2), and
  the SOA is in the authority section, after the answer section. A message that still holds it
  holds the whole answer section, so the empty set is not a partial one.
- A `put` into a full table runs the hand: from where it stopped, or the oldest entry, toward the
  newest; an expired entry is evicted on sight; a visited entry has its bit cleared and stays; the
  first unvisited entry is evicted. The walk is bounded by twice the slot count, which is one
  pass that clears every bit and a second that must then find one, and that bound is asserted.
- `put_failure` keeps a resolution failure (RFC 9520 §3.2): the first for `failure_seconds_min`,
  and each later one after the entry expired for twice the time before, up to 300 s. A hit on it
  is `Outcome.failed`, with the error, and the caller sends no query until it expires. An answer
  for the name ends the backoff. §16 decision 60 says which errors count, and why. Since
  2026-10-28 the table's memory puts and recalls a failure too, so a table with
  `remembered_by` sends no query for the name while the entry lives (§16 decision 61).
- `flush` empties the table, which is what a caller does when its servers change.
- Nothing here reads a clock or a random source; `now_ns` and the seed come in as they do
  everywhere else, so a cache replays from its inputs.

### What the state machine had to add

RFC 2308 wants a negative answer cached for min(SOA TTL, SOA minimum), and the SOA is in the
authority section, which nothing read before. Two additions: `wire.response.negative_ttl_seconds`
reads the first SOA of the authority section, bounds-checked like everything else, and returns
that minimum, or zero when there is no SOA; and a `Lookup` that ends in `NameNotFound` or `NoData`
carries it in `Failure.negative_ttl_seconds`, so the caller can `put_negative` without reading a
message it never saw. A failure that is not a negative answer — a timeout, every server failing —
carries zero, and `put_negative` keeps no zero. Since 2026-10-27 the caller hands such a failure
to `put_failure` instead, which keeps it for a time of its own (§16 decision 60). Since 2026-10-28
the table's memory does that for the caller (§16 decision 61).

A lookup of a relative name walks the search list, and the cache keeps the walk's end under the
name as asked. Each candidate's negative bounds that end, as §5's search list policy has it: a
negative end carries the smallest of the candidates' negative TTLs, and an answer's TTL is no
larger than any of them. So the entry is put with a TTL no larger than that of any negative it
rests on, and a negative with no SOA on the way keeps the end out of the cache
(c4milo/cocuyo#38). Each TTL is what its response carried. The time between an earlier
candidate's negative and the walk's end is not taken off, so the entry can outlive that
negative by that time, as an answer reached through a CNAME of an earlier message can outlive
the CNAME. `AddressLookup`'s outcome is not bounded this way (§19 step 14).

### Measured

The cache rows of §11's table, on the day the cache landed and on the same machine: a hot hit
31 ns, a hit read cold over 1024 entries 44 ns, a miss 13 ns on a young index and 36 ns after
churn, a put in place 37 ns, a put that evicts 97 ns. The first build of the hash copied the
question's name, folded it octet by octet, and mixed the type, the flag and the length in three
steps: the hit cost 50 ns, the miss 23, the eviction 123. Folding eight octets at once as the
name is read (`Name.fold_word`, in `core` because folding is `core`'s) and mixing the prefix
once brought them to those numbers, a third off every row.

The slot took the chain's end the same day (§17 question 13), and §11's table, measured again,
reads a hot hit 34 ns, a cold one 47, a miss 13 and 38, a put in place 36 and an eviction 94.
No row moved by more than 7%, and they moved in both directions, which is inside the fifth §11
puts on a binary's layout: the chain's end costs memory and nothing this table can see. Nothing here was compared against c-ares's
cache, whose entry is a parsed record tree and whose key is a formatted string, so no ratio is
claimed.

### Does it earn its keep

`zig build bench` prints this after the nanosecond rows, on the machine and day §11 names. One
million questions over 50,000 distinct names, drawn Zipf with an exponent of one, arriving one
every 10 milliseconds — a little under three hours of virtual time — with TTLs of 60, 300 and
3600 seconds over 40%, 40% and 20% of the names. `bench/cache_trace.zig` holds every one of those
numbers as a named constant. The rows are the cache since §17 question 14, which renews an expired
entry in place.

| Slots | Memory | Hit rate | Hits | Misses |
| --- | --- | --- | --- | --- |
| 64 | 186.5 KiB | 38.8% | 387,687 | 612,313 |
| 256 | 746.0 KiB | 48.4% | 483,654 | 516,346 |
| 1024 | 2.9 MiB | 55.2% | 552,253 | 447,747 |
| 4096 | 11.7 MiB | 59.1% | 590,785 | 409,215 |
| 16384 | 46.6 MiB | 60.6% | 606,390 | 393,610 |

What it says:

- **The cache earns its keep.** At 1024 slots, the size `engine_cache_slots_default` names (§19,
  New limits) and the engine took by default until 2026-10-11, 2.9 MiB of the
  caller's memory answers 55% of the questions without a packet. That is the answer §17
  question 9 assumed and no measurement had given. It was 52.2% before question 14.
- **Each fourfold step buys less.** From 256 slots to 1024 buys 6.9 points, to 4096 another
  3.9, and to 16384 another 1.6.
- **The ceiling is the workload's, not the policy's.** A name is a hit only if it is asked again
  inside its own TTL, and the tail of a Zipf never is. c-ares's rule, which evicts nothing,
  reaches 61.1% on this trace (below), and no cache with the same TTLs can do better.

**The trace is synthetic, and the table is worth exactly what its assumptions are.** The
popularity curve is Zipf because that is what web object popularity has measured as for decades,
not because anyone has measured DNS names here, and the TTLs follow the rank: the most popular 40%
of names take a minute, the next 40% five minutes and the rest an hour. "Against a real log"
below replays a real one.

### SIEVE against S3-FIFO

Measured on 2026-09-22 by `zig build bench`, over the trace above with the same seed.
`bench/cache_policy/` models both policies over name indices. The model of SIEVE is the
control: it has to answer as the real cache does before the S3-FIFO columns mean anything. A
test holds it to the same hit count on a short trace, and over the whole trace it matches to
within 0.01 point at every size. The cause of that difference was not traced.

S3-FIFO is Algorithm 1 of Yang et al. (SOSP 2023), read from the paper: the small queue S a tenth
of the cache, the main queue M the rest, and a ghost queue G of names as long as M, kept by
insertion stamps as the paper's §4.2 builds it. The paper disagrees with itself on one rule.
Algorithm 1 line 23 moves a name from S to M when `t.freq > 1`, and Figure 5 moves it when it
was visited, which is `freq > 0`. Both are run: `l23` and `f5` below.

Neither paper has an entry that dies on its own, so each model is run under both rules for what
a get does with an entry it finds expired:

- **Evicted.** The get evicts the entry, so the put after the miss goes in as new. This was the
  cache's rule until §17 question 14.
- **In place.** The get leaves the entry, and the put after the miss renews it where it stands
  and counts the renewal as a use: SIEVE's bit is set, as the cache's put in place sets it, and
  S3-FIFO's counter goes up by one. This is the cache's rule since. Left as they were instead,
  the bit and the counter moved no row by more than 0.2 point.

| Slots | Cache | SIEVE, evicted | S3-FIFO l23, evicted | S3-FIFO f5, evicted | SIEVE, in place | S3-FIFO l23, in place | S3-FIFO f5, in place |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 64 | 38.77% | 34.71% | 37.98% | 38.13% | 38.77% | 38.78% | 38.77% |
| 256 | 48.37% | 43.75% | 46.42% | 46.90% | 48.36% | 48.62% | 48.68% |
| 1024 | 55.23% | 52.21% | 51.36% | 52.04% | 55.24% | 55.27% | 55.37% |
| 4096 | 59.08% | 60.07% | 56.73% | 57.03% | 59.07% | 58.92% | 58.97% |
| 16384 | 60.64% | 60.66% | 60.78% | 60.80% | 60.64% | 60.75% | 60.78% |

What it says:

- **The policy is not what moves the hit rate on this trace.** With expired entries renewed in
  place, SIEVE and both readings of S3-FIFO are within 0.4 points of each other at every size.
- **The expiry rule is.** Renewed in place, SIEVE gains 4.1 points at 64 slots, 4.6 at 256 and
  3.0 at 1024, and loses 1.0 at 4096. The reading, which no measurement isolated:
  evicting on the get and putting the name back as new is a promotion given on a miss, which
  SIEVE exists not to give. A tail name asked once more after it expired goes to the newest
  end, the place farthest from the hand.
- **Under the old rule S3-FIFO leads at small sizes and trails at 4096.** It is about 3 points
  ahead at 64 and 256 slots and about 3 behind at 4096. The same reading would say its probation
  queue refuses the promotion SIEVE gives, and then makes every popular name that expires earn M
  again.

So S3-FIFO is not worth a second policy in the library. The expiry rows are why §17 question 14
was answered yes.

### Against c-ares's rule

c-ares evicts nothing: its cache has no bound on the entry count, and every fetch drains the
entries that have expired (§18, from `ares_qcache.c`). `bench/cache_policy/` models that
rule over the same trace, with a binary heap where c-ares has a skip list; both keep the entries
in expiry order, which is all the rule needs. It measures **61.07% hits, with at most 8,748
entries live at once.**

- **SIEVE cannot beat it on hit rate, and does not.** A rule that never evicts a live entry is
  the ceiling for a given trace and TTLs. The cache is 5.8 points under it at 1024
  slots, 2.0 at 4096 and 0.4 at 16384.
- **16384 slots, almost twice what c-ares ever holds, still fall 0.4 short.** The reading, which
  no measurement isolated: the hand takes the first unvisited or expired entry it meets, so it
  can take a live entry nobody has read yet while an expired one waits further along the order.
  c-ares's skip list finds the expired entries first.
- **What SIEVE buys is the bound.** c-ares holds as many entries as the traffic makes: 8,748
  here, and without limit for a peer that makes a process resolve names of its choosing.
  cocuyo holds the caller's number, whatever the traffic.
- **Memory is not compared.** A c-ares entry is a duplicate of the parsed response, a formatted
  key and a skip list node, and its size in bytes was not measured. A cocuyo slot is 2984 octets
  whatever the answer holds.

### How far from the best

`bench/cache_trace.zig` also replays the trace through Belady's rule, the optimal. It writes the
trace down first, so at every eviction it knows each name's next request. A name whose next
request comes after it expires is worth nothing, since that request misses whatever the cache
holds; otherwise the name needed latest goes first, and a newcomer can be the one turned away. It
reads the future, so no cache can run it. It is the bound: no policy, admission included, hits
more often at the same size. A test holds the cache and every model at or under it.

Beside it, two policies that might do better:

- **SIEVE, expired first.** The SIEVE model with an expiry index: before the hand moves, it takes
  the entry that expires soonest if that entry has expired. That is c-ares's order, borrowed.
- **W-TinyLFU**, from Einziger, Friedman and Manes, "TinyLFU: A Highly Efficient Cache Admission
  Policy" (arXiv 1512.00727v2), read from the paper. Every name enters a window of 1% of the
  cache, LRU; the window's victim then competes with the main cache's, and the one asked for
  more often recently stays, the victim keeping a tie (§3.1, §4). The main cache is segmented
  LRU, 80% protected (§4). Frequencies are counted over a sample of ten times the cache, halved
  when a sample has gone by and capped at ten (§3.3, §3.4.1, §5.1). The paper counts with a
  sketch that approximates the histogram; the model keeps the histogram itself, so it measures
  the policy with no counting error, which is the most the sketch could give. An expired name
  loses the admission contest on either side.

| Slots | Cache | SIEVE, expired first | W-TinyLFU | Optimal |
| --- | --- | --- | --- | --- |
| 64 | 38.77% | 35.96% | 38.79% | 45.89% |
| 256 | 48.37% | 45.80% | 49.07% | 57.11% |
| 1024 | 55.23% | 54.95% | 55.97% | 60.89% |
| 4096 | 59.08% | 60.43% | 59.09% | 61.07% |
| 16384 | 60.64% | 61.07% | 60.27% | 61.07% |

What it says:

- **There is room at the sizes that matter.** The optimal is 5.7 points over the cache at
  1024 slots, 8.7 at 256 and 7.1 at 64. At 4096 it already reaches the ceiling, c-ares's
  61.07%, with fewer than half the entries c-ares holds; the cache is 2.0 under it there.
- **The optimal wins by two moves.** It turns away a newcomer that is needed later than what it
  holds, and it drops first a name whose next request comes after it expires. An online policy
  closes the gap only as far as it can predict those two.
- **Taking the soonest expired entry first is not the second move.** It gains 1.4 points at 4096
  and reaches the ceiling at 16384, and loses 2.8 at 64 and 2.6 at 256. The reading, which no
  measurement isolated: it throws a popular name out the moment it expires, so the next request
  puts it back as new, which is the promotion §17 question 14 removed. It stays a model.
- **W-TinyLFU is not the first move either, on this trace.** It closes 0.74 of the 5.66 points
  at 1024 slots and 0.70 at 256, gains nothing at 64 and 4096, and loses 0.37 at 16384. Its
  admission knows how often a name is asked and not how long the answer lives. The optimal's
  rule is about both: a name is worth keeping if it is asked again before it expires. The
  reading, which no measurement isolated, is that a policy has to weigh a name's rate against
  its remaining TTL to close the gap, and no paper read here does.
- Of the online policies measured, none is worth a change to the library: S3-FIFO ties SIEVE,
  expired first trades small sizes for large, and W-TinyLFU gains under a point where it gains.

### Expected hits

An experiment of this repository's, not a published design, tried because the optimal's rule is
about time: `bench/cache_policy/cache_policy_expected.zig` ranks each entry by an estimate of the
hits it can still give, its name's count in the histogram W-TinyLFU keeps times the time its
answer has left. An expired entry is worth nothing. The entry worth least is evicted, reading
every entry or the least of 16 drawn at random, since the worths drift with time and no index
keeps them sorted. With admission, a newcomer worth no more than that entry is turned away. The
count is either every ask, or only the asks after the first, so that a name asked once is worth
nothing until it is asked again.

| Slots | Cache | Every ask | Reuse | Reuse, admission | Reuse, admission, 16 drawn |
| --- | --- | --- | --- | --- | --- |
| 64 | 38.77% | 33.29% | 36.45% | 37.25% | 38.07% |
| 256 | 48.37% | 45.06% | 47.54% | 47.63% | 48.44% |
| 1024 | 55.23% | 54.81% | 55.05% | 55.05% | 55.42% |
| 4096 | 59.08% | 60.16% | 58.57% | 58.57% | 58.64% |
| 16384 | 60.64% | 60.65% | 60.01% | 60.01% | 59.97% |

What it says:

- **Neither form beats the cache.** The best, reuse with admission and 16 drawn, is 0.19 points
  over it at 1024 slots and 0.67 under it at 16384.
- **Counting every ask is the worse estimate.** A name brought in by one ask reads as asked once a
  sample, and a sample is ten times the cache size in asks: 6.4 seconds of the trace at 64 slots.
  A one-hour TTL multiplies that into a worth above a popular name's with a one-minute TTL.
- **The estimate is the whole difficulty.** The optimal knows when each name is asked next; this
  knows a count over a few seconds. The reading, which no measurement isolated, is that the count
  is too short-sighted to weigh against a TTL an hour long, and that tuning its window against
  this trace would fit the Zipf assumption rather than DNS.

It stays a model, and a real trace is what could say more.

### Against a real log

Every table above rests on the synthetic trace. `zig build bench-log -- <dataset.csv>` replays a
real one through the same code: "DNS Exfiltration Dataset" by Kristijan Ziza, Pavle Vuletić and
Predrag Tadić, version 3 on Mendeley Data (doi:10.17632/c4n7fckkz3.3), under CC BY 4.0, the log
of a national ISP's primary DNS server over 26.3 hours in June 2021. `bench/README.md` says where
to fetch it and the SHA-256 of the file measured here. Of its
35,074,151 rows, 174,779 are injected exfiltration traffic and are dropped. `bench/log_csv.zig`
reads it; measured 2026-09-22 on the machine §11 names, in eight and a half minutes.

Two clients are set aside as stuck in a loop, by a rule `bench/log_replay.zig` states: at least
a hundred thousand questions, nine in ten of them for one name. One asks `samba.local.local`
6,779,414 times in the day, a fifth of the log; the other asks `belbi.bg.ac.rs` for 94.4% of its
107,123. Every policy hits such a name nearly every time, so they would pad every table as though
they were a workload: before they were set aside, 1024 slots read 75.04% over every client
where it reads 68.94% without them. 27,992,378 questions remain, in time order throughout; the
whole log has 638,748 names and 35,987 clients.

The log is far more concentrated than the Zipf trace: over the whole log, loops and all, its
thousand most asked names carry 72.7% of the questions, while 62% of its names are asked once. It carries no TTLs, so each name takes one
from the synthetic mixture, twice over: by a hash of its name, which leaves TTL and popularity
unrelated, and by its rank, as the synthetic trace does. It is replayed two ways. Every client
through one cache is a recursive resolver's workload. The hundred busiest clients, which ask
16,720,927 of the questions, each through a cache of its own and summed, is closer to how cocuyo
is deployed: one process on one host. The columns are the cache, the SIEVE model that must match
it, S3-FIFO by Algorithm 1 line 23, W-TinyLFU, expected hits counting reuse with 16 drawn and
admission, and the optimal.

Every client, one cache, TTLs by hash:

| Slots | Cache | SIEVE | S3-FIFO | W-TinyLFU | Expected hits | Optimal |
| --- | --- | --- | --- | --- | --- | --- |
| 64 | 36.43% | 36.43% | 39.65% | 36.63% | 29.41% | 51.09% |
| 256 | 52.75% | 52.76% | 55.89% | 53.94% | 47.42% | 65.68% |
| 1024 | 68.94% | 68.95% | 70.75% | 70.36% | 65.06% | 78.47% |
| 4096 | 80.78% | 80.78% | 81.40% | 80.85% | 77.74% | 84.73% |
| 16384 | 84.69% | 84.69% | 84.70% | 84.47% | 82.92% | 85.13% |

The busiest hundred clients, a cache each, TTLs by hash:

| Slots | Cache | SIEVE | S3-FIFO | W-TinyLFU | Expected hits | Optimal |
| --- | --- | --- | --- | --- | --- | --- |
| 64 | 47.34% | 47.36% | 49.40% | 47.59% | 42.72% | 56.81% |
| 256 | 55.53% | 55.53% | 56.65% | 55.65% | 51.89% | 60.98% |
| 1024 | 59.98% | 60.02% | 60.51% | 59.93% | 57.53% | 61.99% |
| 4096 | 61.75% | 61.75% | 61.84% | 61.60% | 60.45% | 62.08% |
| 16384 | 62.07% | 62.07% | 62.07% | 62.05% | 61.56% | 62.08% |

Every client, one cache, TTLs by rank:

| Slots | Cache | SIEVE | S3-FIFO | W-TinyLFU | Expected hits | Optimal |
| --- | --- | --- | --- | --- | --- | --- |
| 64 | 36.41% | 36.41% | 39.56% | 36.57% | 29.34% | 51.08% |
| 256 | 52.51% | 52.52% | 55.46% | 53.57% | 47.22% | 65.50% |
| 1024 | 67.62% | 67.63% | 69.09% | 68.68% | 64.05% | 76.44% |
| 4096 | 76.55% | 76.55% | 76.56% | 76.46% | 73.66% | 78.01% |
| 16384 | 78.00% | 78.01% | 77.99% | 77.97% | 76.62% | 78.01% |

The busiest hundred clients, a cache each, TTLs by rank:

| Slots | Cache | SIEVE | S3-FIFO | W-TinyLFU | Expected hits | Optimal |
| --- | --- | --- | --- | --- | --- | --- |
| 64 | 43.54% | 43.54% | 44.16% | 42.97% | 38.48% | 48.83% |
| 256 | 47.64% | 47.68% | 47.73% | 47.62% | 43.60% | 49.26% |
| 1024 | 49.01% | 49.02% | 49.04% | 49.05% | 46.36% | 49.26% |
| 4096 | 49.26% | 49.26% | 49.26% | 49.25% | 48.02% | 49.26% |
| 16384 | 49.26% | 49.26% | 49.26% | 49.26% | 48.82% | 49.26% |

c-ares's rule, which evicts nothing, reaches 85.13% over every client with at most 28,810 entries
live, TTLs by hash, and 78.01% with at most 33,116, TTLs by rank.

What it says:

- **Where cocuyo is deployed, SIEVE is close to the best there is.** A cache a client, at
  1024 slots, is 2.0 points under the optimal with TTLs by hash and a quarter of a point
  with TTLs by rank. Past 4096 slots nothing is left to win. S3-FIFO gains 0.5 points at 1024
  and 2.1 at 64; W-TinyLFU nothing.
- **At a resolver's scale S3-FIFO earns its place.** Every client through one cache, it leads
  SIEVE by 3.2 points at 64 slots, 3.1 at 256 and 1.8 at 1024 with TTLs by hash, 1.5 at 1024 by
  rank, and the lead is gone by 4096. That is the workload its paper is about: many names asked
  once, which its probation queue keeps out.
- **The TTL rule moves the numbers and not the order.** Every policy ranks where it did under
  both rules; the rank rule lowers the ceiling, since the most asked names expire soonest.
- **Expected hits is worse everywhere**, by up to seven points: the count behind it is too
  short-sighted on real traffic too.
- **The control holds.** The SIEVE model is within 0.04 points of the cache in every row.

So the cache keeps SIEVE: in one process on one host, which is what cocuyo is, the most any
policy could add at 1024 slots is two points, and S3-FIFO's lead is a resolver's. This is
one log, from one ISP over one day, with TTLs it did not carry; a second log could say otherwise.
The busiest clients are weighed by what they ask.

### Memory

Per slot: two `Name`s at 256 each — the key, and since §17 question 13 the end of the CNAME
chain that reached the answers — an `Answers` at 2448 since §19 step 9 gave it the rdata buffer,
and 24 octets of scalars and padding: 2984, measured and pinned by a test in
`src/cache/cache.zig` (2728 before the chain's end, 568 before step 9). The key index is eight
octets an entry at two entries a slot, rounded up to a power of two. A thousand slots cost
2.9 MiB of slots and 16 KiB of keys; sixteen thousand, the most a `u16` slot index and the key
index allow at `cache_slots_max`, cost 46.6 MiB and 256 KiB. The caller chooses, and an address-only cache pays
for the buffer too, as §9 says of the lookup.

### Sizing the memory

Written on 2026-10-11, with §16 decision 37. A cache's memory is two things: `slots.len` slots,
from 1 to `cache_slots_max`, and a key index whose length is a power of two at least
`cache_keys_per_slot_min` times `slots.len`. `Cache.init` asserts both, and the engine's `init`
and `reinit` assert them of the memory they are handed (§19 step 13). Until that day a caller
worked the key index's length out by hand, and the engine did it in a function of its own that
no caller could reach. The `cache` module now says it once, for both:

- `keys_for(slot_count)` is the least key index a slot count takes: 2 for 1 slot, 4 for 2, 8 for
  3, 2048 for 1024 and 32768 for 16384. A longer index of a power of two is taken too, and buys
  shorter probes for 8 octets an entry.
- `slot_count_valid(slot_count)` says whether a cache takes that many slots. It refuses 0 and
  16385.
- `ttl_seconds_max_valid(ttl_seconds_max)` says whether a cache takes that cap. It refuses 0 and
  604,801: a cap is 1 second to seven days, `cache_ttl_seconds_max`, the cap RFC 8767 §4
  recommends. A cap read from a configuration file is input, as a slot count is.
- `Storage(slot_count)` declares both arrays for a count known when the caller compiles, and
  `slices()` hands them over. `Storage(0)` and `Storage(16385)` do not compile, and the error
  names the bounds. No step of the gate holds that, since a test cannot fail to compile: both
  were compiled by hand on 2026-10-11.
- `Slices` is the pair as `Cache.init` takes it, and `valid()` says what `Cache.init` asserts of
  it.

A caller whose count is known when it compiles writes two lines:

```zig
var cache_memory: cocuyo.cache.Storage(1024) = undefined;
var store = cocuyo.Cache.init(&cache_memory.slots, &cache_memory.keys, seed, config.cache_ttl_seconds_max);
```

A caller that reads the count at run time, from a configuration file, checks it and then gets
the memory however it gets memory. cocuyo allocates none of it (CLAUDE.md non-negotiable 2):

```zig
if (!cocuyo.cache.slot_count_valid(slot_count)) return error.CacheSlotsOutOfRange;
const slots = try allocator.alloc(cocuyo.cache.Slot, slot_count);
const keys = try allocator.alloc(cocuyo.cache.Key, cocuyo.cache.keys_for(slot_count));
const cache_memory: cocuyo.cache.Slices = .{ .slots = slots, .keys = keys };
```

A count outside the bounds, or a key index of the wrong shape, is the caller's programmer error
and stops the program at `Cache.init`, as a broken `Config` stops it at `assert_valid` (CLAUDE.md
non-negotiable 3). The number in a configuration file is input, so the caller refuses a bad one
with `slot_count_valid` before it reaches the assertion: the check and the assertion are two
claims about one bound (non-negotiable 6). The memory needs no value before `Cache.init`, which
writes every slot and every key, so `undefined` is enough.

### Limits

| Constant | Value | Why |
| --- | --- | --- |
| `cache_slots_max` | 16384 | a `u16` chain index with room for the sentinels, and a table nobody has asked for more of |
| `cache_keys_per_slot_min` | 2 | the load factor that keeps a bounded probe short |
| `cache_probe_max` | 16 | the longest chain a `get` walks before calling it a miss |
| `cache_ttl_seconds_max_default` | 3600 | c-ares's default cap, so a consumer replacing it sees the same ceiling; since 2026-10-11 `core`'s constant of that name, which is also the default of `Config.cache_ttl_seconds_max` (§12) |
| `cache_ttl_seconds_max` | 604800 | the most a cap may be: seven days, the cap RFC 8767 §4 recommends; `core`'s constant, since `Config` and the cache both hold a cap to it (2026-10-11) |
| `cache_sweep_steps_max` | twice the slots | one pass clears every bit, the next must find one |
| `cache_failure_seconds_min_default` | 5 | the first time a resolution failure is kept, the example of RFC 9520 §3.2, and the default of `Config.cache_failure_seconds_min`; `core`'s constant (§16 decision 60) |
| `cache_failure_seconds_least` | 1 | RFC 9520 §3.2: at least 1 second; `core`'s limit, since `Config` and the cache both hold the minimum to it (§16 decision 60) |
| `cache_failure_seconds_max` | 300 | RFC 9520 §3.2: not longer than 5 minutes, and where the backoff stops; `core`'s limit (§16 decision 60) |

### Checks

Every rule above is a test, and every test is broken by a mutation in `docs/mutations.md`. The
ones that matter most: a hit sets the bit and moves nothing; the hand evicts an expired entry
before an unvisited one; a visited entry survives one sweep and not two; a NODATA is cached for
the SOA minimum and not the cap; a probe longer than the bound is a miss and not a walk; and a
`get` after `flush` finds nothing.

## 19. Closing the gap with c-ares

c-ares 1.34.8 is what cocuyo replaces, and §1 lists what version one left out of it. On
2026-09-22 the owner decided to close that gap, and settled the four questions that shape how:

1. The engine that owns sockets lives in this repository, as a second module over rotor.
2. Every record type c-ares parses gets a typed decoder.
3. `/etc/hosts` comes in: parsed in `config`, consulted by the engine before a query goes out.
4. DNS cookies (RFC 7873) are on by default with EDNS, as they are in c-ares.

What c-ares does was read that day from its installed headers, `ares.h` and
`ares_dns_record.h`, and from `ares_init_options(3)`, which describe the behaviour a consumer
sees. Where a behaviour has no RFC, that documentation is the source the code names, the way §18
names `ares_qcache.c`.

### Where each piece goes

Four places, in order of preference, so the core stays what §1 made it:

- **The core**: `wire`, `resolver`, `config` and `cache`. I/O-free, allocation-free,
  deterministic, and where every protocol rule lands.
- **The engine**: a module of its own, `io`, in `io/` beside `src/`. It owns sockets, timers
  and connections through a loop with rotor's surface and nothing else, and it is the only
  place in this repository that may open a file or read the environment; the clock stays the
  caller's (non-negotiable 4). It imports `cocuyo` and `rotor`, and `src/` cannot import it. It
  is not exported, for the reason step 13 gives, and the gate compiles it against `sim`.
- **The consumer**: what only a particular program can decide.
- **Out**: with the reason, and where it would attach.

| c-ares | cocuyo before this section | Goes to | Step |
| --- | --- | --- | --- |
| `A`, `AAAA`, `PTR`, `CNAME` | asked for, followed | done | — |
| `NS`, `MX`, `TXT`, `SRV`, `SOA`, `HINFO`, `NAPTR`, `CAA`, `URI`, `TLSA`, `SVCB`, `HTTPS`, `SIG`, `ANY` | skipped, or read for one field | `wire` decoders, `Lookup` for any type | 9 |
| unknown types (`RAW_RR`) | skipped | `wire`, the raw rdata (RFC 3597) | 9 |
| `ares_expand_name`, `ares_expand_string` | `wire.name.decode`; no character-strings | `wire`, with `TXT` | 9 |
| OPT options: COOKIE, NSID, ECS, padding, extended error | OPT written, its options unread | `wire`, a typed reader for each | 10 |
| DNS cookies | none | a `wire` option, `resolver` per-server state | 10 |
| `ares_query` and `ares_search` | the search list applies by `ndots` | `Question.absolute` is the switch (§5) | — |
| `ARES_FLAG_USEVC`, `IGNTC`, `NORECURSE`, `NOCHECKRESP`, `PRIMARY`, `NO_DFLT_SVR`, `ARES_OPT_MAXTIMEOUTMS`, a TCP port per server | none; the maximum timeout is a constant | `Config` | 11 |
| the hosts file, `ARES_OPT_LOOKUPS`, `ares_gethostbyname_file` | none | `config.hosts` parses the consumer's bytes into a `core.Hosts`; `AddressLookup` keeps the `lookups` order | 11, 14 |
| `ARES_OPT_RESOLVCONF`, `RES_OPTIONS`, `LOCALDOMAIN` | the parser takes bytes | the consumer reads them; `config` parses the option string | 11 |
| server failover | the next server on a failure, in a fixed order | `resolver` per-server state | 12 |
| `udp_max_queries` | one port hint per lookup | engine | 13 |
| TCP reuse (`STAYOPEN`) and pipelining | one connection per query | engine; the framing is there (RFC 7766 §6.2.1) | 13 |
| local address binding, socket buffer sizes | none | `Config`, applied by the engine | 13 |
| device binding by name | none | out: rotor opens the sockets and names no device | — |
| the event thread, `sock_state_cb`, `ares_process_fd`, the socket callbacks | `Resolver`, driven by the caller | the engine over rotor, in the caller's loop and on no thread of its own (§16 decision 27) | 13 |
| `ares_cancel`, the active count, wait-empty, `ares_reinit`, `ares_set_servers` | `Lookup.cancel` | engine | 13 |
| the query cache, `ARES_OPT_QUERY_CACHE` and its `qcache_max_ttl` | §18 | the engine builds it over memory the caller hands `init` and `reinit`, or runs with none; the cap is `Config.cache_ttl_seconds_max` (2026-10-11) | 13 |
| `ares_getaddrinfo`: `A` and `AAAA` together, the canonical name, numeric host and service, the hosts file, `V4MAPPED`, `ALL` | two lookups | `resolver`, as `AddressLookup` above the table | 14 |
| `ares_gethostbyaddr`, `ares_getnameinfo` | a `PTR` lookup | `NameLookup` in `resolver`; service names are out | 14 |
| RFC 6724 ordering, off with `ARES_AI_NOSORT` | none; `sortlist` was rejected in §16 | `core.address_order`, over routes the consumer learned; `no_sort` skips it | 15 |
| `ARES_AI_ADDRCONFIG` | none | out: rotor enumerates no interfaces, and the consumer knows its own | — |
| service names (`getservbyname`) | none | out: `/etc/services` is the consumer's; the engine takes a port | — |
| `HOSTALIASES`, `ARES_AI_ENVHOSTS` | none | out for now: glibc's alias file, rarely set; a parser in `config` if asked | — |
| the IDN flags | none | out: no IDN (§16); a caller sends A-labels | — |
| classes `CHAOS` and `HESIOD` | `IN` only | out: `version.bind` is a debugging query, not a resolver's | — |
| macOS SystemConfiguration, the Windows registry, Android | `resolv.conf` only (§14) | out: §14 stands | — |
| custom allocators, `ares_library_init`, `ares_dup`, `ares_save_options` | no allocation | out: nothing to configure | — |
| `ares_threadsafety` | one table, no lock | one engine per loop per thread (rotor decision 4) | 13 |

### Step 9: every record type

`Kind` grows to every type c-ares names, each with the RFC that defines its fields:

```zig
pub const Kind = enum(u16) {
    a = 1,      // RFC 1035 §3.4.1
    ns = 2,     // RFC 1035 §3.3.11
    cname = 5,  // RFC 1035 §3.3.1
    soa = 6,    // RFC 1035 §3.3.13
    ptr = 12,   // RFC 1035 §3.3.12
    hinfo = 13, // RFC 1035 §3.3.2
    mx = 15,    // RFC 1035 §3.3.9
    txt = 16,   // RFC 1035 §3.3.14
    sig = 24,   // RFC 2535 §4.1, kept by RFC 2931
    aaaa = 28,  // RFC 3596 §2.2
    srv = 33,   // RFC 2782
    naptr = 35, // RFC 3403 §4.1
    opt = 41,   // RFC 6891 §6.1.2, never a question
    tlsa = 52,  // RFC 6698 §2.1
    svcb = 64,  // RFC 9460 §2.2
    https = 65, // RFC 9460 §9
    any = 255,  // RFC 1035 §3.2.3, a question and never a record; RFC 8482 §4 says what comes back
    uri = 256,  // RFC 7553 §4
    caa = 257,  // RFC 8659 §4.1
    _,          // any other code, since 2026-09-26 (decision 31)
};
```

A record of a type not in the enum is not an error and never was: the record walk keeps the type
code, and a caller reads the rdata raw (RFC 3597 §3). Since 2026-09-26 a question may name such a
type too: the enum is open, `Kind.of(code)` is any code, and `Kind.from_code` still answers only
for the types cocuyo names.

**What a lookup keeps.** `Lookup` keeps the records of the type asked for, owned by the end of
the CNAME chain (RFC 5452 §6, as today), and copies them out of the message, because the message
buffer is the caller's and may be reused the moment `on_response` returns. Addresses and PTR
names keep their storage; everything else goes into a fixed rdata buffer of `rdata_bytes_max` octets with a
table of `records_kept_max` references, and the three share one union, because one question asks
one type:

```zig
pub const Answers = struct {
    kind: Kind,                    // the question's type, which picks the member (decision 34)
    items: extern union { addresses: [addresses_max]Address, names: [ptr_names_max]Name, records: Records },
    ...
};
pub const Records = extern struct {
    refs: [records_kept_max]Ref,   // type code, TTL, offset and length into `bytes`
    bytes: [rdata_bytes_max]u8,
    count: u8,
};
pub const Answer = struct {
    ...
    records: []const Record,       // the type asked for, each with its rdata, for the kinds kept in the rdata buffer
};
pub const Record = struct { kind_code: u16, ttl_seconds: u32, rdata: []const u8 };
```

The rdata stored is self-contained: names inside it are written out in full. Where the wire
allows a compressed name — the types of RFC 1035, which a receiver MUST decompress (RFC 3597
§4) — the collector decodes each name through `wire.name.decode`, with its two bounds, and
writes it uncompressed with the fixed fields around it. `SRV` (RFC 2782), `NAPTR` (RFC 3403
§4.1) and `SVCB` (RFC 9460 §2.2) forbid compression on the wire, and `SIG` a receiver SHOULD
decompress (RFC 3597 §4); cocuyo decodes through a pointer in all four, because decoding is
bounded and safe and a message that broke the sender's rule is otherwise readable. Rejected:
refusing it as malformed, which fails the lookup for a server's fault the caller cannot see.

**The typed views.** `wire.rdata` holds one decoder per type, each reading a self-contained
rdata slice with every length checked and asserted (§8), and each returning a struct of the
RFC's fields: `Mx{ preference, exchange }`, `Srv{ priority, weight, port, target }`, `Soa{
mname, rname, serial, refresh, retry, expire, minimum }`, `Caa{ flags, tag, value }`, `Svcb{
priority, target, params }` with a bounded iterator over the parameters and their keys (RFC 9460
§7), `Naptr{ order, preference, flags, services, regexp, replacement }`, `Tlsa{ usage, selector,
matching_type, data }`, `Hinfo{ cpu, os }`, `Uri{ priority, weight, target }`, `Sig{
type_covered, algorithm, labels, original_ttl, expiration, inception, key_tag, signer,
signature }`, `Ns`, `Cname` and `Ptr` as a name, `Txt` as a bounded iterator over
character-strings (RFC 1035 §3.3, which is `ares_expand_string`). `A` and `AAAA` stay
addresses. A view holds slices into the rdata it was given and copies nothing.

**Questions.** A question may name any type but three kinds of code, which `Kind.queryable`
refuses and `Question.from_text` answers with `Error.UnqueryableType`:

- Zero, which is never a type (RFC 6895 §3.1).
- OPT, a pseudo-record that belongs to a message and not to a name (RFC 6891 §6.1.1).
- Every other code from 128 to 255, the range RFC 6895 §3.1 keeps for query and meta types:
  AXFR, IXFR, MAILA, MAILB, TSIG and TKEY today. A record of one of them is not a type whose
  rdata can be kept whole (RFC 3597 §2), and a zone transfer is out of scope (§1).

ANY, in that range, is the exception: cocuyo reads it (RFC 8482). Every other code, a DNSSEC type
or a private one (RFC 6895 §3.1) among them, is asked as it is, and its records come back whole,
their rdata copied as the wire has it (RFC 3597 §3, §4). A question built as a literal must name
a queryable type, which the codec and the cache assert; `from_text` is where the check is. Asking
for `CNAME` keeps the CNAME record and follows nothing (RFC 1034 §3.6.2). Asking for `ANY` keeps every record the name owns whatever
its type, which may be one synthesized `HINFO` (RFC 8482 §4.2), and is `NoData` when there are
none. Every other kind follows the chain as `A` does today.

**Rejected alternatives.** Handing the caller a view of the message during `on_response`, which
copies nothing: it breaks the rule that `on_response` never changes what the caller does next,
because the records would be gone by the time `poll` says `done`. Keeping the whole message per
lookup: 64 KiB a slot. A caller-provided rdata buffer per lookup: the fallback if `rdata_bytes_max`
turns out too small for someone, because it changes `Lookup.init` and every slot.

**Gate.** Fixtures for every type from the RFCs' own examples where they give one (RFC 9460
Appendix D has test vectors), the fuzz corpus grown by each, and one mutation per field decoded.
Landed on 2026-09-22: `src/wire/rdata/`, `record_copy.zig`, `response_take.zig`; the sizes it
moved are in §9 and §18, its mutations in `docs/mutations.md`, and what the buffer cost until
`Answers.reset`, `Answers.assign` and `Lookup.init_in_place` in §11. Since 2026-09-26 the fuzz
generator writes a record of every type the codec reads, whole or with one octet changed, and a
record written whole must be taken whole (c4milo/cocuyo#23, `docs/mutations.md` FZ1 to FZ10).
The fixtures hold every example an RFC gives in its record's form: RFC 1035 §5.3 and §6.4.1, RFC
2782, RFC 3403 §6.1 and §6.2, RFC 6698 §2.3, RFC 7553 §5.1 and RFC 8659 §4.2. TXT and SIG have none
(RX1 to RX3). The codec's reading of 66 responses real servers sent is held against dnslib's, record
for record, by `zig build dnslib-check` (c4milo/cocuyo#22, DL1 to DL8, DT1 to DT12). It needs the
network, so it runs in CI's `dnslib` job and not in the gate.

### Step 10: DNS cookies

The COOKIE option (RFC 7873 §4) rides in the OPT record: a client cookie of 8 octets, and after
the first exchange the server cookie it answered with, 8 to 32 octets (§4.2; RFC 9018 §4 fixes
the length at 16 for servers that follow it, and a client reads only the length).

- A query to a server whose server cookie is not known carries a fresh client cookie, its
  transaction's own. Each transaction draws 64 bits for it from the lookup's seed, beside its id,
  port hint and case pattern (§7), and `core.mix` mixes the draw with the seed the `Servers`
  table was built with, the address and port the query goes to, and whether it goes over a
  stream. "The Client Cookie SHOULD have 64 bits of entropy", and "a client MUST use a different
  Client Cookie for each different Server IP address" (RFC 9018 §3). A client "MUST NOT send a
  previously sent Client Cookie to a server in the absence of an associated Server Cookie"
  (§8.1). So no fresh cookie goes out twice: a new transaction draws a new one, and a query that
  TC=1 or a second BADCOOKIE sends to TCP keeps its transaction and has a cookie of its own from
  the stream's mix. The caveat of §7 applies: the mix spreads a seed, it is not a cryptographic
  function, and the defence is against an off-path attacker who sees no cookie at all.
- When a response's COOKIE option echoes the client cookie the lookup sent and carries a server
  cookie, the server keeps the two as a pair: the client "should store the Client Cookie
  alongside the Server Cookie it registered for that server" (RFC 9018 §3). Every later query to
  that server carries the pair (RFC 7873 §5.1). A later response that echoes the pair's client
  cookie updates its server cookie. One that echoes another lookup's fresh client cookie with a
  server cookie replaces the pair, since both are pairs the server gave.
- A response without a COOKIE option to a query that carried a fresh client cookie, from a server
  that has given no server cookie, is a server without cookies. "When a server does not support
  DNS Cookies, the client MUST NOT send the same Client Cookie to that same server again.
  Instead, it is recommended that the client does not send a Client Cookie to that server for a
  certain period (for example, five minutes) before it retries with a new Client Cookie"
  (RFC 9018 §3). The answer stands, and queries to that server carry no COOKIE option for
  `cookie_silence_ns`, the five minutes of that example; EDNS0 stays on. After it, a query
  carries a fresh client cookie again. A server cookie learned meanwhile, from the answer to a
  query sent before the silence began, ends it. Only an answer the lookup takes starts the
  silence. A response without the option that the lookup then ignores, for an rcode cocuyo does
  not know or a malformed answer section (step 12), is taken as never received, and starts none.
- Per-server state, which nothing in cocuyo had before: the pair, the end of the silence, and the
  failover counters of step 12, in a `Servers` table of `servers_max` entries, with the seed it
  was built with. `Lookup.init` takes a pointer to it beside the config, because the config is
  shared and constant and this is neither; `Resolver` owns one and hands it to every lookup.
  Rejected: putting it in `Config`, which is immutable and shared, or in `Lookup`, which is per
  question.
- Each lookup records the COOKIE option the query it built carries: none, its own fresh client
  cookie, or the pair, with the client cookie's octets. Check 6 of §7 compares a response with
  that record, not with the table, which another lookup may change between the send and the
  answer. "It is RECOMMENDED that a client keep the Client Cookie it is expecting in a reply until
  there is no longer an outstanding request associated with that Client Cookie" (RFC 7873 §7.1).
  A lookup whose query carried no COOKIE option expects none back, and learns nothing from one.
- On a response (RFC 7873 §5.3): the client cookie in it must be the one sent, or the response is
  discarded, which lands in §7's checks as one more reason to ignore a message and never disturb
  the wait. A correct client cookie has its server cookie cached even when the response is an
  error: "If the COOKIE option Client Cookie is correct, the client caches the Server Cookie
  provided, even if the response is an error response (RCODE non-zero)" (§5.3). cocuyo caches it
  once the checks of §7 pass, before it reads the rcode or the answer section, so a response the
  lookup then ignores, for an rcode cocuyo does not know or a malformed answer section, teaches
  its server cookie all the same, and changes no failure count (step 12). A response with no
  COOKIE option is discarded when the client is expecting one, which cocuyo reads as: the query
  carried the pair, or the server has given a server cookie since. "If the client is expecting
  the response to contain a COOKIE option and it is missing, the response MUST be discarded"
  (§5.3). So a server that stops sending cookies has every answer discarded until the table is
  built again. c-ares instead accepts such answers again after two minutes (c4milo/cocuyo#36);
  cocuyo keeps the MUST.
- BADCOOKIE (extended RCODE 23) is retried once on the same server with the fresh server cookie:
  "The client SHOULD retry the request using the new Server Cookie from the response" (§5.3).
  Over UDP a second BADCOOKIE goes to TCP, the path `tcp_needed` already takes: "the client
  SHOULD retry using TCP as the transport" (§5.3). Over a stream the retry is a new transaction
  on the stream, and a second BADCOOKIE advances the server. The retry is the server's once,
  whichever transport took it, so a server that had it over UDP and answers BADCOOKIE again over
  TCP is advanced. Over DoH or DoQ a query carries no cookie (§22, §23), so there is no fresh
  server cookie to retry with, and BADCOOKIE advances the server.
- FORMERR from a server that rejects the option is what RFC 6891 §6.2.2's fallback already
  covers: the query is repeated without EDNS.
- cocuyo does not see a change of the client's address: it binds no socket, and a NAT hides the
  public one in any case (RFC 9018 §8.1). "Clients MUST NOT reuse a Client or Server Cookie after
  the Client IP address has changed" (RFC 9018 §3). A consumer that sees its address change
  calls the engine's `reinit`, or builds a new `Servers` table, and either way hands it a new
  seed from a CSPRNG. `reinit` builds the table again from the seed it is given, so the same seed
  draws the same fresh client cookies again: cookies already sent to those servers, which
  RFC 9018 §3 and §8.1 forbid. The engine must be idle first: a consumer with lookups in flight
  calls `cancel_all` and takes their failures, then calls `reinit` (`io/io_lifecycle.zig`).
  Either way every pair and every silence is forgotten, so the next query to each server carries
  a fresh client cookie. So is every latency sample, so each server waits `timeout_ns` again
  until it has 3 (§5), and every mark of a server that changes the case, so each is asked with
  0x20 again (§7). cocuyo adds no function of its own for it.

**Gate.** The fake server of `resolver/fixtures.zig` learns cookies: a good one, a wrong
client cookie, a malformed option, a BADCOOKIE once, twice, over TCP and over a stream under
`use_tcp`, and a server with none. A fresh cookie goes out per transaction and per transport, the
pair once a server cookie came, and none through a silence and a fresh one after it. A response
the lookup ignores teaches its server cookie and starts no silence. Mutations on each check.

Landed on 2026-09-22: `wire/edns.zig` writes and reads the option, `wire/response_opt.zig`
finds the OPT record, `resolver/servers.zig` holds the per-server state, and `on_response`
runs check 6 (§7). `Lookup.init` takes the `Servers` pointer, and the lookup is 3032 octets.

Changed on 2026-10-08 (c4milo/cocuyo#36). Until then each server's client cookie was made once,
from the table's seed and the server's address and port, and every query with EDNS0 carried it
for the life of the table, whether or not the server had ever answered with a server cookie. So
a server without cookies saw one client cookie on every query, which RFC 9018 §3 and §8.1 forbid
because it lets that server track the client. And a BADCOOKIE over a stream advanced the server
at once, so under `use_tcp` or DoT the retry RFC 7873 §5.3 asks for never happened. The
transaction now holds its cookie's draw, and the lookup its record of what its query carried;
the lookup is 3064 octets, a slot 3080.

### Step 11: configuration parity

`Config` grows the knobs c-ares exposes, each with c-ares's default so a consumer that set none
sees the same behaviour:

- `use_tcp` (`USEVC`): every query over TCP.
- `ignore_truncation` (`IGNTC`): a truncated UDP answer is taken as it is, and marked
  `truncated`, because records may be missing from it. The consumer is told, and the cache
  refuses it (RFC 1035 §7.4, c4milo/cocuyo#39).
- `recursion_desired` (`NORECURSE` clears it): the RD bit, on by default.
- `check_response` (`NOCHECKRESP` clears it): off, SERVFAIL, NOTIMP and REFUSED end the lookup
  as answers rather than moving to the next server.
- `primary`: only the first server is asked.
- `timeout_ns_max` (`MAXTIMEOUTMS`): the cap on every wait, measured or doubled per pass (§5).
  Its default is `timeout_ns_max_default`, 5 s, c-ares's, and the constant `timeout_ns_max`,
  30 s, is the most it may be set to. Until 2026-10-09 it capped the doubled wait alone, and the
  constant was its default. A `resolv.conf` or `RES_OPTIONS` `timeout:` longer than the cap
  raises the cap to it, and one shorter leaves it, so a configured wait of up to 30 s is kept
  whole and a cap set by hand is never lowered (§10).
- `servers` becomes `[]const Server`, a `Server` being an endpoint and a TCP port, zero meaning
  the same port, because c-ares configures the two ports apart.
- `lookups`: the order of `.file` and `.dns`, `fb` by default.

`Question.absolute` already is `ares_query` against `ares_search`: an absolute name skips the
search list (§5), so no flag is added.

`config.hosts` parses the hosts file's bytes into caller storage: `hosts_entries_max` lines of
one address and up to `hosts_names_per_entry_max` names, the first name canonical, as a
`core.Hosts` that answers `find(name, family)`, `canonical(name)` and `reverse(address)` (the
type moved to `core` in step 14). Its source is `hosts(5)`; no RFC
states the format, and the code says so. `resolv_conf.parse` gains an option for
`NO_DFLT_SVR`: with it, an empty server list stays empty instead of becoming `127.0.0.1`, and a
lookup with no server fails at once. The option-line parser is exposed so the engine can hand it
`RES_OPTIONS` from the environment, and `LOCALDOMAIN` replaces the search list the same way.

Landed on 2026-09-22: `Config` carries every knob above, `Lookup` honours each, `Server`
replaced `Endpoint` in the server list (the one API change of the step), `config.hosts` keeps
its names in one arena of the caller's storage with a `u16` offset each rather than a `Name` per
alias, `resolv_conf.parse_with` takes the default-server option, and `apply_options` and
`apply_search` serve `RES_OPTIONS` and `LOCALDOMAIN`. No row of §11 moved by more than its
band, so the table stands.

### Step 12: server failover

c-ares deprioritises a server that failed to answer, prefers servers with fewer consecutive
failures, and probes a failed one now and then. cocuyo keeps the count and the instant of the
last failure per server in the `Servers` table, orders a lookup's servers by the count, stable,
with rotation applied among the equals, and lets a failed server back in when
`failover_retry_delay_ns` has passed since its failure and the seed's draw says so, one query in
`failover_retry_chance`. A timeout, a failed send or connection, a DoH or DoQ request that ends
without an answer, and an answer that names the server's own failure each raise the count; any
other answer the lookup accepts resets it; a response the lookup ignores leaves it. c-ares
probes a failed server with a copy of the query alongside the real one, so a recovered server is
found without costing a real query a timeout. Rejected: it needs two transactions per lookup, and
§7's defences bind one; here the probing query is a real one, and the price is one timeout in ten
queries, after the delay, on a server that is still down. Since 2026-10-09 that timeout is a
latency sample as long as its wait (§5), so the wait of a server that stays down rises with each
probe up to `config.timeout_ns_max`, and a probe then costs its query that cap, 5 seconds by
default. Before, it cost the wait the server's record gave: 250 ms for one that had answered in
20 ms.

Landed on 2026-09-22: `Servers` counts consecutive failures per server with the instant of the
last, a timeout, a failed send and a failed connection each counting one and, until 2026-10-08,
an answer of any kind resetting it; `lookup_order.zig` computes a lookup's order at its first
poll, which is the first instant it has, and the order holds for the lookup. The lookup is 3040
octets.

Changed on 2026-10-08 (c4milo/cocuyo#37). An answer that marks the lookup's server failure
raises its server's count and sets the instant, as a timeout does. These answers are:

- SERVFAIL, REFUSED, NOTIMP and BADVERS while `check_response` is on.
- FORMERR from a server asked without EDNS0.
- BADCOOKIE over a stream once the server has had its retry, and BADCOOKIE over DoH or DoQ
  (step 10). The retry itself marks no failure: it has the fresh server cookie left to try.
- Since 2026-10-27, FORMERR with EDNS0 on and BADCOOKIE whose retry the bound of RFC 9520 §3.1
  forbids (§16 decision 58).

Any other answer the lookup accepts resets the count. With `check_response` off, the server's
error is the caller's answer (step 11): it marks no server failure, and it resets the count too.
A response the lookup ignores changes no failure count. It is ignored for an rcode cocuyo does
not know, or for an answer section that is malformed. The lookup takes it as never received: the
wait stands, as §16 decision 10 has it for a malformed one, and nothing it says of the server's
health is kept. Its server cookie is kept all the same. RFC 7873 §5.3 caches the server cookie of
any response whose client cookie is right, "even if the response is an error response", and
cocuyo caches it once the checks of §7 pass, before the rcode or the answer section is read
(step 10). An ignored response without a COOKIE option does not start the silence of step 10,
which needs an answer the lookup took.

Before, every response that passed §7's checks reset the count, and taught its cookie, before
its rcode was read. So a server that answered SERVFAIL to every query kept a count of zero, and
it stayed first in every lookup's order. Each lookup paid it a round trip and moved on. Three
things argued for the change:

- c-ares's features page says it tracks unrecoverable response codes, not only silence.
- §16 decision 25 has a refused connection or a failed handshake fail the lookup as a SERVFAIL
  answer does, and this step, as it landed, counts that connection against the server. A
  SERVFAIL answer reset the same count.
- The rule before left a server that fails every query ahead of one that answers.

What it gives up: a recursive server that answers SERVFAIL for one broken name, and well for the
rest, now counts that answer against itself. Later lookups start at a server with fewer
failures, until the retry draw lets it back in and its next good answer resets the count. A
lookup keeps the order it computed at its first poll for its whole search walk, as before.

### Step 13: the engine

The engine is the c-ares replacement in one import: the state machine, the cache, the config
parsers, and the sockets and timers under them, driven by a completion loop with rotor's
surface. It is rooted at `io/io.zig`, outside `src/`, which non-negotiable 1 keeps free of
sockets. Rejected: the engine in the consumer, which every consumer would then write; a third
repository, which is a third thing to pin; the engine under `src/`.

**The stream, landed on 2026-09-22.** `io/io_tcp.zig`: one connection per server, opened on the
first `connect_tcp` and shared by every lookup that needs it, their queries pipelined onto it
(RFC 7766 §6.2.1.1) and their answers matched back by the table's own demultiplexer. A stream
carries no message boundaries, so a connection holds the partial bytes and takes whole messages
out of them by the length prefix of §8; the buffer it assembles into holds a message of
`tcp_message_bytes`, the longest a prefix can describe unless the caller knows its answers are
smaller, and the two octets of its prefix. Since 2026-10-13 it holds one chunk more, or over TLS
the body of one record more (the stream's rule 11). A connection
nobody is using is closed after `tcp_idle_ns` (§6.2.3). The chunks arrive in a buffer group of
their own, since a datagram group carries rotor's prefix before every payload, and a group that
runs dry is the ordinary end of a receive rather than a broken connection.

**The stream's rules, written on 2026-09-23** from RFC 7766 and rotor's decision 5, for the engine
model to be written from, in Lean then and in `spec/tla/engine/` since 2026-09-24. They are what the engine is held to; where the code
of 2026-09-22 broke one, the model found it, and the fix is recorded with it.

1. One connection per server, in one of `tcp_connections` slots. A lookup that needs a stream to
   its server is put on that server's connection. If there is none, one is opened in the first
   closed slot, or else in the first slot whose connection has no lookups on it, which is closed
   to make room. When no slot can be had, the lookup waits for one that frees with no lookup
   leaving it (rule 12). In the clear, when none does, a connection with no lookups whose connect
   is in flight is closed. The lookup then waits for its slot (rules 10 and 12). Otherwise the
   lookup is told its connection failed. Since 2026-10-25 a lookup joins no marked connection,
   and a server can have a marked connection beside the one that a lookup joins. A lookup that
   finds no slot in the ways above waits for the slot of a marked connection (§16 decision 54).
2. Each opening of a slot is an incarnation, and every operation on the connection carries the
   incarnation in its `user_data`. An event for another incarnation belongs to a connection
   that is gone and changes nothing, whatever it holds: a cancelled connect can still end in
   success (rotor decision 5, rule 2). A provided buffer the event carries goes back to the
   loop all the same.
3. A lookup is on a connection only while it is on a stream to that connection's server. The
   drive takes it off before acting on its poll when the poll shows it anywhere else: its
   deadline passed, its connection failed, it moved to the next name, it ended. Since 2026-10-24
   a deadline ends `tcp_ready` too (§5, §16 decision 52). So a lookup whose query's send never
   ends leaves its connection at its deadline. A query that has started stays at the head of the
   queue until its send ends (rule 9). Since 2026-10-25, when the last lookup leaves while that
   send is in flight, the drive shuts the connection at once (§16 decision 53). When a lookup
   leaves while its own query's send is in flight, and another lookup stays, the drive marks the
   connection. No lookup joins it again, and its last leave ends it at once (§16 decision 54).
4. A connection's users are the lookups on it. When the last leaves, the connection is idle from
   that instant, and one idle for `tcp_idle_ns` is closed by the drive at an instant that late.
   Since 2026-10-20 a TLS connection that closes is idle from the instant it began to close. The
   same wait bounds it (§21, TLS rule 5; §16 decision 49). Since 2026-10-25 a connection whose
   last lookup leaves while the head's send is a query's has no wait: the drive shuts it then
   (rule 3, §16 decision 53).
5. When the connect succeeds, the receive is armed and every lookup on the connection that is
   still connecting is told. When the connect fails, the receive fails, or the peer closes,
   every lookup on the connection is told its connection failed and leaves it, and the
   connection is closed.
6. A send lends the lookup's send buffer to the loop until the send's final event (rotor
   decision 5, rule 3). No send is submitted from that buffer before then. A send asked for
   while the buffer is lent is held, and submitted when the buffer comes back if the attempt
   that asked for it is still the lookup's; otherwise it is dropped, and the lookup's next poll
   asks again. Since 2026-10-25 a query's send on a connection that is up holds the buffer past
   the next loop step only while a lookup is on that connection. At the last leave the drive shuts
   the connection, and the cancel's event gives the buffer back (rule 3, §16 decision 53).
7. A send's completion speaks for the attempt that made it: the lookup in the slot, on the
   transaction it had when the send was submitted. If the lookup has moved on, the completion
   returns the buffer and tells nobody.
8. The drive takes lookups in the table's ready order (§11), and the results reach `take` in the
   order the drive reported them.
9. A stream carries one send at a time, because rotor's contract says two sends in flight on
   one socket may reach the peer in either order, and a short one leaves a gap the other
   fills. A query joins its connection's queue in the order the drive asked for it, and the
   buffer is lent from then. The connection sends the queue's head. A send that comes back
   short sends the rest of the same message before the next one starts. A message finished,
   its buffer comes back, its attempt hears it went out if still current (rule 7), and the
   next one goes. A message whose lookup moved on before any of it went out leaves the queue
   and gives its buffer back; one that has started is sent to its end, since half a message
   would break the stream for every lookup on it. A send that fails, or that the loop refuses,
   fails the connection (rule 5). TLS needs the same order for its own reason: each record's
   nonce is its sequence number, so records reach the peer in the order they were sealed.
10. A connect borrows the address its connection slot holds, from its submission to its final
    event (rotor decision 5, rule 3), whichever incarnation made it, and a cancel changes nothing
    about that. A slot is not opened again while an earlier incarnation's connect is in flight:
    a closed slot waiting on one is not free, and a slot with no lookups on it is taken only
    when its connect has ended. Until 2026-09-23 a slot shut while connecting could be opened
    again at once, and the new address was written over the one the loop still held. A slot's
    reset sets its fields one by one and leaves the address as it is: until 2026-10-01 the reset
    assigned the whole slot, which in a safe build wrote over the address too, and filled the
    64 KiB frame at every opening and shut (`io/io_reset.zig`).
11. Written on 2026-10-13. A connection takes each chunk whole into its frame. Then it hands every
    whole message in the frame to the table, oldest first, before the chunk's event ends. The
    partial message after them stays for the next chunk. So between two chunks the frame holds one
    partial message at most. A stream carries no boundaries, and a server may send its answers back
    to back (RFC 7766 §6.2.1.1). So the chunk that ends a message can start the next one. The frame
    holds a message of `tcp_message_bytes`, its prefix, and what one take adds after a partial
    message. In the clear that is one chunk, `tcp_frame_room_bytes_max`. Over TLS it is the body of
    one record at its longest, `tls_frame_room_bytes_max`. The session opens a whole record into the
    frame (§21, TLS rule 7). A prefix that says more than `tcp_message_bytes` fails the connection
    when it arrives. That message is never whole, and the stream cannot be read past it. Every
    lookup on the connection hears the failure at once. In the clear the connection closes at once.
    Over TLS the peer is still there, so the session says `close_notify` first (TLS rule 5). Each
    message is at least its two-octet prefix, so a frame holds at most `tcp_messages_per_frame_max`
    whole messages. That count bounds the loop over the frame, and the loop never stops before the
    last whole message.

    Until 2026-10-13 the frame held the message and its prefix alone. A connection refused a chunk
    that did not fit beside the partial message, and it did so before it handed a whole message
    over. Take a chunk that ends a message of L octets and holds h octets of the next. A sound
    stream failed when L + h passed `tcp_message_bytes`. At the default, L is then 63,489 octets or
    more. At a `tcp_message_bytes` of 4,096, two answers of 2,050 octets each are enough. The
    loop also stopped after 32 messages, `tcp_messages_per_chunk_max`. The rest stayed in the
    frame until the next chunk. When no chunk came, a lookup whose answer was among them waited
    until its deadline. The engine model holds no frame. It applies a message at the receive that
    brings it, so the code now does what the model does, and the model does not change.

12. Written on 2026-10-18 (§16 decision 46), and amended on the same day after its review. A
    query's send joined the sends that hold a closed slot on the same day (§16 decision 47). A slot
    is pending when no lookup is on it and it frees with no lookup leaving it. Two kinds of slot
    are pending:

    - a connection that closes once its alert or its `close_notify` has gone (§21, TLS rules 4
      and 5);
    - a closed slot whose memory the loop still holds: a connect that was cancelled (rule 10), or
      a send from the records buffer, of the session's own records or of a query's (TLS rule 3).

    A lookup that finds no free slot waits while a slot is pending. In the clear, when no slot is
    pending, the lookup closes the first connection with no lookups whose connect is in flight.
    That cancels the connect, as the idle close does (rule 4), and the slot is then pending. When
    the lookup can have no slot in either way, it is told its connection failed. In the clear each
    slot then holds a lookup. Over TLS no connection is closed to make room (TLS rule 6). Each
    server has at most one connection that a lookup may join, and a TLS configuration has a slot
    for each server. So over TLS a slot is always free or pending, and no lookup is told that.

    Since 2026-10-25 a marked connection holds a slot that frees too (§16 decision 54). No lookup
    joins it, and its lookups leave by their deadlines. Its last leave ends it, and its slot then
    frees, or is pending. A lookup that can have no slot in the ways above waits for that slot,
    and is told its connection failed only when no marked connection holds a slot. Over TLS a slot
    is then always free, pending or marked, and still no lookup is told that.

    The lookup waits in `connecting_tcp`, on no connection, and its deadline still bounds the wait
    (§5). At the end of each drive, after the idle close, the drive admits each lookup that waits,
    in the order of the table's slots. The lookup joins its server's connection, or opens one as
    rule 1 says. When it can have no slot, or the socket or the connect is refused, it waits for
    the next drive.

    In the clear a lookup can wait while no slot is pending. A slot that frees can go to a lookup
    that asks in the polls of that drive, before the drive's end. Each slot may then hold a
    lookup. The lookup that waits is admitted at the end of the drive after one of them leaves, or
    its deadline moves it on.

    The wait relies on the end of an operation that the loop holds. A connection that closes frees
    its slot when its last send ends. A closed slot frees at the event of its connect or its send.
    Since 2026-10-20 a time bounds each (§16 decision 49). The drive shuts a connection that has
    closed for `tcp_idle_ns`. Each way that ends a connection cancels its send, and the slot frees
    at the cancel's event. A lookup that still waits gets the slot at that event.

    Until 2026-10-20 no time bounded the wait. Take a peer that stops reading and keeps its side
    open. It held a TLS connection in `closing`, and a lookup that waited for that slot waited until
    its deadline. A send held a closed slot in the same way after its connection failed. Each way
    that ends a connection now cancels that send too.

    After each drive a lookup waits only while its server has no connection that it may join. The
    drive's end would have joined it to one. Between two drives a connection opens only through
    `connect_again`, for a TLS connection that waits to connect again (TLS rule 8). A lookup may
    join that connection, so a lookup of its server that waited joined it before. Each connection
    that a drive opens is still connecting at the drive's end. So the end of a drive never admits a
    lookup to a connection that is up, and no lookup is ready again after the polls.

    Until 2026-10-18 a lookup that found no free slot was told at once. Over TLS a lookup's second
    pass could come while the connection of its first pass still said its alert. That pass never
    reached the server. The lookup kept `connect` as its cause, and that local failure replaced
    the cause the server gave (§5, The cause of a failure). In the clear a connect that outlasted
    its lookup's wait held the slot the same way. With one slot, the next server got none.

**The datagram's rules, written on 2026-09-23** in the same way, for the same model. Rules 6 to 8
of the stream hold for datagrams as they stand: a send lends its buffer, a completion speaks for
the attempt that made it, and the drive goes on until nothing is left.

1. One socket per server, each with one multishot receive into the datagram group. A socket that
   is open always has a receive armed, or gets one at the next drive: a receive that ends is
   armed again, and one the loop refuses is asked for again at the next drive, not forgotten.
   Written on 2026-10-27: a receive can end on the event that carries a datagram, as rotor's
   io_uring backend ends one. The engine reads that datagram first, then arms the receive again.
   The same holds for a QUIC connection's receive and for a DoH link's.
2. Each arming of a receive is a generation, carried in its `user_data`. An event of another
   generation belongs to a receive that is gone and changes nothing, whatever it holds: a
   cancelled multishot receive can still deliver datagrams before its final event (rotor
   decision 5, rule 2).
3. Every event that carries a buffer gives it back before the event is over, whatever the event
   is for: a datagram once the table has read it, whatever its length, cut or whole (rule 6), and
   a stale event's at once.
4. A port that has carried `udp_queries_per_port` queries is replaced at the end of the drive
   that sent its share, whoever waits on it. A new socket on a new port takes every query from
   then on, and the old one drains: it keeps its receive, since the answers to its queries come
   back to it, until no lookup that sent from it still waits for an answer or has a send in
   flight from it. Then its receive is cancelled and it is closed. A server has one socket
   draining at most, so a port that carries its share while an older one still drains carries
   queries on until that one is closed. The new socket is opened before the old one steps
   aside: when it cannot be opened, the old one stays in use and the replacement is tried again
   at the next drive, so a server always has a socket to send from.
5. A draining socket's receive is held to rule 1 as the current one's is.
6. Written on 2026-10-14 (§16 decision 43). A buffer of the datagram group holds 1,856 octets of a
   datagram: `buffer_bytes_max`, 2,048, less rotor's prefix of 192. The kernel cuts a longer
   datagram to that room, and marks it as truncated. The engine reads the mark of each datagram that
   a server's socket receives. It gives a cut datagram to the table's `on_datagram_cut`, and each
   other datagram to `on_datagram` (§7, A datagram that the buffer cut). A QUIC connection's socket
   is not a server's socket of these rules: colibri reads its datagrams (§24, request rule 1).
7. Written on 2026-10-14 (§16 decision 44). The room of rule 6 is `udp_payload_bytes_max`: what
   rotor's `payload_capacity` gives for `buffer_bytes_max` under `group_options`. "The requestor
   SHOULD place a value in this field that it can actually receive" (RFC 6891 §6.2.3). So `init`
   and `reinit` refuse a configuration whose `udp_payload_bytes` passes the room. Each returns
   `error.UdpPayloadTooLarge`, and the check comes before the call changes anything. A refused
   `init` leaves no engine, as each failed `init` does. A refused `reinit` leaves the engine as it
   was. It keeps its configuration, its tables, its cache and the memory of that cache. It also
   keeps its sockets and its connections, each with its receive. The rule holds for each
   transport, since each query with EDNS carries the size (§17 question 50).

**Checked on 2026-09-23.** The engine model, in Lean then and in `spec/tla/engine/` since
2026-09-24, holds both sets of rules above. Each lookup is the model of §5, and around the lookups sit
the table's ready list and free list (§11), the connections, the sockets, and the operations the
loop holds. A configuration asks every query over TCP, or every query over UDP with a port
replaced every two queries. The model's clock moves in ticks, each the idle close's wait, and a
lookup waits two of them. The loop may refuse every submission for the length of one event, and
socket opens may fail for the length of one event. A stream's send may come back short once a
message, its rest then whole or failed: a second short send takes the same path as the first.

- The Lean walker, `cocuyo-spec engine` until it retired on 2026-09-24, walked every state the model
  reached in a configuration and checked ten invariants in each. TLC checks fifty now, the
  request rules' of §24 and the channel's among them (spec/README.md). A connection's users are the
  lookups on it. A lookup is only on a connection to its server. A buffer is lent to one send at
  most. A connection and a socket each have at most one current operation of each kind. A drive
  leaves nothing on the ready list. After a drive nothing refused, every socket has its receive
  armed and every connection that is up has its receive. And after such a drive, a port that has
  carried its share is replaced unless an older one still drains, and a draining socket nothing is
  owed on is gone. A stream has one send in flight at most, its queue's head's, and no query waits
  twice. A slot whose address a connect that is gone still borrows stays closed. They held in every
  state of one slot and one connection over TCP, and in all 5.85 million of one slot over UDP;
  spec/README.md has the counts. This is model checking over bounded configurations, not a proof.
- The replay drives the engine over the twin in manual mode, where the loop ends each operation
  when and how the walk says, and refuses what the walk says. It runs 16,000 walks and 3.2
  million events, 4,000 walks of them over TLS since 2026-09-24. After each event it compares the engine's whole state with the model's, and
  checks every buffer the event handed the engine is back in its group.

**Moving to TLA+, ruled on 2026-09-24** (§16 decision 24, issue #9). The model moves to
`spec/tla/engine/`, checked by TLC through pepegrillo's `tla` tool, and the Lean one above is
retired once the TLA+ one stands. The loop's operations become a bag, so TLC counts a state and
its operations reordered as one, as the Lean walker learned to the same day. The port is held to
the Lean model by count: for each configuration and bound, TLC's distinct states must equal the
Lean walker's with its operations sorted. Then the replay reads its walks from TLC's traces
rather than the Lean model's, and CI's `spec` job runs TLC. The model landed the same day: its
count equalled the Lean walker's in all six configurations it was first held to, over TLS, TCP
and UDP, and TLC finds each of the Lean model's TLS mutations with the check that caught it. The
replay followed the same day: TLC's simulation mode takes seeded walks through the model
(`spec/tla/engine/EngineTrace.tla`), and the replay drives the engine down them. TLC's walks are
uniformly random where the Lean walker sought states no walk had reached, so its short walks
catch fewer of the engine's mutations. The committed walks keep the full run's walks that catch
the ones they miss. The full run catches three mutations only the twin tests caught before, and
misses one the Lean walks caught, which no walk the model allows can reach (docs/mutations.md).
Then the Lean model retired. CI runs `zig build spec` in its `spec` job, and `zig build tla` in a
`tla` job beside it. The check then took four configurations of two lookups. The Lean walker had
walked one of them, TCP with one connection, and no TLS or UDP one. They showed rule 9's removal
of a waiting query was kept but never checked; the model checks it now.

The code of 2026-09-22 broke eleven of these rules, each fixed with the model:

- A cancelled connect or receive that ended after its slot was reused was taken for the new
  connection's own (the stream's rule 2).
- A lookup whose deadline passed kept its old server's connection, and was sent on it (rule 3).
- A send's completion was told to whatever attempt the lookup was on by then, and a new lookup in
  a slot wrote into a buffer the loop could still be reading (rules 6 and 7).
- The drive stopped after one poll a slot, so a lookup whose connection was already up was left
  with its query unsent (rule 8).
- A stale event on a stream did not give its buffer back.
- The table's deadline bound missed a wait a poll starts (§11), so no timer was armed for a
  connect.
- A receive a replaced socket left behind kept the buffer of a datagram it delivered after its
  cancel, so every port replacement under load could take a buffer from the group (the
  datagram's rules 2 and 3).
- A receive the loop refused to arm again was forgotten, so its socket or its connection heard
  nothing more (the datagram's rule 1).
- A port whose replacement could not be opened left its server with no socket, and the next send
  to it stopped the program on an assertion (the datagram's rule 4).
- Every query pipelined onto a connection was sent at once, and a short send was taken for a
  whole one, so under backpressure the queries could interleave or be cut and the length
  prefixes stopped lining up (the stream's rule 9).
- A slot shut while connecting could be opened again at once, and the new address was written
  over the one the cancelled connect still borrowed (the stream's rule 10). The model found it
  in two events: a lookup's connect outlasts its deadline, and its retry to the next server
  takes the same slot.

The model also showed what the first rule 4 left open: nothing made a retiring port rotate while
its server stayed busy. §17 question 15 put it to the owner, who answered it the same day, and
rule 4 now replaces the port at once and lets the old one drain; the eighth invariant holds the
model to that, and the first check of it found the model's own order wrong, a draining socket
owed nothing kept for a drive. The missing-socket path of the first rule 4 went with it: the new
socket is opened before the old one steps aside, so a server always has one.

**Checked on 2026-10-14.** Until then no configuration of the engine model held a truncated UDP
answer, so in the model no lookup went from a socket to a connection. The model holds no octets.
It holds the datagram's rule 6 as two more replies of a datagram. One is TC set, and one is a cut
datagram that passes the checks of a cut datagram (§7). Each sends its lookup to TCP on the same
server. The operator `Truncates` offers them, and three configurations set it:

- `Engine_truncated_1_1_bound_4_1`: one lookup over UDP, one connection, four operations and one
  failure. TLC finds that every check holds in its 426,197 states. It reaches a lookup that waits
  on a stream, and a lookup that moved to a stream after its query left a draining socket.
- `trace/Trace_udp_truncated_1_1`: the walks of the replay, which hands the engine each cut
  datagram as the kernel does, cut to the room and marked. Its walks come last in the run, so no
  walk that was picked before moves.
- The mutant OA34: a draining socket stays open while its lookup waits on a stream. TLC finds the
  check of rule 4 broken within 1,000 distinct states, and finds no break without `Truncates`.

Every other configuration holds the states that it held before, and TLC writes the same walks
for it (spec/README.md; docs/mutations.md, The owner's answers of 2026-10-14).

**Checked on 2026-10-18.** The model holds the stream's rule 12 (§16 decision 46). Each slot of the
table says whether its lookup waits for a connection slot. `Want` waits while a slot is pending,
and `Admit` runs at the drive's end, after the idle close. Four checks hold it:

- a lookup that waits is in `connectingTcp`, on no connection;
- after a drive with nothing refused, a lookup waits only while no slot is free and its server has
  no connection to join. A slot is then pending, or in the clear each slot holds a lookup;
- no lookup in `connectingTcp` is on a connection that is up;
- no lookup is told its connection failed for want of a slot over TLS, or in the clear while a slot
  has no lookup on it. A refused socket or submission is not judged.

Every configuration over TCP or TLS holds more states, since a lookup that failed there now waits.
The configurations of UDP alone, of DoQ and of DoH hold the states that they held before. The
mutants TS11 to TS13 break the rule three ways, and TLC finds each (spec/README.md). The trace
writes a lookup that waits as `cw`, so a walk with no wait is written as before. Of the committed
short walks, 11 hold a wait, and only they changed.

After the review of the same day, `FreeConn` closes a connection that no lookup is on while its
connect is in flight. It does so in the clear, when no slot is pending. Three configurations in the
clear hold fewer states than the first form of the rule, and those over TLS hold the same. With two
slots and two servers a slot is always free or pending then, so `Engine_tcp_2_2_bound_4_1` holds the
same states too. The mutant TS18 keeps `FreeConn` as it was, and TLC finds "slot waited for" broken.
Ten of the short walks changed again, each in the clear with one connection slot. The picks were
chosen again, and are now fifteen (spec/README.md).

On the same day a query's send began to lend its connection's records buffer (§16 decision 47;
§21, TLS rule 3). Each operation of the model names the buffer that it reads, and the check
"records lent" holds the rule. Three configurations over TLS changed their counts, and 16 walks of
the full run changed. Walk 16271 is one of them, and it is the sixteenth pick (spec/README.md).

**The rest of the engine, landed on 2026-09-22.** `cancel_all` ends every lookup at once, which
is `ares_cancel`, and each failure comes through `take` like any other. `reinit` takes a new
configuration, which is `ares_reinit`: it empties the cache, whose answers came from servers that
may be gone, closes the streams and opens the sockets again. It builds the `Servers` table again
too, so every server's latency samples start over and its wait is `timeout_ns` until it has 3
(§5), and a server marked as one that changes the case is asked with 0x20 again (§7). It
requires an idle engine, because a lookup in flight was started against servers that are going
away and its handle names a slot the new table has never heard of; a caller with lookups in
flight calls `cancel_all` and takes their failures first, which is what tells it what it lost.
`Config.udp_queries_per_port` is c-ares's `udp_max_queries`: a port that has carried its
share is replaced at once, and the old socket drains, keeping its receive until the last query sent
from it has its answer or its end (the datagram's rule 4). `Config.local_address` is
`ARES_OPT_LOCAL_IP4` and `LOCAL_IP6`, and `socket_receive_bytes` and `socket_send_bytes` are the two
buffer sizes, which rotor 0.2.0 made expressible. What a kernel grants is rarely what it was asked
for: Linux doubles and caps, macOS grants and then refuses, and a socket that would not take the
size is used with the size it has, because a buffer smaller than the caller wanted loses datagrams
and a socket that was not opened loses every one. Binding to a device by name stays out: rotor names
no device.

Three stale-event guards came with it, each the same shape as the timer's generation: a send
completion the engine is not waiting for, a receive from a socket that has been replaced, and a
connect or a chunk on a connection that is closed. A `reinit` or a port replacement is exactly
when the loop still holds events for things that are gone.

**Held back on 2026-09-22.** The owner ruled that no library bound to rotor is exposed until a
consumer asks for one: none does today, and every consumer so far drives `Resolver` from a loop
of its own. So the engine is not an exported module, no build option fetches rotor for it, and
`build.zig.zon` does not ship `io/`. What lands is the engine compiled against the twin below,
under `zig build test-io`, which is the gate this step promised: every path of the library
driven from a seed through a loop of rotor's shape. The engine itself names nothing of the
twin; only its tests do, and they compile only when the twin is the `rotor`. The day a consumer
asks, the build's `rotor` import is the one line that changes. A consumer asked on 2026-09-25,
and §24 exports the engine into the caller's loop (§16 decision 27). The first slice landed that
day: the UDP path, the buffer group, one timer, the cache in front, and the twin with its
scripted servers. The TCP path, port rotation, `reinit` and `cancel_all` follow.

```zig
pub const Engine = struct {
    pub const Options = struct {
        // 1 to `lookup_slots_max`: since 2026-10-14 any other count does not compile.
        lookups: u16 = engine_lookups_default,
        // No `cache_slots` since 2026-10-11: the cache's memory is the caller's (decision 37).
        tag: u16 = engine_tag_default,          // the high bits of every user_data the engine submits
        udp_queries_per_port: u32 = udp_queries_per_port_default,
        tcp_idle_ns: u64 = tcp_idle_ns_default,
    };
    pub fn memory_bytes(options: Options) usize;
    /// Since 2026-10-14 a `config.udp_payload_bytes` above `udp_payload_bytes_max`, 1,856 octets,
    /// is refused. The call then changes nothing (the datagram's rule 7).
    pub const InitError = error{ SocketFailed, ReceiveFailed, UdpPayloadTooLarge };
    /// `cache_memory` is the cache's slots and key index, or null for an engine with no cache.
    pub fn init(self: *Engine, memory: []align(alignment) u8, loop: *rotor.Loop, config: *const Config,
        hosts: ?*const Hosts, cache_memory: ?cache.Slices, seed: u64, now_ns: u64, options: Options) InitError!void;
    pub fn deinit(self: *Engine) void;

    pub fn start(self: *Engine, question: Question, now_ns: u64) error{Full}!Handle;
    pub fn address_info(self: *Engine, name: []const u8, port: u16, flags: AddressInfoFlags, now_ns: u64) error{Full}!Handle;
    pub fn name_info(self: *Engine, address: *const Address, now_ns: u64) error{Full}!Handle;
    pub fn cancel(self: *Engine, handle: Handle) void;
    pub fn cancel_all(self: *Engine) void;
    pub fn active(self: *const Engine) usize;

    /// One completion event. True when it was the engine's; false hands it back to the caller.
    pub fn apply(self: *Engine, event: rotor.Event, now_ns: u64) bool;
    /// The results ready since the last call, one per call, until null. Pointers in a result
    /// are valid until the next call.
    pub fn take(self: *Engine, now_ns: u64) ?Result;
    /// New configuration: the cache is flushed, the sockets rebound, and the latency samples and
    /// the marks of servers that lowercase the name forgotten, which is `ares_reinit`. The cache
    /// is built again over `cache_memory`: the same memory, other memory, or none.
    pub fn reinit(self: *Engine, config: *const Config, cache_memory: ?cache.Slices, seed: u64, now_ns: u64) InitError!void;
};

pub const Result = struct {
    handle: Handle,
    outcome: union(enum) { answer: Answer, address_info: AddressInfo, failure: Failure },
};
```

- **Sockets.** One UDP socket per server, bound to an ephemeral port the seed chooses, with one
  multishot receive into a buffer group, as the example does today; after
  `udp_queries_per_port` queries a new socket on a new port replaces it, which is
  `udp_max_queries`, and zero, the default, never replaces it. One TCP connection per server,
  opened on the first `connect_tcp`, pipelined (RFC 7766 §6.2.1.1) with answers matched by
  transaction id through the table, and closed after `tcp_idle_ns` with no query in flight
  (§6.2.3 has clients keep that short).
- **Time.** `Resolver.next_deadline_ns` becomes one rotor timer the engine re-arms as it moves,
  so the caller's `tick` waits for whatever the loop is waiting for and never for cocuyo alone.
- **Results.** A bounded queue the caller drains after applying the tick's events. Rejected:
  a callback per lookup, which is a function pointer and a context the consumer has to keep
  alive, where the consumer already loops on `tick`.
- **The cache.** `start` and `address_info` ask it first; a hit is a result on the next `take`,
  and a lookup that ends puts its answer, or its negative answer with the TTL of §18. Since
  2026-10-11 that holds for an engine handed memory for a cache, and an engine handed none asks
  its servers every time (The cache's memory, below). Since 2026-10-28 a lookup that ends in a
  resolution failure puts it too, and a hit on it ends the lookup with its error (§16 decision
  61).
- **Threads.** One engine per loop, and one loop per thread (rotor decision 4). Work from other
  threads arrives through rotor's `post`, which is the consumer's to arrange.
- **The deterministic twin first.** rotor's decision 10 has a backend be a module carrying its
  surface, so `sim` gains a loop with that surface — `submit`, `tick`, `cancel`, the buffer
  groups — over the scripted server and the virtual clock, and the build compiles the engine a
  second time with the twin as its `rotor`, the way stompy's log runs on its simulator. The
  engine is written against the twin and then run on rotor, so every path is driven at every
  seed before a real socket exists.

**Gate.** The twin over many seeds: many lookups in flight, datagram loss, truncation and the
TCP path, timeouts, cookies and failover, with the invariants checked after every event and the
trace byte-identical on replay; and one live test against real servers, opt in, because the
gate must not need the network.

**The cache's memory, ruled on 2026-10-11** (§16 decision 37). Until then the engine held its
cache's slots and key index inside itself, sized by `Options.cache_slots` when the engine's type
was built. So the size could not come from a number read at run time, an engine could not run
without a cache, and the cap on a TTL was the constant of an hour. These rules replace that:

1. `init` and `reinit` each take `cache_memory`, a `?cocuyo.cache.Slices`: the slots and the key
   index as `Cache.init` takes them (§18, Sizing the memory), or null. It sits after the
   configuration and before the seed. `Options.cache_slots` is gone, and the engine holds no
   cache array.
2. Handed memory, the engine builds a `Cache` over it, keyed by the seed of that call and capped
   at that call's `config.cache_ttl_seconds_max`, and puts it under the table as a `Memory`
   (§20). `Cache.init` writes every slot and every key, so the memory needs no value first and
   the cache starts empty.
3. Handed null, the engine has no cache. The table is given no `Memory`, every lookup goes to
   its servers, and no answer is kept.
4. `reinit` takes the memory again, as it takes the configuration and the seed again. The same
   memory gives an empty cache keyed by the new seed, which is what `reinit` did before. Other
   memory, of any valid size, gives a cache over it, and the engine never touches the old memory
   again. Null turns the cache off, and memory after null turns it on.
5. The memory is the caller's, and must stay valid and unmoved from the call that hands it over
   until the engine's `close` returns, or until a `reinit` that hands over other memory or null
   returns, whatever that `reinit` returns but `UdpPayloadTooLarge`. Between those two, any call
   on the engine may read or write it. No result points into it: a hit is copied into the
   lookup's slot (§20), so a result outlives the memory it was read from. An `init` that fails
   leaves no engine, and the memory is the caller's again at once. A `reinit` refused with
   `UdpPayloadTooLarge` changes nothing (the datagram's rule 7). The engine keeps the memory that
   it held, and the memory of that call is the caller's again at once. A `reinit` that fails at
   its sockets is not like it. The engine is still there, and it has taken what that call handed
   it: `reinit` builds the table and the cache before it opens the sockets, so when they fail to
   open or to arm (`SocketFailed`, `ReceiveFailed`) the engine holds the new configuration, the
   new seed and a cache over the new memory, or none when it was handed null, and the memory it
   held before is the caller's.
   The memory handed to a `reinit` that fails at its sockets stays the engine's until a later
   `reinit` or `close` returns. A caller that got memory for that call does not free it on the
   error, as an `errdefer` would. It hands it to the next `reinit`, or shuts the engine first.
6. Each engine has memory of its own. Two engines are never handed the same slices, as they
   share nothing else (§24, a thread per core). Nothing checks it: the engine sees two slices
   and cannot know who else holds them.
7. Slices `Cache.init` would refuse are the caller's programmer error, and `init` and `reinit`
   assert `cache_memory.valid()` before they change anything. A caller that reads the slot count
   at run time refuses a bad number itself with `cocuyo.cache.slot_count_valid`, before it gets
   the memory.
8. The cap is `Config.cache_ttl_seconds_max`, an hour by default, read at `init` and at each
   `reinit` and never between. `assert_valid` requires it to be at least 1.

This is c-ares's `ARES_OPT_QUERY_CACHE`. `ares_init_options(3)`, read on 2026-10-11 from c-ares
1.34.8's installed page, gives the option one field, `qcache_max_ttl`, "the maximum number of
seconds a query result may be cached", which overrides a larger TTL in the response. The page
says the cache is on by default with a TTL of an hour since c-ares 1.31.0, that a value of zero
turns it off, and that a change to the server configuration flushes it. It names no size, since
c-ares's cache has no bound on its entries (§18), and no line of `resolv.conf`, so the parser
of §10 does not set the cap. cocuyo differs in two ways. The cache is off unless the caller
hands the engine memory, because the engine has none of its own to turn on. And a cap of zero is
refused: handing no memory is the one way to turn the cache off, and a cap of zero over memory
would be a second way that still holds the memory.

`engine_cache_slots_default`, 1,024, stays a named number and no longer a default the engine
takes. It is the size the README and the engine's examples hand an engine, and the size §18's
measurements are quoted at: 2.9 MiB, and 49% to 60% of a real log's questions answered with no
packet. A caller with no measurement of its own starts from it. Removing it was the other choice.
It would have left the README and five examples each writing 1,024 on their own, and §18 calling
a number the default that no code names.

Neither model changes. The Lean models are of one lookup and of the `getaddrinfo` walks, and
hold no cache. The TLA+ model of the engine leaves the cache out (spec/README.md), and its walks
ask a new name at every start, so no cache answers one. The replay's engine is handed two slots
of memory, the size it had as an option.

### Step 14: the `getaddrinfo` shape

`AddressLookup` does what `ares_getaddrinfo` does with the flags c-ares implements, above the
table and not inside the state machine, so §16's decision 9 stands: it starts ordinary lookups
through `Resolver`, one per family, and joins what they return. It lives in `resolver`, which
is where a consumer with a loop of its own can reach it now that the engine is held back (step
13). Services by name stay out: `/etc/services` belongs to the consumer, who has the port.

- **Two moves first**, so `resolver` reaches what the shape needs without importing `config`
  (§2). The address text parser becomes `core.address_text`, reached as `Address.from_text`
  the way `Name.from_text` is. The hosts table becomes a `core` type, `core.Hosts`, with its
  `Entry`, `Storage`, `find`, `canonical` and `reverse`, and `config.hosts.parse` stays its one
  producer. That is the split `Config` already has: the type in `core`, the parser in
  `config`. `cocuyo.resolv_conf.address_text` goes, and `cocuyo.Hosts` joins the flattened
  names. Each move is a commit of its own, before the shape.
- **The walk.** `init` takes the resolver, a `?*const Hosts`, the name's text, a `?Family`,
  where null is both as `AF_UNSPEC` is, and `AddressFlags`. A name that parses as an address
  is answered at once, with no file and no query; with `numeric_host` set, any other name
  fails with `NameNotFound`, which is `EAI_NONAME`. Otherwise the sources of `Config.lookups`
  are tried in order. `.file` answers from the hosts table when it holds the name in a family
  asked for, `v4_mapped` widening that to both, with the entry's official name as the
  canonical name. `.dns` runs the search walk: it takes `lookup_policy.candidate` and starts
  one absolute lookup per family for each candidate, so the two families always ask about the
  same name. Two independent lookups could end on different search suffixes and hand back the
  addresses of two hosts. A candidate ends when both of its lookups have, or as soon as one
  says `NameNotFound`, because a name that does not exist (RFC 1035 §4.1.1) has no record of
  the other type either, and the other lookup is cancelled. Both negative, the next candidate
  starts; the candidates gone, the outcome is `NameNotFound`, or `NoData` if any candidate
  answered NODATA, which is §5's rule. One family answered and the other failed for any other
  reason, the answer stands and `partial` names the failure, so the consumer can tell a
  missing half from an empty one.
- **The join.** The addresses are copied out of the slots into the lookup's own storage, up
  to `address_lookup_addresses_max` with `truncated` past it. A pair's slots are released
  together when the pair ends, and the next pair starts in them, so a walk holds two slots at
  most and never needs one it has not got. Until 2026-09-23 each slot was released the moment
  its lookup ended, and a consumer that started a lookup of its own between the pair's two ends
  took the first slot; with the table full, the next pair then found one slot for two lookups,
  and the walk stopped the program. `canonical_name`, when asked for, is the end of the CNAME chain of the winning
  candidate, that candidate's name when there was no chain, or the hosts entry's official
  name. `v4_mapped` with family `.ipv6` starts the `A` lookup as well and hands its addresses
  back as `::ffff:a.b.c.d` when no `AAAA` came (`getaddrinfo(3)`); with `all` too, both come
  back, `AAAA` first; `v4_mapped` without `.ipv6` is ignored, as the manual says. Unless
  `no_sort`, the result is ordered by step 15's rules that need no route, which puts IPv6
  before IPv4 by precedence, the way `getaddrinfo` does.
- **The TTLs.** `AddressInfo.ttl_seconds` is the smallest TTL of the answers joined, and a
  failure carries the `Failure` of the last lookup that failed, its negative TTL included. A
  walk that ends with a failure but `NoData` (rule 5 below) carries that lookup's `Failure`
  whole, its cause included (§5, The cause of a failure). Until 2026-10-17 it took the error
  from that lookup and the rest from the last lookup that failed, so an `AllServersFailed` could
  carry a NODATA's negative TTL (§16 decision 45). Each
  candidate's lookups are absolute, so §5's bound by the negatives of a walk reaches neither:
  an answer after negative candidates keeps its own TTL, and a walk that is negative throughout
  reports its last candidate's negative TTL. A consumer that caches the outcome under the name
  as asked can keep it longer than an earlier candidate's negative allows (RFC 2308 §5). The
  table's memory keeps each candidate's end under that candidate's own name, so it is not
  affected (§20 step 16).
- **The driving protocol.** The consumer keeps the association from handle to `AddressLookup`
  the way it keeps handles today, and hands `Resolver.poll`'s `.done` and `.failed` events for
  those handles to `on_event`, which says whether it took the event and releases the slot when
  it did. `outcome` is null until the walk is over; `cancel` cancels what is in flight.
  Nothing about `Lookup` or `Resolver` changes.
- **The reverse** is `NameLookup`, beside `AddressLookup` and the same shape: the hosts table
  and DNS in the `lookups` order, and one `PTR` question whose name the address builds, which is
  absolute, so there is no search walk. It answers with the name, the TTL and whether the table
  answered. §17 question 12 is settled: one call, because the recipe left the order of the two
  sources to every consumer that wrote it out.

**The walk's rules, written on 2026-09-23** for the model of spec/lean/Spec/Address.lean:

1. The walk holds the slots of one pair at most: two, or one when one family is asked. It
   releases them together when the pair ends, or when the walk does, and holds none once the
   walk has ended.
2. Until it has ended, the walk has a lookup in flight or an end not yet handed to it: it
   never waits for nothing.
3. A lookup's end is handed to `on_event` in whatever order the consumer polls them. The walk
   decides the same way whichever end comes first, except where the rules below say which end
   wins.
4. `NameNotFound` from one family cancels the other family's lookup. A lookup that has ended
   already keeps its end (`Resolver.cancel`), so the other end may be an answer, a failure or
   `Canceled`.
5. A pair ends when both of its lookups have. The consumer's cancel ends it `Canceled`; else an
   answer from either family ends the walk answered, with `partial` the other family's failure
   when that was neither `NameNotFound` nor `NoData`; else `NameNotFound` from either moves to
   the next candidate; else any failure but `NoData` ends the walk with that failure; else the
   next candidate.
6. The candidates gone, the next source is tried; the sources gone, the walk fails
   `NameNotFound`, or `NoData` when any candidate said `NoData`.
7. The consumer's cancel cancels what is in flight, and the walk ends `Canceled` once the ends
   are in, whatever they were. It ends on the fields of the last lookup that failed. Since
   2026-10-21 a lookup's own `Canceled` end that carries a cause is such a failure too, once the
   consumer has cancelled the walk. So the walk hands on that cause, as `NameLookup` does (§16
   decision 51). A `Canceled` end that rule 4 caused alone does not count. The walk goes on to
   the next candidate, and a negative end keeps the negative TTL of the lookup that said it.

`NameLookup` is the same shape with one lookup: the hosts table and DNS in the `lookups` order, and
one `PTR` question. Its `NameNotFound` or `NoData` moves on to the next source; any other failure
ends the walk with that failure; the sources gone, the walk fails `NameNotFound`, or `NoData` when
the lookup said `NoData`. The consumer's cancel ends it `Canceled` whatever end its lookup had. Its
end hands on its lookup's `Failure`, the cause included, and a `Canceled` end of its lookup whole
(§5, The cause of a failure). A negative end, and a cancel after its lookup failed, put the walk's
error in that `Failure`. Until 2026-10-17 those two ends built a `Failure` of zeros with no cause
(§16 decision 45). Until 2026-09-23 any failure moved on, and a walk whose last source was DNS ended
`NameNotFound` when its lookup had timed out: a timeout reported as a name that does not exist.

**Checked on 2026-09-23.** spec/lean/Spec/Address.lean holds both walks as a model, each lookup
abstracted to how it ends, since `Lookup`'s own model answers for the rest. The model keeps apart
an end arriving in the table and the consumer handing it over, which is where a cancel of the
other family reaches a lookup that has ended or one that has not, and lets other consumers take
and give back the table's free slots between any two events. Its walk checks four invariants in
every state of 95 configurations: the walk holds two slots at most, none once it has ended, never
more than the table has, and it always waits for an end while it runs. The replay drives both
walks over a real table down all 66,565 transitions, comparing the walk's whole state after each.

Both defects this found were found writing the rules down, before the replay ran: the slot a
consumer's lookup could take between a pair's two ends (rule 1), and a reverse walk that
reported a timeout as a name that does not exist. The replay catches either when it is put back.

**Gate.** On the fake server: the lockstep walk against a search list on which the families
would diverge; NXDOMAIN on one family ending the candidate; `NoData` against `NameNotFound` at
the end of the walk; `v4_mapped` alone and with `all`; the canonical name from a chain and from
the hosts table; the `lookups` order both ways round; a numeric host with and without the flag;
a family the hosts table lacks falling through to DNS; a slot count that never exceeds two per
`AddressLookup`. Each check broken in turn, in `docs/mutations.md`.

Landed on 2026-09-22: `resolver/address_lookup.zig` and `address_lookup_walk.zig`, 1152 bytes
a lookup (§9), after the two moves into `core`. What the tests taught: the table harness of the
resolver's fixtures had ignored a reply's rcode, so every NXDOMAIN it built was NODATA, and it
now writes the rcode as the lookup harness does. The ordering hook is in place for step 15: the
result is `AAAA` then `A` until then.

### Step 15: ordering, and the comparison

RFC 6724 §6 orders destination addresses by ten rules, and rules 1, 2, 5 and 9 need the source
address the host would use for each destination, which c-ares learns by connecting a datagram
socket per candidate. That is I/O, so it is the consumer's: `core.address_order.order` is a
pure function over the addresses and a `Route` per address the consumer filled in, or none.

- **The inputs.** `Route` holds the source address, null when the host has none, which rule 1
  puts last; `known_unreachable`, for rule 1; `deprecated`, in RFC 4862's sense, for rule 3;
  `home` and `care_of`, for rule 4, since the RFC's own worked examples exercise it and two
  flags are all it costs; and `encapsulated`, for rule 7, which the RFC leaves to what an
  implementation knows of its interfaces. With no routes, rules 1, 2, 3, 4, 5, 7 and 9 never
  decide, and rules 6, 8 and 10 order the list: precedence, smaller scope, then the order
  received.
- **The table.** RFC 6724 §2.1's default policy table, nine rows, looked up by longest prefix
  over the IPv4-mapped form of an IPv4 address (§3.2), gives `Precedence` and `Label`. Scope
  is §3.1 to §3.4: link-local for `fe80::/10`, `::1`, `127/8` and `169.254/16`; site-local for
  `fec0::/10`; a multicast address's own scope field; global for everything else, ULAs
  included. `CommonPrefixLen` is §2.2, stopping at the source's prefix, which is 64 for IPv6
  (RFC 4291 §2.5.1's interface identifier) and 32 for IPv4.
- **The sort** is stable, which is rule 10, and in place: an insertion sort over at most
  `address_lookup_addresses_max` entries, so it allocates nothing and its cost is bounded.
- **Where it is called.** `AddressLookup` calls it with no routes unless `no_sort`, which is
  `ARES_AI_NOSORT`; a consumer that learned its routes calls it again on the result.

**Gate.** The nine worked examples of RFC 6724 §10.2, each a test with the sources the RFC
lists; a shuffled list coming back in the RFC's order; the no-route order; and each rule broken
in turn.

Landed on 2026-09-22: `core/address_order.zig`, the policy table and the scope prefixes in
`core`'s constants with the RFC 4291 sections they come from, and the hook in `AddressLookup`,
whose `select_families` now keeps the order received so that `no_sort` means what it says. Rule
4 is in after all: the RFC's own examples exercise it, and two flags on `Route` are all it costs.
The comparison against c-ares landed the same day, and §11 carries both of its tables: the
decoders, and end to end at one, sixteen and 128 lookups in flight. cocuyo resolves 1.24 to 1.48
times as many lookups a second on every row, with the lower median latency on each; c-ares has
the better tail at one and at sixteen.

What the comparison states, which §11 has in full: the decoders against c-ares's, and end to end,
both stacks against one in-process responder, lookups per second and latency at a number in
flight, on the machine and the day §11 names. cocuyo's side of that run is the engine of step 13 over rotor itself, built privately for
the bench in `bench/end_to_end/` (the owner's call on 2026-09-22: rotor, not a `poll(2)` loop),
so what is measured is the batteries-included path a consumer would get, while the engine stays
unexported until one asks.

On 2026-09-29 the comparison's driver moved to a schedule (c4milo/cocuyo#5): each row offers a
load, a lookup is sent when it is due whether or not the stack has answered, and its latency runs
from then. The rows add the 99.9th percentile, the slowest lookup and how late the lookups went
out, and the kernel's count of the stack's system calls and context switches per lookup, with
the responder moved to a process of its own so that none of its calls is counted. c-ares's
lookups go out from the main thread, so its callback starts none, and the handoff between the two
threads went with it (docs/mutations.md, the end-to-end driver on a schedule). On 2026-09-30 a row
of cache hits joined them, where both stacks answer from their caches (docs/mutations.md, a row of
cache hits).

### New limits

| Constant | Value | Why |
| --- | --- | --- |
| `records_kept_max` | 32 | half `records_max`: what one answer section holds of one type, with `truncated` past it |
| `rdata_bytes_max` | 2048 | one UDP payload of 1232 plus room for the names decompressed on the way in; `truncated` says when a TCP answer did not fit |
| `cookie_client_bytes` | 8 | RFC 7873 §4 |
| `cookie_server_bytes_max` | 32 | RFC 7873 §4 |
| `cookie_silence_ns` | 5 min | RFC 9018 §3: a server that answered a client cookie without one is sent none for "a certain period (for example, five minutes)"; added on 2026-10-08 (c4milo/cocuyo#36) |
| `opt_record_bytes` | 11 to 55 | the OPT record with a COOKIE option carrying the largest server cookie |
| `query_bytes_max` | 284 to 328 | follows from it |
| `hosts_entries_max` | 1024 | more lines than a machine that is not a blocklist has; past it, dropped and said so |
| `hosts_names_per_entry_max` | 8 | a name and its aliases on one line |
| `failover_retry_chance_default` | 10 | c-ares's default: one query in ten retries a failed server |
| `failover_retry_delay_ns_default` | 5 s | c-ares's default |
| `udp_queries_per_port_default` | 0 | c-ares's default: never replace the socket |
| `tcp_idle_ns_default` | 10 s | chosen, not measured: a burst's worth, and short by RFC 7766 §6.2.3's standard |
| `engine_lookups_default` | 256 | in flight at once; the caller sizes the memory |
| `engine_cache_slots_default` | 1024 | 2.9 MiB of slots, the cost §18 measures; since 2026-10-11 the size the README and the engine's examples hand an engine, and no default the engine takes, since it holds no cache memory of its own (step 13, the cache's memory) |
| `address_lookup_addresses_max` | 32 | both families' `addresses_max`, bounded the way one answer is; `truncated` past it |
| `address_policy_rows` | 9 | RFC 6724 §2.1's default table |
| `common_prefix_bits_v6_max` | 64 | RFC 6724 §2.2 stops at the source's prefix, and RFC 4291 §2.5.1 makes the interface identifier the low 64 bits |
| `tcp_frame_room_bytes_max` | 2,048 | what a frame holds past its partial message in the clear: one chunk, `tcp_chunk_bytes_max`; since 2026-10-13 (step 13, the stream's rule 11) |
| `tls_frame_room_bytes_max` | 16,640 | what a frame holds past its partial message over TLS: the body of one record at its longest (RFC 9846 §5.2), which the session opens into the frame; colibri asks for room as long as the body |
| `tcp_messages_per_frame_max` | 41,088 | the most whole messages a frame holds, each at least its two-octet prefix: a TLS connection's frame, the longest, over two. It bounds the loop over the frame, and never stops it before the last whole message. It replaced `tcp_messages_per_chunk_max`, 32, on 2026-10-13 |
| `udp_payload_bytes_max` | 1,856 | the most `Config.udp_payload_bytes` that the engine's `init` and `reinit` take: what one buffer of the datagram group holds of a datagram, `buffer_bytes_max` less rotor's prefix under `group_options`. A requestor "SHOULD place a value in this field that it can actually receive" (RFC 6891 §6.2.3); since 2026-10-14 (step 13, the datagram's rule 7) |

### Order and gates

Steps 9 to 15 land in that order, each with its mutation table in `docs/mutations.md`, each
committed only when `zig build test` is green, and step 13 beginning with the twin, so the
engine is driven at every seed before it touches a socket. §15 lists them as steps of the plan.
Step 14 begins with its two moves into `core`, each committed on its own before the shape.

## 20. What a consumer gets

cocuyo is a package before it is a library: a consumer writes `.cocuyo` in its `build.zig.zon`,
`@import("cocuyo")` in its source, and what it finds there is this section's subject. The first
consumer to ask for it was colibri's, on 2026-09-22.

colibri owns no I/O and no allocator, as cocuyo does not, so colibri itself never resolves a
name: its driver does, and the driver is what reaches for this. That is why this section adds no
loop. The owner's ruling of 2026-09-22 stands — no library bound to rotor until a consumer asks
for one — and this consumer does not ask for one.

### What is already true

- `build.zig` registers one module, `cocuyo`, rooted at `src/cocuyo.zig`, and returns before the
  tools' dependency when cocuyo is not the root build, so a dependent resolves the library and
  fetches nothing else. `build.zig.zon` ships `build.zig`, `build/` and `src/`; pepegrillo and
  rotor are lazy, and only the root build asks for either. Since 2026-09-25 it registers
  `cocuyo_rotor` too, rooted at `io/io.zig`, and ships `io/` (§24). It also registers
  `chapulin_hooks`, `cocuyo_quic`, `chapulin_quic`, `cocuyo_doh` and, since 2026-10-24, the DoT
  session `chapulin` (§16 decision 38). The build refuses to compile when a registered module's
  root is not under a path the manifest ships.
- `src/cocuyo.zig` holds no logic. It re-exports each module of §2 as a namespace and flattens
  the names a consumer reaches for beside them.

### What is missing

1. **The cache cannot be reached from outside.** `Resolver` never names it. The policy that puts
   a cache in front — ask before a lookup starts, remember an answer when one ends, and remember
   the two negatives RFC 2308 allows and nothing else — lives in `io/io_drive.zig`, which is not
   exported. A consumer that wants cocuyo with its cache writes that policy again, and the part
   that is easy to get wrong is which failures may be remembered at all.
2. **A composition misses the cache entirely.** `AddressLookup` and `NameLookup` ask their
   questions through `Resolver.start`, so a consumer that wrapped its own calls would still send
   every query those two make. c-ares caches `ares_getaddrinfo`, so §19's parity claim is not met
   while this is true.
3. **The module surface is wider than the claim.** The build registers `core`, `wire`,
   `resolver`, `config`, `cache`, `sim` and `io` by name as well, so a consumer can import the
   deterministic twin.
4. **Nothing proves a dependent build.** The branch a dependent takes — the early return, the
   manifest's `paths` — is never compiled by the gate, so it can break without the gate saying so.

### Step 16: the cache under the table

`Resolver` gains one optional field, a `Memory`: a context pointer and two functions the caller
supplies. The table never names a cache, so the module graph of §3 is unchanged — `resolver`
still reads `core` and `wire` alone — and the root module, which sees both, is where a `Cache`
is turned into a `Memory`.

```zig
pub const Negative = enum { name_not_found, no_data };

/// What the table remembers, and what it is handed back. The answers point into the caller's
/// storage and are read before the call returns. `ttl_seconds` is what is left of a life.
pub const Remembered = union(enum) {
    answered: struct {
        answers: *const wire.Answers,
        ttl_seconds: u32,
        canonical_name: ?*const Name, // the end of the CNAME chain, or null (§17 question 13)
    },
    negative: struct { outcome: Negative, ttl_seconds: u32 },
    failed: Error, // a resolution failure of RFC 9520 §2, since 2026-10-28 (§16 decision 61)
};

pub const Memory = struct {
    context: *anyopaque,
    recall: *const fn (context: *anyopaque, question: *const Question, now_ns: u64) ?Remembered,
    remember: *const fn (context: *anyopaque, question: *const Question, end: Remembered, now_ns: u64) void,
};
```

**A hit is a lookup that is already over.** A lookup's first `poll` asks `recall` before it
builds anything. On a hit the answers are copied into the slot the lookup already holds and it is
put in its end state, so that same poll returns `.done` — or `.failed` with `NameNotFound` or
`NoData`, or since 2026-10-28 with a resolution failure — and no query is ever built. The asking
is at the first poll rather than at `start` because `poll` is where the clock comes in, and an expiry needs one (CLAUDE.md non-negotiable 4):
`start` keeps its signature, and nothing above the table learns a new shape. `poll`,
`AddressLookup` and `NameLookup` work unchanged, and every question they ask goes through the
cache, because they all start through the table.

**An end is remembered once.** `poll` may produce a lookup's end more than once, because a
lookup that has ended and waits for `release` answers each poll with it again (§11). The slot
carries a bit that says its end was remembered, set when `poll` first produces it, and a slot
seeded from the cache never writes back what it was handed.

`cocuyo.remembered_by(&cache)` builds a `Memory` from a `Cache`. It is the only place that maps
a `Failure` to what may be kept: `NameNotFound` and `NoData` with the TTL the SOA gave
(RFC 2308 §5), and nothing else — not a timeout, not a refusal, not a malformed answer. The
memory keeps no cause, so a negative that it recalls has none (§5, The cause of a failure).
`io/` then drops its own copy of that policy and passes a `Memory` like any other caller. Since
2026-10-28 the memory keeps a resolution failure too, for a time that the cache sets
(RFC 9520 §3.2). A cancel, a lookup with no server and a name too long are still not kept (§16
decisions 60 and 61).

**A table without a cache, since 2026-10-11.** The engine built its table and its cache in one
function, so that no path built one without the other. One path does now, by the caller's
choice (§19 step 13, the cache's memory; §16 decision 37): an engine handed no memory for a
cache gives its table no `Memory`. Every lookup that table starts, the composed ones included,
goes to its servers, and nothing is remembered. That is the table a caller of the library has
had all along when it calls no `remember_with`. An engine handed memory builds both in that one
function still.

**A recalled answer carries the chain's end.** The cache is keyed by the question, and until
§17 question 13 was answered it stored the answers and not the chain that reached them, so an
answer that came through a CNAME lost its canonical name once remembered. The slot now keeps the
chain's end, and `Remembered` carries it both ways: the table writes `current` when the lookup
was aliased, and a recalled lookup reports it back exactly as one that went out reports its own.
The same question answers the same whether the cache held it or not. It costs one `Name` a slot,
256 octets on 2728.

**A recalled answer's TTLs are aged.** `Remembered.answered.ttl_seconds` is what is left of the
answers' own TTL. A `Cache` keeps as that TTL the life the entry was given, capped (§18). The
difference is the time the answers spent in the memory, and the lookup lowers every TTL they
hold by it, never below zero, as it does for DoH's `Age`. The TTLs of cached data count down
(RFC 1035 §6.1.3), and until c4milo/cocuyo#39 a record kept with a TTL of its own came back with
the TTL it was stored with. A memory may say more is left than the answers' own TTL, as one that
keeps answers longer than their TTL does. Then no TTL is lowered, and the answer reports what
the memory says, as every recalled answer did before #39. That case is the consumer's choice and
not an error, so it asserts nothing.

**A walk's end is bounded by its negatives.** For a relative name the table remembers the
search walk's end under the name as asked. The lookup has already bounded that end by every
negative on the way (§5): a negative end carries the smallest negative TTL of the walk, and an
answer's TTL is no larger than it. So a memory needs no rule of its own for the walk, and a
consumer's cache keyed by the question reads the same TTLs (c4milo/cocuyo#38).

**What it costs.** A hit now takes a slot and copies `Answers` into it, where the engine's
`Started.hit` handed back a pointer and took no slot. §11 measures the copy at 53 ns and a hit
at 31 ns, against a round trip of a millisecond or more, and the copy buys the composition: one
policy, and every lookup shape cached rather than one. The engine's `start` returns a handle
and nothing else, and `Started` goes away.

### Step 16 also: the surface, and a dependent build

- The build registers `cocuyo` and creates the rest, so `cocuyo` is the only name a dependent
  can import. `zig build test-<module>` still names each one, because the build holds the graph
  as a value rather than by name.
- A fixture package under `test/consumer/`, whose manifest depends on cocuyo by relative path,
  is built by `zig build consumer-check`: it imports `cocuyo`, puts a cache under a table and
  builds one query, which is the proof that the packaging works. The same package built with
  `-Dreach-inside` asks for `sim` and must fail, the way `graph-check` proves the module graph,
  and the positive run is the control that stops the negative from passing for the wrong reason.
  It lives outside `src/`, `tools/`, `bench/` and every other directory the lint and the format
  check read, because a nested build materialises into a `zig-pkg/` beside it whatever packages
  the machine already holds, and those are not ours to score.
- What that first run settled: against an empty package cache, a dependent fetches nothing at
  all — no pepegrillo, no rotor, no rotor's own dependency — and builds in about seven seconds.
  The `zig-pkg/` that appears on a machine which already holds them is a copy of what was there,
  not a download, and nothing in it is compiled or linked. The manifest's `lazy` holds.

### Alternatives this beats

- **A synchronous hit, returned by `start`.** It saves the slot and the copy, and it makes every
  composition learn a second control path: `AddressLookup` would have to consume an answer while
  still inside its own `init`, for each of its candidates, and recursion is the shape that
  invites. Rejected for the cost of one copy.
- **`Resolver` generic over the cache.** It costs nothing at run time and it changes every
  signature that names `Resolver`, in the library and in every consumer. Rejected.
- **Leave the policy in each consumer.** Two consumers, two readings of RFC 2308. Rejected: the
  rule about which failures may be remembered is DNS knowledge, and it belongs with the DNS.
- **Export the engine over rotor.** It would answer a different question than the one asked:
  colibri's driver has a loop already. Rejected for now, and the ruling that holds it back is the
  owner's. That ruling gave way on 2026-09-25: the engine is exported into the caller's loop
  (§16 decision 27, §24).

### Checks

- A hit answers without a query: start the same question twice, and the second lookup's first
  `poll` is `.done` with the send count unchanged.
- A cached negative comes back as the failure it was, with its TTL, and an expired one does not.
- A resolution failure is written as `failed`, and one that the memory holds ends the lookup at
  its first poll with its error, and nothing is sent. An engine whose servers all fail a name
  sends nothing for it until the entry expires, and sends again after (since 2026-10-28).
- `AddressLookup` asks one question when the cache holds the other family, and none when it
  holds both.
- An end is remembered once, however many times it is polled.
- A walk's end is written under the name asked with the bound a negative on the way put on it:
  a relative name whose first candidate is NXDOMAIN with no SOA and whose second answers is
  written once, with a TTL of zero (since 2026-10-08, c4milo/cocuyo#38).
- A lookup seeded from the cache does not write back what it was handed.
- An engine handed memory answers a repeated question from its cache and sends nothing, and an
  engine handed none sends the question again (since 2026-10-11).
- `zig build consumer-check` builds the dependent fixture, and the fixture that imports `sim`
  fails to build.
- `zig build readme-check`, since 2026-09-26, builds every Zig block of the README in a package
  that depends on cocuyo, and runs the quick start to its first `send_udp`. The README's driving
  loop had stopped compiling once `send_request` joined the actions, and nothing had noticed.

## 21. DNS over TLS

§1 brought DoT in on 2026-09-23. This section is its plan, step 17, and it records the owner's
rulings of that day with the facts that led to them. Each piece lands with its checks.

### The owner's rulings of 2026-09-23

- The TLS is chapulin's, through its record transport, and the engine drives it. The library
  stays without TLS: the stream path already produces the length-prefixed messages DoT sends
  (RFC 7858 §3.3).
- Strict by default (RFC 8310 §5): a server that does not authenticate fails, and the lookup
  never falls back to cleartext.
- A configuration names its DoT servers per server, all or none. `Server` gains `tls: ?Tls`,
  and `Tls` holds the authentication domain name of RFC 8310 §7.1, the SPKI pins of RFC 7858
  §4.2, and the port, 853 unless set (RFC 7858 §3.1). A `Config` with one TLS server has only TLS servers, so failover never
  reaches port 53. A mixed list was the alternative, and it lets a lookup leak to cleartext.
- The caller hands in what TLS needs and cocuyo does not read. A handshake needs 256 bits of
  fresh randomness, which a `u64` seed cannot give: the engine takes a 32-byte seed from a
  CSPRNG at init and expands it with ChaCha20, one stream per engine, which each session hands
  colibri's `start` since colibri#71. A certificate's validity needs the wall clock: the caller gives Unix seconds pinned to
  a `now_ns` at init and at `reinit`, and the engine adds the elapsed `now_ns`. chapulin's own
  DRBG was the alternative, and it is one stream for every session in the process. As built,
  neither is an argument of `init` or of `reinit`: the caller puts the seed and the clock in
  the context it hands `use_tls` after `init`, and `reinit` neither reads nor writes a context
  (the session interface, below; §24, the context a session starts from, rules 4 and 5).
- chapulin changes first, in three pieces, before DoT lands here:
  1. After the handshake, `ch_read` pulls records through a `recv` callback. A record that
     holds only a session ticket makes it read another, and a `recv` with nothing to give fails
     the session. An engine over a completion loop holds only what has arrived, so `ch_read`
     must answer "need more bytes" and leave the session alive. Landed in chapulin at `73a36a8`
     the same day. A `recv` that returns 0 at a record boundary makes `ch_read` return
     `CH_RECORD_AGAIN`, and the session stays connected. A ticket or a KeyUpdate in the records
     before that is handled first, and a KeyUpdate's reply goes out through `send`. A message
     split across records keeps its first part in chapulin's buffer, which the caller leaves
     alone between calls. A `recv` that returns 0 inside a record kills the session.
  2. RFC 8310 §9 makes session resumption a MUST. chapulin's webpki build refuses it, because
     nothing binds a ticket to the name it was issued for. The ticket gets bound to the name.
     Landed in chapulin at `756ad91` the same day. A ticket carries a binding over the hostname
     and every trust anchor, and a resumption with a binding that does not match refuses to
     start. A resumed hello offers the ticket alone, so a server that declines it fails the
     handshake, and the caller drops the ticket and connects again in full. The caller owns the
     ticket's age, its 7-day cap and its single use.
  3. RFC 8310 §9 makes RFC 7250 raw public keys a MUST, offered only when an SPKI pin is
     configured. chapulin has none in any build. Landed in chapulin at `b6f2b11` the same day.
     A caller gives up to 4 pins, each the SHA-256 of a DER SubjectPublicKeyInfo. With pins
     alone, and no anchors and no clock, the hello offers a raw public key only. With pins
     beside anchors it offers a raw key first and X.509 after, and a chain must pass as before
     with a pin naming a key on its validated path. A ticket's binding covers the pins too.
     Since chapulin `3d5db4e`, on 2026-09-25 (its decision 65), a hello under pins alone offers
     a raw key first and X.509 after as well, and a chain passes when a pin names its leaf's key.
     The rest of the chain, its dates and its names are not read, and a pin on an intermediate
     or a root key matches nothing. Public resolvers send chains, so a resolver known by its key
     is known by its leaf's.
- A TLS server is known by its name, by its SPKI pins, or by both, the owner ruled the same day.
  Pins alone is RFC 8310 §6.3's "SPKI + IP" profile: raw public keys, no certificate authority
  and no clock. A name alone is its "ADN + IP". With both, both must pass (§6.4). A name was
  the only alternative, and it leaves the raw-key MUST of §9 unused. RFC 7858 §4.2 asks that a
  pin be accepted as base64 text too, so `config` reads one (RFC 4648 §4).

### What a TLS server changes

- **The lookup.** Every query to a TLS server goes on the stream. All or none makes a TLS
  configuration a stream configuration, so the lookup is §5's with `use_tcp` on, and its model
  is unchanged. Truncation, cookies and failover behave as they do over TCP.
- **The query.** It carries the EDNS(0) Padding option (RFC 7830 §3), sized so the message is a
  multiple of 128 octets (RFC 8467 §4.1). Padding is only for an encrypted transport (RFC 7830
  §6), so a query over UDP or plain TCP carries none. A query sent without EDNS after a FORMERR
  cannot carry the option, and goes unpadded.
- **The answer.** A Padding option in it is accepted, whatever its octets (RFC 7830 §3).
- **The engine.** A connection to a TLS server connects, then handshakes, then is up, and the
  rules below hold it to that.

### The engine's TLS rules, written on 2026-09-23

These extend the stream's rules of §19 step 13, for the engine model to be written from before the
code is.

1. A connection to a TLS server handshakes between its connect and its first query. When the
   connect succeeds, the receive is armed and the session starts, which makes its first flight.
   The connection is up when the handshake has ended, and only then are the lookups on it told.
   A lookup that joins it meanwhile waits, as one that joins a connection still connecting does
   (the stream's rule 5).
2. The session's own records are sealed when the session makes them: its flights, and later a
   record it makes of its own accord, such as a KeyUpdate's answer or a `close_notify`. A query
   is sealed when it reaches the head of the queue with nothing in flight. Records go out in the
   order they were sealed, since each record's nonce is its sequence number (RFC 9846 §5.3). So
   records the session makes while a send is in flight go out right after that send, ahead of
   every query not yet sealed. Records made while another entry of the session's own records
   waits behind the send in flight join that entry, since the two go out together and in the
   order they were made. A queue holds two entries of the session's records at most, then:
   the one in flight and the one behind it. Until 2026-09-24 each made its own entry, and a peer
   asking one KeyUpdate after another while a send stalled filled the queue; the model's walks
   found it.
3. A connection's sealed records wait in a buffer of the connection's own. Each send from that
   buffer lends it to the loop until the send's final event (rotor decision 5, rule 3). Two kinds
   of send read it:

   - a send of the session's own records;
   - a query's send, which reads the query's sealed records there (rule 2).

   The slot is not opened again while a send of an earlier incarnation reads the buffer. The
   stream's rule 10 keeps it closed for a connect in the same way. A closed slot whose buffer is
   lent is pending (the stream's rule 12). The buffer is written only behind what the send in
   flight reads, and only by the opening that made that send. A reset leaves the buffer's bytes as
   they are, for the same reason (§16 decision 47).
4. A handshake that fails fails the connection (the stream's rule 5): a record the session
   refuses, a certificate or a name that does not verify. No query was sent on it, and each
   lookup on it fails over to the next server. The server has refused the lookup, so one whose
   passes run out ends in `AllServersFailed` (§16 decision 25). Since 2026-09-27 the connection
   says the session's fatal alert before it closes, as RFC 9846 §6.2 asks (c4milo/cocuyo#31).
   Its lookups hear the failure at once and leave it. The alert is sealed as rule 2 seals the
   session's records, and the connection closes once it has gone, as rule 5's idle close does
   after its `close_notify`. A session that staged no alert closes it at once. A resumed
   handshake that fails is rule 8's. A record the session refuses once the connection is up
   fails it the same way, resumed or not: the server has failed the lookups on it. Its queries
   not yet sealed leave the queue and give their buffers back, since nothing more may be sent
   (§6.2). What is sealed goes out first, in the order it was sealed, the send in flight among
   it: each record's nonce is its sequence number (§5.3), so the alert, sealed after them, can
   be read only after them.
5. An idle connection that is up makes the session's `close_notify` (RFC 9846 §6.1). It closes
   when that record has gone, and no lookup joins it meanwhile. A record the peer sends
   meanwhile is not read: the session has said its last. One whose handshake has not
   ended has no session to close, and closes at once. A connection that fails otherwise closes
   at once too: one whose peer has gone has nobody to send anything to. A party that has sent
   an error alert owes no `close_notify` (§6.1). Since 2026-10-13 one failure is not the
   session's or the peer's: a prefix that says more than `tcp_message_bytes` (the stream's rule
   11). The peer is still there, so the session makes its `close_notify`. RFC 9846 §6.1 asks for
   it: "Each party MUST send a "close_notify" alert before closing its write side of the
   connection". Then the connection ends as rule 4 ends a refused record. Its lookups hear the
   failure at once, its queries not yet sealed leave, and it closes once the alert has gone.

   Since 2026-10-20 the idle close's wait bounds a connection that closes (§16 decision 49). No
   lookup is on it, and the session has said its last record, so it is idle (RFC 7766 §3). Its
   wait counts from the instant it began to close. When its last record has not gone after
   `tcp_idle_ns`, the drive shuts it. The shut cancels the send, and the slot frees at the
   cancel's event (rule 3). The peer then sees the stream end, after all of that record, a part of
   it, or none of it.

   Since 2026-10-25 a connection that is up makes no `close_notify` when its last lookup leaves
   while a query's send is in flight. The peer has not read that query, so it does not read a
   `close_notify` either. The drive shuts the connection at once, and the slot frees at the
   cancel's event (the stream's rule 3, §16 decision 53). A send of the session's own records in
   flight does not shut it. That send holds no lookup's buffer, so the idle close ends the
   connection as above. Since 2026-10-25 a marked connection makes its `close_notify` at its last
   leave, with no wait, when no query's send is in flight (§16 decision 54).
6. A TLS connection is never closed to make room for another. A TLS configuration needs a slot
   for each of its servers, and the engine asserts it has them. Each server has at most one
   connection that a lookup may join. Take a lookup whose server has no such connection, and that
   finds no free slot. A slot then frees with no lookup leaving it: a connection that closes, or a
   slot whose memory the loop holds. Since 2026-10-18 the lookup waits for it (the stream's rule
   12). Since 2026-10-25 a marked connection is not one that a lookup may join. So a server can
   have a marked connection and one more. Then the slot of a marked connection frees once its
   lookups leave, and the lookup waits for it (§16 decision 54).
7. Records received go to the session whole. The connection reads each record's length from
   its five-octet header, and keeps a partial record until the rest arrives. A header that says
   more than RFC 9846 §5.2 allows fails the connection. The session's `recv` hands over whole
   records and answers 0 only at a record boundary, which chapulin reads as "no record yet"; a 0
   inside a record would kill the session. Since 2026-10-13 the connection takes each chunk
   whole into its record buffer. Then it hands every whole record in the buffer to the session,
   oldest first, before the chunk's event ends. The partial record after them stays. So the
   buffer holds a record at its longest, header and all, and one chunk: `tls_record_in_bytes_max`.
   Each record is at least its header, so the buffer holds at most `tls_records_per_buffer_max`
   whole records. That count bounds the loop, and the loop never stops before the last whole
   record. A record the session refuses puts the connection in its `closing` state. The rest of
   the chunk then leaves the buffer unread (rules 4 and 5). The session opens each record into
   the connection's frame after the partial message. So over TLS the frame holds the body of one
   record past that message (the stream's rule 11). Until 2026-10-13 the buffer held one record
   alone, and the loop stopped after 32 records, `tls_records_per_chunk_max`. So a sound
   connection failed when a chunk ended a full AES-GCM record and held 240 octets or more of the
   next. Records past the 32nd waited for the next chunk. And a full AES-GCM record found no room
   in the frame after a partial message of more than 49,136 octets.
8. Each server keeps the newest ticket its sessions were given, and the next connection to that
   server resumes with it. A ticket is used once, since reuse lets an observer link two
   connections (RFC 9846 §C.4). It is dropped at its lifetime, or 7 days after it came,
   whichever is sooner (§4.7.1). Its age is the engine's clock since it came, not the wall
   clock. A resumed handshake that fails is not the server's failure. A server that declines a
   ticket has said nothing yet about its certificate, and a full handshake is what decides. So
   the connection is opened again in the same slot, in full. That happens as soon as the loop
   has given back any records the failed session had in flight (TLS rule 3). Its lookups stay on
   it meanwhile, count no failure, and hear only how the full handshake ends.

   Since 2026-10-21 the connection cancels a send in flight as it drops the failed session (§16
   decision 49). So the loop gives the records back at the cancel's event. A peer that stops
   reading cannot hold the connection in its wait.
9. A TLS configuration opens no UDP socket. Every query goes on a stream (all or none), so a
   datagram socket would only hold a descriptor and a receive that nothing may use. The owner
   ruled so on 2026-09-23.

The model holds rules 1 to 6, 8 and 9. Rule 7 is about octets, which the model does not count. Four
invariants were added for them: a slot a send of records still borrows stays closed; the sealed
entries lead each queue, so records go out in the order they were sealed; no query waits on a
connection that is not up; and no event leaves the session owing an answer. The last came from a
mutation nothing caught without it (docs/mutations.md TM3). The replay drives no TLS configuration
until step 5, when the engine speaks TLS. Other checks hold rules 3, 4, 5 and 8:

- Three hold rule 8. A connection that opens resuming spends its server's ticket. One opened again
  after a declined ticket handshakes in full. A declined ticket counts no failure, and keeps its
  lookups on the connection.
- Since 2026-09-27 one holds rule 4's alert. A handshake the session refused, not resumed, or a
  record it refused once up, leaves its connection closing. No lookup is on it, no query waits
  unsealed, and the session's records wait in its queue.
- Since 2026-10-18 one holds rule 3 for each send from the records buffer. The buffer is lent to
  one send at most, of whichever incarnation. A query's send that reads it is its connection's
  head, or the slot is closed. Each operation names the buffer that it reads, so the model's
  choice of a slot sees each send that reads one (§16 decision 47).
- Since 2026-10-20 one holds rule 5's bound. After the clock moves, no connection that closed
  before it still closes (§16 decision 49).

### The session interface, written on 2026-09-24

The engine does not call chapulin by name. It is generic over a `Session` type in its
`Options`, whose functions are chapulin's record transport in the engine's words:

- `start` stages the first flight, from the server's `Tls`, the wall clock, the engine's seeded
  stream and a kept ticket;
- `take_out` hands over the records the session made, in the order it sealed them;
- `handshake` takes one whole record during the handshake, and says whether the handshake goes
  on, has ended, or failed;
- `seal` makes the records of one query;
- `open` takes one whole record once the session is up, and says what it held: a query's answer,
  nothing the engine sees (a ticket to keep, a KeyUpdate whose answer it made), the peer's
  close, or a failure;
- `close` makes the `close_notify`, and `wipe` drops every secret.

Two types fill it:

- `io/io_chapulin.zig` fills it from chapulin's record transport. Since 2026-09-27 it runs over
  colibri's `tls.record.Client`, whose module carries chapulin's objects (§16 decision 32):
  nothing is vendored, and cocuyo links no object of its own. It ran over chapulin's Zig API from
  2026-09-26 (c4milo/cocuyo#30), and over an object from a chapulin checkout before that.
  colibri's client writes a refused flight's fatal alert into the output it was handed, and
  `failure_written` counts it, which is how the session stages it for TLS rule 4. Since
  2026-10-24 the build registers it as `chapulin` (§16 decision 38, as amended for §17 question
  64). A consumer that speaks DoT binds colibri's `tls` and `tls_provider` into it. Its `io` is
  `cocuyo_rotor`, into which the consumer binds its rotor.
- The twin fills it with `sim.tls`, a session whose records carry their plaintext unsealed and
  whose handshake steps are spelled in the records the twin's server sends. The twin's servers
  script it, and the replay drives the model's steps with it one by one, so the gate needs no
  chapulin.

chapulin's session starts from a `Context` the caller hands `Resolver.use_tls`:

- the trust anchors, at most 12, each a root's subject Name and SubjectPublicKeyInfo as DER;
- since 2026-10-20, the consumer's statement of its CPU, a `tls.Cpu`: what its probe found, and
  the timing mode of the thread that drives the engine. The session hands it to colibri's TLS
  value, and it decides the suites of each hello (§16 decision 48);
- the wall clock, as Unix seconds pinned to a `now_ns`, which the session carries forward by
  the elapsed `now_ns` when it starts a handshake;
- a ChaCha20 stream the caller's 32-byte seed keys. chapulin draws randomness through
  `ch_rand_bytes`, and only during a handshake: when it starts, and, once chapulin speaks
  P-256, when a HelloRetryRequest asks for a key share of that group (chapulin's answer of
  2026-09-24). So the session points that function at the stream for every call it makes while
  the handshake runs, and at nothing otherwise. The stream is thread-local, one engine to a
  thread. The owner ruled the same day that an image defines `ch_rand_bytes` and
  `ch_assert_fail` once, for every chapulin object and every user of chapulin it links, and that
  each must be safe to call from several threads at once (chapulin's docs/porting.md). An
  image may link chapulin's non-blocking TCP object beside its QUIC object since chapulin
  `0c201b7`, which names each object's build record after its transport. Since `ca80351` the
  transports are named for what TLS runs over and who does the I/O, and the record here is
  `ch_build_info_tcp_nonblocking`. Since colibri#71, landed on 2026-09-27, colibri's objects
  are built `RAND=session`: each session hands the stream to colibri's `start`, chapulin draws
  from it wherever it draws, and nothing enters it around a call. The image defines only
  `ch_assert_fail`, and the owner ruled the same day that `chapulin_hooks` drops its
  `ch_rand_bytes`, `enter` and `leave`.

Since 2026-10-11 the engine has no context of its own (§16 decision 39). It holds none until
`use_tls` has run, and a lookup started against a TLS configuration before that stops the
program at an assertion, since forgetting the call is a programmer error. The `Context` carries
no default either. `Context.init` takes all of it: the anchors, the statement of the CPU, the
32-octet seed and the wall clock. The clock comes with the `now_ns` it was read at. §24, the
context a session starts from, says what a context must carry for each transport, and what the
engine checks of it.

The session collects what chapulin makes as soon as chapulin makes it. chapulin says it is
connected only once the client's last flight has been collected, so a session that left it for
`take_out` could not tell the engine the handshake had ended.

What the fake cannot show is chapulin's to show, in its own suite and in step 6's live check:
the ciphers, the certificate and pin checks, and the resumption binding. The engine's own work
is what the fake does show: which records go when, what a lookup hears, and when a slot is free.

### Limits chapulin sets

- The authentication name is a DNS name. chapulin checks a DNS-ID against the certificate's
  subjectAltName and has no IP-address form, so `dns.google` works and `8.8.8.8` does not.
- At most 12 trust anchors, the caller's to choose.
- At most 3 certificates verified in a chain, each at most 3072 octets.
- A connection holds a `ch_record` of 2744 octets (measured with clang on arm64, 2026-09-23),
  a buffer of at least 12338 octets for chapulin, and room for one whole record in and one
  chunk after it (TLS rule 7, since 2026-10-13).
- Since colibri v0.8.0, pinned on 2026-10-20, a session runs AES-GCM only where the program states
  its CPU and its thread's timing mode (§16 decision 32). The session states what its context
  carries (§16 decision 48). A context that states no timing mode makes a hello that offers
  TLS_CHACHA20_POLY1305_SHA256 alone.

RFC 8310 §9's other items stand as follows. chapulin speaks TLS 1.3 only and never compresses,
which meets two MUSTs. It does not cite RFC 7525, and has neither False Start nor Cached
Information, which are SHOULDs.

### New limits

The owner ruled on 2026-09-23 that `query_bytes_max` grows from 328 to 386 octets, so that the
largest query pads to a whole block like every other. The alternative kept 328 and let a query
past 256 octets pad short of its block. Every caller's send buffer grows by 58 octets, and so do
the engine's send and held buffers, per slot.

| Constant | Value | Why |
| --- | --- | --- |
| `padding_block_bytes` | 128 | RFC 8467 §4.1 |
| `spki_pin_bytes` | 32 | an SPKI pin is a SHA-256 (RFC 7858 §4.2) |
| `spki_pins_max` | 4 | a primary pin and the backup RFC 7858 §4.2 asks for, each with room to rotate; chapulin's own bound |
| `opt_option_header_bytes` | 4 | an EDNS(0) option's code and length (RFC 6891 §6.1.2) |
| `port_dns_tls_default` | 853 | RFC 7858 §3.1 |
| `query_bytes_max` | 328 to 386 | the largest query, padded to 384, and the stream's prefix |
| `tls_record_in_bytes_max` | 16,645 to 18,693 | a TLS connection's record buffer: a record at its longest, 16,645 octets with its header (RFC 9846 §5.2), and since 2026-10-13 one chunk of 2,048 after it (TLS rule 7) |
| `tls_records_per_buffer_max` | 3,738 | the most whole records the buffer holds, each at least its five-octet header (RFC 9846 §5.1). It bounds the loop over the buffer, and never stops it before the last whole record. It replaced `tls_records_per_chunk_max`, 32, on 2026-10-13 |

### Order and checks

1. chapulin's three pieces, in chapulin.
2. `core`: `Server.tls`, and `assert_valid` refusing a list that mixes TLS and cleartext. A TLS
   server's stream goes to its TLS port. Done 2026-09-23.
3. `wire` and `resolver`: the Padding option on a query to a TLS server, and a TLS
   configuration sending every query on the stream. Done 2026-09-23. Until step 5 the engine
   asserts that its configuration has no TLS server: a stream it opened to one would carry
   cleartext on port 853, which RFC 7858 §3.1 forbids.
4. The engine model: a connection handshakes between its connect and its first query, and a
   handshake that fails fails the connection. Design, model, code, in that order (§19 step 13).
   The rules and the model landed 2026-09-23; the code is step 5's.
5. The engine over chapulin, behind a build option naming a chapulin checkout, as colibri's own
   endpoints link it: the headers are read in place and nothing is vendored. The engine's side
   landed on 2026-09-24, over the session interface and checked with the twin's session: the TLS
   rules in `io/io_tls.zig`, the queue's sealed entries in `io/io_tcp_queue_ring.zig`, twin
   tests in `io/io_tls_test.zig`, and the replay over the model's two TLS configurations. The
   full walks found one defect in the rules as first written, the queue filled by KeyUpdates
   (TLS rule 2). chapulin's own session, `io/io_chapulin.zig`, landed the same day, with
   `-Dchapulin`, `zig build test-chapulin` and `examples/dot_rotor.zig` (`build/dot.zig`). On
   2026-09-26 it moved onto chapulin's Zig API, a lazy dependency, and `-Dchapulin` went from it
   (c4milo/cocuyo#30). On 2026-09-27 it moved onto colibri's `tls.record.Client`, and the
   `chapulin` dependency went from cocuyo (§16 decision 32). On 2026-10-24 the build registered
   it as the module `chapulin` (§16 decision 38, as amended for §17 question 64).
6. A live check against the public resolvers that serve DoT: `dns.google`, `cloudflare-dns.com`
   and `dns.quad9.net`. `tools/dot_live/run.sh` runs it, on macOS, with each resolver's roots from
   the system store. On 2026-09-24, with chapulin at `5f8e824`, all three resolved `example.com`:
   `dns.google` over an RSA chain ending at GTS Root R1, the other two over ECDSA chains ending at
   SSL.com's ECC root and DigiCert Global Root G3. A name the certificate does not carry, and a
   root the chain does not end at, each failed the lookup, with no query sent in the clear. Only
   IPv4 was tried: the machine had no IPv6 route. Resumption was tried live the same day, with
   chapulin at `0cc5355`: the example resolves a second name once the first connection has closed
   idle, over a connection that spends the ticket the first kept. `cloudflare-dns.com` and
   `dns.quad9.net` resumed. `dns.google` answered the resumed hello with a `handshake_failure`
   alert, and the engine opened the connection again in full, as TLS rule 8 says, and was
   answered. chapulin offered no `signature_algorithms` beside a ticket, and Google refuses such a
   hello even with a good ticket: OpenSSL resumed 6 times of 9 against it, chapulin 0 of 10, and
   chapulin with the schemes added 5 of 6. chapulin `20df0b8` changed two things
   (its docs/decisions.md 55). Its resumed hello offers the schemes, and it completes a declined
   ticket as a full handshake in the same connection. With it all three resumed, `dns.google` in
   9 lookups of 9. On GitHub's macOS runner the same day, `dns.google` and `dns.quad9.net` each
   declined the ticket, and chapulin finished each handshake in full on the same connection: the
   fallback for a declined ticket, seen live. An earlier run there timed out through `dns.google`
   once, which the next run did not repeat. The example
   reads whether a handshake resumed from chapulin's `psk_selected`. TLS rule 8's reconnect stays,
   for a resumed handshake that fails some other way. Since the same day the check runs once a
   day on macOS in CI's `dot-live` workflow, against chapulin at a pinned commit. It is not a
   gate: a failure there can be a resolver changing what it does, as Google's refusal was. On
   2026-09-27 it passed over colibri's `tls.record.Client` at colibri `a6a4791` (§16 decision
   32): all three resolvers resolved and resumed, read AAAA, MX, TXT and HTTPS records, and refused
   a name the certificate does not carry and a root the chain does not end at, and Cloudflare, known
   by its leaf key alone, resolved and resumed as well. Google shows one of two chains for
   `dns.google`, by the frontend a connection reaches: the leaf issued by WR2, and WR2 by GTS
   Root R1, or the leaf issued by WE2, and WE2 by GTS Root R4. With GTS Root R1 alone, two runs
   in nine were refused through Google. Their logs print no chain, so that they met WE2 is
   inferred from the later ones. On 2026-10-01 the check added GlobalSign ECC Root CA - R4,
   which issued neither chain, so a WE2 frontend stayed refused, as strict mode must refuse it:
   one scheduled run of eleven, and four of eleven of the DoH check, each log with the WE2 chain
   printed beside the failure. Since 2026-10-11 the check hands in GTS Root R1 and GTS Root R4,
   and says which chain a run met. Each chain carries a third certificate, its root's name and
   key signed by GlobalSign Root CA, which chapulin's walk does not read once an anchor has
   verified the second. That day every connection to 8.8.8.8 from here was shown the WR2 chain,
   in ten runs of the check in a row. The WE2 chain was captured from a Google web frontend that
   shows it for `dns.google` and answers no DNS. chapulin's walk verified it with the two roots,
   and refused it with the roots of 2026-10-01. The DoT and DoH examples completed their
   handshakes with that frontend with the two roots, and ended them during the handshake with
   the roots of 2026-10-01.

Checks, one for each piece:

- A mixed list trips `assert_valid`, and an all-TLS list passes it.
- A TLS server with neither a name nor a pin, or with more pins than the bound, is invalid.
- RFC 7858 Appendix A's two pins read to their bytes, and a pin in any other text is refused:
  the wrong length, a character outside RFC 4648's alphabet, missing padding, nonzero pad bits.
- A padded query's length is a multiple of 128 octets, and one over UDP has no Padding option.
- A TLS configuration never asks for a datagram, which the lookup model's `use_tcp` theorem
  already states.
- The engine model's invariants hold with the handshake stage in, and the replay agrees.
- A certificate that does not match the name fails the lookup over to the next server, and no
  query goes out on port 53.
- A lookup whose every handshake failed ends in `AllServersFailed`, and one no server answered
  in `Timeout` (§16 decision 25).
- An engine over a TLS configuration has no context until `use_tls` names one, and the
  session's `Context` carries no default (§16 decision 39).

## 22. DNS over HTTPS, the DNS half

§1 brought DoH in on 2026-09-23, split: the HTTP that carries it is colibri's, in colibri's
driver, over HTTP/2 or HTTP/3, and the DNS is cocuyo's. This section is the DNS half's plan,
and it records the owner's rulings of 2026-09-24. Each piece lands with its checks.

### The owner's rulings of 2026-09-24

- The resolver speaks DoH. DoH servers go in `Config`. The table hands the driver an HTTP request
  to make for each transaction, and the driver hands each answer back by handle. Search lists, CNAME
  chains, failover, the cache and the `getaddrinfo` shape all work over DoH as over UDP. A codec
  alone was the alternative, and it leaves the driver to rebuild cocuyo's policy.
- The URI template is the driver's to expand (RFC 8484 §3, RFC 6570). cocuyo carries it in
  `Config` as text it never reads, and hands the driver the `dns` variable's value: the message
  in base64url, without padding (RFC 8484 §6). A GET expands the template with it; a POST sends
  the message itself as the body.
- A query over DoH is cache-friendly. Its ID is 0 (RFC 8484 §4.1). Its name is asked in the case
  it was given, with no 0x20, and it carries no DNS cookie. So the same question makes the same
  octets, and an HTTP cache can share the answer. The three anti-spoofing measures it goes
  without are for a datagram anyone can forge, and TLS already covers them. It is padded to 128
  octets, as a query over DoT is (RFC 8467 §4.1). A query as over UDP was the alternative, and
  RFC 8484 §4.1 advises against it: no two requests would be alike.
- A `Config` names its servers per server, and every server is one kind: cleartext, TLS or
  HTTPS. `Server` gains `https: ?Https`, and `Https` holds the URI template. Failover never
  crosses from an encrypted server to a cleartext one, which extends §21's all-or-none rule.

### What an HTTPS server changes

- **The lookup.** A lookup over DoH moves as one over UDP does: one request for each
  transaction, one answer, and a deadline that moves it on. Its poll asks for `send_https`
  (`send_request` since §23), which carries the message, the server, and the transaction the
  answer must name: the transaction's number within the lookup, which sits in padding
  `Transaction` already had, so a lookup is no larger. The driver says when the request went
  out, as it says a datagram did.
- **The answer.** HTTP correlates a request and its response (RFC 8484 §4.1), so an answer comes
  back by the lookup's handle and the transaction it answers, and not through the key table. An
  answer for a transaction the lookup has left is dropped, and so is any datagram. Of §7's
  checks, the ID and the source endpoint are HTTP's, and every other check stands: the question
  must be the one asked. A truncated answer is taken as one over a stream is, since there is
  nowhere else to ask, and marked `truncated`: TC there can say the server could not get the
  full answer (RFC 8484 §10), so no cache keeps it (§18). A handle is the caller's until it
  releases it, as for every other event: a request still open then is the driver's to forget.
- **The TTLs.** Every TTL of an answer, and the negative TTL of RFC 2308, is lowered by the HTTP
  `Age` the driver reports, and never below zero (RFC 8484 §5.1, a MUST). The cache keeps what
  is left.
- **An HTTP failure.** A response that is not 2xx carries no answer (RFC 8484 §4.2.1). The driver
  retries what HTTP retries, such as a 401 once it has credentials. What reaches the lookup is
  that this server failed this transaction, and the lookup moves to the next server, counting
  the failure against this one, as for a connection that failed. A lookup whose passes run out
  after one ends in `AllServersFailed` (§16 decision 25).
- **`use_tcp`.** Every query on a stream means TCP, and a DoH server takes HTTP, so
  `assert_valid` refuses the two together.
- **The engine.** The engine of §19 step 13 speaks no HTTP yet, and asserts that its
  configuration has no HTTPS server. colibri's driver was to drive DoH. Since 2026-09-25 the
  engine drives it over colibri's HTTP/3 (§16 decision 26, §24).

### New limits

| Constant | Value | Why |
| --- | --- | --- |
| `dns_variable_bytes_max` | 512 | the largest query without its prefix, 384 octets, in base64url without padding |
| `transactions_per_server_max` | 3 | the query and its two retries on one server, EDNS0 off and a server cookie; it shows a transaction's number never wraps |

### Order and checks

1. `core`: `Server.https`, and `assert_valid` refusing a list of more than one kind. Done
   2026-09-24.
2. The lookup's model: an HTTPS transport, its answer by transaction, and its HTTP failure.
   Design, model, code, in that order (§5). Done 2026-09-24: the theorem that a lookup over DoH
   never asks for a datagram or a stream, and 27 DoH configurations among the 82 walked.
3. `wire`: the `dns` variable, base64url without padding (RFC 4648 §5, RFC 8484 §6). Done
   2026-09-24, as `wire.doh.dns_variable`.
4. `resolver`: `send_https`, `on_https_answer` and `on_https_failed` (renamed for DoQ in §23),
   the query's shape, and the `Age`. Done 2026-09-24. The replay of every DoH transition the model reaches agrees with the
   lookup, and docs/mutations.md DH1 to DH21 and DM1 to DM3 record the checks broken.

Checks, one for each piece:

- A list of two kinds trips `assert_valid`, and a list of one kind passes it.
- The `dns` variable of a known message is the base64url RFC 4648 §10 gives for its octets,
  without `=`.
- A query over DoH has ID 0, the name as given and no cookie, and is padded to 128 octets.
  RFC 8484 §4.1.1's query for `www.example.com` is, octet for octet, the query cocuyo builds
  for it without EDNS0.
- An answer for a transaction the lookup has left is dropped; one for its current transaction
  is taken.
- An `Age` of 250 turns a TTL of 600 into 350, and an `Age` past the TTL into 0.
- An HTTP failure moves the lookup to the next server and counts one failure.
- The lookup model's theorems hold with HTTPS in, and the replay agrees.

## 23. DNS over QUIC, the DNS half

§1 brought DoQ (RFC 9250) in on 2026-09-23. For a stub, DoQ has DoH's shape with QUIC where
HTTP was: each query goes on a QUIC stream of its own, and its response comes back on the same
stream (RFC 9250 §4.2). So QUIC pairs a query with its answer, as HTTP does, and the ID is not
needed. This section is the DNS half's plan, and it records the owner's rulings of 2026-09-24.

### The owner's rulings of 2026-09-24

- QUIC is colibri's driver's, over rotor, as DoH's HTTP is (§22). cocuyo supplies the DNS half,
  and its engine (§19 step 13) does not speak DoQ. The alternative was a QUIC interface in the
  engine, as chapulin's TLS has one. It is much larger, and the engine is not exported.
  Reversed on 2026-09-25 (§16 decision 26): colibri declined the driver, and the engine carries
  DoQ over colibri's QUIC (§24).
- DoH and DoQ share one action. A lookup over either asks for one request for each
  transaction and takes the answer by the transaction's number. So `send_https`,
  `on_https_answer` and `on_https_failed` became `send_request`, `on_request_answer` and
  `on_request_failed` before either was released. The alternative was one action for each
  transport: two paths that differ in nothing the lookup reads.
- The name is "request", the word RFC 8484 and RFC 9250 share: a "DoH request", and an
  "outstanding request" a DoQ client cancels (RFC 9250 §4.3.1). "Exchange" was the first name,
  and the owner turned it down: it is RFC 8484's word for HTTP, and RFC 9250 never uses it this
  way. "Transaction" names every query cocuyo makes, and "stream" is cocuyo's word for TCP.
- A DoQ server is named as a DoT server is: `Server.quic: ?Tls`. It has a name, SPKI pins or
  both, and port 853, which is UDP here (RFC 9250 §4.1.1). DoQ authenticates as DoT does, and
  a stub should use the strict profile (RFC 9250 §5.1). A `Config`'s servers are still all one
  kind: cleartext, TLS, HTTPS or QUIC.
- A query over DoQ has DoH's shape: ID 0, which RFC 9250 §4.2.1 makes a MUST, no 0x20, no
  cookie, and padded to 128 octets (§5.4). QUIC's encryption, and its address validation
  (§5.3), cover what 0x20 and cookies defend against. The alternative kept 0x20 and cookies as
  DoT does.

### What a QUIC server changes

- **The lookup.** It moves as over DoH (§22): one request for each transaction, one answer,
  and a deadline that moves it on. Its message carries the two-octet length prefix every DoQ
  message has (RFC 9250 §4.2). The driver writes it on a new client-initiated stream and ends
  the stream with FIN. It hands back the response's message, without the prefix, with an `Age`
  of zero.
- **The answer.** An answer for a transaction the lookup has left is dropped, as over DoH. The
  driver cancels that stream with STOP_SENDING (§4.3.1): that is QUIC's, and the driver's.
- **A failure.** A stream the server resets (§4.3.2), a connection that fails (§4.4) and a
  handshake that fails each end the request without an answer. The driver says so, and the
  lookup moves to the next server, counting a failure against this one. A lookup whose passes
  run out after one ends in `AllServersFailed` (§16 decision 25).
- **0-RTT.** Only a QUERY or a NOTIFY may go in 0-RTT data (§4.5), and every message cocuyo
  builds is a QUERY. So the driver may use 0-RTT; the privacy trade-off of §7.1 is its own.
- **No fallback.** RFC 9250 §5.2 lets a client fall back to DoT, then to cleartext, by its usage
  profile. A strict profile does not fall back, and the servers are all one kind (§21).
- **No keepalive.** A DoQ message must not carry edns-tcp-keepalive (§5.5.2). cocuyo sends it
  on no transport.
- **The engine.** It asserts that its configuration has no QUIC server, as it does for HTTPS,
  until §24 makes it carry DoQ.

### Order and checks

1. `core`: `Server.quic` and `Transport.quic`. `assert_valid` refuses a list of more than one
   kind, a QUIC server it cannot authenticate, a QUIC server on port 53 (RFC 9250 §4.1.1), and
   `use_tcp` beside QUIC. Done 2026-09-24.
2. The rename, and the lookup model: its HTTPS transport becomes the request transport, and
   the walk runs every request configuration for DoH servers and for DoQ servers. Done
   2026-09-24: `request_never_stream` holds, and 27 DoQ configurations join the 82, for 109.
3. `resolver`: a DoQ message with its prefix, in DoH's shape. Done 2026-09-24. The replay of
   all 2.2 million transitions agrees with the lookup, and docs/mutations.md QU1 to QU9 record
   the checks broken.

Checks, one for each piece:

- A list with a QUIC server and a server of another kind trips `assert_valid`. A list of QUIC
  servers passes it, and a QUIC server with neither a name nor a pin does not.
- A query over DoQ has ID 0, its length prefix, the name as given and no cookie, and its message
  is padded to 128 octets.
- An answer by transaction, a request that failed, and a truncated answer read as it stands and
  marked `truncated`, over DoQ as over DoH.
- The lookup model's theorems hold, and the replay agrees over the DoQ configurations.

## 24. The engine in the caller's loop: DoH, DoQ and a thread per core

§1 brought DoH and DoQ in with their transports in colibri's driver. On 2026-09-24 colibri
declined that driver: colibri owns no I/O, rotor is test-only there, and it has no TLS of its
own. The owner ruled on 2026-09-25 that every DNS capability comes from cocuyo. This section is
the plan those rulings make, and §16 decisions 26 to 28 record them.

### The owner's rulings of 2026-09-25

- DoH and DoQ are the engine's. It carries DoQ over colibri's QUIC and DoH over colibri's
  HTTP/3, with chapulin's QUIC mode as their TLS, as it carries DoT over chapulin's record
  transport. The library in `src/` still depends on nothing. The engine in `io/` may use
  colibri, and colibri's library never uses cocuyo. (Decision 26.)
- The engine plugs into the caller's loop. Embedded in a consumer, it runs on the consumer's
  rotor loop, beside whatever else the consumer drives there, colibri's connections included.
  On its own, it runs on a loop of its own. The components of an image share one loop on each
  thread, and nothing else. (Decision 27.)
- A thread per core: one loop on each core, one engine on each loop, and nothing shared between
  cores. (Decision 28.)
- An image defines chapulin's `ch_rand_bytes` and `ch_assert_fail` once, for every chapulin
  object and every user of chapulin it links, and each must be safe to call from several threads
  at once. Ruled on 2026-09-24 (§21, chapulin's docs/porting.md). Since colibri#71, on
  2026-09-27, no object cocuyo links imports `ch_rand_bytes`, and `ch_assert_fail` is the one
  hook left.

### What already holds

The engine was written for a loop it does not own:

- `init` takes the caller's `*rotor.Loop`, and never makes one.
- Every operation it submits carries its `tag` in the high bits of `user_data`, and `apply`
  returns false for an event that is not its own, which goes back to the caller untouched.
- `loop_operations` says how many operations the loop must hold for it, so the caller sizes the
  loop's `Options` for every component it runs.
- Nothing in it is global but chapulin's thread-local stream, and nothing allocates (CLAUDE.md
  non-negotiable 2). The engine is a value its caller declares, and since 2026-10-11 its cache's
  memory is a second one (the cache's memory, below).

So a consumer that ticks its loop hands each event to the engine's `apply` first, and to its own
handlers when `apply` says the event is not the engine's.

### What changes

1. **The engine is exported.** `build.zig` registers it as a module beside `cocuyo`, and ships
   `io/`. The owner named both on 2026-09-25: the module is `cocuyo_rotor`, cocuyo's resolver
   bound to rotor, and its type is `Resolver`, which holds the table, `cocuyo.Resolver`. A module
   named `rotor` was the alternative, and it collides with rotor's own in every consumer's build;
   `EventLoop` for the type says it owns the loop, when it runs on the caller's. The consumer binds its `rotor` import, and colibri's modules once it speaks DoH or
   DoQ, so an image holds one rotor and one colibri, and the engine's `rotor.Loop` is the
   consumer's own type. cocuyo's builds bind its lazy rotor, as the comparison of §19 step 15
   does today. The ruling of 2026-09-22 that held the engine back gives way: a consumer asks.
2. **chapulin's hooks move to the image.** Today `io/io_chapulin.zig` defines `ch_rand_bytes`
   and `ch_assert_fail`, and its `ch_rand_bytes` panics when the stream it reads is not the
   engine's. In an image where another user of chapulin draws too, one definition serves both.
   So the hooks become a module the image binds: a thread-local stream that each user of
   chapulin sets around the calls that can draw (§21), and one `ch_rand_bytes` that reads it.
   cocuyo ships the module. An image with other users of chapulin binds cocuyo's for every
   user, or its own with the same surface. Since colibri#71, on 2026-09-27, the module holds
   `ch_assert_fail` alone: each session hands its stream to colibri's `start`.
3. **A request interface.** The TLS session interface of §21 lets the engine speak TLS without
   naming chapulin. A request interface lets it carry DoH and DoQ without naming colibri. `Options` gains
   the request transport's type:
   - colibri's QUIC and HTTP/3, over chapulin's QUIC object in colibri's `tls`, fill it where
     the build resolves colibri (decisions 29 and 32);
   - the twin fills it in the gate;
   - a type that refuses fills it by default, as `tls.None` does.
4. **The engine speaks DoQ and DoH.** §22 and §23 wrote the DNS half. This is the rest:
   - A connection to a server is one QUIC connection over one UDP socket. It is up when the
     handshake has ended and the negotiated ALPN is `doq` (RFC 9250 §4.1) or `h3` (RFC 9114
     §3.2). colibri does not check the ALPN, so the engine does.
   - A request goes on a new client-initiated bidirectional stream.
     - Over DoQ the stream carries the message with its prefix, then FIN (RFC 9250 §4.2), and
       the answer is read to FIN.
     - Over DoH it carries a GET, with the template expanded with the `dns` variable and
       `accept: application/dns-message` (RFC 8484 §4.1). A 2xx answer's body goes to the
       lookup with its `Age` (§5.1). Any other status fails the request (§4.2.1).
   - A request the lookup has left, for a new transaction or a released handle, is cancelled.
     Over DoQ that is STOP_SENDING with DOQ_REQUEST_CANCELLED (RFC 9250 §4.3.1, a MUST).
   - A stream the server resets, a connection that fails and a handshake that fails fail every
     request on it, once each. Decision 25 counts each as the server's failure.
   - Each server keeps its newest ticket, used once, as TLS rule 8 has it. There is no 0-RTT,
     since chapulin's QUIC mode and colibri refuse it. RFC 9250 §4.5 allows 0-RTT and requires
     nothing.
   - The idle timeout is negotiated (RFC 9250 §4.4), and a connection near it takes no new
     request.
   - DoH goes over HTTP/3 first. HTTP/2 joined the plan on 2026-09-26, once colibri's h2 client
     had its TLS (c4milo/colibri#7): HTTP/3 first and HTTP/2 when it fails (DoH over HTTP/2,
     below). Since decision 33, on 2026-09-28, colibri's `client.Channel` carries both (DoH over
     colibri's client, below).

### The engine's request rules, written on 2026-09-25

These extend the stream's and the datagram's rules of §19 step 13, and the TLS rules of §21, for
the engine model to be written from before the code is. A request configuration's servers are
all DoQ or all DoH (§22, §23), and the rules hold for both. Where they differ, the rule says so.

1. **A connection for each server.** Each server of a request configuration has a connection
   slot of its own, as TLS rule 6 has it, and a connection is never closed to make room. A
   connection is one QUIC connection over a datagram socket of its own, whose receive is held to
   the datagram's rules 1 to 3. It opens when the drive first takes a request for its server:
   the socket is opened, its receive armed, and colibri makes the client's first flight.
2. **Up once the handshake ends, on the right protocol.** The connection is up when colibri says
   the handshake has ended and the ALPN negotiated is the transport's: `doq` (RFC 9250 §4.1) or
   `h3` (RFC 9114 §3.2). colibri does not check it. Any other protocol fails the connection
   (rule 7).
3. **A request is taken at once.** The drive takes a lookup's request onto its server's
   connection whatever the connection's state, and tells the lookup it went out, so the lookup's
   deadline covers the handshake as well. The request's bytes are copied into a request slot,
   one for each lookup slot: over DoQ the message with its prefix, over DoH the message alone.
   Over DoH the channel builds the GET from the message. The exchange holds the GET's path in a
   buffer of its own, of `doh_request_bytes_max` octets (rule 21; DoH over HTTP/3, the path).
   colibri reads a stream's bytes by offset until the server acknowledges them, so they
   cannot stay in the lookup's send buffer, which the lookup's next poll writes over.
4. **A request waits for its connection.** A request taken while its connection opens or
   handshakes waits in the connection's queue. When the connection is up, each waiting request
   opens its stream in the order it was taken, and supplies its bytes, then FIN. A stream colibri
   cannot open yet, for want of the server's stream credit or, over DoH, of a free answer
   buffer, waits, and each drive asks again.
   Every datagram received is followed by a drive, so the credit's arrival is. The model gives
   the server credit for every request.
5. **The answer by its stream.** A stream the server ends with FIN is read whole, into one buffer
   the engine keeps for the purpose, and handed over at once: the table reads an answer before
   the call returns. Over DoQ the message goes to the lookup without its prefix, with the
   transaction the request carried and an `Age` of zero. Over DoH a 2xx response's body goes with
   its `Age` (RFC 8484 §5.1), and any other status fails the request (§4.2.1). The lookup hears
   it only if the request's attempt is still its own, as stream rule 7 has it for a send. Over
   DoQ the stream must hold one message and its prefix, and the message's ID must be 0: a FIN
   before the prefix's octets have come, octets after them, or another ID is a protocol error
   (RFC 9250 §4.2, §4.2.1, §4.3.3). The engine fails the connection, as rule 7 says, which is
   the silent abandonment §4.3.3 allows. An answer longer than the buffer fails it too, as an
   answer longer than a TCP connection's frame does. The buffer holds a message of
   `tcp_message_bytes` and its prefix, since a DoQ stream holds what a TCP connection holds
   (§4.2).
6. **A request the lookup left is cancelled.** When the drive finds a lookup has left the
   transaction its request carries, because its deadline passed, it moved on, it ended, or it was
   cancelled or released, the engine cancels the stream. It sends STOP_SENDING and resets its own
   side, so colibri needs the request's bytes no more. Over DoQ STOP_SENDING is a MUST, with
   DOQ_REQUEST_CANCELLED (RFC 9250 §4.3.1). Over HTTP/3 ending both directions is a SHOULD (RFC
   9114 §4.1.1), with H3_REQUEST_CANCELLED (§8.1). The request slot is free
   from then, and whatever the stream carries later tells nobody.
7. **A failure fails each request on it, once.** A stream the server resets fails its request. A
   connection fails for a handshake that fails, a connection error, the server's close, an idle
   timeout, a receive or a send that fails, or a socket the system refuses. Then each request on
   it whose attempt is current hears it failed, once, and the connection closes. Decision 25
   counts each as the server's failure. A request taken later opens the connection again.
8. **A datagram at a time.** A connection sends one datagram at a time, from a buffer of its
   slot's that is lent to the loop from the send's submission to its final event (rotor decision
   5, rule 3). The next datagram is asked of colibri when the buffer comes back, and a slot
   opened again sends nothing until an earlier incarnation's send has ended. A send that fails
   fails the connection (rule 7). One the loop refuses stays in the buffer and goes at the next
   drive, before anything the transport makes after it. It never left the host, so sending it
   later sends it once, where asking colibri again would wait for its loss timer.
9. **An idle connection closes.** A connection with no request on it for `quic_idle_ns`, or one
   with no request on it and less than `quic_idle_margin_ns_min` left before the idle timeout it
   negotiated (RFC 9250 §4.4), closes. A request taken for such a connection closes it first,
   which is §4.4's SHOULD: a client checks the idle time before it sends a query, and opens a
   new connection when little is left. The engine has colibri make CONNECTION_CLOSE, with
   DOQ_NO_ERROR (RFC 9250 §4.4) or H3_NO_ERROR (RFC 9114 §8.1), and closes the socket once that
   datagram has gone. A request taken meanwhile waits, and opens the connection again once it
   has closed. The model leaves out the negotiated timeout: the twin's is never near in the
   replay.
10. **Tickets.** Each server keeps the newest ticket its connections were given, spent once, and
    dropped at its lifetime or 7 days after it came, as TLS rule 8 has it. chapulin finishes a
    declined ticket as a full handshake on the same connection, so a decline is no failure.
11. **One timer.** The engine keeps one timer, due at the sooner of the table's deadline and each
    connection's next QUIC deadline. When it fires, colibri is told of each connection that is
    due, and a connection colibri closes there fails as rule 7 says.
12. **A DoH request asks for no compression it can avoid.** Its GET carries `accept-encoding:
    identity`. A request with no Accept-Encoding leaves the server free to apply any content
    coding (RFC 9110 §12.5.3), and the engine decodes none. A 2xx response whose Content-Encoding
    names a coding other than `identity` fails the request, since its body is not the DNS
    message (§8.4). `:path` carries the query in the `dns` variable, and it goes as a literal
    with QPACK's N bit (RFC 9204 §4.5.4): never in the dynamic table, where its value could be
    probed through what compresses (§7.1, §7.1.3). colibri's encoder takes that choice for each
    field line. HPACK has the same literal, for when HTTP/2 joins. The rest stays as it is: a
    DNS message compresses its names (RFC 1035 §4.1.4), which the codec reads, and TLS 1.3
    compresses nothing (RFC 9846 §4.2.2).
13. **A GOAWAY drains the connection.** Written on 2026-09-25 (c4milo/cocuyo#17). A server that
    sends GOAWAY takes no new stream, and answers each it took before the stream the GOAWAY names
    (RFC 9114 §5.2). The transport says it came, once, with `next`, and the connection drains:
    its streams go on until each is answered or reset, a request taken meanwhile waits in its
    queue, and once no stream is left it closes as an idle connection does (rule 9), and opens
    again for what waits. A stream the server will not process is reset, and its request fails,
    which §5.2 lets the client retry and the lookup's failover does. A connection that fails while
    it drains, the server's close among the ways, fails the requests on its streams, and opens
    again for those in its queue, which never went to it. The same holds for a failure while the
    engine's own close is going, its timer's or its CONNECTION_CLOSE's send: the connection has
    closed either way, and what waits opens it again. A GOAWAY after the first changes nothing
    (§5.2: "An endpoint MAY send multiple GOAWAY frames"). DoQ has no GOAWAY (RFC 9250): a DoQ
    server that stops taking queries stops granting streams, and closes. The model holds it with
    four checks, which four mutants break (docs/mutations.md RQ12 to RQ15), and the replay agrees
    with it over TLC's full run of 4,020,000 events.

Since 2026-09-29 (c4milo/cocuyo#33) rule 13 holds for no request connection. They carry DoQ
alone, which has no GOAWAY (RFC 9250), and colibri's channel handles DoH's (rules 18 to 25). So the
drain went from the design, the model and the code. What rule 13 said of a failure while the
engine's own close is going stands, and rule 9 carries it: the connection fails none of the
requests that wait, since none went to it, and it opens again for them.

The model holds rules 1 to 4 and 6 to 11. Rules 5 and 12 are about octets, and the model reads a
stream's answer as an event, with no octets. The invariants the model gains:

- A request slot is free, or holds one request, on its lookup's server's connection.
- A request has a stream only on a connection that is up, and waits only on one that is
  handshaking or closing.
- A closing connection fails none that waits when it fails.
- A stream's request is its lookup's current attempt, or it has been cancelled.
- A connection that fails leaves no request on it, and each current attempt heard of it once.
- A connection's datagram buffer is lent exactly when a send of it is in flight.
- A connection is up only with its transport's ALPN.

### The request interface, written on 2026-09-25

The engine does not call colibri by name. It is generic over a QUIC connection type in its
`Options`, as §21's session interface makes it generic over a TLS session. The type's functions are
colibri's `quic` and `h3` over chapulin's QUIC object, in the engine's words:

- `start` begins a connection to a server, from its `Tls` (the name, the pins), the protocol the
  configuration's kind asks (`doq` for a QUIC server, `h3` for an HTTPS one), a kept ticket, the
  wall clock and the engine's seeded stream. It makes the first flight. The wall clock and the
  stream are the context's, which the consumer hands `use_quic`, and since 2026-10-11 the engine
  holds none until it does (the context a session starts from, below).
- `receive` takes one datagram. What it did is read with `next`, one thing at a time: the
  handshake ended, and on which protocol; the handshake failed; a stream was answered; a stream was
  reset; the connection closed, by the server, an error or the idle timeout; a ticket came. An
  answer's octets are written into the buffer `next` is handed, which is the engine's (request
  rule 5), and the answer says how many there were, even past the buffer's end. Over DoH it
  carries the status, the `Age` and whether the content is a DNS message in no content coding
  (request rules 5 and 12). A stream `next` calls answered or reset reads its slot's bytes no more.
- `request` opens a stream for a request slot, or says it cannot yet, for want of the server's
  stream credit. It is handed the slot's bytes, the first of which hold the lookup's message:
  with its prefix over DoQ, where the stream carries them and then FIN. Over DoH it makes the
  slot's bytes a GET built from the server's template and the `dns` variable, with
  `accept-encoding: identity` and a never-indexed `:path` (request rule 12). The slot's bytes
  stay the transport's until the stream no longer needs them (request rule 3), and there are
  `request_bytes_max` of them.
- `cancel` sends STOP_SENDING and resets the engine's side of a stream (request rule 6).
- `datagram` writes the next datagram the connection owes into the connection's buffer, at most
  `datagram_bytes_max` octets, or nothing.
- `deadline` gives the connection's next QUIC deadline, and `expire` tells it the instant came.
  What that did is read with `next` (request rule 11). `idle_left_ns` says how long the
  connection has before its negotiated idle timeout (request rule 9).
- `close` makes the CONNECTION_CLOSE of an idle close (request rule 9), and `wipe` drops every
  secret.

Three types fill it:

- `io/io_quic.zig` fills it from colibri's `quic` and `h3`, over chapulin's QUIC session in
  colibri's `tls`. It is built where the build resolves colibri, a lazy dependency (decisions 29
  and 32), as `io/io_chapulin.zig` is. Since 2026-10-11 its session is the one the consumer
  names, and chapulin's is the one a consumer on a network names (decision 38).
- The twin fills it with `sim.quic`, whose datagrams carry what happened in one octet and the
  stream it happened on, as `sim.tls`'s records carry a handshake step. The twin's servers script
  it, and the replay drives the model's steps with it one by one.
- `quic.None` refuses a request configuration at `init`, as `tls.None` refuses a TLS one. It is
  the default.

The model's QUIC timer takes no time: the lookups' deadlines are the model's only clock. So the
replay makes a twin connection due at the instant the walk reaches its `qtime`, and the engine's
one timer fires there, with the outcome the walk names.

A spike on 2026-09-24 ran both through colibri's test client and chapulin's QUIC object, outside
every repository. Cloudflare and Google answered DoH over HTTP/3. AdGuard and NextDNS answered
DoQ; AdGuard answered three names on one connection, and resumed a second. A wrong root failed
the handshake with `unknown_ca`, and every server accepted ChaCha20-Poly1305, the one suite
chapulin's QUIC mode offers.

### colibri under the request interface, written on 2026-09-25

colibri's `quic` module fills the request interface. It allocates nothing and owns no I/O: every
buffer is the caller's, and a datagram goes in and comes out as octets. What it asks of the type
that holds it:

- **Two vtables.** A connection takes a TLS provider, `tls.QuicVTable`, and a packet-protection
  suite, `crypto.suite.VTable`. The provider installs each level's keys into the suite as the
  handshake reaches it.
- **State, not events.** colibri reports a close and a completed stream from `receive`. The
  handshake's end, an answered stream and a reset stream are read off the connection's state, after
  each `receive`, each send and each timer. The client's handshake usually ends inside a send, when
  the provider writes the client's Finished.
- **Bytes read again.** colibri reads a stream's bytes through a stream provider at every send
  that carries them, a retransmission included, and an answer can arrive before the server has
  acknowledged the request. So `io/io_quic.zig` copies each request into a buffer of its own,
  one for each stream, and keeps it until the stream's sending half is acknowledged or reset.
  The interface's promise that a stream `next` reported reads its slot's bytes no more holds.
- **A cancelled stream is drained.** A stream frees its place in colibri's table once both halves
  have ended. `io/io_quic.zig` reads a cancelled stream to its end, or past the server's reset,
  and tells nobody.
- **A send can fail, and `datagram` cannot.** A send colibri refuses makes a CONNECTION_CLOSE owed,
  and `next` says the connection closed.
- **The timer is read, not asked.** `connection_timer.next` takes the connection mutably, so
  `deadline` gives the value `io/io_quic.zig` read after its last call.
- **ALPN is the engine's to check.** colibri never reads it; the provider says what was negotiated.

So `io/io_quic.zig` is generic over the provider and its suite, which its `Options.Session`
names. Since 2026-10-11 the option has no default (decision 38, and the session a connection
names, below):

- `io/io_chapulin_quic.zig` puts colibri's `tls.quic.Client`, chapulin's QUIC session, behind
  both vtables (decision 32). It is built where the build resolves colibri, as the DoT session
  is, and the live check of step 4 runs it against AdGuard and NextDNS. Since 2026-10-20 the
  build registers it as `chapulin_quic` (decision 38, as amended).
- `io/io_quic_plain.zig` is a provider and a suite that encrypt nothing, for the gate: the
  handshake's messages are made-up octets at the Initial, Handshake and 1-RTT levels of RFC 9001
  §4, in the order §4.1.5's Figure 5 puts them. A packet is sealed by appending sixteen octets,
  the length of the tag every QUIC cipher suite adds (RFC 9001 §5.3), which check nothing but the
  length. It is written from colibri's two vtables and RFC 9001, and it is test-only: it
  authenticates nobody, and it is never for a network.

### chapulin under colibri, written on 2026-09-25

chapulin's QUIC object fills both of colibri's vtables almost one to one: it owns every key,
derives the Initial keys from the Destination Connection ID (RFC 9001 §5.2), applies and removes
header protection, and moves handshake octets one level at a time. Since 2026-09-27 colibri's
`tls.quic.Client` puts it there (decision 32), and `io/io_chapulin_quic.zig` is the session over
it. What its build and its checks give it:

- **The object.** colibri's `tls` builds it from the chapulin colibri pins, `RAND=session
  TRUST=webpki TRANSPORT=quic-nonblocking ROLE=both`, beside the TCP object the DoT session runs
  over. Both import `ch_assert_fail` from `chapulin_hooks`, and no other hook since colibri#71.
  They were built `RAND=extern` before it. colibri compares each object's build record
  with the headers it translated, once for each configuration. Until 2026-09-27 the session linked
  an object made from a chapulin checkout, `bin/chapulin-quic-nonblocking.o`.
- **A name, pins, or both, as over DoT.** Since chapulin `3d5db4e` its QUIC mode takes a
  configuration as its record transport does (its decisions 64 and 65). The session tells colibri
  what the DoT session does: a name with the context's anchors and the clock, and pins as they
  are. A DoQ server known by pins alone, RFC 8310 §6.3's "SPKI + IP", gets no anchors and no
  clock, and is known by its leaf's key. A configuration chapulin refuses, such as a name with no
  anchor, fails the session's start, and the lookup ends in `AllServersFailed`. Until then the
  session refused pins, because chapulin's QUIC mode did.
- **The engine's stream, handed to colibri's `start`.** chapulin draws when its session starts,
  which colibri's provider does at `set_transport_params`, and when handshake octets arrive, at
  `provide_handshake`, a HelloRetryRequest for P-256 among them. Since colibri#71, on 2026-09-27,
  every draw comes from the stream the session hands `start`, and the connection gets colibri's
  provider itself. Until then the session handed it a provider of its own, which entered the
  stream around those two calls and passed every call on to colibri's.
- **One QUIC object in an image**, colibri's. Two would define the same calls. colibri's `h3` and
  cocuyo's session use the one object.
- **The suites the context's statement of the CPU allows.** cocuyo pins colibri v0.8.0 since
  2026-10-20. Its session runs the AES instructions only where the program states a
  data-independent timing for its thread (its decision 97, as amended for chapulin 0.2.0). The
  session states what its context carries, which the consumer fills (§16 decision 48). Under
  `data_independent`, and a probe that found the AES instructions, the hello offers
  TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256 and ChaCha20-Poly1305, in that order. Under any
  other value it offers ChaCha20-Poly1305 alone.

  At the pin, until decision 48, the session stated nothing. From 2026-09-27 colibri built its
  objects `SUITE=aesgcm AES=hw` for a target whose features include them, and `SUITE=chacha` for
  any other. Until 2026-09-27 the session's object offered ChaCha20-Poly1305 alone. The spike of
  2026-09-24 found every server accepted it.
- **QUIC version 2 beside version 1.** Since colibri v0.8.0 a client lists version 2 before
  version 1, and a server may switch it to version 2 (colibri's decisions 108 and 111). So DoQ
  and DoH on HTTP/3 may run on version 2. A ticket names the version of the connection that
  received it, and a session that resumes with it starts in that version. colibri seals each
  packet in the connection's version, and chapulin's suite asserts that its own version is the
  same. So `cocuyo_quic` starts colibri's connection in the version its session names,
  `original_version` (the session a connection names, below). colibri's own client does the
  same. Until colibri v0.8.0 both sides spoke version 1 alone (RFC 9000 §15).
- **A test on version 2.** A test of the session runs colibri's QUIC server over chapulin in
  memory, under the DoH tests' identity (`io/testdata/`). The server switches the session to
  version 2, and issues a ticket. It takes that ticket on the next connection, which starts in
  version 2 (`io_chapulin_quic_resume_test.zig`).

### colibri over the twin

The twin is in `src/`, which depends on nothing, so it cannot hold a colibri server. The twin's
network gains a responder instead: a server a test registers for a scripted server's QUIC port,
which is handed every datagram sent there and queues the datagrams it answers with, at the
instants it names. The engine's tests in `io/` register one that runs colibri's connection in its
server role over `io/io_quic_plain.zig`, and answers each stream's query with the scripted
server's answer. The engine then runs over colibri on the twin: real packets, streams, flow
control, loss and its recovery, with the twin's clock and its seeds.

### colibri as a dependency

colibri is pinned by hash in `build.zig.zon` as a lazy dependency (decision 29). `io/io_quic.zig`
is a module of its own, `cocuyo_quic`. It imports colibri's `quic`, and gives the type that a
consumer names in `Options.quic`. `cocuyo_rotor` never imports colibri. So a consumer binds
colibri only into the modules of the encrypted transports it speaks:

- For DoQ, colibri's `quic` into `cocuyo_quic`, and colibri's `quic` and `tls` into
  `chapulin_quic`, the session over chapulin (the session a connection names, below).
- For DoH, colibri's `client` and `tls` into `cocuyo_doh` (DoH over colibri's client, below).
- For DoT, colibri's `tls` and `tls_provider` into `chapulin`, the DoT session over chapulin
  (§16 decision 38, as amended for §17 question 64). The session's `io` is `cocuyo_rotor`.

The gate fetches colibri for the engine's tests over colibri on the twin. cocuyo's own build
resolves it for the DoT and DoQ sessions too, which import its `tls` (decision 32). The gate runs
the tests of both sessions and builds their examples. So a colibri that breaks a session fails the
gate. The library in `src/` never imports colibri.

An engine over colibri holds, for each server, colibri's connection, its receive pool, its two
scratch buffers and a request buffer for each lookup. Measured with `@sizeOf` on 2026-09-25, in a
Debug build on an Apple M1 Pro: colibri's connection is 141,248 octets, the pool 377,504, the
scratch buffers 21,832 and 3,923, and one connection of 256 streams 652,168 in all. An engine of
eight servers holds 5.2 MB of them. The pool is most of it, and it is the floor colibri keeps
beside its blocks: two for each of the 128 streams a connection may hold.

### DoH over HTTP/3, written on 2026-09-25

`cocuyo_quic`'s HTTP/3, which this section wrote, went on 2026-09-29 with `cocuyo_h2` (decision
33): colibri's channel carries DoH since (DoH over colibri's client, below). What the section says
of the template, its expansion and what an answer carries stands, in `doh` and `cocuyo_doh`.

§22 left a DoH server's URI template to the driver, and since decision 26 the engine is the
driver. The engine splits it, since the port its socket goes to is the template's, and
`cocuyo_quic` expands the path, since the interface's `request` builds the GET. A consumer that
speaks DoH names a type with `http3` set in its options, which adds colibri's `h3` to each
connection; one that speaks DoQ alone pays nothing for it. DoQ and DoH share everything below the
stream: the connection, the handshake, tickets, cancelling, the idle close and the timer. The
request rules and the model hold for both as they stand.

**The template, read when the connection opens.** The engine splits a server's template when it
opens a connection to it (`io/io_request_template.zig`). A template it refuses fails the
connection before a socket opens, as a configuration chapulin refuses fails at the session's
start. The lookup counts it as the server's failure and ends in `AllServersFailed`.

- It begins with the scheme `https`, in any case (RFC 3986 §3.1): DoH "MUST be used with the
  https URI scheme" (RFC 8484 §5).
- An authority follows `//`, and ends at the first `/`, `?`, `#` or `{` (RFC 3986 §3.2). It holds
  no expression, since the TLS name cannot change with a query. It holds no userinfo, which
  `:authority` must not carry (RFC 9114 §4.3.1). Its host is a registered name (RFC 3986 §3.2.2),
  and it is the name the certificate is checked against (RFC 9110 §4.3.4). An IP address is
  refused, since the session checks a name. The authority goes to `:authority` as the template
  writes it.
- A port may follow the host, and the connection goes to it: "establishing a QUIC connection to
  that address on the indicated port" (RFC 9114 §3.1), which is 443 when the template names none
  (RFC 9110 §4.2.2). The address is the configured endpoint's, since the engine resolves no host
  to reach a resolver. A port that is not digits, or is 0, is refused.
- The rest is the path's template, and it names `dns` in an expression outside a fragment: a GET
  carries the query only there (RFC 8484 §4.1).

**The path, expanded for each request** by `cocuyo_doh` (`io/io_doh_template.zig`).
RFC 6570's expansion, with `dns` the one variable defined (RFC 8484 §4.1) and every other one
undefined, so skipped (RFC 6570 §2.3, §3.2.1):

- The operators are those of Appendix A's table: none, `+`, `.`, `/`, `;`, `?` and `&`. A
  fragment, `#`, is not part of the request, so a template that uses one is refused.
- The value is base64url without padding (RFC 8484 §6), which holds unreserved characters alone.
  No operator encodes it (RFC 6570 §3.2.1).
- A prefix modifier on `dns` would cut the query, so a template that has one is refused. An
  explode modifier changes nothing for a string.
- A literal a URI allows is copied, and one it does not is written pct-encoded (RFC 6570 §3.1).
  A character §2.1 excludes refuses the template.
- An empty path is `/` (RFC 9114 §4.3.1).

At `start` the template is expanded once with a `dns` value `dns_variable_bytes_max` long, and
one whose path would pass `doh_request_bytes_max` is refused. The bound is on the path alone, the
`:path` of the GET. An exchange holds the path in a buffer of that size. Until 2026-10-14 this
section and the constant's comment gave the bound to the GET's HEADERS frame. That left 960 octets
for the path. The code gave the bound to the path, and the owner ruled for the code (§17 question
41).

The expansion has the whole buffer. A path that starts with `?` gives one octet of it to the `/`
that goes first. Until 2026-10-14 a path that starts with `/` also lost that octet. So `start`
refused such a template when its path at its longest was exactly 1,536 octets (§17 question 42).

**The GET.** Six field lines: `:method GET`, `:scheme https`, `:authority`, `:path`, `accept:
application/dns-message` (RFC 8484 §4.1) and `accept-encoding: identity` (request rule 12).
`:path` is never indexed (RFC 9204 §4.5.4). colibri's `write_request` checks the section, opens
the stream and writes the HEADERS frame into the request's slot, which the stream then carries
with FIN. That was `cocuyo_quic`'s HTTP/3, which went on 2026-09-29. Since then colibri's channel
builds the GET from an exchange, whose own buffer holds the path (request rule 21). No request
slot holds a HEADERS frame.

**colibri's `h3` under the interface.** What it asks, beside what `quic` asks:

- **Started once the handshake ends.** `h3`'s `start` opens its control stream and its QPACK
  streams and writes SETTINGS (RFC 9114 §6.2.1, §7.2.4.2). It asserts the server's transport
  parameters are there, so `cocuyo_quic` calls it when colibri first says the handshake ended,
  which is often inside a send.
- **The server's streams.** An `h3` connection lets the server open 8 unidirectional streams,
  where §6.2 asks for 3 at least, and gives each 1,024 octets of credit, as §6.2 recommends.
  colibri's `h3` tracks 8 of them. DoQ gives the server none.
- **One provider for both.** `h3` serves its three streams from its own buffers, and hands every
  request stream to `cocuyo_quic`'s, which keeps a request's octets as it does over DoQ.
- **Events, not state.** `h3`'s `receive` returns one event at a time: a response's header
  section, a piece of its content, its end, a reset, a refused stream, SETTINGS and GOAWAY.
  `cocuyo_quic` reads them all after each datagram, each send and each timer, since `h3` also
  reads the server's SETTINGS and QPACK streams there.
- **The grease** colibri draws its reserved setting and error codes from is drawn from the
  connection's seeded stream, as its connection IDs are.

**An answer's buffer.** `h3` takes a response's content out of colibri's pool as it arrives, a
piece at a time, and pieces of different streams come in turn. So an answer cannot wait in the
pool until it is whole, as a DoQ answer does. Each `h3` connection has `answers` buffers of
`tcp_message_bytes`, one for each response in flight, and a DoH request opens its stream only
when one is free. Until then it waits, as it waits for the server's stream credit (request rule
4). An answer is never lost for want of room, and at most `answers` requests are in flight on a
connection. A buffer for each request slot was the alternative, and it costs 64 KB for each
lookup. A shared arena was the other, and colibri keeps granting the server credit whatever the
arena holds, so an answer could arrive with nowhere to go.

**What an answer carries.** When a response ends, `next` hands its content over, with:

- its final status: an interim one (1xx) is skipped (RFC 9114 §4.1);
- its `Age` in seconds: the first member of the field's value (RFC 9111 §5.1), 0 when the field
  is absent or not a number, and 2^31 when the number is larger (§1.2.2);
- whether the content is a DNS message: `Content-Type` is `application/dns-message` (RFC 8484 §6,
  RFC 9110 §8.3.1: type and subtype compared in any case, parameters ignored), and every
  `Content-Encoding` is `identity` (RFC 9110 §8.4).

The engine hands a 2xx answer that is a DNS message to the lookup, with its `Age`. Any other
fails the request (RFC 8484 §4.2.1, request rule 12), and counts as the server's failure
(decision 25). Content longer than the buffer fails the connection, as request rule 5 has it.

**GOAWAY drains the connection** (request rule 13). colibri's `h3` reads the frame and refuses a
new stream after it, but it opens no connection and holds no request that waits, so the rest is
the engine's. `next` says the GOAWAY came, once. A request from the stream it names on is cancelled
and hears its stream reset, and no new stream opens. The engine drains the connection: requests
taken meanwhile wait in its queue, and once the requests before that stream are answered it closes
as an idle connection does and opens again for them. colibri's `h3` reads the control stream before
the request streams, and a server can send its GOAWAY ahead of the answers it promised, so the
drain waits for them rather than for the datagram's end.

**The idle close** sends H3_NO_ERROR in its CONNECTION_CLOSE (request rule 9, RFC 9114 §8.1).

### An independent server, written on 2026-09-25

Every other test of the engine's DoQ and DoH runs colibri's client against colibri's server, so a
bug both ends share, or a misreading of RFC 9250 in the test server, passes it; and the live checks
depend on public servers, which a test cannot tell what to do. `tools/interop/run.sh` runs the
engine against AdGuard's dnsproxy on the loopback, whose QUIC and HTTP/3 are quic-go's, with a
CA and a leaf of its own and a hosts file to answer from, so it needs no network. Over DoQ and over
DoH on HTTP/3, three names resolve at once, each on a stream of one connection, and a fourth over a
connection that resumes. A name the leaf does not carry, a root the chain does not end at and a
pin on the issuer's key are refused, and the leaf's key alone, with a backup pin, resolves. The
`interop` workflow runs it once a day. No conformance suite for RFC 9250 exists that this found,
nothing like h2spec for HTTP/2, so this is the one check of the protocol against another's reading.

On 2026-09-26 the check grew to every transport the engine speaks (c4milo/cocuyo#20, #21):

- Plain DNS over UDP and over TCP, through `examples/cleartext_rotor.zig`, the engine with no TLS.
  dnsproxy's own log, with `--verbose`, must show each lookup's queries on the transport asked
  for and none on the other, since dnsproxy answers both.
- DoT, several names on one connection and a fourth over a connection that resumes, the name and
  root refusals, and the pins, as DoQ has them. The DoT example takes a port now, as DoQ's does.
- Records beyond A over every transport. dnsproxy answers A from its hosts file and asks
  `tools/interop/zone.zig` for the rest, a server of the check's own on the loopback: AAAA, MX,
  TXT, one of them of two strings, and HTTPS of one name, asked at once, then a CNAME to it.
  dnsproxy reads each answer and writes it again, compressed its own way, before cocuyo reads it.
  Every record must read back as the zone wrote it (`examples/answer_text.zig` writes them out).

The live checks ask each public resolver for AAAA, MX, TXT and HTTPS at once as well, of a name that
has each, and require each type answered and every record of the type asked.

### A thread per core

An image runs one loop on each core and one engine on each loop. Nothing crosses between cores:

- Each engine has its own table, cache, connections, tickets and seeds. The seeds come from a
  CSPRNG, one set for each engine: two engines with one seed would draw the same transaction ids.
  Since 2026-10-11 the caller hands each engine its cache's memory (the cache's memory, below),
  and no two engines are handed the same.
- A `Config` is read and never written, so every engine may hold a pointer to one.
- A name one core resolved is a miss on another, and each core opens its own connection to
  each encrypted server. An image of `n` cores holds up to `n` times `servers_max` of them. A
  cache shared across cores was the alternative, and it needs a lock or atomics in the lookup's
  path, which the architecture refuses. A miss costs one round trip.
- cocuyo keeps no global mutable state, and the global-state rule holds it there: no
  container-level `var` under `src/` or `io/` but a `threadlocal` one.

Step 6 shows it twice, written on 2026-09-25:

- **On the twin, in the gate** (`io/io_threads_test.zig`). Two threads start together, each with
  a twin loop and an engine of its own, seeded apart, and both engines hold a pointer to one
  `Config`. The twin's network is thread-local (step 2), so each thread's scripted servers are
  its own, and each thread's answer with a TTL of their own. Both engines resolve the same names
  at once. Each must take an answer for every lookup it started, each carrying its own servers'
  TTL: an answer from the other thread's servers, or a cache the two shared, would carry the
  other's.
- **Over rotor, on the kernel's loops** (`examples/threads_rotor.zig`). Two threads, each with a
  rotor loop and an engine of its own, on one `Config`, resolve at once against a responder
  thread on the loopback, and each must take an answer for every lookup it started. CI runs it
  on Linux, where rotor runs io_uring, and on macOS, where it runs kqueue. The events of one loop
  cannot reach the other's engine, since each engine applies only what its own loop hands it,
  and each engine counts any event it refuses: there must be none.
- **Under ThreadSanitizer** (`-Dsanitize-thread`, Linux). The same example, with every module
  of cocuyo's and the engine's instrumented, after the comparison's planted race is reported.
  The sanitizer sees an access two threads share that nothing orders, whether or not the bad
  interleaving happened in the run.

### DoH over HTTP/2, written on 2026-09-26

`cocuyo_h2` and the request connections over TCP, which this section wrote, went on 2026-09-29
(decision 33), and the request connections carry DoQ alone since. Rules 14 to 16 stand for a
channel's TCP link, and rule 17 for a channel. The request connections no longer read the
transport after a send ends or where a request is held back, since only HTTP/2 needed those reads.

HTTP/3 runs over UDP, and a network may block it. RFC 9114 §3.1 says what a client does then:
"Connectivity problems (e.g., blocking UDP) can result in a failure to establish a QUIC
connection; clients SHOULD attempt to use TCP-based versions of HTTP in this case." A DoH server
may also speak HTTP/2 alone, the least version RFC 8484 §5.2 recommends.

**The owner's ruling of 2026-09-26** (decision 30):

- A DoH server is tried over HTTP/3 first, and over HTTP/2 when that fails. `Config` does not
  change: a DoH server is still its template. The engine's `Options` gains an HTTP/2 transport
  beside the QUIC one.
- The work goes in two parts. Step 7a carries DoH over HTTP/2 alone, in an engine built with the
  HTTP/2 transport and without HTTP/3. Step 7b holds both transports in one engine and races them:
  HTTP/3 first, HTTP/2 a short delay after it, and the server kept on the one that answered. 7b's
  rules and limits are written once 7a has landed.

**What HTTP/2 changes.** HTTP/2 and HTTP/3 carry the same request, and share nothing below it:

- The connection is TCP, TLS over the TCP, and HTTP/2 over the TLS (RFC 9113 §3.2). The session
  offers the ALPN token `h2`, and the connection is up only on it: "HTTP/2 connections over TLS
  MUST use protocol negotiation in TLS" (§3.3). colibri's `attach_tls` checks the token, TLS 1.3
  and the suite (§9.2), and the engine checks the token too, as request rule 2 has it.
- There is one connection to a server: "Clients SHOULD NOT open more than one HTTP/2 connection
  to a given host and port pair" (§9.1). Request rule 1 already says so.
- A request is a stream (§5.1). A HEADERS frame opens it, carries the GET and ends the client's
  side of the stream, since a GET has no content. The field lines are HTTP/3's six (request rule
  12): `:method`, `:scheme`, `:authority`, `:path`, `accept` and `accept-encoding` (§8.3.1).
- A request the lookup left is cancelled with RST_STREAM and the code CANCEL, which says "the
  stream is no longer needed" (§7). HTTP/2 has no STOP_SENDING, and a RST_STREAM closes both
  directions of the stream (§6.4).
- A GOAWAY drains the connection, as request rule 13 has it (§6.8). The streams above its last
  stream ID were never processed, so they fail, and the lookup's failover retries them. A
  connection whose stream identifiers run out drains the same way: "A client that is unable to
  establish a new stream identifier can establish a new connection for new streams" (§5.1.1).
- TCP resends what is lost, so the transport has no loss timer. HTTP/2 negotiates no idle
  timeout. So the transport's `deadline` is null and its `idle_left_ns` unbounded, and request
  rules 9 and 11 hold with nothing added. colibri keeps a deadline for the acknowledgement of its
  SETTINGS, and RFC 9113 §6.5.3 lets a client fail the connection past it ("MAY"). The engine
  does not. A server that answers without acknowledging is still answering, and one that answers
  nothing fails each request at its lookup's deadline.
- An idle connection closes with a GOAWAY of NO_ERROR, then the session's `close_notify`. RFC
  9113 §9.1 asks for the first: "the terminating endpoint SHOULD first send a GOAWAY". RFC 9846
  §6.1 asks for the second, before a party closes its write side.
- `:path` goes as a never-indexed literal (RFC 7541 §6.2.3), which an intermediary that
  re-encodes the request must keep as one (§7.1.3). colibri's `write_request` takes the mark for
  each pseudo-header field and each field line (colibri 3d86a42), and writes every line it is
  not told to mark as a literal without indexing (§6.2.2), so no line of a GET enters a table.
- Flow control is colibri's (§5.2, §6.9). A DoH answer holds at most 65,535 octets, the initial
  window of a stream (§6.9.2), and colibri opens the windows again as it reads.

**The request connection over TCP.** These extend the request rules, for the model to be written
from before the code is.

14. **A connect before the handshake.** A request connection over TCP opens a stream socket and
    submits its connect. The connect's address is lent to the loop until the connect's final
    event. The slot is not opened again while a connect of an earlier opening is in flight, as
    the stream's rule 10 has it: a request taken meanwhile waits in the queue. The connection
    opens at the event that gives the address back, before the drive polls, so a request that
    fails there is heard in the same drive. When the connect succeeds, the receive is armed and
    the transport makes its first flight. A connect that fails, or that the loop refuses, fails
    the connection (request rule 7).
15. **Octets, one send at a time.** A connection sends from its slot's buffer one send at a time,
    as request rule 8 has it for a datagram. A send that goes short leaves the rest in the buffer,
    and the rest goes next, before anything the transport makes after it: the octets are one
    stream, and TLS records go in the order they were sealed (RFC 9846 §5.3). The receive is
    multishot, into the TCP connections' chunks, and hands the transport the octets as they come.
    The transport keeps a partial record until the rest arrives, as TLS rule 7 has it. A receive
    that ends with no octets is the server's end of the stream, and fails the connection (request
    rule 7).
16. **No handshake, nothing to close.** A connection that goes idle before its handshake has
    ended has no session to close, and closes at once, as TLS rule 5 has it. One still connecting
    has its connect cancelled, and the address stays lent until the connect's final event (rule
    14).
17. **The transport is read after it moves.** Written on 2026-09-26 (c4milo/cocuyo#18). The
    engine reads what a connection's transport says after each receive and each expiry, and also
    after the connection's send ends and when the transport holds back a request the drive takes.
    Either can leave the transport with something to say that no octet from the server will
    prompt:
    - colibri's HTTP/2 reads no frame while the replies it owes have no room (colibri's decision
      39). So frames that came while its octets waited to go stay unread until a send has taken
      those octets, an answer among them.
    - A client whose stream identifiers have run out "can establish a new connection for new
      streams" (RFC 9113 §5.1.1). The transport holds the request back and says the connection
      drains, as a GOAWAY does (rule 13), when it is next read.

    Without these reads each waits for the server to send again. A server that owes nothing does
    not, so the answer waits, and the request with it, until the lookup's deadline. Every read
    tells what the transport held first, then what the read brought. The read after a request held
    back is where the drive takes it, so a lookup it tells of is polled in the same drive: at the
    drive's end it would wait for a drive that may not come. Every other reason to hold a request
    back brings a read of its own: streams in flight bring answers, and octets still owed bring a
    send's end (rule 4).

The model holds rule 17 with two moves of colibri's and one check:

- A receive that comes while the connection's send is in flight may leave a stream's answer or
  reset held, one at a time, which colibri tells at its next read.
- The environment may spend an up connection's stream identifiers. The next request taken on it
  waits, and the transport holds the connection's drain.
- The check: a transport holds a step only while a send of its connection is in flight, since the
  send's end reads it.

Two mutants break the rule (docs/mutations.md RQ21 and RQ22). With no read at a send's end, the
check fails. With none when a request is held back, the request waits on a connection that is
still up, which the invariant on where a request waits forbids. The replay's twin keeps a held
step until its next read, and spends a connection's stream identifiers when the walk says so. The
engine's side is broken against the walks and one engine test (TR1 to TR5).

**The interface.** A request transport says which socket it runs over: `socket` is `.datagram`
for colibri's QUIC and the twin's, and `.stream` for colibri's HTTP/2 and for a twin transport
over the twin's TCP. `datagram` becomes `output`, since over TCP what it writes is the next octets
of a stream, as many as the buffer holds. The rest of the interface stands.

The engine's request connections become one set for each transport: the QUIC set, for DoQ and
DoH over HTTP/3, and the HTTP/2 set. In 7a a DoH configuration goes to the HTTP/2 set when the
engine has one, whether or not its QUIC one speaks HTTP/3; 7b races the two. The replay's engine
holds both transports of the twin, so one engine type walks every configuration.

**The transport** is `cocuyo_h2`: colibri's `h2` connection under the request interface, as
`cocuyo_quic` puts colibri's QUIC there. It is a module of its own, and a consumer that speaks DoH
over HTTP/2 binds its `h2` import to colibri's. Its TLS is a session type in its options, as
`cocuyo_quic`'s is:

- For the gate, a provider of cocuyo's that encrypts nothing. Its records are framed as RFC 9846
  §5.1 frames a record, and its handshake messages are made-up octets that carry the ALPN each
  side offers and selects.
- For a consumer, colibri's `tls.record.Client`, whose provider is colibri's `tls.Provider`
  already (decision 32), built where the build resolves colibri, as `io/io_chapulin_quic.zig`
  is. It takes the name, the pins and the ticket DoT's session takes, and offers the ALPN token
  `h2`.

The template's expansion and the response's reading, which step 5 wrote for HTTP/3, read nothing
of colibri's. They move to a module both transports import.

**The model.** A request configuration gains a socket kind. Over a stream socket:

- A connection opens by connecting, and is `connecting` until the connect's event. While a
  connect of an earlier opening is in flight, the slot waits, `reopening`, until that connect's
  event.
- A send may end short, which keeps the rest to go first.
- A receive may end with no octets, which fails the connection.
- No transport timer fires.

Four checks hold the new rules, and five mutants break them (docs/mutations.md RQ16 to RQ20):

- A connect of the slot is in flight exactly when the slot's address is lent, one at most. So a
  slot opens only when no connect of an earlier opening is in flight.
- A connection that connects, or waits to, has no receive, and neither owes nor sends anything.
- A short send's rest goes before anything made after it.
- A receive that ends with no octets ends its connection's opening.

The replay drives a twin transport over the twin's TCP, whose octets are framed by a two-octet
length. So the walks' short sends and ended receives reach the engine as the model names them.

### DoH over colibri's client, written on 2026-09-28

colibri's `client` module carries HTTP requests to one origin behind one set of calls
(c4milo/colibri#70, its decisions 100 and 101). Its `client.Channel` holds a QUIC connection and a
TCP connection to the origin, and chooses between them. It opens QUIC first, and opens TCP when
QUIC's attempt fails or when a delay passes during QUIC's handshake. The first connection whose
handshake completes takes the requests, and the other closes. That is decision 30's race, which
step 7b was to write in the engine. The channel opens no socket and resolves no name: it asks its
caller to open a UDP flow or a TCP connection to an address the caller handed it. Its TLS is
colibri's `tls`, over chapulin (decision 32).

Since colibri v0.9.0, pinned on 2026-10-29, the channel is `client.ConnectionPool` (colibri's
decisions 125 and 126). The engine's DoH interface does not change. What changed in `cocuyo_doh`:

- The pool holds one TCP connection, `tcp_connections_max`, as the channel has one TCP link. The
  channel holds the memory the pool keeps it and its requests in, one request for each answer
  buffer.
- Each of colibri's calls and events about a connection names a `ConnectionHandle`. The channel
  keeps the handle of each link from its `open`, and names it in each call about that link.
- colibri says `send` when a TCP connection owes octets. The engine asks for a link's octets each
  time it can send them, so the channel reads that event past. `unheard_per_next_max` is 3.
- The owner approved both limits on 2026-10-29: `tcp_connections_max` new, and
  `unheard_per_next_max` from 2 to 3.
- The test server matches the root and a path of one segment itself, since colibri's router calls
  the program's functions (colibri's decision 127).

**The owner's rulings of 2026-09-28** (decision 33):

- colibri's `client.Channel` makes decision 30's choice. The engine holds one channel for each DoH
  server, and opens the sockets the channel asks for. Step 7b's race is not written, and
  `cocuyo_h2` and the HTTP/3 half of `cocuyo_quic` go. DoQ stays on `cocuyo_quic`, and `Config`
  does not change.
- A channel carries DoH on whatever version it comes up on: HTTP/3 over QUIC, and HTTP/2 or
  HTTP/1.1 over TCP. Over TCP it offers `h2`, then `http/1.1` (RFC 7301 §3.1), and colibri speaks
  HTTP/1.1 when the server selects it or selects nothing (its decision 88). RFC 8484 §5.2 calls
  HTTP/2 the minimum recommended version for DoH for speed alone, since earlier versions "are
  capable of conveying the semantic requirements of DoH". A server that answers over HTTP/1.1
  alone is slow, then, and not wrong.
- The channels are a fixed array in the engine, one for each of `servers_max` servers, as every
  connection set is. The alternative was a slice of channels the caller hands `init`, where an
  engine of one DoH server pays for one channel, and `init` changes.

**What the channel gives the engine**, at colibri `1fb8b33`, which v0.5.0 carries:

- **Exchanges in the caller's memory.** A request is an `HttpExchange`: the method, the path, the
  field lines, the response fields wanted with the octets their values go into, and the buffer the
  body goes into. `request` returns its id, and a `finished` event reports its end once: a
  response, or `refused` when the server processed none of it, `reset`, `closed`, `malformed`,
  `invalid` or `too_large`. After `finished`, or once `cancel` returns, the memory is the caller's
  again.
- **The path never indexed.** An exchange can ask for its path as a never-indexed literal (colibri
  `28d3736`): RFC 7541 §6.2.3 over HTTP/2 and RFC 9204 §4.5.4 over HTTP/3, as request rule 12 asks.
  HTTP/1.1 compresses no field line, so there the mark asks nothing.
- **What a GOAWAY leaves.** An exchange that a connection refused unprocessed, because it takes no
  new exchange, moves once to another connection (RFC 9113 §8.7, RFC 9114 §4.1.1). So request rule
  13's drain is the channel's, and the engine hears `refused` only when no connection took the
  exchange. Since colibri v0.8.0 that move shares its one budget with a resend (below).
- **One event at a time.** `receive` returns at most one: `open` a transport to an address, `close`
  one, `connected` on a protocol, a transport's `ticket`, an exchange `finished`, and `closed` once
  the channel was shut down and every exchange has ended. The caller reads until nothing is taken
  and nothing said, and again after each send and each instant, as request rule 17 has it.
- **Its size.** 987,216 octets, of which the QUIC connection is 700,472 and the TCP one 285,928.
  The caller places the QUIC connection's receive pool beside it, as `cocuyo_quic` does, since
  colibri `1fb8b33`, which the owner asked for on 2026-09-28: 377,504 octets for
  `quic_receive_bytes_default`, 66,560 octets of capacity. A server's channel and pool are
  1,364,720 octets, and eight servers' are 10.9 MB. Every window the channel advertises follows
  the pool's capacity (RFC 9000 §4.1).

**What colibri v0.8.0 changed**, pinned on 2026-10-20 (its decisions 120, 121 and 124):

- **A request and a response.** `HttpExchange` became two types. `client.Request` holds the
  method, the path, the field lines and the never-indexed marks. `client.Response` holds the
  fields wanted, the octets of their values and the body, then what arrived and how the exchange
  ended. `request` takes both, and the `finished` event names both. The memory stays the
  caller's.
- **One configuration.** `client.Config` holds one TLS value, and the channel builds the TLS
  configuration of each transport from it. Its `versions` name the protocols, so the type writes
  no ALPN list. `start_quic` draws the grease value and the two connection IDs itself.
- **A GET sent again.** A connection may close or fail before any octet of a request's response
  arrives. colibri then sends an idempotent request again, once, on another connection (its
  decision 124, ruling 3). A GET is idempotent (RFC 9110 §9.2.2), so each of the engine's
  requests can reach the server twice before the engine fails it over. The resend and a move
  after a GOAWAY share one budget, `moves_max`. A resend that is refused ends `closed`, not
  `refused`, since the first try may have reached the server. The lookup's deadline still bounds
  both tries (rule 22).
- **Names.** The root exports each type under its own name, such as `client.Address`,
  `client.Event`, `client.Input`, `client.Transport` and `client.Alternative`.
- **Its size.** 1,012,272 octets, of which the QUIC connection is 703,984 and the TCP one
  305,704, and 378,144 for the pool. At v0.6.0 they were 988,744, 701,296, 286,584 and 377,504.
  The TCP connection grew by its room for a long head (§16 decision 41). A server's channel and
  pool are 1,390,416 octets, and eight servers' are 11.1 MB. `cocuyo_doh`'s type of 4 answers is
  1,683,816 octets, 22,880 more than at v0.6.0. `@sizeOf` gave each number, in a Debug build on
  an Apple M1 Pro on 2026-10-20.

**The request rules over a channel.** A DoH configuration's requests go to its servers' channels.
Rules 3 to 8, 10 to 12 and 17 hold, rule 8 for the QUIC link and rules 14 to 16 for the TCP link.
Rules 1, 2, 9 and 13 give way to these, for DoH alone:

18. **A channel for each DoH server.** A DoH server's slot holds a channel and two links: a QUIC
    link over a datagram socket and a TCP link over a stream socket. The channel opens when the
    drive first takes a request for its server. It is handed the server's address with the
    template's port, since the engine resolves no host to reach a resolver; no HTTPS record; and
    the HTTP/3 alternative the server's last channel learned from Alt-Svc, which the channel uses
    while it is fresh. Its TLS names what the server's `Tls` names, and offers `h3` over QUIC, and
    `h2` then `http/1.1` over TCP. Since colibri v0.8.0 the channel builds those lists from its
    `versions`, which allow all three (colibri's decision 120). It gives QUIC's handshake
    `doh_fallback_delay_ns` before TCP opens beside it.
19. **A link opens and closes when the channel says.**
    - `open` for QUIC opens the link's datagram socket and arms its receive. Then it starts the
      channel's QUIC connection with the engine's stream, the wall clock, and the server's QUIC
      ticket. colibri draws the connection IDs and the grease from that stream (its decision 120,
      since v0.8.0). Until then the type drew them, from the same stream.
    - `open` for TCP opens the link's stream socket and connects, as rule 14 has it. When the
      connect succeeds, the link starts the channel's TCP connection with the server's TCP ticket.
    - `close` closes the link's socket once what it holds to send has gone. A link that has
      closed for `quic_idle_ns` is shut then, whatever it holds, and the channel is read (rules 17
      and 24, §16 decision 55).
    - A link keeps the handle of its send. Each end of a link cancels its send: the bound, a
      failure, a close with nothing to send, a new opening, and `cancel_all`. The buffer comes back
      at the cancel's event, and a new opening of the link sends nothing until then (rule 8).
    - A connect that fails or that the loop refuses, a receive that ends with no octets, and a
      socket the system refuses are told to the channel as the link's end, and the channel is
      read then (rule 17). The channel decides what that fails, and says so in each exchange's
      `finished`.
20. **Up on the version the channel speaks.** `connected` names it: HTTP/3 over QUIC, or HTTP/2 or
    HTTP/1.1 over TCP. Each carries the same GET and ends each exchange the same way, so the
    engine treats them alike. Over HTTP/1.1 a connection answers its requests in the order they
    went, so an answer waits for those before it, and the lookup's deadline still bounds the wait.
21. **A request becomes an exchange.** A request the drive takes waits in its slot's queue until
    one of the channel's answer buffers is free (rule 4). Then it becomes the channel's exchange: a
    GET of the path the template expands with `dns`, with `accept: application/dns-message` and
    `accept-encoding: identity` (rule 12), the path never indexed, and `content-type`,
    `content-encoding` and `age` wanted. The body goes into the answer buffer. A channel holds 16
    exchanges at most, and past them a request waits for one to end. Since colibri v0.8.0 the
    channel may send the GET again, once, on another connection (A GET sent again, above).
22. **An exchange ends once.** A `response` of a 2xx status, whose content is a DNS message in no
    content coding, goes to the lookup with its `Age` (rule 5). Any other response, `refused`,
    `reset`, `closed`, `malformed` and `too_large` fail the request, once, if its attempt is
    current, and decision 25 counts each as the server's failure. Since colibri v0.8.0 a `closed`
    can end a GET that went twice, so the server may have answered its first try. The engine writes
    every request from a template it checked at `start`, so `invalid` is its own error. No
    assertion holds that, though this rule said so until 2026-10-21: such a request fails with
    `local`, since no server took part. Since then each failure carries its reason (§5, The cause
    of a failure; §16 decision 51). The channel's `Finished.result` holds the answer or that
    reason (§17 question 67).
23. **A ticket for each transport.** Each server keeps the newest ticket of each transport, spent
    once, and dropped at its lifetime or 7 days after it came, as rule 10 has it.
24. **An idle channel shuts down.** A channel with no request on it for `quic_idle_ns` shuts down.
    It ends each connection as the protocol ends one, with H3_NO_ERROR or with a GOAWAY and a
    `close_notify`, says `close` for each link, then `closed`, and the slot is free. A request
    taken meanwhile waits, and opens a new channel once the old one has closed. The server keeps
    the channel's HTTP/3 alternative for the next. The same wait bounds a link that closes, as
    `tcp_idle_ns` bounds a connection that closes.

    The first drive at or after that wait from the instant the link began to close shuts it. The
    shut cancels its send (rule 19, §16 decision 55).
25. **The channel's instant.** The engine's one timer counts each channel's next instant (rule
    11). When it comes, the channel is told, then read.

Rule 9 also closed a connection near the idle timeout its QUIC handshake negotiated. For HTTP/3
that is RFC 9114 §5.1, where clients open a new connection and "SHOULD do so if approaching the
idle timeout". The channel opens the connections, so it can do that itself, or its calls can let
the caller do it. colibri's channel does neither at `1fb8b33`, and the owner asked colibri for one
of them on 2026-09-28. Until then, a request that meets the server's idle close fails, and the
lookup's failover takes it. colibri v0.5.0 does it itself (its `e610161`). A QUIC connection that
has held no exchange closes at its idle deadline less a margin, and the channel's next exchange
opens another. One that holds an exchange sends a PING at that instant instead. The margin is one
probe timeout, held between a second and half the idle timeout.

**The interface.** The engine calls a channel through a DoH interface, as it calls colibri's QUIC
through the request interface, so `cocuyo_rotor` never imports colibri. The type is `Options.doh`:

- `start` makes a server's channel from its `Tls`, its address and port, and the alternative kept.
- `request`, `cancel` and `shutdown` are the channel's own.
- `receive` hands the channel a datagram or octets of the stream a link read, and `next` returns
  what it says, one thing at a time, until it has nothing more. The octets of the stream the
  channel has not taken stay with the type until it takes them: a partial record until the rest
  arrives (TLS rule 7). colibri takes each whole record in the read after the chunk that made it
  whole. Its connection has room for a partial frame of HTTP/2 and one record more (§16 decision
  41, checked on 2026-10-17). Since colibri v0.8.0 it has room for a partial head of HTTP/1.1 and
  one record more (§17 question 52). It also opens records while a KeyUpdate's reply is owed (§17
  question 51). colibri takes no record in three states (§16 decision 41):
  - over HTTP/2, while h2 owes a reply that has no room in colibri's output;
  - after its connection stopped;
  - after the server's `close_notify` (RFC 9846 §6.1).

  The type keeps a record at its longest and one of the engine's chunks after it. Since 2026-10-13
  the engine's own record buffer has the same size (TLS rule 7). Octets past what the type keeps
  end the TCP link, as they failed `cocuyo_h2`'s connection (request rule 7): the type tells the
  channel the link ended, and says `close` for it. A datagram the channel has not taken when the
  next arrives is dropped, as the network may drop one.

  Since v0.8.0 colibri names the least memory a program gives a TCP transport (its decision 124,
  ruling 5). `client.constants.stream_input_len_min`, 32,768 octets, is what a program holds so
  that `receive` takes some octets. That size is for cleartext, where the program holds a whole
  head of HTTP/1.1. Over TLS colibri keeps the partial head in its own room, so a whole record is
  enough. So the type keeps 18,693 octets. Each start of a channel asserts that colibri's room
  holds its longest partial unit and one record more. A second assertion holds `output_bytes_max` to
  `client.constants.stream_output_len_min`, 16,645 octets, the least output that takes any
  record colibri owes.
- The type reads a response for the engine. An exchange's end carries a DNS message and its
  `Age`, or nothing, and the engine hands the one to the lookup and fails the request on the
  other (rule 22).
- `datagram` and `output` write what each link owes.
- `deadline` and `expire` are the channel's instant.
- `start_link` starts a link's connection once its socket can carry octets, offering the ticket
  kept for its transport with the ticket's age, the time since it came (RFC 9846 §4.3.11.1), and
  `link_ended` tells the channel a link's socket ended.
- `take_ticket` hands over a transport's ticket, and `alternative` the HTTP/3 alternative.

Three types fill it:

- `cocuyo_doh` fills it from colibri's `client.Channel` (`io/io_doh_channel.zig`). It is a module
  of its own, whose `client` and `tls` imports a consumer that speaks DoH binds to colibri's. It
  reads the template and the response through `doh`, as the two transports did. It holds the
  channel, the receive pool of its QUIC connection, and `answers` exchanges, 4 unless the consumer
  names another, as `cocuyo_quic`'s answer buffers were. Each exchange holds its GET's path, the
  three response fields it wants, and its answer buffer, and a request past them waits (rule 21).
  The buffer is `message_bytes_max` long whatever `tcp_message_bytes` says: a DoH response's
  content is the message alone, with no prefix (RFC 8484 §6).

  Its context is the DoQ session's. It holds the anchors, the statement of the CPU (§16 decision
  48) and the wall clock. It also holds the stream that chapulin and the QUIC connection IDs draw
  from. The channel hands the statement to its one TLS value. The consumer hands the context to
  `use_doh`, and since 2026-10-11 the engine holds none until it does (the context a session
  starts from, below). It keeps a copy of the ticket each link resumes with, which it wipes once
  the link's connection has ended.
- The twin fills it with `sim.channel`, which says exactly the steps a test or the replay queues,
  one at each of the engine's reads. While it has one queued it is due at once, so the engine's
  timer brings the read when nothing else does. Its links carry an item of the twin's QUIC that
  says nothing, so the engine's sockets send and receive on the twin's network. The replay drives
  the model's steps with it one by one. It was to be scripted by the twin's servers, as
  `sim.quic`'s datagrams carry what happened, but a channel says things no link carries, its first
  `open` and its `closed` among them.
- `doh.None` refuses a DoH configuration at `init`, and is the default.

`Options.h2` and `cocuyo_quic`'s `http3` go. So do `cocuyo_h2`, `io/io_quic_h3.zig`, the HTTP/3
test server, their tests, and the engine's tests over the twin's TCP transport. The engine's
stream-socket code stays, and carries the TCP link. They went on 2026-09-29.

**The model**, written on 2026-09-28 (`spec/tla/engine/EngineChannel.tla`). A DoH configuration's
connection becomes a channel:

- The channel has two links, a QUIC link over a datagram socket and a TCP link over a stream
  socket, and each moves as the request connection over that socket moves: rule 8 for the QUIC
  link, and rules 14 to 16 for the TCP link.
- What the channel says is the environment's. At any read it may say whatever its calls allow:
  open a link it has none of while it holds exchanges, close one it asked for, owe octets or a
  ticket on a running one, end an exchange, hold one while a link's send is in flight, and closed
  once shut down with every link closed. colibri's choice, QUIC first and TCP once QUIC failed or
  its delay passed, is among what that allows, and colibri's own model holds it (its decision
  105).
- `connected` changes nothing the engine does (rule 20), so the model leaves it out, with the
  octets and the channel's instant, which only makes a link owe octets.
- The request configurations over TCP go with `cocuyo_h2`, when the code lands. DoQ's stand.
  They went on 2026-09-29.

The checks it gains, seven:

- A link connects, waits to or runs exactly while the channel has asked for it and not closed it,
  and once closed it reads nothing and sends only what it kept (`links asked`).
- A link's buffer and its address are lent exactly while a send or a connect of it is in flight
  (`link lent`).
- A request is an exchange on its server's channel or waits for the next one, never both. Only a
  channel that shuts down keeps requests for the next, and a closed one holds nothing (`exchanges
  placed`).
- A channel that shuts down takes no new exchange (`shutting takes none`).
- What a channel holds, it holds only while a send of one of its links is in flight (`channel held
  while sending`).
- A link that starts resuming spent its transport's ticket (`link ticket spent`).
- A link's socket that ends fails no request itself (`link end fails none`).

`listening` asks it of every running link too. Two configurations, one server and one lookup or
two, three operations and one failure, hold at 1,672,552 and 14,986,512 states; CI checks the
second once a day. Ten mutants break the rules, and TLC finds each (docs/mutations.md CH1 to
CH10). Writing the model moved rule 19: a link's end is followed by
a read of the channel, since without it an exchange's end the channel held waited on a send the
socket's close had taken away. The replay walks both configurations over `sim.channel`, and moved
the model to rules 17 and 19 twice more: the engine reads a channel after it puts a request on
it, and after a link that waited for an earlier connect fails to open at that connect's end. Both
configurations hold at the same states after it.

**Beyond the model.** The engine runs over `sim.channel` on the twin, in the gate. It runs over
colibri's channel against colibri's server on the twin: HTTP/3, HTTP/2 when QUIC's datagrams are
dropped, and HTTP/1.1 from a server that selects no protocol. colibri's channel always runs
chapulin, so those tests run with the sessions' tests, which link it. The server runs under a TLS
identity of cocuyo's own (`io/testdata/`), the owner's ruling of 2026-09-28: a CA and a leaf for
`dns.example`, made once with openssl and valid for a hundred years, so no test reads colibri's
test files or moves its clock to fit them. Since colibri v0.8.0 the server is `server.Endpoint`,
which names in ALPN the versions it serves (colibri's decision 119). A test server that selects no
protocol has its TCP configuration made again with none, which only a test does. Its route table,
`server.router` (colibri's decision 122), sends a GET of the root or of one segment to the query
in `dns`. A path that no route names gets 404, and another method of a routed path gets 405 with
an `Allow` field. A method that no route names gets 501 (RFC 9110 §15.5.5, §15.5.6, §15.6.2).
RFC 8484 §4.1 asks a DoH server for both GET and POST, but the test servers have no POST route.
The engine sends GET alone (rule 21), so no test would send a POST, and a route that no test
reaches checks nothing. One more server writes its own octets over colibri's TLS, with whitespace
before a value. So its head or its trailer section can be longer than the field section that
colibri's client takes. The interop check runs
dnsproxy on the loopback over HTTP/3, and over HTTP/2 with no UDP listener. The live check runs
against Google and Cloudflare.

### The cache's memory, written on 2026-10-11

§19 step 13 has the rules, and §16 decision 37 the ruling. This is what a consumer of
`cocuyo_rotor` writes. With a size it knows when it compiles, the size the README recommends:

```zig
const cocuyo = @import("cocuyo");
const dns = @import("cocuyo_rotor");

const Resolver = dns.Resolver(.{});
var resolver: Resolver = undefined;
var cache_memory: cocuyo.cache.Storage(dns.constants.cache_slots_default) = undefined;

try resolver.init(&loop, &config, cache_memory.slices(), seed, now_ns);
```

With a slot count its own configuration file gave it, it checks the count with
`cocuyo.cache.slot_count_valid`, gets `slot_count` slots and `cocuyo.cache.keys_for(slot_count)`
keys from wherever it gets memory, and hands them over as `.{ .slots = slots, .keys = keys }`
(§18, Sizing the memory). With no cache, it hands over `null`. The cap on a TTL is the
configuration's: `config.cache_ttl_seconds_max`, which the consumer may set from the same file.

`reinit` takes the memory as `init` does, so a consumer whose configuration changed may hand
over a cache of another size, or none, with the new servers. A consumer that hands over other
memory may free the old once that `reinit` returns, whatever it returns but `UdpPayloadTooLarge`.
When that `reinit` fails at its sockets, the memory it handed over is the engine's from then on.
The consumer keeps it for the next `reinit`, or until `close` (§19 step 13, rule 5). A `reinit`
refused with `UdpPayloadTooLarge` changes nothing. The old memory is still the engine's, and the
new memory is the consumer's (What `init` and `reinit` return, below).

The engine and its cache's memory are two values now, and each must stay where it is: the loop
and the table hold pointers into the engine, and the engine's cache holds the two slices. An
engine on each core has a `Storage` on each core. `test/consumer/embed.zig` hands its resolver a
`Storage` of two slots, so `zig build consumer-check` shows the types a consumer names are ones
it can reach, and `examples/threads_rotor.zig` gives each of its two engines one of its own.

### What `init` and `reinit` return, written on 2026-10-14

`cocuyo_rotor.InitError` holds three errors. Each tells the consumer what the engine holds after
the call:

- `UdpPayloadTooLarge`: the configuration's `udp_payload_bytes` passes
  `limits.udp_payload_bytes_max`, 1,856 octets (§16 decision 44). The call changes nothing. A
  refused `init` leaves no engine. A refused `reinit` leaves the engine as it was, with the
  memory that it held. The memory of the call is the consumer's again.
- `SocketFailed`: a socket of a server did not open.
- `ReceiveFailed`: the loop refused a buffer group or a receive.

After `SocketFailed` or `ReceiveFailed`, a failed `init` leaves no engine. A failed `reinit`
holds the new configuration and the new memory (§19 step 13, the cache's memory, rule 5). A
consumer that reads the size of a payload at run time compares it with
`limits.udp_payload_bytes_max` before it calls `init`.

### The session a connection names, written on 2026-10-11

§16 decision 38 has the ruling. `cocuyo_quic.Options` has three fields, and the first names the
TLS a connection runs:

- `Session`, a type: colibri's provider and its packet suite at once, with `start`,
  `original_version`, `provider`, `suite`, `take_ticket`, `lifetime_ns` and `wipe`, and its
  `Context` and `Ticket` (colibri under the request interface, above). It has no default.
  `original_version` joined on 2026-10-20. It names the version the session started in, and the
  connection starts in it too (chapulin under colibri, above; §17 question 57).
- `streams`, the requests one connection holds at once. It has no default either.
- `receive_bytes`, colibri's receive pool, `receive_bytes_default` when the consumer names none.

A consumer that names no session does not compile. The compiler stops where the options are
written, with `missing struct field: Session`. A consumer writes its options as
`examples/doq_rotor.zig` does, with `Session` of `chapulin_quic`, the session over chapulin.
Here `dns` is `cocuyo_rotor`, where the example has an engine its own build makes:

```zig
const Quic = cocuyo_quic.Connection(.{ .Session = chapulin.Session, .streams = at_once_max });
const Resolver = dns.Resolver(.{ .lookups = at_once_max + 1, .tcp_connections = 0, .quic = Quic });
```

`cocuyo_quic` by itself exports no session that protects anything. Since 2026-10-20 the build
registers `chapulin_quic`, rooted at `io/io_chapulin_quic.zig` (§16 decision 38, as amended).
Before that the package shipped the file and registered no module for it, so each consumer's
build made one. The registered module links libc, which chapulin's object needs. It imports
three modules that the build registers: `cocuyo`, `cocuyo_quic` and `chapulin_hooks`. It leaves
`quic` and `tls` for the consumer to bind.

So a consumer that speaks DoQ binds colibri into two modules of this package:

- colibri's `quic` into `cocuyo_quic`;
- colibri's `quic` and `tls` into `chapulin_quic`.

The session's `cocuyo_quic` is the module that the consumer binds colibri's `quic` into. So the
session and its connection read one `cocuyo_quic` and one colibri. `test/consumer/build.zig`
binds them so, and `zig build consumer-check` builds its program `doq` over them. The check
first requires the package's pins of rotor and colibri to be the pins of `build.zig.zon`.
The DoQ example and the session's tests use the registered module, into which `build/doq.zig`
binds colibri as a consumer does. A package outside the tree made the module by hand on
2026-10-11, before the build registered it (docs/mutations.md, cocuyo_quic's session with no
default).

Until the ruling the option defaulted to `cocuyo_quic.Plain`. A consumer that wrote
`Connection(.{ .streams = at_once_max })` built, and its connections ran the plain session.
What its lookups did then depended on who answered:

- **A server that speaks DoQ.** No handshake ended, no query left, and every try at the server
  ran out, as at a server that never answers. "Initial packets apply the packet protection
  process" (RFC 9001 §5.2), under keys both sides derive from the client's first Destination
  Connection ID, and a server "proceeds with the handshake" on "an Initial packet fully
  conforming with the specification" (RFC 9000 §5.2.2). The plain session's Initial carries
  its header and its made-up hello as they are, then sixteen zero octets where the tag goes.
  A server finds no protection to remove and reads no hello. A request has a stream only on a
  connection that is up (request rule 4), so its query never leaves. A configuration's servers
  are all spoken to one way (§22, §23), so every lookup failed, and the run said so.
- **A peer that sends the plain session's messages.** The handshake ended on `doq`, each query
  went to the peer in the clear, and the peer's answers were taken. The messages are in
  `io/io_quic_plain.zig` for anyone to send, and the session checks none of them against a
  key. Such a peer is cocuyo's own test server, or an attacker who answers in the server's
  place. Against the attacker the run said nothing. This is the attack a Strict profile is
  for: it "mitigates both passive and active attacks" (RFC 8310 §5).

So the default carried no query to a DoQ resolver in the clear: to a resolver it carried none.
What it cost a consumer under attack is every protection DoQ is chosen for. Both halves are
read from the code and the RFCs. Of the first, what a server makes of the plain session's first
datagram was run against one server on 2026-10-11, and of the second, the gate's tests run the
handshake and a query against the test server (docs/mutations.md, cocuyo_quic's session with
no default).

`cocuyo_quic` still exports three things for tests, under the names they had:

- `plain`, the session of `io/io_quic_plain.zig`: a provider and a suite for either role.
- `Plain`, that session behind the interface `Options.Session` asks for, in the client's role.
- `server`, a DoQ server over colibri and `plain` (`io/io_quic_server.zig`).

This is true of each of the three:

- It encrypts nothing. A packet's payload and its header go as they are, and the sixteen
  octets after them are read for their count alone.
- It authenticates nobody. It has no certificate, no name and no pin, and its handshake's
  messages are made-up octets any peer can send.
- It is never for a network. A test names it, and carries its datagrams from one side to the
  other in memory or over the twin.

A test that runs colibri's QUIC without chapulin writes `.Session = cocuyo_quic.Plain`, so the
choice stands in the test's own text. The module's tests do (`io/io_quic.zig`), and so do the
engine's over colibri on the twin (`io/io_quic_test.zig`). Nothing else in the tree left the
option unset: the example and `test/consumer/` name chapulin's session, and the benchmarks and
the README's blocks name no connection of `cocuyo_quic`.

The check is a test of `io/io_quic.zig` that reads the fields of `Options` when it compiles. It
requires `Session` to carry no default value and to be a `type`, so that the options hold no
value that means no session (docs/mutations.md QS1 to QS3).

### The context a session starts from, written on 2026-10-11

§16 decision 39 has the ruling. A context is the value every session of one encrypted transport
starts from. The consumer builds it and hands it to the engine once, after `init` and before
the first lookup:

- **DoT.** `use_tls` takes the `Context` of `Options.tls`. The one of chapulin's session is
  built by `Context.init` (§21, the session interface). It takes the anchors, the statement of
  the CPU, a 32-octet seed, and the wall clock with the `now_ns` it was read at.
- **DoQ.** `use_quic` takes the `Context` of `Options.quic`. `cocuyo_quic`'s has two fields, and
  the consumer writes both. `session` is the context of the session its options name, and
  chapulin's is built as the DoT one is. `stream` is a ChaCha20 stream of a second seed, which
  the connection IDs are drawn from: "an unpredictable value" (RFC 9000 §7.2).
- **DoH.** `use_doh` takes the `Context` of `Options.doh`. `cocuyo_doh`'s is built by
  `Context.init` as the DoT one is. Its one stream serves chapulin, the connection IDs and the
  grease of the channel's QUIC link.

**What a context carries.** A context that a network may see carries four things, and the
consumer supplies each, as it supplies the engine's seed and its clock (§3):

- **A stream seeded from the consumer's CSPRNG.** The seed is 32 octets, drawn for this context
  and for nothing else. chapulin draws the handshake's random and its key shares from the
  stream, so the seed is never a constant, never the clock, and never the `u64` seed of `init`
  (CLAUDE.md non-negotiable 4). A context built again takes a new draw (rules 4 and 5). DoQ's
  context takes two draws, one for the session's stream and one for the connection IDs'.
- **The anchors, or the pins.** A server known by a name is checked against the context's
  anchors, 12 roots at most, each a subject Name and a SubjectPublicKeyInfo as DER. A server
  known by pins alone carries them in its `Tls`, in the configuration, and is checked against
  no anchor (§21). So a context with no anchors serves a configuration whose every server is
  known by pins, and under it a server known by a name alone is refused. A DoH server is known
  by its template's host, so a DoH context needs anchors.
- **The wall clock.** Unix seconds at a `now_ns` of the consumer's clock, which the context
  carries forward by the `now_ns` that has passed since. A chain's dates are judged against
  it. A server known by pins alone reads no clock.
- **The statement of the CPU.** A `tls.Cpu` since 2026-10-20: what the consumer's probe found,
  and the timing mode of the thread that drives the engine. Each session hands it to colibri's
  TLS value, and it decides the suites of each hello (§16 decision 48). A consumer that cannot
  state the mode passes `not_stated`, and each hello then offers TLS_CHACHA20_POLY1305_SHA256
  alone.

**What the engine holds.** Until 2026-10-11 `init` set the three contexts to defaults: no
anchor, a wall clock of zero, and a stream seeded with zeros for DoQ and DoH and left undefined
for DoT. Those were values for tests, and nothing checked that a consumer replaced them. The
rules now:

1. The engine holds no context for a transport until that transport's `use_` call has run.
   Each context is an optional, null after `init`. `io/io_context.zig` is the one file that
   reads them, and a session gets its context from there, after an assertion that one was set.
2. `has_context` says whether the transport the engine's configuration speaks has its context.
   A configuration's servers are all spoken to one way (§22, §23), so it reads one context:
   DoT's for a TLS configuration, DoQ's for a QUIC one, DoH's for an HTTPS one. A configuration
   of plain DNS needs none, and for it the answer is always yes.
3. `start` asserts `has_context`. Forgetting the call is a programmer error (CLAUDE.md
   non-negotiable 3), so the program stops at its first lookup, in every build, since
   assertions stay on. A lookup is the first call that can reach a server: `init` and `reinit`
   start no session.
4. `init` leaves the engine with no context, whatever its memory held. An engine closed and
   started again is handed its contexts again, each built from a new draw of its seed. The
   `use_` functions take a context by value, so the consumer's own copy still holds its stream
   as it was built: handed again, or built again from the same octets, it starts the stream
   where the first one started, and its handshakes draw what the first one's drew.
5. `reinit` keeps the contexts. It drops the tickets, which were the old servers', and neither
   reads nor writes a context, as before the ruling. A kept context's stream goes on from where
   it was. A consumer whose new configuration speaks another transport sets that transport's
   context before its next lookup, on either side of the `reinit`. One that wants the wall
   clock pinned again calls `use_` again, with a context built from a new draw, as rule 4
   says and as `reinit` itself takes a new seed (§19 step 10).
6. The context types carry no default. Each of chapulin's two sessions and `cocuyo_doh` builds
   its context with `init`, every argument written, and `cocuyo_quic`'s is its two fields.

**What the engine cannot check.** It checks that the consumer set a context, which is the
programmer error it can see. It cannot tell a seed drawn from a CSPRNG from any other 32
octets, a seed drawn anew from one used before, a wall clock that is right from one that is
not, or the anchors the consumer meant from others. Nor can it tell a statement of the CPU that
is true from one that is not. Those are the consumer's to get right, as the `u64` seed of `init`
is (§7).

**Contexts that carry nothing.** Seven context types are structs of no fields. Three are the
twin's (`sim.tls`, `sim.quic` and `sim.channel`), whose sessions draw nothing, check no
certificate and read no clock. One is `cocuyo_quic.Plain`'s. Three are those of `tls.None`,
`quic.None` and `channel.None`, which refuse their transport at `init`. None carries a default,
since none carries a value, and an engine over the twin still has no context until its test
names one.

**Tests name their contexts.** A test builds its context through a helper whose name says it is
a test's, and none of the helpers is exported:

- `test_context`, in the tests of the two sessions over chapulin and of `cocuyo_quic`, and in
  the engine's tests over colibri on the twin. Each seeds its stream with one octet repeated.
  The helpers of the two sessions state nothing of the CPU. Each session's tests also have a
  `test_context_with`, which takes the statement a test names (§16 decision 48).
- `identity.test_context`, for `cocuyo_doh`'s tests: the test identity's CA for the anchors and
  an instant inside its validity for the wall clock (`io/io_doh_channel_identity.zig`). It
  states nothing of the CPU, and `identity.test_context_with` takes the statement a test names.
- `use_test_contexts`, on the twin's rig (`io/io_sim_test.zig`): it hands an engine the empty
  context of each of the twin's types it speaks.

A fixture that holds a context holds one of these from where the fixture is built, as its
field's default. None is left `undefined` for a later statement to fill.

The replay's world hands its engine the twin's context for the transport a walk configures
(`tools/spec_replay/engine_world.zig`).

**The models.** None holds a context. The engine's TLA+ model starts a handshake and says how
it ends, and never what it started from, and the Lean models are of one lookup and of the
`getaddrinfo` walks. No transition of §5 and no rule of §19 steps 13 and 14 changes, so no
model does.

**The checks.** The engine's are tests on the twin (`io/io_context_test.zig`): for each of the
three transports the predicate refuses an engine whose context was never set and takes it
after the `use_` call; a configuration of plain DNS needs none; the context of one transport
does not count for another; `reinit` keeps each, and a lookup started after it is answered over
each; and `init` leaves none. Each context type has a test that reads its fields when it
compiles and requires that none carries a default, as decision 38's check reads
`Options.Session`. Thirty mutations break the rules, and the tests catch each
(docs/mutations.md, the context a session starts from, TC1 to TC30). The assertion itself has
no row, since taking one away changes nothing a test can see: it was shown by hand to stop a
lookup over each transport.

### New limits

| Constant | Value | Why |
| --- | --- | --- |
| `quic_connections_max` | `servers_max` | one connection to a server |
| `quic_streams_max` | the engine's `lookups` | one stream for a request, and a request for each lookup at most |
| `quic_idle_ns_default` | 10 s | how long a connection with no request is kept, TCP's `tcp_idle_ns_default`; RFC 9250 §5.5.2 names no value, and this one is chosen, not measured |
| `quic_idle_margin_ns_min` | 1 s | how near the negotiated idle timeout a connection stops taking requests: a query and its answer take less, chosen, not measured |
| `quic_connection_events_max` | 16 | beside one answer or reset for each of the engine's `lookups`, the `next` calls one datagram or one expiry is read with, which bounds the loop: the handshake's end, a close and tickets, chosen, not measured. What a flood leaves unread is read with the next datagram |
| `quic_receive_bytes_default` | 66,560 | colibri's receive pool for a connection: a DoQ answer at its longest, 65,537 octets with its prefix, rounded up to the pool's 1,024-octet blocks. The engine reads a stream once all of it has arrived, so a stream's window holds one whole; colibri's default of 1 MiB is far past it |
| `quic_idle_timeout_ms_max` | 30,000 | the idle timeout a connection advertises (RFC 9000 §18.2); the server's may be shorter, and the smaller holds (RFC 9250 §4.4); chosen, not measured |
| `quic_connection_id_bytes` | 8 | the destination connection ID a client's first Initial carries: RFC 9000 §7.2 asks for 8 octets at least |
| `doh_request_bytes_max` | 1,536 | the `:path` of a DoH GET, which an exchange holds in a buffer of this size: `start` refuses a template whose path, with a `dns` value of 512 octets, passes it (§17 question 41). A test sends that GET with the longest authority, 259 octets, over HTTP/2, and its server answers; HTTP/3 was not tried at that length |
| `answers_default` | 4 | a DoH connection's answer buffers when the consumer names none, 262 KB of them; chosen, not measured |
| `doh_channels_max` | `servers_max` | one channel for each DoH server (decision 33) |
| `channel_events_max` | 16 | beside an end for each request, what one read of a channel takes at most: its links' opens and closes, its tickets and its close, which bounds the loop over it; chosen, not measured, as `quic_connection_events_max` is. What a flood leaves unread is read at the next read |
| `doh_fallback_delay_ns` | 250 ms | how long a channel gives QUIC's handshake before TCP opens beside it: the Connection Attempt Delay RFC 8305 §5 recommends, which that RFC sets between attempts at two addresses, not two versions of HTTP; taken from it, not measured |
| `doh_stream_bytes_max` | 18,693 | the octets of the stream a channel keeps until colibri takes them: a record at its longest, 16,645 octets with its header (RFC 9846 §5.2), and one of the engine's chunks, 2,048. It is the engine's `tls_record_in_bytes_max` since 2026-10-13 (§21, TLS rule 7) |
| `doh_datagram_bytes_max` | 2,048 | the datagram a channel keeps until colibri takes it: the engine's datagram buffer, which holds any datagram the engine reads |
| `doh_values_bytes_max` | 256 | where a response's `content-type`, `content-encoding` and `age` are copied; a response whose values do not fit fails its request as too large; chosen, not measured |

`cocuyo_doh` imports neither the engine nor `cocuyo_quic`. So four of its sizes copy theirs:
`engine_chunk_bytes_max` is the engine's `tcp_chunk_bytes_max`, `doh_datagram_bytes_max` its
`buffer_bytes_max`, `doh_stream_bytes_max` its `tls_record_in_bytes_max`, and the channel's receive
pool `cocuyo_quic`'s `receive_bytes_default`. Since 2026-10-13 a test of `cocuyo_doh` imports both,
and holds each copy to the size it copies.

### Order and checks

1. colibri exports its library modules. Done 2026-09-25 in colibri `465da2a` (its decision 86):
   `quic`, `h3` and the modules under them, by name. colibri's audit found no process-wide
   mutable state in its library, so threads that drive their own connections share nothing.
2. The engine exported, with the hooks module and the lint rule on global state. `test/consumer/`
   binds a rotor of its own, runs the engine on a loop it ticks itself beside an operation of
   its own, and requires each event to reach its owner. The export landed on 2026-09-25:
   `cocuyo_rotor` is registered with its `rotor` import unbound, `test/consumer/` builds a
   program that binds its own rotor and runs the resolver on its loop, and a twin test hands the
   resolver an event of another component's and requires it back untouched. The hooks module
   landed the same day: `chapulin_hooks`, registered, holds `ch_rand_bytes`, `ch_assert_fail`
   and the thread-local stream, with `enter` and `leave` for each user of chapulin, and the DoT
   session links it whenever it is linked. Since 2026-09-27 it holds `ch_assert_fail` alone
   (colibri#71). The lint rule landed the same day, as pepegrillo's
   `global_state` at `6fcb273`, configured over `src/` and `io/`. Its first run found five
   shared `var`s. Four were test fixtures. The fifth was the twin's network, one per process,
   which two threads' loops would have reset under each other. All five are thread-local now.
3. The engine model gains the request transport: connections and their streams, the cancel and
   the failure. Design, model, code, in that order (§19 step 13). The rules above were written,
   and the model landed on 2026-09-25: `spec/tla/engine/EngineRequest.tla`, eight checks, and
   three configurations of 19,712, 210,148 and 3,140,695 states, which hold. Eleven mutants break
   the request rules, and TLC finds each (docs/mutations.md RQ1 to RQ11). Writing the model moved
   rule 8: a datagram the loop refuses is asked for again at the next drive rather than failing
   its connection, since failing it after the drive's polls would leave lookups for no drive to
   take. TLC's seeded walks turned out to depend on the model's text as well as its meaning: the
   new module, before anything used it, changed one short walk over UDP. So the committed walks
   were written again, and the engine's mutations broken again against them. Every one is still
   caught, by the same seven picked walks.
4. DoQ over colibri and chapulin, with twin tests and a live check against AdGuard and NextDNS.
   The engine's half and the twin's QUIC landed on 2026-09-25: `io/io_request.zig` and the two
   files beside it, `sim.quic`, and seventeen tests of the engine over it, which thirteen
   mutations break (docs/mutations.md DQ1 to DQ13). The replay over the model's request walks
   landed the same day: two request configurations of the walks, 4,020,000 events of TLC's full
   run replayed in agreement, and eleven mutations of the request path, each caught by the walks
   (RW1 to RW11). Writing the replay moved request rule 8, and the model with it: a datagram the
   loop refuses is kept for the next drive, and the request configurations then held 24,192,
   257,212 and 5,295,912 states; request rule 13, a GOAWAY that drains its connection, took them
   to 28,328, 326,032 and 7,396,714 (c4milo/cocuyo#17). colibri over the twin (decision 29) and
   the live check are the rest of the step. colibri under the interface landed on 2026-09-25: `cocuyo_quic`
   (`io/io_quic.zig` and the files beside it) over colibri `d2c1431`, pinned by hash, a session
   that encrypts nothing and a test server over it, and the twin's responder. Nine tests run the
   engine over colibri's client and server on the twin: an answer, six lookups on one connection,
   another protocol refused, lost datagrams resent through the engine's timer, the idle close, a
   hundred and forty cancelled streams drained, STOP_SENDING, a close held back while colibri's
   closing period ended, and a request sent again after its answer, because the server's
   acknowledgement was lost (docs/mutations.md QC1 to QC8). The live check passed the same
   day, over chapulin's QUIC object at `3a3fa40` behind colibri (`io/io_chapulin_quic.zig`):
   AdGuard and NextDNS each answered two names over DoQ, the second over a connection that
   resumed with the first one's ticket, and a name the certificate does not carry and a root the
   chain does not end at each ended in `AllServersFailed` (`tools/doq_live/run.sh`, and the
   `doq-live` workflow once a day). Both chains end at USERTrust ECC Certification Authority. On
   2026-09-27 the session moved onto colibri's `tls.quic.Client` at colibri `a6a4791` (decision
   32), and the check passed again: both resolvers resolved and resumed, read AAAA, MX, TXT and
   HTTPS records, and refused what strict mode refuses, and AdGuard, known by its leaf key alone,
   resolved and resumed as well. On 2026-10-11 `cocuyo_quic`'s `Options.Session` lost its
   default, the session that encrypts nothing: a consumer names its session, and the gate's
   tests name the plain one (decision 38, docs/mutations.md QS1 to QS3).
5. DoH over HTTP/3, with a live check against Cloudflare and Google. Done 2026-09-25. The engine
   reads a server's template for the port, the name and the path (docs/mutations.md UT1 to UT23),
   and speaks DoH on the twin (DE1 to DE8). `cocuyo_quic` reads a response's `Age` and media type
   (HR1 to HR11), and puts colibri's `h3` under the interface with a test server over it: seven
   tests run the client against that server in memory, and nine the engine over both on the twin
   (QH1 to QH21). The live check passed the same day, over chapulin's QUIC object at `3a3fa40`:
   Google and Cloudflare each answered two names over DoH on HTTP/3, the second over a connection
   that resumed with the first one's ticket, and a template whose host the certificate does not
   carry and a root the chain does not end at each ended in `AllServersFailed`
   (`tools/doh_live/run.sh`, and the `doh-live` workflow once a day). On 2026-09-27 it passed
   again over colibri's `tls.quic.Client` at colibri `a6a4791` (decision 32). With GTS Root R1
   alone, one run in seven was refused through Google. With the root added on 2026-10-01, which
   issued neither of Google's chains, four scheduled runs of eleven were. Since 2026-10-11 it
   hands in GTS Root R1 and GTS Root R4, the roots Google's two chains for `dns.google` end at,
   as the DoT check does (§21 step 6).
6. Two engines on two threads of one image, each on its own loop, resolving at once. Done
   2026-09-25. On the twin, two threads with one `Config` resolve the same names at once, and
   each takes every answer from its own servers. Over rotor, the two engines each took four of
   four answers and refused no event, on kqueue, and under ThreadSanitizer in a Linux container,
   which reported nothing, and reported a race once both threads drove one engine
   (docs/mutations.md TP1 and TP2).
7. DoH over HTTP/2 (c4milo/cocuyo#18), in two parts written on 2026-09-26:
   - 7a, HTTP/2 alone. The model gains the request connection over TCP, and TLC and the replay
     hold it. The engine runs over colibri's `h2` client on the twin, with the provider that
     encrypts nothing. It runs over chapulin against dnsproxy's DoH over HTTP/2 on the loopback,
     and against Cloudflare and Google. The model landed on 2026-09-26 (`4f692f9`), and TLC holds
     its three TCP configurations. The replay (`2090691`) agrees with it over the full run,
     4,824,000 events. The engine carries its request connections over TCP (`f714168`), and over
     colibri's `h2` client on the twin (`778806e`): the engine's TCP tests and the twenty-one of
     `cocuyo_h2` and eight of the engine over colibri catch every mutation of theirs
     (docs/mutations.md TC1 to TC9, HT1 to HT23). Rule 17 closed the two stalls found then. What
     7a left, colibri's `tls.record.Client` under `cocuyo_h2`, dnsproxy and the live check, goes
     with `cocuyo_h2` since decision 33: the channel carries HTTP/2 over `tls.record.Client`.
   - 7b, HTTP/3 first and HTTP/2 after it, in one engine, rewritten on 2026-09-28 for decision 33:
     the engine over colibri's `client.Channel`. The rules were written first (DoH over colibri's
     client, above). Then the model gains the channel, and TLC and the replay hold it. Then the
     code, from the colibri tag that carries the channel: `cocuyo_doh`, `sim.channel`, and the
     engine's DoH over them, with `cocuyo_h2` and the HTTP/3 half of `cocuyo_quic` gone. Then
     dnsproxy over both versions, and the live check. The model landed on 2026-09-28:
     `EngineChannel.tla`, seven checks, and configurations of 1,672,552 and 14,986,512 states,
     which hold. Ten mutants break the channel's rules, and TLC finds each (docs/mutations.md CH1
     to CH10). The engine's half landed the same day: `io/io_channel.zig` and
     `io/io_channel_link.zig` under `Options.doh`, `sim.channel`, and fourteen tests of the engine
     over it, which eighteen mutations break (docs/mutations.md CE1 to CE18). Then the replay: it
     walks the two channel configurations over `sim.channel`, and agrees with the model over the
     full run of fourteen configurations, 5,628,000 events. A fifteenth test came with it, for the
     read after a request is put on a channel (CE19). The walks catch seventeen of the nineteen
     mutations, and the tests the other two (docs/mutations.md, the channel on the model's walks).
     `cocuyo_doh` came the same day, on colibri v0.4.0: sixteen tests of the type against
     colibri's server and of the engine over it on the twin, HTTP/2 and HTTP/1.1, which
     twenty-five mutations break (docs/mutations.md, `cocuyo_doh` over colibri's channel). HTTP/3
     against colibri's server waits for its server over QUIC, in v0.5.0. `example-doh-rotor` went
     through the channel the same day, and so did the interop check: against dnsproxy on the
     loopback DoH comes up on HTTP/3, and on HTTP/2 from a second dnsproxy with no QUIC listener,
     and resumes on each. The removal came on 2026-09-29: `cocuyo_h2`, the HTTP/3 half of
     `cocuyo_quic`, `Options.h2`, the engine's request connections over TCP and their tests went,
     with the limits `h3_peer_uni_streams`, `h3_peer_uni_stream_bytes` and `h2_plaintext_bytes`.
     The request interface lost `socket`, `http3`, the start's `https` and an answer's `http`.
     The model lost `RStream`, its three configurations and its seven mutants. The replay agrees
     with the model over the full run of twelve configurations, 4,824,000 events
     (docs/mutations.md, the TCP request connections removed). colibri v0.5.0 was pinned the
     same day, its tag at `bb9263e`. Two tests run DoH over HTTP/3 against colibri's server over
     QUIC, the type's in memory and the engine's on the twin, and DC28 breaks the source address
     the channel is handed with a QUIC link's datagram. The TCP test server no longer writes
     the SETTINGS its HTTP/2 session owes ahead of a response, since colibri writes its preface
     first (its `e3126a9`). The drain went the same day (c4milo/cocuyo#33): DoQ has no GOAWAY,
     and only the twin said one came. The request configurations hold at 24,192, 257,212 and
     5,305,638 states, and the replay agrees with the model over the full run, 4,824,000 events
     (docs/mutations.md, the GOAWAY drain removed).

Checks, one for each piece:

- An event another component submitted comes back from `apply` false and untouched, and the
  engine's own is taken.
- In an image with two users of chapulin, each handshake draws from its own user's stream.
- A container-level `var` that is not `threadlocal` fails the lint, and the canary shows it.
- A request connection whose ALPN is not `doq` is never up.
- A request the lookup left sends STOP_SENDING, and its answer never reaches the table.
- A reset stream, a failed connection and a failed handshake each fail every request on them,
  once.
- A 2xx answer's `Age` lowers its TTLs, and a 404 fails the request.
- RFC 8484 §4.1.1's template and query expand to the `:path` it shows, and each of RFC 6570's
  operators puts `dns` where Appendix A's table says. A template that is not `https`, has
  userinfo, an IP address, an expression in its authority, a prefix on `dns`, a fragment, or no
  `dns` at all fails its connection.
- An `Age` that is a list takes its first member, one that is not a number counts as 0, and one
  past 2^31 as 2^31.
- A 2xx answer whose `Content-Type` is not `application/dns-message`, or whose content was
  coded, fails the request.
- More DoH requests than a connection has answer buffers all get answered, the rest waiting for
  a buffer.
- A GOAWAY fails every request on its connection once, and the next request opens a new one.
- Two engines on two threads resolve at once, and neither sees the other's events.
- Over HTTP/2, a connection whose ALPN is not `h2` is never up, and a request the lookup left
  sends RST_STREAM with CANCEL and never reaches the table.
- Over HTTP/2, a GOAWAY drains the connection, and a stream above its last stream ID fails once.
- Over HTTP/2, `:path` goes as a never-indexed literal (RFC 7541 §6.2.3).
- Over TCP, a connect that fails or is refused fails every request on the connection once, a
  send that goes short sends its rest first, and a receive that ends with no octets fails every
  request on the connection once.
- Over TCP, a connection idle before its handshake ends closes with nothing sent, and one idle
  once up sends a GOAWAY of NO_ERROR and a `close_notify` before its socket closes.
- A DoH channel opens QUIC first, and TCP once QUIC's handshake has run `doh_fallback_delay_ns`.
  The requests go on the first connection up, and the other closes.
- A link's socket opens only when its channel asks, and closes when the channel says.
- A server that selects `http/1.1`, or no protocol, answers over HTTP/1.1.
- An idle channel shuts down, and a request taken meanwhile opens the next channel.
- `cocuyo_quic`'s options carry no default session, and no value that means none.
- A package that depends on cocuyo and colibri binds colibri into `cocuyo_quic` and
  `chapulin_quic`, and builds a resolver over DoQ that names the session. The package's pins of
  rotor and colibri are the pins of `build.zig.zon`.
- The same package binds colibri into `chapulin`, and builds a resolver over DoT that names the
  DoT session.
- An engine has no context for an encrypted transport until its `use_` call, a configuration of
  plain DNS needs none, `init` leaves none, `reinit` keeps each, and no context type carries a
  default.

The checks over HTTP/2 and over TCP went on 2026-09-29 with the code they checked. A channel's
links hold the rules they held over TCP, and `cocuyo_doh`'s tests what they held of HTTP/2.

## 25. DNSSEC: a plan the owner has not ruled on

§1 puts DNSSEC validation out of scope. On 2026-10-01 the owner asked for a plan to bring it in,
and this section is that plan. Nothing in it is decided: §1 and §16 stand as they are, and
nothing under `src/` or `io/` changes, until the owner answers the questions §17 lists from 16
on. It was written on 2026-10-03 from the RFCs added to `docs/rfcs/` on 2026-10-01, and every
rule below cites the passage that states it, read in those copies.

c-ares validates nothing. Its 1.34.8 headers, read on 2026-10-03, have no channel flag for
DNSSEC: `ares.h` names none. `ares_dns_record.h` names the AD and CD header bits for a caller
that builds its own messages, and no DNSSEC record type but SIG: a DNSKEY, a DS, an RRSIG or an
NSEC comes back as a raw record, which is what cocuyo already does (decision 31). So this is not
part of the gap §19 closes. It is a feature of cocuyo's own, which is why it waits for a ruling.

### Two things DNSSEC support can mean

RFC 4033 §2 defines two stub resolvers, and they promise different things.

| Question | Stage A: the server's word | Stage B: cocuyo validates |
| --- | --- | --- |
| What RFC 4033 §2 calls it | a non-validating security-aware stub resolver | a validating security-aware stub resolver |
| What a consumer learns | that the server says it validated the answer: the AD bit | that cocuyo verified the signatures: secure, insecure or bogus |
| What it rests on | the server, and a channel that authenticates the server (RFC 4035 §4.9.3) | a trust anchor the caller supplies, and the time of day |
| What a server that lies can do | anything | refuse to answer, and nothing else |
| Queries it adds | none | none while the signer's keys are held; otherwise the DS and DNSKEY questions down to the signer, and the question once more |
| Cryptography | none | signature verification, chapulin's, reached through an interface so that `src/` holds none |
| What it changes | a bit in the query, a field in the answer | a module, a ninth state in §5, two models, and new calls in chapulin and colibri |

RFC 4033 §12 says which threat each stage answers. A stub that does not validate is exposed to
attacks on its channel to the recursive server and to attacks by that server. Channel security
defends against the first. Against the second, "the only known defense" is for the stub "to
perform its own signature validation".

The plan is Stage A first, then Stage B, each behind a setting that is off by default (RFC 4033
§12: validation "may cause entire legitimate zones to become effectively unreachable due to
DNSSEC configuration errors or bugs"). Both report through one type, so Stage B adds no field
to what Stage A adds:

```zig
/// What is known of where an answer came from (docs/design.md §25).
pub const Security = enum(u2) {
    /// Nothing was checked: neither stage is on.
    unchecked,
    /// cocuyo proved the name lies in a zone that is not signed, or under no trust anchor
    /// (RFC 4035 §4.3). Stage B.
    insecure,
    /// The server said it validated: AD on every message used, over a channel the
    /// configuration relies on (RFC 4035 §4.9.3). Stage A.
    authenticated,
    /// cocuyo verified signatures from a trust anchor down to the answer (RFC 4035 §4.3).
    /// Stage B.
    secure,
};
```

`Answer` and `Failure` each gain `security: Security`. A failure carries it for the two negatives,
`NameNotFound` and `NoData`, since a denial can be proved as an answer can. Bogus data is not a
value of it: it is a failure, `Error.Bogus`, with the reason beside it. The names are a sketch
for the step that lands them.

### Stage A: the server's word, over a channel that authenticates it

The rules:

1. A configuration says whether the AD bit is relied on: `Config.authenticated_data`, one of
   `ignored`, which is the default, `encrypted` and `always`. "A resolver MUST disregard the
   meaning of the CD and AD bits in a response unless the response was obtained by using a
   secure channel or the resolver was specifically configured to regard the message header bits
   without using a secure channel" (RFC 4035 §4.6). `encrypted` is the first case: the bit
   counts from a TLS, HTTPS or QUIC server, which strict mode has authenticated (§21), and from
   no other. `always` is the second: it is for a validating resolver on the loopback, which is
   what `options trust-ad` in a `resolv.conf` says. That option is glibc's, since 2.31, as
   recalled from its manual page and not read on this machine.
2. When the bit is relied on, every query carries AD set. That asks for the bit without asking
   for DNSSEC records (RFC 6840 §5.7), so DO stays clear and no response grows. A validating
   server sets AD in a response only when the query had DO or AD set (§5.8). CD stays clear: a
   stub that does not validate depends on the server to (RFC 4035 §4.9.2).
3. A lookup ends `authenticated` when every message it acted on had AD set: each link of a CNAME
   chain that spans messages, each negative that moved it to the next search candidate, and the
   message that ended it. One message without the bit ends it `unchecked`.
4. The bit covers the answer and the authority sections (RFC 4035 §3.2.3), which is all a lookup
   reads of a message beside the OPT record.
5. The cache keeps the status with the entry and hands it back with a hit. The engine starts a
   new cache at every `reinit` (§19 step 13), so a status never crosses a change of servers or
   of this setting.
6. A server that validates answers SERVFAIL for data it found bogus (RFC 4035 §3.2.2). Stage A
   sees that as any other server failure: the lookup moves to the next server and can end
   `AllServersFailed` (§5). The extended error option says why (RFC 8914), and the codec reads
   it already. Whether `Failure` carries its code is question 18.

What changes, and where:

- `wire`: the AD and CD bits by name, at the positions RFC 6895 §2 draws, with
  `Header.authentic_data` and `Query.authentic_data`.
- `core`: `Config.authenticated_data`, and `Security`.
- `resolver`: the last free bit of `Lookup.flags` holds rule 3's conjunction. `Answer` and
  `Failure` gain `security`.
- `cache`: the status in a slot.
- `config`: `options trust-ad`, read as `always`.
- The lookup's model: the bit, and a theorem that an end is `authenticated` only when every
  message the lookup acted on had AD set, and never under `ignored`.

No limit is new. Checks, one for each piece:

- A query under `ignored` has AD clear, and one under `encrypted` or `always` has it set, with
  DO clear in both.
- An answer whose message had AD set is `authenticated`; the same answer over a cleartext server
  under `encrypted` is `unchecked`.
- A chain of two messages with AD on one alone ends `unchecked`.
- A negative that had AD set ends `authenticated`, and the cache hands it back so.
- Live, once a day, beside the DoT check (§21 step 6): a signed name comes back `authenticated`
  from each public resolver, an unsigned one `unchecked`, and one signed wrongly on purpose fails.

### Stage B: what a validating lookup sends

1. Every query carries an OPT record with DO set: "A validating security-aware stub resolver
   MUST set the DO bit" (RFC 4035 §4.9.1). The bit is RFC 3225 §3's.
2. Every query has CD set: a validating stub SHOULD set it, or the server answers by its own
   policy and may hold back data the stub's policy would accept (RFC 4035 §4.9.2). With CD
   clear, a validating server turns bogus data into SERVFAIL and the stub never sees why.
3. AD is clear in the query, and neither AD nor DO is read in the response: a validating stub
   SHOULD NOT examine AD (RFC 4035 §4.9.3), and a resolver MUST ignore DO in a response
   (RFC 6840 §5.6).
4. EDNS0 is never turned off. §5 asks a server that answered FORMERR again without the OPT
   record. A query without OPT has no DO, its answer has no signatures, and "the absence of
   DNSSEC data in a response MUST NOT by itself be taken as an indication that no
   authentication information exists" (RFC 4035 §5). So under validation that FORMERR counts
   as the server failing the lookup, and the lookup moves on. RFC 3225 §3 has the older rule,
   to try again without EDNS0, and RFC 4035 §4.1 is the one followed.
5. The advertised payload is 1220 octets at least: a security-aware resolver MUST support that
   size (RFC 4035 §4.1). The default of 1232 already does, and `assert_valid` refuses less under
   validation. The same section's SHOULD, 4000 octets, is not met: an answer that does not fit
   comes truncated, and the lookup asks over TCP as it does today.
6. The transaction id, the source port, the case of the name and the cookie stay as §7 has them.
   Canonical form writes owner names in lowercase (RFC 4034 §6.2), so the case a query was sent
   in changes nothing that is signed.

### Stage B: what is verified in a message

The validator reads a message that has passed every check of §7, for the name and the type the
lookup is asking at that moment. It reads the message in place, in the caller's buffer, and
keeps none of it. It answers one of four things: `secure`, `insecure`, `bogus` with a reason, or
`keys_wanted`.

1. **What must be signed.** Every RRset the lookup uses from the message: each CNAME the chain
   follows, the RRset that answers, the SOA whose MINIMUM gives a negative its TTL, and the NSEC
   or NSEC3 records of a denial. The additional section is never used and never validated.
2. **One signature.** An RRSIG covers an RRset when RFC 4035 §5.3.1's conditions hold: the same
   owner and class, the Type Covered equal to the RRset's type, a Labels field no larger than
   the owner's label count, the time inside the inception and the expiration, and a signer,
   algorithm and key tag that match a key of the signer's zone with the Zone Key flag set. One
   more check the section implies and does not state: the signer's name is the owner's name or
   an ancestor of it, or a key of one signed zone could sign another zone's data.
3. **The signed data.** It is rebuilt, never copied (RFC 4035 §5.3.2): the RRSIG's rdata without
   the signature, then each record with its owner in canonical form, its TTL replaced by the
   Original TTL and its rdata in canonical form, in canonical order (RFC 4034 §3.1.8.1, §6.2,
   §6.3). The names in an NSEC's rdata keep their case and those in an RRSIG's are lowered,
   which corrects §6.2's list (RFC 6840 §5.1). The records are found in the message and fed to
   the hash one at a time in order, so no copy of the RRset is made. A record that repeats
   another is fed once (RFC 4034 §6.3).
4. **Which signature.** One valid signature is enough, and an RRset is bogus only when every
   signature over it fails (RFC 6840 §5.4, a SHOULD). An RRSIG whose key is not in the zone's
   set is disregarded (§5.12, a MUST). Each key that matches a signature's tag is tried, since
   a tag is not unique (RFC 4034 Appendix B), up to a named bound.
5. **Algorithms cocuyo does not verify.** A zone whose authenticated DS set names no algorithm
   and digest cocuyo supports is treated as unsigned: `insecure`, never `bogus` (RFC 4035 §5.2,
   RFC 6840 §5.2). Under a zone that has one supported algorithm, a validator accepts any
   single valid path and does not insist that every algorithm in the DS or DNSKEY set work
   (RFC 6840 §5.11). So one valid signature is enough there too, and an RRset with none is
   `bogus`.
6. **Time.** The time must lie between the inception and the expiration, both included
   (RFC 4035 §5.3.1), compared in serial number arithmetic (RFC 4034 §3.1.5, RFC 1982). No RFC
   gives an allowance for a clock that is wrong. RFC 4033 §6 asks only that the possibility be
   allowed for, so the allowance is a setting, zero by default (question 23).
7. **The TTL.** An RRset found authentic is kept no longer than the smallest of its TTL as
   received, the RRSIG's TTL, the Original TTL and the time left before the signature expires
   (RFC 4035 §5.3.3, a MUST). `Answer.ttl_seconds` takes all four, beside the chain's minimum of
   §5.
8. **Wildcards.** An RRset whose owner has more labels than its RRSIG's Labels field came from a
   wildcard, and is authentic only with a proof that no closer match exists (RFC 4035 §5.3.4,
   RFC 5155 §8.8).
9. **Chains.** Each link of a CNAME chain is an RRset of its own, under its own signer. A CNAME
   with no signature stands when a validated DNAME in the message produces it (RFC 4035 §4.8,
   RFC 6672 §5.3.1). The chain is secure only if every link is, and bogus if any link is
   (RFC 6672 §5.3.3).
10. **Denial with NSEC.** A name error needs a record that covers the name and one that covers
    the wildcard that could have answered; no data needs a record at the name with the type's
    bit clear (RFC 4035 §5.4). The CNAME bit must be clear too (RFC 6840 §4.3). An NSEC from
    the parent's side of a delegation denies nothing at its owner but a DS, and nothing below
    it; one with the DNAME bit set denies nothing below its owner (RFC 6840 §4.1).
11. **Denial with NSEC3.** RFC 5155 §8, case by case: the closest encloser proof (§8.3), the
    name error (§8.4), no data (§8.5, §8.6), and the two wildcard cases (§8.7, §8.8). A record
    with an unknown hash is ignored (§8.1), and so is one whose flags are neither 0 nor 1
    (§8.2). A record whose iteration count is above `nsec3_iterations_max` makes the answer
    `insecure`, once its own signature has been verified (RFC 9276 §3.2). A proof that rests on
    an Opt-Out record is `insecure` as well: names under such a record "may or may not exist
    as insecure delegations" (RFC 5155 §9.2).
12. **Compact denial.** An NSEC at the name asked, with the NXNAME bit set, says the name does
    not exist, under a response code of NOERROR (RFC 9824 §2, §3.1; §4 has the NSEC3 form).
    The validator reads it as a name error.
13. **The response code is not signed.** The proof says whether a negative is a name error or
    no data, and the lookup acts on the proof (RFC 9824 §8). A negative with no proof, under a
    signed zone, is `bogus`.
14. **Data with no signature.** Under a zone whose keys are held, it is `bogus`, by the rule of
    RFC 4035 §5 quoted above for a query without OPT. Under an insecure delegation the store
    holds, it is `insecure`. Otherwise the validator does not yet know, and answers
    `keys_wanted`.
15. **Questions that cannot be secure.** An RRSIG is never signed (RFC 4035 §2.2), so a question
    for RRSIG ends `unchecked`. A question for ANY is validated one RRset at a time, and is
    bogus if any of them fails (RFC 6840 §4.2).
16. **Bounded work.** RFC 4035 §5.4 says "the resolver MUST bound the work it puts into
    answering any particular query", and RFC 4033 §12 names the attack: tampered RRSIGs and
    needlessly complex chains. The signatures tried for one RRset, the keys tried for one
    signature, the verifications in one message and the NSEC3 hashes in one message each have
    a named limit. A message past one is `bogus`.

### Stage B: where the keys come from

The key store is memory the caller hands in, as the cache's is. An entry is a zone's name and
one of three things, each with the instant it expires by item 7 above: the zone's validated
DNSKEY set, a validated DS set whose keys have not come yet, or an insecure delegation. A trust
anchor is a DS or a DNSKEY record the caller supplies at init, for the root or for any zone
(RFC 4035 §4.4). A name under no anchor is reported `insecure` at once. RFC 4033 §5 calls that
case indeterminate, and says its own signalling "does not distinguish between indeterminate and
insecure states"; `Security` does not either.

When the validator answers `keys_wanted`, a walk fetches what is missing. Its rules:

1. The walk has a target: the signer's name of the RRSIG that could not be checked, or, for
   data with no signature, the name asked.
2. It starts at the deepest zone above the target whose keys the store holds, or at the deepest
   anchor above it. That is RFC 6840 Appendix C.1's policy, the anchor closest to the name.
   §5.10 suggests C.2's as the default, which tries every anchor above the name until one
   gives a secure result; question 20 asks which. An anchor's zone is entered by asking for
   its DNSKEY set and matching it to the anchor (RFC 4035 §5).
3. From a zone whose keys it holds, the walk takes the next name toward the target, one label
   longer, and asks for its DS set. The answer is validated with the keys of the zone it stands
   in, which is where a DS lives: on the parent's side of a delegation (RFC 4034 §5).
4. A DS set that validates makes the name a signed delegation. The walk asks for its DNSKEY set,
   which is authentic when a key in it with the Zone Key flag matches a DS by tag, algorithm and
   digest, and that key's signature over the set verifies (RFC 4035 §5.2, RFC 4034 §5.2). A DS
   with a digest type cocuyo does not know is passed over (RFC 6840 §5.2), and a SHA-1 digest is
   passed over when the set holds a SHA-256 one (RFC 4509 §3). The store keeps the keys, and
   the walk stands in the new zone.
5. A proof that the name is a delegation with no DS makes it an insecure delegation: an NSEC or
   an NSEC3 at the name with the NS bit set and the DS and SOA bits clear, or a closest encloser
   proof whose covering NSEC3 has Opt-Out set (RFC 4035 §5.2, RFC 6840 §4.4, RFC 5155 §8.6). A
   set SOA bit marks the child's own record, which proves nothing here. The store keeps the
   delegation, and the walk ends: everything at or under that name is `insecure`.
6. A proof that the name exists and is no delegation, or is an empty non-terminal, leaves the
   walk in the same zone, and it takes the next label.
7. A proof that the name does not exist ends the walk, and the lookups that wait for it end
   `Bogus`: the response they read spoke of a name the zone above has proved is not there.
8. The walk ends when the store holds the target's keys, when it holds an insecure delegation
   above the target, or when a walk for data with no signature reaches the name asked inside a
   signed zone, which makes that data `bogus` (RFC 4035 §5).
9. Each DS and DNSKEY question is an ordinary lookup of the table's, absolute, and validated by
   the same validator with keys the store already holds. So nothing is stored that was not
   validated, and nothing of a message is kept.
10. One walk serves every lookup that waits for the same target. A walk asks
    `chain_questions_max` questions at most.
11. A walk whose question fails for another reason, a timeout or every server failing, ends the
    lookups that wait for it with that failure, and not with `Bogus`.

Counted from these rules, not measured: `www.example.com` under the root's anchor alone takes
seven questions the first time, which are the question, the root's DNSKEY set, the DS and DNSKEY
sets of `com` and of `example.com`, and the question again. A second name under `example.com`
takes one. A name in another zone under `com` takes four.

### Stage B: what the lookup does with it

These rows join §5's table, for a table that validates. The model changes first, then the code.

| State | Event | Next state | Effect |
| --- | --- | --- | --- |
| `awaiting_udp` | a response the validator calls `bogus` | `tcp_needed` | the same server, over TCP, as a truncated answer does |
| `awaiting_tcp`, or over DoH or DoQ | a response the validator calls `bogus` | `query_ready` or `failed` | advance the server, as SERVFAIL does |
| any state that awaits an answer | a response the validator answers `keys_wanted` | `awaiting_keys` | no deadline; the lookup keeps its server, its candidate and its place in the chain |
| `awaiting_keys` | the walk ended with the keys held, or an insecure delegation | `query_ready` | the same server and a new transaction, as a chain's next name is asked |
| `awaiting_keys` | the walk failed | `failed` | with the walk's failure |
| `awaiting_udp` | FORMERR with EDNS0 on | `query_ready` or `failed` | advance the server; EDNS0 stays on |

A lookup whose passes run out after a bogus answer ends `Bogus`, where it would have ended
`AllServersFailed`. A lookup asks again after waiting for keys `key_asks_max` times at most for
each message it reads, so no sequence of answers makes it wait forever.

A bogus answer over UDP goes to TCP because an attacker off the path who guesses a transaction
can forge a datagram and cannot forge a stream. The forged answer costs one connection, and the
answer that counts is the server's own. Ignoring it and keeping the wait, as §16 decision 10
does for a malformed message, was the alternative: a zone that is really broken would then cost
every server's whole timeout before the lookup said so. RFC 4035 §5.4 asks that a query whose
denial came incomplete be sent again, and both paths do.

### Stage B: where each piece goes

| Piece | Module | Why there |
| --- | --- | --- |
| DO, CD and AD; DS, RRSIG, NSEC, DNSKEY, NSEC3, NSEC3PARAM and DNAME named in `Kind`; their rdata read; the type bit maps | `wire` | the codec, which verifies nothing |
| canonical name order (RFC 4034 §6.1) | `core`, on `Name` | beside `equal` |
| canonical form, the signed data, the key tag, what a DS digest and a signature are computed over, the denial proofs, the key store, the validator, the walk's rules, and the `Verifier` it asks for digests and signatures | `dnssec`, new, reading `core` and `wire` | the DNS half, with no cryptography in it |
| the verifier over chapulin | a module outside `src/`, whose `tls` import a consumer binds to colibri's | as `cocuyo_quic` and `cocuyo_doh` are bound, so that `src/` depends on nothing |
| the `Validator` the table is handed, `awaiting_keys`, the walk's lookups, the slot kept for them | `resolver` | under the table, as `Memory` is (decision 22) |
| `cocuyo.validated_by(&store)` | `src/cocuyo.zig` | the one file that reaches both modules, as `remembered_by` does |
| the status in a slot, and bogus entries | `cache` | |
| anchors from text: the DS and DNSKEY presentation forms (RFC 4034 §5.3, §2.2) | `config` | a parser beside `resolv_conf` |
| the key store's memory, the anchors and the time of day, in `Options` | `io` | the engine hands them down |

The table names no cryptography. It names what it asks of a validator, and `dnssec` fills that
in from a key store:

```zig
pub const Validator = struct {
    context: *anyopaque,
    /// Reads a message that passed §7's checks, for the name and the type being asked.
    validate: *const fn (
        context: *anyopaque,
        asked: *const Name,
        kind: Kind,
        message: []const u8,
        now_ns: u64,
    ) Validation,
    /// The next DS or DNSKEY question a walk wants asked, or null.
    next_question: *const fn (context: *anyopaque, now_ns: u64) ?Question,
    /// A question the table asked for a walk ended without a validated answer.
    question_failed: *const fn (context: *anyopaque, question: *const Question, err: Error) void,
};
```

The table asks a walk's questions as lookups of its own, which the consumer never sees as
events, and it keeps `trust_slots_reserved` slots that only they may take. Without that, a table
full of lookups that wait for keys would have no slot to fetch a key in, and none could ever
move. A walk's own lookups never wait for keys: one that would ends, and the walk starts again
from the top of what the store holds.

Because validation sits under the table, every lookup the table starts is validated, the
composed ones included: `AddressLookup` and `NameLookup` change in one place, where each hands
its lookups' `security` on. A bare `Lookup` with no table validates nothing, as it has no cache.

**Memory.** No message is copied, and a lookup's slot grows by two small counters at most. A
store entry is a name, a buffer of `zone_keys_bytes` and a few fields: about 2.4 KiB by sum of
the limits below, not measured, so the engine's default of 64 entries is about 150 KiB. A
verification uses the stack alone.

**Time.** A signature's dates are seconds since 1970 (RFC 4034 §3.1.5), and `now_ns` is a
monotonic count. So the caller passes one more value, as non-negotiable 4 has it pass every
other: Unix seconds, pinned to a `now_ns`, at init and whenever it corrects its clock. The store
adds the `now_ns` that has passed, which is what the engine's TLS context does for a
certificate's dates (§21). This value may go backwards. `now_ns` still may not.

**Cache.** An entry keeps its status, and a validating table takes only entries a validating
table wrote. An entry lives no longer than item 7's TTL. A bogus end is remembered for
`bogus_ttl_seconds`: resolvers "MUST cache DNSSEC validation failures" (RFC 9520 §3.4), for one
second at least and five minutes at most (§3.2). The backoff §3.2 recommends is not in the first
cut. Neither is RFC 8198's aggressive use of validated NSEC records, a SHOULD: the cache keeps
what a server said about the question asked and infers nothing, which is the rule
`docs/rfcs/README.md` gives for RFC 8020.

### Stage B: the cryptography

The owner ruled on 2026-10-03 that every cryptographic operation is chapulin's, as the TLS under
DoT, DoQ and DoH already is (§16 decision 35). This section's first draft took it from Zig's
`std.crypto`, and what follows replaces that draft.

**Where it sits.** `src/` depends on nothing, and chapulin reaches cocuyo through colibri's
`tls` alone (decision 32), which nothing under `src/` imports. So `dnssec` holds no
cryptography. It names what it asks of a verifier, as the table names what it asks of a cache
(decision 22): whether an algorithm or a digest type can be checked, the digest of octets it
feeds in pieces, and whether a signature verifies under a key over data it feeds in pieces. A
module outside `src/`, beside `cocuyo_quic` and `cocuyo_doh`, fills that in from chapulin
through a `tls` import the consumer binds to colibri's, and the engine takes it in `Options`. A
consumer of the library alone, with no colibri, hands in a verifier of its own or does not
validate.

**What chapulin has, and what it would gain.** Read on 2026-10-03 at `c798fb8`, the commit
colibri v0.6.0 pins. Since 2026-10-20 cocuyo pins colibri v0.8.0, which pins chapulin `e6e3c1e7`,
and nobody read that commit for this table. The third column is RFC 9904 §3's "Implement for
DNSSEC Validation".

| Number | Algorithm | RFC 9904 §3 | chapulin at `c798fb8` | What it would gain |
| --- | --- | --- | --- | --- |
| 8 | RSASHA256 | MUST | PKCS #1 v1.5 over SHA-256, with the exponent 65537 alone and a modulus of 2048 to 4096 bits | the exponent the key carries, and a lower floor |
| 10 | RSASHA512 | MUST | SHA-512, and no PKCS #1 v1.5 over it | that signature |
| 13 | ECDSAP256SHA256 | MUST | verification, with the signature in DER | nothing: the binding writes r and s as DER |
| 14 | ECDSAP384SHA384 | RECOMMENDED | the same | nothing |
| 15 | ED25519 | RECOMMENDED | none: it has X25519 and no Ed25519 | Ed25519 verification |
| 16 | ED448 | RECOMMENDED | none | nothing planned: such a zone is read as unsigned |
| 5, 7 | RSASHA1, RSASHA1-NSEC3-SHA1 | MUST | none: it holds no SHA-1 | SHA-1 under PKCS #1 v1.5, off unless the configuration turns it on |
| 1, 3, 6 | RSAMD5, DSA, DSA-NSEC3-SHA1 | MUST NOT | none | nothing |
| 12, 17, 23 | ECC-GOST, SM2SM3, ECC-GOST12 | MAY | none | nothing |
| 253, 254 | private | MAY | none | nothing; RFC 6840 §5.3 asks nothing of a validator that supports none |

Two more things are needed that no algorithm number names:

- **SHA-1 as a hash.** It is NSEC3's only hash (RFC 5155 §11), and a validator of algorithm 8,
  10, 13 or 14 "MUST be able to validate negative answers in the form of both NSEC and NSEC3
  with hash algorithm 1" (RFC 5702 §5.2, RFC 6605 §5). A DS digest of type 1 is SHA-1 too, which
  RFC 9904 §4 has as MUST to implement, beside SHA-256, a MUST, and SHA-384, RECOMMENDED.
  chapulin holds no SHA-1, and refuses a certificate signed with it. Without it no denial in
  an NSEC3 zone can be validated: neither a name that does not exist, nor the proof that a
  delegation is unsigned.
- **Public calls.** None of the above is one. chapulin's object exports its TLS, record and
  QUIC calls, and no call that hashes or verifies, and colibri's `tls` carries that object.

So three repositories change, in this order: chapulin gains the calls and what the table lists,
colibri's `tls` hands them on, and cocuyo binds them. §21 began the same way, with chapulin's
three pieces first.

Algorithms 5 and 7 are off by default because RFC 9905 §2 asks both things at once:
implementations "MUST continue to support validation using these algorithms", and operators
"MUST treat" them "as unsupported, rendering responses insecure". By item 5 above, a zone that
has only an algorithm the verifier does not check is `insecure`, so a zone signed with Ed448
alone, or by default with SHA-1 alone, is read as unsigned and never as bogus.

**What signed zones publish.** Counted on 2026-10-03: the DNSKEY, DS and NSEC3PARAM sets of the
root and of the 1,437 top-level domains in IANA's list of that day, asked of 1.1.1.1 over TCP
with dig 9.10.6, by a script that is not in this tree. Every zone answered, and 1,362 are
signed, the root among them. Zones below the top level are not counted. Step 4's tool repeats
the count with cocuyo's own lookups.

| What | Zones, of 1,362 signed |
| --- | --- |
| RSASHA256 (8) | 1,091 |
| ECDSAP256SHA256 (13) | 276 |
| RSASHA512 (10) | 28 |
| RSASHA1-NSEC3-SHA1 (7) | 4 |
| ED25519 (15) | 3 |
| ECDSAP384SHA384 (14) | 1 |
| RSASHA1 (5), ED448 (16) | none |
| two algorithms at once | 41 |
| an RSA key under 2048 bits | 961, of the 1,123 with an RSA key: 1024 bits in 715, and 1280 bits in 246 |
| an RSA exponent other than 65537 | 1: `lv`'s one key with the SEP flag has 2^32 + 1, which is five octets |
| NSEC3, always with SHA-1 | 1,308; no iterations in 1,222, and 20 at most; a salt of 10 octets at most |
| a DS set that holds a SHA-256 digest | 1,348, of the 1,350 with a DS in the root; the other 2 hold SHA-1 alone |
| the largest DNSKEY set | 6 keys; 1,824 octets of rdata; the root's holds 4 keys |

**What chapulin's RSA must admit.** A key may be 512 to 4096 bits for algorithm 8 and 1024 to
4096 for algorithm 10 (RFC 5702 §2), with any exponent. chapulin's floor is 2048 bits, and its
exponent is fixed at 65537. A key the verifier cannot use is passed over, and data that only
such keys sign is then `bogus`. The count says what that would cost. Every key under 2048 bits
is one without the SEP flag, the kind a zone by convention signs its records with, its
delegations among them; the count did not read which key signed what. So with a floor of 2048
bits, 961 of the signed top-level domains, and every zone under them, would fail to validate.
The floor has to come down to 1024 bits. The exponent has to be read from the key, five octets
of it at least, or `lv` and every zone under it fails the same way.

So the order chapulin's additions are worth, by the zones each opens: the public calls, SHA-1
as a hash, and RSA with the key's own size and exponent, which together cover algorithms 8 and
13; then RSA over SHA-512, for 28 zones; then Ed25519, for 3. Algorithm 7's 4 zones stay
`insecure` by default, as RFC 9905 §2 asks. No top-level domain signs with Ed448.

**The RFCs' own examples.** Decoded from the copies in `docs/rfcs/` on 2026-10-03: the example
zone of RFC 4035 Appendix A signs with algorithm 5 under a 1024-bit key whose exponent is 3;
RFC 5155 Appendix A's with algorithm 7 under 512-bit keys; and RFC 5702 §6 gives a 512-bit key
for algorithm 8 and a 1024-bit one for algorithm 10. chapulin as it stands verifies none of
them. So the validator's own tests run over a verifier the test supplies, with no cryptography
in it: it calls a signature valid when its octets are a fixed function of the signed data, as
the twin's session encrypts nothing (decision 29). Those tests check everything but the
arithmetic, on the RFCs' whole responses. The arithmetic is checked in the binding's tests,
over chapulin, on the examples chapulin admits: RFC 6605 §6's for ECDSA once the calls are
public, and each other as its algorithm lands.

**What the ruling rejected: Zig's `std.crypto`.** Read the same day: 0.16's has every algorithm the
plan would verify, and no Ed448. Its ECDSA and Ed25519 verifiers take the message in pieces, and
RSA of any size and exponent can be written over `std.crypto.ff`. It adds no dependency, so a
verifier over it could sit in `src/`, validate for a consumer with no colibri, and run every
example above in the gate. It would also be a second implementation of SHA-2, P-256, P-384 and
RSA in every image that speaks DoT, DoQ or DoH, outside what chapulin proves and tests: its
CBMC harnesses, its reference specifications and the Wycheproof vectors, as chapulin's
CLAUDE.md lists them. Both at once was the other choice, chapulin under the engine and
`std.crypto` for a consumer without colibri, at the cost of keeping two.

### Stage B: what stays out

- Resolving from the root. cocuyo stays a stub: it asks a recursive server for the DS and DNSKEY
  sets, and never an authoritative one.
- Updating a trust anchor from the zone's own keys (RFC 5011). The anchors are the caller's
  values, replaced at `reinit`. RFC 5011 §8.1 leaves accepting a key to the resolver's owner,
  and allows an update "out-of-band". IANA's file of the root's anchors (RFC 9718) is the
  caller's to fetch and read.
- Aggressive use of NSEC and NSEC3 (RFC 8198), as the cache rule above says.
- Handing the DNSSEC records to a consumer that validates for itself (RFC 4035 §4.9.1, a MAY).
  `Answer` holds one type's records.
- Signing, SIG(0) and TSIG.

### New limits

Every value below is chosen, not measured, unless its reason cites an RFC or the count of
2026-10-03 above, which covers the root and the top-level domains and no zone below them.

| Constant | Value | Why |
| --- | --- | --- |
| `dnssec_payload_bytes_min` | 1220 | RFC 4035 §4.1 |
| `anchors_max` | 8 | more than one, as RFC 4035 §4.4 asks: the root's keys while one replaces another, and a zone of the caller's own |
| `rsa_modulus_bits_max` | 4096 | RFC 5702 §2, and chapulin's own bound in the build colibri carries |
| `signature_bytes_max` | 512 | an RSA signature under the largest key |
| `rsa_modulus_bits_min` | 1024 | the count: 715 top-level domains publish a key of that size and none publishes a smaller one; RFC 5702 §2 allows 512 |
| `rsa_exponent_bytes_max` | 8 | the count: the longest exponent published is five octets; eight bounds what one verification costs |
| `zone_keys_bytes` | 2048 | the octets of keys one store entry keeps; the count's largest set is 1,824 |
| `zone_keys_max` | 8 | the keys one store entry keeps; the count's largest set holds 6 |
| `ds_records_max` | 8 | the DS records read from one set; the count's largest holds 3 |
| `signatures_per_rrset_max` | 4 | the RRSIGs tried for one RRset |
| `keys_per_signature_max` | 2 | the keys tried for one RRSIG when tags collide (RFC 4034 Appendix B) |
| `verifications_per_message_max` | 16 | a chain of `cname_hops_max` links and its end take 9 |
| `nsec3_iterations_max` | 100 | RFC 9276 Appendix A: a limit of 100 for reading a zone as insecure "is interoperable without significant problems"; the count's largest is 20 |
| `nsec3_hashes_per_message_max` | 32 | a closest encloser proof hashes one name for each label it tries |
| `chain_questions_max` | 32 | the DS and DNSKEY questions one walk asks |
| `key_asks_max` | 2 | the times a lookup asks one message again after waiting for keys |
| `trust_slots_reserved` | 1 | the slots only a walk's questions may take |
| `key_store_zones_default` | 64 | the engine's default; the caller sizes the store |
| `bogus_ttl_seconds` | 5 | RFC 9520 §3.2: one second at least, five minutes at most, and its own example starts at 5 |
| `clock_skew_seconds_default` | 0 | no RFC gives a value |

`records_max` stays 64. A signature covers every record of its RRset, so an RRset the record
walk cannot read whole cannot be verified, and under a signed zone a message with more records
than that fails the lookup.

### The models

- **The lookup's**, in Lean: `awaiting_keys` and the rows above. Theorems: a lookup that waits
  for keys asks for nothing to be sent; an end is `secure` only when every message it used was
  validated secure; a message the validator called bogus adds nothing to any end; a validating
  lookup never sends a query without EDNS0; and the measure that proves every lookup ends still
  falls at every send.
- **The walk's**, in Lean, a new file beside the `getaddrinfo` walks: zones as a tree with signed
  and unsigned delegations, a server that may answer anything, and verification abstracted to
  "valid under these keys". The theorem to prove, not only to check: whenever the store holds a
  zone's keys, there is a path from an anchor to that zone on which each DS set was validated
  under the keys of the zone above it and each DNSKEY set matched a validated DS; and it holds
  an insecure delegation only after a proof validated under keys it held. The walk ends within
  `chain_questions_max` questions.
- **The table's and the engine's**, in TLA+: the reserved slot, and two properties TLC checks. A
  walk's lookups never reach the consumer. A lookup that waits for keys is asked again or fails.

Each replay drives the code down its model's transitions, as §5 and §19 step 13 have it.

### Order and checks

Each step lands with its checks, each check broken on purpose and recorded in
`docs/mutations.md`. Steps 1 to 3 are Stage A, and the rest is Stage B.

1. The sources the plan lacks, into `docs/rfcs/` (question 24): RFC 1982, RFC 3110, RFC 8017,
   RFC 8032, RFC 4470 and RFC 2181. Done on 2026-10-17.
2. The ruling written down: §1, a decision in §16, CLAUDE.md's "Ask before" list, and the
   README's known limits.
3. Stage A whole, with its checks above.
4. What signed zones publish, measured: a tool asks for the DNSKEY, DS and NSEC3PARAM sets of
   the root and of every top-level domain, which a question may already name (decision 31),
   and reports what the count of 2026-10-03 above reports. That count came from a script over
   `dig` that is not in this tree; the tool makes it repeatable, and extends it to a list of
   zones below the top level. It needs no validator.
5. chapulin, then colibri, in their own repositories: the public calls, SHA-1, PKCS #1 v1.5
   over SHA-512, the RSA keys step 4 says are needed, and Ed25519. c4milo/chapulin#189 asks
   chapulin for them, opened on 2026-10-03. cocuyo pins the colibri that carries them.
6. `wire`: the types, the bits and the bit maps. The fuzz target builds each new type, and the
   dnslib check reads them.
7. `dnssec`, the pure half, over a verifier the tests supply: canonical order and form, the key
   tag, what a DS digest and a signature are computed over, and time. Against the RFCs' own
   examples where no arithmetic is needed: the ordered list of RFC 4034 §6.1, and the octets
   each example signs. The time of day is a parameter, so an example signed years ago is read
   under its own date.
8. `dnssec`, the denials: NSEC against the responses of RFC 4035 Appendix B, NSEC3 against RFC
   5155 Appendix B, and compact denial against RFC 9824 §3.
9. The key store and the validator, on whole messages: every response of RFC 4035 Appendix B and
   of RFC 5155 Appendix B, read under the tests' verifier, and refused with any signed octet
   changed.
10. The verifier over chapulin, outside `src/`: the DS examples of RFC 4034 §5.4 and RFC 4509
    §2.3, and the keys and signatures of RFC 5702 §6, RFC 6605 §6 and RFC 8080 §6, each that
    chapulin admits.
11. The lookup: its rows in §5, its model, then `awaiting_keys`.
12. The walk: its rules, its model, then the table's part and the TLA+ model.
13. The cache: the status, the TTL bound and the bogus entries.
14. The twin: a server in `sim` that signs for the tests' verifier, so the tests cover whole
    chains, a server that lies, signatures that have expired, signatures taken out, and a key
    that is replaced.
15. The engine: its options, the time, an example that resolves under the root's anchor over
    chapulin, the fill check and the instruction counts, and what one validation costs by
    algorithm, in §11.
16. A live check, once a day and not a gate: names known to be signed, unsigned and signed
    wrongly on purpose, through the public resolvers over DoT. cocuyo's status is compared with
    the AD bit the same server sets for the same question.

Checks, one for each piece of Stage B:

- A query under validation has DO and CD set and AD clear, and no response's AD or DO is read.
- Each of RFC 4035 §5.3.1's conditions refuses a signature when it alone is broken.
- A signature verifies over records the message holds in another order, with compressed names,
  lowered TTLs and mixed case, and fails with any one signed octet changed.
- Two keys with one tag: the signature verifies under the second.
- An RRset with one bad signature and one good one is secure.
- A zone whose DS set names only Ed448 is insecure, and one that names it beside algorithm 13
  validates under 13.
- A signature a second before its inception or a second after its expiration is refused, across
  the wrap of the 32-bit count.
- An answer's TTL is no larger than the time its signature has left.
- A wildcard answer without its proof is bogus.
- A CNAME a validated DNAME produces stands, and one it could not produce is bogus.
- NXDOMAIN with no proof under a signed zone is bogus, and NOERROR with NXNAME is a name error.
- An NSEC3 record above the iteration limit makes its answer insecure, and only once its
  signature has verified.
- An answer with its signatures taken out, under a signed zone, is bogus and never insecure.
- A delegation with no DS makes everything under it insecure, and the child's own NSEC does not.
- A lookup that waits for keys sends nothing, and asks again when they come.
- A table full of lookups that wait still fetches their keys.
- A walk past `chain_questions_max` fails the lookups that wait for it.
- A bogus answer over UDP is asked again over TCP, and a bogus one there moves to the next
  server.
- A hit from the cache hands back the status the entry was stored with.

### The decision this asks for, and what it would reject

When the owner rules, this goes to §16 as its next decision, in these words or better ones.

**Validation is a validator the table is handed, and the keys it needs are fetched under the
table.** The table names a `Validator` as it names a `Memory` (decision 22), so every lookup it
starts is validated, the composed ones included, which is the argument that put the cache under
the table (decision 23). Its cryptography is chapulin's, behind a verifier `dnssec` names, so
`src/` holds none. A message is validated in place when it arrives, with keys the store already
holds. A lookup whose keys are missing waits, the table asks the DS and DNSKEY questions
in a slot it keeps for them, and the lookup asks its question again. Rejected:

- A composition above the table, as `AddressLookup` is (decision 18). Validation decides what a
  lookup may do with a message, follow its CNAME or move to the next search candidate, so it
  belongs where the message is read. Above the table, every other composition would also have
  to learn it.
- Keeping a response until its keys come, which is a buffer of up to 64 KiB for each lookup that
  waits; decision 14 refused the whole message in a slot. Asking again costs one round trip,
  which the recursive server answers from its cache.
- Walking up from the signer, by the Signer's Name of each DS answer. It asks one DS question
  for each zone, where walking down asks one for each label, but each answer must be kept
  unvalidated until the keys above it come, or be asked twice.
- Cryptography under `src/`, from Zig's `std.crypto`, which this section's first draft had and
  the owner ruled out (decision 35).
- chapulin imported by `dnssec` itself, which gives the library a dependency (CLAUDE.md, "Ask
  before") and a consumer with no colibri no way to supply its own.
- Ed448 written for this, in either library, before a count says a zone needs it.
- Stage A alone, which leaves a server that lies undetected (RFC 4033 §12), or Stage B alone,
  which leaves out the cheap case: a consumer that already trusts the resolver it reaches over
  TLS.

### What reading the RFCs found in the code as it stands

None of these is DNSSEC's, and none is acted on here. On 2026-10-17 the owner asked for an issue
for each (question 25). They are c4milo/cocuyo#48 to c4milo/cocuyo#52, in the order below.

- `src/wire/edns.zig` cites RFC 6891 §6.1.4 for the DO bit. RFC 3225 §3 states it
  (non-negotiable 7).
- RCODE 6, YXDOMAIN, is not in `wire.Rcode`, so a response that carries it is ignored and the
  lookup waits out its deadline. A server answers it when a DNAME's substitution makes a name
  too long (RFC 6672 §2.2).
  Since 2026-10-27 `wire.Rcode` has `yxdomain`, and the lookup ends at once with `NameTooLong`
  (§16 decision 57).
- `attempts_max` is 5, which lets a configuration send one server five queries over one
  transport. "A resolver MUST NOT retry a given query to a server address over a given DNS
  transport more than twice (i.e., three queries in total)" (RFC 9520 §3.1). The default, 2,
  could send four when FORMERR and BADCOOKIE each add a retry. Fixed on 2026-10-27: a lookup counts the queries to each server, and
  `attempts_max` stays 5 (§16 decision 58).
- cocuyo caches no failure that is not a negative answer, and `docs/rfcs/README.md` says RFC
  9520 does not apply. "Resolvers MUST implement a cache for resolution failures" (RFC 9520
  §3.2), and §2's own example of a resolver with several servers to choose from is a stub.
  Fixed on 2026-10-27 in the cache module: `Cache.put_failure` keeps a resolution failure with a
  backoff to five minutes (§16 decision 60). Since 2026-10-28 the engine uses it through the
  table's memory (§16 decision 61).
- Under compact denial a name that does not exist can come back as NOERROR with no data, DO
  set or not (RFC 9824 §5). A lookup that does not validate then ends `NoData` where the name
  does not exist, and `AddressLookup` does not cancel the other family, as its rule 4 would.
