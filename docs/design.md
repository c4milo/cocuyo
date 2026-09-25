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
  record iterator hands out rdata unread, so a validator sits above the codec.
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
  cocuyo's DNS half is the same for both. §21 is DoT's plan and the rulings that shape it, and
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

### File layout

```text
src/cocuyo.zig                 the public surface, re-exports only
src/core/     core.zig constants.zig address.zig name.zig name_text.zig config.zig errors.zig
              address_text.zig hosts.zig address_order.zig (§19 steps 14 and 15)
src/wire/     wire.zig wire_header.zig wire_name.zig wire_question.zig wire_record.zig
              wire_query.zig wire_response.zig wire_edns.zig wire_fuzz.zig
src/resolver/ resolver.zig lookup.zig lookup_poll.zig lookup_response.zig lookup_policy.zig
              entropy.zig constants.zig address_lookup.zig (§19 step 14)
src/config/   resolv_conf.zig resolv_conf_options.zig constants.zig
src/cache/    cache.zig cache_keys.zig cache_chain.zig cache_sweep.zig constants.zig
src/sim/      sim.zig sim_types.zig sim_loop.zig sim_loop_perform.zig sim_network.zig
              sim_server.zig sim_buffers.zig constants.zig fixtures.zig sim_scenarios_test.zig
io/           io.zig io_drive.zig io_events.zig io_udp.zig io_results.zig constants.zig
              fixtures.zig io_sim_test.zig
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
| Send buffer | `poll(now_ns, out)` | `out.len >= query_bytes_max` |
| Receive buffer | the caller's own | at least `config.udp_payload_bytes` |
| Servers and search list | `Config`, caller-owned slices | must outlive the lookups |
| Time | `now_ns` on every entry point | monotonic, non-decreasing, asserted |
| Entropy | a `u64` seed per lookup | must come from a CSPRNG; §7 says why |
| Sockets, connects, reads, writes | the caller performs them | cocuyo makes no syscall |

## 4. The public API

```zig
/// Every type c-ares parses, since §19 step 9; the full list with each type's RFC is there.
pub const Kind = enum(u16) { a = 1, ns = 2, cname = 5, soa = 6, ptr = 12, hinfo = 13, mx = 15, txt = 16,
    sig = 24, aaaa = 28, srv = 33, naptr = 35, opt = 41, tlsa = 52, svcb = 64, https = 65, any = 255,
    uri = 256, caa = 257 };
pub const Family = enum(u8) { ipv4, ipv6 };
pub const Address = struct { family: Family, octets: [16]u8 };
pub const Endpoint = struct { address: Address, port: u16 };

/// A name in uncompressed wire form, root label included.
pub const Name = struct {
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
    timeout_ns: u64 = timeout_ns_default,
    timeout_ns_max: u64 = timeout_ns_max, // the cap on the doubling wait (c-ares maxtimeout)
    udp_payload_bytes: u16 = udp_payload_bytes_default,
    mix_case: bool = true,
    rotate: bool = false,
    use_tcp: bool = false,        // every query over TCP (use-vc, ARES_FLAG_USEVC)
    ignore_truncation: bool = false, // a truncated UDP answer taken as it is (ARES_FLAG_IGNTC)
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
};
```

### One lookup

```zig
/// Per-server state every lookup of a caller shares: the DNS cookies of §19 step 10, the failover
/// counters of step 12. `Resolver` holds one; a caller driving a `Lookup` alone builds one.
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
    pub fn on_tcp_connected(self: *Lookup, now_ns: u64) void;
    pub fn on_tcp_failed(self: *Lookup, now_ns: u64) void;
    /// Over DoH or DoQ (§22, §23): the answer to the transaction `send_request` named, and its
    /// `Age` over DoH; or the request ended without one.
    pub fn on_request_answer(self: *Lookup, transaction: u16, message: []const u8, age_seconds: u32, now_ns: u64) Verdict;
    pub fn on_request_failed(self: *Lookup, transaction: u16, now_ns: u64) void;
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
    ttl_seconds: u32,             // the minimum TTL over the records used
    truncated: bool,              // more records existed than the slot can hold
};

/// One kept record: the type as the octets said it, the TTL, and self-contained rdata with every
/// name written out in full, so `wire.rdata.Mx.parse(kept.rdata)` and the others need no message.
pub const Kept = struct { kind_code: u16, ttl_seconds: u32, rdata: []const u8 };

pub const Failure = struct {
    err: Error,
    server_index: u8,
    attempts_made: u8,
    negative_ttl_seconds: u32, // the SOA minimum for NameNotFound and NoData (§18), else zero
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

    // Every event goes through the table rather than through the lookup, because each one can
    // move the instant the table is waiting for, and the timer it hands out has to follow.
    pub fn on_sent(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_send_failed(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_tcp_connected(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_tcp_failed(self: *Resolver, handle: Handle, now_ns: u64) void;
    // Over DoH or DoQ (§22, §23) an answer comes by handle: HTTP or QUIC paired it with its query.
    pub fn on_request_answer(self: *Resolver, handle: Handle, transaction: u16, message: []const u8, age_seconds: u32, now_ns: u64) Verdict;
    pub fn on_request_failed(self: *Resolver, handle: Handle, transaction: u16, now_ns: u64) void;

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
    ttl_seconds: u32,
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
| `awaiting_udp` | `poll` at or past it | `query_ready` or `failed` | advance the server, then the attempt |
| `awaiting_udp` | `on_response` unmatched | unchanged | return `ignored`, the wait stands |
| `awaiting_udp` | `on_response` with TC=1 | `tcp_needed` | keep the same server |
| `awaiting_udp` | `on_response` with a CNAME and no answer | `query_ready` | new transaction, hop count up |
| `awaiting_udp` | `on_response` with an answer | `done` | copy the records out |
| `awaiting_udp` | `on_response` NXDOMAIN or NODATA | `query_ready` or `failed` | advance the search candidate |
| `awaiting_udp` | `on_response` SERVFAIL, REFUSED, NOTIMP | `query_ready` or `failed` | advance the server |
| `awaiting_udp` | `on_response` FORMERR and EDNS0 was on | `query_ready` | same server, EDNS0 off |
| `awaiting_udp` | `on_response` FORMERR and EDNS0 was off | `query_ready` or `failed` | advance the server, as SERVFAIL does |
| `awaiting_udp` | `on_response` BADCOOKIE, the first from this server | `query_ready` | same server, the fresh cookie |
| `awaiting_udp` | `on_response` BADCOOKIE again | `tcp_needed` | same server, over TCP |
| `tcp_needed` | `poll` | `connecting_tcp` | return `connect_tcp`, arm the deadline |
| `connecting_tcp` | `on_tcp_connected` | `tcp_ready` | re-arm the deadline |
| `connecting_tcp` | `on_tcp_failed` | `query_ready` or `failed` | advance the server, as SERVFAIL does |
| `connecting_tcp` | deadline | `query_ready` or `failed` | advance the server |
| `tcp_ready` | `poll` | `tcp_ready` | build with the length prefix, return `send_tcp` |
| `tcp_ready` | `on_sent` | `awaiting_tcp` | arm the deadline |
| `tcp_ready`, `awaiting_tcp` | `on_tcp_failed` | `query_ready` or `failed` | advance the server, as SERVFAIL does |
| `awaiting_tcp` | `on_response` | as the UDP rows | TC=1 means nothing here, so the message is read as if it were clear |
| `awaiting_tcp` | `on_response` BADCOOKIE | `query_ready` or `failed` | advance the server, as SERVFAIL does |
| `done`, `failed` | any | unchanged | `poll` returns the same value; `on_response` is `ignored` |

Over DoH or DoQ (§22, §23) the lookup keeps the UDP states, and three rows change. `poll` in
`query_ready` returns `send_request`. An answer comes through `on_request_answer`, and only for
the transaction the lookup waits on; it is read as one over TCP is, so TC=1 means nothing and
BADCOOKIE advances the server. And one row is added:

| State | Event | Next state | Effect |
| --- | --- | --- | --- |
| `awaiting_udp` | `on_request_failed` for the current transaction | `query_ready` or `failed` | advance the server, as SERVFAIL does |

After `send_tcp` the caller reads two bytes, calls `wire.message_len(prefix)`, reads that many
bytes and passes them to `on_response`. There is no `read` action: the `wait` deadline already
governs the read, and the framing rule is three lines in the example (§15 step 6).

### Retry and timeout policy

- A deadline is `now_ns + (config.timeout_ns << round)`, capped at `timeout_ns_max`, where `round`
  counts completed passes over the server list. Doubling per round rather than per try is what
  glibc does; this is recalled, not measured.
- On expiry: `server_index += 1`. On wrap: `server_index = 0`, `round += 1`. When
  `round == config.attempts` the lookup fails with `Timeout`, or with `AllServersFailed` if any
  server answered SERVFAIL, REFUSED or NOTIMP, FORMERR without EDNS0, or BADCOOKIE over TCP,
  or refused the lookup: a connection or a handshake that failed, or a DoH or DoQ request that
  ended without an answer (§16 decision 25). So `Timeout` means that every try went unanswered.
  A failed send is not a refusal: the loop or the local stack refused it, and the server said
  nothing.
- EDNS0 is off for the server that answered FORMERR, and on again at the next server and the
  next name. RFC 6891 §6.2.2 makes a server's lack of EDNS0 a fact about that server, and a
  lookup that kept it off would ask every later server without a cookie and with a 512-octet
  limit.
- `rotate` starts the first try at `seed % servers.len` instead of server 0, so a process with many
  lookups does not aim all of them at one server.

### Search list policy

`ndots` decides the order, not whether the search list is used.

- A name ending in a dot is absolute: one candidate, the name itself, no search list.
- A name with at least `ndots` dots: the name itself first, then `name + "." + search[i]` for each
  entry in order.
- A name with fewer: the search entries first, then the name itself.
- NXDOMAIN or NODATA advances to the next candidate and resets the server and round counters.
  Exhausting the candidates fails with `NameNotFound`, or `NoData` if any candidate returned
  NOERROR with no record of the wanted type.
- SERVFAIL, REFUSED or NOTIMP moves to the next server, not to the next candidate. When every
  server has failed the lookup fails with `AllServersFailed`, and the walk stops there.

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
well-founded order, so no sequence of answers makes a lookup retry forever. `zig build spec`
builds the proofs, then walks every state the model reaches under 109 configurations and replays
each of the 2.2 million transitions against `Lookup`, comparing the answer and the whole state
after every event. `zig build test` replays a committed slice of 3,694 of them without Lean.
spec/README.md says what the model abstracts and why.

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
6. The cookie (RFC 7873 §5.3, since §19 step 10): when the query carried an OPT record, a
   COOKIE option in the response must echo the client cookie sent, and a server that has given a
   server cookie before must give one again; an OPT record that is malformed — a version cocuyo
   does not speak, an owner that is not the root, a cookie of a length neither form allows — is a
   discard too. Before a server has given a cookie, a response without one is a server without
   them, and stands.
7. Only then is the answer section walked.

Matching on the transaction id alone is the textbook cache-poisoning hole. Checking the source
address without the port is the same hole with one extra step. The question compare is exact
because of the next rule, not case-insensitive.

### Entropy: three fields, one seed

- **Transaction id**, 16 bits, drawn per transaction. A CNAME re-query is a new transaction and
  draws a new one.
- **DNS-0x20**, RFC 5452 and the DNS-0x20 draft: the case of each ASCII letter in the query's
  qname is randomised, and the response's question section must come back with the same case. This
  is in v1, on by default, and `Config.mix_case` turns it off for a server that mangles case.
  Roughly one bit per letter, so it is the largest entropy source available to a stub.
- **Source port**, RFC 5452: cocuyo owns no socket, so it cannot bind a port. `send_udp` carries
  a `local_port_hint` drawn from `[port_ephemeral_min, port_ephemeral_max]` and the caller may bind
  it. A caller that sends every query from one socket keeps the id and case entropy and loses the
  port entropy. The README says that in those words; the alternative, demanding a socket per query,
  would mean owning sockets.

All three come from a per-lookup generator seeded by the caller's `u64`. That keeps the state
machine replayable from a seed, which is the point of the determinism rule, and it puts the quality
of the defence in the caller's hands where it is visible. The docs say, in bold, that the seed must
come from a CSPRNG and never from the clock.

### Parsing

- Every length is checked against the end of the message before the bytes are read.
- No recursion anywhere in the parser. Compression is a loop with two bounds.
- A count field is never a reason to read. `ancount` says how many records the sender claims;
  the walk stops at the end of the message or at `records_max`, whichever comes first, and a count
  that disagrees with what was walked makes the message malformed.
- An unmatched or malformed datagram never disturbs the wait. An attacker who floods the socket
  costs the caller one bounded pass per datagram and changes no state, which is what makes the
  birthday attack of RFC 5452 §4 not worth running against a lookup that keeps listening until its
  deadline.

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

One loop, two bounds, no recursion.

- Read one length byte. The top two bits select the form: `00` is a label of that length, which
  must be at most `label_bytes_max`; `11` is a pointer whose low 14 bits are an offset; `01` and
  `10` are reserved and make the message malformed.
- A pointer offset must be **strictly less** than the offset of the pointer's own first byte. A
  pointer that points forwards or at itself is malformed. This alone makes a loop impossible,
  because every hop strictly decreases the offset.
- `compression_hops_max` bounds the hops anyway, asserted as well as checked, so a long legal
  chain is cheap and a pathological one is cheaper.
- The reconstructed name, counting length octets and the root, must be at most `name_bytes_max`.
- Decoding writes an uncompressed copy into a caller-provided `*Name`, so no caller ever holds a
  pointer into a datagram buffer it is about to reuse.

Both bounds are checks that return errors and assertions that must never fire, because a check
that returns and an assertion that holds are different claims: the first says the input was
hostile, the second says the code that already rejected the hostile input did its job.

### Record walking

For each record: skip the owner name without decompressing it, read type, class, TTL and
rdlength, check `offset + rdlength <= message.len`, then hand out the rdata slice. The owner name
is decompressed only when the type is one the lookup wants (§11). Type-specific rules:

- `A`: rdlength is exactly 4. `AAAA`: exactly 16. Anything else is malformed.
- `CNAME` and `PTR`: an rdata name, decompressed, and the decode must consume exactly `rdlength`
  bytes. Trailing bytes inside an rdata name make the message malformed.
- `OPT`: the owner must be the root, the class is the sender's UDP payload size, the TTL's high
  byte extends the rcode, and the version must be 0.

## 9. Memory the caller provides

Byte counts are hand-computed from the field list; a test pins `@sizeOf` so a layout change shows
up as a diff rather than as a surprise. The pins that exist are in `src/core/core.zig`: `Name` is
256 bytes, `Address` 17, `Endpoint` 20 and `Question` 260, all measured.

| Part of `Lookup` | Bytes | Note |
| --- | --- | --- |
| the scalars | 84 | state, flags, four indices, the server order, the transaction, two instants, the generator, the failure, the negative TTL, the chain's TTL, the config pointer, the servers pointer |
| `question` | 260 | the name as asked, its type, and whether it was absolute |
| `current` | 256 | the current candidate, or where the CNAME chain has reached |
| `answers` | 2448 | a union: `[addresses_max]Address` is 272, `[ptr_names_max]Name` is 256, and the records of §19 step 9 are 2436 — 32 references of 12 and a buffer of `rdata_bytes_max` — plus the count, the TTL, the hop count and two flags |
| total | 3048, measured | pinned by a test in `src/resolver/lookup_init_test.zig` |

The total is larger than the parts because Zig chooses a struct's field order and pads accordingly.
It also means a declaration order cannot be relied on for locality: the measurement that pinned
the first total, 856, also found `state` sitting past both names, so §11's demultiplexer earns its
keep through the side table and not through this layout. The lookup was 864 octets until the
records of §19 step 9 landed on 2026-09-22 and the union grew to hold an rdata buffer; every
caller pays it, an address lookup included, because a union is the size of its largest member.
The caller-provided buffer §19 keeps as the fallback is what would take it back.

| Caller allocation | Size | For |
| --- | --- | --- |
| `[N]Resolver.Slot` | 3064 bytes each, measured | one per concurrent lookup: a lookup plus the table's own octets, the ready list's two links and its flag among them (§11) |
| `[2N]MatchKey` | 4 bytes each | the id-to-slot table, power-of-two length |
| send buffer | `query_bytes_max`, 386 | shared by the whole table |
| receive buffer | `config.udp_payload_bytes`, 1232 by default | the caller's, per socket |
| `[M]AddressLookup` | 1152 bytes each, measured | one per `getaddrinfo`-shaped lookup in flight: the name, the canonical name, 32 addresses, two handles and the walk's scalars, beside the two slots it takes; pinned by a test in `src/resolver/address_lookup_test.zig` |

So 1024 concurrent lookups cost 3048 KiB of slots plus 8 KiB of keys. Nothing else is allocated,
ever, by anybody.

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
record walk the owner name is skipped without decompression until the type says the record is
wanted. The fast path — one server, no search expansion, the answer in the first datagram — makes
one pass and rebuilds nothing.

Two hints applied by refusing a feature: **thread-compatible, not thread-safe** (a `Lookup` is
touched only by its owner and cocuyo contains no lock or atomic), and **no promises that constrain
the implementation** (no iterator stability, no stable addresses for answers, which is why
`Answer` hands out slices into the slot and documents their lifetime as until the next call).

Not applied, on purpose: no hand-unrolling, no inline attributes, no specialised memcpy. They
waited for `bench/`, and `bench/` says none of them would buy anything a caller could see. A
change to any of these carries a new table, or it does not land.

### End to end against c-ares

§19 step 15's comparison, `zig build bench-cares` after its table: one responder thread on the
loopback answers every query with one A record, and each stack resolves 20,000 distinct absolute
names against it with 1, 16 and 128 lookups in flight, so neither's cache answers. cocuyo's side
is the engine of §19 step 13 over rotor, built privately for the bench and run on this thread,
ReleaseSafe with its assertions on. c-ares's side is the Homebrew build of the version the
binary prints, with its event thread, which gives it a second thread of its own, and one
`ares_query_dnsrec` per lookup, the next started from the callback. The responder and the kernel
are in every number and are the same for both. Lookups per second over the wall time, and the
median and 99th-percentile latency from start to result, in microseconds, on the machine above.

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
- From sixteen in flight to 128, cocuyo gains 11% and c-ares loses 5%, while latency grows about
  eightfold for both. The responder is one thread, and past sixteen in flight it is much of what
  the run measures.
- c-ares at one in flight rests on two runs. Four more runs of that row alone, taken to diagnose
  the stall below, finished three times at 35,876, 36,326 and 36,561: within 1% of the cell.
- Nothing here says anything about Linux, about a real network, or about a working set that a
  cache would answer: the names are distinct, so neither cache is ever asked twice.

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

Each limit lives in a `constants.zig` with a doc comment saying why that number, and is never
written at the use site. Shared limits live in `src/core/constants.zig`.

| Constant | Value | Why |
| --- | --- | --- |
| `header_bytes` | 12 | RFC 1035 §4.1.1 |
| `message_bytes_max` | 65535 | the TCP length prefix is 16 bits |
| `udp_payload_bytes_default` | 1232 | the widely recommended EDNS0 size that avoids IPv6 fragmentation; recalled, not measured |
| `query_bytes_max` | 386 | 12 header + 255 qname + 4 type and class + 55 OPT + 4 Padding option header, padded to 384 (§21), + 2 TCP prefix |
| `name_bytes_max` | 255 | RFC 1035 §2.3.4 |
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
| `attempts_max` | 5 | bounds the retry loop |
| `ndots_default` | 1 | the `resolv.conf` default |
| `timeout_ns_default` | 5 s | the `resolv.conf` default |
| `timeout_ns_max` | 30 s | caps the doubling |
| `port_ephemeral_min`, `_max` | 49152, 65535 | the IANA ephemeral range |
| `lookup_slots_max` | 1024 | bounds a `Handle` index and the key table |

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
past the end, rdata lengths one byte too long, names at exactly 255 and 256 bytes. The seed prints
on failure. `zig build fuzz -- --seed <hex>` runs one, `zig build fuzz-gate [count]` runs a range
and is part of `zig build test`. The invariants: the parser never reads outside the message, always
terminates, and never returns a name longer than `name_bytes_max`.

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
   the caller reuses one socket.
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
    short and force a retry they can race.
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
   and `Answer.truncated` says so when they do. I have not measured it.
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
11. **Service names.** §19 leaves `/etc/services` to the consumer, so `AddressLookup` takes no
    port and the reverse recipe returns no service. If a consumer needs `getservbyname`, a
    parser in `config` is the place.
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
    stands. On the synthetic trace that is 3.0 points more hits at the default 1024 slots and
    1.0 fewer at 4096 (§18). An expired entry holds its slot until its name is asked again or
    the hand meets it. The public surface is unchanged.
15. **Should a port be replaced under load?** Answered on 2026-09-23: yes. A port that had
    carried `udp_queries_per_port` queries was replaced only once no lookup waited on its
    server, so under steady load it was never replaced, and the setting did nothing when it
    mattered most; the engine model showed nothing made a retiring port rotate. Now a new socket
    takes every query at once and the old one drains, as c-ares does as recalled rather than
    read (§19 step 13, the datagram's rule 4). A server holds two sockets at most while one
    drains.

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
pub const Outcome = enum { answered, name_not_found, no_data };

pub const Slot = struct {
    name: Name,             // folded: the key, and what a hit hands back
    answers: wire.Answers,  // the records, for an answered entry
    expires_ns: u64,
    hash: u32,
    links: Links,           // older and newer: the insertion-order chain, oldest to newest
    kind: Kind,
    outcome: Outcome,
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
};

pub const Cache = struct {
    pub fn init(slots: []Slot, keys: []Key, seed: u64, ttl_seconds_max: u32) Cache;
    pub fn get(self: *Cache, question: *const Question, now_ns: u64) ?Hit;
    pub fn put(self: *Cache, question: *const Question, answers: *const wire.Answers, now_ns: u64) void;
    pub fn put_negative(self: *Cache, question: *const Question, outcome: Outcome, ttl_seconds: u32, now_ns: u64) void;
    pub fn flush(self: *Cache) void;
    pub fn len(self: *const Cache) usize;
};
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
- A `put` for a question the cache holds replaces the entry in place and sets the bit; it does not
  move it in the order. A `put` of a TTL of zero, or of an answer marked truncated, is refused.
  The TTL is capped at `ttl_seconds_max`.
- A `put` into a full table runs the hand: from where it stopped, or the oldest entry, toward the
  newest; an expired entry is evicted on sight; a visited entry has its bit cleared and stays; the
  first unvisited entry is evicted. The walk is bounded by twice the slot count, which is one
  pass that clears every bit and a second that must then find one, and that bound is asserted.
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
carries zero, and zero is not cached.

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

- **The cache earns its keep.** At the 1024 slots the engine takes by default, 2.9 MiB of the
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
  3.0 at the default 1024, and loses 1.0 at 4096. The reading, which no measurement isolated:
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
  the ceiling for a given trace and TTLs. The cache is 5.8 points under it at the default 1024
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

- **There is room at the sizes that matter.** The optimal is 5.7 points over the cache at the
  default 1024 slots, 8.7 at 256 and 7.1 at 64. At 4096 it already reaches the ceiling, c-ares's
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
  over it at the default 1024 slots and 0.67 under it at 16384.
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
they were a workload: before they were set aside, the default size read 75.04% over every client
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

- **Where cocuyo is deployed, SIEVE is close to the best there is.** A cache a client, at the
  default 1024 slots, is 2.0 points under the optimal with TTLs by hash and a quarter of a point
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
policy could add at the default size is two points, and S3-FIFO's lead is a resolver's. This is
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

### Limits

| Constant | Value | Why |
| --- | --- | --- |
| `cache_slots_max` | 16384 | a `u16` chain index with room for the sentinels, and a table nobody has asked for more of |
| `cache_keys_per_slot_min` | 2 | the load factor that keeps a bounded probe short |
| `cache_probe_max` | 16 | the longest chain a `get` walks before calling it a miss |
| `cache_ttl_seconds_max_default` | 3600 | c-ares's default cap, so a consumer replacing it sees the same ceiling |
| `cache_sweep_steps_max` | twice the slots | one pass clears every bit, the next must find one |

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
| the event thread, `sock_state_cb`, `ares_process_fd`, the socket callbacks | `Resolver`, driven by the caller | the engine over rotor would be the built-in driver; held back until a consumer asks | 13 |
| `ares_cancel`, the active count, wait-empty, `ares_reinit`, `ares_set_servers` | `Lookup.cancel` | engine | 13 |
| the query cache | §18 | the engine wires it in | 13 |
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
};
```

A record of a type not in the enum is not an error and never was: the record walk keeps the type
code, and a caller reads the rdata raw (RFC 3597 §3).

**What a lookup keeps.** `Lookup` keeps the records of the type asked for, owned by the end of
the CNAME chain (RFC 5452 §6, as today), and copies them out of the message, because the message
buffer is the caller's and may be reused the moment `on_response` returns. Addresses and PTR
names keep their storage; everything else goes into a fixed rdata buffer of `rdata_bytes_max` octets with a
table of `records_kept_max` references, and the three share one union, because one question asks
one type:

```zig
pub const Answers = struct {
    items: union { addresses: [addresses_max]Address, names: [ptr_names_max]Name, records: Records },
    ...
};
pub const Records = struct {
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

**Questions.** Every kind but `opt` is queryable. Asking for `CNAME` keeps the CNAME record and
follows nothing (RFC 1034 §3.6.2). Asking for `ANY` keeps every record the name owns whatever
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
`Answers.reset`, `Answers.assign` and `Lookup.init_in_place` in §11.

### Step 10: DNS cookies

The COOKIE option (RFC 7873 §4) rides in the OPT record: a client cookie of 8 octets, and after
the first exchange the server cookie it answered with, 8 to 32 octets (§4.2; RFC 9018 §3 fixes
the length at 16 for servers that follow it, and a client reads only the length).

- The client cookie is a pseudorandom function of the server's address and a secret (§4.1).
  cocuyo derives it from the caller's seed and the server address through `core.mix`. The
  RFC's third input, the client's own IP address, is not known before a socket is bound, and
  is left out; its purpose is a different cookie per source address, which the seed gives per
  process instead. The caveat of §7 applies: the mix spreads a seed, it is not a cryptographic
  function, and the defence is against an off-path attacker who sees no cookie at all.
- Per-server state, which nothing in cocuyo had before: the client cookie, the server cookie
  learned and its length, and the failover counters of step 12, in a `Servers` table of
  `servers_max` entries. `Lookup.init` takes a pointer to it beside the config, because the
  config is shared and constant and this is neither; `Resolver` owns one and hands it to every
  lookup. Rejected: putting it in `Config`, which is immutable and shared, or in `Lookup`, which
  is per question.
- On a response (§5.3): the client cookie in it must be the one sent, or the response is
  discarded, which lands in §7's checks as one more reason to ignore a message and never disturb
  the wait. A correct client cookie has its server cookie cached even when the response is an
  error. BADCOOKIE (extended RCODE 23) is retried once with the fresh server cookie, and a second
  BADCOOKIE goes to TCP (§5.3), which is the path `tcp_needed` already takes. A response with
  no COOKIE option is discarded only when the client is expecting one (§5.3), which cocuyo reads
  as: a server cookie has been learned from that server. Before that, a server that answers
  without the option is one without cookies, and its answer stands.
- FORMERR from a server that rejects the option is what RFC 6891 §6.2.2's fallback already
  covers: the query is repeated without EDNS.

**Gate.** The fake server of `resolver/fixtures.zig` learns cookies: a good one, a wrong
client cookie, a malformed option, a BADCOOKIE once, twice and over TCP, and a server with none.
Mutations on each check.

Landed on 2026-09-22: `wire/edns.zig` writes and reads the option, `wire/response_opt.zig`
finds the OPT record, `resolver/servers.zig` holds the per-server state, and `on_response`
runs check 6 (§7). `Lookup.init` takes the `Servers` pointer, and the lookup is 3032 octets.

### Step 11: configuration parity

`Config` grows the knobs c-ares exposes, each with c-ares's default so a consumer that set none
sees the same behaviour:

- `use_tcp` (`USEVC`): every query over TCP.
- `ignore_truncation` (`IGNTC`): a truncated UDP answer is taken as it is.
- `recursion_desired` (`NORECURSE` clears it): the RD bit, on by default.
- `check_response` (`NOCHECKRESP` clears it): off, SERVFAIL, NOTIMP and REFUSED end the lookup
  as answers rather than moving to the next server.
- `primary`: only the first server is asked.
- `timeout_ns_max` (`MAXTIMEOUTMS`): the cap on the doubling wait, a field with the constant as
  its default.
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
`failover_retry_chance`. Success resets the count; a timeout or a failed send raises it. c-ares
probes a failed server with a copy of the query alongside the real one, so a recovered server is
found without costing a real query a timeout. Rejected: it needs two transactions per lookup,
and §7's defences bind one; here the probing query is a real one, and the price is one timeout
in ten queries, after the delay, on a server that is still down.

Landed on 2026-09-22: `Servers` counts consecutive failures per server with the instant of the
last, a timeout, a failed send and a failed connection each counting one and an answer of any
kind resetting it; `lookup_order.zig` computes a lookup's order at its first poll, which is the
first instant it has, and the order holds for the lookup. The lookup is 3040 octets.

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
out of them by the length prefix of §8; the buffer it assembles into is `tcp_message_bytes`, the
longest a prefix can describe unless the caller knows its answers are smaller. A connection
nobody is using is closed after `tcp_idle_ns` (§6.2.3). The chunks arrive in a buffer group of
their own, since a datagram group carries rotor's prefix before every payload, and a group that
runs dry is the ordinary end of a receive rather than a broken connection.

**The stream's rules, written on 2026-09-23** from RFC 7766 and rotor's decision 5, for the engine
model to be written from, in Lean then and in `spec/tla/engine/` since 2026-09-24. They are what the engine is held to; where the code
of 2026-09-22 broke one, the model found it, and the fix is recorded with it.

1. One connection per server, in one of `tcp_connections` slots. A lookup that needs a stream to
   its server is put on that server's connection. If there is none, one is opened in the first
   closed slot, or else in the first slot whose connection has no lookups on it, which is closed
   to make room. When no slot can be had, the lookup is told its connection failed.
2. Each opening of a slot is an incarnation, and every operation on the connection carries the
   incarnation in its `user_data`. An event for another incarnation belongs to a connection
   that is gone and changes nothing, whatever it holds: a cancelled connect can still end in
   success (rotor decision 5, rule 2). A provided buffer the event carries goes back to the
   loop all the same.
3. A lookup is on a connection only while it is on a stream to that connection's server. The
   drive takes it off before acting on its poll when the poll shows it anywhere else: its
   deadline passed, its connection failed, it moved to the next name, it ended.
4. A connection's users are the lookups on it. When the last leaves, the connection is idle from
   that instant, and one idle for `tcp_idle_ns` is closed by the drive at an instant that late.
5. When the connect succeeds, the receive is armed and every lookup on the connection that is
   still connecting is told. When the connect fails, the receive fails, or the peer closes,
   every lookup on the connection is told its connection failed and leaves it, and the
   connection is closed.
6. A send lends the lookup's send buffer to the loop until the send's final event (rotor
   decision 5, rule 3). No send is submitted from that buffer before then. A send asked for
   while the buffer is lent is held, and submitted when the buffer comes back if the attempt
   that asked for it is still the lookup's; otherwise it is dropped, and the lookup's next poll
   asks again.
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
    again at once, and the new address was written over the one the loop still held.

**The datagram's rules, written on 2026-09-23** in the same way, for the same model. Rules 6 to 8
of the stream hold for datagrams as they stand: a send lends its buffer, a completion speaks for
the attempt that made it, and the drive goes on until nothing is left.

1. One socket per server, each with one multishot receive into the datagram group. A socket that
   is open always has a receive armed, or gets one at the next drive: a receive that ends is
   armed again, and one the loop refuses is asked for again at the next drive, not forgotten.
2. Each arming of a receive is a generation, carried in its `user_data`. An event of another
   generation belongs to a receive that is gone and changes nothing, whatever it holds: a
   cancelled multishot receive can still deliver datagrams before its final event (rotor
   decision 5, rule 2).
3. Every event that carries a buffer gives it back before the event is over, whatever the event
   is for: a datagram once the table has read it, whatever its length, and a stale event's at
   once.
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

**Checked on 2026-09-23.** The engine model, in Lean then and in `spec/tla/engine/` since
2026-09-24, holds both sets of rules above. Each lookup is the model of §5, and around the lookups sit
the table's ready list and free list (§11), the connections, the sockets, and the operations the
loop holds. A configuration asks every query over TCP, or every query over UDP with a port
replaced every two queries. The model's clock moves in ticks, each the idle close's wait, and a
lookup waits two of them. The loop may refuse every submission for the length of one event, and
socket opens may fail for the length of one event. A stream's send may come back short once a
message, its rest then whole or failed: a second short send takes the same path as the first.

- The Lean walker, `cocuyo-spec engine` until it retired on 2026-09-24, walked every state the
  model reached in a configuration and checked ten invariants in each; TLC checks twenty-five now, eight of them the request rules' of §24
  (spec/README.md). A connection's users are the lookups on it. A lookup is only on a
  connection to its server. A buffer is lent to one send at most. A connection and a socket each
  have at most one current operation of each kind. A drive leaves nothing on the ready list.
  After a drive nothing refused, every socket has its receive armed and every connection that is
  up has its receive. And after such a drive, a port that has carried its share is replaced
  unless an older one still drains, and a draining socket nothing is owed on is gone. A stream
  has one send in flight at most, its queue's head's, and no query waits twice. A slot whose
  address a connect that is gone still borrows stays closed. They held in every state of one slot
  and one connection over TCP, and in all 5.85 million of one slot over UDP; spec/README.md has
  the counts. This is model checking over bounded configurations,
  not a proof.
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

**The rest of the engine, landed on 2026-09-22.** `cancel_all` ends every lookup at once, which
is `ares_cancel`, and each failure comes through `take` like any other. `reinit` takes a new
configuration, which is `ares_reinit`: it empties the cache, whose answers came from servers that
may be gone, closes the streams and opens the sockets again. It requires an idle engine, because
a lookup in flight was started against servers that are going away and its handle names a slot
the new table has never heard of; a caller with lookups in flight calls `cancel_all` and takes
their failures first, which is what tells it what it lost. `Config.udp_queries_per_port` is
c-ares's `udp_max_queries`: a port that has carried its share is replaced at once, and the old
socket drains, keeping its receive until the last query sent from it has its answer or its
end (the datagram's rule 4). `Config.local_address` is `ARES_OPT_LOCAL_IP4`
and `LOCAL_IP6`, and `socket_receive_bytes` and `socket_send_bytes` are the two buffer sizes,
which rotor 0.2.0 made expressible. What a kernel grants is rarely what it was asked for: Linux
doubles and caps, macOS grants and then refuses, and a socket that would not take the size is
used with the size it has, because a buffer smaller than the caller wanted loses datagrams and a
socket that was not opened loses every one. Binding to a device by name stays out: rotor names no
device.

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
        lookups: u16 = engine_lookups_default,
        cache_slots: u16 = engine_cache_slots_default,
        tag: u16 = engine_tag_default,          // the high bits of every user_data the engine submits
        udp_queries_per_port: u32 = udp_queries_per_port_default,
        tcp_idle_ns: u64 = tcp_idle_ns_default,
    };
    pub fn memory_bytes(options: Options) usize;
    pub fn init(self: *Engine, memory: []align(alignment) u8, loop: *rotor.Loop, config: *const Config,
        hosts: ?*const Hosts, seed: u64, now_ns: u64, options: Options) Error!void;
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
    /// New configuration: the cache is flushed and the sockets rebound, which is `ares_reinit`.
    pub fn reinit(self: *Engine, config: *const Config, hosts: ?*const Hosts, now_ns: u64) Error!void;
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
  and a lookup that ends puts its answer, or its negative answer with the TTL of §18.
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
   are in, whatever they were.

`NameLookup` is the same shape with one lookup: the hosts table and DNS in the `lookups` order,
and one `PTR` question. Its `NameNotFound` or `NoData` moves on to the next source; any other
failure ends the walk with that failure; the sources gone, the walk fails `NameNotFound`, or
`NoData` when the lookup said `NoData`. The consumer's cancel ends it `Canceled` whatever end
its lookup had. Until 2026-09-23 any failure moved on, and a walk whose last source was DNS
ended `NameNotFound` when its lookup had timed out: a timeout reported as a name that does not
exist.

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

### New limits

| Constant | Value | Why |
| --- | --- | --- |
| `records_kept_max` | 32 | half `records_max`: what one answer section holds of one type, with `truncated` past it |
| `rdata_bytes_max` | 2048 | one UDP payload of 1232 plus room for the names decompressed on the way in; `truncated` says when a TCP answer did not fit |
| `cookie_client_bytes` | 8 | RFC 7873 §4 |
| `cookie_server_bytes_max` | 32 | RFC 7873 §4 |
| `opt_record_bytes` | 11 to 55 | the OPT record with a COOKIE option carrying the largest server cookie |
| `query_bytes_max` | 284 to 328 | follows from it |
| `hosts_entries_max` | 1024 | more lines than a machine that is not a blocklist has; past it, dropped and said so |
| `hosts_names_per_entry_max` | 8 | a name and its aliases on one line |
| `failover_retry_chance_default` | 10 | c-ares's default: one query in ten retries a failed server |
| `failover_retry_delay_ns_default` | 5 s | c-ares's default |
| `udp_queries_per_port_default` | 0 | c-ares's default: never replace the socket |
| `tcp_idle_ns_default` | 10 s | chosen, not measured: a burst's worth, and short by RFC 7766 §6.2.3's standard |
| `engine_lookups_default` | 256 | in flight at once; the caller sizes the memory |
| `engine_cache_slots_default` | 1024 | 2.9 MiB of slots, the cost §18 measures |
| `address_lookup_addresses_max` | 32 | both families' `addresses_max`, bounded the way one answer is; `truncated` past it |
| `address_policy_rows` | 9 | RFC 6724 §2.1's default table |
| `common_prefix_bits_v6_max` | 64 | RFC 6724 §2.2 stops at the source's prefix, and RFC 4291 §2.5.1 makes the interface identifier the low 64 bits |

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
  `cocuyo_rotor` too, rooted at `io/io.zig`, and ships `io/` (§24). The build refuses to compile
  when a registered module's root is not under a path the manifest ships.
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
/// storage and are read before the call returns.
pub const Remembered = union(enum) {
    answered: *const wire.Answers,
    negative: struct { outcome: Negative, ttl_seconds: u32 },
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
`NoData` — and no query is ever built. The asking is at the first poll rather than at `start`
because `poll` is where the clock comes in, and an expiry needs one (CLAUDE.md non-negotiable 4):
`start` keeps its signature, and nothing above the table learns a new shape. `poll`,
`AddressLookup` and `NameLookup` work unchanged, and every question they ask goes through the
cache, because they all start through the table.

**An end is remembered once.** `poll` may produce a lookup's end more than once, because a
lookup that has ended and waits for `release` answers each poll with it again (§11). The slot
carries a bit that says its end was remembered, set when `poll` first produces it, and a slot
seeded from the cache never writes back what it was handed.

`cocuyo.remembered_by(&cache)` builds a `Memory` from a `Cache`. It is the only place that maps
a `Failure` to what may be kept: `NameNotFound` and `NoData` with the TTL the SOA gave
(RFC 2308 §5), and nothing else — not a timeout, not a refusal, not a malformed answer.
`io/` then drops its own copy of that policy and passes a `Memory` like any other caller.

**A recalled answer carries the chain's end.** The cache is keyed by the question, and until
§17 question 13 was answered it stored the answers and not the chain that reached them, so an
answer that came through a CNAME lost its canonical name once remembered. The slot now keeps the
chain's end, and `Remembered` carries it both ways: the table writes `current` when the lookup
was aliased, and a recalled lookup reports it back exactly as one that went out reports its own.
The same question answers the same whether the cache held it or not. It costs one `Name` a slot,
256 octets on 2728.

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
- `AddressLookup` asks one question when the cache holds the other family, and none when it
  holds both.
- An end is remembered once, however many times it is polled.
- A lookup seeded from the cache does not write back what it was handed.
- `zig build consumer-check` builds the dependent fixture, and the fixture that imports `sim`
  fails to build.

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
  CSPRNG at init and expands it with ChaCha20 behind chapulin's `ch_rand_bytes`, one stream per
  engine. A certificate's validity needs the wall clock: the caller gives Unix seconds pinned to
  a `now_ns` at init and at `reinit`, and the engine adds the elapsed `now_ns`. chapulin's own
  DRBG was the alternative, and it is one stream for every session in the process.
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
3. A connection's sealed records wait in a buffer of the connection's own, which a send lends to
   the loop until its final event (rotor decision 5, rule 3). The slot is not opened again while
   a send of an earlier incarnation's records is in flight, as the stream's rule 10 keeps it for
   a connect.
4. A handshake that fails fails the connection (the stream's rule 5): a record the session
   refuses, a certificate or a name that does not verify. No query was sent on it, and each
   lookup on it fails over to the next server. The server has refused the lookup, so one whose
   passes run out ends in `AllServersFailed` (§16 decision 25).
5. An idle connection that is up makes the session's `close_notify` (RFC 9846 §6.1). It closes
   when that record has gone, and no lookup joins it meanwhile. A record the peer sends
   meanwhile is not read: the session has said its last. One whose handshake has not
   ended has no session to close, and closes at once. A connection that fails closes at once
   too: a party that has sent an error alert owes no `close_notify` (§6.1), and one whose peer
   has gone has nobody to send it to.
6. A TLS connection is never closed to make room for another. A TLS configuration needs a slot
   for each of its servers, and the engine asserts it has them.
7. Records received go to the session whole. The connection reads each record's length from
   its five-octet header, and keeps a partial record until the rest arrives. A record longer
   than the buffer fails the connection. The session's `recv` hands over whole records and
   answers 0 only at a record boundary, which chapulin reads as "no record yet"; a 0 inside a
   record would kill the session.
8. Each server keeps the newest ticket its sessions were given, and the next connection to that
   server resumes with it. A ticket is used once, since reuse lets an observer link two
   connections (RFC 9846 §C.4). It is dropped at its lifetime, or 7 days after it came,
   whichever is sooner (§4.7.1). Its age is the engine's clock since it came, not the wall
   clock. A resumed handshake that fails is not the server's failure. A server that declines a
   ticket has said nothing yet about its certificate, and a full handshake is what decides. So
   the connection is opened again in the same slot, in full. That happens as soon as the loop
   has given back any records the failed session had in flight (TLS rule 3). Its lookups stay on
   it meanwhile, count no failure, and hear only how the full handshake ends.
9. A TLS configuration opens no UDP socket. Every query goes on a stream (all or none), so a
   datagram socket would only hold a descriptor and a receive that nothing may use. The owner
   ruled so on 2026-09-23.

The model holds rules 1 to 6, 8 and 9. Rule 7 is about octets, which the model does not count. Four
invariants were added for them: a slot a send of records still borrows stays closed; the sealed
entries lead each queue, so records go out in the order they were sealed; no query waits on a
connection that is not up; and no event leaves the session owing an answer. The last came from a
mutation nothing caught without it (docs/mutations.md TM3). Three more hold rule 8: a connection
that opens resuming spends its server's ticket; one opened again after a declined ticket
handshakes in full; and a declined ticket counts no failure and keeps its lookups on the
connection. The replay drives no TLS
configuration until step 5, when the engine speaks TLS.

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

- `io/io_chapulin.zig` fills it from chapulin's record transport. It is built only when
  `-Dchapulin` names a checkout, as colibri's own endpoints link chapulin: the headers are read
  in place and nothing is vendored.
- The twin fills it with `sim.tls`, a session whose records carry their plaintext unsealed and
  whose handshake steps are spelled in the records the twin's server sends. The twin's servers
  script it, and the replay drives the model's steps with it one by one, so the gate needs no
  chapulin.

chapulin's session starts from a `Context` the caller hands `Resolver.use_tls`:

- the trust anchors, at most 12, each a root's subject Name and SubjectPublicKeyInfo as DER;
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
  `ch_build_info_tcp_nonblocking`.

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
  a buffer of at least 12338 octets for chapulin, and room for one whole record in.

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
   `-Dchapulin`, `zig build test-chapulin` and `examples/dot_rotor.zig` (`build/dot.zig`).
6. A live check against the public resolvers that serve DoT: `dns.google`, `cloudflare-dns.com`
   and `dns.quad9.net`. `tools/dot_live/run.sh` runs it, on macOS, with each resolver's root from
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
   gate: a failure there can be a resolver changing what it does, as Google's refusal was.

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
  nowhere else to ask. A handle is the caller's until it releases it, as for every other event:
  a request still open then is the driver's to forget.
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
- An answer by transaction, a request that failed, and a truncated answer read as it stands,
  over DoQ as over DoH.
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
  at once. Ruled on 2026-09-24 (§21, chapulin's docs/porting.md).

### What already holds

The engine was written for a loop it does not own:

- `init` takes the caller's `*rotor.Loop`, and never makes one.
- Every operation it submits carries its `tag` in the high bits of `user_data`, and `apply`
  returns false for an event that is not its own, which goes back to the caller untouched.
- `loop_operations` says how many operations the loop must hold for it, so the caller sizes the
  loop's `Options` for every component it runs.
- Nothing in it is global but chapulin's thread-local stream, and nothing allocates (CLAUDE.md
  non-negotiable 2).

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
   user, or its own with the same surface.
3. **A request interface.** The TLS session interface of §21 lets the engine speak TLS without
   naming chapulin. A request interface lets it carry DoH and DoQ without naming colibri. `Options` gains
   the request transport's type:
   - colibri's QUIC and HTTP/3, over chapulin's QUIC object, fill it when the build names a
     colibri checkout and a chapulin checkout;
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
   - DoH goes over HTTP/3 first. HTTP/2 joins when colibri's h2 client has its TLS
     (c4milo/colibri#7).

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
   one for each lookup slot: over DoQ the message with its prefix, over DoH the HEADERS frame of
   a GET. colibri reads a stream's bytes by offset until the server acknowledges them, so they
   cannot stay in the lookup's send buffer, which the lookup's next poll writes over.
4. **A request waits for its connection.** A request taken while its connection opens or
   handshakes waits in the connection's queue. When the connection is up, each waiting request
   opens its stream in the order it was taken, and supplies its bytes, then FIN. A stream colibri
   cannot open yet, for want of the server's stream credit, waits for the next credit.
5. **The answer by its stream.** A stream the server ends with FIN is read whole, into one buffer
   the engine keeps for the purpose, and handed over at once: the table reads an answer before
   the call returns. Over DoQ the message goes to the lookup without its prefix, with the
   transaction the request carried and an `Age` of zero. Over DoH a 2xx response's body goes with
   its `Age` (RFC 8484 §5.1), and any other status fails the request (§4.2.1). The lookup hears
   it only if the request's attempt is still its own, as stream rule 7 has it for a send.
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
   fails the connection (rule 7). One the loop refuses is asked for again at the next drive, as a
   refused receive is: colibri makes a datagram again from what is still unacknowledged, and
   QUIC takes a datagram lost or late.
9. **An idle connection closes.** A connection with no request on it for `quic_idle_ns`, or one
   near the idle timeout it negotiated (RFC 9250 §4.4), closes. The engine has colibri make
   CONNECTION_CLOSE, with DOQ_NO_ERROR (RFC 9250 §4.4) or H3_NO_ERROR (RFC 9114 §8.1), and closes
   the socket once that datagram has gone. A request taken meanwhile waits, and opens the connection again once it has closed.
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

The model holds rules 1 to 4 and 6 to 11. Rules 5 and 12 are about octets, and the model reads a
stream's answer as an event, with no octets. The invariants the model gains:

- A request slot is free, or holds one request, on its lookup's server's connection.
- A request has a stream only on a connection that is up.
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
  wall clock and the engine's seeded stream. It makes the first flight.
- `receive` takes one datagram. What it did is read with `next`, one thing at a time: the
  handshake ended, and on which protocol; the handshake failed; a stream was answered; a stream was
  reset; the server closed; a ticket came. An answer carries its message, and over DoH its status,
  its `Age` and whether a content coding was applied (request rules 5 and 12).
- `request` opens a stream for a request slot, or says the server's stream credit has run out. Over
  DoQ it carries the lookup's message with its prefix, then FIN. Over DoH it carries a GET built
  from the server's template and the `dns` variable, with `accept-encoding: identity` and a
  never-indexed `:path` (request rule 12). The request's bytes stay in the slot until the stream
  no longer needs them (request rule 3).
- `cancel` sends STOP_SENDING and resets the engine's side of a stream (request rule 6).
- `datagram` hands over the next datagram the connection owes, or nothing.
- `deadline` gives the connection's next QUIC deadline, and `expire` tells it the instant came.
  What that did is read with `next` (request rule 11).
- `close` makes the CONNECTION_CLOSE of an idle close (request rule 9), and `wipe` drops every
  secret.

Three types fill it:

- `io/io_quic.zig` fills it from colibri's `quic` and `h3` and chapulin's QUIC object. It is built
  only when the build names a colibri checkout and a chapulin checkout, as `io/io_chapulin.zig` is
  built only when it names chapulin's.
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

### A thread per core

An image runs one loop on each core and one engine on each loop. Nothing crosses between cores:

- Each engine has its own table, cache, connections, tickets and seeds. The seeds come from a
  CSPRNG, one set for each engine: two engines with one seed would draw the same transaction ids.
- A `Config` is read and never written, so every engine may hold a pointer to one.
- A name one core resolved is a miss on another, and each core opens its own connection to
  each encrypted server. An image of `n` cores holds up to `n` times `servers_max` of them. A
  cache shared across cores was the alternative, and it needs a lock or atomics in the lookup's
  path, which the architecture refuses. A miss costs one round trip.
- cocuyo keeps no global mutable state, and the global-state rule holds it there: no
  container-level `var` under `src/` or `io/` but a `threadlocal` one.

### New limits

| Constant | Value | Why |
| --- | --- | --- |
| `quic_connections_max` | `servers_max` | one connection to a server |
| `quic_streams_max` | the engine's `lookups` | one stream for a request, and a request for each lookup at most |
| `quic_receive_bytes` | measured in step 4 | colibri's receive pool for a connection, the caller's to size; its default of 1 MiB is far past the answers a connection has in flight |

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
   session links it whenever it is linked. The lint rule landed the same day, as pepegrillo's
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
5. DoH over HTTP/3, with a live check against Cloudflare and Google.
6. Two engines on two threads of one image, each on its own loop, resolving at once.
7. DoH over HTTP/2, after colibri#7.

Checks, one for each piece:

- An event another component submitted comes back from `apply` false and untouched, and the
  engine's own is taken.
- In an image with two users of chapulin, each handshake draws from its own user's stream.
- A container-level `var` that is not `threadlocal` fails the lint, and the canary shows it.
- A connection whose ALPN is neither `doq` nor `h3` is never up.
- A request the lookup left sends STOP_SENDING, and its answer never reaches the table.
- A reset stream, a failed connection and a failed handshake each fail every request on them,
  once.
- A 2xx answer's `Age` lowers its TTLs, and a 404 fails the request.
- Two engines on two threads resolve at once, and neither sees the other's events.
