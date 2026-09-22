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
- **No DNSSEC validation.** Seam: EDNS0 exists, the DO bit is a flag cocuyo never sets, and the
  record iterator hands out rdata unread, so a validator sits above the codec.
- **No DNS-over-TLS and no DNS-over-HTTPS.** Seam: the TCP path already produces length-prefixed
  messages, and the socket is the caller's, so DoT is the caller's TLS over the same bytes.
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
| `io` | `cocuyo`, `rotor` | the engine of §19 step 13: sockets, timers and connections over a loop with rotor's surface, in `io/`; compiled against `sim` for the gate, and not exported |

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
    pub fn cancel(self: *Lookup) void;
};

pub const Action = union(enum) {
    send_udp: struct { server: Endpoint, local_port_hint: u16, message_bytes: []const u8 },
    connect_tcp: Endpoint,
    send_tcp: struct { message_bytes: []const u8 }, // length prefix included
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
    pub fn poll(self: *Resolver, now_ns: u64, out: []u8) ?Event; // null: nothing to do now
    pub fn next_deadline_ns(self: *Resolver) ?u64;               // arm one timer for the table
    pub fn on_datagram(self: *Resolver, message: []const u8, from: Endpoint, now_ns: u64) Verdict;

    // Every event goes through the table rather than through the lookup, because each one can
    // move the instant the table is waiting for, and the timer it hands out has to follow.
    pub fn on_sent(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_send_failed(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_tcp_connected(self: *Resolver, handle: Handle, now_ns: u64) void;
    pub fn on_tcp_failed(self: *Resolver, handle: Handle, now_ns: u64) void;

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
    unreachable: bool = false,
    deprecated: bool = false,
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
| `tcp_needed` | `poll` | `connecting_tcp` | return `connect_tcp`, arm the deadline |
| `connecting_tcp` | `on_tcp_connected` | `tcp_ready` | re-arm the deadline |
| `connecting_tcp` | `on_tcp_failed` or deadline | `query_ready` or `failed` | advance the server |
| `tcp_ready` | `poll` | `tcp_ready` | build with the length prefix, return `send_tcp` |
| `tcp_ready` | `on_sent` | `awaiting_tcp` | arm the deadline |
| `awaiting_tcp` | `on_response` | as the UDP rows | TC=1 here is malformed, so `ignored` |
| `done`, `failed` | any | unchanged | `poll` returns the same value; `on_response` is `ignored` |

After `send_tcp` the caller reads two bytes, calls `wire.message_len(prefix)`, reads that many
bytes and passes them to `on_response`. There is no `read` action: the `wait` deadline already
governs the read, and the framing rule is three lines in the example (§15 step 6).

### Retry and timeout policy

- A deadline is `now_ns + (config.timeout_ns << round)`, capped at `timeout_ns_max`, where `round`
  counts completed passes over the server list. Doubling per round rather than per try is what
  glibc does; this is recalled, not measured.
- On expiry: `server_index += 1`. On wrap: `server_index = 0`, `round += 1`. When
  `round == config.attempts` the lookup fails with `Timeout`, or with `AllServersFailed` if any
  server answered SERVFAIL, REFUSED or NOTIMP.
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

This ordering is glibc's behaviour as recalled, not as measured. §17 asks whether to pin it
against a live `getaddrinfo` before shipping.

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
  `ChainTooLong`.

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
| the scalars | 80 | state, flags, four indices, the server order, the transaction, two instants, the generator, the failure, the negative TTL, the config pointer, the servers pointer |
| `question` | 260 | the name as asked, its type, and whether it was absolute |
| `current` | 256 | the current candidate, or where the CNAME chain has reached |
| `answers` | 2448 | a union: `[addresses_max]Address` is 272, `[ptr_names_max]Name` is 256, and the records of §19 step 9 are 2436 — 32 references of 12 and a buffer of `rdata_bytes_max` — plus the count, the TTL, the hop count and two flags |
| total | 3040, measured | pinned by a test in `src/resolver/lookup_init_test.zig` |

The total is larger than the parts because Zig chooses a struct's field order and pads accordingly.
It also means a declaration order cannot be relied on for locality: the measurement that pinned
the first total, 856, also found `state` sitting past both names, so §11's demultiplexer earns its
keep through the side table and not through this layout. The lookup was 864 octets until the
records of §19 step 9 landed on 2026-09-22 and the union grew to hold an rdata buffer; every
caller pays it, an address lookup included, because a union is the size of its largest member.
The caller-provided buffer §19 keeps as the fallback is what would take it back.

| Caller allocation | Size | For |
| --- | --- | --- |
| `[N]Resolver.Slot` | 3048 bytes each, measured | one per concurrent lookup: a lookup plus the table's own octets |
| `[2N]MatchKey` | 4 bytes each | the id-to-slot table, power-of-two length |
| send buffer | `query_bytes_max`, 284 | shared by the whole table |
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
of them sits within 5% of the first, most within 2%. The harness overhead, the first row, is included in every
other row and not subtracted. The numbers are cocuyo's alone: nothing here is measured against
c-ares or any other resolver, so the table supports no claim about speed relative to what cocuyo
replaces. Nanoseconds per operation, from the commit that landed §19 step 12; the table was first
measured by the commit that added it, and is re-measured whole whenever a change moves a row,
because the rows move together (below):

| Case | Fastest | Median |
| --- | --- | --- |
| harness overhead, an empty call through the same function pointer | 1.5 | 1.5 |
| query build, `example.com`, EDNS0, no cookie | 8.4 | 8.6 |
| query build, a 255-octet name, over TCP | 10.6 | 11.0 |
| name decode, two labels | 15.8 | 16.3 |
| name decode, through a compression pointer | 17.1 | 17.5 |
| response parse, one A record | 49.6 | 50.9 |
| response parse, a CNAME then its A record, with a 256-octet restore of the chain | 187.2 | 189.4 |
| response parse, 17 A records, 16 kept | 587.4 | 593.9 |
| datagram match, an id nobody holds, 1 in flight | 3.1 | 3.1 |
| datagram match, an id nobody holds, 1024 in flight | 3.1 | 3.2 |
| datagram match, right id and wrong question, 1 in flight | 36.7 | 37.9 |
| datagram match, right id and wrong question, 64 in flight | 37.5 | 38.2 |
| datagram match, right id and wrong question, 1024 in flight | 37.6 | 38.6 |
| datagram match, right id and wrong question, rotating over all 1024 slots | 54.1 | 55.1 |
| slot restore, a 3048-octet copy the accepted case pays and a caller does not | 52.0 | 53.6 |
| datagram match, accepted, 1024 in flight, with the slot restore | 148.0 | 149.4 |
| lookup round trip: `init_in_place`, `poll`, `on_sent`, `on_response` | 209.5 | 211.3 |
| `resolv.conf` parse, three lines | 329.1 | 331.1 |
| cache hit, one entry, hot | 30.9 | 31.7 |
| cache hit, rotating over 1024 entries | 43.4 | 44.6 |
| cache miss, 1024 entries, a young index | 12.4 | 12.8 |
| cache miss, 1024 entries, after churn | 35.1 | 36.1 |
| cache put, replacing an entry in place | 37.6 | 38.9 |
| cache put, evicting, 1024 entries and the table full | 95.8 | 97.0 |

What the table says, against the estimates:

- The estimates hold, and were pessimistic. A query builds in 9 ns. A response with one record
  parses in 51 ns, and one with seventeen records, sixteen of them kept, in 588 ns: about 34 ns for
  each record walked beyond the first — (588 − 51) / 16, the seventeenth walked and its owner
  decoded before it is refused — which is a skip, an owner name decoded through a pointer at 17 ns,
  and the address copied. A CNAME chain resolved in one message costs 186 ns: the chain moves
  once, the section is walked twice, five names are decoded on the way (the two owners on each of
  the two passes, and the CNAME's target once), three 256-octet copies move the chain, and the row
  carries the restore its name says.
- The demultiplexer is the constant it was designed to be. An id nobody holds is refused in 3 ns
  whether 1 or 1024 lookups are in flight, and a real id with the wrong question — the probe plus
  every check of §7 short of the answer walk — costs 37 ns at 1 in flight and 38 ns at 1024.
  Accepting one at 1024 in flight costs 149 ns, of which 54 is the slot the harness puts back after
  each iteration, so 95 ns is the match, check 6 and the answer walk.
- Those rows aim every iteration at one slot, which sits in the first-level cache from the second
  iteration on. The rotating row aims each iteration at a different one of the 1024, whose 3 MiB
  do not fit the 128 KiB first level and do fit the 12 MiB second: the same path costs 54 ns there,
  so a slot read cold out of the first level adds 17 ns. A datagram arriving from the kernel finds
  its slot at least that cold.
- A whole lookup, minus the network — made in its slot, its query built with its cookie, the
  send heard, the answer read and its OPT record sought — is 211 ns. Against the shortest round
  trip the estimate considered, one millisecond, that is 0.021%: the network is about 4,700 times
  the library.
- The cookies of §19 step 10 cost 17 ns a lookup: the round trip read 185 ns before them and
  201 after, the accepted match 80 and 97 net of the restore. That is the COOKIE option written
  into every query, a 41-octet cookie copied out of the server table on the way, and the OPT
  record sought across the three sections of every accepted response for check 6. The slot
  restore row fell from 52 to 41 while the slot grew from 3032 octets to 3040, and rose to 54
  again at 3048: a copy of a size that is a multiple of 32 is the faster one, which is the layout
  effect below in another form.
- The failover of §19 step 12 costs 10 ns a lookup: the round trip read 201 ns before it and
  211 after. That is the order computed at the first poll — a sort of one server, the draw that
  decides a retry — and every read of the current server going through the order.
- The rdata buffer of §19 step 9 costs what is written, not what is held. With `collect` building
  a whole `Answers` per response, one A record parsed in 79 ns, a lookup started in 302 and a cache
  put in place took 60; with `reset` and `assign` touching only the storage a kind uses, and
  `init_in_place` building a lookup in its slot instead of in a local that is then copied, the
  three rows read 51, 185 and 38, which is below where two of them stood before the buffer
  existed, because the copy `init_in_place` removes was there at 864 octets too.
- The cache of §18 answers a hot hit in 32 ns — the keyed hash over the name, one probe, the
  folded compare and the division that turns the expiry into seconds — and a miss in 13 ns when
  the index is young, because the walk stops at the first empty entry. After churn, when every
  entry the evictions freed is a tombstone the walk steps over, a miss walks to the probe bound and
  costs 36 ns; that is the bound doing what §18 says, and `flush` is what resets it. A hit read
  cold over 1024 entries, 2.7 MiB of slots, costs 44 ns, 12 ns over the hot one. A put that
  replaces an entry in place costs 38 ns; one that has to evict, with the hand meeting an
  unvisited entry at once, 96 ns: the miss, the eviction's unlink and key removal, the key insert,
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

**Against c-ares.** `zig build bench-cares` on 2026-09-22, the same machine, clock and method as
the table above: cocuyo ReleaseSafe against the Homebrew build of c-ares 1.34.8, which is its
shipping build, optimised, with its assertions compiled out. Two runs back to back; every median
from the second, each within 2% of the first. The cocuyo rows here are the same code as above
measured in a different binary, and sit up to a tenth below the table above — 7.8 ns against 8.6
for the query build — so a comparison reads within one table and never across two. Nanoseconds
per operation:

| Case | cocuyo | c-ares | c-ares over cocuyo |
| --- | --- | --- | --- |
| query build, `example.com`, EDNS0: cocuyo from a name it holds into the caller's buffer; c-ares from a prepared record into a buffer it allocates and the caller frees | 7.8 | 945.4 | 121 |
| the same, with c-ares building the record as well: create, question, OPT, write, both freed | 7.8 | 1,281.3 | 165 |
| response parse, one A record: cocuyo checks owners and copies the address out; c-ares parses to a record tree, the address is read, the tree is freed | 41.8 | 680.0 | 16 |
| response parse, a CNAME then its A record, the same two ways | 166.8 | 1,059.8 | 6.4 |
| response parse, 17 A records: cocuyo keeps sixteen and says so, c-ares keeps all seventeen | 560.8 | 4,039.3 | 7.2 |

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
one timer rather than one per lookup; it is a cached value invalidated when the owning slot fires
or is retired, not a scan. `on_datagram` is one call per datagram.

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

## 12. Named limits

Each limit lives in a `constants.zig` with a doc comment saying why that number, and is never
written at the use site. Shared limits live in `src/core/constants.zig`.

| Constant | Value | Why |
| --- | --- | --- |
| `header_bytes` | 12 | RFC 1035 §4.1.1 |
| `message_bytes_max` | 65535 | the TCP length prefix is 16 bits |
| `udp_payload_bytes_default` | 1232 | the widely recommended EDNS0 size that avoids IPv6 fragmentation; recalled, not measured |
| `query_bytes_max` | 284 | 12 header + 255 qname + 4 type and class + 11 OPT + 2 TCP prefix |
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
| `opt_record_bytes_max` | 55 | the OPT record with the largest COOKIE option; `query_bytes_max` is 328 with it |
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
- **Everywhere.** cocuyo does not read `/etc/hosts`, does not consult nsswitch, and does not know
  about NIS, LDAP or mDNS. A name that resolves for every other program on the box can fail here,
  and that is by design, not a bug.

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
7. **Search-list order.** §5 records glibc's behaviour from memory. Worth pinning against a live
   `getaddrinfo` on both hosts before v1 is called done.
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
12. **Does `name_info` need an entry point?** §19 step 14 makes it a recipe: `Hosts.reverse`,
    then a `PTR` lookup. If a consumer wants one call, it is a small type beside
    `AddressLookup`.

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
- A `get` that finds an expired entry evicts it and misses. A `get` that hits sets the visited bit
  and returns the remaining TTL, which is the expiry less `now_ns`, rounded down to a second.
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

The cache rows of §11's table, on the same day and machine: a hot hit 31 ns, a hit read cold
over 1024 entries 44 ns, a miss 13 ns on a young index and 36 ns after churn, a put in place
37 ns, a put that evicts 97 ns. The first build of the hash copied the question's name, folded
it octet by octet, and mixed the type, the flag and the length in three steps: the hit cost
50 ns, the miss 23, the eviction 123. Folding eight octets at once as the name is read
(`Name.fold_word`, in `core` because folding is `core`'s) and mixing the prefix once brought
them to the numbers above, a third off every row. Nothing here was compared against c-ares's
cache, whose entry is a parsed record tree and whose key is a formatted string, so no ratio is
claimed.

### Memory

Per slot: a `Name` at 256, an `Answers` at 2448 since §19 step 9 gave it the rdata buffer, and
24 octets of scalars and padding: 2728, measured and pinned by a test in `src/cache/cache.zig`
(568 before that step, with `Answers` at 284). The key index is eight octets an entry at two
entries a slot, rounded up to a power of two. A thousand slots cost 2.7 MiB of slots and 16 KiB
of keys; sixteen thousand, the most a `u16` slot index and the key index allow at
`cache_slots_max`, cost 43 MiB and 256 KiB. The caller chooses, and an address-only cache pays
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
| OPT options: COOKIE, NSID, ECS, padding, extended error | OPT written, its options unread | `wire` for COOKIE; the rest as raw options | 10 |
| DNS cookies | none | a `wire` option, `resolver` per-server state | 10 |
| `ares_query` and `ares_search` | the search list applies by `ndots` | `Question.absolute` is the switch (§5) | — |
| `ARES_FLAG_USEVC`, `IGNTC`, `NORECURSE`, `NOCHECKRESP`, `PRIMARY`, `NO_DFLT_SVR`, `ARES_OPT_MAXTIMEOUTMS`, a TCP port per server | none; the maximum timeout is a constant | `Config` | 11 |
| the hosts file, `ARES_OPT_LOOKUPS`, `ares_gethostbyname_file` | none | `config.hosts` parses the consumer's bytes into a `core.Hosts`; `AddressLookup` keeps the `lookups` order | 11, 14 |
| `ARES_OPT_RESOLVCONF`, `RES_OPTIONS`, `LOCALDOMAIN` | the parser takes bytes | the consumer reads them; `config` parses the option string | 11 |
| server failover | the next server on a failure, in a fixed order | `resolver` per-server state | 12 |
| `udp_max_queries` | one port hint per lookup | engine | 13 |
| TCP reuse (`STAYOPEN`) and pipelining | one connection per query | engine; the framing is there (RFC 7766 §6.2.1) | 13 |
| local address and device binding, socket buffer sizes | none | engine | 13 |
| the event thread, `sock_state_cb`, `ares_process_fd`, the socket callbacks | `Resolver`, driven by the caller | the engine over rotor would be the built-in driver; held back until a consumer asks | 13 |
| `ares_cancel`, the active count, wait-empty, `ares_reinit`, `ares_set_servers` | `Lookup.cancel` | engine | 13 |
| the query cache | §18 | the engine wires it in | 13 |
| `ares_getaddrinfo`: `A` and `AAAA` together, the canonical name, numeric host and service, the hosts file, `V4MAPPED`, `ALL` | two lookups | `resolver`, as `AddressLookup` above the table | 14 |
| `ares_gethostbyaddr`, `ares_getnameinfo` | a `PTR` lookup | `Hosts.reverse`, then the `PTR` lookup; service names are out | 14 |
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

**Held back on 2026-09-22.** The owner ruled that no library bound to rotor is exposed until a
consumer asks for one: none does today, and every consumer so far drives `Resolver` from a loop
of its own. So the engine is not an exported module, no build option fetches rotor for it, and
`build.zig.zon` does not ship `io/`. What lands is the engine compiled against the twin below,
under `zig build test-io`, which is the gate this step promised: every path of the library
driven from a seed through a loop of rotor's shape. The engine itself names nothing of the
twin; only its tests do, and they compile only when the twin is the `rotor`. The day a consumer
asks, the build's `rotor` import is the one line that changes. The first slice landed that
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
  to `address_lookup_addresses_max` with `truncated` past it, and each slot is released the
  moment its lookup ends, so a walk across candidates holds two slots and not two per
  candidate. `canonical_name`, when asked for, is the end of the CNAME chain of the winning
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
- **`name_info`** is a recipe rather than an entry point: `Hosts.reverse` for the address,
  then `Question.from_address` and a `PTR` lookup, two calls the consumer makes in order. §17
  asks whether that is enough.

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
  puts last; `unreachable`, for rule 1; `deprecated`, in RFC 4862's sense, for rule 3; and
  `encapsulated`, for rule 7, which the RFC leaves to what an implementation knows of its
  interfaces. Rule 4, home and care-of addresses, never decides: mobile IPv6 is outside
  version one, and the rule is written down as skipped rather than left out. With no routes,
  rules 1, 2, 5 and 9 never decide either, and rules 6, 8 and 10 order the list: precedence,
  smaller scope, then the order received.
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

Then the comparison the README will state: the decoders against c-ares's, which
`zig build bench-cares` measures today, and end to end, both stacks against one in-process
responder, lookups per second and latency at a number in flight, on the machine and the day §11
names. cocuyo's side of that run is a `poll(2)` loop in `bench/`, which may own a socket
(CLAUDE.md, Layout). The engine over rotor would have been that driver, and will be the day it
is exposed.

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
| `engine_cache_slots_default` | 1024 | §18's memory table row |
| `address_lookup_addresses_max` | 32 | both families' `addresses_max`, bounded the way one answer is; `truncated` past it |
| `address_policy_rows` | 9 | RFC 6724 §2.1's default table |
| `common_prefix_bits_v6_max` | 64 | RFC 6724 §2.2 stops at the source's prefix, and RFC 4291 §2.5.1 makes the interface identifier the low 64 bits |

### Order and gates

Steps 9 to 15 land in that order, each with its mutation table in `docs/mutations.md`, each
committed only when `zig build test` is green, and step 13 beginning with the twin, so the
engine is driven at every seed before it touches a socket. §15 lists them as steps of the plan.
Step 14 begins with its two moves into `core`, each committed on its own before the shape.
