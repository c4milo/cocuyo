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

- **No cache.** Seam: `Answer.ttl_seconds` is reported, and `Lookup` touches no socket, so a cache
  wraps `Resolver.start` from above without changing this library.
- **No DNSSEC validation.** Seam: EDNS0 exists, the DO bit is a flag cocuyo never sets, and the
  record iterator hands out rdata unread, so a validator sits above the codec.
- **No DNS-over-TLS and no DNS-over-HTTPS.** Seam: the TCP path already produces length-prefixed
  messages, and the socket is the caller's, so DoT is the caller's TLS over the same bytes.
- **No mDNS, no zone transfers, no `NS`, `MX`, `TXT` or `SRV`.** Seam: the record iterator is
  type-agnostic; only answer collection is typed.
- **No `/etc/hosts`, no nsswitch, no NIS.** Seam: the same place as the cache.
- **No A-plus-AAAA merge and no Happy Eyeballs.** A caller that wants both runs two lookups.
- **No TCP connection reuse or pipelining** (RFC 7766 §6.2). One query per connection. Seam:
  `connect_tcp` names a server, so a caller with a pool can satisfy it from the pool.

## 2. Module graph

`build.zig` declares each module with its imports listed, so the dependency direction is enforced
by the build rather than by review.

| Module | Imports | Holds |
| --- | --- | --- |
| `core` | nothing | types, limits, errors, `Name`, `Address`, `Config` |
| `wire` | `core` | the codec: build a query, parse a response |
| `resolver` | `core`, `wire` | `Lookup`, `Resolver`, retry policy, entropy |
| `config` | `core` | the `resolv.conf` parser |
| `sim` | `core`, `wire`, `resolver` | the scripted server and the virtual clock, test-only |

`resolver` cannot import `config`. That is the split between the state machine and the config
parser, made structural: `Config` is a `core` type, the parser is one producer of it, and the
state machine cannot reach the parser even by accident.

The library root, `src/cocuyo.zig`, re-exports `core`, `wire`, `resolver` and `config`, so a
consumer writes `cocuyo.Lookup` and `cocuyo.resolv_conf.parse`. `sim` is never packaged.

### File layout

```text
src/cocuyo.zig                 the public surface, re-exports only
src/core/     core.zig constants.zig address.zig name.zig name_text.zig config.zig errors.zig
src/wire/     wire.zig wire_header.zig wire_name.zig wire_question.zig wire_record.zig
              wire_query.zig wire_response.zig wire_edns.zig wire_fuzz.zig
src/resolver/ resolver.zig lookup.zig lookup_poll.zig lookup_response.zig lookup_policy.zig
              entropy.zig constants.zig
src/config/   resolv_conf.zig resolv_conf_options.zig constants.zig
src/sim/      sim.zig sim_script.zig sim_gate.zig
examples/udp_blocking.zig
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
pub const Kind = enum(u16) { a = 1, cname = 5, ptr = 12, aaaa = 28, opt = 41 };
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

pub const Config = struct {
    servers: []const Endpoint,
    search: []const Name,
    ndots: u8 = ndots_default,
    attempts: u8 = attempts_default,
    timeout_ns: u64 = timeout_ns_default,
    udp_payload_bytes: u16 = udp_payload_bytes_default,
    mix_case: bool = true,
    rotate: bool = false,
};
```

### One lookup

```zig
pub const Lookup = struct {
    pub fn init(config: *const Config, question: Question, seed: u64) Lookup;
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
    names: []const Name,          // PTR results; addresses and names share storage
    canonical_name: ?*const Name, // the end of the CNAME chain, when there was one
    ttl_seconds: u32,             // the minimum TTL over the records used
    truncated: bool,              // more records existed than the slot can hold
};

pub const Failure = struct { err: Error, server_index: u8, attempts_made: u8 };
```

`on_response` never changes what the caller does next: the caller always calls `poll` afterwards.
`ignored` exists for counters and tests. A response that arrives after `.done`, for a cancelled
lookup, or from the wrong place, is `ignored` in any state — a stray late datagram is normal for a
caller with one socket, so it is an operational event, not a programmer error.

### Many lookups

```zig
pub const MatchKey = packed struct { transaction_id: u16, slot: u16 };
pub const Handle = packed struct { index: u16, generation: u16 };

pub const Resolver = struct {
    pub fn init(slots: []Lookup, keys: []MatchKey, config: *const Config, seed: u64) Resolver;
    pub fn start(self: *Resolver, question: Question) error{NoSlot}!Handle;
    pub fn poll(self: *Resolver, now_ns: u64, out: []u8) ?Event; // null: nothing to do now
    pub fn next_deadline_ns(self: *const Resolver) ?u64;         // arm one timer for the table
    pub fn on_datagram(self: *Resolver, message: []const u8, from: Endpoint, now_ns: u64) Verdict;
    pub fn cancel(self: *Resolver, handle: Handle) void;
};

pub const Event = struct { handle: Handle, action: Action };
```

A caller that has its own table of in-flight requests uses `Lookup` directly and skips `Resolver`.
It then owns the matching rules of §7, and the documentation says so in those words.

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
6. Only then is the answer section walked.

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
| hot block | 40 | state, flags, five indices, id, port hint, deadline, generator, TTL, free-list link |
| `name_question` | 256 | the name as asked, wire form |
| `name_current` | 256 | the current candidate or chain position |
| answers, a union | 272 | `[addresses_max]Address` is 272, `[ptr_names_max]Name` is 256 |
| total | about 824 | pinned by a test as each part lands |

The hot block is first and sized to stay inside one cache line, so the code that scans slots never
pulls in the name storage (§11).

| Caller allocation | Size | For |
| --- | --- | --- |
| `[N]Lookup` | about 824 bytes each | one per concurrent lookup |
| `[2N]MatchKey` | 4 bytes each | the id-to-slot table, power-of-two length |
| send buffer | `query_bytes_max`, 284 | shared by the whole table |
| receive buffer | `config.udp_payload_bytes`, 1232 by default | the caller's, per socket |

So 1024 concurrent lookups cost about 824 KiB of slots plus 8 KiB of keys. Nothing else is
allocated, ever, by anybody.

## 10. The config parser

`resolv_conf.parse` turns bytes into a `core.Config` and a storage struct the caller owns. It is a
separate module, it cannot be reached from the state machine, and it is independently testable
because it takes bytes rather than a path: the caller reads the file.

```zig
pub const Storage = struct {
    servers: [servers_max]Endpoint,
    search: [search_max]Name,
};

pub fn parse(bytes: []const u8, storage: *Storage) Config;
```

Recognised, and nothing else: `nameserver`, `search`, `domain`, `options ndots:`,
`options timeout:`, `options attempts:`, `options rotate`. `domain` is `search` with one entry, and
the last of the two wins. An unrecognised line, a malformed address or an option cocuyo does not
know is skipped, not an error — that is what every stub resolver does, and a config file with one
bad line must not stop a program from resolving. Counts above `servers_max` or `search_max` are
truncated, and the returned `Config` says so through the slice lengths.

`parse` cannot fail. It returns the default `Config` for empty input, which is the localhost
nameserver, matching the historical behaviour of the platform stubs.

## 11. Performance

The hints in <https://abseil.io/fast/hints> are the discipline here. Four of them change the
design rather than the prose.

**Estimate before optimising.** The costs, all estimated by hand from the operation counts and
none measured yet: building a query writes about 300 bytes and takes a few dozen branches;
parsing a response is one pass over at most 1232 bytes with no allocation; matching a datagram to
a lookup is one probe. Against a network wait of roughly 1 to 50 milliseconds, every one of those
is noise. The single structure that can matter is matching an inbound datagram when many lookups
are in flight, because that is the one cost that grows with the table. So that is the one thing
designed for a constant, and everything else is written for clarity first and measured later.

**Place frequently accessed fields together, and reduce the cache lines touched.** A naive
demultiplexer scans the slots, touching 824 bytes per candidate. Instead `Resolver` keeps a side
table of `MatchKey`, four bytes each, sixteen to a cache line, indexed by the low bits of the
transaction id with open addressing. Because the id is drawn from the generator it is uniform, so
one probe finds the slot, and the slot's own hot block — one cache line — carries the state and
the server index needed to finish the checks of §7. The `Lookup` layout is hot block first for the
same reason.

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

Not applied yet, on purpose: no hand-unrolling, no inline attributes, no specialised memcpy. Those
wait for `bench/`, which measures three operations — query build, response parse, datagram match —
and reports nanoseconds per operation. Until then, every number in this document says it is an
estimate.

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
  Every estimate in §11 is then either confirmed or corrected in place.

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
5. **TCP reuse.** Unanswered, so v1 is one query per connection, as §1 records. RFC 7766 §6.2
   pipelining would be a v2 change with `connect_tcp` unchanged.
6. **`/etc/hosts`.** Unanswered, so it is out of v1. It would live beside `resolv_conf.zig` in
   `config`, which is the module the state machine cannot import.
7. **Search-list order.** §5 records glibc's behaviour from memory. Worth pinning against a live
   `getaddrinfo` on both hosts before v1 is called done.
8. **A second example.** Unanswered, so step 6 ships the blocking one alone. A second example with
   many concurrent lookups on one socket is where `Resolver` and §11 earn their keep.
