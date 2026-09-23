# cocuyo

A DNS resolver library for Zig that owns the DNS protocol and none of the I/O.

cocuyo builds queries, reads responses, and decides what to do next. It never opens a socket,
starts a thread, sets a timer or allocates memory. Every function that would block returns a value
naming the I/O it needs, and your program does it: a blocking socket, epoll, kqueue, io_uring, or
any completion loop you already run.

It is written from the RFCs, as a replacement for c-ares. The name is the Colombian word for the
firefly, and for a car's hazard lights.

> **Status: pre-release.** The library is feature-complete against its plan and is not yet tagged
> or licensed (see [License](#license)). It needs Zig 0.16.0. The API may still change.

## Why cocuyo

c-ares does two jobs: the DNS protocol, and owning the sockets it speaks it over. Embedding it means
connecting its event loop to yours through `ARES_OPT_SOCK_STATE_CB` and `ares_process`, and testing
it means a network.

cocuyo does the first job only. That choice gives you four things:

- **It fits your loop.** You send the bytes it hands you and give it the bytes you receive. The same
  library runs under a blocking socket and under io_uring, unchanged.
- **Its memory is yours, sized once.** You hand cocuyo its lookup table and its cache at init. It
  never allocates, so there is no allocator to pass and no out-of-memory path at run time.
- **It is deterministic.** Time and randomness are arguments. The same seed and the same clock
  replay the same lookup byte for byte, so the state machine is tested without a network.
- **It checks itself in production.** Assertions stay on in every build cocuyo offers. A malformed
  response is an error value, never a crash; a broken internal rule stops the program.

## When to choose it, and when not to

cocuyo sends DNS queries to the servers you give it. That is all it does. It is not your operating
system's resolver, and it does not see what that resolver sees.

- **macOS.** `/etc/resolv.conf` is a partial, legacy view. The system resolves through
  per-interface configuration and through mDNSResponder, for `.local` names and for split-DNS domains
  routed to a VPN. A program calling `getaddrinfo` sees all of that. cocuyo reading `resolv.conf`
  sees none of it.
- **Linux with systemd-resolved.** `/etc/resolv.conf` usually points at the 127.0.0.53 stub, which
  applies per-link routing, so cocuyo gets close to what other programs see. Where `resolv.conf` is
  a static list instead, per-link domains are invisible.
- **Everywhere.** cocuyo reads the hosts file only when you parse it and hand it the table. It does
  not consult nsswitch, NIS, LDAP or mDNS. A name that resolves for every other program on the
  machine can fail here, by design.

Choose cocuyo when you want a resolver that is explicit, testable and the same on every host: a
server, a proxy, a container, an embedded system. Choose `getaddrinfo` on a thread when you need
exactly what the rest of the machine sees.

## What it does

| Area | What cocuyo provides |
| --- | --- |
| Lookups | One question per lookup, for every record type c-ares parses: A, AAAA, PTR, CNAME, NS, SOA, MX, TXT, SRV, NAPTR, TLSA, SVCB, HTTPS, URI, CAA and more |
| Many lookups | `Resolver`, a bounded table of lookups that decides which lookup an incoming datagram belongs to |
| `getaddrinfo` shape | `AddressLookup` joins A and AAAA, the hosts file and the search list, and orders addresses by RFC 6724; `NameLookup` does the reverse |
| Transport | UDP with EDNS0 (RFC 6891) and its fallback, TCP on truncation or by choice (RFC 7766), with the length prefix handled for you |
| Robustness | Retries with a doubling timeout, rotation, and server failover that tracks failures per server |
| Configuration | `resolv.conf`, `RES_OPTIONS` and `LOCALDOMAIN`, and the hosts file, parsed from bytes you read |
| Cache | Optional, sized by you, with SIEVE eviction and RFC 2308 negative caching |
| Security | DNS cookies (RFC 7873), DNS-0x20 case randomisation, a source-port hint, and strict response matching |

The search-list walk has been checked on the wire against glibc 2.39, musl 1.2.5 and c-ares 1.34.8.
cocuyo walks as glibc and c-ares do. The one difference is SERVFAIL: cocuyo stops and reports the
failure, as c-ares does, where glibc moves on to the next search domain and hides it.

## How it works

You own the loop. cocuyo tells you what to do next, and you tell it what happened. This is the
driving loop of [`examples/udp_blocking.zig`](examples/udp_blocking.zig), shortened:

```zig
var servers = cocuyo.Servers.init(&config, seed);
var lookup = cocuyo.Lookup.init(&config, &servers, try cocuyo.Question.from_text(name, .a), seed);
var query: [cocuyo.constants.query_bytes_max]u8 = undefined;

while (true) {
    switch (lookup.poll(clock.read(), &query)) {
        .send_udp => |send| {
            // Send send.message_bytes to send.server, ideally from send.local_port_hint.
            lookup.on_sent(clock.read());
        },
        .wait => |deadline_ns| {
            // Receive until deadline_ns, then hand over whatever arrived:
            // _ = lookup.on_response(datagram, from, clock.read());
        },
        .connect_tcp, .send_tcp => {
            // The answer was truncated: the same exchange over TCP.
        },
        .done => |answer| return answer, // addresses, TTL, canonical name
        .failed => |failure| return failure.err,
    }
}
```

For many lookups at once, `Resolver` does the same with one `poll` for the whole table, one
deadline to arm one timer, and one `on_datagram` call per datagram received.

## Quick start

Add cocuyo to your package:

```bash
zig fetch --save git+https://github.com/c4milo/cocuyo
```

Import its module in `build.zig`. cocuyo exports one module, `cocuyo`, and fetches nothing else
when it is a dependency:

```zig
const cocuyo = b.dependency("cocuyo", .{ .target = target, .release = true });
exe.root_module.addImport("cocuyo", cocuyo.module("cocuyo"));
```

Then give it its memory and ask it for its first action. `config`, `seed` and `now_ns` are yours:
a `Config` from `cocuyo.resolv_conf.parse` or built by hand, a seed from a secure random source, and
a monotonic clock in nanoseconds.

```zig
const cocuyo = @import("cocuyo");

var slots: [64]cocuyo.Slot = @splat(.{});
var keys: [256]cocuyo.MatchKey = @splat(.{});
var entries: [1024]cocuyo.cache.Slot = @splat(cocuyo.cache.Slot.empty);
var index: [2048]cocuyo.cache.Key = @splat(.{});

var store = cocuyo.Cache.init(&entries, &index, seed, cocuyo.cache.constants.ttl_seconds_max_default);
var table = cocuyo.Resolver.init(&slots, &keys, &config, seed);
table.remember_with(cocuyo.remembered_by(&store)); // optional: the cache under every lookup

_ = try table.start(try cocuyo.Question.from_text("example.com.", .a));
var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
const event = table.poll(now_ns, &query).?; // event.action is .send_udp: the bytes, and where
```

[`examples/`](examples) holds two complete programs that resolve real names against real servers:
one over a blocking UDP socket, one over a completion-based event loop.

> **The seed must come from a cryptographically secure random source, never from the clock.**
> cocuyo draws the transaction id, the source-port hint and the DNS-0x20 case pattern from it. A
> guessable seed makes a guessable query, and a guessable query can be spoofed.

## Security

cocuyo parses unauthenticated input from the network. A response is considered only if all of these
hold, checked in this order:

1. Its length is between the 12-octet header and the largest message allowed.
2. Its transaction id is the one sent.
3. It came from the address and port the query went to.
4. It is a response to a standard query.
5. Its question is byte-identical to the one sent, letter case included.
6. Its DNS cookie matches, when the query carried one (RFC 7873).

Only then is the answer read. Three sources of entropy defend each query against spoofing: a 16-bit
transaction id, the random letter case of DNS-0x20, and a source port. cocuyo owns no socket, so it
cannot bind a port; it suggests one. **A caller that sends every query from one socket keeps the id
and case entropy and loses the port entropy.**

The parser checks every length against the end of the message before reading, never recurses, and
never trusts a count field: a sender's claim of how many records follow is checked, not obeyed. A
datagram that does not match never disturbs the lookup waiting for the real one.

Every check has a test, and every test is proved by breaking the check on purpose and confirming the
test fails. [`docs/mutations.md`](docs/mutations.md) records each mutation and the test that caught
it.

## Performance

Measured on 2026-09-22 on an Apple M1 Pro with 32 GiB under macOS 26.6.2, Zig 0.16.0, ReleaseSafe
with assertions on. [`docs/design.md`](docs/design.md) §11 has the method and every row.

Per operation, cocuyo against c-ares 1.34.8's shipping build, in nanoseconds:

| Operation | cocuyo | c-ares |
| --- | --- | --- |
| Build a query for `example.com` with EDNS0 | 7.7 | 958.4 |
| Parse a response with one A record | 49.3 | 693.4 |
| Parse a CNAME and its A record | 185.1 | 1,084.1 |
| Parse 17 A records | 583.5 | 4,157.7 |

The difference is the record model, not the arithmetic: c-ares builds and frees heap objects per
message, and cocuyo copies into memory you sized once. Against a network round trip of a
millisecond, neither cost is one a user would notice.

End to end, both stacks resolve 20,000 distinct names against one responder on the loopback,
cocuyo through its event-loop engine and c-ares through its own event thread:

| In flight | cocuyo lookups/s | c-ares lookups/s | cocuyo p99 | c-ares p99 |
| --- | --- | --- | --- | --- |
| 1 | 45,199 | 36,304 | 78 µs | 42 µs |
| 16 | 110,194 | 87,306 | 409 µs | 272 µs |
| 128 | 122,089 | 82,554 | 1,724 µs | 2,038 µs |

cocuyo does 1.24 to 1.48 times the lookups per second, with a lower median latency in every row.
c-ares has the better 99th percentile at one and sixteen in flight. That gap is under investigation
and is not yet explained.

The cache, replayed over a real ISP's DNS log of 28 million questions: at its default of 1,024
entries, a cache per client answers 49% to 60% of questions without a packet. The range is the
TTLs, which the log does not carry and the replay assigns two ways. Either way the cache is at
most 2 points under the best any eviction policy could do with the same memory, which is why it
uses SIEVE and not something more complex. The replay and its source are in
[`bench/README.md`](bench/README.md).

## Compared with c-ares

cocuyo covers what c-ares does as a DNS client: every record type it parses, its configuration
options, cookies, failover, the hosts file and a cache. What it does not cover, today:

- **The platform's own configuration.** c-ares also reads the macOS system configuration, the
  Windows registry and Android's settings. cocuyo reads `resolv.conf` alone.
- **A ready-made event loop.** c-ares ships one. cocuyo's engine over the rotor event loop exists
  and is tested, with one reused TCP connection per server, but it is not exported yet. Until it
  is, you drive the library yourself, as the examples do.
- **A C interface.** cocuyo is a Zig library. There is no C header.
- **Windows.** The library does no I/O of its own, so it depends on no platform; the engine runs
  on macOS and Linux.
- **Binding sockets to a network device by name.**

## What it will not do

These are out of scope on purpose. Each has a place it would attach if that changes.

- **DNSSEC validation.** EDNS0 is in place and records are handed out as read, so a validator can
  sit above the library.
- **DNS over TLS or HTTPS.** You own the socket, so TLS is yours to add over the TCP path, which
  already speaks the length-prefixed form DNS over TLS uses.
- **mDNS and zone transfers.** Neither is a stub resolver's job.
- **nsswitch, NIS and internationalised domain names.**

## Build and test

```bash
zig build test
```

That is the gate every change passes: the lint rules, the module-graph check, a build of a package
that depends on cocuyo, and every unit test. Other steps:

| Command | What it does |
| --- | --- |
| `zig build examples` | Build the examples into `zig-out/bin` |
| `zig build example-udp-blocking -- example.com` | Resolve a name over a blocking socket |
| `zig build bench` | The microbenchmarks and the cache replays |
| `zig build bench-cares` | The comparison with the installed c-ares |
| `zig build bench-log -- <dataset.csv>` | The cache over a real DNS log |
| `tools/search_order/run.sh` | The search-list walk against glibc, musl and c-ares |

## Design

[`docs/design.md`](docs/design.md) is the full design: the module graph, the state machine, the
public API, the security rules, the named limits, every measurement with its machine and date, and
the decisions with the alternatives they beat. [`docs/mutations.md`](docs/mutations.md) lists every
check and the test that proves it. The RFCs cocuyo is written from are in [`docs/rfcs/`](docs/rfcs),
unmodified.

## License

Not yet chosen: this repository has no LICENSE file yet.
