# cocuyo

[![CI](https://github.com/c4milo/cocuyo/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/c4milo/cocuyo/actions/workflows/ci.yml)
[![Coverage](https://raw.githubusercontent.com/c4milo/cocuyo/badges/.github/badges/coverage.svg)](https://github.com/c4milo/cocuyo/actions/workflows/ci.yml?query=branch%3Amain)
[![Release](https://img.shields.io/github/v/release/c4milo/cocuyo)](https://github.com/c4milo/cocuyo/releases/latest)
[![License](https://img.shields.io/github/license/c4milo/cocuyo)](LICENSE)

A DNS resolver library for Zig that owns the DNS protocol and none of the I/O.

cocuyo builds queries, reads responses, and decides what to do next. It never opens a socket,
starts a thread, sets a timer or allocates memory. Every function that would block returns a value
naming the I/O it needs, and your program does it: a blocking socket, epoll, kqueue, io_uring, or
any completion loop you already run.

It is written from the RFCs, as a replacement for c-ares. The name is the Colombian word for the
firefly, and for a car's hazard lights.

> **Status: 0.6.0.** The library is feature-complete against its plan. The engine over rotor is
> exported as `cocuyo_rotor`, and carries DNS over TLS, over QUIC and over HTTPS, each with its
> TLS from colibri's `tls`. A question may ask for any record type. It needs Zig 0.16.0.
> Until 1.0, a minor version may change the API.

## Why cocuyo

c-ares does two jobs: the DNS protocol, and owning the sockets it speaks it over. Embedding it means
connecting its event loop to yours through `ARES_OPT_SOCK_STATE_CB` and `ares_process`, and testing
it means a network.

cocuyo does the first job only. That choice gives you four things:

- **It fits your loop.** You send the bytes it hands you and give it the bytes you receive. The same
  library runs under a blocking socket and under io_uring, unchanged.
- **Its memory is yours, sized once.** You hand cocuyo its lookup table and its cache's memory at
  init, sized by a constant or by a number you read at run time. It never allocates, so there is
  no allocator to pass and no out-of-memory path at run time.
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
| Lookups | One question per lookup, for any record type: A, AAAA, PTR, CNAME, NS, SOA, MX, TXT, SRV, NAPTR, TLSA, SVCB, HTTPS, URI, CAA and more read into fields, and every other type, DNSSEC's among them, handed out whole with `Kind.of(code)` |
| Many lookups | `Resolver`, a bounded table of lookups that decides which lookup an incoming datagram belongs to |
| `getaddrinfo` shape | `AddressLookup` joins A and AAAA, the hosts file and the search list, and orders addresses by RFC 6724; `NameLookup` does the reverse |
| Transport | UDP with EDNS0 (RFC 6891) and its fallback, TCP on truncation or by choice (RFC 7766), with the length prefix handled for you |
| Encryption | In the engine: DNS over TLS (RFC 7858, strict as RFC 8310 asks), DNS over QUIC (RFC 9250) and DNS over HTTPS (RFC 8484) on HTTP/3, HTTP/2 or HTTP/1.1, a server known by its name, by SPKI pins, or by both |
| Robustness | Retries with each server's wait set from its measured latency and doubled per pass, rotation, and server failover that tracks failures per server |
| Configuration | `resolv.conf`, `RES_OPTIONS` and `LOCALDOMAIN`, and the hosts file, parsed from bytes you read |
| Cache | Optional, over memory you hand in, sized when you compile or from a number you read at run time, with a TTL cap you set, SIEVE eviction, RFC 2308 negative caching, and a cache of resolution failures (RFC 9520) |
| Security | DNS cookies (RFC 7873), DNS-0x20 case randomisation, a source-port hint, and strict response matching |

The search-list walk has been checked on the wire against glibc 2.39, musl 1.2.5 and c-ares 1.34.8.
cocuyo walks as glibc and c-ares do. The one difference is SERVFAIL: cocuyo stops and reports the
failure, as c-ares does, where glibc moves on to the next search domain and hides it.

## How it works

You own the loop. cocuyo tells you what to do next, and you tell it what happened. This is the
driving loop of [`examples/udp_blocking.zig`](examples/udp_blocking.zig), shortened. `socket`
stands for your own UDP socket, and `clock` for a monotonic clock in nanoseconds:

<!-- readme-check: loop -->
```zig
var servers = cocuyo.Servers.init(&config, seed);
var lookup = cocuyo.Lookup.init(&config, &servers, try cocuyo.Question.from_text(name, .a), seed);
var query: [cocuyo.limits.query_bytes_max]u8 = undefined;

while (true) {
    switch (lookup.poll(clock.read(), &query)) {
        .send_udp => |send| {
            // From a port bound at send.local_port_hint, where the socket allows it.
            try socket.send(send.server, send.message_bytes);
            lookup.on_sent(clock.read());
        },
        .wait => |deadline_ns| {
            // Receive until the deadline, and hand over whatever arrived.
            if (try socket.receive_until(deadline_ns)) |datagram| {
                _ = lookup.on_response(datagram.bytes, datagram.from, clock.read());
            }
        },
        .connect_tcp, .send_tcp => {
            // The answer was truncated: the same exchange over TCP.
        },
        .send_request => {
            // A DoH or DoQ server: an HTTP or a QUIC client carries the bytes, as the engine does.
        },
        .done => |answer| return answer, // addresses, TTL, canonical name
        .failed => |failure| return failure.err,
    }
}
```

When a lookup fails, `failure.err` says how it ended, and `failure.cause` says why a server failed
it. The cause is the last such failure the lookup met. Its `server_index` names the server that
gave it, and its `what` is one of these:

- `.rcode`, a response's code. It is SERVFAIL, REFUSED, NOTIMP or BADVERS, FORMERR to a query
  without EDNS0, or a BADCOOKIE that moves the lookup to the next server.
- `.reason`, the reason that came with `on_tcp_failed` or `on_request_failed`:
  - `connect`: the connect failed.
  - `handshake`: the TLS handshake failed, or over DoQ the QUIC handshake.
  - `local`: no server took part, as when the system refused a socket or each connection slot
    held a lookup.
  - `closed`: a connection that was up failed, or a send on it.
  - `status`: over DoH, a response that holds no DNS message, such as a status that is not 2xx.
  - `reset`: over DoH or DoQ, the server reset the request's stream, or refused it.

The engine passes the reason at each failure it sees. If you own the sockets, pass it yourself.
Each reason fits some calls alone:

- `on_tcp_failed` before `on_tcp_connected`: `connect` or `local`, and `handshake` over TLS alone.
- `on_tcp_failed` after `on_tcp_connected`: `closed` alone.
- `on_request_failed`: any reason, but `connect` and `status` over DoH alone.

A reason that does not fit its call is a programmer error. An assertion stops it, and assertions
stay on in production. When you cannot tell what failed, pass `connect` before `on_tcp_connected`,
`closed` after it, and `closed` for a request (docs/design.md §5, The cause of a failure).

The cause is null when no server failed the lookup. So `AllServersFailed` has a cause when the
lookup sent a query, and `Timeout`, where every try went unanswered, never has one. A failure that
the cache recalls sent no query, so it has no cause (docs/design.md §16 decision 61). Another error can carry a cause too: a
name that does not exist after one server answered SERVFAIL. The examples print it after the
error, as `example.com: AllServersFailed (handshake from server 0)`.

For many lookups at once, `Resolver` does the same with one `poll` for the whole table, one
deadline to arm one timer, and one `on_datagram` call per datagram received. A datagram longer
than the receive buffer arrives cut, and the kernel marks it as truncated. Hand that one to
`on_datagram_cut`: the lookup that it matches asks the same server over TCP (docs/design.md §7).

## An event loop to drive it: rotor

cocuyo works with any loop, and it was built alongside one:
[rotor](https://github.com/c4milo/rotor), a completion-based event loop for Zig by the same author.
rotor runs on io_uring on Linux, falling back to epoll where io_uring is refused, as in a container
under Docker's default security profile, and on kqueue on macOS.

- **One lookup over rotor.** [`examples/udp_rotor.zig`](examples/udp_rotor.zig) drives the same
  lookup as the blocking example, over rotor's loop. It shows the three things a completion loop
  changes: a send is queued and completes later, one receive delivers every datagram, and replies
  arrive in buffers the loop picks. cocuyo cannot tell the two examples apart.

  ```bash
  zig build example-udp-rotor -- example.com
  ```

- **Many lookups over rotor.** The engine in [`io/`](io) runs a whole `Resolver` over rotor: one
  UDP socket per server with source-port rotation, one reused TCP connection per server, one timer
  for every deadline, and a cache in front when you hand it the memory for one
  ([quick start](#quick-start)). It is tested on a deterministic twin of rotor, and end
  to end over rotor itself on macOS and Linux; the throughput comparison with c-ares below runs on
  it. It is exported as the module `cocuyo_rotor`, whose type `Resolver` runs on a loop
  you own: your build binds its `rotor` import to your rotor, and every event your loop hands out
  goes to the engine's `apply` first ([`test/consumer/`](test/consumer) is such a package).
- **One engine for each core.** Each thread runs a loop and an engine of its own, with cache
  memory of its own, and nothing is shared between them but a `Config`, which is only read.
  [`examples/threads_rotor.zig`](examples/threads_rotor.zig) runs two at once, and CI runs it under
  ThreadSanitizer as well.

rotor is optional. cocuyo does not depend on it: a project that depends on cocuyo fetches nothing
else, and only this repository's examples and benchmarks fetch rotor.

## Encrypted transports

The engine carries DNS over TLS, over QUIC and over HTTPS. Each lookup's policy,
failover and cache stay as they are over UDP; what changes is the connection a query goes on.

- **DNS over TLS** (RFC 7858) goes over a TCP connection, with
  [chapulin](https://github.com/c4milo/chapulin)'s TLS 1.3, through
  [colibri](https://github.com/c4milo/colibri)'s `tls` module, as a session behind an interface of
  cocuyo's.
- **DNS over QUIC** (RFC 9250) goes over colibri's QUIC, in the module `cocuyo_quic`, with the
  TLS session your build names (below). This repository's example and its daily checks name
  chapulin's QUIC mode, through colibri's `tls`.
- **DNS over HTTPS** (RFC 8484) goes through colibri's HTTP client, in the module `cocuyo_doh`,
  which tries HTTP/3 over QUIC first, and HTTP/2 or HTTP/1.1 over TCP when QUIC is not answered in
  time. A DoH server is named by its URI template.
- Every server is authenticated, strictly (RFC 8310): by the name its certificate must carry, by
  SPKI pins of its key, or by both. A server that cannot be authenticated is not asked.
- DoQ and DoH over HTTP/3 offer QUIC version 2 beside version 1, and run on version 2 when the
  server switches to it. A ticket from such a connection resumes in version 2.
- Each encrypted transport starts its sessions from a context you hand the engine: `use_tls` for
  DoT, `use_quic` for DoQ, `use_doh` for DoH. A context carries a stream seeded with 32 octets
  from your secure random source. It also carries the roots a named server's chain may end at,
  what you state of your CPU, and the wall clock. DoQ's carries a second stream, for its
  connection IDs, seeded with a second draw of 32 octets. The three examples each build one.
- The call is required, after `init` and before the first lookup that reaches a server of that
  transport. The engine has no context of its own. A lookup started against a DoT, DoQ or DoH
  configuration whose context was never set stops the program at an assertion, in every build.
  `has_context` says whether the engine has the context its configuration needs.
- The engine cannot check the seed, the clock or the statement of the CPU you hand it. `reinit`
  keeps the contexts, and `init` forgets them. A context you hand over again is built from a new
  draw. No context type has a default, so every field of one is written where it is built.
- What you state of your CPU is a `tls.Cpu`, which each context's `init` takes after the
  anchors. It holds what your probe of the CPU found, and the timing mode of the thread that
  drives the engine. colibri reads it to choose the suites of each hello (docs/design.md §16
  decision 48).
- Fill `probe` once, at start, from `platform.probe()` of stdx, at the commit colibri pins. Set
  `timing` to `.data_independent` only for a thread that runs in that mode. On arm64 that thread
  has set PSTATE.DIT. On x86-64 the operating system has set DOITM. Where the probe also found
  the AES instructions, each hello then offers TLS_AES_256_GCM_SHA384 and TLS_AES_128_GCM_SHA256,
  then TLS_CHACHA20_POLY1305_SHA256. Where it did not, each hello offers
  TLS_CHACHA20_POLY1305_SHA256 alone.
- If you cannot state the mode, set `timing` to `.not_stated`. Put your probe beside it, or
  `.not_known` for each of its answers. Each hello then offers TLS_CHACHA20_POLY1305_SHA256
  alone, and a server that holds only AES-GCM refuses it.
- The three examples state nothing by default. The word `cpu`, first on the command line, turns
  the statement on (docs/design.md §16 decision 48):

  ```bash
  zig build example-dot-rotor -- cpu dns.google 8.8.8.8 dns.google gts-root-r1.der gts-root-r4.der
  ```

  With the word, the example probes the CPU once, through stdx's `platform.probe()`. On arm64,
  where the probe found FEAT_DIT, it sets PSTATE.DIT, reads the bit back, and states
  `.data_independent` with its probe. Elsewhere it states nothing, as without the word: on x86-64
  no program can read DOITM. Each example says what it states before its first lookup, and after
  each turn the suite its handshake chose.
- The word is off by default because an example is a model that you copy. A program states
  `.data_independent` only for a thread that it put in that mode itself, and `.not_stated` is
  true of each program. stdx is a dependency of these examples alone. Only cocuyo's own build
  requests it, so a package that depends on cocuyo never fetches it. `zig build graph-check`
  fails when a module of the library reaches stdx, or when a module of the engine reaches it
  other than through colibri.
- cocuyo's library depends on none of them. The engine speaks TLS through a session interface,
  which this repository fills with chapulin's session in colibri's `tls`; QUIC through
  `cocuyo_quic`, whose `quic` import a consumer that speaks DoQ binds to colibri's; and HTTPS
  through `cocuyo_doh`, whose `client` and `tls` imports a consumer that speaks DoH binds to
  colibri's.
- The DoT session to name is `Session` of the module `chapulin`, in the `tls` option of
  `cocuyo_rotor`'s `Resolver`, as `examples/dot_rotor.zig` does. Your build binds colibri's `tls`
  and `tls_provider` into `chapulin`. The session's `io` is `cocuyo_rotor`, into which your build
  binds its rotor. [`test/consumer/build.zig`](test/consumer/build.zig) has the lines, and the
  gate builds that package.
- `cocuyo_quic` takes its TLS as a type, in `Options.Session`, and the option has no default: a
  consumer that names no session does not compile. A session names the QUIC version it started in,
  `original_version`, and the connection starts in it. The session to name is the one over chapulin,
  `Session` of the module `chapulin_quic`, as `examples/doq_rotor.zig` does. Your build binds
  colibri's `quic` and `tls` into `chapulin_quic`, and colibri's `quic` into `cocuyo_quic`.
  [`test/consumer/build.zig`](test/consumer/build.zig) has the lines, and the gate builds that
  package.
- `cocuyo_quic` also exports `plain`, `Plain` and `server`, for tests: a session, the same
  session behind the option's interface, and a DoQ server over it. They encrypt nothing,
  authenticate nobody, and are never for a network.

They are checked every day against public resolvers: Google, Cloudflare and Quad9 over TLS,
AdGuard and NextDNS over QUIC, Google and Cloudflare over HTTPS. Each resolves twice,
the second time over a connection that offers the first one's ticket, and refuses a name its
certificate does not carry and a root its chain does not end at. Over TLS and QUIC a server known
by its key alone resolves, and a wrong pin is refused, and each is asked for AAAA, MX, TXT and
HTTPS records as well as A. Every transport, plain DNS over UDP and TCP among them, also runs every
day against AdGuard's dnsproxy on the loopback, an implementation written elsewhere, for addresses
and for records of those four types and CNAME.

Each of these checks resolves through each encrypted server in two runs: first without the word
`cpu`, then with it. Without the word each handshake must run ChaCha20-Poly1305. With it each must
run AES-GCM on an arm64 host whose system reports the AES instructions, PMULL and FEAT_DIT.
Elsewhere each must run ChaCha20-Poly1305. The one exception is an arm64 Mac whose system hides
one of the three: there each run with the word fails.

## Quick start

Add cocuyo to your package, pinned to a release:

```bash
zig fetch --save "git+https://github.com/c4milo/cocuyo?ref=v0.6.0"
```

Import its module in `build.zig`. The library is one module, `cocuyo`, and fetches nothing else
when it is a dependency. The engine over rotor is a second, `cocuyo_rotor`, whose `rotor` import
your build binds to your rotor. Ask rotor for its release build as you ask cocuyo: a rotor asked
for no mode builds Debug, whatever mode your program builds in.

<!-- readme-check: build -->
```zig
const cocuyo = b.dependency("cocuyo", .{ .target = target, .release = true });
exe.root_module.addImport("cocuyo", cocuyo.module("cocuyo"));

// Only for the engine, over a rotor your build already depends on.
const engine = cocuyo.module("cocuyo_rotor");
const rotor = b.dependency("rotor", .{ .target = target, .release = true });
engine.addImport("rotor", rotor.module("rotor"));
exe.root_module.addImport("cocuyo_rotor", engine);
```

Then give it its memory and ask it for its first action. `config`, `seed` and `now_ns` are yours:
a `Config` from `cocuyo.resolv_conf.parse` or built by hand, a seed from a secure random source, and
a monotonic clock in nanoseconds. A `Config` built by hand that sets `timeout_ns`, a server's wait
until it has been measured, above 5 seconds raises `timeout_ns_max` as far, since that cap on every
wait defaults to 5 seconds.

<!-- readme-check: quick-start -->
```zig
const cocuyo = @import("cocuyo");

var slots: [64]cocuyo.Slot = @splat(.{});
var keys: [256]cocuyo.MatchKey = @splat(.{});
var cache_memory: cocuyo.cache.Storage(1024) = undefined; // 1,024 slots and their key index

const cap_seconds = config.cache_ttl_seconds_max; // no answer is kept longer: an hour by default
var store = cocuyo.Cache.init(&cache_memory.slots, &cache_memory.keys, seed, cap_seconds);
var table = cocuyo.Resolver.init(&slots, &keys, &config, seed);
table.remember_with(cocuyo.remembered_by(&store)); // optional: the cache under every lookup

_ = try table.start(try cocuyo.Question.from_text("example.com.", .a));
var query: [cocuyo.limits.query_bytes_max]u8 = undefined;
const event = table.poll(now_ns, &query).?; // event.action is .send_udp: the bytes, and where
```

The engine, `cocuyo_rotor`, takes the cache's memory the same way, at `init` and again at `reinit`,
and builds the cache itself. Hand it `null` and it has no cache: every lookup goes to its servers.
`loop` is your `rotor.Loop`, and `allocator` and `slot_count` stand for wherever your memory and
your configuration come from:

<!-- readme-check: engine -->
```zig
const cocuyo = @import("cocuyo");
const dns = @import("cocuyo_rotor");

const Resolver = dns.Resolver(.{});
var resolver: Resolver = undefined;
// A size known when you compile: 1,024 slots, the size measured below, 2.9 MiB.
var cache_memory: cocuyo.cache.Storage(dns.constants.cache_slots_default) = undefined;
try resolver.init(&loop, &config, cache_memory.slices(), seed, now_ns);

// A size read at run time, handed over at a `reinit`. The engine must be idle.
if (!cocuyo.cache.slot_count_valid(slot_count)) return error.CacheSlotsOutOfRange;
const entries = try allocator.alloc(cocuyo.cache.Slot, slot_count);
const index = try allocator.alloc(cocuyo.cache.Key, cocuyo.cache.keys_for(slot_count));
try resolver.reinit(&config, .{ .slots = entries, .keys = index }, new_seed, now_ns);
```

A cache takes 1 to 16,384 slots, 2,984 octets each, and `cocuyo.cache.keys_for` gives the key
index a slot count needs. The memory must stay valid, and where it is, until the engine's `close`,
or until a `reinit` hands the engine other memory or none. A `reinit` that fails at its sockets has
still taken the memory it was handed. So never free that memory on that error: hand it to the next
`reinit`, or keep it until `close`. Each engine has its own. The cache keeps no answer longer than
`Config.cache_ttl_seconds_max`, an hour unless you set it and seven days at most, the cap
RFC 8767 §4 recommends; `cocuyo.cache.ttl_seconds_max_valid` says whether a cap you read at run
time is one a cache takes. cocuyo never reads the cap from a `resolv.conf`, which has no line for
it.

The engine receives each datagram into a buffer that holds 1,856 octets of it,
`dns.limits.udp_payload_bytes_max`. So `init` and `reinit` refuse a `Config.udp_payload_bytes`
above it with `error.UdpPayloadTooLarge`, as RFC 6891 §6.2.3 asks. Such a call changes nothing. A
refused `reinit` keeps the memory it held, so do not free that memory on this error. The memory you
handed it is yours again. The default, 1,232, fits.

[`examples/`](examples) holds complete programs that resolve real names against real servers: one
lookup over a blocking UDP socket, the same over [rotor](#an-event-loop-to-drive-it-rotor), and the
engine over plain DNS, DNS over TLS, over QUIC and over HTTPS. The
[build and test](#build-and-test) table has the command for each.

> **The seed must come from a cryptographically secure random source, never from the clock.**
> cocuyo draws the transaction id, the source-port hint, the DNS-0x20 case pattern and the DNS
> client cookie from it. A guessable seed makes a guessable query, and a guessable query can be
> spoofed.

## Security

cocuyo parses unauthenticated input from the network. A response is considered only if all of these
hold, checked in this order:

1. Its length is between the 12-octet header and the largest message allowed.
2. Its transaction id is the one sent.
3. It came from the address and port the query went to.
4. It is a response to a standard query.
5. Its question is byte-identical to the one sent, letter case included.
6. Its DNS cookie matches the one its query carried, when it carried one (RFC 7873).

Only then is the answer read. Three sources of entropy defend each query against spoofing: a 16-bit
transaction id, the random letter case of DNS-0x20, and a source port. cocuyo owns no socket, so it
cannot bind a port; it suggests one. **A caller that sends every query from one socket keeps the id
and case entropy and loses the port entropy.**

Some servers and forwarders echo the name in lowercase. The first such reply is still ignored, and
the lookup it answers waits out its deadline. That try is no sample of the server's latency, so
the server's wait does not rise for it. From then on that server is asked for every name in
lowercase, without the random case, until the engine's `reinit`, or a new `Servers` table for a
caller driving lookups alone. Every other server keeps it. A server that changes the case any
other way cannot be told from an echo of another query, and needs `Config.mix_case` off.

A query carries a client cookie of its own until the server answers it with a server cookie; from
then on it carries the two together. A server that answers without cookies is sent none for five
minutes, then a fresh client cookie (RFC 9018 §3). cocuyo does not see a change of your address:
it binds no socket. **When your address changes, call the engine's `reinit`, or build a new
`Servers` table, with a new seed from a CSPRNG.** The seed must be new: given the same one,
`reinit` draws the same fresh client cookies again, cookies those servers have already seen,
which RFC 9018 §3 and §8.1 forbid. `reinit` needs the engine idle, so call `cancel_all` and take
the failures first. Either way every server cookie is forgotten, so no cookie outlives the
address it was used from, as RFC 9018 §3 requires.

The parser checks every length against the end of the message before reading, never recurses, and
never trusts a count field: a sender's claim of how many records follow is checked, not obeyed. A
datagram that does not match never disturbs the lookup waiting for the real one.

Every check has a test, and every test is proved by breaking the check on purpose and confirming the
test fails. [`docs/mutations.md`](docs/mutations.md) records each mutation and the test that caught
it.

## How it is checked

Every claim above has a check behind it, and each check is itself broken on purpose to show it
catches what it should.

- **Proofs of the lookup.** The state machine of design §5 is a Lean 4 model with proofs: a lookup
  that has ended stays ended, under `use_tcp` no event leads to a datagram, a server that refused
  never turns into a timeout, and no sequence of answers makes a lookup send forever. Every
  transition the model reaches is replayed against the Zig code. [`spec/README.md`](spec/README.md)
  lists the theorems and the axioms each one rests on.
- **A model of the engine.** The engine's rules are a TLA+ model. TLC checks its invariants over
  every state of small configurations and rejects each mutant of the model, and 24,000 of TLC's
  walks are replayed against the engine on a deterministic twin of rotor.
- **Mutation.** Every check has a test that fails when the check is broken.
  [`docs/mutations.md`](docs/mutations.md) records each mutation and what caught it.
- **Fuzzing.** The codec's fuzz target writes a well-formed record of every type, whole or with one
  octet changed, and a record written whole must be read whole.
- **Other implementations.** Every record of 66 responses real servers sent is compared with
  dnslib's reading of it. The search-list walk was compared on the wire with glibc, musl and c-ares.
  Every transport runs each day against AdGuard's dnsproxy on the loopback, and the encrypted ones
  against public resolvers.
- **Threads.** Two engines on two threads of one image run under ThreadSanitizer in CI.
- **Coverage.** kcov runs every module's tests in CI, and the badge above is the share of the
  library's and the engine's lines they run, test code left out (`zig build coverage`).

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
c-ares has the better 99th percentile at one and sixteen in flight in this table. At one in flight
that was the order of the runs: cocuyo ran first and paid for the process's first 20 milliseconds,
the responder's thread and the cores coming up to speed. Warm, its p99 there is 57 to 64
microseconds, and the comparison now warms up before its first row; the table stands until a
quiet machine measures it again (docs/design.md §11). The two also spend memory differently: c-ares allocates a heap object for
each message and each record, and cocuyo holds only the memory its caller sized at init, so what it
uses cannot grow with the load.

The cache, replayed over a real ISP's DNS log of 28 million questions: at 1,024 entries, the size
the quick start declares, a cache per client answers 49% to 60% of questions without a packet.
The range is the TTLs, which the log does not carry and the replay assigns two ways. Either way
the cache is at most 2 points under the best any eviction policy could do with the same memory,
which is why it uses SIEVE and not something more complex. The replay and its source are in
[`bench/README.md`](bench/README.md).

## Compared with c-ares

cocuyo covers what c-ares does as a DNS client: every record type it parses, its configuration
options, cookies, failover, the hosts file and a cache.

The cache is where a c-ares user meets a difference. c-ares's query cache is on unless
`ARES_OPT_QUERY_CACHE` turns it off with a TTL of zero, and `ares_init_options(3)` gives it a cap
on the TTL and no size. cocuyo's holds the slots you hand it and no more, and the engine has no
cache until you hand it the memory for one. Its cap on a TTL is `Config.cache_ttl_seconds_max`,
an hour by default as c-ares's `qcache_max_ttl` is, and a cap of zero is refused: no memory is how
the cache is off. A `qcache_max_ttl` of zero in a configuration you port is yours to turn into
`null` memory before it reaches a `Config`, whose `assert_valid` stops the program on it.

What it does not cover, today:

- **The platform's own configuration.** c-ares also reads the macOS system configuration, the
  Windows registry and Android's settings. cocuyo reads `resolv.conf` alone.
- **A ready-made event loop.** c-ares ships one. cocuyo's engine runs on
  [rotor](#an-event-loop-to-drive-it-rotor), a loop you own, and `cocuyo_rotor` joins it to yours.
- **A C interface.** cocuyo is a Zig library. There is no C header.
- **Windows.** The library does no I/O of its own, so it depends on no platform; the engine runs
  on macOS and Linux.
- **Binding sockets to a network device by name.**

## What it will not do

These are out of scope on purpose. Each has a place it would attach if that changes.

- **DNSSEC validation.** EDNS0 is in place, and a question may ask for DNSKEY, DS or RRSIG, whose
  records are handed out as read, so a validator can sit above the library.
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
| `zig build example-udp-rotor -- example.com` | Resolve a name over rotor's event loop |
| `zig build example-threads-rotor` | Two engines on two threads, each on its own loop |
| `zig build example-cleartext-rotor -- <name> <server>[:<port>] [udp \| tcp]` | Resolve over plain DNS through the engine |
| `zig build example-dot-rotor -- [cpu] ...` | Resolve over DNS over TLS |
| `zig build example-doq-rotor -- [cpu] ...` | Resolve over DNS over QUIC |
| `zig build example-doh-rotor -- [cpu] ...` | Resolve over DNS over HTTPS |
| `tools/dot_live/run.sh`, `tools/doq_live/run.sh`, `tools/doh_live/run.sh` | The live checks against public resolvers |
| `tools/interop/run.sh` | Every transport against dnsproxy on the loopback |
| `tools/dnslib/run.sh` | The codec against dnslib's reading of real responses |
| `zig build spec`, `zig build tla` | The Lean proofs and every replay, and TLC over the engine model |
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

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) states the bar a change meets and the workflow. Report a
vulnerability privately, as [SECURITY.md](SECURITY.md) says, never in a public issue.
[`docs/landscape.md`](docs/landscape.md) surveys the other DNS resolver libraries, with sources, and
says where cocuyo is weaker than each.

## License

cocuyo is licensed under the [Apache License, Version 2.0](LICENSE).
