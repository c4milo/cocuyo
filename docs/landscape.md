# DNS resolver libraries (surveyed 2026-09-26)

Why cocuyo exists: no other DNS client surveyed here has these four properties at once.

- **No I/O.** It opens no socket, starts no thread and arms no timer, and it calls no function
  that does. Every step that would wait returns a value naming the I/O it wants. The time and the
  randomness come in as arguments.
- **No allocation.** The caller hands it all of its memory once, at init.
- **A whole stub resolver.** It keeps the search list, CNAME chains, retries, server failover and
  the fallback to TCP, not only the encoding and decoding of messages.
- **A machine-checked model.** A model of its lookup state machine, with proofs, is replayed
  against its code.

Each project below has at most two of them.

## Terms

- A **stub resolver** sends each question to a recursive resolver and reads the answer. It does
  not walk the DNS tree from the root itself.
- A **sans-I/O** library takes the bytes received and the current time as arguments, and returns
  the bytes to send and the next deadline. The caller owns every socket, thread and timer.
- **DoT** is DNS over TLS (RFC 7858), **DoH** is DNS over HTTPS (RFC 8484), and **DoQ** is DNS
  over QUIC (RFC 9250).
- **DNSSEC validation** checks the signatures on an answer up to a trust anchor. A resolver that
  passes on the AD bit another resolver set does not validate.

## How this was surveyed

Every fact about another project comes from its own documentation, manual pages, release notes,
changelog or repository page, and links to it. No other implementation's source code was read,
as cocuyo's rules require of its code ([CLAUDE.md](../CLAUDE.md), non-negotiable 8). Where the
sources do not say something, this page says so. A release date is the one on the linked release
page or download directory.

## C libraries that own their sockets

**c-ares** (MIT, C; [c-ares.org](https://c-ares.org/)). A stub resolver with asynchronous
queries, and the library cocuyo replaces. It runs its I/O in one of three ways:

- Since 1.26.0 it can run an event thread of its own
  ([`ares_init_options`](https://c-ares.org/docs/ares_init_options.html)).
- Without the thread, the caller's loop watches the sockets c-ares opens and hands their events
  to `ares_process_fds`, added in 1.34.0
  ([`ares_process`](https://c-ares.org/docs/ares_process.html)).
- `ares_set_socket_functions_ex`, also 1.34.0, lets the caller replace the socket calls with a
  transport of its own
  ([`ares_set_socket_functions`](https://c-ares.org/docs/ares_set_socket_functions.html)).

It allocates: `ares_library_init_mem` swaps in the caller's `malloc`, `free` and `realloc`
([`ares_library_init`](https://c-ares.org/docs/ares_library_init.html)). Its query cache has been
on by default since 1.31.0, with a one-hour ceiling
([`ares_init_options`](https://c-ares.org/docs/ares_init_options.html)). It randomises the case of
the query name (DNS-0x20), sends DNS cookies (RFC 7873, RFC 9018), orders servers by their
failures, and watches the system configuration on Windows, macOS, iOS and systems that use
`resolv.conf` ([features](https://c-ares.org/features/)). It reads and writes DNSSEC records and
does not validate them ([c-ares.org](https://c-ares.org/)). Its feature list names no encrypted
transport. OSS-Fuzz fuzzes it continuously, and static and dynamic analysers check it
([README](https://github.com/c-ares/c-ares)). It runs on Linux, FreeBSD, OpenBSD, macOS, Solaris,
AIX, Windows, Android and iOS ([c-ares.org](https://c-ares.org/)). The latest release is 1.34.8 of
2026-07-07. The release before it, 1.34.7, fixed a use-after-free over TCP (CVE-2026-33630), CPU
exhaustion through unbounded chains of compression pointers, and memory amplification through
record counts it did not check ([releases](https://github.com/c-ares/c-ares/releases)).

**getdns** (BSD-3-Clause, C; [getdnsapi.net](https://getdnsapi.net/)). An implementation of the
getdns API, an interface for application developers with DNSSEC in view. The specification
requires an event base, set through an extension, before any asynchronous call, and requires
synchronous calls to work without one ([spec](https://getdnsapi.net/documentation/spec/)). The
implementation ships extensions for libevent, libuv and libev, each a shared library of its own
([README](https://github.com/getdnsapi/getdns)). It allocates, and takes the caller's memory
functions through `getdns_context_create_with_memory_functions`
([spec](https://getdnsapi.net/documentation/spec/)). Its transports are UDP, TCP and TLS, tried in
an order the caller sets ([spec](https://getdnsapi.net/documentation/spec/)). Stubby, built from
the same tree, is a stub resolver that sends queries over TLS
([README](https://github.com/getdnsapi/getdns)). getdns validates DNSSEC and reports the result
for each record ([spec](https://getdnsapi.net/documentation/spec/)). It runs as a stub, or as a
recursive resolver through libunbound ([README](https://github.com/getdnsapi/getdns)). The latest
release is 1.7.3 of 2022-12-22 ([releases](https://github.com/getdnsapi/getdns/releases)), and
the last commit on its `develop` branch is of 2023-01-09
([commits](https://github.com/getdnsapi/getdns/commits/develop)).

**libunbound** (BSD-3-Clause, C; [Unbound](https://nlnetlabs.nl/projects/unbound/about/)). The
library of Unbound, which NLnet Labs describes as a validating, recursive, caching resolver. In
asynchronous mode it starts a thread, or forks a process, to do the work. The caller watches one
descriptor from `ub_fd` and calls `ub_process` when it is readable. Results are allocated, and
`ub_resolve_free` releases them. Each result says whether DNSSEC proved it secure or bogus,
against trust anchors the caller adds. It can forward to a resolver over DoT with
`ub_ctx_set_tls`
([libunbound(3)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/libunbound.html)).
Unbound serves DoH and DoQ to its own clients, and its manual names TLS alone for queries it sends
([unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)).
Unbound is in OSS-Fuzz, and an issue of May 2025 puts its fuzzing coverage near 9%
([#1288](https://github.com/NLnetLabs/unbound/issues/1288)). X41 D-Sec audited its source in 2019
([report][x41]). The latest release is 1.26.1 of 2026-09-16
([download](https://nlnetlabs.nl/projects/unbound/download/)).

**ldns** (BSD-3-Clause, C; [about](https://www.nlnetlabs.nl/projects/ldns/about/)). A library
for DNS programming in C, covering the low-level operations of DNS and DNSSEC. Its resolver sends
a query to a server and returns the reply, and its documentation describes no asynchronous
interface ([resolver](https://nlnetlabs.nl/documentation/ldns/resolver_8h.html)). Its parser does
no I/O, and allocates the packet it returns, which `ldns_pkt_free` releases
([`ldns_wire2pkt`](https://nlnetlabs.nl/documentation/ldns/wire2host_8h.html)). It has been in
maintenance mode since 2020, with basic maintenance and bug fixes only
([about](https://www.nlnetlabs.nl/projects/ldns/about/)). The latest release is 1.9.2 of
2026-06-10 ([download](https://www.nlnetlabs.nl/projects/ldns/download/)).

**udns** (LGPL, C; [udns](https://www.corpit.ru/mjt/udns.html)). A stub resolver with
synchronous and asynchronous queries. It uses one UDP socket for every query and every server, so
the caller's loop watches one descriptor. The caller calls `dns_ioevent` when it is readable and
`dns_timeouts` for the deadlines ([udns(3)](https://www.corpit.ru/mjt/udns/udns.3.html)). It
speaks UDP only, with EDNS0, and never falls back to TCP. It allocates its query objects and
result buffers with `malloc` ([udns](https://www.corpit.ru/mjt/udns.html)). The latest release is
0.6 of 2024-07-26.

**adns** (GPL-3.0-or-later, C; [adns](https://www.chiark.greenend.org.uk/~ian/adns/)). GNU adns
runs many queries at once without blocking, falls back to TCP for long replies, keeps no global
state, and reads `resolv.conf`. Its interface is documented only in the comments of its C
header, which this survey does not read, so how a caller drives its I/O is not described here.
Its download directory lists 1.7.0 of 2026-09-11
([releases](https://www.chiark.greenend.org.uk/~ian/adns/ftp/)).

**dns.c** (MIT, C; [dns.c](https://25thandclement.com/~william/projects/dns.c.html)). One C file
with no dependencies, with stub and recursive modes. It uses no callbacks: each resolver object
offers `pollfd`, `events` and `timeout`, so any event loop can wait on it. It randomises source
ports, encrypts transaction ids with a 16-bit Feistel cipher, and lets the user name the entropy
source. DNSSEC is on its to-do list. The last tag is `rel-20150630`, of 2015-06-30.

**libasr** (ISC-style, C; [asr_run(3)](https://man.openbsd.org/asr_run.3)). OpenBSD's
asynchronous resolver, and the nearest shape to cocuyo's among the C libraries. `asr_run` never
blocks. When it cannot go on, it returns and names the descriptor, whether it waits to read or to
write, and how many milliseconds to wait, and the caller calls it again when that holds or the
time runs out. It opens the descriptor itself, and the caller frees the results it hands back
([asr_run(3)](https://man.openbsd.org/asr_run.3)). The manual does not mention DNSSEC or
encrypted transports. The portable release was archived on 2023-06-22, and is maintained inside
OpenSMTPD and OpenBSD instead ([libasr](https://github.com/OpenSMTPD/libasr),
[licence](https://github.com/OpenSMTPD/libasr/blob/master/LICENCE)).

## The C libraries' own resolvers

**glibc** (GNU LGPL, C; [glibc](https://www.gnu.org/software/libc/)). `getaddrinfo` returns when
it has the answer, in a list it allocates and `freeaddrinfo` releases
([getaddrinfo(3)](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html)). `res_query` and
`res_search` send a query and wait for the response
([resolver(3)](https://man7.org/linux/man-pages/man3/resolver.3.html)). `getaddrinfo_a`, since
glibc 2.2.3, runs lookups in the background and reports each one that completes by a signal,
by a function started as a new thread, or through polling
([getaddrinfo_a(3)](https://man7.org/linux/man-pages/man3/getaddrinfo_a.3.html)). It does not
validate DNSSEC. Since 2.31 the `trust-ad` option keeps the AD bit a validating resolver set, for
a system that trusts that resolver and the path to it
([resolv.conf(5)](https://man7.org/linux/man-pages/man5/resolv.conf.5.html)). `getaddrinfo` goes
through the Name Service Switch, which is how systemd-resolved answers it
([systemd-resolved(8)](https://man7.org/linux/man-pages/man8/systemd-resolved.service.8.html)).
These manuals name no encrypted transport. The latest release is 2.44 of 2026-07-25
([glibc](https://sourceware.org/glibc/)).

**musl** (MIT, C; [musl](https://musl.libc.org/about.html)). musl sends each query to every
configured nameserver at once and takes the first answer. It tries a name with at least `ndots`
dots only as it is, never with the search list
([functional differences](https://wiki.musl-libc.org/functional-differences-from-glibc.html)).
It gained TCP fallback in 1.2.4, in 2023 ([releases](https://musl.libc.org/releases.html)).
cocuyo's own measurement found that musl stops the search walk at NODATA, and asks a server that
answered SERVFAIL three times ([design §5](design.md#search-list-policy)). The sources read do not
mention DNSSEC validation or encrypted transports. The latest release is 1.2.6 of 2026-03-20
([releases](https://musl.libc.org/releases.html)).

## Resolvers in other languages

**Go's `net`** (BSD-3-Clause, Go; [license](https://go.dev/LICENSE)). On Unix, Go has a resolver
of its own that reads `/etc/resolv.conf` and sends queries itself, and a cgo resolver that calls
`getaddrinfo`. It prefers its own, because a blocked query then costs a goroutine and not an
operating system thread. When cgo is available, it uses the cgo resolver on macOS, and wherever
`resolv.conf` or `nsswitch.conf` asks for something it does not implement. `Resolver.Dial` lets
the caller supply the connection each query goes over ([`net`](https://pkg.go.dev/net)). Go
collects garbage ([FAQ](https://go.dev/doc/faq#garbage_collection)). The package documentation
names no encrypted transport and no DNSSEC validation. The latest release is go1.27.1 of 2026-09-01
([release history](https://go.dev/doc/devel/release)). Apart from `net`,
[`golang.org/x/net/dns/dnsmessage`](https://pkg.go.dev/golang.org/x/net/dns/dnsmessage) packs and
unpacks messages through a `Parser` and a `Builder`, and is written to keep heap allocation low.
Its documentation describes a message codec, not lookups.

**hickory-resolver** (MIT OR Apache-2.0, Rust; formerly trust-dns). A resolver that runs in the
process and does not use the host's resolver. It needs a Tokio runtime, which its documentation
passes as `TokioRuntimeProvider`. Optional features add DoT, DoH on HTTP/2, DoQ and DoH on HTTP/3
([docs.rs](https://docs.rs/hickory-resolver/latest/hickory_resolver/),
[feature names](https://docs.rs/crate/hickory-resolver/latest/features)). With `dnssec-ring` or
`dnssec-aws-lc-rs` it validates DNSKEY and DS records up to a root key it bundles
([README](https://github.com/hickory-dns/hickory-dns)). Its `system_conf` module reads the host's
configuration, `/etc/resolv.conf` on most Unixes
([`system_conf`](https://docs.rs/hickory-resolver/latest/hickory_resolver/system_conf/index.html)).
Its mDNS support is experimental. X41 D-Sec audited Hickory DNS for OSTIF in autumn 2024, the
resolver library included, and reported four findings with security impact, two medium and two
low ([OSTIF](https://ostif.org/hickorydns-audit-complete/)). A post from ISRG's Prossimo of
February 2025 reports initial production use of its client and stub resolver, and a conformance
suite that runs it beside other DNS implementations in a virtual network
([Prossimo](https://www.memorysafety.org/blog/hickory-update-2025/)). The latest release is
0.26.3 of 2026-09-10 ([releases](https://github.com/hickory-dns/hickory-dns/releases)).

**domain** (BSD-3-Clause, Rust; NLnet Labs). Building blocks for DNS. The `base` and `rdata`
modules, which hold the message and record types, are always enabled. The `resolv` module is
an asynchronous stub resolver on Tokio, with a synchronous version behind `resolv-sync`. Its
types can take `heapless` vectors as their octet sequences
([docs.rs](https://docs.rs/domain/latest/domain/)). The `net::client` module carries
messages over UDP, over a stream that is "typically TCP or TLS", and over combinations of them.
A transport runs as a task the caller spawns. Its datagram transport sends no DNS cookies, and
its stream transport puts no limit on attempts to connect
([`net::client`](https://docs.rs/domain/latest/domain/net/client/index.html)). Its DNSSEC
validator is behind the `unstable-validator` flag
([docs.rs](https://docs.rs/domain/latest/domain/)). The latest release is 0.12.3 of 2026-09-25
([releases](https://github.com/NLnetLabs/domain/releases)).

**ocaml-dns's `dns-client`** (BSD-2-Clause, OCaml;
[ocaml-dns](https://github.com/mirage/ocaml-dns)). Of the libraries found, its split is the
nearest to cocuyo's. Its `Pure` module builds a query from a name, a type and a random function
the caller passes, and checks a response against the state the query left, with no I/O
([`Pure`](https://mirage.github.io/ocaml-dns/dns-client/Dns_client/Pure/index.html)). A functor
runs it over a module the caller supplies: a random function, a monotonic clock, `connect` and
`send_recv`, with one time budget shared by connecting and asking
([`S`](https://mirage.github.io/ocaml-dns/dns-client/Dns_client/module-type-S/index.html)).
There are backends for Lwt, MirageOS, Unix and Miou
([README](https://github.com/mirage/ocaml-dns)). The client speaks DoT, and DNSSEC validation is
a separate `dnssec` package ([CHANGES](https://github.com/mirage/ocaml-dns/blob/main/CHANGES.md)).
OCaml collects garbage ([OCaml docs](https://ocaml.org/docs/garbage-collector)). The latest
release is 10.2.6 of 2026-09-13
([CHANGES](https://github.com/mirage/ocaml-dns/blob/main/CHANGES.md)).

## A system service

**systemd-resolved** (LGPL-2.1-or-later, C; [systemd](https://github.com/systemd/systemd)). A
system service, not a library. Programs reach it through D-Bus, through Varlink, through glibc's
NSS module `nss-resolve`, or as a DNS server on 127.0.0.53. It sends each lookup to the servers of
the links whose search and route-only domains match it, and it also resolves by LLMNR and
multicast DNS
([systemd-resolved(8)](https://man7.org/linux/man-pages/man8/systemd-resolved.service.8.html)).
With `DNSSEC=` true it validates every lookup locally. With `allow-downgrade` it turns validation
off for a server that does not support DNSSEC, which the manual says leaves it open to downgrade
attacks. `DNSOverTLS=` is strict when true, or opportunistic
([resolved.conf(5)](https://man7.org/linux/man-pages/man5/resolved.conf.5.html)). The manual
names no DoH or DoQ setting. The latest release is v262 of 2026-09-22
([release](https://github.com/systemd/systemd/releases/tag/v262)). On Linux, a cocuyo caller often
talks to it through that server on 127.0.0.53
([README](../README.md#when-to-choose-it-and-when-not-to)).

## Zig

**The standard library of Zig 0.16** (MIT;
[LICENSE](https://codeberg.org/ziglang/zig/src/branch/master/LICENSE)). Since 0.16.0 every I/O
call takes an `Io` instance, and every networking API goes through it. The release notes' HTTP
example sends DNS queries to every configured nameserver at once, connects to each address as it
arrives, and cancels the other queries and connections after the first one succeeds. Of the `Io`
implementations, `Io.Threaded` is complete, and `Io.Evented` and the io_uring one do not yet
implement networking
([release notes](https://ziglang.org/download/0.16.0/release-notes.html)). The notes do not say
which record types, transports or configuration sources the resolver supports, or how it
allocates, and this survey does not read the standard library's source. Zig 0.16.0 was released
on 2026-04-13 ([download](https://ziglang.org/download/)).

**Community libraries.** Three more Zig DNS libraries were found. All three are MIT, and all
three take an allocator:

- zigdig calls itself naive. It builds and reads messages, reads `resolv.conf`, and has a helper
  that connects to the system's resolver. It has no EDNS0, does not follow CNAMEs, and names Zig
  0.14.0 ([zigdig](https://github.com/lun-4/zigdig)).
- zig-dns calls itself experimental. It builds and reads messages, and its command-line example
  sends them with zig-network ([zig-dns](https://github.com/dantecatalfamo/zig-dns)).
- milo-g's zigdns builds and reads messages, and does not yet encode compressed names or EDNS
  records ([zigdns](https://github.com/milo-g/zigdns)).

## Sans-I/O and allocation-free DNS code

**dns-protocol** (MIT OR Apache-2.0, Rust). It describes itself as the DNS protocol "sans I/O":
`no_std`, with no allocator, working in buffers the caller provides
([docs.rs](https://docs.rs/dns-protocol/latest/dns_protocol/)). Its documentation describes a
message codec, and its example sends the bytes over a socket the caller opened. The latest
release is 0.1.2 of 2024-06-12 ([crates.io](https://crates.io/crates/dns-protocol)), and the
repository that holds it is archived ([async-dns](https://github.com/notgull/async-dns)).

**SPCDNS** (LGPL-3.0, C; [SPCDNS](https://github.com/spc476/SPCDNS)). An encoder and decoder of
30 record types. `dns_encode` and `dns_decode` allocate nothing and use the memory they are
given. Its author says it is not a general-purpose resolver, and the query code it ships is
simple and UDP only ([README](https://github.com/spc476/SPCDNS)). Its last tag is v2.1.3, and its
last commit is of 2024-06-26 ([commits](https://github.com/spc476/SPCDNS/commits/master)).

**mdns-proto** (MIT OR Apache-2.0, Rust). Sans-I/O state machines for multicast DNS (RFC 6762)
and DNS-SD (RFC 6763). The caller feeds datagrams and timer ticks in and takes datagrams out.
Without an allocator it only parses; building messages needs the `alloc` tier
([docs.rs](https://docs.rs/mdns-proto/latest/mdns_proto/)). It applies the sans-I/O shape to
multicast DNS, not to unicast lookups. The latest release is 0.3.0 of 2026-06-18
([crates.io](https://crates.io/crates/mdns-proto)).

## Embedded stacks

**lwIP's DNS client** (BSD, C; [lwIP](https://www.nongnu.org/lwip/2_1_x/index.html)). Part of
the lwIP TCP/IP stack, and called only from its TCP/IP thread. `dns_gethostbyname` answers at
once from a table of names already resolved, or returns `ERR_INPROGRESS` and calls the caller's
function when the answer comes. It resolves addresses, and names under `.local` by one-shot
multicast DNS only ([DNS](https://www.nongnu.org/lwip/2_1_x/group__dns.html)). The page does not
say how it holds its memory. The latest release is 2.2.1 of 2025-02-06
([download](https://download.savannah.nongnu.org/releases/lwip/)).

**Zephyr's DNS resolver** (Apache-2.0, C; [DNS Resolve][zdr]). Part of Zephyr's network stack.
It hands IPv4 and IPv6 addresses and CNAMEs to a callback, and can also ask by mDNS, LLMNR and
DNS-SD. Kconfig options bound the answer size, the name length and the CNAME follow-up queries.
The page does not mention encrypted transports or DNSSEC. The latest release is v4.4.2 of
2026-08-07
([release](https://github.com/zephyrproject-rtos/zephyr/releases/tag/v4.4.2)).

## Verified DNS software

**IRONSIDES** (Ada and SPARK; [IRONSIDES](https://ironsides.martincarlisle.com/)). An
authoritative server and a recursive server. SPARK shows the code free of exceptions and data
flow errors, and shows it ends only where its authors say it can. They are servers, not a
library. The latest snapshots are of 2015 for the authoritative server and 2014 for the
recursive one.

**VeriDNS** (Lean 4; [VeriDNS](https://github.com/BasisResearch/VeriDNS)). A recursive resolver
server, written and proved in Lean 4. Each module quotes the RFC text it implements, a language
pipeline turns that text into propositions, and the code is proved against them. The proofs cover
its I/O loop, up to the transport it calls through the foreign function interface. It speaks UDP
alone, with no TCP fallback, no EDNS0, no cookies, no DoT or DoH and no DNSSEC validation
([README](https://github.com/BasisResearch/VeriDNS)). It is a server, not a library, and it has
no release.

## Looked for and not found

- **A second sans-I/O unicast stub resolver.** Searches for "sans-io DNS", "DNS resolver library
  no allocation", "no_std no-alloc DNS" and embedded DNS resolvers found message codecs
  (dns-protocol, SPCDNS, `dnsmessage`, the Zig libraries), a multicast DNS state machine
  (mdns-proto), and ocaml-dns's `Pure` module, whose pure part covers one query and its response.
  None keeps a whole lookup, with retries, search list, failover and TCP fallback, outside I/O and
  allocation.
- **A stub resolver library checked against a formal model.** The formal work found is on
  servers: IRONSIDES and VeriDNS. The outside checks found on resolver libraries are audits
  (Hickory DNS, Unbound) and OSS-Fuzz (c-ares, Unbound).
- **DoQ or DoH in a C resolver library.** The manuals and feature lists read for c-ares, getdns,
  libunbound, ldns, udns, glibc and musl name neither as a way to send queries. hickory-resolver
  has both.
- **Details this survey could not source.** adns's I/O model, which only its header describes;
  the resolver of Zig's standard library beyond its release notes; and the memory model of lwIP's
  and Zephyr's DNS clients.
- **Not surveyed.** The platforms' own resolver interfaces (Apple's DNS-SD, Windows' `DnsQueryEx`),
  recursive servers that are not libraries (BIND, Knot Resolver, PowerDNS Recursor), and
  FreeRTOS-Plus-TCP's DNS client.

## Summary

Each cell comes from the paragraph above that covers the project. "None listed" means the
project's own feature list or manual names no such thing; "not stated" means the sources read do
not say. "Latest" is the date of the latest release, except for SPCDNS, where it is the last
commit, and libasr, whose portable release is archived.

| Project | Language | Who does the I/O | Allocates | Encrypted | Validates DNSSEC | Latest |
| --- | --- | --- | --- | --- | --- | --- |
| c-ares | C | its thread, or the caller's loop | yes | none listed | no | 2026-07-07 |
| getdns | C | it, over an event library | yes | DoT | yes | 2022-12-22 |
| libunbound | C | its thread or process | yes | DoT | yes | 2026-09-16 |
| ldns | C | it, blocking | yes | none listed | low-level functions | 2026-06-10 |
| udns | C | it, one fd in the caller's loop | yes | none listed | not stated | 2024-07-26 |
| dns.c | C | it, fd in the caller's loop | not stated | none listed | no | 2015-06-30 |
| libasr | C | it, fd in the caller's loop | yes | none listed | not stated | archived |
| glibc | C | it, blocking or background | yes | none listed | no | 2026-07-25 |
| musl | C | it, blocking | not stated | not stated | not stated | 2026-03-20 |
| Go `net` | Go | it, on goroutines | yes | none listed | none listed | 2026-09-01 |
| hickory-resolver | Rust | it, on Tokio | not stated | DoT, DoH, DoQ | yes | 2026-09-10 |
| domain | Rust | it, on Tokio | not stated | DoT | unstable | 2026-09-25 |
| ocaml-dns client | OCaml | the caller's module | yes | DoT | other package | 2026-09-13 |
| systemd-resolved | C | a service | does not apply | DoT | yes | 2026-09-22 |
| Zig 0.16 std | Zig | it, through `Io` | not stated | not stated | not stated | 2026-04-13 |
| lwIP | C | it, in lwIP's thread | not stated | none listed | not stated | 2025-02-06 |
| Zephyr | C | it, in Zephyr's stack | not stated | not stated | not stated | 2026-08-07 |
| dns-protocol | Rust | none: a codec | no | no transport | not stated | 2024-06-12 |
| SPCDNS | C | none: a codec | no | no transport | not stated | 2024-06-26 |
| cocuyo | Zig | the caller's | no | DoT, DoQ, DoH on HTTP/3 | no | 2026-09-26 |

## Where cocuyo stands

cocuyo (Apache-2.0, Zig 0.16) is the one row with all four properties of the first section:

- **No I/O, no allocation, and time and randomness as arguments,** in the library in `src/`
  ([design §1](design.md#1-scope-and-agreement-with-the-split)). Lint rules over `src/` refuse a
  socket, an allocator, a clock and a global random source ([CLAUDE.md](../CLAUDE.md)).
- **A whole stub resolver:** the search list, CNAME chains, retries, failover, TCP fallback, DNS
  cookies, DNS-0x20, a cache, and the `getaddrinfo` shape with RFC 6724 ordering
  ([README](../README.md#what-it-does)).
- **Checked against models.** Lean proofs cover the lookup, and 2,237,654 transitions of the
  model, under 109 configurations, are replayed against the code
  ([spec/README.md](../spec/README.md)). TLC checks a TLA+ model of the engine, and 24,000 of
  its walks are replayed against the engine on a deterministic twin of rotor
  ([README](../README.md#how-it-is-checked)). Each check is broken on purpose, and
  [mutations.md](mutations.md) records the test that caught it, or why none does.
- **Checked against other implementations.** Its reading of 66 responses real servers sent is
  compared record for record with dnslib's. Its search-list walk was compared on the wire with
  glibc 2.39, musl 1.2.5 and c-ares 1.34.8 ([design §5](design.md#search-list-policy)). Every
  transport runs daily against AdGuard's dnsproxy on the loopback, and the encrypted ones against
  public resolvers ([README](../README.md#encrypted-transports)).

Two of the bugs c-ares 1.34.7 fixed were an unbounded chain of compression pointers and record
counts it did not check. cocuyo's parser bounds the pointer walk and never reads because a count
says to ([design §7](design.md#parsing)). A test catches the mutation that breaks each rule
(mutations 1, 2 and 6 of [design §13](design.md#13-tests-mutation-and-fuzzing)). That shows the
rules exist and are tested. It does not show cocuyo is free of such bugs.

Where cocuyo is weaker:

- **Age and deployment.** 0.1.0 was tagged on 2026-09-22 and 0.2.0 on 2026-09-26
  ([releases](https://github.com/c4milo/cocuyo/releases)). A minor version may change the API
  until 1.0 ([README](../README.md)). It has no record of use in production. c-ares, Unbound,
  glibc and musl have release histories of years, linked above.
- **No outside review.** No third party has audited cocuyo, and it is not in OSS-Fuzz. Its fuzz
  target is its own seeded generator ([design §13](design.md#13-tests-mutation-and-fuzzing)).
  Hickory DNS and Unbound have been audited, and c-ares and Unbound are in OSS-Fuzz.
- **No DNSSEC validation.** getdns, libunbound, hickory-resolver and systemd-resolved validate,
  and domain and ocaml-dns have validators. cocuyo hands records out as read
  ([README](../README.md#what-it-will-not-do)).
- **No C interface.** cocuyo is a Zig library that needs Zig 0.16.0, with no C header. Every C
  library above has a C interface.
- **No Windows engine, and no platform configuration.** The engine runs on macOS and Linux, and
  cocuyo reads `resolv.conf` alone. c-ares runs on Windows, Android and iOS and watches the
  system configuration there. systemd-resolved routes by link, and Go falls back to the system
  resolver on macOS ([README](../README.md#compared-with-c-ares),
  [design §14](design.md#14-what-cocuyo-sees-and-what-the-platform-resolver-sees)).
- **DoH reaches HTTP/3 servers alone.** RFC 8484 §5.2 makes HTTP/2 the minimum recommended
  version of HTTP for DoH, and HTTP/3 is above it, so cocuyo's DoH meets the recommendation
  ([RFC 8484](rfcs/rfc8484.txt)). What it cannot do yet is reach a DoH server that speaks HTTP/2
  and not HTTP/3: DoH over HTTP/2 is being built
  ([design §24](design.md#doh-over-http2-written-on-2026-09-26)). hickory-resolver speaks both.
- **Encryption needs the engine.** The library alone has no encrypted transport. DoT needs the
  engine, rotor and chapulin, and DoQ and DoH need colibri as well
  ([README](../README.md#encrypted-transports)).
- **Tail latency.** Against c-ares on the loopback, c-ares has the lower 99th percentile at one and
  sixteen lookups in flight, and the cause is not yet known
  ([README](../README.md#performance)). The two spend memory differently: c-ares allocates a heap
  object for each message and each record ([design §11](design.md#11-performance)), and cocuyo
  holds only the memory its caller sized at init, so what it uses cannot grow with the load.
- **Source-port entropy is the caller's.** cocuyo cannot bind a port, so it suggests one. A
  caller that sends every query from one socket loses that entropy
  ([README](../README.md#security)).
- **No mDNS and no LLMNR.** hickory-resolver has experimental mDNS, lwIP one-shot mDNS, Zephyr
  mDNS and LLMNR, and systemd-resolved both.

[x41]: https://ostif.org/wp-content/uploads/2019/12/X41-Unbound-Security-Audit-2019-Final-Report.pdf
[zdr]: https://docs.zephyrproject.org/latest/services/connectivity/networking/api/dns_resolve.html
