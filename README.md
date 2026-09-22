# cocuyo

A DNS resolver library in Zig. It builds query bytes and parses response bytes. It owns no socket,
no file descriptor, no thread, no timer and no allocator: the caller does the sending and the
receiving, and cocuyo says what to do next.

`cocuyo` is the Colombian word for the firefly, and for a car's hazard lights — a small light that
shows the way while somebody else does the walking.

**Status: the design is written and the implementation has not started.** See
[docs/design.md](docs/design.md), whose §15 is the build plan and §17 the open questions.

## Why not c-ares

c-ares conflates two jobs: the DNS protocol, and owning sockets. That is what makes it awkward to
embed — it wants to run its own event-loop integration through `ARES_OPT_SOCK_STATE_CB` and
`ares_process`, a readiness model you then have to bolt onto whatever loop you actually have.

cocuyo splits them. The protocol is a state machine plus a codec: bytes in, bytes out, and an
action telling the caller what to do next — send this query to this server, wait this long, retry,
fall back to TCP. The caller performs it, on a completion-based event loop, a blocking socket in a
test, or a thread pool.

A resolver is a parser of hostile input, and a parser you can only test against a live network is
a parser you cannot test. The state machine is deterministic: time is a parameter and entropy is a
caller-supplied seed, so one seed replays byte for byte.

## What version one does

`A`, `AAAA` and `PTR` lookups. RFC 1035 with RFC 3596, name compression on parse, CNAME chains,
EDNS0 (RFC 6891), TCP fallback on a truncated reply (RFC 7766), retry and timeout as state rather
than as sleeping, and a separate `resolv.conf` parser the state machine cannot import.

Out of scope, deliberately: DNSSEC validation, DNS-over-TLS, DNS-over-HTTPS, mDNS, zone transfers,
a cache, `/etc/hosts`, and record types beyond the four above. §1 of the design document names the
seam each one would attach to.

## Security

cocuyo parses unauthenticated input from the network, so §7 of the design document is the part to
read. In short: a response counts only if the transaction ID matches, the source address and port
match the server the query went to, and the question section comes back byte-identical, case
included. Matching on ID alone is the textbook cache-poisoning hole.

DNS-0x20 is in version one and on by default. Source-port randomisation is the caller's, because
cocuyo owns no socket: the action that says "send this" carries a port hint the caller may bind.
Reusing one socket for every query keeps the ID and case entropy and loses the port entropy.

## What cocuyo sees, and what the platform resolver sees

cocuyo sends DNS queries to the servers it is given. That is all it does. It is not the system
resolver, and on a Mac it is not close to it.

- **macOS.** `/etc/resolv.conf` is a partial, legacy view. The system resolves through
  per-interface configuration held by `SCDynamicStore` and read by `res_getservers`, and through
  mDNSResponder for `.local` names and for split-DNS domains routed to a VPN. A program calling
  `getaddrinfo` or `DNSServiceGetAddrInfo` sees all of that. cocuyo reading `resolv.conf` sees none
  of it.
- **Linux with systemd-resolved.** `/etc/resolv.conf` usually points at the 127.0.0.53 stub, which
  does re-expand into per-link routing, so you get closer to parity there. Where `resolv.conf` is
  instead a static list, per-link domains are invisible.
- **Everywhere.** cocuyo does not read `/etc/hosts`, does not consult nsswitch, and does not know
  about NIS, LDAP or mDNS. A name that resolves for every other program on the machine can fail
  here. That is by design, not a bug.

Choose cocuyo when you want a resolver that is explicit, testable and identical on every host: a
server, a proxy, a container. Choose `getaddrinfo` on a thread when you need exactly what the rest
of the machine sees.

## Build

```bash
zig build test
```

Zig 0.16. The library has no dependencies. The developer tooling has one, pepegrillo, which is
lazy and is never linked into the library.
