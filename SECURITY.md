# Security policy

## How to report a vulnerability

Use GitHub's private vulnerability reporting: open the repository's
[Security tab](https://github.com/c4milo/cocuyo/security) and click "Report a vulnerability". The
report stays private, and the advisory and CVE, if one is warranted, come out of the same thread.

If you cannot use GitHub, email camilo.aguilar@gmail.com with the same details you would put in the
report.

Do not open a public issue for a vulnerability.

## What to expect

One maintainer runs this project. You get an acknowledgment within 7 days and an assessment within
30: confirmed, not a vulnerability, or needs more information. I promise communication, not a fix
date; the fix date comes out of the assessment.

## Scope

cocuyo's rule is that the caller is trusted and the network is not. In scope is anything a server,
or anyone who can put packets on the network, can make cocuyo do that it should not:

- The library in `src/`: the codec, the lookup state machine, the `resolv.conf` and hosts file
  parsers and the cache. A malformed message is the expected case and must end in an error value,
  never a crash, a read out of bounds or an assertion. An assertion that a server can trip is a bug
  in scope.
- An answer taken from a message that is not the answer: a wrong transaction id, source address,
  question or cookie that cocuyo accepts anyway.
- The engine in `io/`, exported as `cocuyo_rotor`, `cocuyo_quic` and `cocuyo_doh`. A server that
  strict mode should refuse (RFC 8310 §5) and that cocuyo asks anyway is in scope, as is a ticket or
  a pin used where it should not be.

Out of scope, so triage stays fast:

- Reading or changing plain DNS by someone on the path. DNS over UDP and TCP carries no integrity.
  cocuyo makes an off-path forgery expensive with random transaction ids, source ports, DNS-0x20
  and cookies, and offers DoT, DoQ and DoH for the path itself. It does not validate DNSSEC
  (`docs/design.md` §1).
- A forger who already matches a query's id, port and cookie, and echoes its name in lowercase,
  turning DNS-0x20 off for that one server until the table is built again. `docs/design.md` §7
  records it as the cost of the fallback for servers that lowercase the name.
- Attacks that need a malicious `Config`, a caller that breaks the documented contract, or a
  compromised host.
- Resource limits the caller chose. cocuyo's memory is sized at init, and a lookup that runs out of
  room says so.
- Bugs in [chapulin](https://github.com/c4milo/chapulin), which carries the TLS, or in
  [colibri](https://github.com/c4milo/colibri), which carries QUIC and HTTP: report those there.
  cocuyo's side of each interface is in scope here.

[`docs/design.md`](docs/design.md) §7 states the security rules the code holds, and
[`docs/mutations.md`](docs/mutations.md) the test that catches each one broken.

## Supported versions

The latest release only. One maintainer does not promise backports.

## Disclosure policy

Coordinated disclosure with a 90-day default, negotiable in either direction: shorter when the fix
is easy, longer when a deployment needs it. Reporters get credited in the advisory unless they
decline.
