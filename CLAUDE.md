# cocuyo rules

cocuyo is a DNS resolver library in Zig, written from the RFCs, named for the firefly — and for
what Colombians call a car's hazard lights: a small light that shows the way while somebody else
does the walking. Home: github.com/c4milo/cocuyo.

It replaces c-ares. c-ares conflates two jobs, the DNS protocol and owning sockets, which is why
embedding it means bolting an event loop onto `ARES_OPT_SOCK_STATE_CB` and `ares_process`. cocuyo
owns the protocol and nothing else.

cocuyo is standalone. It names no consumer, never takes a decision that only makes sense inside
one, and nothing may depend on it in the other direction.

## Read before changing behaviour

- `docs/design.md` — the module graph, the state machine, the public API, the security rules, the
  named limits and the numbered build plan. Sections are cited by number in commits and comments
  ("§5 step 3"). §16 records decisions with the alternatives they beat: if you are about to do
  something §16 rejected, say so and stop, rather than reversing it in code.
- `docs/mutations.md` — every check, the mutation that breaks it, and the test that catches it.

## Non-negotiables

The architecture depends on every rule in this section.

1. **cocuyo owns no I/O.** No socket, no file descriptor, no poll, no thread, no timer. Every
   function that would block returns a value naming the I/O it wants. `tools/lint/io.zig` enforces
   it over `src/`; `examples/` is where a socket may appear, and it is not part of the library.
2. **No allocation.** The caller hands cocuyo its memory at init. No file in `src/` names an
   allocator, tests included. `tools/lint/heap.zig` enforces it.
3. **Assertions stay on in production**, roughly two per function, covering positive and negative
   space. Assertions are for programmer error only. Operational failures — a malformed response, a
   truncated message, a server that did not answer — return error values. A malformed response is
   the expected case, not a bug.
4. **Time and entropy are values the caller passes.** `now_ns` is a parameter on every entry point
   and must never decrease. The transaction id, the source-port hint and the 0x20 case pattern come
   from a generator seeded by the caller's `u64`, which must come from a CSPRNG and never from the
   clock. `tools/lint/determinism.zig` enforces that nothing in `src/` reads a clock or a global
   random source.
5. **Every limit is named** in a `constants.zig` with a doc comment saying why that number, and
   never written at the use site. Every loop and every queue is bounded.
   `tools/lint/magic_numbers.zig` and `tools/lint/unbounded_loop.zig` enforce it.
6. **A bound is a check and an assertion both.** They are different claims: the check says the
   input was hostile and returns an error, the assertion says the code that already rejected the
   hostile input did its job. Every length is checked against the end of the message before the
   bytes are read, and no count field is ever a reason to read.
7. **Every RFC rule is cited by section, in the code.** A check that exists because an RFC
   demands it carries the RFC and the section in a comment on the line that does the checking, so
   a reader can go from any validation to the sentence that requires it. Cite the RFC that
   *states* the rule, not one that inherits it: the case-insensitivity rule is RFC 1035 §2.3.3 as
   clarified by RFC 4343, not RFC 4343 alone.
8. **Read the RFCs, never a summary and never another implementation's source.** The copies to
   read are in `docs/rfcs/`, unmodified from rfc-editor.org, with `docs/rfcs/SHA256SUMS` to show
   they stay that way, and `docs/rfcs/README.md` saying what each one is read for. Where cocuyo
   implements something no RFC states — DNS-0x20, `resolv.conf` — the code says what the source
   is instead of citing an RFC that does not say it.
9. **A cleanup is registered before what can fail.** A `defer` or an `errdefer` under a statement
   that can return leaves whatever the block took above it unreleased: the statement returns
   before the cleanup is registered. `tools/lint/defer_order.zig` enforces it, and
   `tools/lint/unreleased_acquire.zig` reads the other side of it: a socket opened with `try`
   that nothing releases, where a statement under it can still fail.
10. **Tests are proved by mutation.** A test must fail when the code it covers is broken. When you
   add a check, break it on purpose and confirm a test fails. Report `CAUGHT` or `NOT CAUGHT` per
   mutation in the body of the commit that adds the check, and keep the table in
   `docs/mutations.md`. A `NOT CAUGHT` means a test is missing: write it.

## Conventions

- Names spell words out: `message_bytes`, not `msg_sz`. `_bytes` and `_len` count bytes and `_max`
  names a limit. Protocol vocabulary stays as the RFC spells it: `qname`, `rdata`, `ancount`.
- Functions stay at cognitive complexity 15 or less, scored by `tools/cognitive_complexity.zig`.
  `test` blocks are scored under the same limit. Split the function or the test; never raise the
  threshold.
- A hand-written file stays at or under 500 lines, its tests included. Split it, and name each
  piece after the file it came from: `lookup.zig` becomes `lookup_poll.zig`,
  `lookup_response.zig`, keeping the original name as the entry point, so a directory listing
  groups the pieces under their origin. Four or more files sharing a prefix move into a directory
  named for it.
- Tests live in the file they test.
- Prose is active voice and plain words: short sentences, one idea each, terms defined before use,
  lists for list-like content, no metaphors. A number recalled rather than measured says so where
  it appears.
- Every Markdown file must render on GitHub as written: real list markers only, pipes inside a
  table cell escaped as `\|`, fenced code blocks with a language, no definition lists, no LaTeX.
  `tools/lint/markdown.zig` checks it over `docs/`, `README.md` and this file.

### Commits

- Conventional Commits: `type(scope)!: description`, with the scope and the `!` optional. The type
  is one of `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, and a scope
  is a module of §2 or a directory of code beside them: `core`, `wire`, `resolver`, `config`,
  `cache`, `sim`, `io`, `bench`, `examples`.
- The description is imperative, starts lowercase, and ends without a period: `add the name
  decoder`, never `Adds the name decoder.` The subject line stays at or under 72 columns.
- One blank line before the body. A body line stays at or under 100 columns, and the body stays at
  or under 3 paragraphs and 100 words. The diff shows the what, so the body says why, and carries
  the mutation results for any commit that adds or changes a check.
- **No `Co-Authored-By` trailer.** The trailer block is the final run of `Key: value` lines naming
  `Signed-off-by`, `Reviewed-by`, `Refs` or `Closes`, and counts against neither limit.
- `tools/commit_lint.zig` configures pepegrillo's linter to check all of the above. `zig build
  hooks` once after cloning points `core.hooksPath` at `.githooks/`, whose `pre-push` refuses a
  push whose commits break a rule. `zig build lint-commits` runs the same check by hand.
- Stage by explicit path. Never `git add -A` and never `git add .`

## Layout

- `build.zig` stays short: build options and the module graph. Helpers live in `build/`.
- `src/<module>/` is one Zig module per module of §2, declared in `build/modules.zig` with its
  imports listed, so the dependency direction is enforced by the build rather than by review:
  `core` imports nothing, `wire` reads `core`, `resolver` reads `core` and `wire`, `config` reads
  `core` alone, `cache` reads `core` and `wire` and never `resolver`, and `sim` reads the first
  three. `resolver` cannot reach `config`, and `zig build graph-check` compiles a fixture to show
  the compiler rejects it.
- `io/` holds the engine of §19 step 13, outside `src/` because it owns sockets. It reads
  `cocuyo` and a `rotor` import the build binds to `sim`, so `zig build test-io` runs it on the
  twin, and to rotor itself for `zig build bench-cares` alone. It is not exported and not
  shipped: the owner ruled on 2026-09-22 that no library bound to rotor is exposed until a
  consumer asks for one.
- Each module owns its `constants.zig`. A limit two modules share lives in `src/core/constants.zig`.
- `examples/` holds worked examples, `bench/` the microbenchmarks, `docs/` the design set, and
  `tools/` developer tooling that is never linked into the library. `test/` holds fixtures that
  are whole packages of their own rather than files of this one: `test/consumer/` depends on
  cocuyo the way a consumer does, and it sits outside every linted directory because a nested
  build leaves packages beside it. `bench/` is outside the module
  graph and may read a clock; it is linted and formatted like `src/`, and it gets a module graph
  of its own at ReleaseSafe from `build/bench.zig`.

## Ask before

- Changing a named limit or the public API.
- Adding a dependency. The library has none and is meant to keep it that way. pepegrillo is a
  ruled dependency of the tools, approved by the owner on 2026-09-21: `build.zig.zon` pins it by
  hash as a lazy dependency, the tools import it, and it is never linked into the library.
- Weakening an assertion or a check to make a test pass.
- Adding anything §1 puts out of scope: DNSSEC, DoT, DoH, mDNS, zone transfers, nsswitch, IDN,
  the platform resolver configuration of §14. The cache (§18) and the gap with c-ares (§19:
  every record type, cookies, the hosts file, failover, the engine over rotor) were decided in on
  2026-09-22; what §19 lists as out stays out.

## Commands

- Build: `zig build`. `-Drelease` builds ReleaseSafe; ReleaseFast and ReleaseSmall are not offered,
  because assertions stay on.
- Lint: `zig build lint` — the cognitive-complexity score over `build.zig`, `build/`, `src/`,
  `tools/`, `examples/`, `bench/` and `io/`, then the `tools/lint` rules (heap, io, determinism, unbounded-loop,
  relative-import, markdown, file-length, magic-numbers, defer-order, unreleased-acquire) over
  the tree and over a canary tree that
  holds one violation of each, so a rule that stopped checking fails the build.
- Test: `zig build test` — the lint, the graph check, the consumer check, the hook check, then
  every module's unit tests and the tools' own tests. Every change passes it before it is
  committed. `zig build test-<module>` (`test-core`, `test-wire`, `test-resolver`, `test-config`,
  `test-cache`, `test-sim`, `test-cocuyo`, `test-io`) and `zig build test-tools` run one target's tests with
  nothing else in the graph, which is what a mutation is measured against. `zig build
  consumer-check` alone builds `test/consumer/`, the package that depends on cocuyo the way a
  consumer does, and requires the same package to fail when it reaches for a module the surface
  does not export (design §20).
- Bench: `zig build bench` — the microbenchmarks of design §15 step 7, built ReleaseSafe
  whatever `-Drelease` says. `zig build test` compiles the bench and runs the harness's own tests,
  so it cannot rot. A number goes into design §11 with the machine, the command and the date, or it
  does not go in.
- Comparison: `zig build bench-cares` — the same two operations against the installed c-ares,
  found under `-Dcares=<prefix>` (a Homebrew prefix by default), then end to end: both stacks
  against one responder thread on the loopback, cocuyo's side being the `io/` engine over rotor,
  built privately for the bench (`bench/end_to_end/`). It links libraries the gate must not
  require, so it and its tests (`zig build test-cares`) run only when asked. The numbers go in
  design §11 beside cocuyo's, with the c-ares version the binary prints.
- Format: `zig build fmt`, or `zig fmt build.zig build src tools examples bench`.
- Commit messages: `zig build hooks` once after clone; `zig build lint-commits` by hand.

## Current task

docs/design.md §15 names the steps, each with the check that proves it, and docs/mutations.md
records what each step's checks were broken against.

Steps 0 to 7 are done:

- **0**, the build: the module graph the compiler enforces, the lint rules with their canary, the
  graph check, the commit linter and the pre-push hook.
- **1**, `core`: the types, the limits, `Name` between text and wire form, and the reverse name.
- **2**, `wire`: the header, name decoding with its two bounds, the question compare, the query
  builder, EDNS0, the record walk, the answer walk, and a seeded fuzz target whose gate runs
  4096 seeds inside `zig build test`.
- **3**, `Lookup`: the eight states of §5, the response checks of §7, the retry, search and CNAME
  policies.
- **4**, `Resolver`: the slot table, the key table and the demultiplexer.
- **5**, `config`: the `resolv.conf` parser and the address text parser it needs.
- **6**, `examples/udp_blocking.zig`, which resolves real names against real servers.

- **7**, `bench/`: query build, response parse and datagram match in nanoseconds per operation,
  measured ReleaseSafe on the machine §11 names. Every estimate in §11 is now a measurement, and
  the layout question §11 left open is closed on the cold-slot row, the one measurement that can
  see a cache line.

- **8**, `cache`: the SIEVE cache of §18 above the state machine, with the negative TTL of
  RFC 2308 read from the SOA in `wire` and carried in `Failure` by `resolver`. Question 9 of §17
  was answered yes on 2026-09-22, because c-ares has had a cache on by default since 1.31.0 and a
  replacement without one is not one.

Steps 9 to 15 are §19, the gap with c-ares, decided on 2026-09-22:

- **9**, every record type, done the same day: `Kind` names every type c-ares parses,
  `src/wire/rdata/` decodes each from stored rdata, `record_copy.zig` writes a record out of a
  message with its names in full, and a lookup for any type keeps its records in the rdata
  buffer of `Answers`, which grew the lookup to 3024 octets (§9).
- **10**, DNS cookies, done the same day: every query with EDNS carries the client cookie of
  its server, and the server cookie once learned (`resolver/servers.zig`, owned by `Resolver`
  and handed to every lookup); `on_response` discards a wrong or, once expected, a missing
  cookie (§7 check 6), learns from what it accepts, and answers BADCOOKIE with one retry, then
  TCP, then the next server.
- **11**, configuration parity and the hosts file, done the same day: `Config.servers` is a
  list of `Server`, each with a TCP port of its own; `use_tcp`, `ignore_truncation`,
  `recursion_desired`, `check_response`, `primary`, `timeout_ns_max` and `lookups` join it and
  the lookup honours each; `resolv.conf` reads `use-vc` and may refuse the default server;
  `apply_options` and `apply_search` take `RES_OPTIONS` and `LOCALDOMAIN`; `config.hosts`
  parses the hosts file into the caller's storage.
- **12**, server failover, done the same day: `Servers` counts consecutive failures per
  server (a timeout, a failed send, a failed connection) and an answer resets them; a lookup
  walks its servers in `lookup_order.zig`'s order, computed at its first poll: sorted by
  failures, rotated among the fewest, and one query in `failover_retry_chance` a failed server
  whose delay has passed goes first with the real query.
- **13**, the engine, first slice done the same day: `src/sim/` is the twin of rotor's loop, a
  virtual clock and scripted servers behind rotor's surface, and `io/` is the engine over it,
  with one UDP socket per server, a buffer group, one timer and the cache in front, run on the
  twin by `zig build test-io`. The owner ruled the same day that no library bound to rotor is
  exposed until a consumer asks for one, so the engine is not exported. Still to come in 13: the
  TCP path, port rotation, `reinit` and `cancel_all`.
- **14**, the `getaddrinfo` shape, done the same day: the address text parser and the hosts
  table moved to `core` (the parser of the table stays in `config`), and `AddressLookup` in
  `resolver` composes a numeric host, the hosts table in `Config.lookups` order, and one
  absolute `A` and `AAAA` lookup per search candidate in lockstep, joined with `v4_mapped`,
  `all` and the canonical name as `getaddrinfo(3)` has them; it holds two slots at most and is
  1152 bytes (§9).
- **15**, the ordering, done the same day: `core.address_order` applies the ten rules of
  RFC 6724 §6 over routes the consumer supplies, since the source per destination is I/O, with
  the policy table and the scopes of the RFC as named constants; `AddressLookup` applies the
  route-free rules unless `no_sort`. The nine worked examples of the RFC are the gate. The
  end-to-end comparison against c-ares is the part of 15 still open.
- **13**, the engine, second slice done the same day: `io/io_tcp.zig` is the stream path, one
  connection per server shared by the lookups that need it, framed by RFC 7766 §8 and closed
  when idle; and the table hands out work from a ready list, so what one completion event costs
  no longer grows with the lookups in flight (§11, §16 decisions 20 and 21).
- **13** also has `cancel_all` and `reinit`, the port rotation of `udp_queries_per_port` and the
  local address of `Config.local_address`. Since rotor 0.2.0 it also has the socket buffer sizes
  of `Config.socket_receive_bytes` and `socket_send_bytes`. Nothing of c-ares is left but device
  binding by name, which stays out because rotor names no device.
- **15**'s comparison is done: §11 carries the decoder table and the end-to-end one, measured
  2026-09-22 over five runs. Five defects in the comparison's own driver had to be fixed first
  (docs/mutations.md K1 to K3, R1 to R4, and the responder's start-up delay), which is what an
  end-to-end number costs. The handoff between the driver's two threads is checked in every order
  it can run (X1 to X5), and `-Dsanitize-thread` runs its tests under ThreadSanitizer on Linux,
  on the LLVM backend and after a planted race it must report (T1).
- **16**, the package a consumer gets, §20, asked for by colibri's driver: the cache under every
  lookup as a `Memory` the caller supplies, the module surface closed to `cocuyo` alone, and
  `zig build consumer-check` compiling a dependent package. Landed 2026-09-22.
- The cache's hit rate is measured (§18, over a synthetic trace), and the engine runs on Linux
  over io_uring in CI. Both needed the buffer group's storage to stop claiming an alignment no
  loader keeps (docs/mutations.md N1). Since rotor 0.3.0 a process that the kernel or a
  container's seccomp profile refuses io_uring runs on epoll instead: the rotor example resolves
  in a container with Docker's default profile, where on rotor 0.2.0 it failed `PermissionDenied`.
- §17 questions 13 and 14 are answered: the cache keeps the chain's end, and a get leaves an
  expired entry for the put after the miss to renew in place. SIEVE is measured against S3-FIFO,
  W-TinyLFU, c-ares's rule and the offline optimal (§18): on the synthetic trace no online policy
  measured beats it by a point, though the optimal is 5.7 points over it at the default size.
- Next: the p99 of the comparison on a quiet machine.

§17 holds the questions the owner has not answered.
