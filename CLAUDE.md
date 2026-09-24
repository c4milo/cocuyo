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
- `spec/README.md` — the Lean models of `Lookup`, of the engine, and of the `getaddrinfo` walks,
  and the replays that check the code against them. A change to a transition of §5, or to a rule
  of §19 steps 13 and 14, changes the design, then the model, then the code, in that order, and
  never the model from the code.

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
- `spec/` holds the Lean models of design §5 and of the engine's streams, and the lookup's
  proofs, a Lake package of its own. `tools/spec_replay/` holds the Zig replays that drive
  `Lookup` and the engine down the models' transcripts, the engine's over the twin in manual
  mode, wired by `build/spec.zig`.

## Ask before

- Changing a named limit or the public API.
- Adding a dependency. The library has none and is meant to keep it that way. pepegrillo is a
  ruled dependency of the tools, approved by the owner on 2026-09-21: `build.zig.zon` pins it by
  hash as a lazy dependency, the tools import it, and it is never linked into the library.
- Weakening an assertion or a check to make a test pass.
- Adding anything §1 puts out of scope: DNSSEC, mDNS, zone transfers, nsswitch, IDN, the
  platform resolver configuration of §14. DoT and DoH were decided in on 2026-09-23: DoT in the
  engine, over rotor with chapulin's non-blocking record transport, strict by default (RFC 8310);
  DoH's DNS half in cocuyo and its HTTP/2 and HTTP/3 in colibri's driver, which cocuyo may never
  depend on. DNS over QUIC (RFC 9250) joined the same day, split the same way by the owner's
  ruling of 2026-09-24: its DNS half in cocuyo, its QUIC in colibri's driver. The cache (§18) and the gap with c-ares (§19:
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
- Model: `zig build spec` — the Lean proofs of `Lookup` and the pins on the axioms they rest on,
  then every transition the lookup model reaches, the engine's walks, and every transition of
  the `getaddrinfo` walks, replayed against the code (spec/README.md has the counts). It needs
  `lake` at the version `spec/lean-toolchain` pins, so it runs only when asked and in CI's
  `spec` job; `zig build test` replays the committed slices without Lean.
- DNS over TLS: `-Dchapulin=<checkout>` names a chapulin checkout whose `bin/chapulin-record.o`
  `build/dot.zig` says how to make. With it, `zig build test-chapulin` runs the session's tests
  and `zig build example-dot-rotor` resolves over DoT; `tools/dot_live/run.sh <checkout>` runs
  the live check of design §21 step 6. Neither is in the gate, which needs no chapulin.
- Format: `zig build fmt`, or `zig fmt build.zig build src tools examples bench`.
- Commit messages: `zig build hooks` once after clone; `zig build lint-commits` by hand.

## Where work is tracked

- Open work, known bugs and later steps are GitHub issues on github.com/c4milo/cocuyo. This
  file holds rules, layout and commands, and never a log of what is done or next.
- docs/design.md names each step of the plan with the check that proves it (§15, §19, §21,
  §22), docs/mutations.md records what each step's checks were broken against, and §17 holds
  the questions the owner has not answered.
