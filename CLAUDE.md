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
9. **Tests are proved by mutation.** A test must fail when the code it covers is broken. When you
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
  is a module of §2: `core`, `wire`, `resolver`, `config`, `sim`, `bench`, `examples`.
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
  `core` alone, and `sim` reads all three. `resolver` cannot reach `config`, and
  `zig build graph-check` compiles a fixture to show the compiler rejects it.
- Each module owns its `constants.zig`. A limit two modules share lives in `src/core/constants.zig`.
- `examples/` holds worked examples, `bench/` the microbenchmarks, `docs/` the design set, and
  `tools/` developer tooling that is never linked into the library.

## Ask before

- Changing a named limit or the public API.
- Adding a dependency. The library has none and is meant to keep it that way. pepegrillo is a
  ruled dependency of the tools, approved by the owner on 2026-09-21: `build.zig.zon` pins it by
  hash as a lazy dependency, the tools import it, and it is never linked into the library.
- Weakening an assertion or a check to make a test pass.
- Adding anything §1 puts out of scope for version one: a cache, DNSSEC, DoT, DoH, mDNS, zone
  transfers, `/etc/hosts`, or record types beyond `A`, `AAAA`, `CNAME` and `PTR`.

## Commands

- Build: `zig build`. `-Drelease` builds ReleaseSafe; ReleaseFast and ReleaseSmall are not offered,
  because assertions stay on.
- Lint: `zig build lint` — the cognitive-complexity score over `build.zig`, `build/`, `src/`,
  `tools/` and `examples/`, then the `tools/lint` rules (heap, io, determinism, unbounded-loop,
  relative-import, markdown, file-length, magic-numbers) over the tree and over a canary tree that
  holds one violation of each, so a rule that stopped checking fails the build.
- Test: `zig build test` — the lint, the graph check, the hook check, then every module's unit
  tests and the tools' own tests. Every change passes it before it is committed.
  `zig build test-<module>` (`test-core`, `test-wire`, `test-resolver`, `test-config`, `test-sim`,
  `test-cocuyo`) and `zig build test-tools` run one target's tests with nothing else in the graph,
  which is what a mutation is measured against.
- Format: `zig build fmt`, or `zig fmt build.zig build src tools examples`.
- Commit messages: `zig build hooks` once after clone; `zig build lint-commits` by hand.

## Current task

docs/design.md §15 names the steps, each with the check that proves it. Step 0 is done: the module
graph, the lint rules with their canary, the graph check, the commit linter and the pre-push hook.

Next is step 1, `core`: the types, the limits, and `Name` between text and wire form.
