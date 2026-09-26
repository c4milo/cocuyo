# Contributing

cocuyo parses what any server on the network sends it, so its bar is set for the reader who did not
write the code and has to trust it. This page states the bar and walks the workflow.
[CLAUDE.md](CLAUDE.md) holds the full rules, and the build enforces most of them; this is the
contributor's summary.

## The bar

Five rules hold the architecture up, and a change that breaks one does not land:

- **The library owns no I/O.** Nothing in `src/` opens a socket or a file, polls, starts a thread
  or reads a clock. A function that would block returns a value naming the I/O it wants.
- **The library allocates nothing.** The caller hands cocuyo its memory at init.
- **Assertions stay on in production.** They are for programmer error. A malformed response is the
  expected case and returns an error value.
- **Every limit is named** in a `constants.zig`, with a comment saying why that number, and every
  loop and queue is bounded. A length is checked against the end of the message before the bytes
  are read.
- **Every RFC rule is cited** by RFC and section on the line that checks it. The RFCs are read
  from [`docs/rfcs/`](docs/rfcs), never from a summary, and never from another implementation's
  source.

A change lands with what proves it:

| Change | Must land with |
| --- | --- |
| A new check | A test that fails when the check is broken on purpose, and the mutation, with `CAUGHT`, in [`docs/mutations.md`](docs/mutations.md) and in the commit body |
| A change to a transition of the lookup (design §5), or to the engine's rules (§19 steps 13 and 14) | The design first, then the Lean or TLA+ model under [`spec/`](spec), then the code, in that order, with the replays agreeing |
| A new record type or field | Its RFC section at the code, its RFC example where the RFC gives one, and the fuzz generator writing it |
| A new limit | Its name and its reason in a `constants.zig` |
| Any change | `zig build test` green |

A `NOT CAUGHT` mutation means a test is missing: write the test.

Some changes need the owner first: a named limit or the public API, a new dependency (the library
has none), weakening an assertion or a check, and anything design §1 puts out of scope, such as
DNSSEC or mDNS.

## Style

- Names spell words out: `message_bytes`, not `msg_sz`. `_bytes` and `_len` count bytes, and
  `_max` names a limit. Protocol words stay as the RFC spells them: `qname`, `rdata`, `ancount`.
- A function stays at cognitive complexity 15 or less, tests included, and a hand-written file at
  500 lines or less. Split the function or the file; never raise the limit.
- Tests live in the file they test.
- Prose is active voice and plain words, one idea to a sentence, and no metaphors. A number that was
  recalled rather than measured says so.

## Workflow

Everything needs Zig 0.16.0.

```bash
zig build hooks           # once after cloning: the pre-push hook checks commit messages
zig build test            # the lint, the graph checks, the README's code and every unit test
zig build test-wire       # one module's tests alone, which is what a mutation is measured against
zig build lint-commits    # the commit-message check, by hand
```

- Commits are Conventional Commits: `type(scope): description`, the description imperative and
  lowercase, the subject at most 72 columns. The body says why, in at most three paragraphs and
  100 words, and carries the mutation results of any check the commit adds.
- Stage by explicit path, never `git add -A`.
- `zig build spec` runs the Lean proofs and the model replays, and needs `lake` and Java.
  `zig build tla` runs TLC. Both run in CI, and a change to a model runs them before it lands.
- The checks that need the network or other implementations run in their own workflows: the live
  checks against public resolvers, the interop check against AdGuard's dnsproxy, and the dnslib
  check. CLAUDE.md says how to run each by hand.

## Where things are

- [`docs/design.md`](docs/design.md) is the design: the module graph, the state machine, the
  security rules, the named limits and the plan. Commits and comments cite it by section.
- [`docs/mutations.md`](docs/mutations.md) records every check, the mutation that breaks it and the
  test that catches it.
- [`spec/README.md`](spec/README.md) explains the models and the replays that tie them to the code.
- Open work, known bugs and later steps are [GitHub issues](https://github.com/c4milo/cocuyo/issues).

Security reports go through [SECURITY.md](SECURITY.md), never a public issue.
