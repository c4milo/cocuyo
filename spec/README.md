# The lookup, in Lean

This directory holds a model of `Lookup`, the state machine of docs/design.md §5, in Lean 4, and
proofs of what §5 promises of it. `tools/spec_replay/` ties the model to the Zig code.

## The rule

The model is written from docs/design.md and the RFCs, never from the Zig source. When the replay
finds the two disagree, the design decides. If the design is silent, the rule is settled in the
design first, then written in the model, then made true in the code. A model copied from the code
would agree with the code by construction and prove nothing about it.

## What is here

- `Spec/Lookup.lean` is the model: the eight states, the events a caller delivers, what each
  answers, and `enabled`, the events the contract of §4 lets a caller deliver in each state.
- `Spec/LookupProofs.lean` holds the proofs:
  - `ended_absorbing`: a lookup that is done or has failed is changed by nothing.
  - `cancel_after_end` and `cancel_before_end`: a cancel leaves an end standing, and ends
    anything else as cancelled.
  - `useTcp_never_udp`: under `use_tcp`, no event leads to a datagram.
  - `step_good` and `init_good`: the server, pass, candidate and hop counters stay inside the
    configuration.
  - `step_le`, `sent_lt` and `lexLt_wf`: no event raises a measure, every send lowers it, and its
    order is well-founded. So no sequence of answers makes a lookup send forever.
- `Spec/Axioms.lean` pins the axioms each theorem rests on. A proof left unfinished rests on
  `sorryAx`, which changes a pinned line and fails the build.
- `Main.lean` writes the transcript the replay reads.

## What the model leaves out

- Time. A poll comes before the deadline or at it, and nothing else about the clock matters to a
  transition.
- The message. A reply is what §7's checks and §5's rcode policy make of it: unmatched, an answer,
  a CNAME to a new name, NXDOMAIN, NODATA, a server failure, FORMERR, TC=1 with nothing else, or
  BADCOOKIE.
- The server order of §19 step 12. The model counts a position in the order, which is what the
  lookup's `server_index` is.
- Entropy, the cookies' values and the answers' records.
- What a poll handed out and the caller has not answered yet. The model keeps it to know when
  `on_sent` may come, and the replay does not compare it, because the lookup does not keep it.

## The replay

`cocuyo-spec all 8` walks every state the model reaches from `init` under 55 configurations:
none, one, two or three servers, one to three passes and one to three names, with and without
`use_tcp`. It tries every enabled event in every state and writes one line per transition, with
the model's answer and its whole state after it. A state reached a second time is written but not
walked again, so each transition appears once, 1,771,958 of them in all, 168 deep at most.

`tools/spec_replay/replay.zig` drives `Lookup` down the same tree. It builds each reply around the
question the lookup is asking, and it compares the answer and the state after every event: the
stage, the server's position, the pass, the candidate, the hops, and the flags EDNS0, NODATA seen,
a server failed and the cookie retried. A field that drifts is caught at the event that moved it.

## Running it

- `zig build test` replays `tools/spec_replay/lookup_gate.txt`, a committed slice of 2,910
  transitions: one server, one pass and one name, over UDP and over TCP. It needs no Lean.
- `zig build spec` needs `lake` on the path, at the version `lean-toolchain` pins. It builds the
  proofs and the axiom pins, requires the committed slice to be the one the model writes, and
  replays the whole transcript. It took 8 seconds on the machine of design §11 on 2026-09-23.
- After a change to the model, `lake exe cocuyo-spec gate 8 > ../tools/spec_replay/lookup_gate.txt`
  in this directory writes the slice again.

The `8` is `cname_hops_max` of `src/core/constants.zig`. The transcript records it, and the replay
refuses a transcript written for another.
