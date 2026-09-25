# The lookup and the engine, in Lean and TLA+

`lean/` holds two models in Lean 4, a Lake package; `tla/` holds the engine's in TLA+; and
`tools/spec_replay/` ties each to the Zig code:

- `Lookup`, the state machine of docs/design.md §5, with proofs of what §5 promises of it.
- The engine's streams and datagrams, the rules of §19 step 13, with invariants checked over
  every state the model reaches in small configurations.
- The `getaddrinfo` walks, `AddressLookup` and `NameLookup`, the rules of §19 step 14, checked
  the same way.

## The rule

The model is written from docs/design.md and the RFCs, never from the Zig source. When the replay
finds the two disagree, the design decides. If the design is silent, the rule is settled in the
design first, then written in the model, then made true in the code. A model copied from the code
would agree with the code by construction and prove nothing about it.

## What is here

- `lean/Spec/Lookup.lean` is the model: the eight states, the events a caller delivers, what each
  answers, and `enabled`, the events the contract of §4 lets a caller deliver in each state.
- `lean/Spec/LookupProofs.lean` and the two modules under `lean/Spec/LookupProofs/` hold the
  proofs:
  - `ended_absorbing`: a lookup that is done or has failed is changed by nothing.
  - `cancel_after_end` and `cancel_before_end`: a cancel leaves an end standing, and ends
    anything else as cancelled.
  - `useTcp_never_udp`: under `use_tcp`, no event leads to a datagram.
  - `request_never_stream`: over DoH or DoQ (design §22, §23), no event leads to a datagram, a
    connection or a stream, and a reply is read as one over a stream is.
  - In `LookupProofs/Measure.lean`, `step_good` and `init_good`: the server, pass, candidate and
    hop counters stay inside the configuration.
  - There too, `step_le`, `sent_lt` and `lexLt_wf`: no event raises a measure, every send lowers
    it, and its order is well-founded. So no sequence of answers makes a lookup send forever.
  - In `LookupProofs/Timeout.lean`, `refused_never_timeout`: a lookup that a server refused, its
    connection, its handshake or its request failing, never ends in `timeout`, whatever it hears
    afterwards (design §16 decision 25). It is `Timeout`'s promise, that every try went
    unanswered, which nothing checked before the decision.
- `lean/Spec/Axioms.lean` pins the axioms each theorem rests on. A proof left unfinished rests on
  `sorryAx`, which changes a pinned line and fails the build.
- `lean/Spec/Address.lean` is the model of both walks, and `lean/Spec/AddressWalk.lean` walks it and
  writes its transcript.
- `lean/Spec/Tokens.lean` spells states and events for the transcripts.
- `lean/Main.lean` writes the transcripts the replays read.
- `tla/engine/EngineTable.tla`, `tla/engine/EngineIo.tla` and `tla/engine/Engine.tla` are the
  engine model: the table's slots, free list and ready list, the connections, the sockets, the
  loop's operations, and the lookup's transitions in each slot. `Checks` names what every event
  must keep.
- `tla/engine/Engine_*.cfg` are the configurations TLC walks breadth first, and
  `tla/engine/mutants/` breaks the model's TLS rules and the stream's rule 9 with
  `tla/engine/EngineMutants.tla`.
- `tla/engine/EngineTrace.tla` writes TLC's walks for the replay, one configuration of
  `tla/engine/trace/` for each of the replay's.

## What the lookup model leaves out

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
- A DoH or DoQ transaction's number. The model delivers an answer or a failed request to the current
  transaction, and an unmatched reply is one for another. DoH and DoQ move alike, so the model's
  `quic` names which servers the replay asks and no transition reads it. That a late answer names a
  number the lookup has left is the unit tests' to show (docs/mutations.md DH8, DH9, DH21).

## The replay

`cocuyo-spec all 8` walks every state the model reaches from `init` under 109 configurations:
none, one, two or three servers, one to three passes and one to three names, over UDP, under
`use_tcp`, over DoH, or over DoQ. It tries every enabled event in every state and writes one line
per transition, with the model's answer and its whole state after it. A state reached a second
time is written but not walked again, so each transition appears once, 2,237,654 of them in all,
168 deep at most.

`tools/spec_replay/replay.zig` drives `Lookup` down the same tree. It builds each reply around the
question the lookup is asking, and it compares the answer and the state after every event: the
stage, the server's position, the pass, the candidate, the hops, and the flags EDNS0, NODATA seen,
a server failed and the cookie retried. A field that drifts is caught at the event that moved it.

## The engine

The engine model is written from the stream's rules and the datagram's rules of §19 step 13, the TLS
rules of §21, and rotor's decision 5, with two servers and one pass. A configuration asks every
query over TCP, every query over TLS, or every query over UDP with no answer truncated and a port
replaced every two queries, the old one draining beside the new. A TLS session is what it does to
the queue: the records it makes, which are sealed as it makes them, and the steps its handshake
takes, a flight to answer, the handshake's end or a failure, and later a KeyUpdate to answer or a
ticket to keep. A kept ticket may lapse at any moment, which stands for its lifetime and the 7-day
cap. It leaves out the timer, the bytes of a message, the TLS records' contents and the cache. Time
moves in ticks, each the idle close's wait, and only when a deadline arrives or the caller lets a
tick pass; a lookup waits two ticks. Two faults stand in for a kernel under pressure: the loop
refuses every submission for the length of one event, as a full ring does, and every socket open
fails for the length of one event, as a process with no descriptor left sees.

TLC walks it breadth first (`zig build tla`) and checks seventeen rules in every state and every
event:

- A connection's users are the lookups on it.
- A lookup is on a connection only while it streams to that connection's server.
- A buffer is lent to one send at most, and is lent exactly when a send holds it.
- A connection has its connect while it connects, and at most its receive once it is up.
- A server's current socket has at most one current receive, and so does its draining socket
  while it drains; one that is gone has none.
- A drive leaves nothing on the ready list.
- After a drive nothing refused, every socket has its receive armed, and every connection that
  is up has its receive.
- After such a drive, a port that has carried its share is replaced unless an older one still
  drains, and a draining socket nothing is owed on is gone.
- A stream has one send in flight at most, and it is its queue's head's; no query waits in two
  queues or twice in one.
- A query waits in a connection's queue only while its lookup is on that connection, or once it
  has started going out.
- A connect or a send of records that is gone keeps its slot closed until its final event, since
  it borrows the slot's memory until then.
- The sealed entries lead each queue, only its head among them a query, and something is sealed
  only while a send is in flight: records go out in the order they were sealed.
- No query waits on a connection that is not up.
- No event leaves the session owing an answer to a flight, the handshake's end or a KeyUpdate.
- A connection that opens resuming spends its server's ticket, so a ticket is used once.
- A connection opened again after its resumed handshake failed handshakes in full.
- A resumed handshake that fails counts no failure against its server and keeps its lookups on
  the connection, unless the loop refuses the connect again.

Each configuration bounds the operations in flight, the failures a server and the queries a port
(`OpsMax`, `FailuresMax` and `SentMax`), since nothing else bounds the graph. A stream's send may
come back short once a message, since a second short send takes the path the first took and the
model does not count octets.

The model was first written in Lean, and a hand-written walker checked it. It retired on
2026-09-24, once TLC counted what it counted and the replay read TLC's walks (§16 decision 24).
Its last results stand. At six operations and two failures, or five and one, it reported on
2026-09-23:

| Transport | Slots | Connections | Operations, failures | States | Transitions | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
| TCP | 1 | 1 | 6, 2 | 1,038,503 | 14,908,528 | hold |
| UDP | 1 | 1 | 6, 2 | 5,848,772 | 85,609,860 | hold |
| TCP | 2 | 1 | 5, 1 | 11,014,930 | 125,509,380 | hold |

Two lookups on one TCP connection is where queries queue behind each other (the stream's rule 9),
and it did not finish at six and two in nine hours, so it was walked at five and one.

From 2026-09-24 the Lean walker counted a state and the same state with its operations sorted as
one, since the rules read the loop's operations as a multiset. It checked that claim on three
small graphs whole (docs/mutations.md CN1 and CN2). The TLA+ model makes the claim native: its
operations are a bag.

The TLS model, one lookup on two connections, walked on 2026-09-24 on an Apple M1 Pro, the
operations sorted:

| Operations, failures | States | Transitions | Seconds | Invariants |
| --- | --- | --- | --- | --- |
| 2, 0 | 51,406 | 376,976 | 1.8 | hold |
| 2, 1 | 275,126 | 2,054,004 | 10 | hold |
| 3, 0 | 1,164,712 | 11,978,040 | 66 | hold |
| 3, 1 | 6,835,766 | 71,454,920 | 472 | hold |
| 4, 0 | 4,467,223 | 58,243,444 | 260 | hold |
| 4, 1 | 26,769,958 | 354,070,484 | 2,852 | hold |

Every row took every kind of event and reached every stage, a resumed connection and a kept
ticket among them. Unsorted, three operations and none was 3,463,580 states and 151 seconds.
Before the sorting, four and one ran an hour without finishing; the row above took 6.6 GB, on a
machine busy with other work. These counts are what TLC's had to equal.

The TLS configurations are walked and replayed like the others. The engine drives the twin's
session (`src/sim/sim_tls.zig`), whose records carry their plaintext unsealed and whose handshake
steps are one octet each. A walk's `tls:R0*:flight` puts one step in a record on the receive that
`R0*` names, an answer comes in a data record, and `lapse:v` drops the ticket kept for server
`v`.

The replay cannot visit that many states, so it follows walks TLC takes through the TLA+ model
(below). Each line is an event and the model's whole state after it.
`tools/spec_replay/engine_replay.zig` drives the engine of `io/` over the twin in manual mode,
where every operation waits until the walk ends it with the outcome it names, and the twin refuses
what the walk says to refuse, which is how the replay reaches the orders rotor's rule 2 allows.
After each event it compares the engine's state with the model's, and requires every buffer the
event handed the engine to be back in its group.

## The engine in TLA+

`tla/engine/` holds the engine model in TLA+, checked by TLC through pepegrillo's `tla` tool
(docs/design.md §16 decision 24). It was ported from the Lean model, definition by definition:
`EngineTable.tla` holds the configuration, the lookup's transitions the engine asks of it, the
table and the connections; `EngineIo.tla` the sockets and the sends; and `Engine.tla` the drive,
the events, the checks and the specification. The Lean model retired once the replay read its
walks from TLC.

Three choices make TLC count what the Lean walker counts:

- The loop's operations are a bag, so an event names an operation by its value, and a state is one
  state whatever order its operations came in: the Lean walker's sorting, made native.
- The bound guards `Next` rather than being a `CONSTRAINT`. A state beyond it is reached, counted
  and checked, and has no successor, as in the Lean walker; TLC leaves a state that breaks a
  `CONSTRAINT` out, and the check on the event that reached it with it. So every configuration
  says `CHECK_DEADLOCK FALSE`.
- Five of the seventeen checks read the event or the state before it, which a TLC invariant cannot.
  So `broken` holds the names of the checks the last event broke, and `Clean` asks it be empty.
  In a model that keeps its rules it always is, so it splits no state.

`zig build tla` runs every configuration, each with the verdict its header expects, on TLC
v1.7.4, which `tools/tla.zig` pins by SHA-256 and the tool fetches once. It needs Java 11 or
newer. On 2026-09-24, on an Apple M1 Pro, TLC's count of each configuration equalled the Lean
walker's, its operations sorted:

| Transport | Slots | Connections | Operations, failures | States, both | TLC seconds |
| --- | --- | --- | --- | --- | --- |
| TLS | 1 | 2 | 2, 0 | 51,406 | 10 |
| TLS | 1 | 2 | 2, 1 | 275,126 | 45 |
| TLS | 1 | 2 | 3, 0 | 1,164,712 | 138 |
| TCP | 1 | 1 | 4, 1 | 19,767 | 4 |
| UDP | 1 | 1 | 3, 1 | 38,457 | 5 |
| UDP | 1 | 1 | 4, 1 | 115,774 | 12 |
| TLS | 1 | 2 | 4, 1 | 26,769,958 | 4,897 |

TLC walked these 1.7 to 5.6 times slower than the Lean walker, the gap narrowing as the graph
grows. It adds a fingerprint per state in place of the whole state, a queue on disk and worker
threads, and it reports a shortest counterexample. The last row is not in `zig build tla`: it took 4.3 GB and ran on a machine busy with other
work, beside the Lean walker's run of the same row. `tla/engine/mutants/` breaks the TLS rules the
Lean model's mutations broke, TM1 to TM3 and R8a to R8d, and the stream's rule 9 as TQ1 breaks
it (below). TLC must find each broken (docs/mutations.md).

Every configuration above has one lookup. Two lookups are where queries wait behind each other on
a stream (the stream's rule 9) and share a server's socket, so `zig build tla` checks four
configurations with two as well. The Lean walker walked one of them, TCP with one connection, at
five operations and one failure (the table above), and none over UDP or TLS. Measured on
2026-09-24 on the same machine, busy with other work, one configuration at a time:

| Transport | Slots | Connections | Operations, failures | States | TLC seconds |
| --- | --- | --- | --- | --- | --- |
| TCP | 2 | 1 | 4, 1 | 758,374 | 66 |
| TCP | 2 | 2 | 4, 0 | 223,480 | 18 |
| UDP | 2 | 1 | 4, 0 | 1,534,175 | 94 |
| TLS | 2 | 2 | 2, 0 | 1,315,522 | 97 |

They found a rule the model kept without checking. A lookup that moved on took its waiting query
out of the queue, but no check said it must. So TQ1, which leaves the query queued, changed what
the model reached with two lookups and broke nothing. The check that a query waits only for a
lookup on its connection catches TQ1 in 5 states. With one lookup no query ever waits on a plain
stream, and TQ1 changes nothing.

### The walks TLC takes

`tla/engine/EngineTrace.tla` runs the specification in TLC's simulation mode, which takes seeded
random walks, and prints each state as the replay reads it, with the event that led to it. An
event names an operation by its token, such as `finish:C0*:ok`, since the model's operations are
a bag. The replay applies it to the oldest of the engine's operations with that token, and writes
the engine's operations in the order the model writes them. Each configuration of the replay has
a file in `tla/engine/trace/`.

`zig build tla -- walks <seed> <walks> <depth>` (`tools/tla_walks.zig`) runs every configuration
at once, each on one worker, so a seed always writes the same walks. A walk of depth `d` holds
`d` states, its `init` and `d - 1` events. With `--pick <file> <walk>...` it also writes the
walks named to the file, each by its place in the whole run, counted from 1 in the
configurations' order.

TLC holds a function built as `[x \in S |-> e]` as that expression, and stacks each `EXCEPT` on it
as another layer. A check writes each state it keeps out whole, but a walk keeps none, so each
step built on the layers of every step before it: one walk of 200 events took four minutes.
`EngineTrace.tla` holds each of the state's functions whole with TLC's `@@`, which builds its
result whole, and the same walk takes under a second.

TLC's walks are uniformly random. The Lean walker's took, at each step, an event leading to a
state no walk had reached when there was one. So TLC's short walks catch fewer mutations of the
engine than the Lean walker's did, and the committed walks keep more of the full run's
(docs/mutations.md).

## The walks

The walks' model abstracts each lookup to how it ends. An end arrives when the lookup settles in
the table and is delivered when the consumer hands it to `on_event`, and the two are apart,
because the walk's cancel of the other family reaches a lookup that has not settled and not one
that has. Other consumers may take and give back the table's free slots between any two events.

`cocuyo-spec walks` walks every state the model reaches, depth first, under 95 configurations:
the sources in each order, with and without the name in the hosts table; one to three search
candidates; either family or both; a table of two or three slots; and the reverse walk under
each source order. Four invariants are checked in every state: the walk holds two slots at
most, none once it has ended, never more than the table has, and it waits for an end while it
runs. `tools/spec_replay/walk_replay.zig` drives both walks over a real table down all 66,565
transitions, restoring the parent's frame for each line as the lookup's replay does, and
compares the walk's whole state after each.

## Running it

- `zig build test` replays `tools/spec_replay/lookup_gate.txt`, a committed slice of 3,694
  transitions: one server, one pass and one name, over UDP, over TCP, over DoH and over DoQ. It also
  replays two sets of engine walks TLC wrote. `tools/spec_replay/engine_gate.txt` holds ten walks
  of forty events in each of the eight engine configurations. `tools/spec_replay/engine_picks.txt`
  holds seven walks of the full run, which `engine_picks` in `build/spec.zig` names: each is where
  the full run caught a mutation of the engine that the short walks miss (docs/mutations.md). The
  gate also holds `tools/spec_replay/walk_gate.txt`, the forward walk with two candidates and both
  families and every reverse configuration. It needs neither Lean nor Java.
- `zig build spec` needs `lake` on the path, at the version `lean/lean-toolchain` pins, and Java
  11 or newer for TLC. pepegrillo's `lean` tool builds the proofs and the axiom pins first. Then
  the step requires the committed slices to be the ones the models write, and replays the
  lookup's whole transcript, the walks' whole transcript, and TLC's full run: 2,000 engine walks
  of 200 events in each of the eight engine configurations, 3.2 million events. TLC wrote the
  full run in 241 seconds on an Apple M1 Pro busy with other work on 2026-09-24, and the replay
  took 17. `zig build spec-lean` is the Lean half alone, which needs no Java, and `zig build
  spec-engine` the engine's part alone, which needs no Lean.
- After a change to a model, `lake exe cocuyo-spec gate 8 > ../../tools/spec_replay/lookup_gate.txt`
  and `lake exe cocuyo-spec walks-gate > ../../tools/spec_replay/walk_gate.txt` in `lean/` write
  the Lean slices again. From the repository's root, `zig build tla -- walks 1 10 41 >
  tools/spec_replay/engine_gate.txt` writes the short engine walks, and `zig build tla -- walks 1
  2000 201 --pick tools/spec_replay/engine_picks.txt <walk>... > /dev/null` the picked ones, the
  walks named being `engine_picks`. A change to the engine model changes TLC's walks, so the picks
  are chosen again: `zig build mutations -- engine` breaks the engine each way
  `tools/mutations/engine.zon` says, and names the full run's first walk that catches each
  mutation the short walks miss.

The `8` is `cname_hops_max` of `src/core/constants.zig`. The transcript records it, and the replay
refuses a transcript written for another.
