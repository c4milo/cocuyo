# The lookup and the engine, in Lean

This directory holds three models in Lean 4, and `tools/spec_replay/` ties each to the Zig code:

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
- `Spec/Engine.lean`, `Spec/EngineSockets.lean` and `Spec/EngineStep.lean` are the engine
  model: the table's slots, free list and ready list, the connections, the sockets, the loop's
  operations, and a `Spec.Lookup` in each slot. `invariants` names what every state must keep.
- `Spec/EngineWalk.lean` walks the engine model: breadth first to check the invariants in every
  state reached, and in seeded walks for the replay.
- `Spec/Address.lean` is the model of both walks, and `Spec/AddressWalk.lean` walks it and
  writes its transcript.
- `Spec/Tokens.lean` spells states and events for the transcripts.
- `Main.lean` writes the transcripts the replays read.

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

## The engine

The engine model is written from the stream's rules and the datagram's rules of §19 step 13, the
TLS rules of §21, and rotor's decision 5, with two servers and one pass. A configuration asks
every query over TCP, every query over TLS, or every query over UDP with no answer truncated and
a port replaced every two queries, the old one draining beside the new. A TLS session is what it
does to the queue: the records it makes, which are sealed as it makes them, and the steps its
handshake takes, a flight to answer, the handshake's end or a failure, and later a KeyUpdate to
answer or a ticket to keep. A kept ticket may lapse at any moment, which stands for its lifetime
and the 7-day cap. It leaves out the timer, the bytes of a message, the TLS records' contents and the
cache. Time moves in ticks, each the idle close's
wait, and only when a deadline arrives or the caller lets a tick pass; a lookup waits two ticks.
Two faults stand in for a kernel under pressure: the loop refuses every submission for the length
of one event, as a full ring does, and every socket open fails for the length of one event, as a
process with no descriptor left sees.

`cocuyo-spec engine <tcp|udp|tls> <slots> <connections>` walks it breadth first and checks
sixteen invariants in every state:

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

The walk stops at six operations in flight, two failures a server and three queries a port,
since nothing else bounds the graph; `engine` takes the first two as its last two arguments, for a
configuration too big to walk at the defaults. A stream's send may come back short once a message, since a
second short send takes the path the first took and the model does not count octets. It
reported, on 2026-09-23:

| Transport | Slots | Connections | Operations, failures | States | Transitions | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
| TCP | 1 | 1 | 6, 2 | 1,038,503 | 14,908,528 | hold |
| UDP | 1 | 1 | 6, 2 | 5,848,772 | 85,609,860 | hold |
| TCP | 2 | 1 | 5, 1 | 11,014,930 | 125,509,380 | hold |

Two lookups on one TCP connection is where queries queue behind each other (the stream's rule 9),
and it did not finish at six and two in nine hours, so it was walked at five and one. The TLS
model has not been walked whole. One lookup on two connections ran an hour at four operations and
one failure without finishing, and broke no invariant in what it reached. Until the replay drives
TLS in §21 step 5, the TLS model rests on `engine-probe` walks of 400,000 events over seeds 1, 7
and 42, and on the mutations of docs/mutations.md that break it on purpose.

`cocuyo-spec engine-probe <tcp|udp|tls> <slots> <connections> <seed> <walks> <length>` walks one
configuration the seeded way below and stops at the first invariant broken, for a quick look before
the breadth-first walk.

The TLS configurations are walked and replayed like the others. The engine drives the twin's
session (`src/sim/sim_tls.zig`), whose records carry their plaintext unsealed and whose handshake
steps are one octet each. A walk's `tls:i:step` puts one step in a record on the receive at `i`,
an answer comes in a data record, and `lapse:v` drops the ticket kept for server `v`.

The replay cannot visit that many states, so `cocuyo-spec engine-walks` writes seeded walks that
take, at each step, an event leading to a state no walk has reached yet when there is one. Each
line is an event and the model's whole state after it. `tools/spec_replay/engine_replay.zig`
drives the engine of `io/` over the twin in manual mode, where every operation waits until the
walk ends it with the outcome it names, and the twin refuses what the walk says to refuse, which
is how the replay reaches the orders rotor's rule 2 allows. After each event it compares the
engine's state with the model's, and requires every buffer the event handed the engine to be
back in its group.

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

- `zig build test` replays `tools/spec_replay/lookup_gate.txt`, a committed slice of 2,910
  transitions: one server, one pass and one name, over UDP and over TCP. It also replays
  `tools/spec_replay/engine_gate.txt`, ten engine walks of forty events in each of the eight
  engine configurations, and three walks of the full run that `engineGatePicks` in `Main.lean`
  names: each is where the full run caught a mutation of the engine that the short walks miss
  (docs/mutations.md ET8, ET10, ET11 and ET14). The model regenerates a picked walk by walking its
  configuration up to it, so it is the full run's walk byte for byte. The gate also holds `tools/spec_replay/walk_gate.txt`, the forward walk with two
  candidates and both families and every reverse configuration. It needs no Lean.
- `zig build spec` needs `lake` on the path, at the version `lean-toolchain` pins. It builds the
  proofs and the axiom pins, requires the committed slices to be the ones the models write, and
  replays the lookup's whole transcript and 2,000 engine walks of 200 events in each of the eight
  engine configurations, 3.2 million events, and the walks' whole transcript. It took about a
  minute and a quarter on the machine of design §11 on 2026-09-23, with six configurations, most
  of it the model writing the engine's walks.
- After a change to a model, `lake exe cocuyo-spec gate 8 > ../tools/spec_replay/lookup_gate.txt`
  `lake exe cocuyo-spec engine-gate > ../tools/spec_replay/engine_gate.txt` and
  `lake exe cocuyo-spec walks-gate > ../tools/spec_replay/walk_gate.txt` in this directory write
  the slices again.

The `8` is `cname_hops_max` of `src/core/constants.zig`. The transcript records it, and the replay
refuses a transcript written for another.
