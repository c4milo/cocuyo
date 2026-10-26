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
- `lean/Spec/LookupProofs.lean` and the three modules under `lean/Spec/LookupProofs/` hold the
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
  - `tcpReady_expires`: the caller may deliver the deadline in `tcpReady`, and after it the lookup
    is not in `tcpReady` (design §5; §16 decision 52). So a query's send that never ends holds no
    lookup past its deadline.
  - In `LookupProofs/Cause.lean`, `failure_cause`: a lookup that fails with `allServersFailed`
    holds a cause, and one that fails with `timeout` holds none, whatever the caller tells it
    (design §5, The cause of a failure; §16 decision 45). Since 2026-10-21 it proves too that the
    cause names a server of the configuration (§16 decision 51). Its lemma `keep_server` reads no
    more of `keep` than the bound of that server, so an edit of `keep` meets the check of the
    slice, and not a proof that stops.
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
  `tla/engine/mutants/` breaks the model's TLS rules, the stream's rule 9, the request rules, the
  channel's rules, the datagram's rules 4 and 6 and the deadline of `tcpReady` with
  `tla/engine/EngineMutants.tla`.
- `tla/engine/EngineTrace.tla` writes TLC's walks for the replay, one configuration of
  `tla/engine/trace/` for each of the replay's.

## What the lookup model leaves out

- Time. A poll comes before the deadline or at it, and nothing else about the clock matters to a
  transition. So the wait's length is left out too, which since 2026-10-09 comes from each
  server's measured latency, a try that ran out counting as a sample as long as its wait
  (docs/design.md §5). The model did not change for either. Since 2026-10-20 a try that a reply
  to it marked is no sample, and that reply is the model's unmatched reply (docs/design.md §16
  decision 50). The deadline after it moves the lookup as each deadline does, so the model did not
  change for that either.
- The message. A reply is what §7's checks and §5's rcode policy make of it: unmatched, an answer,
  a CNAME to a new name, NXDOMAIN, NODATA, a server failure, FORMERR, TC=1 with nothing else, or
  BADCOOKIE. Since 2026-10-14 a datagram that the buffer cut can move a lookup. When the lookup
  waits over UDP and the datagram passes the checks of a cut datagram, the lookup moves as TC=1
  moves it (docs/design.md §7, A datagram that the buffer cut). So the model's TC=1 stands for it
  there, and its unmatched reply everywhere else. No transition changed, and only the comment of
  TC=1 says so. The replay checks both claims (below). A cut datagram tells the server's state
  nothing. The model holds no such state but the cause of the last server failure, and TC=1 does
  not touch that.
- The server order of §19 step 12. The model counts a position in the order, which is what the
  lookup's `server_index` is. A cause names its server by that position too. The Zig cause names
  the configured server, and the replay finds that server's position in the lookup's order.
- TLS. A stream of the model is TCP's, so a failed connection never gives `handshake`. The unit
  tests of `src/resolver/lookup_failure.zig` and of `io/` show that reason (docs/design.md §16
  decision 51).
- Entropy, the cookies' values and the answers' records. Which COOKIE option a query carries,
  none, a fresh client cookie or the server's pair, and a server's silence (docs/design.md §19
  step 10) change no transition: a response that check 6 refuses is an unmatched reply. Nor does
  whether a query mixes the case or goes in lowercase, to a server marked as one that lowercases
  the name (docs/design.md §7, since 2026-10-09): a reply whose question differs in case alone is
  an unmatched reply, and the wait stands.
- Every TTL: a record's, the negative TTL of RFC 2308 §5, and the bounds the CNAME chain and the
  search walk put on what a lookup ends with (docs/design.md §5). They change no transition.
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
time is written but not walked again, so each transition appears once, 20,512,658 of them in all,
183 deep at most. On 2026-10-08 a first BADCOOKIE over a stream became a retry on the stream with
the fresh server cookie (docs/design.md §5, §19 step 10; c4milo/cocuyo#36), where before it
advanced the server. The retry reaches states the walk did not reach before: the transcript held
2,237,654 transitions, 168 deep, and the slice below 3,694.

On 2026-10-17 the cause of the last server failure replaced the flag that a server failed
(docs/design.md §5, The cause of a failure; §16 decision 45). A state holds the cause now, so
two states that differ in their cause alone are walked apart. The transcript grew from 2,680,454
transitions, 173 deep, to 7,530,842, 183 deep, and the slice below kept its 4,414 lines. An ended
state's cause is not part of what makes it new to the walk: each line below it repeats the cause,
which the line that reached it checked. In that slice one pass ended a lookup at its first server
failure, so no lookup ran with a cause, and no cause replaced another. So the slice gained one
server with two passes over DoH, 2,282 transitions more, and holds 6,696.

On 2026-10-21 the cause came to name the position of its server. A failed connection or request
came to carry its reason (docs/design.md §16 decision 51). The model's events `tcp_failed` and
`request_failed` each take a reason, and the transcript spells one as `tcp_failed_connect`. A
cause is spelt as what the server gave and that position, as `servfail@1`. A stream before it is
up takes `connect` or `local`, and after it `closed`. A request takes each reason over DoH, and all
but `connect` and `status` over DoQ. States that differ in a reason or a server alone are walked
apart. So the transcript grew from 7,530,842 transitions to 19,921,682, 183 deep. The slice gained
two servers and one pass over DoQ. There a cause can name a server that the lookup is not on at its
end. The slice grew from 6,696 transitions to 13,694.

On 2026-10-24 a deadline came to end `tcpReady` (docs/design.md §5; §16 decision 52). The model's
`waiting` holds `tcpReady`, so `expire` is an event of that state, and it moves the lookup as in
`connectingTcp`. A reply in `tcpReady` is still the unmatched reply alone: `listens` holds the
stages where each reply comes, as `waiting` held them before. So the transcript gained one line for
each state in `tcpReady`. It grew from 19,921,682 transitions to 20,512,658, 183 deep. The slice
grew from 13,694 transitions to 13,838, and none of its lines changed.

`tools/spec_replay/replay.zig` drives `Lookup` down the same tree. It builds each reply around the
question the lookup is asking, and it compares the answer and the state after every event: the
stage, the server's position, the pass, the candidate, the hops, the flags EDNS0, NODATA seen, a
server failed and the cookie retried, and the cause the lookup holds. A failed lookup's cause is
read from the `Failure` it reports. A field that drifts is caught at the event that moved it.
The cause ends each line of the lookup's transcript, after the state. The engine's walks spell a
lookup without it: the engine model keeps the flag that a server failed, since which cause a
lookup holds changes no transition of the engine (`replay_text.zig`).

Since 2026-10-14 the replay also hands a cut datagram to the lookup at each `reply_truncated`
line (`tools/spec_replay/replay_cut.zig`). The datagram is the answer to what the lookup asks,
less its last octet. It goes to the lookup that the line's parent left, before the line's own
event:

- Where that lookup waits over UDP, the cut datagram must answer and move as the line's TC=1 does.
- Everywhere else, over DoH or DoQ, on a stream or once the lookup has ended, it must be ignored
  and leave the parent's state, as the unmatched reply does.

The transcript reaches each state with a `reply_truncated` line, so each state gets a cut
datagram. No line of the transcript changed for it.

## The engine

The engine model is written from the stream's rules and the datagram's rules of §19 step 13, the
TLS rules of §21, the request rules of §24, and rotor's decision 5, with two servers and one pass.
A configuration asks every query over TCP, every query over TLS, every query as a request over DoQ
or DoH, or every query over UDP with a port replaced every two queries, the old one draining beside
the new. Over UDP no answer is truncated, but in the configurations that set `Truncates` since
2026-10-14 (below). A TLS session is what it does to the queue: the records it makes, which are
sealed as it makes them, and the steps its handshake takes, a flight to answer, the handshake's end
or a failure, and later a KeyUpdate to answer or a ticket to keep. A kept ticket may lapse at any
moment, which stands for its lifetime and the 7-day cap. It leaves out the timer, the bytes of a
message, the TLS records' contents and the cache. So the stream's rule 11 and TLS rule 7 are not in
it, since they count octets. In the model a message reaches its lookup at the receive that brings
it, and rule 11 asks the same of the code. Time moves in ticks, each the idle close's wait, and
only when a deadline arrives or the caller lets a tick pass; a lookup waits two ticks. Two faults
stand in for a kernel under pressure: the loop refuses every submission for the length of one
event, as a full ring does, and every socket open fails for the length of one event, as a process
with no descriptor left sees.

TLC walks it breadth first (`zig build tla`) and checks these rules in every state and every
event, and the channel's rules below:

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
- A connection slot's records buffer is lent to one send at most, of whichever incarnation. A
  query's send that reads it is its connection's head, or the slot is closed. Over TLS each send
  names the buffer that it reads, and in the clear no operation names one.
- The sealed entries lead each queue, only its head among them a query, and something is sealed
  only while a send is in flight: records go out in the order they were sealed.
- No query waits on a connection that is not up.
- A lookup ready to send on a stream finds its connection up. The model asserts it where the
  query goes out, and TLC stops at a walk that breaks it (docs/design.md §17 question 66).
- No event leaves the session owing an answer to a flight, the handshake's end or a KeyUpdate.
- A connection that opens resuming spends its server's ticket, so a ticket is used once.
- A connection opened again after its resumed handshake failed handshakes in full.
- A resumed handshake that fails counts no failure against its server and keeps its lookups on
  the connection, unless the loop refuses the connect again.
- A request slot is free, or its request waits on its server's connection or has a stream there,
  never both, and a connection holds only its server's requests.
- A request has a stream only on a connection that is up, and waits only on one that is not.
- Every request speaks for its lookup's attempt: one its lookup left is cancelled.
- A closed connection holds nothing and owes nothing.
- A connection's datagram buffer is lent exactly when one send of it is in flight, whichever
  incarnation made it.
- A connection is up only on its transport's protocol.
- A connection has at most one current receive, and none once closed; after a drive with nothing
  refused, every open connection has its receive.
- A connection that opens resuming spends its server's ticket.
- A connection that fails while it closes fails none of the requests that wait on it.
- After the clock moves, no TLS connection that closed before still closes: the idle close's wait
  bounds it (docs/design.md §16 decision 49).
- A lookup in `tcpReady` has its deadline armed, or is offered with its deadline passed
  (docs/design.md §16 decision 52).
- After the clock reaches the deadline of a lookup in `tcpReady`, it is not in `tcpReady` on the
  same try.
- A query's send on a connection that is up has a lookup on that connection. When the last lookup
  leaves during that send, the drive shuts the connection (docs/design.md §16 decision 53).

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

A request connection is what colibri tells the engine: that it owes a datagram, that the
handshake ended on the transport's protocol or on another or failed, that a stream was answered
or reset, that the server closed, that a ticket came, and that its QUIC timer fired, to resend or
to give up. An answer stands for a DoQ message, and a reset for a reset stream. DoH went over these
connections too, and moved alike, until colibri's channel took it (decision 33). Until 2026-09-29 a
GOAWAY drained the connection, as request rule 13 had it. DoQ has none (RFC 9250), and the drain
went (c4milo/cocuyo#33). The request configurations, walked again on 2026-09-26 once request rule
13 drained a connection on GOAWAY, on an Apple M1 Pro with no other check running, three
operations and one failure:

| Servers | Lookups | States | Seconds | Invariants |
| --- | --- | --- | --- | --- |
| 1 | 1 | 28,328 | 3 | hold |
| 1 | 2 | 326,032 | 35 | hold |
| 2 | 1 | 7,396,714 | 742 | hold |

Before request rule 13 they held 24,192, 257,212 and 5,295,912 states, and before the kept
datagram 19,712, 210,148 and 3,140,695. Checked again on 2026-09-29, once the TCP connections
went, they hold the same states, and so does every other configuration. Once the drain went the
same day, they hold 24,192, 257,212 and 5,305,638 states, the first two what they held before rule
13.

Every stage was reached: a connection up with a request on a stream, one closing, a lookup
answered, one failed after its request failed, and a connection opened again while an earlier
incarnation's datagram was still in flight. Twelve mutants in `mutants/` break the request rules,
and TLC finds each (docs/mutations.md RQ1 to RQ11 and RQ14). RQ12, RQ13 and RQ15 broke the drain,
and went with it.

The request connections over TCP, DoH over HTTP/2 under request rules 14 to 17, were modelled
from 2026-09-26 with `RStream`, and seven mutants broke them (docs/mutations.md RQ16 to RQ22).
They went on 2026-09-29 with `cocuyo_h2` (decision 33): colibri's channel carries DoH over TCP,
and a channel's TCP link holds rules 14 to 16 (below). Their three configurations last held 54,756,
729,476 and 21,061,842 states.

With `Channel` a DoH server's requests go through colibri's channel, as request rules 18 to 25 have
them (`EngineChannel.tla`): a channel for each server, and for each channel a QUIC link over a
datagram socket and a TCP link over a stream socket, which the engine opens and closes when the
channel says. At any read the channel may say whatever its calls allow: open a link it has none of
while it holds exchanges, close one it asked for, owe octets or a ticket on a running one, end an
exchange, hold one while a link's send is in flight, and closed once shut down with every link
closed. Which link it opens when is colibri's choice, and colibri's own model holds it, so here the
channel may open either. The channel configurations, checked on 2026-09-28 on the same machine,
three operations and one failure. The second took its time while other checks ran, and its header
says `\* nightly:`:

| Servers | Lookups | States | Seconds | Invariants |
| --- | --- | --- | --- | --- |
| 1 | 1 | 1,672,552 | 172 | hold |
| 1 | 2 | 14,986,512 | 1,724 | hold |

Checked again once the replay moved the model (below), both hold the same states. It reached a TCP
link waiting for an earlier opening's connect, a link closing, both links running, a link started
with a ticket, the TCP link keeping octets to send, a channel shutting down with a request waiting
for the next, one holding an exchange's end, and a lookup answered through the channel. Answers and
failures alone reach the channel, since a lookup moves on the other replies as it does on these, and
the channel not at all. Ten mutants break the channel's rules, and TLC finds each (docs/mutations.md
CH1 to CH10).

The replay walks the request configurations as it walks the others, with one slot or two and two
servers, over the twin's QUIC (`sim.quic`). A step of colibri's is one item in a datagram on the
connection's receive: a flight while the handshake runs and a PING once up for the model's
`datagram`, the handshake's end on `doq` or on another protocol, its refusal, the server's close, a
ticket, and an answer or a reset on the slot's stream. The model has no timer, so the replay makes
a connection's QUIC timer due at the instant the walk reaches its `qtime`, and fires the engine's
one timer there. Writing the replay moved request rule 8: a datagram the loop refuses stays in the
buffer and goes at the next drive, before whatever colibri makes after it, and the model keeps it
apart from what colibri owes.

The TLS configurations are walked and replayed like the others. The engine drives the twin's
session (`src/sim/sim_tls.zig`), whose records carry their plaintext unsealed and whose handshake
steps are one octet each. A walk's `tls:R0*:flight` puts one step in a record on the receive that
`R0*` names, an answer comes in a data record, and `lapse:v` drops the ticket kept for server
`v`.

The channel configurations are replayed over the twin's channel (`sim.channel`), which says the
steps the replay queues on it. A walk's `chan:open:1:0:-` has server 0's channel open its TCP
link. A link's step names the link: twice its server for the QUIC link, and one more for the TCP
link. The channel's other steps name the server, then the exchange's slot and how it ended. The
replay queues the step, which the twin says at the engine's next read, and fires the engine's
timer, since the twin is due at once while it has a step queued. A link's operations are `A` for
the TCP link's connect, `W` for a send and `Y` for a receive. The line writes each channel after
the requests: its stage, its exchanges, the requests waiting for the next channel, the end it
holds, `I` when it went idle at this instant, and each link's state and flags. The engine keeps a
send's octets counted until the send ends, so that a short one's rest is known, and `K` is written
only while none of the link's sends is in flight: the model keeps only what waits for a send.

Writing the replay moved the model twice, to rules 17 and 19. The engine reads a channel after
it puts a request on it, and after a link that waited for an earlier connect fails to open at
that connect's end. The model read it at neither, so an end the channel held was told in the
engine and still held in the model. The twin moved once: a new channel keeps what a test reads of
the links, since a link the last channel closed is the engine's until its socket shuts.

The replay cannot visit that many states, so it follows walks TLC takes through the TLA+ model
(below). Each line is an event and the model's whole state after it.
`tools/spec_replay/engine_replay.zig` drives the engine of `io/` over the twin in manual mode,
where every operation waits until the walk ends it with the outcome it names, and the twin refuses
what the walk says to refuse, which is how the replay reaches the orders rotor's rule 2 allows.
After each event it compares the engine's state with the model's, and requires every buffer the
event handed the engine to be back in its group. The model's wait is two ticks, fixed, and since
2026-10-09 the engine's comes from each server's latency (docs/design.md §5). The replay's
configuration caps every wait at two ticks, under the 250 ms floor, and a cap below the floor
wins, so every wait the engine arms is the model's, whatever samples the tries that ran out add.
So no walk runs servers that wait different times, where a lookup sent later can run out sooner.
The model holds no cache. Since 2026-10-11 the engine has one only when its caller hands it the
memory (docs/design.md §19 step 13), and the replay hands its engine two slots, the size it had
as an option before. Each start of a walk asks a new name, so the cache answers none.
The table's bound on the soonest deadline takes any deadline a lookup arms, and a test in
`src/resolver/table_ready.zig` arms a later send with an earlier deadline, but no walk does.

## The engine in TLA+

`tla/engine/` holds the engine model in TLA+, checked by TLC through pepegrillo's `tla` tool
(docs/design.md §16 decision 24). It was ported from the Lean model, definition by definition:
`EngineTable.tla` holds the configuration, the lookup's transitions the engine asks of it, the
table and the connections; `EngineIo.tla` the sockets and the sends; `EngineRequest.tla` the
requests over DoQ, and `EngineChannel.tla` DoH through colibri's channel (§24); `EngineEvents.tla`
the drive and the events; and `Engine.tla` the checks and the specification. `EngineEvents.tla`
was split from `Engine.tla` on 2026-09-27 by the file-length rule, with nothing moved past what it
came before: TLC orders strings as it first reads them, so a check read ahead of the events would
change the order of their successors, and with it every walk. The Lean model retired once the
replay read its walks from TLC.

Three choices make TLC count what the Lean walker counts:

- The loop's operations are a bag, so an event names an operation by its value, and a state is one
  state whatever order its operations came in: the Lean walker's sorting, made native.
- The bound guards `Next` rather than being a `CONSTRAINT`. A state beyond it is reached, counted
  and checked, and has no successor, as in the Lean walker; TLC leaves a state that breaks a
  `CONSTRAINT` out, and the check on the event that reached it with it. So every configuration
  says `CHECK_DEADLOCK FALSE`.
- Seventeen of the fifty checks read the event or the state before it, which a TLC
  invariant cannot. So `broken` holds the names of the checks the last event broke, and `Clean`
  asks it be empty. In a model that keeps its rules it always is, so it splits no state.

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

On 2026-09-27 a refusal started saying its alert before its connection closes, and a connection
that is up could refuse a record (TLS rule 4, c4milo/cocuyo#31), which added the states of a
connection closing after a refusal. On the same Apple M1 Pro TLC counted 68,678 states at 2, 0,
413,862 at 2, 1 and 2,138,766 at 3, 0, where the table above has the counts before it, and
1,687,238 for two slots at 2, 0. The Lean walker, retired, counts none of the new ones.

TLC walked these 1.7 to 5.6 times slower than the Lean walker, the gap narrowing as the graph
grows. It adds a fingerprint per state in place of the whole state, a queue on disk and worker
threads, and it reports a shortest counterexample. The last row is not in `zig build tla`: it took 4.3 GB and ran on a machine busy with other
work, beside the Lean walker's run of the same row. `tla/engine/mutants/` breaks the TLS rules the
Lean model's mutations broke, TM1 to TM3 and R8a to R8d, rule 4's alert as R4a and R4b break
it, and the stream's rule 9 as TQ1 breaks it (below). TLC must find each broken (docs/mutations.md).

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

On 2026-10-08 a SERVFAIL reply started counting a failure against its server, as a timeout does.
Before, every reply the lookup accepted reset the count (docs/design.md §19 step 12,
c4milo/cocuyo#37). A server whose failures pass `FailuresMax` makes a state beyond the bound, and
TLC walks from no such state. Every way a lookup moves to the next server now records a failure
first: a timeout, a send that failed, a connection or a handshake that failed, a request that
failed, and a SERVFAIL. Before, a SERVFAIL was the one way that recorded none. So where the bound
is no failure, the walk stops at the first of them and never reaches the second server. Where it
is one failure, the walk still reaches it. Every configuration holds, and every mutant of
`mutants/` is still caught. TLC counted each configuration's states, the model before the change
and after, on an Apple M1 Pro while other checks ran. The connections are `Conns`, the stream
connections: a request configuration has none, and a request connection for each server instead.

| Transport | Servers | Slots | Connections | Operations, failures | Before | After |
| --- | --- | --- | --- | --- | --- | --- |
| TCP | 2 | 1 | 1 | 4, 1 | 22,684 | 18,625 |
| TCP | 2 | 2 | 1 | 4, 1 | 834,131 | 561,813 |
| TCP | 2 | 2 | 2 | 4, 0 | 223,428 | 59,420 |
| TLS | 2 | 1 | 2 | 2, 0 | 68,678 | 15,449 |
| TLS | 2 | 1 | 2 | 2, 1 | 413,862 | 252,573 |
| TLS | 2 | 1 | 2 | 3, 0 | 2,138,766 | 286,964 |
| TLS | 2 | 2 | 2 | 2, 0 | 1,687,238 | 243,462 |
| UDP | 2 | 1 | 1 | 3, 1 | 38,457 | 25,385 |
| UDP | 2 | 1 | 1 | 4, 1 | 115,774 | 70,400 |
| UDP | 2 | 2 | 1 | 4, 0 | 1,534,175 | 64,745 |
| Request | 1 | 1 | 0 | 3, 1 | 24,192 | 22,688 |
| Request | 1 | 2 | 0 | 3, 1 | 257,212 | 217,540 |
| Request | 2 | 1 | 0 | 3, 1 | 5,305,638 | 2,897,539 |

The channel configurations hold the same states as before, 1,672,552 and 14,986,512, since a
lookup on a channel hears answers and failures alone (above). TCP with one lookup held 22,684
states before the change, where its header still gave the Lean walker's 19,767, and two lookups
on one connection held 834,131, where the table above has 758,374, and two lookups on two
connections held 223,428, where it has 223,480. Some change after 2026-09-24 moved the three
counts without recording them.

Five configurations were bounded at no failure, and after the change none of them reached the
second server: TCP with two lookups and two connections, TLS with one lookup at two operations and
at three, TLS with two lookups, and UDP with two lookups. TLC checked this on 2026-10-08 on the
same machine, with one more invariant in a copy of the model: every state it walks from has each
lookup at the first place of its order, that place the first server, and each connection closed or
to the first server. The invariant held in all five, at the counts in the table above. The model
before the change broke it in each of the five within 1,625 distinct states. The model after it
breaks it within 26 distinct states in each of the six configurations of two servers and one
failure. So from 2026-10-08 to 2026-10-09 no configuration TLC checked had any of these:

- Two lookups, one of them on the second server, over UDP, over TLS, or over TCP with two
  connections.
- Two TCP connections open at once, one to each server.
- One lookup on the second server over TLS at three operations.

One lookup over TLS still reached the second server at two operations and one failure
(`Engine_tls_1_2_bound_2_1`). So did two lookups on one TCP connection, one lookup over TCP or over
UDP, and the request configuration of two servers. The walks the replay reads have no bound:
`EngineTrace.tla`'s step reads no `Within`. The short walks take a lookup to the second server in
each of the twelve configurations they walk.

On 2026-10-09 the coverage came back. TLS with one lookup at two operations and no failure went,
since `Engine_tls_1_2_bound_2_1` is the same configuration at one failure. The other four went to
one failure, and their names with them: `Engine_tcp_2_2_bound_4_1`, `Engine_tls_1_2_bound_3_1`,
`Engine_tls_2_2_bound_2_1` and `Engine_udp_2_1_bound_4_1`. In a copy of the model, each of the
four breaks that invariant within 6 distinct states, so one lookup reaches the second server over
TLS at three operations again. Two more invariants show the rest of the list reached again:

- Two lookups, one of them on the second server, within 21 distinct states over TCP with two
  connections, 19 over TLS and 35 over UDP.
- Two TCP connections open at once, one to each server, within 5.

TLC checked the four on 2026-10-09 on the same machine, one at a time, with ten workers, while
other work ran:

| Configuration | States | Depth | Seconds | Invariants | CI checks it |
| --- | --- | --- | --- | --- | --- |
| `Engine_tcp_2_2_bound_4_1` | 2,438,035 | 62 | 187 | hold | on each push |
| `Engine_tls_1_2_bound_3_1` | 9,004,551 | 53 | 735 | hold | once a day |
| `Engine_tls_2_2_bound_2_1` | 16,382,680 | 75 | 1,111 | hold | once a day |
| `Engine_udp_2_1_bound_4_1` | 13,390,228 | 78 | 793 | hold | once a day |

On 2026-10-08, with three workers each and two or three of them at once, TLC had taken 9 minutes
over the first and 38 over the second, and had not finished the last two in 40, past 11,912,347
and 12,470,699 states. The three checked once a day say `\* nightly:` in their headers, as the
channel's of two lookups does. `.github/workflows/tla-nightly.yml` checks each configuration so
marked in a job of its own, and every other configuration and mutant in one more. Until 2026-10-09
one job checked them all, 29 million states, and the configurations now hold 62 million.

The largest configuration CI checks on each push holds 2,897,539 states, and the largest it checks
once a day 16,382,680.

On 2026-10-14 a datagram that the buffer cut began to send its lookup to TCP, once it passes the
checks of a cut datagram (docs/design.md §7; §16 decision 43; §19 step 13, the datagram's rule
6). Until then no configuration held a truncated UDP answer. A message's four replies were an answer,
NXDOMAIN, SERVFAIL and an unmatched message, so no lookup went from a socket to a connection. The
model holds no octets, no mark of the kernel and no cookie. So it holds the rule as two more
replies of a datagram: TC set, and a cut datagram that passes the checks. Each sends its lookup
to `tcpNeeded` on the same server. TC set counts as the server's success, and a cut datagram
counts nothing. A cut datagram that fails a check is the unmatched reply. `Truncates` offers the
two replies. It is an operator, false in the model, and three configurations set it with
`Truncates <- Truncating`:

- `Engine_truncated_1_1_bound_4_1`, which TLC checks;
- `trace/Trace_udp_truncated_1_1`, whose walks the replay reads;
- the mutant `mutants/OA34`.

So no other configuration, mutant or walk changes.

TLC checked the configuration on 2026-10-14 on an Apple M1 Pro while other work ran: 426,197
states, which hold, in 32 seconds. In a copy of the model, an invariant that says a state is
never reached broke within these distinct states. So the configuration reaches each state:

- a lookup in `awaitingTcp`: 273;
- a lookup that moved to a stream after its query left a draining socket: 6,022.

At three operations the configuration held 33,347 states and reached neither. A stream's send is
a fourth operation beside the receives of the two sockets, so the configuration is checked at
four.

The mutant OA34 keeps a draining socket open while the lookup whose query left it waits on a
stream, as the code's OA33 does. TLC finds the check "rotated" broken within 1,000 distinct states.
The same mutant without `Truncates` holds in 70,400 states, the count of
`Engine_udp_1_1_bound_4_1`, whose constants are the same. So the configuration catches a broken
rule that no other configuration reaches.

The trace configuration is the replay's `Trace_udp_1_1` with `Truncates` set. Its name sorts last,
so its walks come after the twelve configurations' walks, and no walk picked before moves. TLC
writes the first twelve configurations' walks as it wrote them before, octet for octet. The short
walks gain ten walks, with two cut datagrams and one TC answer among them. The full run gains
2,000 walks, with 1,179 cut datagrams and 1,220 TC answers. Of those, 520 and 570 come on a
draining socket's receive. Its walk 24001, the first of the new walks, catches OA29 and OA33,
which the short walks miss, so it is a pick (docs/mutations.md, The owner's answers of
2026-10-14).

On 2026-10-18 a lookup that finds no free connection slot began to wait for a slot that frees with
no lookup leaving it (docs/design.md §19 step 13, the stream's rule 12; §16 decision 46). Until then
the engine told it at once that its connection failed. The review of the same day amended the rule
in the clear. There, when no slot is pending, the lookup closes a connection that no lookup is on
while its connect is in flight. The model holds the rule as the code does:

- Each slot of the table holds `waits`. `Want` sets it while a slot is pending, and `Act` clears it
  at the lookup's next poll that acts.
- `Frees` says which connection slots are pending: a connection that closes, and a closed slot that
  the loop borrows.
- In the clear, with no slot free and no closed slot borrowed, `FreeConn` closes a connection. It
  closes the first one that no lookup is on and the loop borrows, and its slot is then pending.
- `Admit` runs at the drive's end, after the idle close. Each lookup that waits joins its server's
  connection, or opens one as `Want` does. A slot it cannot have, or a refusal, leaves it waiting.
- Four checks hold the rule: "waits connecting", "waits for no free slot", "told when up" and "slot
  waited for". The last reads `slotless`. `Want` sets it when it tells a lookup its connection
  failed, with no socket or submission refused. It sets it over TLS, and in the clear while a slot
  has no lookup on it. `slotless` reads neither `FreeConn` nor `Pending`, so the rule judges a
  mutant of the engine's choice.

TLC checked each configuration on 2026-10-18 on an Apple M1 Pro while other work ran. The first
form is the rule before the review:

| Configuration | Before | First form | Now |
| --- | --- | --- | --- |
| `Engine_tcp_1_1_bound_4_1` | 18,625 | 22,847 | 20,098 |
| `Engine_tcp_2_1_bound_4_1` | 561,813 | 914,106 | 690,360 |
| `Engine_tcp_2_2_bound_4_1` | 2,438,035 | 3,466,275 | 3,466,275 |
| `Engine_tls_1_2_bound_2_1` | 252,573 | 294,898 | 294,898 |
| `Engine_tls_1_2_bound_3_1` | 9,004,551 | 11,259,959 | 11,259,959 |
| `Engine_tls_2_2_bound_2_1` | 16,382,680 | 28,446,316 | 28,446,316 |
| `Engine_truncated_1_1_bound_4_1` | 426,197 | 451,556 | 427,125 |

The other configurations, of UDP alone, of DoQ and of DoH, hold the states that they held before.
With two slots and two servers, a lookup that finds no free slot always finds one pending, so it
closes no connect there. So the largest configuration CI checks on each push holds 3,466,275
states, `Engine_tcp_2_2_bound_4_1`. The largest it checks once a day holds 28,446,316,
`Engine_tls_2_2_bound_2_1`. Four mutants break the rule, and TLC finds each:

- `mutants/TS11`: no slot is ever pending, which is the engine before the change. Over TLS with one
  lookup it breaks "slot waited for".
- `mutants/TS12`: only a connection that closes is pending. Over TCP it breaks "slot waited for".
- `mutants/TS13`: the drive's end admits no lookup. Over TCP it breaks "waits for no free slot".
- `mutants/TS18`: `FreeConn` as it was in the first form, which closes no connect. Over TCP it
  breaks "slot waited for".

The trace writes a lookup that waits as `cw`, in place of `c-`. So a walk where no lookup waits is
written octet for octet as before. Of the short walks, 11 of 130 hold a wait. The first form changed
those 11. The review's rule changed ten of them again, five over TCP with one lookup and five over
TCP with two lookups on one connection. The full run holds 23,831 states in which a lookup waits,
where the first form held 26,687, and its replay agrees with the engine over 5,226,000 events.

The picks were chosen again after the review (docs/mutations.md, A pass that waits for a connection
slot). `zig build mutations -- engine` ran each of the 80 rows that the walks catch against the new
full run. The short walks catch each row they caught before. The tool named the full run's first
walk that catches each row that they miss, and those fifteen walks are the picks now. Against the
fourteen picks before the change, walks 8025, 8241 and 12004 came in, and walks 13182 and 17842
left. Each of the 24 rows that the picked walks catch is `CAUGHT` by the new picks.

On 2026-10-18 a query's send began to lend its connection's records buffer, as a send of the
session's own records does (docs/design.md §21, TLS rule 3; §16 decision 47). Over TLS a query is
sealed into that buffer, and its send reads it there. Until then only a send of the session's own
records borrowed the slot. So a connection that failed during a query's send left its slot free.
A new opening then wrote its hello over the octets that the loop could still read. The model held
the same gap, and the change came to the model first:

- Each operation holds `buffer`, the connection slot whose records buffer it reads, as a set of
  one. Over TLS `Pump` gives each send its connection: a query's send and a send of the session's
  records. In the clear a query's send reads its lookup's own buffer, and every operation holds
  none. So no configuration in the clear changes.
- `Borrowed` reads a connect of the slot, and each operation whose `buffer` names the slot.
- The check "records lent" holds the rule. A slot's records buffer is lent to one send at most, of
  whichever incarnation. A query's send that reads it is its connection's head, or the slot is
  closed.
- The same check requires that each operation names the buffer that it reads. Over TLS a send of
  the session's records names its own connection. A query's send names the connection that its
  query heads, or a closed slot. In the clear no operation names one. The review of the change
  added this part, since without it the check read only what `Pump` wrote.
- `mutants/TB5` puts back `Borrowed` as it was. TLC finds "records lent" broken at the seventh
  state of its counterexample. A connection fails while its query's send is in flight, and the
  lookup's next pass opens the slot again.
- `mutants/TB8` puts back `Pump` as it was, where a query's send names no buffer. Before the review
  TLC found no error in it over 294,898 states, the count before the change. Now TLC finds "records
  lent" broken at the sixth state, where the query's send names no buffer.

TLC checked each configuration on 2026-10-18 on an Apple M1 Pro while other work ran:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tls_1_2_bound_2_1` | 294,898 | 297,743 |
| `Engine_tls_1_2_bound_3_1` | 11,259,959 | 11,165,668 |
| `Engine_tls_2_2_bound_2_1` | 28,446,316 | 28,696,711 |

A closed slot that a query's send borrows is pending now. So a lookup's next pass opens the other
slot, or waits, where it opened the same slot again before. That adds states of a slot that frees
at the send's event, and removes states of a second opening beside the send. The largest
configuration CI checks once a day now holds 28,696,711 states, `Engine_tls_2_2_bound_2_1`.

The configurations in the clear, of DoQ and of DoH hold the states that they held before. The
second part of the check adds no state and changes no walk. The short walks did not change. Of
the full run's 26,000 walks, 16 changed, all over TLS: 2 with one lookup and 14 with two. In each
a connection failed while its query's send was in flight, and that send has not ended. The model
opened the same slot again there before, and now opens the other. The replay of the full run
agrees with the engine over 5,226,000 events.

None of the fifteen picks was among the 16 walks, so the replay of the gate did not reach the new
path. The row TB9 breaks the engine as TB4 does, with no assertion to help, and the walks must
catch it. The short walks and the picks missed it, and the full run caught it first at walk 16271.
That walk has one lookup and two servers over TLS. At its event 100 the connection fails while
its query's send is in flight, and the lookup's next pass connects in the other slot. So walk
16271 is the sixteenth pick, and the replay of the gate now drives that path.

On 2026-10-20 the idle close's wait began to bound a connection that closes (docs/design.md §21,
TLS rule 5; §16 decision 49). Until then a TLS connection that closed freed its slot only at the
end of its last send. A peer that stopped reading held that slot for ever. The model held the same
gap: `CloseIdle` passed over a connection that closes. The change came to the model first:

- `CloseIdle` shuts a connection that closes, as it shuts each connection that no lookup is on.
  A tick is the idle close's wait, so the first move of the clock after the connection began to
  close shuts it. The shut leaves the send in flight, and its slot is pending until that send ends.
- `Refuse`, and the idle close of a connection that is up, set `idleNow`. The connection is idle
  from the instant it began to close. The code keeps that instant where it keeps the instant its
  last lookup left. So the trace writes `I` there, as the code does.
- The check "closing bounded" holds the rule. After the clock moves, no connection that closed
  before it still closes.
- `mutants/CL5` puts back `CloseIdle` as it was. TLC finds "closing bounded" broken at the sixth
  state of its counterexample. A handshake is refused, its alert's send is in flight, and the clock
  moves.

The model holds no cancel. Each operation may end at each event already, so the cancel's event is
one that the model holds. In the clear no connection closes, so no configuration in the clear
changes. Neither does a configuration of UDP, DoQ or DoH.

TLC checked each configuration over TLS on 2026-10-20 on an Apple M1 Pro while other work ran:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tls_1_2_bound_2_1` | 297,743 | 213,063 |
| `Engine_tls_1_2_bound_3_1` | 11,165,668 | 5,747,714 |
| `Engine_tls_2_2_bound_2_1` | 28,696,711 | 21,536,161 |

A connection that closes no longer stays closing past a move of the clock, so TLC reaches fewer
states. The largest configuration CI checks once a day now holds 21,536,161 states,
`Engine_tls_2_2_bound_2_1`. TLC took 3 hours 26 minutes over it with three workers, and 1 hour 59
minutes over `Engine_tls_1_2_bound_3_1`, while other work ran.

Two of the 130 short walks changed, one in each configuration over TLS. In each the idle close
makes a `close_notify`, and the trace now writes `I` there. No short walk moves the clock while a
connection closes. Of the full run's 26,000 walks, 2,014 changed, all over TLS: 839 with one lookup
and 1,175 with two. In 1,715 of them the clock moves while a connection closes, 2,236 times, and
the idle close shuts it. The replay of the full run agrees with the engine over 5,226,000 events.

Three of the sixteen picks changed, walks 16068, 16271 and 16478, and each now drives the new path.
The rows of docs/mutations.md that the walks catch ran again against the full run (The wait on a
connection that closes). For each older row that the short walks miss, the tool named the walk that
it named before. For the new rows it named two walks more, 16003 for CL11 and 16135 for CL13.

CL11 puts back the old `close_idle`, and the full run caught it first at walk 16003. CL13 drops the
instant at which a refused connection begins to close. The full run caught it first at walk 16135,
where a handshake is refused after the clock moved. No pick caught CL13, so both walks are picks
now, eighteen in all.

On 2026-10-24 a deadline came to end `tcpReady` (docs/design.md §5; §16 decision 52). Until then a
lookup whose query's send never ended stayed in that stage until the caller cancelled it. The model
held the same gap: `Waiting` left out `tcpReady`, so no move of the clock reached that stage. The
change came to the model first:

- `Waiting` holds `tcpReady`. `WaitsOnServer` keeps the three stages that it held before. `LPoll`
  answers `wait` in those alone, and `Settle` offers a lookup in `tcpReady` for its send.
- `LookupEvent` arms the deadline at `tcpConnected`, as the code arms it at `on_tcp_connected`.
- At the deadline the lookup moves on, and the drive takes it off its connection (the stream's
  rule 3). A query that has started stays at the head of its queue. When the last lookup leaves,
  `CloseIdle` closes the connection at the next move of the clock.
- Two checks hold the rule. "ready armed": a lookup in `tcpReady` has its deadline armed, or is
  offered with its deadline passed. "ready bounded": after the clock reaches its deadline, it is
  not in `tcpReady` on the same try.
- `mutants/RD1` puts back `Waiting` as it was. TLC finds "ready armed" broken at the third state of
  its counterexample, where a lookup in `tcpReady` has no deadline.
- `mutants/RD13` keeps `Waiting`, and arms the wait again at the deadline of a lookup in
  `tcpReady`, which stays there. TLC finds "ready bounded" alone broken, at the fourth state of its
  counterexample. For it, `Expire` and `Rearms` are definitions of their own in
  `EngineTable.tla`. They hold what `LStep` and `LookupEvent` did before, so no count changed.

TLC checked each configuration of a stream on 2026-10-24 on an Apple M1 Pro while other work ran:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tcp_1_1_bound_4_1` | 20,098 | 21,071 |
| `Engine_tcp_2_1_bound_4_1` | 690,360 | 704,681 |
| `Engine_tcp_2_2_bound_4_1` | 3,466,275 | 3,583,539 |
| `Engine_tls_1_2_bound_2_1` | 213,063 | 217,719 |
| `Engine_truncated_1_1_bound_4_1` | 427,125 | 466,646 |

TLC checked the two nightly configurations over TLS in `zig build tla`'s full run:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tls_1_2_bound_3_1` | 5,747,714 | 6,661,256 |
| `Engine_tls_2_2_bound_2_1` | 21,536,161 | 22,205,523 |

The configurations of UDP alone, of DoQ and of DoH reach no `tcpReady`, and hold the states that
they held before. The largest configuration CI checks on each push now holds 3,583,539 states.
The largest it checks once a day holds 22,205,523, `Engine_tls_2_2_bound_2_1`.

The trace writes a lookup in `tcpReady` among the lookups that wait, in `w[...]`. Of the 130 short
walks, 23 changed: 22 over TCP and one of UDP with truncated answers. Ten of the eighteen picks
changed. The picks were chosen again (docs/mutations.md, The deadline of a ready lookup).
`zig build mutations -- engine` ran each of the 87 rows that the walks catch against the new full
run. For each row that the short walks miss, the tool named the full run's first walk that catches
it. Those seventeen walks are the picks now. Walks 8006, 8094, 12003, 16016, 16052, 16480 and
16789 came in, and walks 8025, 8046, 8241, 12004, 12011, 16068, 16271 and 16478 left. Each of the
20 rows that the picked walks catch is `CAUGHT` by the new picks.

On 2026-10-25 the last lookup to leave a connection during a query's send came to shut it at once
(docs/design.md §16 decision 53). Until then the idle close shut it, at the next move of the clock.
The query's send held its lookup's buffer until then, and each later send of that slot was held.
The change came to the model first:

- `QueryInFlight` says that a connection's head is a query whose send is in flight. Over TLS the
  head may be the session's own records, which hold no lookup's buffer.
- `Release` shuts the connection when no lookup stays on it and `LeaveShuts` holds: a query's send
  is in flight. The shut leaves that send to the loop, and its next event gives the buffer back.
- The check "held bounded" holds the rule. A query's send on a connection that is up has a lookup
  on that connection.
- `mutants/SH1` puts back `Release` as it was, with `LeaveShuts` false. TLC finds "held bounded"
  broken at the fourth state of its counterexample. A lookup's query goes out, and a cancel ends
  the lookup while that send is in flight.

TLC checked each configuration of a stream on 2026-10-25 on an Apple M1 Pro while other work ran:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tcp_1_1_bound_4_1` | 21,071 | 15,018 |
| `Engine_tcp_2_1_bound_4_1` | 704,681 | 543,240 |
| `Engine_tcp_2_2_bound_4_1` | 3,583,539 | 2,936,207 |
| `Engine_tls_1_2_bound_2_1` | 217,719 | 167,633 |
| `Engine_truncated_1_1_bound_4_1` | 466,646 | 384,006 |

TLC checked the two nightly configurations over TLS in `zig build tla`'s full run:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tls_1_2_bound_3_1` | 6,661,256 | 4,629,420 |
| `Engine_tls_2_2_bound_2_1` | 22,205,523 | 17,278,895 |

A connection with no lookup no longer stays up beside a query's send, so TLC reaches fewer states.
The configurations of UDP alone, of DoQ and of DoH reach no stream, and hold the states that they
held before. The largest configuration CI checks on each push now holds 2,936,207 states,
`Engine_tcp_2_2_bound_4_1`. The largest it checks once a day holds 17,278,895,
`Engine_tls_2_2_bound_2_1`.

Of the 130 short walks, 11 changed, all over TCP. Three of the seventeen picks changed: walks 8006,
8094 and 12003. The picks were chosen again (docs/mutations.md, A send held behind a stalled one).
`zig build mutations -- engine` ran each row of the engine against the new full run. For each row
that the short walks miss, the tool named the full run's first walk that catches it. Those eighteen
walks are the picks now. Walks 8016, 8023, 16047 and 20016 came in, and walks 8006, 8094 and 16789
left. Each of the 28 rows that the picked walks catch, or that they missed before, is `CAUGHT` by
the new picks.

On 2026-10-25 a connection that a lookup left during its query's send came to take no lookup
(docs/design.md §16 decision 54). Until then each new lookup to that server joined it, and delayed
its shut. The change came to the model first:

- A connection holds `marked`. `MarkLeft` sets it in `Release` when the lookup that leaves has its
  query's send in flight there, and a lookup stays. The mark stays until the connection ends.
- `FindConn` passes over a marked connection. `Want` waits when no slot is free or pending, and a
  marked connection that is up holds a slot (`Marked`).
- `Leave` takes the place of `Release` in the drive. At the last leave of a marked connection with
  no query's send in flight, it shuts the connection in the clear. Over TLS it seals the
  `close_notify`, and the connection closes.
- Three checks hold the rule. "joins no marked": no lookup joins a marked connection. "left
  marked": a connection that is up with a lookup on it, whose head is a query whose send is in
  flight, and whose lookup left it, is marked. "marked held": a marked connection is up with a
  lookup on it, or it closes.
- `mutants/NJ1` lets `FindConn` take a marked connection. TLC finds "joins no marked" broken at the
  eighth state of its counterexample. `mutants/NJ2` marks nothing, and TLC finds "left marked"
  broken at the fifth state. `mutants/NJ3` leaves a marked connection up at its last leave, and
  TLC finds "marked held" broken at the eighth state.
- `ReleaseKeepsQueued`, the operator of TQ1, marks as `Release` does. So TQ1 still breaks "queued
  for its lookup" alone, at the fifth state, and SH1 still breaks "held bounded" alone, at the
  fourth.

TLC checked each configuration of a stream on 2026-10-25 on an Apple M1 Pro while other work ran:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_tcp_1_1_bound_4_1` | 15,018 | 15,018 |
| `Engine_tcp_2_1_bound_4_1` | 543,240 | 593,915 |
| `Engine_tcp_2_2_bound_4_1` | 2,936,207 | 2,910,103 |
| `Engine_tls_1_2_bound_2_1` | 167,633 | 167,633 |
| `Engine_truncated_1_1_bound_4_1` | 384,006 | 384,006 |
| `Engine_tls_2_2_bound_2_1` | 17,278,895 | 18,790,144 |

A mark needs two lookups on one connection. So each configuration with one lookup holds the states
that it held before. `Engine_tls_1_2_bound_3_1` has one lookup too, and did not run. With one
connection slot, a new lookup now waits for the slot of a marked connection. So
`Engine_tcp_2_1_bound_4_1` holds more states. The largest configuration CI checks on each push now
holds 2,910,103 states, `Engine_tcp_2_2_bound_4_1`. The largest it checks once a day holds
18,790,144, `Engine_tls_2_2_bound_2_1`.

The trace writes ` X` after the queue of a marked connection. So a walk where no connection is
marked is written as before. None of the 130 short walks marks a connection, and none changed. Of
the 26,000 walks of the full run, 365 mark one: 193 over TCP with one connection slot, 170 over TCP
with two, and 2 over TLS. Of the eighteen picks, walk 12003 changed, and it marks a connection.
`zig build mutations -- engine` ran each row that the walks catch, and the rows NJ4 to NJ15,
against the new full run (docs/mutations.md, A connection no lookup may join). The short walks miss
the four rows NJ12 to NJ15, and the picks caught NJ13 at walk 12003. For the other three the tool
named the full run's first walk that catches each: walks 12004, 12338 and 12392. They came in, and
the picks are twenty-one now. No walk left.

A review of the change on 2026-10-25 added a check, a configuration and three mutants:

- `Leave` ends a marked connection through `EndMarked`. Over TLS, with no send refused, the end
  leaves the connection closing, with its `close_notify`. `unsaid` notes an end that does not. The
  check "marked said" asks that, and TLC holds forty-nine checks now.
- `Want` judges `slotless` by decision 54 too. A lookup told that its connection failed while a
  marked connection holds a slot sets it, in the clear as over TLS.
- `Engine_tls_2_1_bound_2_1` has one server, two lookups and one connection over TLS, at two
  operations. CI checks it on each push, and it reaches a mark over TLS. Before it only the nightly
  `Engine_tls_2_2_bound_2_1` did. TLC counts 142,068 states, in 24 seconds.
- `mutants/NJ16` tells the lookup that its connection failed in place of the wait, in the clear.
  TLC finds "slot waited for" broken at the fifth state of its counterexample. `mutants/NJ17` does
  the same over TLS, and TLC finds it at the eleventh state. `mutants/NJ18` shuts a marked
  connection over TLS at its last leave, and TLC finds "marked said" broken at the eleventh state.

Each other configuration of a stream holds the states of the table above. NJ1 to NJ3, TQ1 and SH1
each still break their one check alone. The trace does not write `unsaid`, and a model that keeps
its rules never sets it. So no walk changed. Two walks of the full run mark a TLS connection, and
neither reaches a last leave of it with its sends ended. So no walk catches the code's NJ10, the
shut in place of that `close_notify`. The test of NJ10 and `Engine_tls_2_1_bound_2_1` hold that
rule (docs/mutations.md, A connection no lookup may join).

On 2026-10-26 the idle wait came to bound a channel's link that closes (docs/design.md §24,
request rules 19 and 24; §16 decision 55). Until then a link that closed waited for its last send
to end. A peer that stopped reading held that link closing for ever, and the model held the same
gap. The change came to the model first:

- `ShutLapsed` shuts each link that closes at each move of the clock. A tick is the idle wait, so
  the first move of the clock after the link began to close shuts it. The shut leaves the send to
  the loop, and the buffer stays lent until the send's next event.
- That event reads the channel no more, since its opening has ended. So `ShutLapsed` reads the
  channel at the shut, which tells first what it held. A first form read nothing there, and TLC
  found "channel held while sending" broken at the sixth state of its counterexample.
- `Moving` calls `ShutLapsed` at each move of the clock, before `Pass` moves the deadlines. The
  code's drive shuts the link before its polls find a deadline. So an end that the channel told at
  the shut reaches its lookup first. A form that shut the link in the drive, after `Pass`, put
  the results in another order than the code. The replay of the full run found it at walk 2243.
- The clock can move while a link closes: `idle` is enabled then, as it is while a connection
  closes.
- The check "link closing bounded" holds the rule. After the clock moves, no link that closed
  before it still closes. TLC holds fifty checks now.
- `mutants/DL1` puts back the drive as it was. TLC finds "link closing bounded" broken at the fifth
  state of its counterexample. A link's send is in flight, the channel closes the link, and the
  clock moves.

The model holds no cancel, as before: each operation may end at each event already. Only the
channel configurations change. TLC checked them on 2026-10-26 on an Apple M1 Pro while other work
ran:

| Configuration | Before | Now |
| --- | --- | --- |
| `Engine_channel_1_1_bound_3_1` | 1,672,552 | 1,800,872 |
| `Engine_channel_1_2_bound_3_1` | 14,986,512 | 17,297,696 |

The clock now moves while a link closes, so TLC reaches more states. TLC took 59 minutes over the
nightly `Engine_channel_1_2_bound_3_1` with four workers. The form that shut the link after `Pass`
held 17,986,988 states there. Each of the ten mutants CH1 to CH10 is still violated.

The trace writes nothing new. A link that the drive shuts is written `down`, with its buffer lent
until the send's event. A link that the channel closed with nothing to send is written the same.

Of the 130 short walks, 5 changed, all over DoH: one with one lookup and four with two. Of the full
run's 26,000 walks, 2,329 changed, all over DoH: 1,076 with one lookup and 1,253 with two. In 1,740
of them the clock moves while a link closes, 2,277 times, and the drive shuts the link. Three of the
twenty-one picks changed: walks 4, 13 and 2002. The replay of the full run agrees with the engine
over 5,226,000 events.

`zig build mutations -- engine` ran each row that the walks catch, and DL2 to DL12, against the
new full run (docs/mutations.md). The short walks
catch DL10 and DL11. They miss DL12, the shut at the bound that reads no channel, and the full run
caught it first at walk 12. The full run now catches CE12 first at walk 3, where it caught it
first at walk 4 before. So walks 3 and 12 came in, walk 4 left, and the picks are twenty-two now.

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

- `zig build test` replays `tools/spec_replay/lookup_gate.txt`, a committed slice of 13,838
  transitions. It holds one server, one pass and one name, over UDP, over TCP, over DoH and over
  DoQ. It holds one server with two passes over DoH too, where a second cause replaces the first.
  It holds two servers with one pass over DoQ, where a cause names a server that the lookup left.
  It also
  replays two sets of engine walks TLC wrote. `tools/spec_replay/engine_gate.txt` holds ten walks
  of forty events in each of the thirteen engine configurations.
  `tools/spec_replay/engine_picks.txt` holds twenty-two walks of the full run, which `engine_picks`
  in `build/spec.zig` names. Each is where the full run caught a mutation of the engine that the
  short walks miss (docs/mutations.md). The gate also holds `tools/spec_replay/walk_gate.txt`, the
  forward walk with two candidates and both families and every reverse configuration. It needs
  neither Lean nor Java.
- `zig build spec` needs `lake` on the path, at the version `lean/lean-toolchain` pins, and Java
  11 or newer for TLC. pepegrillo's `lean` tool builds the proofs and the axiom pins first. Then
  the step requires the committed slices to be the ones the models write, and replays the
  lookup's whole transcript, the walks' whole transcript, and TLC's full run: 2,000 engine walks
  of 200 events in each of the thirteen engine configurations, 5,226,000 events. TLC wrote the
  full run in 872 seconds on an Apple M1 Pro on 2026-09-29, while a TLC check held most of the
  cores, and its replay took 61 seconds, its build among them, while the check still ran. With the
  thirteenth configuration, on 2026-10-14 on the same machine, TLC wrote it in 473 seconds and the
  replay took 44 while other work ran. `zig build
  spec-lean` is the Lean half alone, which needs no Java, and `zig build spec-engine` the engine's
  part alone, which needs no Lean.
- After a change to a model, `lake exe cocuyo-spec gate 8 > ../../tools/spec_replay/lookup_gate.txt`
  and `lake exe cocuyo-spec walks-gate > ../../tools/spec_replay/walk_gate.txt` in `lean/` write
  the Lean slices again. From the repository's root, `zig build tla -- walks 1 10 41 >
  tools/spec_replay/engine_gate.txt` writes the short engine walks, and `zig build tla -- walks 1
  2000 201 --pick tools/spec_replay/engine_picks.txt <walk>... > /dev/null` the picked ones, the
  walks named being `engine_picks`. A change to the engine model changes TLC's walks, so the picks
  are chosen again: `zig build mutations -- engine` breaks the engine each way
  `tools/mutations/engine.zon` says, and names the full run's first walk that catches each
  mutation the short walks miss.

The `8` is `cname_hops_max` of `src/core/limits.zig`. The transcript records it, and the replay
refuses a transcript written for another.
