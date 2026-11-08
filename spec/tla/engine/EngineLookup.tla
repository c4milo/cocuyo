----------------------------- MODULE EngineLookup ----------------------------
\* The engine of docs/design.md §19 step 13, §21 and §24, written from the stream's rules, the
\* datagram's rules, the TLS rules and the request rules, and never from the Zig source
\* (spec/README.md). This
\* module holds the configuration and the lookup's transitions the engine asks of it;
\* EngineTable.tla, which extends it, holds the table and the connections, EngineIo.tla the sockets
\* and the sends, and Engine.tla the drive, the events and the checks. Split from EngineTable.tla
\* by the file-length rule. It was ported from the Lean model that came before it, and held to it by
\* count until that one retired (§16 decision 24).
\*
\* Three choices of the port. An absent value is the empty set and a present one a set of one.
\* The loop's operations are a bag: every rule reads them as a multiset, so an event names an
\* operation by its value and TLC counts a state once whatever the order they came in. Numbers
\* the Lean model took from `Nat` subtract with `Sub`, which stops at zero as `Nat` does.
EXTENDS Naturals, Sequences, FiniteSets, Bags

CONSTANTS
    Servers,      \* the configured servers
    Slots,        \* the table's slots
    Conns,        \* the connection slots
    PollsMax,     \* the polls one drive makes at most, as the code bounds it
    TimeoutTicks, \* the ticks a lookup waits for its server
    UseTcp,       \* every query over TCP
    PerPort,      \* the queries a port carries before it is replaced; zero for never
    Tls,          \* every server speaks TLS, so every query goes on a stream (§21)
    Request,      \* every server speaks DoQ or DoH, so every query is a request (§24)
    Channel,      \* every server speaks DoH through colibri's channel (§24, rules 18 to 25)
    OpsMax,       \* the walk's bound on the operations the loop holds
    FailuresMax,  \* the walk's bound on a server's failures
    SentMax       \* the walk's bound on the queries a port has carried

\* Whether a datagram's answer may come truncated: TC set by its server, or the datagram cut by the
\* buffer it arrives in (docs/design.md §7, §19 step 13, the datagram's rule 6). Only the
\* configurations of that rule set it, with `Truncates <- Truncating`. So each other configuration
\* reaches what it reached before.
Truncates == FALSE
Truncating == TRUE

-------------------------------------------------------------------------------
\* Helpers.

Sub(a, b) == IF a > b THEN a - b ELSE 0
Get(opt) == CHOOSE x \in opt : TRUE
Least(S) == CHOOSE x \in S : \A y \in S : x <= y
Lesser(a, b) == IF a < b THEN a ELSE b
Contains(seq, x) == \E i \in 1..Len(seq) : seq[i] = x
Take(seq, n) == SubSeq(seq, 1, Lesser(n, Len(seq)))
Drop(seq, n) == IF n >= Len(seq) THEN <<>> ELSE SubSeq(seq, n + 1, Len(seq))
HeadIs(seq, x) == Len(seq) > 0 /\ Head(seq) = x

RECURSIVE SumOver(_, _)
\* The copies of every element of S in bag B.
SumOver(S, B) == IF S = {} THEN 0 ELSE
    LET x == CHOOSE x \in S : TRUE IN B[x] + SumOver(S \ {x}, B)

Count(B, P(_)) == SumOver({x \in DOMAIN B : P(x)}, B)
Add(B, x) == B (+) SetToBag({x})
Remove(B, x) == B (-) SetToBag({x})
\* Every element of B through F, its copies kept.
MapBag(B, F(_)) == [y \in {F(x) : x \in DOMAIN B} |-> SumOver({x \in DOMAIN B : F(x) = y}, B)]

-------------------------------------------------------------------------------
\* The lookup of spec/lean/Spec/Lookup.lean, as the engine runs it: one pass over the servers,
\* one name, no CNAME past the answer, and the four replies the table makes of a message. Over
\* DoQ or DoH a query is a request, sent and answered as a datagram's, and a request that fails is
\* the server's failure (§22, §23). Under `Truncates` a datagram has two replies more: TC set, and
\* a datagram the buffer cut that passes the checks of a cut datagram (§7). Each sends its lookup
\* to TCP.

Stream == UseTcp \/ Tls
Fresh == IF Stream THEN "tcpNeeded" ELSE "queryReady"
\* The stages that wait on a server, for its answer or for its connection.
WaitsOnServer(stage) == stage \in {"awaitingUdp", "connectingTcp", "awaitingTcp"}
Ended(stage) == stage \in {"done", "failed"}
OnStream(stage) == stage \in {"connectingTcp", "tcpReady", "awaitingTcp"}
\* The stages a deadline bounds. Since 2026-10-24 `tcpReady` waits for the deadline that
\* `tcpConnected` arms, and its query's send does not stop it (§5, §16 decision 52).
Waiting(stage) == WaitsOnServer(stage) \/ stage = "tcpReady"

\* An end closes every try the lookup kept open (§5, Tries kept open).
LFail(lk, err) == [lk EXCEPT !.stage = "failed", !.err = err, !.offered = FALSE, !.opens = {}]
LDone(lk) == [lk EXCEPT !.stage = "done", !.opens = {}]

LInit ==
    LET lk == [stage |-> Fresh, server |-> 0, round |-> 0, candidate |-> 0, hops |-> 0,
               edns |-> TRUE, hadNoData |-> FALSE, serverFailed |-> FALSE,
               cookieRetried |-> FALSE, offered |-> FALSE, err |-> "timeout", opens |-> {}]
    IN IF Servers = 0 THEN LFail(lk, "noServers") ELSE lk

\* The next server, then failure: the engine's lookups make one pass (§5, retry policy).
AdvanceServer(lk) ==
    IF lk.server + 1 < Servers
    THEN [lk EXCEPT !.server = @ + 1, !.stage = Fresh, !.edns = TRUE, !.cookieRetried = FALSE,
                    !.offered = FALSE]
    ELSE LFail([lk EXCEPT !.round = @ + 1],
               IF lk.serverFailed THEN "allServersFailed" ELSE "timeout")

\* NXDOMAIN on the one name there is: the walk over the names is over (§5, search list policy).
NoName(lk) == LFail(lk, IF lk.hadNoData THEN "noData" ELSE "nameNotFound")

LReply(lk, r) ==
    CASE r = "unmatched" -> <<lk, "ignored">>
      [] r = "answer" -> <<LDone(lk), "accepted">>
      [] r = "nxdomain" -> <<NoName(lk), "accepted">>
      [] r = "servfail" -> <<AdvanceServer([lk EXCEPT !.serverFailed = TRUE]), "accepted">>
      \* The same server, over TCP (§5). Only a datagram brings either, so only `awaitingUdp`.
      [] r \in {"truncated", "cut"} -> <<[lk EXCEPT !.stage = "tcpNeeded"], "accepted">>

LPoll(lk) ==
    CASE lk.stage = "queryReady" ->
            <<[lk EXCEPT !.offered = TRUE], IF Request THEN "sendRequest" ELSE "sendUdp">>
      [] lk.stage = "tcpNeeded" -> <<[lk EXCEPT !.stage = "connectingTcp"], "connectTcp">>
      [] lk.stage = "tcpReady" -> <<[lk EXCEPT !.offered = TRUE], "sendTcp">>
      [] WaitsOnServer(lk.stage) -> <<lk, "wait">>
      [] lk.stage = "done" -> <<lk, "done">>
      [] lk.stage = "failed" -> <<lk, "failed">>

\* The transport a try in `stage` went over: a stream, a request, or a datagram.
TryKind(stage) == IF stage = "awaitingTcp" THEN "tcp" ELSE IF Request THEN "req" ELSE "udp"

\* A lookup whose query went out keeps that try open when it moves on, as the position in its
\* order it went to and its transport. One in `connectingTcp` or `tcpReady` sent nothing (§5, Tries
\* kept open; §16 decision 66).
KeepOpen(lk) ==
    IF lk.stage \in {"awaitingUdp", "awaitingTcp"}
    THEN [lk EXCEPT !.opens = @ \cup {<<lk.server, TryKind(lk.stage)>>}] ELSE lk

\* The deadline passed: a lookup that waits moves to the next server, and keeps its try open (§5).
Expire(lk) == IF Waiting(lk.stage) THEN LPoll(AdvanceServer(KeepOpen(lk))) ELSE LPoll(lk)

\* A reply to the open try at position p over transport `kind`: it closes that try. An answer ends
\* the lookup, and NXDOMAIN ends the walk over the one name, as the current try's would. SERVFAIL is
\* that server's failure, and TC or a cut datagram closes the try alone, since its server answered.
\* The lookup waits on its current try for each of those (§5, Tries kept open; the Lean model's
\* `earlierHeard`).
LEarlier(lk, p, kind, r) ==
    LET closed == [lk EXCEPT !.opens = @ \ {<<p, kind>>}] IN
    CASE r = "unmatched" -> <<lk, "ignored">>
      [] r = "answer" -> <<[LDone(closed) EXCEPT !.offered = FALSE], "accepted">>
      [] r = "nxdomain" -> <<NoName(closed), "accepted">>
      [] r = "servfail" -> <<[closed EXCEPT !.serverFailed = TRUE], "accepted">>
      [] r \in {"truncated", "cut"} -> <<closed, "accepted">>

\* Whether the try at position p over transport `kind` is open.
Opened(lk, p, kind) == ~Ended(lk.stage) /\ <<p, kind>> \in lk.opens

\* One event on a lookup, and what it answers.
LStep(lk, ev, r) ==
    CASE ev = "poll" -> LPoll(lk)
      [] ev = "expire" -> Expire(lk)
      [] ev = "sent" ->
            IF lk.stage = "queryReady"
            THEN <<[lk EXCEPT !.stage = "awaitingUdp", !.offered = FALSE], "none">>
            ELSE IF lk.stage = "tcpReady"
            THEN <<[lk EXCEPT !.stage = "awaitingTcp", !.offered = FALSE], "none">>
            ELSE <<lk, "none">>
      [] ev = "sendFailed" ->
            IF lk.stage \in {"queryReady", "tcpReady"} THEN <<AdvanceServer(lk), "none">>
            ELSE <<lk, "none">>
      [] ev = "tcpConnected" ->
            IF lk.stage = "connectingTcp" THEN <<[lk EXCEPT !.stage = "tcpReady"], "none">>
            ELSE <<lk, "none">>
      \* A connection or a handshake that failed is the server refusing the lookup, which counts
      \* as SERVFAIL does (§16 decision 25).
      [] ev = "tcpFailed" ->
            IF OnStream(lk.stage)
            THEN <<AdvanceServer([lk EXCEPT !.serverFailed = TRUE]), "none">>
            ELSE <<lk, "none">>
      [] ev = "requestFailed" ->
            IF lk.stage = "awaitingUdp"
            THEN <<AdvanceServer([lk EXCEPT !.serverFailed = TRUE]), "none">>
            ELSE <<lk, "none">>
      [] ev = "reply" ->
            IF lk.stage \in {"awaitingUdp", "awaitingTcp"} THEN LReply(lk, r) ELSE <<lk, "ignored">>
      \* A reply to an earlier try names it as `<<p, kind, reply>>`, and the failure of its
      \* connection or its request as `<<p, kind, reason>>`. The failure is that server's (§16
      \* decision 25), unless the engine closed the connection itself: `local`, no server took part.
      [] ev = "earlier" ->
            IF Opened(lk, r[1], r[2]) THEN LEarlier(lk, r[1], r[2], r[3]) ELSE <<lk, "ignored">>
      [] ev = "earlierFailed" ->
            IF Opened(lk, r[1], r[2])
            THEN <<[lk EXCEPT !.opens = @ \ {<<r[1], r[2]>>},
                              !.serverFailed = @ \/ r[3] # "local"], "none">>
            ELSE <<lk, "none">>
      [] ev = "cancel" ->
            IF Ended(lk.stage) THEN <<lk, "none">> ELSE <<LFail(lk, "canceled"), "none">>

===============================================================================
