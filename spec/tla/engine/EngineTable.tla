----------------------------- MODULE EngineTable -----------------------------
\* The engine of docs/design.md §19 step 13, §21 and §24, written from the stream's rules, the
\* datagram's rules, the TLS rules and the request rules, and never from the Zig source
\* (spec/README.md). This
\* module holds the configuration, the lookup's transitions the engine asks of it, the table and
\* the connections; EngineIo.tla holds the sockets and the sends, and Engine.tla the drive, the
\* events and the checks. It was ported from the Lean model that came before it, and held to it by
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
    OpsMax,       \* the walk's bound on the operations the loop holds
    FailuresMax,  \* the walk's bound on a server's failures
    SentMax       \* the walk's bound on the queries a port has carried

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
\* the server's failure (§22, §23).

Stream == UseTcp \/ Tls
Fresh == IF Stream THEN "tcpNeeded" ELSE "queryReady"
Waiting(stage) == stage \in {"awaitingUdp", "connectingTcp", "awaitingTcp"}
Ended(stage) == stage \in {"done", "failed"}
OnStream(stage) == stage \in {"connectingTcp", "tcpReady", "awaitingTcp"}

LFail(lk, err) == [lk EXCEPT !.stage = "failed", !.err = err, !.offered = FALSE]

LInit ==
    LET lk == [stage |-> Fresh, server |-> 0, round |-> 0, candidate |-> 0, hops |-> 0,
               edns |-> TRUE, hadNoData |-> FALSE, serverFailed |-> FALSE,
               cookieRetried |-> FALSE, offered |-> FALSE, err |-> "timeout"]
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
      [] r = "answer" -> <<[lk EXCEPT !.stage = "done"], "accepted">>
      [] r = "nxdomain" -> <<NoName(lk), "accepted">>
      [] r = "servfail" -> <<AdvanceServer([lk EXCEPT !.serverFailed = TRUE]), "accepted">>

LPoll(lk) ==
    CASE lk.stage = "queryReady" ->
            <<[lk EXCEPT !.offered = TRUE], IF Request THEN "sendRequest" ELSE "sendUdp">>
      [] lk.stage = "tcpNeeded" -> <<[lk EXCEPT !.stage = "connectingTcp"], "connectTcp">>
      [] lk.stage = "tcpReady" -> <<[lk EXCEPT !.offered = TRUE], "sendTcp">>
      [] Waiting(lk.stage) -> <<lk, "wait">>
      [] lk.stage = "done" -> <<lk, "done">>
      [] lk.stage = "failed" -> <<lk, "failed">>

\* One event on a lookup, and what it answers.
LStep(lk, ev, r) ==
    CASE ev = "poll" -> LPoll(lk)
      [] ev = "expire" -> IF Waiting(lk.stage) THEN LPoll(AdvanceServer(lk)) ELSE LPoll(lk)
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
      [] ev = "cancel" ->
            IF Ended(lk.stage) THEN <<lk, "none">> ELSE <<LFail(lk, "canceled"), "none">>

-------------------------------------------------------------------------------
\* The state.

Sockets == IF Tls \/ Request THEN 0 ELSE Servers
\* A request connection for each server, over DoQ or DoH (§24, request rule 1).
RServers == IF Request THEN Servers ELSE 0

NoSlot == [lookup |-> {}, order |-> <<>>, conn |-> {}, busy |-> FALSE, held |-> FALSE,
           heldCurrent |-> FALSE, reported |-> FALSE, expired |-> FALSE, remaining |-> 0,
           sentFrom |-> {}]
NoConn == [stage |-> "closed", server |-> 0, users |-> 0, idleNow |-> FALSE, queue |-> <<>>,
           sealed |-> 0, partSent |-> FALSE, owes |-> FALSE, resumed |-> FALSE]
NoSock == [sent |-> 0, retiring |-> FALSE, draining |-> FALSE]
\* A request connection: its stage, the requests waiting for it to be up, the ones on a stream,
\* whether colibri owes a datagram, whether its slot's datagram buffer is lent to a send of any
\* incarnation, whether it went idle at this instant, and whether its protocol was the right one.
NoRConn == [stage |-> "closed", queue |-> <<>>, streams |-> {}, owes |-> FALSE, lent |-> FALSE,
            idleNow |-> FALSE, alpn |-> FALSE, resumed |-> FALSE]

Query(l) == [kind |-> "query", slot |-> l]
Records == [kind |-> "records", slot |-> 0]
Op(kind, target) == [kind |-> kind, target |-> target, current |-> TRUE, draining |-> FALSE]
IsSend(kind) == kind \in {"send", "sendTo"}

\* A socket per server, each with its receive armed; none over TLS (§21, TLS rule 9).
InitState ==
    [slots |-> [l \in 0..Slots - 1 |-> NoSlot],
     conns |-> [k \in 0..Conns - 1 |-> NoConn],
     ops |-> SetToBag({Op("receiveFrom", v) : v \in 0..Sockets - 1}),
     ready |-> <<>>, free |-> [i \in 1..Slots |-> i - 1], results |-> <<>>, lastTaken |-> {},
     failures |-> [v \in 0..Servers - 1 |-> 0], socks |-> [v \in 0..Sockets - 1 |-> NoSock],
     jammed |-> FALSE, starved |-> FALSE, tickets |-> [v \in 0..Servers - 1 |-> FALSE],
     rconns |-> [v \in 0..RServers - 1 |-> NoRConn], reqs |-> [l \in 0..Slots - 1 |-> {}]]

\* The configured server a slot's lookup is asking now.
ServerOf(st, l) ==
    LET sl == st.slots[l] IN
    IF sl.lookup = {} THEN 0
    ELSE LET lk == Get(sl.lookup) IN
         IF lk.server < Len(sl.order) THEN sl.order[lk.server + 1] ELSE 0

-------------------------------------------------------------------------------
\* The table.

Offer(st, l) == IF Contains(st.ready, l) THEN st ELSE [st EXCEPT !.ready = Append(@, l)]

Settle(st, l) ==
    IF st.slots[l].lookup = {} \/ Waiting(Get(st.slots[l].lookup).stage) THEN st
    ELSE Offer(st, l)

Unwait(st, l) == [st EXCEPT !.slots[l].remaining = 0]
Arm(st, l) == [st EXCEPT !.slots[l].remaining = TimeoutTicks]

RecordFailure(st, v) == [st EXCEPT !.failures[v] = IF @ + 1 < 255 THEN @ + 1 ELSE 255]
RecordSuccess(st, v) == [st EXCEPT !.failures[v] = 0]

RECURSIVE Leading(_, _, _)
\* How many entries at the front of `sorted` fail no sooner than server i: the span of the stable
\* insertion sort (§19 step 12, with rotation and the retry promotion off).
Leading(sorted, f, i) ==
    IF sorted = <<>> \/ f[Head(sorted)] > f[i] THEN 0 ELSE 1 + Leading(Tail(sorted), f, i)

RECURSIVE SortFrom(_, _, _)
SortFrom(f, i, sorted) ==
    IF i >= Servers THEN sorted
    ELSE LET n == Leading(sorted, f, i) IN
         SortFrom(f, i + 1, SubSeq(sorted, 1, n) \o <<i>> \o SubSeq(sorted, n + 1, Len(sorted)))

SortByFailures(f) == SortFrom(f, 0, <<>>)

\* The attempt a lookup is on: what changes when it draws a new transaction.
Attempt(lk) == <<lk.server, lk.round, lk.candidate, lk.hops, lk.edns, lk.cookieRetried>>

\* The lookup moved on: its send in flight speaks for nobody, and a held one is to be dropped.
ForgetAttempt(st, l) ==
    LET forgot == [st EXCEPT !.slots[l].heldCurrent = FALSE] IN
    [forgot EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF IsSend(op.kind) /\ op.target = l THEN [op EXCEPT !.current = FALSE] ELSE op)]

\* One event on one lookup, through the table: the servers learn what it says of them, its wait
\* follows it, and its send is forgotten when it drew a new transaction or ended.
LookupEvent(st, l, ev, r) ==
    IF st.slots[l].lookup = {} THEN <<st, "none">>
    ELSE
    LET lk == Get(st.slots[l].lookup)
        v == ServerOf(st, l)
        moved == LStep(lk, ev, r)
        after == moved[1]
        out == moved[2]
        counted ==
            CASE ev = "sendFailed" ->
                    IF lk.stage \in {"tcpReady", "queryReady"} THEN RecordFailure(st, v) ELSE st
              [] ev = "tcpFailed" -> IF OnStream(lk.stage) THEN RecordFailure(st, v) ELSE st
              [] ev = "requestFailed" ->
                    IF lk.stage = "awaitingUdp" THEN RecordFailure(st, v) ELSE st
              [] ev = "expire" -> IF Waiting(lk.stage) THEN RecordFailure(st, v) ELSE st
              [] ev = "reply" ->
                    IF out = "accepted" /\ r # "unmatched" THEN RecordSuccess(st, v) ELSE st
              [] OTHER -> st
        kept == [counted EXCEPT !.slots[l].lookup = {after}]
        rearmed == out = "connectTcp" \/ (ev = "sent" /\ after.stage \in {"awaitingTcp", "awaitingUdp"})
        cleared == IF Waiting(after.stage) /\ ~rearmed THEN kept
                   ELSE [kept EXCEPT !.slots[l].expired = FALSE]
        timed == IF Waiting(after.stage) THEN (IF rearmed THEN Arm(cleared, l) ELSE cleared)
                 ELSE Unwait(cleared, l)
    IN <<IF Attempt(after) # Attempt(lk) \/ Ended(after.stage) THEN ForgetAttempt(timed, l)
         ELSE timed, out>>

TableEvent(st, l, ev) == Settle(LookupEvent(st, l, ev, "none")[1], l)

WaitingSlots(st) ==
    {l \in 0..Slots - 1 : st.slots[l].lookup # {} /\ Waiting(Get(st.slots[l].lookup).stage)}

\* The ticks to the soonest deadline, or zero when no lookup waits.
Soonest(st) ==
    IF WaitingSlots(st) = {} THEN 0 ELSE Least({st.slots[l].remaining : l \in WaitingSlots(st)})

RECURSIVE PassFrom(_, _, _)
PassFrom(st, ticks, l) ==
    IF l >= Slots THEN st
    ELSE
    LET sl == st.slots[l]
        passed ==
            IF sl.lookup = {} \/ ~Waiting(Get(sl.lookup).stage) THEN st
            ELSE LET left == Sub(sl.remaining, ticks)
                     counted == [st EXCEPT !.slots[l].remaining = left]
                 IN IF left = 0 THEN Offer([counted EXCEPT !.slots[l].expired = TRUE], l)
                    ELSE counted
    IN PassFrom(passed, ticks, l + 1)

\* Ticks pass, and every lookup whose deadline they reach is offered, slot by slot (§11).
Pass(st, ticks) == PassFrom(st, ticks, 0)

-------------------------------------------------------------------------------
\* The connections.

\* Every current operation of connection slot k is left to the loop to end (rule 2).
CancelOps(st, k) ==
    [st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in {"connect", "receive", "sendRecords"} /\ op.target = k
        THEN [op EXCEPT !.current = FALSE] ELSE op)]

Sending(st, l) == \E op \in DOMAIN st.ops : IsSend(op.kind) /\ op.target = l
RecordsInFlight(st, k) ==
    \E op \in DOMAIN st.ops : op.kind = "sendRecords" /\ op.target = k /\ op.current

\* Whether connection k has its one send in flight: its head's (the stream's rule 9).
InFlight(st, k) ==
    LET q == st.conns[k].queue IN
    IF q = <<>> THEN FALSE
    ELSE IF Head(q).kind = "query" THEN Sending(st, Head(q).slot) ELSE RecordsInFlight(st, k)

RECURSIVE QuerySlots(_)
QuerySlots(q) ==
    IF q = <<>> THEN <<>>
    ELSE (IF Head(q).kind = "query" THEN <<Head(q).slot>> ELSE <<>>) \o QuerySlots(Tail(q))

Queued(st, k) == QuerySlots(st.conns[k].queue)

RECURSIVE FreeBuffers(_, _)
FreeBuffers(st, ls) ==
    IF ls = <<>> THEN st
    ELSE LET l == Head(ls) IN
         FreeBuffers(IF Sending(st, l) THEN st ELSE [st EXCEPT !.slots[l].busy = FALSE], Tail(ls))

\* Closes connection k: a query waiting in it and not being sent gives its buffer back.
Shut(st, k) == [CancelOps(FreeBuffers(st, Queued(st, k)), k) EXCEPT !.conns[k] = NoConn]

\* The lookup leaves its connection, and a query of its that has not started goes with it.
Release(st, l) ==
    IF st.slots[l].conn = {} THEN st
    ELSE
    LET k == Get(st.slots[l].conn)
        left == [st EXCEPT !.slots[l].conn = {}]
        waiting == Contains(left.conns[k].queue, Query(l)) /\ ~Sending(left, l)
        freed == IF waiting THEN [left EXCEPT !.slots[l].busy = FALSE] ELSE left
        users == Sub(freed.conns[k].users, 1)
    IN [freed EXCEPT !.conns[k].users = users, !.conns[k].idleNow = @ \/ users = 0,
                     !.conns[k].queue = IF waiting THEN SelectSeq(@, LAMBDA e : e # Query(l))
                                        ELSE @]

\* Whether the loop still holds memory of slot k's, of whichever incarnation (rule 10, TLS rule 3).
Borrowed(st, k) ==
    \E op \in DOMAIN st.ops : op.kind \in {"connect", "sendRecords"} /\ op.target = k

\* A slot for a new connection: the first closed one, or else the first nobody uses, closed to make
\* room; never one the loop still borrows, and never closed to make room over TLS (TLS rule 6).
FreeConn(st) ==
    LET closed == {k \in 0..Conns - 1 : st.conns[k].stage = "closed" /\ ~Borrowed(st, k)}
        unused == {k \in 0..Conns - 1 : st.conns[k].users = 0 /\ ~Borrowed(st, k)}
    IN IF closed # {} THEN <<{Least(closed)}, st>>
       ELSE IF Tls THEN <<{}, st>>
       ELSE IF unused # {} THEN <<{Least(unused)}, Shut(st, Least(unused))>>
       ELSE <<{}, st>>

\* Opens a connection to server v, resuming with its ticket and spending it over TLS (TLS rule 8).
OpenConn(st, v) ==
    LET found == FreeConn(st)
        room == found[2]
    IN IF found[1] = {} \/ room.starved \/ room.jammed THEN <<{}, room>>
       ELSE
       LET k == Get(found[1])
           resumed == Tls /\ room.tickets[v]
           spent == IF resumed THEN [room EXCEPT !.tickets[v] = FALSE] ELSE room
           opened == [spent EXCEPT !.conns[k] =
                          [NoConn EXCEPT !.stage = "connecting", !.server = v, !.resumed = resumed]]
       IN <<{k}, [opened EXCEPT !.ops = Add(@, Op("connect", k))]>>

\* The connection to server v a lookup may join: not one that is closing (TLS rule 5).
FindConn(st, v) ==
    LET ks == {k \in 0..Conns - 1 : st.conns[k].stage \notin {"closed", "closing"} /\
                                    st.conns[k].server = v}
    IN IF ks = {} THEN {} ELSE {Least(ks)}

\* The lookup asks for a stream to its server (rule 1).
Want(st, l) ==
    LET v == ServerOf(st, l)
        found == IF st.slots[l].conn # {} THEN <<st.slots[l].conn, st>>
                 ELSE IF FindConn(st, v) # {} THEN <<FindConn(st, v), st>>
                 ELSE OpenConn(st, v)
        at == found[1]
        now == found[2]
    IN IF at = {} THEN TableEvent(now, l, "tcpFailed")
       ELSE
       LET k == Get(at)
           joined == IF now.slots[l].conn = {k} THEN now
                     ELSE [now EXCEPT !.slots[l].conn = {k}, !.conns[k].users = @ + 1]
       IN IF joined.conns[k].stage = "up" THEN TableEvent(joined, l, "tcpConnected") ELSE joined

RECURSIVE TellFrom(_, _, _, _)
TellFrom(st, k, connected, l) ==
    IF l >= Slots THEN st
    ELSE
    LET sl == st.slots[l]
        told == IF sl.lookup # {} /\ sl.conn = {k} /\ OnStream(Get(sl.lookup).stage)
                THEN TableEvent(st, l, IF connected THEN "tcpConnected" ELSE "tcpFailed")
                ELSE st
    IN TellFrom(told, k, connected, l + 1)

\* Tells every lookup on the connection, slot by slot, that it is up or that it failed.
TellAll(st, k, connected) == TellFrom(st, k, connected, 0)

\* The connection is no good: every lookup on it is told, and leaves it, and it is closed.
FailConn(st, k) ==
    LET told == TellAll(st, k, FALSE)
        sl == told.slots
    IN Shut([told EXCEPT !.slots = [l \in DOMAIN sl |->
                IF sl[l].conn = {k} THEN [sl[l] EXCEPT !.conn = {}] ELSE sl[l]]], k)

===============================================================================
