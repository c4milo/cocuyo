----------------------------- MODULE EngineTable -----------------------------
\* The table and the connections of the engine model. The configuration and the lookup are
\* EngineLookup.tla's, which this extends, split by the file-length rule.
EXTENDS EngineLookup

-------------------------------------------------------------------------------
\* The state.

Sockets == IF Tls \/ Request THEN 0 ELSE Servers
\* A request connection for each server, over DoQ (§24, request rule 1).
RServers == IF Request /\ ~Channel THEN Servers ELSE 0
\* A channel for each server, over DoH through colibri's client, and two links each (rule 18).
CServers == IF Channel THEN Servers ELSE 0
\* The request slots: one pool, smaller than the engine's default of 2 × `lookups`, so that a walk
\* fills it. Two lookups over two servers reach four requests (§24, request rule 3).
Pool == IF Request THEN Slots + 1 ELSE 0

\* `waits`: the slot's lookup waits for a connection slot, on no connection (the stream's rule 12).
NoSlot == [lookup |-> {}, order |-> <<>>, conn |-> {}, busy |-> FALSE, held |-> FALSE,
           heldCurrent |-> FALSE, reported |-> FALSE, expired |-> FALSE, remaining |-> 0,
           sentFrom |-> {}, waits |-> FALSE, kept |-> {}, keptFrom |-> {}]
\* `marked`: a lookup left the connection during its query's send, so none joins it (decision 54).
\* `keepers`: the lookups that stay on it for an open try, past their deadline (the stream's rule 3).
NoConn == [stage |-> "closed", server |-> 0, users |-> 0, keepers |-> 0, idleNow |-> FALSE, queue |-> <<>>,
           sealed |-> 0, partSent |-> FALSE, owes |-> FALSE, resumed |-> FALSE, marked |-> FALSE]
NoSock == [sent |-> 0, retiring |-> FALSE, draining |-> FALSE]
\* A request connection: its stage, the requests waiting for it to be up, the ones on a stream,
\* whether colibri owes a datagram, whether its slot's datagram buffer is lent to a send of any
\* incarnation, whether it went idle at this instant, and whether its protocol was the right one.
NoRConn == [stage |-> "closed", queue |-> <<>>, streams |-> {}, owes |-> FALSE, made |-> FALSE,
            lent |-> FALSE, idleNow |-> FALSE, alpn |-> FALSE, resumed |-> FALSE]
\* A channel: its stage, the requests it holds as exchanges, the ones taken while it shut down,
\* which wait for the next, an exchange's end it holds and has not told, and whether it went idle
\* at this instant (rules 18, 21 and 24).
NoChan == [stage |-> "closed", exchanges |-> {}, queue |-> <<>>, held |-> {}, idleNow |-> FALSE]
\* A channel's link: its socket's state, whether its buffer is lent to a send and over TCP its
\* address to a connect, of any incarnation, whether the channel owes octets on it, whether the
\* engine keeps octets of it not yet sent, and whether its connection started with a ticket.
NoLink == [state |-> "down", lent |-> FALSE, connectLent |-> FALSE, owes |-> FALSE, made |-> FALSE,
           resumed |-> FALSE]

Query(l) == [kind |-> "query", slot |-> l]
Records == [kind |-> "records", slot |-> 0]
\* An operation of the loop. `buffer` is the connection slot whose records buffer it reads, as a
\* set of one. Over TLS each send from a connection reads one, a query's send and a send of the
\* session's own records (TLS rule 3). Every other operation reads none.
Op(kind, target) == [kind |-> kind, target |-> target, current |-> TRUE, draining |-> FALSE,
                     buffer |-> {}]
IsSend(kind) == kind \in {"send", "sendTo"}

\* A socket per server, each with its receive armed; none over TLS (§21, TLS rule 9). `slotless`
\* says that the engine told a lookup its connection failed for want of a slot over TLS, or in the
\* clear while a slot had no lookup or was marked. Both break the stream's rule 12. A model that
\* keeps its rules never sets it, so it splits no state; the check "slot waited for" asks that. So
\* it is with `joinedMarked` and "joins no marked", and `unsaid` and "marked said" (decision 54).
InitState ==
    [slots |-> [l \in 0..Slots - 1 |-> NoSlot],
     conns |-> [k \in 0..Conns - 1 |-> NoConn],
     ops |-> SetToBag({Op("receiveFrom", v) : v \in 0..Sockets - 1}),
     ready |-> <<>>, free |-> [i \in 1..Slots |-> i - 1], results |-> <<>>, lastTaken |-> {},
     failures |-> [v \in 0..Servers - 1 |-> 0], socks |-> [v \in 0..Sockets - 1 |-> NoSock],
     jammed |-> FALSE, starved |-> FALSE, tickets |-> [v \in 0..Servers - 1 |-> FALSE],
     rconns |-> [v \in 0..RServers - 1 |-> NoRConn], reqs |-> [r \in 0..Pool - 1 |-> {}],
     rfree |-> [i \in 1..Pool |-> i - 1], rorder |-> <<>>,
     chans |-> [v \in 0..CServers - 1 |-> NoChan], links |-> [i \in 0..2 * CServers - 1 |-> NoLink],
     asked |-> [i \in 0..2 * CServers - 1 |-> FALSE], slotless |-> FALSE, unsaid |-> FALSE,
     linkTickets |-> [i \in 0..2 * CServers - 1 |-> FALSE], joinedMarked |-> FALSE]

\* `kept`: the connections the slot's lookup stays on for an open try, past the deadline that moved
\* it on (the stream's rule 3). `keptFrom`: the sockets its open datagram tries went out from, as
\* `sentFrom` names one, which a draining socket stays open for (the datagram's rule 4).

\* The configured server at position p of a slot's order.
ServerAt(st, l, p) == IF p < Len(st.slots[l].order) THEN st.slots[l].order[p + 1] ELSE 0

\* The position of configured server v in a slot's order: one pass reaches each server once.
PosOf(st, l, v) ==
    LET ps == {p \in 0..Len(st.slots[l].order) - 1 : st.slots[l].order[p + 1] = v} IN
    IF ps = {} THEN Servers ELSE Least(ps)

\* Whether the slot's lookup keeps an open try at configured server v over transport `kind`.
KeepsTry(st, l, v, kind) ==
    st.slots[l].lookup # {} /\ Opened(Get(st.slots[l].lookup), PosOf(st, l, v), kind)

\* The configured server a slot's lookup is asking now.
ServerOf(st, l) ==
    LET sl == st.slots[l] IN
    IF sl.lookup = {} THEN 0
    ELSE LET lk == Get(sl.lookup) IN
         IF lk.server < Len(sl.order) THEN sl.order[lk.server + 1] ELSE 0

-------------------------------------------------------------------------------
\* The table.

Offer(st, l) == IF Contains(st.ready, l) THEN st ELSE [st EXCEPT !.ready = Append(@, l)]

\* A lookup in `tcpReady` is offered for its send, and its deadline stands beside it.
Settle(st, l) ==
    IF st.slots[l].lookup = {} \/ WaitsOnServer(Get(st.slots[l].lookup).stage) THEN st
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

\* Whether the event arms the lookup's deadline: a connect asked for, a query sent, a connection up.
Rearms(ev, out, after) ==
    \/ out = "connectTcp"
    \/ ev = "sent" /\ after.stage \in {"awaitingTcp", "awaitingUdp"}
    \/ ev = "tcpConnected" /\ after.stage = "tcpReady"

\* One event on one lookup, through the table: the servers learn what it says of them, its wait
\* follows it, and its send is forgotten when it drew a new transaction or ended.
LookupEvent(st, l, ev, r) ==
    IF st.slots[l].lookup = {} THEN <<st, "none">>
    ELSE
    LET lk == Get(st.slots[l].lookup)
        \* An earlier try's event speaks for the server that try went to.
        v == IF ev \in {"earlier", "earlierFailed"} THEN ServerAt(st, l, r[1]) ELSE ServerOf(st, l)
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
              \* SERVFAIL is the server's failure, as a timeout is, and any other answer the lookup
              \* accepts is the server up; a reply it ignores says nothing (§19 step 12). Nor does
              \* a datagram the buffer cut, which no check 6 read (§7).
              [] ev = "reply" ->
                    IF out # "accepted" \/ r \in {"unmatched", "cut"} THEN st
                    ELSE IF r = "servfail" THEN RecordFailure(st, v)
                    ELSE RecordSuccess(st, v)
              [] ev = "earlier" ->
                    IF out # "accepted" \/ r[3] = "cut" THEN st
                    ELSE IF r[3] = "servfail" THEN RecordFailure(st, v)
                    ELSE RecordSuccess(st, v)
              [] ev = "earlierFailed" ->
                    IF Opened(lk, r[1], r[2]) /\ r[3] # "local" THEN RecordFailure(st, v) ELSE st
              [] OTHER -> st
        \* A datagram try left open at its deadline keeps the socket it went out from, until that
        \* try closes (the datagram's rule 4).
        held == IF ev = "expire" /\ lk.stage = "awaitingUdp" /\ ~Request
                THEN counted.slots[l].keptFrom \cup counted.slots[l].sentFrom
                ELSE counted.slots[l].keptFrom
        from == {x \in held : Opened(after, PosOf(counted, l, x[1]), "udp")}
        kept == [counted EXCEPT !.slots[l].lookup = {after}, !.slots[l].keptFrom = from]
        rearmed == Rearms(ev, out, after)
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

\* Whether connection k's send in flight is a query's: its head is a query whose send is in flight
\* (the stream's rule 9). Over TLS the head may be the session's own records, whose send reads the
\* slot's records buffer and no lookup's buffer.
QueryInFlight(st, k) ==
    LET q == st.conns[k].queue IN q # <<>> /\ Head(q).kind = "query" /\ Sending(st, Head(q).slot)

RECURSIVE TellKeptFrom(_, _, _, _)
\* Tells every lookup that stays on connection k for an open try that k ended, for `reason`, slot
\* by slot, and takes it off k. That closes the try. A failure is its server's; `local`, a close the
\* engine made itself, is no server's (the stream's rule 5).
TellKeptFrom(st, k, reason, l) ==
    IF l >= Slots THEN st
    ELSE
    LET v == st.conns[k].server
        told == IF k \in st.slots[l].kept /\ KeepsTry(st, l, v, "tcp")
                THEN LookupEvent(st, l, "earlierFailed", <<PosOf(st, l, v), "tcp", reason>>)[1] ELSE st
        off == IF k \in told.slots[l].kept
               THEN [told EXCEPT !.slots[l].kept = @ \ {k}, !.conns[k].keepers = Sub(@, 1)]
               ELSE told
    IN TellKeptFrom(off, k, reason, l + 1)

TellKept(st, k, reason) == TellKeptFrom(st, k, reason, 0)

\* Shuts connection k, which the engine closes itself, after telling its keepers `local`.
ShutTelling(st, k) == Shut(TellKept(st, k, "local"), k)

\* Whether a leave shuts connection k at once: no lookup is on it, and a query's send is in flight.
\* That send holds a lookup's buffer, and the shut cancels it (§16 decision 53).
LeaveShuts(st, k) == st.conns[k].users = 0 /\ QueryInFlight(st, k)

\* The lookup in slot l left connection k, in `before`, during its own query's send, and a lookup
\* stays: the drive marks k until k ends, and no lookup joins it again (§16 decision 54).
MarkLeft(before, st, k, l) ==
    IF st.conns[k].users > 0 /\ HeadIs(before.conns[k].queue, Query(l)) /\ Sending(before, l)
    THEN [st EXCEPT !.conns[k].marked = TRUE] ELSE st

\* The lookup in slot l, no longer on connection k in `left`, leaves it: its query that has not
\* started goes too. When no lookup stays during a query's send, the drive shuts the connection.
\* When one stays, MarkLeft decides.
LeaveConn(left, l, k) ==
    LET waiting == Contains(left.conns[k].queue, Query(l)) /\ ~Sending(left, l)
        freed == IF waiting THEN [left EXCEPT !.slots[l].busy = FALSE] ELSE left
        users == Sub(freed.conns[k].users, 1)
        released == [freed EXCEPT !.conns[k].users = users,
                                  !.conns[k].idleNow = @ \/ (users = 0 /\ freed.conns[k].keepers = 0),
                                  !.conns[k].queue = IF waiting
                                                     THEN SelectSeq(@, LAMBDA e : e # Query(l))
                                                     ELSE @]
        marked == MarkLeft(left, released, k, l)
    IN IF LeaveShuts(marked, k) THEN ShutTelling(marked, k) ELSE marked

\* The lookup leaves its connection.
Release(st, l) ==
    IF st.slots[l].conn = {} THEN st
    ELSE LET k == Get(st.slots[l].conn) IN LeaveConn([st EXCEPT !.slots[l].conn = {}], l, k)

\* The lookup leaves connection k that it stayed on for an open try (the stream's rule 3). With no
\* lookup left, the connection is idle from now.
ReleaseKept(st, l, k) ==
    LET keepers == Sub(st.conns[k].keepers, 1) IN
    [st EXCEPT !.slots[l].kept = @ \ {k}, !.conns[k].keepers = keepers,
               !.conns[k].idleNow = @ \/ (keepers = 0 /\ st.conns[k].users = 0)]

\* The lookup's connection moves to the ones it stays on: its query went out there, and the try it
\* went out for is open (the stream's rule 3; §16 decision 66). Nothing of it waits in the queue. It
\* is a keeper there now, and no user, so its leave as a user follows the rules of a leave.
Keep(st, l) ==
    LET k == Get(st.slots[l].conn) IN
    LeaveConn([st EXCEPT !.slots[l].conn = {}, !.slots[l].kept = @ \cup {k},
                         !.conns[k].keepers = @ + 1], l, k)

\* Whether the loop still holds memory of slot k's, of whichever incarnation: its address, which a
\* connect reads, or its records buffer, which a send over TLS reads (rule 10, TLS rule 3).
Borrowed(st, k) ==
    \E op \in DOMAIN st.ops : (op.kind = "connect" /\ op.target = k) \/ op.buffer = {k}

\* A slot for a new connection: the first closed one, or else the first nobody uses, closed to make
\* room; never one the loop still borrows, and never closed to make room over TLS (TLS rule 6). In
\* the clear, with no slot free and none that a cancelled connect borrows, the first connection
\* nobody uses whose connect is in flight is closed. Its slot frees at that connect's event, and
\* the lookup waits for it (rules 10 and 12).
FreeConn(st) ==
    LET closed == {k \in 0..Conns - 1 : st.conns[k].stage = "closed" /\ ~Borrowed(st, k)}
        unused == {k \in 0..Conns - 1 : st.conns[k].users = 0 /\ ~Borrowed(st, k)}
        lapsed == {k \in 0..Conns - 1 : st.conns[k].users = 0 /\ st.conns[k].stage # "closed" /\
                                        Borrowed(st, k)}
        cancelled == \E k \in 0..Conns - 1 : st.conns[k].stage = "closed" /\ Borrowed(st, k)
    IN IF closed # {} THEN <<{Least(closed)}, st>>
       ELSE IF Tls THEN <<{}, st>>
       ELSE IF unused # {} THEN <<{Least(unused)}, ShutTelling(st, Least(unused))>>
       ELSE IF lapsed # {} /\ ~cancelled THEN <<{}, Shut(st, Least(lapsed))>>
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

\* The connection to server v a lookup may join: not closing (TLS rule 5), not marked (decision 54).
FindConn(st, v) ==
    LET ks == {k \in 0..Conns - 1 : st.conns[k].stage \notin {"closed", "closing"} /\
                                    ~st.conns[k].marked /\ st.conns[k].server = v}
    IN IF ks = {} THEN {} ELSE {Least(ks)}

\* Whether connection slot k frees with no lookup leaving it (the stream's rule 12). Its connection
\* closes, or the loop borrows it while it is closed.
Frees(st, k) ==
    LET c == st.conns[k] IN
    c.stage = "closing" \/ (Borrowed(st, k) /\ c.stage = "closed")

\* Whether a slot is pending, which a lookup that finds no free slot waits for (rule 12).
Pending(st) == \E k \in 0..Conns - 1 : Frees(st, k)

\* Whether a marked connection that is up holds a slot, which frees at its last leave (decision 54).
Marked(st) == \E k \in 0..Conns - 1 : st.conns[k].marked /\ st.conns[k].stage = "up"

\* The lookup goes on connection k, and hears at once when it is up. `joinedMarked` notes a mistake.
JoinConn(st, l, k) ==
    LET joined == IF st.slots[l].conn = {k} THEN st
                  ELSE [st EXCEPT !.slots[l].conn = {k}, !.conns[k].users = @ + 1,
                                  !.joinedMarked = @ \/ st.conns[k].marked]
    IN IF joined.conns[k].stage = "up" THEN TableEvent(joined, l, "tcpConnected") ELSE joined

\* The lookup asks for a stream to its server (rule 1). With no slot free, it waits while one is
\* pending, which FreeConn may have made so in the clear, or while a marked connection holds a slot
\* (§16 decision 54). It is told its connection failed when neither is so (rule 12).
Want(st, l) ==
    LET v == ServerOf(st, l)
        found == IF st.slots[l].conn # {} THEN <<st.slots[l].conn, st>>
                 ELSE IF FindConn(st, v) # {} THEN <<FindConn(st, v), st>>
                 ELSE OpenConn(st, v)
        now == found[2]
        roomless == FreeConn(st)[1] = {}
        \* What `slotless` judges by, read from neither FreeConn nor Pending, so that a mutant of
        \* the engine's choice is judged by the rule. With no socket or submission refused, a
        \* lookup told it failed found each slot held by a lookup on no marked one, never over TLS.
        unheld == ~st.jammed /\ ~st.starved /\
                  (Tls \/ \E k \in 0..Conns - 1 : st.conns[k].users = 0 \/ st.conns[k].marked)
    IN IF found[1] # {} THEN JoinConn(now, l, Get(found[1]))
       ELSE IF roomless /\ (Pending(now) \/ Marked(now)) THEN [now EXCEPT !.slots[l].waits = TRUE]
       ELSE TableEvent(IF unheld THEN [now EXCEPT !.slotless = TRUE] ELSE now, l, "tcpFailed")

\* The lookup in table slot l, which waits, joins its server's connection or opens one as Want
\* does. A slot it cannot have, or a refusal, leaves it waiting for the next drive (rule 12).
AdmitOne(st, l) ==
    LET v == ServerOf(st, l)
        found == IF FindConn(st, v) # {} THEN <<FindConn(st, v), st>> ELSE OpenConn(st, v)
    IN IF found[1] = {} THEN found[2]
       ELSE JoinConn([found[2] EXCEPT !.slots[l].waits = FALSE], l, Get(found[1]))

RECURSIVE AdmitFrom(_, _)
AdmitFrom(st, l) ==
    IF l >= Slots THEN st ELSE AdmitFrom(IF st.slots[l].waits THEN AdmitOne(st, l) ELSE st, l + 1)

\* What the drive does at its end: each lookup that waits for a slot admitted, slot by slot.
Admit(st) == AdmitFrom(st, 0)

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

\* The connection is no good: every lookup on it is told, and leaves it, and it is closed. Since
\* 2026-11-03 that is each lookup that stays on it for an open try too (the stream's rule 5).
FailConn(st, k) ==
    LET told == TellKept(TellAll(st, k, FALSE), k, "failed")
        sl == told.slots
    IN Shut([told EXCEPT !.slots = [l \in DOMAIN sl |->
                [sl[l] EXCEPT !.conn = IF @ = {k} THEN {} ELSE @]]], k)

===============================================================================
