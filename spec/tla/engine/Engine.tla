-------------------------------- MODULE Engine --------------------------------
\* What must hold after each event, and the specification. `s` is the engine; `broken` names the
\* checks the last event broke, empty in every state of a model that keeps its rules, so it splits
\* no state and TLC counts what the Lean walker counted. The checks read the event as well as the
\* two states, which an invariant of TLC's cannot, so the step writes them down and `Clean` asks.
\* The drive and the events are EngineEvents.tla's.
EXTENDS EngineEvents

VARIABLES s, broken

-------------------------------------------------------------------------------
\* What must hold after an event took `before` to `st`.

UsersCounted(st) ==
    \A k \in 0..Conns - 1 :
        st.conns[k].users = Cardinality({l \in 0..Slots - 1 : st.slots[l].conn = {k}})

AttachedRight(st) ==
    \A l \in 0..Slots - 1 :
        LET sl == st.slots[l] IN
        sl.conn = {} \/
        LET k == Get(sl.conn) IN
        st.conns[k].stage # "closed" /\
        (Contains(st.ready, l) \/
         (sl.lookup # {} /\ OnStream(Get(sl.lookup).stage) /\ st.conns[k].server = ServerOf(st, l)))

BuffersLent(st) ==
    \A l \in 0..Slots - 1 :
        LET sends == Count(st.ops, LAMBDA op : IsSend(op.kind) /\ op.target = l)
            queued == \E k \in 0..Conns - 1 : Contains(st.conns[k].queue, Query(l))
        IN sends <= 1 /\ (st.slots[l].busy = (sends = 1 \/ queued))

BorrowKept(st) ==
    \A op \in DOMAIN st.ops :
        op.kind \notin {"connect", "sendRecords"} \/ op.current \/
        st.conns[op.target].stage \in {"closed", "reopening"}

RECURSIVE AllQueued(_, _)
AllQueued(st, k) == IF k >= Conns THEN <<>> ELSE Queued(st, k) \o AllQueued(st, k + 1)

NoRepeats(seq) == \A i, j \in 1..Len(seq) : i # j => seq[i] # seq[j]

OneSendAStream(st) ==
    NoRepeats(AllQueued(st, 0)) /\
    \A k \in 0..Conns - 1 :
        LET q == st.conns[k].queue
            queries == {i \in 1..Len(Queued(st, k)) : Sending(st, Queued(st, k)[i])}
            records == Count(st.ops, LAMBDA op :
                           op.kind = "sendRecords" /\ op.target = k /\ op.current)
        IN /\ Cardinality(queries) + records <= 1
           /\ \A i \in queries : HeadIs(q, Query(Queued(st, k)[i]))
           /\ (records = 0 \/ HeadIs(q, Records))

\* A query waits in a connection's queue only while its lookup is on that connection, or once it has
\* started going out: a message whose lookup moved on before any of it went out left the queue
\* and gave its buffer back (the stream's rule 9).
QueuedForItsLookup(st) ==
    \A k \in 0..Conns - 1 :
        \A i \in 1..Len(st.conns[k].queue) :
            LET e == st.conns[k].queue[i] IN
            e.kind = "query" => st.slots[e.slot].conn = {k} \/ Sending(st, e.slot)

SealedInOrder(st) ==
    \A k \in 0..Conns - 1 :
        LET c == st.conns[k] IN
        /\ c.sealed <= Len(c.queue)
        /\ Len(SelectSeq(c.queue, LAMBDA e : e.kind = "records")) <= 2
        /\ \A i \in (c.sealed + 1)..Len(c.queue) : c.queue[i].kind = "query"
        /\ \A i \in 2..Lesser(c.sealed, Len(c.queue)) : c.queue[i].kind = "records"
        /\ ((c.sealed > 0) = InFlight(st, k) \/ st.jammed)

Answered(st) == \A k \in 0..Conns - 1 : ~st.conns[k].owes

QueriesAfterUp(st) ==
    \A k \in 0..Conns - 1 :
        LET c == st.conns[k] IN
        c.stage \in {"up", "closing"} \/ \A i \in 1..Len(c.queue) : c.queue[i].kind # "query"

OpsCurrent(st) ==
    \A k \in 0..Conns - 1 :
        LET connects == Count(st.ops, LAMBDA op : op.kind = "connect" /\ op.target = k /\ op.current)
            receives == Count(st.ops, LAMBDA op : op.kind = "receive" /\ op.target = k /\ op.current)
            stage == st.conns[k].stage
        IN IF stage = "connecting" THEN connects = 1 /\ receives = 0
           ELSE IF stage \in {"handshaking", "up", "closing"}
           THEN connects = 0 /\ receives <= 1
           ELSE connects = 0 /\ receives = 0

SocksCurrent(st) ==
    \A v \in 0..Sockets - 1 :
        LET armed(draining) == Count(st.ops, LAMBDA op :
                op.kind = "receiveFrom" /\ op.target = v /\ op.current /\ op.draining = draining)
        IN armed(FALSE) <= 1 /\
           IF st.socks[v].draining THEN armed(TRUE) <= 1 ELSE armed(TRUE) = 0

ListeningAll(st) ==
    /\ \A v \in 0..Sockets - 1 :
          Listening(st, v, FALSE) /\ (~st.socks[v].draining \/ Listening(st, v, TRUE))
    /\ \A k \in 0..Conns - 1 : ~Reads(st.conns[k].stage) \/ Receiving(st, k)

RotatedAll(st) ==
    \A v \in 0..Sockets - 1 :
        (~st.socks[v].retiring \/ st.socks[v].draining) /\
        (~st.socks[v].draining \/ DrainNeeded(st, v))

DriveDone(st) == st.ready = <<>>

TicketSpent(before, st) ==
    \A k \in 0..Conns - 1 :
        ~(st.conns[k].resumed /\ before.conns[k].stage = "closed") \/
        ~st.tickets[st.conns[k].server]

ReopenedInFull(before, st) ==
    \A k \in 0..Conns - 1 :
        LET c == st.conns[k] IN
        (c.stage # "reopening" \/ ~c.resumed) /\
        (before.conns[k].stage # "reopening" \/ c.stage = "reopening" \/ ~c.resumed)

DeclineForgiven(before, e, st) ==
    ~(e.kind = "tls" /\ e.step = "failed") \/
    LET k == e.op.target IN
    ~Resumed(before, k) \/ before.jammed \/ before.starved \/
    (st.failures = before.failures /\
     \A l \in 0..Slots - 1 : before.slots[l].conn # {k} \/ st.slots[l].conn = {k})

\* A handshake the session refused, not resumed, or a record it refused once up, leaves its
\* connection saying the session's alert: closing, with no lookup on it, nothing queued but what is
\* sealed, and the session's records among it (TLS rule 4). A loop that refuses the send closes it
\* at once instead.
RefusalSaid(before, e, st) ==
    ~(e.kind = "tls" /\ e.step = "failed") \/
    LET k == e.op.target
        c == st.conns[k]
    IN Resumed(before, k) \/ before.jammed \/ before.starved \/
       (/\ c.stage = "closing"
        /\ \A l \in 0..Slots - 1 : st.slots[l].conn # {k}
        /\ c.sealed = Len(c.queue)
        /\ SelectSeq(c.queue, LAMBDA x : x.kind = "records") # <<>>)

\* The liveness of the receives is owed only after a drive that ran with nothing refused.
Drove(before, e) ==
    e.kind \notin {"take", "jam", "starve", "lapse"} /\ ~before.jammed /\ ~before.starved

Checks(before, e, st) ==
    << <<"users counted", UsersCounted(st)>>, <<"attached right", AttachedRight(st)>>,
       <<"buffers lent", BuffersLent(st)>>, <<"one send a stream", OneSendAStream(st)>>,
       <<"borrow kept", BorrowKept(st)>>, <<"sealed in order", SealedInOrder(st)>>,
       <<"queued for its lookup", QueuedForItsLookup(st)>>,
       <<"queries after up", QueriesAfterUp(st)>>, <<"answered", Answered(st)>>,
       <<"ticket spent", TicketSpent(before, st)>>,
       <<"reopened in full", ReopenedInFull(before, st)>>,
       <<"decline forgiven", DeclineForgiven(before, e, st)>>,
       <<"refusal said", RefusalSaid(before, e, st)>>,
       <<"ops current", OpsCurrent(st)>>, <<"sockets current", SocksCurrent(st)>>,
       <<"drive done", DriveDone(st)>>,
       <<"listening", ~Drove(before, e) \/ (ListeningAll(st) /\ RListening(st) /\ LListening(st))>>,
       <<"rotated", ~Drove(before, e) \/ RotatedAll(st)>>,
       <<"requests placed", RequestsPlaced(st)>>, <<"streams when up", StreamsWhenUp(st)>>,
       <<"requests current", RequestsCurrent(st)>>, <<"closed empty", ClosedEmpty(st)>>,
       <<"datagram lent", DatagramLent(st)>>, <<"up on protocol", UpOnProtocol(st)>>,
       <<"receive current", RecvCurrent(st)>>, <<"request ticket spent", RTicketSpent(before, st)>>,
       <<"waiting kept", WaitingKept(before, e, st)>>,
       <<"links asked", LinksAsked(st)>>, <<"link lent", LinkLent(st)>>,
       <<"exchanges placed", ExchangesPlaced(st)>>,
       <<"shutting takes none", ShutTakesNone(before, st)>>,
       <<"channel held while sending", ChanHeldWhileSending(st)>>,
       <<"link ticket spent", LinkTicketSpent(before, st)>>,
       <<"link end fails none", LinkEndFailsNone(before, e, st)>> >>

Broken(before, e, st) ==
    LET checks == Checks(before, e, st) IN
    {checks[i][1] : i \in {i \in 1..Len(checks) : ~checks[i][2]}}

-------------------------------------------------------------------------------
\* The specification.

\* The walk's bound: nothing else bounds the graph (spec/README.md).
Within ==
    /\ BagCardinality(s.ops) <= OpsMax
    /\ \A v \in 0..Servers - 1 : s.failures[v] <= FailuresMax
    /\ \A v \in 0..Sockets - 1 : s.socks[v].sent <= SentMax

Init == s = InitState /\ broken = {}

\* A state beyond the bound is reached, counted and checked, and not walked from: the Lean walker's
\* bound, which TLC's CONSTRAINT is not, since that leaves such a state unchecked.
Next ==
    /\ Within
    /\ \E e \in Enabled(s) : LET t == Step(s, e) IN s' = t /\ broken' = Broken(s, e, t)

Spec == Init /\ [][Next]_<<s, broken>>

\* Every check held on every event.
Clean == broken = {}

===============================================================================
