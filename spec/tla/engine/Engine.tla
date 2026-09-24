-------------------------------- MODULE Engine --------------------------------
\* The engine's drive, its events, the events the caller and the loop may deliver, and what must
\* hold, as the Lean model before it had them. `s` is the engine; `broken` names the checks
\* the last event broke, empty in every state of a model that keeps its rules, so it splits no
\* state and TLC counts what the Lean walker counted. The checks read the event as well as the two
\* states, which an invariant of TLC's cannot, so the step writes them down and `Clean` asks.
EXTENDS EngineIo

VARIABLES s, broken

-------------------------------------------------------------------------------
\* The drive.

Report(st, l) ==
    IF st.slots[l].reported THEN <<st, FALSE>>
    ELSE <<[Release([st EXCEPT !.slots[l].reported = TRUE], l) EXCEPT !.results = Append(@, l)],
           TRUE>>

\* What the drive does with one lookup's poll: off its connection unless it streams to that
\* connection's server (rule 3), then what the poll asked. Says whether the lookup moved on.
Act(st, l, out) ==
    LET sl == st.slots[l]
        placed == IF sl.conn # {} /\ sl.lookup # {} /\
                     ~(OnStream(Get(sl.lookup).stage) /\
                       st.conns[Get(sl.conn)].server = ServerOf(st, l))
                  THEN Release(st, l) ELSE st
    IN CASE out = "connectTcp" -> <<Want(placed, l), TRUE>>
         [] out \in {"sendTcp", "sendUdp"} -> <<Send(placed, l), TRUE>>
         [] out \in {"done", "failed"} -> Report(placed, l)
         [] OTHER -> <<placed, TRUE>>

\* One poll: the lookup's order fixed at its first, its expiry if its deadline came.
PollOne(st, l) ==
    LET sl == st.slots[l] IN
    IF sl.lookup = {} THEN <<st, "none">>
    ELSE
    LET lk == Get(sl.lookup)
        ordered == IF sl.order = <<>> /\ ~Ended(lk.stage)
                   THEN [st EXCEPT !.slots[l].order = SortByFailures(st.failures)] ELSE st
        ev == IF sl.expired /\ Waiting(lk.stage) THEN "expire" ELSE "poll"
    IN LookupEvent([ordered EXCEPT !.slots[l].expired = FALSE], l, ev, "none")

Live(st) == Cardinality({l \in 0..Slots - 1 : st.slots[l].lookup # {}})

RECURSIVE Go(_, _, _, _)
Go(fuel, polls, refused, st) ==
    IF fuel = 0 \/ polls >= PollsMax \/ refused > Live(st) \/ st.ready = <<>> THEN st
    ELSE
    LET l == Head(st.ready)
        polled == PollOne([st EXCEPT !.ready = Tail(@)], l)
    IN IF polled[2] = "wait" THEN Go(fuel - 1, polls, refused, polled[1])
       ELSE LET acted == Act(polled[1], l, polled[2]) IN
            Go(fuel - 1, polls + 1, IF acted[2] THEN 0 ELSE refused + 1, acted[1])

\* Polls the table until nothing is left to do or the bound is reached, as the code's drive does.
PollAll(st) == Go(4 * Slots * (Servers + 2) + 8, 0, 0, st)

\* Every lookup polled, the idle connections closed when time moved, then every connection that
\* reads given its receive and every socket tended.
Drive(st, moved) ==
    LET polled == PollAll(st) IN
    TendSockets(TendConns(IF moved THEN CloseIdle(polled) ELSE polled))

-------------------------------------------------------------------------------
\* Events.

\* A send ended: the buffer comes back, the attempt that made it hears how it went if it is still
\* the lookup's, and a held send goes out (rules 6 and 7).
ReturnBuffer(st, l, op, ok) ==
    LET freed == [st EXCEPT !.slots[l].busy = FALSE]
        heard == IF op.current THEN TableEvent(freed, l, IF ok THEN "sent" ELSE "sendFailed")
                 ELSE freed
        sl == heard.slots[l]
        dropped == [heard EXCEPT !.slots[l].held = FALSE, !.slots[l].heldCurrent = FALSE]
    IN IF sl.held /\ sl.heldCurrent THEN Send(dropped, l) ELSE dropped

\* The connection whose queue slot l's query heads, when it is still there.
HeadOf(st, l) ==
    LET ks == {k \in 0..Conns - 1 : HeadIs(st.conns[k].queue, Query(l))} IN
    IF ks = {} THEN {} ELSE {Least(ks)}

Dequeue(st, k) ==
    [st EXCEPT !.conns[k].queue = Drop(@, 1), !.conns[k].sealed = Sub(@, 1),
               !.conns[k].partSent = FALSE]

\* After a whole send a closing connection with nothing queued closes (TLS rule 5); any other sends
\* its next.
AfterSend(st, k) ==
    IF st.conns[k].stage = "closing" /\ st.conns[k].queue = <<>> THEN Shut(st, k) ELSE Pump(st, k)

SendRest(st, k, op) ==
    IF st.jammed THEN FailConn(st, k)
    ELSE [st EXCEPT !.conns[k].partSent = TRUE, !.ops = Add(@, op)]

\* A stream's send ended (the stream's rule 9).
StreamSendEnded(st, op, outcome) ==
    LET l == op.target
        h == HeadOf(st, l)
    IN IF h = {} THEN ReturnBuffer(st, l, [op EXCEPT !.current = FALSE], FALSE)
       ELSE
       LET k == Get(h) IN
       CASE outcome = "short" -> SendRest(st, k, op)
         [] outcome = "ok" -> AfterSend(ReturnBuffer(Dequeue(st, k), l, op, TRUE), k)
         [] OTHER -> FailConn([Dequeue(st, k) EXCEPT !.slots[l].busy = FALSE], k)

\* A connection waiting to open again connects in full once the loop holds nothing of its slot's
\* (TLS rule 8).
ConnectAgain(st, k) ==
    IF st.conns[k].stage # "reopening" \/ Borrowed(st, k) THEN st
    ELSE IF st.starved \/ st.jammed THEN FailConn(st, k)
    ELSE [st EXCEPT !.conns[k].stage = "connecting", !.conns[k].resumed = FALSE,
                    !.ops = Add(@, Op("connect", k))]

\* A resumed handshake failed: the session is dropped, and the connection waits, its lookups on
\* it, to connect again in full (TLS rule 8).
RetryFull(st, k) ==
    LET cancelled == CancelOps(st, k)
        c == cancelled.conns[k]
    IN ConnectAgain([cancelled EXCEPT !.conns[k] =
           [NoConn EXCEPT !.stage = "reopening", !.server = c.server, !.users = c.users,
                          !.idleNow = c.idleNow]], k)

RecordsSendEnded(st, op, outcome) ==
    LET k == op.target IN
    IF ~op.current THEN ConnectAgain(st, k)
    ELSE CASE outcome = "short" -> SendRest(st, k, op)
           [] outcome = "ok" -> AfterSend(Dequeue(st, k), k)
           [] OTHER -> FailConn(st, k)

SendEnded(st, op, outcome) ==
    LET ended == [st EXCEPT !.ops = Remove(@, op)] IN
    CASE op.kind = "sendTo" -> ReturnBuffer(ended, op.target, op, outcome = "ok")
      [] op.kind = "sendRecords" -> RecordsSendEnded(ended, op, outcome)
      [] OTHER -> StreamSendEnded(ended, op, outcome)

ReceiveFromEnded(st, op) ==
    LET ended == [st EXCEPT !.ops = Remove(@, op)] IN
    IF op.current THEN Listen(ended, op.target, op.draining) ELSE ended

\* A connect ended. Over TLS the session starts and its first flight goes, and the lookups wait for
\* the handshake's end (TLS rule 1).
ConnectEnded(st, op, ok) ==
    LET k == op.target
        ended == [st EXCEPT !.ops = Remove(@, op)]
    IN IF ~op.current THEN ended
       ELSE IF ~ok THEN FailConn(ended, k)
       ELSE IF Tls
       THEN MakeRecords(ArmReceive([ended EXCEPT !.conns[k].stage = "handshaking",
                                                 !.conns[k].idleNow = TRUE], k), k)
       ELSE TellAll(ArmReceive([ended EXCEPT !.conns[k].stage = "up",
                                             !.conns[k].idleNow = TRUE], k), k, TRUE)

\* The session's step on what connection k received (TLS rules 1, 2, 4 and 8).
TlsStep(st, k, t) ==
    IF st.conns[k].stage = "closing" THEN st
    ELSE
    LET owing == IF t \in {"failed", "ticket"} THEN st ELSE [st EXCEPT !.conns[k].owes = TRUE] IN
    CASE t \in {"flight", "rekey"} -> MakeRecords(owing, k)
      [] t = "ticket" -> [owing EXCEPT !.tickets[owing.conns[k].server] = TRUE]
      [] t = "failed" -> IF owing.conns[k].resumed THEN RetryFull(owing, k) ELSE FailConn(owing, k)
      [] t = "done" ->
            LET answered == MakeRecords(owing, k) IN
            IF answered.conns[k].stage # "handshaking" THEN answered
            ELSE TellAll([answered EXCEPT !.conns[k].stage = "up"], k, TRUE)

ReceiveEnded(st, op, outcome) ==
    LET ended == [st EXCEPT !.ops = Remove(@, op)] IN
    IF ~op.current THEN ended
    ELSE IF outcome = "exhausted" THEN ArmReceive(ended, op.target) ELSE FailConn(ended, op.target)

Message(st, l, r) ==
    LET heard == LookupEvent(st, l, "reply", r) IN
    IF heard[2] = "accepted" THEN Settle(heard[1], l) ELSE heard[1]

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

Start(st) ==
    IF st.free = <<>> THEN st
    ELSE
    LET l == Head(st.free) IN
    Offer([st EXCEPT !.free = Tail(@), !.slots[l].lookup = {LInit}, !.slots[l].order = <<>>,
                     !.slots[l].conn = {}, !.slots[l].held = FALSE,
                     !.slots[l].heldCurrent = FALSE, !.slots[l].reported = FALSE,
                     !.slots[l].expired = FALSE], l)

TakeResult(st) ==
    LET freed ==
            IF st.lastTaken = {} THEN st
            ELSE
            LET l == Get(st.lastTaken)
                listed == [st EXCEPT !.ready = SelectSeq(@, LAMBDA x : x # l),
                                     !.free = <<l>> \o @, !.lastTaken = {}]
            IN [ForgetAttempt(listed, l) EXCEPT !.slots[l].lookup = {}, !.slots[l].order = <<>>,
                                                !.slots[l].expired = FALSE]
    IN IF freed.results = <<>> THEN freed
       ELSE [freed EXCEPT !.results = Tail(@), !.lastTaken = {Head(freed.results)}]

\* Time moves: nothing went idle at the new instant yet.
Tick(st) == LET c == st.conns IN [st EXCEPT !.conns = [k \in DOMAIN c |-> [c[k] EXCEPT !.idleNow = FALSE]]]

Finish(st, op, outcome) ==
    CASE op.kind \in {"send", "sendTo", "sendRecords"} -> SendEnded(st, op, outcome)
      [] op.kind = "connect" -> ConnectEnded(st, op, outcome = "ok")
      [] op.kind = "receive" -> ReceiveEnded(st, op, outcome)
      [] op.kind = "receiveFrom" -> ReceiveFromEnded(st, op)

Cancel(st, l) ==
    IF st.slots[l].lookup # {} /\ ~Ended(Get(st.slots[l].lookup).stage)
    THEN TableEvent(st, l, "cancel") ELSE st

\* One event and the drive that follows it.
Happen(st, e) ==
    CASE e.kind = "start" -> Drive(Start(st), FALSE)
      [] e.kind = "take" -> TakeResult(st)
      [] e.kind = "cancel" -> Drive(Cancel(st, e.slot), FALSE)
      [] e.kind = "expire" -> Drive(Pass(Tick(st), Soonest(st)), TRUE)
      [] e.kind = "idle" -> Drive(Pass(Tick(st), 1), TRUE)
      [] e.kind = "finish" -> Drive(Finish(st, e.op, e.outcome), FALSE)
      [] e.kind = "message" -> Drive(Message(st, e.slot, e.reply), FALSE)
      [] e.kind = "tls" -> Drive(TlsStep(st, e.op.target, e.step), FALSE)
      [] e.kind = "lapse" -> [st EXCEPT !.tickets[e.server] = FALSE]
      [] e.kind = "straggle" -> Drive(st, FALSE)
      [] e.kind = "jam" -> [st EXCEPT !.jammed = TRUE]
      [] e.kind = "starve" -> [st EXCEPT !.starved = TRUE]

\* One event. A refusal lasts the one event after it.
Step(st, e) ==
    LET t == Happen(st, e) IN
    IF e.kind \in {"jam", "starve"} THEN t ELSE [t EXCEPT !.jammed = FALSE, !.starved = FALSE]

-------------------------------------------------------------------------------
\* What the caller and the loop may do.

NoOp == Op("connect", 0)
Ev(kind) == [kind |-> kind, op |-> NoOp, outcome |-> "-", slot |-> 0, reply |-> "-",
             step |-> "-", server |-> 0]

\* A message is for a lookup whose query went out to the receive's server: on the connection, or
\* from the very socket the receive is on.
Awaits(st, op, l) ==
    LET sl == st.slots[l] IN
    sl.lookup # {} /\
    LET stage == Get(sl.lookup).stage
        age == IF op.draining THEN "draining" ELSE "current"
    IN \/ op.kind = "receive" /\ sl.conn = {op.target} /\ stage = "awaitingTcp"
       \/ op.kind = "receiveFrom" /\ ServerOf(st, l) = op.target /\ stage = "awaitingUdp" /\
          sl.sentFrom = {<<op.target, age>>}

\* How an operation may end, as rotor decision 5, rule 2 allows.
Endings(st, op) ==
    IF op.kind = "send"
    THEN IF HeadOf(st, op.target) # {} /\ st.conns[Get(HeadOf(st, op.target))].partSent
         THEN {"ok", "failed"} ELSE {"ok", "short", "failed"}
    ELSE IF op.kind = "sendRecords" /\ op.current
    THEN IF st.conns[op.target].partSent THEN {"ok", "failed"} ELSE {"ok", "short", "failed"}
    ELSE IF op.kind \in {"sendRecords", "sendTo"} THEN {"ok", "failed"}
    ELSE IF op.kind = "receive" /\ op.current THEN {"failed", "exhausted"}
    ELSE IF op.kind = "receiveFrom" /\ op.current THEN {"exhausted"}
    ELSE IF op.current THEN {"ok", "failed"}
    ELSE {"ok", "failed", "canceled"}

Receives(op) == op.kind \in {"receive", "receiveFrom"}

\* What the session makes of what a TLS connection's current receive brought (§21).
TlsSteps(st, op) ==
    IF ~(Tls /\ op.kind = "receive" /\ op.current) THEN {}
    ELSE CASE st.conns[op.target].stage = "handshaking" -> {"flight", "done", "failed"}
           [] st.conns[op.target].stage = "up" -> {"rekey", "ticket"}
           \* A record after the close_notify, which is not read (TLS rule 5).
           [] st.conns[op.target].stage = "closing" -> {"rekey"}
           [] OTHER -> {}

Enabled(st) ==
    (IF st.free # <<>> THEN {Ev("start")} ELSE {}) \cup
    (IF st.results # <<>> \/ st.lastTaken # {} THEN {Ev("take")} ELSE {}) \cup
    {[Ev("cancel") EXCEPT !.slot = l] :
        l \in {l \in 0..Slots - 1 : st.slots[l].lookup # {} /\ ~Ended(Get(st.slots[l].lookup).stage)}} \cup
    (IF WaitingSlots(st) # {} THEN {Ev("expire")} ELSE {}) \cup
    (IF \E k \in 0..Conns - 1 : st.conns[k].stage # "closed" /\ st.conns[k].users = 0
     THEN {Ev("idle")} ELSE {}) \cup
    UNION {{[Ev("finish") EXCEPT !.op = op, !.outcome = o] : o \in Endings(st, op)} :
           op \in DOMAIN st.ops} \cup
    UNION {{[Ev("message") EXCEPT !.op = op, !.slot = l, !.reply = r] :
                l \in {l \in 0..Slots - 1 : Awaits(st, op, l)},
                r \in {"answer", "servfail", "nxdomain", "unmatched"}} :
           op \in {op \in DOMAIN st.ops : Receives(op) /\ op.current}} \cup
    UNION {{[Ev("tls") EXCEPT !.op = op, !.step = t] : t \in TlsSteps(st, op)} :
           op \in DOMAIN st.ops} \cup
    {[Ev("straggle") EXCEPT !.op = op] : op \in {op \in DOMAIN st.ops : Receives(op) /\ ~op.current}} \cup
    {[Ev("lapse") EXCEPT !.server = v] : v \in {v \in 0..Servers - 1 : st.tickets[v]}} \cup
    (IF st.jammed THEN {} ELSE {Ev("jam")}) \cup
    (IF st.starved THEN {} ELSE {Ev("starve")})

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
    ~before.conns[k].resumed \/ before.jammed \/ before.starved \/
    (st.failures = before.failures /\
     \A l \in 0..Slots - 1 : before.slots[l].conn # {k} \/ st.slots[l].conn = {k})

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
       <<"ops current", OpsCurrent(st)>>, <<"sockets current", SocksCurrent(st)>>,
       <<"drive done", DriveDone(st)>>,
       <<"listening", ~Drove(before, e) \/ ListeningAll(st)>>,
       <<"rotated", ~Drove(before, e) \/ RotatedAll(st)>> >>

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
