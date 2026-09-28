-------------------------------- MODULE EngineEvents ---------------------------
\* The engine's drive, its events, and the events the caller and the loop may deliver, as the Lean
\* model before it had them. Split from Engine.tla, which extends this, by the file-length rule,
\* with nothing moved past what it came before: TLC orders strings as it first reads them, and the
\* committed walks are TLC's.
EXTENDS EngineChannel

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
         [] out = "sendRequest" ->
                <<IF Channel THEN ChanTake(placed, l) ELSE TakeRequest(placed, l), TRUE>>
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

\* Every lookup polled and every request its lookup left cancelled, the idle connections and
\* channels closed when time moved, then every connection that reads given its receive and every
\* socket and link tended.
Drive(st, moved) ==
    LET polled == IF Channel THEN CancelLeftC(PollAll(st)) ELSE CancelLeft(PollAll(st))
        idled == IF moved THEN CloseIdleC(CloseIdleR(CloseIdle(polled))) ELSE polled
    IN TendLinks(TendRConns(TendSockets(TendConns(idled))))

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

\* Whether a failure on connection k is a resumed handshake's, which rule 8 opens again in full.
\* One once up is the server's, resumed or not (TLS rule 4).
Resumed(st, k) == st.conns[k].resumed /\ st.conns[k].stage = "handshaking"

\* The session's step on what connection k received (TLS rules 1, 2, 4 and 8).
TlsStep(st, k, t) ==
    IF st.conns[k].stage = "closing" THEN st
    ELSE
    LET owing == IF t \in {"failed", "ticket"} THEN st ELSE [st EXCEPT !.conns[k].owes = TRUE] IN
    CASE t \in {"flight", "rekey"} -> MakeRecords(owing, k)
      [] t = "ticket" -> [owing EXCEPT !.tickets[owing.conns[k].server] = TRUE]
      [] t = "failed" -> IF Resumed(owing, k) THEN RetryFull(owing, k) ELSE Refuse(owing, k)
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
Tick(st) ==
    LET c == st.conns
        r == st.rconns
        ch == st.chans
    IN [st EXCEPT !.conns = [k \in DOMAIN c |-> [c[k] EXCEPT !.idleNow = FALSE]],
                  !.rconns = [v \in DOMAIN r |-> [r[v] EXCEPT !.idleNow = FALSE]],
                  !.chans = [v \in DOMAIN ch |-> [ch[v] EXCEPT !.idleNow = FALSE]]]

Finish(st, op, outcome) ==
    CASE op.kind \in {"send", "sendTo", "sendRecords"} -> SendEnded(st, op, outcome)
      [] op.kind = "connect" -> ConnectEnded(st, op, outcome = "ok")
      [] op.kind = "receive" -> ReceiveEnded(st, op, outcome)
      [] op.kind = "receiveFrom" -> ReceiveFromEnded(st, op)
      [] op.kind = "qsend" -> QSendEnded(st, op, outcome)
      [] op.kind = "qrecv" -> QRecvEnded(st, op, outcome)
      [] op.kind = "rconnect" -> RConnectEnded(st, op, outcome = "ok")
      [] op.kind = "lsend" -> LSendEnded(st, op, outcome)
      [] op.kind = "lrecv" -> LRecvEnded(st, op, outcome)
      [] op.kind = "lconnect" -> LConnectEnded(st, op, outcome = "ok")

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
      [] e.kind = "quic" -> Drive(QuicStep(st, e.op.target, e.step, e.slot, e.reply), FALSE)
      [] e.kind = "qtime" -> Drive(QuicTime(st, e.server, e.step), FALSE)
      [] e.kind = "lapse" -> [st EXCEPT !.tickets[e.server] = FALSE]
      [] e.kind = "exhaust" -> [st EXCEPT !.rconns[e.server].spent = TRUE]
      [] e.kind = "straggle" -> Drive(st, FALSE)
      [] e.kind = "jam" -> [st EXCEPT !.jammed = TRUE]
      [] e.kind = "starve" -> [st EXCEPT !.starved = TRUE]
      [] e.kind = "chan" -> Drive(ChanStep(st, e.step, e.server, e.slot, e.reply), FALSE)

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
    \* Over TCP a request connection's send may go short, and its receive end with no octets
    \* (request rule 15).
    ELSE IF op.kind = "qsend" /\ op.current /\ RStream THEN {"ok", "short", "failed"}
    ELSE IF op.kind \in {"sendRecords", "sendTo", "qsend"} THEN {"ok", "failed"}
    ELSE IF op.kind = "qrecv" /\ op.current /\ RStream THEN {"failed", "exhausted", "ended"}
    ELSE IF op.kind \in {"receive", "qrecv"} /\ op.current THEN {"failed", "exhausted"}
    ELSE IF op.kind = "receiveFrom" /\ op.current THEN {"exhausted"}
    \* A link's send over TCP may go short, and its receive end with no octets (rule 19, request
    \* rule 15).
    ELSE IF op.kind = "lsend" /\ op.current /\ IsTcp(op.target) THEN {"ok", "short", "failed"}
    ELSE IF op.kind = "lsend" THEN {"ok", "failed"}
    ELSE IF op.kind = "lrecv" /\ op.current /\ IsTcp(op.target)
    THEN {"failed", "exhausted", "ended"}
    ELSE IF op.kind = "lrecv" /\ op.current THEN {"failed", "exhausted"}
    ELSE IF op.current THEN {"ok", "failed"}
    ELSE {"ok", "failed", "canceled"}

Receives(op) == op.kind \in {"receive", "receiveFrom", "qrecv"}

\* What the session makes of what a TLS connection's current receive brought (§21).
TlsSteps(st, op) ==
    IF ~(Tls /\ op.kind = "receive" /\ op.current) THEN {}
    ELSE CASE st.conns[op.target].stage = "handshaking" -> {"flight", "done", "failed"}
           [] st.conns[op.target].stage = "up" -> {"rekey", "ticket", "failed"}
           \* A record after the close_notify, which is not read (TLS rule 5).
           [] st.conns[op.target].stage = "closing" -> {"rekey"}
           [] OTHER -> {}

\* What colibri may tell of a request connection: a step on what its receive brought, a stream
\* answered or reset, one held, or its timer (EngineRequest.tla). Built here, after `Ev` (see
\* there).
RequestEvents(st) ==
    UNION {{[Ev("quic") EXCEPT !.op = op, !.step = t] : t \in QuicSteps(st, op.target)} \cup
           {[Ev("quic") EXCEPT !.op = op, !.step = "answer", !.slot = l, !.reply = r] :
                l \in Unheld(st, op.target), r \in {"answer", "servfail", "nxdomain"}} \cup
           {[Ev("quic") EXCEPT !.op = op, !.step = "reset", !.slot = l] :
                l \in Unheld(st, op.target)} \cup
           {[Ev("quic") EXCEPT !.op = op, !.step = "hold", !.slot = l, !.reply = r] :
                l \in Holdable(st, op.target), r \in {"answer", "servfail", "nxdomain", "reset"}} :
           op \in QReceives(st)} \cup
    {[Ev("qtime") EXCEPT !.server = v, !.step = t] : v \in QTimed(st), t \in {"retransmit", "timeout"}}

\* What a channel may say at a read (EngineChannel.tla): open a link it has none of for its
\* exchanges, close one it asked for, owe octets or a ticket on a running one, end an exchange,
\* hold one while a link's send is in flight, and closed once shut down with every link closed.
ChannelEvents(st) ==
    UNION {LET c == st.chans[v]
               say(step, n) == [Ev("chan") EXCEPT !.step = step, !.server = n]
               \* An answer ends the lookup, and a failure moves it on: the other replies move the
               \* lookup as these do, and the channel not at all.
               replies == {"answer", "failed"}
               sending == \E i \in LinksOf(v) : LSending(st, i)
               held == {h.slot : h \in c.held}
               opens == IF c.exchanges = {} THEN {}
                        ELSE {i \in LinksOf(v) : st.links[i].state \in {"down", "closing"}}
               running == {i \in LinksOf(v) : st.links[i].state = "running"}
               shut == c.stage = "shutting" /\ c.exchanges = {} /\
                       \A i \in LinksOf(v) : ~st.asked[i]
           IN IF c.stage = "closed" THEN {}
              ELSE {say("open", i) : i \in opens} \cup
                   {say("close", i) : i \in {i \in LinksOf(v) : st.asked[i]}} \cup
                   {say("octets", i) : i \in {i \in running : ~st.links[i].owes}} \cup
                   {say("newTicket", i) : i \in {i \in running : ~st.linkTickets[i]}} \cup
                   {[say("finished", v) EXCEPT !.slot = l, !.reply = r] :
                        l \in c.exchanges \ held, r \in replies} \cup
                   {[say("hold", v) EXCEPT !.slot = l, !.reply = r] :
                        l \in IF sending /\ held = {} THEN c.exchanges ELSE {}, r \in replies} \cup
                   (IF shut THEN {say("closed", v)} ELSE {})
           : v \in 0..CServers - 1}

Enabled(st) ==
    (IF st.free # <<>> THEN {Ev("start")} ELSE {}) \cup
    (IF st.results # <<>> \/ st.lastTaken # {} THEN {Ev("take")} ELSE {}) \cup
    {[Ev("cancel") EXCEPT !.slot = l] :
        l \in {l \in 0..Slots - 1 : st.slots[l].lookup # {} /\ ~Ended(Get(st.slots[l].lookup).stage)}} \cup
    (IF WaitingSlots(st) # {} THEN {Ev("expire")} ELSE {}) \cup
    (IF \/ \E k \in 0..Conns - 1 : st.conns[k].stage # "closed" /\ st.conns[k].users = 0
        \/ \E v \in 0..RServers - 1 : st.rconns[v].stage \in IdleStages /\ RUsers(st, v) = 0
        \/ \E v \in 0..CServers - 1 : st.chans[v].stage = "open" /\ CUsers(st, v) = 0
     THEN {Ev("idle")} ELSE {}) \cup
    RequestEvents(st) \cup ChannelEvents(st) \cup
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
    {[Ev("exhaust") EXCEPT !.server = v] : v \in Spendable(st)} \cup
    (IF st.jammed THEN {} ELSE {Ev("jam")}) \cup
    (IF st.starved THEN {} ELSE {Ev("starve")})

===============================================================================
