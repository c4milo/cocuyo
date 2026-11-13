---------------------------- MODULE EngineRequest -----------------------------
\* The engine's requests over DoQ, written from the request rules of docs/design.md §24: a QUIC
\* connection for each server over a datagram socket of its own, a pool of request slots (rule 3),
\* the streams, the one datagram a connection has in flight, the cancel of a request its
\* lookup left, the failure told to each request once, and the idle close.
\*
\* colibri is abstracted to what it tells the engine: that it owes a datagram, that the handshake
\* ended on some protocol or failed, that a stream was answered or reset, that the server closed,
\* that a ticket came, and that its timer fired. The octets are not modelled: an answer the model
\* delivers stands for a DoQ message, and a reset for a reset stream.
EXTENDS EngineIo

Distinct(seq) == \A a, b \in 1..Len(seq) : a # b => seq[a] # seq[b]

-------------------------------------------------------------------------------
\* Requests.

\* A request names its lookup's table slot, its server, and the attempt it went for. A request is
\* named by its slot in the pool, which the connections' queues and streams hold.
RequestOf(st, r) == Get(st.reqs[r])
SlotOfReq(st, r) == RequestOf(st, r).slot

\* The requests on connection v: waiting for it, and on its streams.
RUsers(st, v) == Len(st.rconns[v].queue) + Cardinality(st.rconns[v].streams)

\* Whether request r speaks for its lookup's attempt now (request rules 5 and 6).
CurrentRequest(st, r) ==
    st.reqs[r] # {} /\
    LET l == SlotOfReq(st, r) IN
    st.slots[l].lookup # {} /\
    LET lk == Get(st.slots[l].lookup) IN
    lk.stage = "awaitingUdp" /\ Attempt(lk) = RequestOf(st, r).attempt

\* Whether request r's try is open: it is its lookup's current request, or the request of an
\* earlier try the lookup keeps open (§5, Tries kept open; request rule 6).
OpenRequest(st, r) ==
    st.reqs[r] # {} /\
    (CurrentRequest(st, r) \/ KeepsTry(st, SlotOfReq(st, r), RequestOf(st, r).server, "req"))

\* Request slot r is free again: on the free list's head, and out of the order requests were taken.
FreeReq(st, r) ==
    [st EXCEPT !.reqs[r] = {}, !.rfree = <<r>> \o @, !.rorder = SelectSeq(@, LAMBDA x : x # r)]

\* Request r leaves its connection: out of the queue if it waits, and its stream cancelled if it has
\* one, which colibri owes the server STOP_SENDING and a reset for (request rule 6).
DropRequest(st, r) ==
    IF st.reqs[r] = {} THEN st
    ELSE
    LET v == RequestOf(st, r).server
        streamed == r \in st.rconns[v].streams
        left == [FreeReq(st, r) EXCEPT !.rconns[v].queue = SelectSeq(@, LAMBDA x : x # r),
                                       !.rconns[v].streams = @ \ {r}, !.rconns[v].owes = @ \/ streamed]
    IN [left EXCEPT !.rconns[v].idleNow = @ \/ RUsers(left, v) = 0]

RECURSIVE CancelLeftFrom(_, _)
CancelLeftFrom(st, r) ==
    IF r >= Pool THEN st
    ELSE CancelLeftFrom(IF st.reqs[r] # {} /\ ~OpenRequest(st, r) THEN DropRequest(st, r) ELSE st,
                        r + 1)

\* Every request whose try closed is cancelled: its lookup ended, moved to another name, was
\* cancelled, or heard that try answered or failed. A deadline alone leaves the request (request
\* rule 6; §16 decision 66).
CancelLeft(st) == CancelLeftFrom(st, 0)

RECURSIVE OldestEarlier(_, _)
\* The first request of `seq`, the order they were taken in, that is no lookup's current one.
OldestEarlier(st, seq) ==
    IF seq = <<>> THEN {}
    ELSE IF ~CurrentRequest(st, Head(seq)) THEN {Head(seq)} ELSE OldestEarlier(st, Tail(seq))

\* The pool is full and a lookup needs a slot: the oldest request that is no lookup's current one,
\* by `drop`, its lookup hearing `local` while its try is open (request rule 3). The pool holds more
\* slots than the table, so such a request is there.
EvictBy(st, Dropping(_, _)) ==
    LET found == OldestEarlier(st, st.rorder) IN
    IF ~Assert(found # {}, "a full pool of current requests") THEN st
    ELSE
    LET r == Get(found)
        l == SlotOfReq(st, r)
        v == RequestOf(st, r).server
        told == IF OpenRequest(st, r)
                THEN LookupEvent(st, l, "earlierFailed", <<PosOf(st, l, v), "req", "local">>)[1]
                ELSE st
    IN Dropping(told, r)

\* Request r of slot l at server v ended unanswered: its lookup hears it once if its try is open,
\* the current try's as `requestFailed`, an earlier one's as that try's failure (request rule 7).
TellFailed(st, r) ==
    LET l == SlotOfReq(st, r)
        v == RequestOf(st, r).server
    IN IF CurrentRequest(st, r) THEN TableEvent(st, l, "requestFailed")
       ELSE IF OpenRequest(st, r)
       THEN LookupEvent(st, l, "earlierFailed", <<PosOf(st, l, v), "req", "failed">>)[1]
       ELSE st

\* Request r of slot l at server v ended with reply `reply`: the current try's or an earlier one's.
\* A reply the lookup accepts offers it (request rule 5).
TellAnswered(st, r, reply) ==
    LET l == SlotOfReq(st, r)
        v == RequestOf(st, r).server
        heard == IF CurrentRequest(st, r) THEN LookupEvent(st, l, "reply", reply)
                 ELSE LookupEvent(st, l, "earlier", <<PosOf(st, l, v), "req", reply>>)
    IN IF ~OpenRequest(st, r) THEN st
       ELSE IF heard[2] = "accepted" THEN Settle(heard[1], l) ELSE heard[1]

\* Request r failed: its lookup hears it once, since the slot is free before anyone else can tell it
\* (request rule 7).
FailRequest(st, r) == FreeReq(TellFailed(st, r), r)

RECURSIVE FailRequestsFrom(_, _, _)
FailRequestsFrom(st, v, r) ==
    IF r >= Pool THEN st
    ELSE FailRequestsFrom(IF st.reqs[r] # {} /\ RequestOf(st, r).server = v THEN FailRequest(st, r)
                          ELSE st, v, r + 1)

-------------------------------------------------------------------------------
\* Connections.

\* Connection v's current operations are left to the loop to end. Its datagram buffer stays lent
\* until a send's final event, whichever incarnation made it (request rule 8).
ShutR(st, v) ==
    LET lent == st.rconns[v].lent IN
    [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in {"qsend", "qrecv"} /\ op.target = v THEN [op EXCEPT !.current = FALSE]
        ELSE op)] EXCEPT !.rconns[v] = [NoRConn EXCEPT !.lent = lent]]

QListen(st, v) ==
    IF st.jammed \/ Holds(st, "qrecv", v, FALSE) THEN st
    ELSE [st EXCEPT !.ops = Add(@, Op("qrecv", v))]

QReceiving(st, v) == \E op \in DOMAIN st.ops : op.kind = "qrecv" /\ op.target = v /\ op.current

\* Opens connection v for the requests in `queue`: its socket, its receive, and colibri's first
\* flight, resuming with the server's ticket, which it spends (request rules 1 and 10). A socket
\* the system refuses fails each of them.
OpenR(st, v, queue) ==
    IF st.starved THEN FailRequestsFrom(st, v, 0)
    ELSE
    LET opened == [st EXCEPT !.rconns[v].stage = "handshaking", !.rconns[v].queue = queue,
                             !.rconns[v].owes = TRUE, !.rconns[v].resumed = st.tickets[v],
                             !.rconns[v].idleNow = FALSE, !.tickets[v] = FALSE]
    IN QListen(opened, v)

\* The handshake ended on the transport's protocol: the connection is up, and each waiting request
\* opens its stream in the order it was taken (request rules 2 and 4).
UpR(st, v) ==
    LET q == st.rconns[v].queue IN
    [st EXCEPT !.rconns[v].stage = "up", !.rconns[v].alpn = TRUE, !.rconns[v].queue = <<>>,
               !.rconns[v].streams = {q[i] : i \in 1..Len(q)}, !.rconns[v].owes = TRUE]

\* The CONNECTION_CLOSE has gone: the connection closes, and opens again for the requests taken
\* while it closed (request rule 9).
ClosedR(st, v) ==
    LET q == st.rconns[v].queue
        shut == ShutR(st, v)
    IN IF q = <<>> THEN shut ELSE OpenR(shut, v, q)

\* Connection v fails: each request on it hears so once, and it closes (request rule 7). One that
\* closes has no request on a stream, and opens again for those that wait, which never went to it
\* (request rule 9).
FailRConn(st, v) ==
    IF st.rconns[v].stage = "closing" THEN ClosedR(st, v) ELSE ShutR(FailRequestsFrom(st, v, 0), v)

RECURSIVE CloseIdleRFrom(_, _)
CloseIdleRFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v]
        closed == IF c.stage \in {"handshaking", "up"} /\ RUsers(st, v) = 0 /\ ~c.idleNow
                  THEN [st EXCEPT !.rconns[v].stage = "closing", !.rconns[v].owes = TRUE]
                  ELSE st
    IN CloseIdleRFrom(closed, v + 1)

\* A connection with no request on it since before this instant closes: colibri owes the
\* CONNECTION_CLOSE, and the socket closes once it has gone (request rule 9).
CloseIdleR(st) == CloseIdleRFrom(st, 0)

\* Whether a connection, as `c`, has a datagram to send and its buffer to send it from.
Sends(c) == c.stage # "closed" /\ ~c.lent /\ (c.made \/ c.owes)

\* Connection v's datagram goes, whose state before the drive's tending was `c`: the one kept from
\* a refusal, or else one colibri makes now. One the loop refuses is kept (request rule 8).
SendR(st, c, v) ==
    LET made == IF c.made THEN st ELSE [st EXCEPT !.rconns[v].made = TRUE, !.rconns[v].owes = FALSE]
    IN IF st.jammed THEN made
       ELSE [made EXCEPT !.rconns[v].made = FALSE, !.rconns[v].lent = TRUE,
                         !.ops = Add(@, Op("qsend", v))]

-------------------------------------------------------------------------------
\* Events.

\* A receive ended: one that ran out is armed again, and one that failed fails its connection.
QRecvEnded(st, op, outcome) ==
    LET finished == [st EXCEPT !.ops = Remove(@, op)] IN
    IF ~op.current THEN finished
    ELSE IF outcome = "exhausted" THEN QListen(finished, op.target)
    ELSE FailRConn(finished, op.target)

\* Request r's stream ended: answered, or reset. Its lookup hears if r's try is open.
StreamEnded(st, v, r, answer, reply) ==
    LET reached == IF answer THEN TellAnswered(st, r, reply) ELSE TellFailed(st, r)
        left == [FreeReq(reached, r) EXCEPT !.rconns[v].streams = @ \ {r}, !.rconns[v].owes = TRUE]
    IN [left EXCEPT !.rconns[v].idleNow = @ \/ RUsers(left, v) = 0]

RECURSIVE TendRConnsFrom(_, _)
TendRConnsFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v]
        listened == IF c.stage # "closed" /\ ~QReceiving(st, v) THEN QListen(st, v) ELSE st
    IN TendRConnsFrom(IF Sends(c) THEN SendR(listened, c, v) ELSE listened, v + 1)

\* What a drive does last, connection by connection: a receive armed on each socket that has none,
\* and a datagram sent when the buffer is back: the one the loop refused before, or the one colibri
\* owes. A datagram the loop refuses is kept for the next drive, and a receive it refuses is asked
\* for again there (request rule 8, the datagram's rule 1).
TendRConns(st) == TendRConnsFrom(st, 0)

\* A free request slot for slot l's request at server v, taken: the free list's head, after the
\* oldest earlier request when none is free (rule 3). Returns it, and the state.
TakeSlot(st, l, v, Evict(_)) ==
    LET room == IF st.rfree = <<>> THEN Evict(st) ELSE st
        r == Head(room.rfree)
        told == TableEvent(room, l, "sent")
    IN <<r, [told EXCEPT !.reqs[r] = {[slot |-> l, server |-> v,
                                       attempt |-> Attempt(Get(told.slots[l].lookup))]},
                         !.rfree = Tail(@), !.rorder = Append(@, r)]>>

\* The drive takes slot l's request onto its server's connection whatever the connection's state,
\* and tells the lookup it went out, so its deadline covers the handshake (request rules 3 and 4).
\* The requests of the lookup's earlier tries stay (rule 6).
TakeRequest(st, l) ==
    LET v == ServerOf(st, l)
        took == TakeSlot(st, l, v, LAMBDA x : EvictBy(x, DropRequest))
        r == took[1]
        taken == took[2]
        c == taken.rconns[v]
    IN CASE c.stage = "closed" -> OpenR(taken, v, <<r>>)
         [] c.stage = "up" -> [taken EXCEPT !.rconns[v].streams = @ \cup {r},
                                            !.rconns[v].owes = TRUE]
         [] OTHER -> [taken EXCEPT !.rconns[v].queue = Append(@, r)]

\* A datagram's send ended: the buffer comes back. A send that failed fails its connection, and a
\* closing connection whose CONNECTION_CLOSE has gone closes (request rules 7 to 9).
QSendEnded(st, op, outcome) ==
    LET v == op.target
        back == [[st EXCEPT !.ops = Remove(@, op)] EXCEPT !.rconns[v].lent = FALSE]
    IN IF ~op.current THEN back
       ELSE IF outcome = "failed" THEN FailRConn(back, v)
       ELSE IF back.rconns[v].stage = "closing" /\ ~back.rconns[v].owes /\ ~back.rconns[v].made
            THEN ClosedR(back, v)
       ELSE back

\* What colibri made of a datagram connection v received.
QuicStep(st, v, seen, l, r) ==
    CASE seen = "datagram" -> [st EXCEPT !.rconns[v].owes = TRUE]
      [] seen = "done" -> UpR(st, v)
      [] seen \in {"otherAlpn", "failed", "close"} -> FailRConn(st, v)
      [] seen = "newTicket" -> [st EXCEPT !.tickets[v] = TRUE, !.rconns[v].owes = TRUE]
      [] seen = "answer" -> StreamEnded(st, v, l, TRUE, r)
      [] seen = "reset" -> StreamEnded(st, v, l, FALSE, r)

\* Connection v's QUIC timer fired: colibri resends what is unacknowledged, or gives up on the
\* connection (request rule 11).
QuicTime(st, v, seen) ==
    IF seen = "retransmit" THEN [st EXCEPT !.rconns[v].owes = TRUE] ELSE FailRConn(st, v)

\* What colibri may make of what connection v's current receive brought, by the connection's stage.
\* A closing connection reads nothing.
QuicSteps(st, v) ==
    CASE st.rconns[v].stage = "handshaking" -> {"datagram", "done", "otherAlpn", "failed"}
      [] st.rconns[v].stage = "up" -> {"datagram", "newTicket", "close"}
      [] OTHER -> {}

\* The current receives of the connections, whose datagrams colibri reads.
QReceives(st) == {op \in DOMAIN st.ops : op.kind = "qrecv" /\ op.current}

\* The connections whose QUIC timer may fire.
QTimed(st) == {v \in 0..RServers - 1 : st.rconns[v].stage # "closed"}

-------------------------------------------------------------------------------
\* What must hold (request rules 1 to 9).

\* A request slot is free, or its request waits on its server's connection or has a stream there,
\* and never both; and whatever a connection holds is a request of that server's.
RequestsPlaced(st) ==
    /\ \A r \in 0..Pool - 1 :
          st.reqs[r] = {} \/ Channel \/
          LET v == RequestOf(st, r).server
              c == st.rconns[v]
          IN c.stage # "closed" /\ (Contains(c.queue, r) # (r \in c.streams))
    /\ \A v \in 0..RServers - 1 :
          LET c == st.rconns[v] IN
          Distinct(c.queue) /\
          \A r \in c.streams \cup {c.queue[i] : i \in 1..Len(c.queue)} :
              st.reqs[r] # {} /\ RequestOf(st, r).server = v

\* A request has a stream only on a connection that is up, and waits only on one that handshakes or
\* closes.
StreamsWhenUp(st) ==
    \A v \in 0..RServers - 1 :
        LET c == st.rconns[v] IN
        (c.streams = {} \/ c.stage = "up") /\
        (c.queue = <<>> \/ c.stage \in {"handshaking", "closing"})

\* Whether request r of `before` still speaks for an open try in `st`: its lookup's current attempt,
\* or an earlier try it keeps open. A request whose try closed is cancelled, as rule 6 says, and
\* none of what rule 9 keeps (§16 decision 66).
StillOpen(before, st, r) ==
    LET rq == RequestOf(before, r)
        sl == st.slots[rq.slot]
    IN sl.lookup # {} /\
       \/ KeepsTry(st, rq.slot, rq.server, "req")
       \/ Get(sl.lookup).stage = "awaitingUdp" /\ Attempt(Get(sl.lookup)) = rq.attempt
\* Whether event e is about request connection v itself: what colibri made of its receive, its
\* timer, or the end of its datagram's send. An event about another connection can end a lookup,
\* which closes the tries of its requests that wait on v.
About(e, v) ==
    \/ e.kind \in {"quic", "finish"} /\ e.op.kind \in {"qrecv", "qsend"} /\ e.op.target = v
    \/ e.kind = "qtime" /\ e.server = v


\* What colibri tells of a connection, or its timer, or a datagram's end, fails none of the requests
\* that wait on one that closes: they never went to it (request rule 9). A socket the system refuses
\* for the connection they open again fails them, as rule 7 has it. Since 2026-11-05 an event about
\* another connection may end a lookup, which closes the try of its request that waits here, and that
\* request goes (§16 decision 66). The owner ruled that day: "Accept, with proof". RQ23 is the
\* proof: what this still forbids, caught here.
WaitingKept(before, e, st) ==
    ~(e.kind \in {"quic", "qtime", "finish"}) \/ before.starved \/
    \A v \in 0..RServers - 1 :
        LET c == before.rconns[v] IN
        c.stage # "closing" \/
        \A i \in 1..Len(c.queue) :
            st.reqs[c.queue[i]] # {} \/ (~About(e, v) /\ ~StillOpen(before, st, c.queue[i]))


\* After a drive, every request's try is open: one whose try closed is cancelled (rule 6).
RequestsOpen(st) == \A r \in 0..Pool - 1 : st.reqs[r] = {} \/ OpenRequest(st, r)

\* The pool's slots are each free or taken, once: the free list and the order requests were taken
\* in hold them all, and a lookup has one current request at most (rule 3).
PoolKept(st) ==
    LET live == {r \in 0..Pool - 1 : st.reqs[r] # {}}
        free == {st.rfree[i] : i \in 1..Len(st.rfree)}
        taken == {st.rorder[i] : i \in 1..Len(st.rorder)}
    IN /\ Distinct(st.rfree) /\ Distinct(st.rorder)
       /\ free \cap live = {} /\ free \cup live = 0..Pool - 1 /\ taken = live
       /\ \A l \in 0..Slots - 1 :
             Cardinality({r \in live : CurrentRequest(st, r) /\ SlotOfReq(st, r) = l}) <= 1

\* A closed connection holds nothing and owes nothing, and keeps no datagram.
ClosedEmpty(st) ==
    \A v \in 0..RServers - 1 :
        LET c == st.rconns[v] IN
        c.stage # "closed" \/ (c.queue = <<>> /\ c.streams = {} /\ ~c.owes /\ ~c.made)

\* A connection's datagram buffer is lent exactly when one send of it is in flight.
DatagramLent(st) ==
    \A v \in 0..RServers - 1 :
        LET qsends == Count(st.ops, LAMBDA op : op.kind = "qsend" /\ op.target = v) IN
        qsends <= 1 /\ st.rconns[v].lent = (qsends = 1)

\* A connection is up only on its transport's protocol.
UpOnProtocol(st) == \A v \in 0..RServers - 1 : st.rconns[v].stage # "up" \/ st.rconns[v].alpn

\* A connection has at most one current receive, and none once closed.
RecvCurrent(st) ==
    \A v \in 0..RServers - 1 :
        LET armedRecv == Count(st.ops, LAMBDA op : op.kind = "qrecv" /\ op.target = v /\ op.current)
        IN armedRecv <= 1 /\ (st.rconns[v].stage # "closed" \/ armedRecv = 0)

\* After a drive with nothing refused, every open connection has a receive in flight: its own, or
\* one of an earlier opening, whose end lets the next drive arm the connection's.
RListening(st) ==
    \A v \in 0..RServers - 1 : st.rconns[v].stage = "closed" \/ Holds(st, "qrecv", v, FALSE)

\* A connection that opened resuming spent its server's ticket (request rule 10).
RTicketSpent(prior, st) ==
    \A v \in 0..RServers - 1 :
        ~(st.rconns[v].resumed /\ prior.rconns[v].stage = "closed") \/ ~st.tickets[v]

===============================================================================
