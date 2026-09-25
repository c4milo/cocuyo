---------------------------- MODULE EngineRequest -----------------------------
\* The engine's requests over DoQ and DoH, written from the request rules of docs/design.md §24:
\* a QUIC connection for each server over a datagram socket of its own, a request slot for each
\* lookup slot, the streams, the one datagram a connection has in flight, the cancel of a request
\* its lookup left, the failure told to each request once, and the idle close.
\*
\* colibri is abstracted to what it tells the engine: that it owes a datagram, that the handshake
\* ended on some protocol or failed, that a stream was answered or reset, that the server closed,
\* that a ticket came, and that its timer fired. The octets are not modelled, and DoQ and DoH move
\* alike: an answer the model delivers stands for a DoQ message and for a 2xx DoH body, and a reset
\* for a reset stream and for a DoH status that is not 2xx.
EXTENDS EngineIo

Distinct(seq) == \A a, b \in 1..Len(seq) : a # b => seq[a] # seq[b]

-------------------------------------------------------------------------------
\* Requests.

RequestOf(st, l) == Get(st.reqs[l])

\* The requests on connection v: waiting for it, and on its streams.
RUsers(st, v) == Len(st.rconns[v].queue) + Cardinality(st.rconns[v].streams)

\* Whether slot l's request speaks for its lookup's attempt now (request rules 5 and 6).
CurrentRequest(st, l) ==
    st.reqs[l] # {} /\ st.slots[l].lookup # {} /\
    LET lk == Get(st.slots[l].lookup) IN
    lk.stage = "awaitingUdp" /\ Attempt(lk) = RequestOf(st, l).attempt

\* Slot l's request leaves its connection: out of the queue if it waits, and its stream cancelled
\* if it has one, which colibri owes the server STOP_SENDING and a reset for (request rule 6).
DropRequest(st, l) ==
    IF st.reqs[l] = {} THEN st
    ELSE
    LET v == RequestOf(st, l).server
        streamed == l \in st.rconns[v].streams
        left == [st EXCEPT !.reqs[l] = {}, !.rconns[v].queue = SelectSeq(@, LAMBDA x : x # l),
                           !.rconns[v].streams = @ \ {l}, !.rconns[v].owes = @ \/ streamed]
    IN [left EXCEPT !.rconns[v].idleNow = @ \/ RUsers(left, v) = 0]

RECURSIVE CancelLeftFrom(_, _)
CancelLeftFrom(st, l) ==
    IF l >= Slots THEN st
    ELSE CancelLeftFrom(IF st.reqs[l] # {} /\ ~CurrentRequest(st, l) THEN DropRequest(st, l) ELSE st,
                        l + 1)

\* Every request whose lookup has left it is cancelled: its deadline passed, it moved on, it ended,
\* or it was cancelled (request rule 6).
CancelLeft(st) == CancelLeftFrom(st, 0)

\* Slot l's request failed: its lookup hears it if the request is still its attempt, once, since the
\* slot is free before anyone else can tell it (request rule 7).
FailRequest(st, l) ==
    LET told == IF CurrentRequest(st, l) THEN TableEvent(st, l, "requestFailed") ELSE st IN
    [told EXCEPT !.reqs[l] = {}]

RECURSIVE FailRequestsFrom(_, _, _)
FailRequestsFrom(st, v, l) ==
    IF l >= Slots THEN st
    ELSE FailRequestsFrom(IF st.reqs[l] # {} /\ RequestOf(st, l).server = v THEN FailRequest(st, l)
                          ELSE st, v, l + 1)

-------------------------------------------------------------------------------
\* Connections.

\* Connection v's current operations are left to the loop to end. Its datagram buffer stays lent
\* until a send's final event, whichever incarnation made it (request rule 8).
ShutR(st, v) ==
    LET lent == st.rconns[v].lent IN
    [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in {"qsend", "qrecv"} /\ op.target = v THEN [op EXCEPT !.current = FALSE]
        ELSE op)] EXCEPT !.rconns[v] = [NoRConn EXCEPT !.lent = lent]]

\* Connection v fails: each request on it hears so once, and it closes (request rule 7).
FailRConn(st, v) == ShutR(FailRequestsFrom(st, v, 0), v)

QListen(st, v) == IF st.jammed THEN st ELSE [st EXCEPT !.ops = Add(@, Op("qrecv", v))]

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

\* The drive takes slot l's request onto its server's connection whatever the connection's state,
\* and tells the lookup it went out, so its deadline covers the handshake (request rules 3 and 4).
\* An earlier request of the slot's is cancelled first.
TakeRequest(st, l) ==
    LET v == ServerOf(st, l)
        cleared == DropRequest(st, l)
        told == TableEvent(cleared, l, "sent")
        taken == [told EXCEPT !.reqs[l] = {[server |-> v,
                                            attempt |-> Attempt(Get(told.slots[l].lookup))]}]
        c == taken.rconns[v]
    IN CASE c.stage = "closed" -> OpenR(taken, v, <<l>>)
         [] c.stage = "up" -> [taken EXCEPT !.rconns[v].streams = @ \cup {l},
                                            !.rconns[v].owes = TRUE]
         [] OTHER -> [taken EXCEPT !.rconns[v].queue = Append(@, l)]

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

-------------------------------------------------------------------------------
\* Events.

\* A datagram's send ended: the buffer comes back. A send that failed fails its connection, and a
\* closing connection whose CONNECTION_CLOSE has gone closes (request rules 7 to 9).
QSendEnded(st, op, succeeded) ==
    LET v == op.target
        back == [[st EXCEPT !.ops = Remove(@, op)] EXCEPT !.rconns[v].lent = FALSE]
    IN IF ~op.current THEN back
       ELSE IF ~succeeded THEN FailRConn(back, v)
       ELSE IF back.rconns[v].stage = "closing" /\ ~back.rconns[v].owes /\ ~back.rconns[v].made
            THEN ClosedR(back, v)
       ELSE back

\* A receive ended: one that ran out is armed again, and one that failed fails its connection.
QRecvEnded(st, op, ranOut) ==
    LET finished == [st EXCEPT !.ops = Remove(@, op)] IN
    IF ~op.current THEN finished
    ELSE IF ranOut THEN QListen(finished, op.target) ELSE FailRConn(finished, op.target)

\* Slot l's stream ended: answered, or reset. Its lookup hears if the request is still its attempt.
StreamEnded(st, v, l, answer, r) ==
    LET replied == LookupEvent(st, l, "reply", r)
        reached == IF ~CurrentRequest(st, l) THEN st
                 ELSE IF ~answer THEN TableEvent(st, l, "requestFailed")
                 ELSE IF replied[2] = "accepted" THEN Settle(replied[1], l) ELSE replied[1]
        left == [reached EXCEPT !.reqs[l] = {}, !.rconns[v].streams = @ \ {l}, !.rconns[v].owes = TRUE]
    IN [left EXCEPT !.rconns[v].idleNow = @ \/ RUsers(left, v) = 0]

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
    /\ \A l \in 0..Slots - 1 :
          st.reqs[l] = {} \/
          LET v == RequestOf(st, l).server
              c == st.rconns[v]
          IN c.stage # "closed" /\ (Contains(c.queue, l) # (l \in c.streams))
    /\ \A v \in 0..RServers - 1 :
          LET c == st.rconns[v] IN
          Distinct(c.queue) /\
          \A l \in c.streams \cup {c.queue[i] : i \in 1..Len(c.queue)} :
              st.reqs[l] # {} /\ RequestOf(st, l).server = v

\* A request has a stream only on a connection that is up, and waits only on one that is not.
StreamsWhenUp(st) ==
    \A v \in 0..RServers - 1 :
        LET c == st.rconns[v] IN
        (c.streams = {} \/ c.stage = "up") /\ (c.queue = <<>> \/ c.stage \in {"handshaking", "closing"})

\* After a drive, every request speaks for its lookup's attempt: one it left is cancelled.
RequestsCurrent(st) == \A l \in 0..Slots - 1 : st.reqs[l] = {} \/ CurrentRequest(st, l)

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

\* After a drive with nothing refused, every open connection has its receive armed.
RListening(st) == \A v \in 0..RServers - 1 : st.rconns[v].stage = "closed" \/ QReceiving(st, v)

\* A connection that opened resuming spent its server's ticket (request rule 10).
RTicketSpent(prior, st) ==
    \A v \in 0..RServers - 1 :
        ~(st.rconns[v].resumed /\ prior.rconns[v].stage = "closed") \/ ~st.tickets[v]

===============================================================================
