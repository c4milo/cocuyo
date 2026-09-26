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
\*
\* With `RStream` the connections run over TCP, as DoH over HTTP/2 does (request rules 14 to 16):
\* a connection connects before it handshakes, and waits while a connect of an earlier opening
\* still borrows the slot's address; a send may go short, and its rest goes first; a receive may
\* end with no octets, which ends the connection; and no transport timer fires. HTTP/2 moves as
\* HTTP/3 does above the stream, so the rest of the model holds for it as it stands.
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

\* A draining connection whose last stream has ended closes as an idle one does, and opens again
\* for the requests that wait (request rule 13).
DrainedClose(st, v) ==
    IF st.rconns[v].stage = "draining" /\ st.rconns[v].streams = {}
    THEN [st EXCEPT !.rconns[v].stage = "closing", !.rconns[v].owes = TRUE]
    ELSE st

\* Slot l's request leaves its connection: out of the queue if it waits, and its stream cancelled
\* if it has one, which colibri owes the server STOP_SENDING and a reset for (request rule 6).
DropRequest(st, l) ==
    IF st.reqs[l] = {} THEN st
    ELSE
    LET v == RequestOf(st, l).server
        streamed == l \in st.rconns[v].streams
        left == [st EXCEPT !.reqs[l] = {}, !.rconns[v].queue = SelectSeq(@, LAMBDA x : x # l),
                           !.rconns[v].streams = @ \ {l}, !.rconns[v].owes = @ \/ streamed]
    IN DrainedClose([left EXCEPT !.rconns[v].idleNow = @ \/ RUsers(left, v) = 0], v)

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
\* until a send's final event, whichever incarnation made it (request rule 8), and over TCP its
\* address until a connect's final event (request rule 14).
ShutR(st, v) ==
    LET c == st.rconns[v] IN
    [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in {"qsend", "qrecv", "rconnect"} /\ op.target = v
        THEN [op EXCEPT !.current = FALSE] ELSE op)]
     EXCEPT !.rconns[v] = [NoRConn EXCEPT !.lent = c.lent, !.connectLent = c.connectLent]]

RECURSIVE FailStreamsFrom(_, _, _)
FailStreamsFrom(st, v, l) ==
    IF l >= Slots THEN st
    ELSE FailStreamsFrom(IF l \in st.rconns[v].streams THEN FailRequest(st, l) ELSE st, v, l + 1)


QListen(st, v) == IF st.jammed THEN st ELSE [st EXCEPT !.ops = Add(@, Op("qrecv", v))]

QReceiving(st, v) == \E op \in DOMAIN st.ops : op.kind = "qrecv" /\ op.target = v /\ op.current

\* Whether a connection in `stage` has its receive and sends: once its socket is open, and over
\* TCP once its connect has succeeded too (request rule 14).
Talks(stage) == stage \notin {"closed", "connecting", "reopening"}

\* Submits connection v's connect, for the requests in `queue`. The loop borrows the slot's
\* address until the connect's final event, and a connect it refuses fails each request (request
\* rule 14).
ConnectR(st, v, queue) ==
    IF st.jammed THEN FailRequestsFrom(st, v, 0)
    ELSE [st EXCEPT !.rconns[v].stage = "connecting", !.rconns[v].queue = queue,
                    !.rconns[v].idleNow = FALSE, !.rconns[v].connectLent = TRUE,
                    !.ops = Add(@, Op("rconnect", v))]

\* Opens connection v for the requests in `queue`, and a socket the system refuses fails each of
\* them. A datagram socket's receive is armed, and colibri makes its first flight, resuming with
\* the server's ticket, which it spends (request rules 1 and 10). A TCP connection connects first,
\* and waits while a connect of an earlier opening still borrows the slot's address (request rule
\* 14).
OpenR(st, v, queue) ==
    IF st.starved THEN FailRequestsFrom(st, v, 0)
    ELSE IF RStream /\ st.rconns[v].connectLent
    THEN [st EXCEPT !.rconns[v].stage = "reopening", !.rconns[v].queue = queue,
                    !.rconns[v].idleNow = FALSE]
    ELSE IF RStream THEN ConnectR(st, v, queue)
    ELSE
    LET opened == [st EXCEPT !.rconns[v].stage = "handshaking", !.rconns[v].queue = queue,
                             !.rconns[v].owes = TRUE, !.rconns[v].resumed = st.tickets[v],
                             !.rconns[v].idleNow = FALSE, !.tickets[v] = FALSE]
    IN QListen(opened, v)

\* A connection that waited for an earlier opening's connect opens, now the loop has given the
\* address back, or closes when every request that waited has left (request rule 14).
ReopenR(st, v) ==
    LET q == st.rconns[v].queue
        cleared == [st EXCEPT !.rconns[v].stage = "closed", !.rconns[v].queue = <<>>]
    IN IF q = <<>> THEN cleared ELSE OpenR(cleared, v, q)

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

\* Connection v fails: each request on it hears so once, and it closes (request rule 7). One that
\* drains or closes fails the requests on its streams alone, and opens again for those that wait,
\* which never went to it (request rule 13).
FailRConn(st, v) ==
    IF st.rconns[v].stage \in {"draining", "closing"} THEN ClosedR(FailStreamsFrom(st, v, 0), v)
    ELSE ShutR(FailRequestsFrom(st, v, 0), v)

\* The server's GOAWAY: the connection takes no new stream, and drains (request rule 13).
Drain(st, v) == DrainedClose([st EXCEPT !.rconns[v].stage = "draining", !.rconns[v].owes = TRUE], v)

\* The stages an idle connection closes from.
IdleStages == IF RStream THEN {"connecting", "reopening", "handshaking", "up"} ELSE {"handshaking", "up"}

RECURSIVE CloseIdleRFrom(_, _)
CloseIdleRFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v]
        idle == c.stage \in IdleStages /\ RUsers(st, v) = 0 /\ ~c.idleNow
        closed == IF ~idle THEN st
                  ELSE IF c.stage = "up" \/ ~RStream
                  THEN [st EXCEPT !.rconns[v].stage = "closing", !.rconns[v].owes = TRUE]
                  ELSE ShutR(st, v)
    IN CloseIdleRFrom(closed, v + 1)

\* A connection with no request on it since before this instant closes: colibri owes the
\* CONNECTION_CLOSE, or over TCP the GOAWAY and the `close_notify`, and the socket closes once it
\* has gone (request rule 9). Over TCP one whose handshake has not ended has nothing to close, and
\* closes at once (request rule 16).
CloseIdleR(st) == CloseIdleRFrom(st, 0)

\* Whether a connection, as `c`, has a datagram to send and its buffer to send it from.
Sends(c) == Talks(c.stage) /\ ~c.lent /\ (c.made \/ c.owes)

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
        listened == IF Talks(c.stage) /\ ~QReceiving(st, v) THEN QListen(st, v) ELSE st
    IN TendRConnsFrom(IF Sends(c) THEN SendR(listened, c, v) ELSE listened, v + 1)

\* What a drive does last, connection by connection: a receive armed on each socket that has none,
\* and a datagram sent when the buffer is back: the one the loop refused before, or the one colibri
\* owes. A datagram the loop refuses is kept for the next drive, and a receive it refuses is asked
\* for again there (request rule 8, the datagram's rule 1).
TendRConns(st) == TendRConnsFrom(st, 0)

-------------------------------------------------------------------------------
\* Events.

\* A datagram's send ended: the buffer comes back. A send that failed fails its connection, and a
\* closing connection whose CONNECTION_CLOSE has gone closes (request rules 7 to 9). Over TCP a
\* send that went short keeps its rest in the buffer, to go before anything made after it
\* (request rule 15).
QSendEnded(st, op, outcome) ==
    LET v == op.target
        back == [[st EXCEPT !.ops = Remove(@, op)] EXCEPT !.rconns[v].lent = FALSE]
    IN IF ~op.current THEN back
       ELSE IF outcome = "failed" THEN FailRConn(back, v)
       ELSE IF outcome = "short" THEN [back EXCEPT !.rconns[v].made = TRUE]
       ELSE IF back.rconns[v].stage = "closing" /\ ~back.rconns[v].owes /\ ~back.rconns[v].made
            THEN ClosedR(back, v)
       ELSE back

\* A receive ended: one that ran out is armed again, and one that failed fails its connection. Over
\* TCP one that ended with no octets is the server's end of the stream, and fails it too (request
\* rule 15).
QRecvEnded(st, op, outcome) ==
    LET finished == [st EXCEPT !.ops = Remove(@, op)] IN
    IF ~op.current THEN finished
    ELSE IF outcome = "exhausted" THEN QListen(finished, op.target)
    ELSE FailRConn(finished, op.target)

\* A connect ended, and the loop gives the slot's address back (request rule 14). The current
\* opening's success arms its receive, and the transport makes its first flight, resuming with the
\* server's ticket, which it spends (request rule 10). Its failure fails the connection. An earlier
\* opening's end opens the connection that waited for it, before the drive polls, so a request
\* that fails there is heard in the same drive.
RConnectEnded(st, op, succeeded) ==
    LET v == op.target
        back == [st EXCEPT !.ops = Remove(@, op), !.rconns[v].connectLent = FALSE]
    IN IF ~op.current THEN (IF back.rconns[v].stage = "reopening" THEN ReopenR(back, v) ELSE back)
       ELSE IF ~succeeded THEN FailRConn(back, v)
       ELSE QListen([back EXCEPT !.rconns[v].stage = "handshaking", !.rconns[v].owes = TRUE,
                                 !.rconns[v].resumed = st.tickets[v], !.tickets[v] = FALSE], v)

\* Slot l's stream ended: answered, or reset. Its lookup hears if the request is still its attempt.
StreamEnded(st, v, l, answer, r) ==
    LET replied == LookupEvent(st, l, "reply", r)
        reached == IF ~CurrentRequest(st, l) THEN st
                 ELSE IF ~answer THEN TableEvent(st, l, "requestFailed")
                 ELSE IF replied[2] = "accepted" THEN Settle(replied[1], l) ELSE replied[1]
        left == [reached EXCEPT !.reqs[l] = {}, !.rconns[v].streams = @ \ {l}, !.rconns[v].owes = TRUE]
    IN DrainedClose([left EXCEPT !.rconns[v].idleNow = @ \/ RUsers(left, v) = 0], v)

\* What colibri made of a datagram connection v received.
QuicStep(st, v, seen, l, r) ==
    CASE seen = "datagram" -> [st EXCEPT !.rconns[v].owes = TRUE]
      [] seen = "done" -> UpR(st, v)
      [] seen \in {"otherAlpn", "failed", "close"} -> FailRConn(st, v)
      [] seen = "newTicket" -> [st EXCEPT !.tickets[v] = TRUE, !.rconns[v].owes = TRUE]
      [] seen = "goaway" -> Drain(st, v)
      [] seen = "answer" -> StreamEnded(st, v, l, TRUE, r)
      [] seen = "reset" -> StreamEnded(st, v, l, FALSE, r)

\* Connection v's QUIC timer fired: colibri resends what is unacknowledged, or gives up on the
\* connection (request rule 11).
QuicTime(st, v, seen) ==
    IF seen = "retransmit" THEN [st EXCEPT !.rconns[v].owes = TRUE] ELSE FailRConn(st, v)

\* What colibri may make of what connection v's current receive brought, by the connection's stage.
\* A GOAWAY after the first changes nothing (RFC 9114 §5.2: "An endpoint MAY send multiple GOAWAY
\* frames"; request rule 13). A closing connection reads nothing.
QuicSteps(st, v) ==
    CASE st.rconns[v].stage = "handshaking" -> {"datagram", "done", "otherAlpn", "failed"}
      [] st.rconns[v].stage = "up" -> {"datagram", "newTicket", "close", "goaway"}
      [] st.rconns[v].stage = "draining" -> {"datagram", "newTicket", "close", "goaway"}
      [] OTHER -> {}

\* The current receives of the connections, whose datagrams colibri reads.
QReceives(st) == {op \in DOMAIN st.ops : op.kind = "qrecv" /\ op.current}

\* The connections whose QUIC timer may fire. Over TCP there is none: TCP resends what is lost, and
\* HTTP/2 negotiates no idle timeout (§24, DoH over HTTP/2).
QTimed(st) == IF RStream THEN {} ELSE {v \in 0..RServers - 1 : st.rconns[v].stage # "closed"}

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

\* A request has a stream only on a connection that is up or drains, and waits only on one that
\* connects or waits to, handshakes, drains or closes.
StreamsWhenUp(st) ==
    \A v \in 0..RServers - 1 :
        LET c == st.rconns[v] IN
        (c.streams = {} \/ c.stage \in {"up", "draining"}) /\
        (c.queue = <<>> \/
         c.stage \in {"connecting", "reopening", "handshaking", "draining", "closing"})

\* A draining connection has a stream: the end of its last one closes it (request rule 13).
DrainingHasStreams(st) == \A v \in 0..RServers - 1 : st.rconns[v].stage # "draining" \/ st.rconns[v].streams # {}

\* A draining connection opens no stream: its streams only end (request rule 13).
DrainShrinks(before, st) ==
    \A v \in 0..RServers - 1 :
        before.rconns[v].stage # "draining" \/ st.rconns[v].stage # "draining" \/
        st.rconns[v].streams \subseteq before.rconns[v].streams

\* A GOAWAY fails no request: it only drains its connection (request rule 13).
GoawayFailsNone(before, e, st) ==
    ~(e.kind = "quic" /\ e.step = "goaway") \/ \A l \in 0..Slots - 1 : before.reqs[l] = {} \/ st.reqs[l] # {}

\* What colibri tells of a connection, or its timer, or a datagram's end, fails none of the requests
\* that wait on one that drains or closes: they never went to it (request rule 13). A socket the
\* system refuses for the connection they open again fails them, as rule 7 has it, and over TCP
\* so does a connect the loop refuses (request rule 14).
WaitingKept(before, e, st) ==
    ~(e.kind \in {"quic", "qtime", "finish"}) \/ before.starved \/ (RStream /\ before.jammed) \/
    \A v \in 0..RServers - 1 :
        LET c == before.rconns[v] IN
        c.stage \notin {"draining", "closing"} \/ \A i \in 1..Len(c.queue) : st.reqs[c.queue[i]] # {}

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
UpOnProtocol(st) ==
    \A v \in 0..RServers - 1 : st.rconns[v].stage \notin {"up", "draining"} \/ st.rconns[v].alpn

\* A connection has at most one current receive, and none once closed.
RecvCurrent(st) ==
    \A v \in 0..RServers - 1 :
        LET armedRecv == Count(st.ops, LAMBDA op : op.kind = "qrecv" /\ op.target = v /\ op.current)
        IN armedRecv <= 1 /\ (st.rconns[v].stage # "closed" \/ armedRecv = 0)

\* After a drive with nothing refused, every open connection has its receive armed, and over TCP
\* every one whose connect has succeeded.
RListening(st) == \A v \in 0..RServers - 1 : ~Talks(st.rconns[v].stage) \/ QReceiving(st, v)

\* A connection that opened resuming spent its server's ticket (request rule 10): when it opened,
\* or over TCP when its connect succeeded.
RTicketSpent(prior, st) ==
    \A v \in 0..RServers - 1 :
        ~(st.rconns[v].resumed /\ prior.rconns[v].stage \in {"closed", "connecting"}) \/
        ~st.tickets[v]

\* A connect of the slot is in flight exactly when the slot's address is lent, and one at most: a
\* connecting connection's own, or an earlier opening's, which a reopening one waits for (request
\* rule 14).
ConnectLent(st) ==
    ~RStream \/
    \A v \in 0..RServers - 1 :
        LET c == st.rconns[v]
            connects == Count(st.ops, LAMBDA op : op.kind = "rconnect" /\ op.target = v)
            own == Count(st.ops, LAMBDA op : op.kind = "rconnect" /\ op.target = v /\ op.current)
        IN /\ connects <= 1 /\ c.connectLent = (connects = 1)
           /\ (c.stage = "connecting") = (own = 1)
           /\ (c.stage # "reopening" \/ c.connectLent)

\* A connection that connects, or waits to, has no receive, and neither owes nor sends anything of
\* its opening: its first flight is made once its connect has succeeded (request rule 14).
ConnectFirst(st) ==
    ~RStream \/
    \A v \in 0..RServers - 1 :
        LET c == st.rconns[v] IN
        c.stage \notin {"connecting", "reopening"} \/
        (~QReceiving(st, v) /\ ~c.owes /\ ~c.made /\
         Count(st.ops, LAMBDA op : op.kind = "qsend" /\ op.target = v /\ op.current) = 0)

\* The rest of a send that went short is kept, or is the send in flight, and what the connection
\* owed before still waits: nothing made after the rest takes the buffer first (request rule 15).
RestFirst(before, e, st) ==
    ~(e.kind = "finish" /\ e.op.kind = "qsend" /\ e.op.current /\ e.outcome = "short") \/
    LET v == e.op.target IN
    st.rconns[v].made \/
    (Count(st.ops, LAMBDA op : op.kind = "qsend" /\ op.target = v /\ op.current) = 1 /\
     (before.rconns[v].owes => st.rconns[v].owes))

\* A receive that ended with no octets ended its connection's opening: the server ended the
\* stream (request rule 15).
EndedCloses(before, e, st) ==
    ~(e.kind = "finish" /\ e.op.kind = "qrecv" /\ e.op.current /\ e.outcome = "ended") \/
    st.rconns[e.op.target].stage \in {"closed", "connecting", "reopening"}

===============================================================================
