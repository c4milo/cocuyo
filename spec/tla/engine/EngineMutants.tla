---------------------------- MODULE EngineMutants -----------------------------
\* The engine's rules broken on purpose, one operator each: the TLS rules as docs/mutations.md's
\* TM1 to TM3 and R8a to R8d broke the Lean model, the stream's rule 9 as TQ1 breaks it, and the
\* request rules of §24 as RQ1 to RQ20 break them. A
\* configuration in mutants/ puts one in place of the rule with TLC's `Rule <- Mutant`, and TLC
\* must find the check that catches it.
EXTENDS Engine

\* TM1: the session's records go to the back of the queue, behind queries not yet sealed.
MakeRecordsBehind(st, k) ==
    LET c == st.conns[k] IN
    IF c.sealed >= 2 /\ c.sealed <= Len(c.queue) /\ c.queue[c.sealed] = Records
    THEN [st EXCEPT !.conns[k].owes = FALSE]
    ELSE Pump([st EXCEPT !.conns[k].queue = Append(@, Records), !.conns[k].sealed = @ + 1,
                         !.conns[k].owes = FALSE], k)

\* TM2: a slot is opened again while a send of its records is in flight.
BorrowedByConnect(st, k) == \E op \in DOMAIN st.ops : op.kind = "connect" /\ op.target = k

\* Each TlsStep mutant is whole: one that fell back to TlsStep would call itself once it stood in
\* TlsStep's place.

\* TM3: the handshake's end tells the lookups without sealing the client's last flight.
TlsStepUnsealed(st, k, t) ==
    IF st.conns[k].stage = "closing" THEN st
    ELSE
    LET owing == IF t \in {"failed", "ticket"} THEN st ELSE [st EXCEPT !.conns[k].owes = TRUE] IN
    CASE t \in {"flight", "rekey"} -> MakeRecords(owing, k)
      [] t = "ticket" -> [owing EXCEPT !.tickets[owing.conns[k].server] = TRUE]
      [] t = "failed" -> IF owing.conns[k].resumed THEN RetryFull(owing, k) ELSE FailConn(owing, k)
      [] t = "done" ->
            IF owing.conns[k].stage # "handshaking" THEN owing
            ELSE TellAll([owing EXCEPT !.conns[k].stage = "up"], k, TRUE)

\* R8a: a declined ticket fails the connection.
TlsStepDeclineFails(st, k, t) ==
    IF st.conns[k].stage = "closing" THEN st
    ELSE
    LET owing == IF t \in {"failed", "ticket"} THEN st ELSE [st EXCEPT !.conns[k].owes = TRUE] IN
    CASE t \in {"flight", "rekey"} -> MakeRecords(owing, k)
      [] t = "ticket" -> [owing EXCEPT !.tickets[owing.conns[k].server] = TRUE]
      [] t = "failed" -> FailConn(owing, k)
      [] t = "done" ->
            LET answered == MakeRecords(owing, k) IN
            IF answered.conns[k].stage # "handshaking" THEN answered
            ELSE TellAll([answered EXCEPT !.conns[k].stage = "up"], k, TRUE)

\* R8b: a connection that resumes leaves its server's ticket kept.
OpenConnKeepsTicket(st, v) ==
    LET found == FreeConn(st)
        room == found[2]
    IN IF found[1] = {} \/ room.starved \/ room.jammed THEN <<{}, room>>
       ELSE
       LET k == Get(found[1])
           opened == [room EXCEPT !.conns[k] = [NoConn EXCEPT !.stage = "connecting",
                                                  !.server = v, !.resumed = Tls /\ room.tickets[v]]]
       IN <<{k}, [opened EXCEPT !.ops = Add(@, Op("connect", k))]>>

\* R8c: the connection opened again resumes again.
ConnectAgainResumed(st, k) ==
    IF st.conns[k].stage # "reopening" \/ Borrowed(st, k) THEN st
    ELSE IF st.starved \/ st.jammed THEN FailConn(st, k)
    ELSE [st EXCEPT !.conns[k].stage = "connecting", !.conns[k].resumed = TRUE,
                    !.ops = Add(@, Op("connect", k))]

\* R8d: the connection opened again takes its slot while the loop still holds its records.
ConnectAgainBorrowed(st, k) ==
    IF st.conns[k].stage # "reopening" THEN st
    ELSE IF st.starved \/ st.jammed THEN FailConn(st, k)
    ELSE [st EXCEPT !.conns[k].stage = "connecting", !.conns[k].resumed = FALSE,
                    !.ops = Add(@, Op("connect", k))]

\* TQ1: a lookup that leaves keeps its waiting query queued, the stream's rule 9 as the code's SQ6
\* broke it. On a plain stream a query waits only behind another lookup's, so one lookup never
\* shows it.
ReleaseKeepsQueued(st, l) ==
    IF st.slots[l].conn = {} THEN st
    ELSE
    LET k == Get(st.slots[l].conn)
        left == [st EXCEPT !.slots[l].conn = {}]
        users == Sub(left.conns[k].users, 1)
    IN [left EXCEPT !.conns[k].users = users, !.conns[k].idleNow = @ \/ users = 0]

\* RQ1: a request its lookup left is never cancelled (request rule 6).
CancelLeftNever(st) == st

\* RQ2: the handshake's end is taken whatever protocol it negotiated (request rule 2).
QuicStepAnyProtocol(st, v, seen, l, r) ==
    CASE seen = "datagram" -> [st EXCEPT !.rconns[v].owes = TRUE]
      [] seen = "done" -> UpR(st, v)
      [] seen = "otherAlpn" -> [UpR(st, v) EXCEPT !.rconns[v].alpn = FALSE]
      [] seen \in {"failed", "close"} -> FailRConn(st, v)
      [] seen = "newTicket" -> [st EXCEPT !.tickets[v] = TRUE, !.rconns[v].owes = TRUE]
      [] seen = "answer" -> StreamEnded(st, v, l, TRUE, r)
      [] seen = "reset" -> StreamEnded(st, v, l, FALSE, r)

\* RQ3: a request opens its stream before its connection is up (request rule 4).
TakeRequestEager(st, l) ==
    LET v == ServerOf(st, l)
        cleared == DropRequest(st, l)
        told == TableEvent(cleared, l, "sent")
        taken == [told EXCEPT !.reqs[l] = {[server |-> v,
                                            attempt |-> Attempt(Get(told.slots[l].lookup))]}]
        c == taken.rconns[v]
    IN IF c.stage = "closed" THEN OpenR(taken, v, <<l>>)
       ELSE [taken EXCEPT !.rconns[v].streams = @ \cup {l}, !.rconns[v].owes = TRUE]

\* RQ4: a connection that fails tells none of its requests (request rule 7).
FailRConnSilent(st, v) == ShutR(st, v)

RECURSIVE TendRConnsEagerFrom(_, _)
TendRConnsEagerFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v]
        listened == IF c.stage # "closed" /\ ~QReceiving(st, v) THEN QListen(st, v) ELSE st
    IN TendRConnsEagerFrom(IF c.stage # "closed" /\ (c.made \/ c.owes) THEN SendR(listened, c, v)
                           ELSE listened, v + 1)

\* RQ5: a datagram is sent while the buffer is still lent to the one before (request rule 8).
TendRConnsEager(st) == TendRConnsEagerFrom(st, 0)

\* RQ6: a connection that closes forgets its buffer is lent, so the next incarnation sends from it
\* while the loop still holds it (request rule 8).
ShutRForgetsLent(st, v) ==
    [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in {"qsend", "qrecv"} /\ op.target = v THEN [op EXCEPT !.current = FALSE]
        ELSE op)] EXCEPT !.rconns[v] = NoRConn]

\* RQ7: a connection that resumes leaves its server's ticket kept (request rule 10).
OpenRKeepsTicket(st, v, queue) ==
    IF st.starved THEN FailRequestsFrom(st, v, 0)
    ELSE
    LET opened == [st EXCEPT !.rconns[v].stage = "handshaking", !.rconns[v].queue = queue,
                             !.rconns[v].owes = TRUE, !.rconns[v].resumed = st.tickets[v],
                             !.rconns[v].idleNow = FALSE]
    IN QListen(opened, v)

RECURSIVE TendRConnsDeafFrom(_, _)
TendRConnsDeafFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v] IN
    TendRConnsDeafFrom(IF Sends(c) THEN SendR(st, c, v) ELSE st, v + 1)

\* RQ8: a receive the loop refused, or one that ended, is not armed again (the datagram's rule 1).
TendRConnsDeaf(st) == TendRConnsDeafFrom(st, 0)

RECURSIVE CloseIdleRBusyFrom(_, _)
CloseIdleRBusyFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v]
        closed == IF c.stage \in {"handshaking", "up"} /\ ~c.idleNow
                  THEN [st EXCEPT !.rconns[v].stage = "closing", !.rconns[v].owes = TRUE]
                  ELSE st
    IN CloseIdleRBusyFrom(closed, v + 1)

\* RQ9: a connection closes for idleness with requests still on it (request rule 9).
CloseIdleRBusy(st) == CloseIdleRBusyFrom(st, 0)

\* RQ10: a connection that closes still owes a datagram (request rule 7).
ShutRStillOwes(st, v) ==
    LET c == st.rconns[v] IN
    [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in {"qsend", "qrecv", "rconnect"} /\ op.target = v
        THEN [op EXCEPT !.current = FALSE] ELSE op)]
     EXCEPT !.rconns[v] = [NoRConn EXCEPT !.lent = c.lent, !.connectLent = c.connectLent,
                                          !.owes = c.owes]]

RECURSIVE TendRConnsTwiceFrom(_, _)
TendRConnsTwiceFrom(st, v) ==
    IF v >= RServers THEN st
    ELSE
    LET c == st.rconns[v]
        listened == IF c.stage # "closed" THEN QListen(st, v) ELSE st
    IN TendRConnsTwiceFrom(IF Sends(c) THEN SendR(listened, c, v) ELSE listened, v + 1)

\* RQ11: a receive is armed beside the one that is current (the datagram's rule 1).
TendRConnsTwice(st) == TendRConnsTwiceFrom(st, 0)

\* RQ12: a GOAWAY fails its connection, as the server's close does (request rule 13).
DrainFails(st, v) == FailRConn(st, v)

\* RQ13: a draining connection stays open once its last stream has ended (request rule 13).
DrainedNever(st, v) == st

\* RQ14: a connection that fails while it drains or closes fails the requests that wait on it too
\* (request rule 13).
FailRConnAll(st, v) == ShutR(FailRequestsFrom(st, v, 0), v)

\* RQ15: a request taken while its connection drains opens a stream on it (request rule 13).
TakeRequestOnDraining(st, l) ==
    LET v == ServerOf(st, l)
        cleared == DropRequest(st, l)
        told == TableEvent(cleared, l, "sent")
        taken == [told EXCEPT !.reqs[l] = {[server |-> v,
                                            attempt |-> Attempt(Get(told.slots[l].lookup))]}]
        c == taken.rconns[v]
    IN CASE c.stage = "closed" -> OpenR(taken, v, <<l>>)
         [] c.stage \in {"up", "draining"} -> [taken EXCEPT !.rconns[v].streams = @ \cup {l},
                                                          !.rconns[v].owes = TRUE]
         [] OTHER -> [taken EXCEPT !.rconns[v].queue = Append(@, l)]

\* RQ16: a connection opens again while a connect of an earlier opening still borrows the slot's
\* address (request rule 14).
OpenRAtOnce(st, v, queue) ==
    IF st.starved THEN FailRequestsFrom(st, v, 0)
    ELSE IF RStream THEN ConnectR(st, v, queue)
    ELSE
    LET opened == [st EXCEPT !.rconns[v].stage = "handshaking", !.rconns[v].queue = queue,
                             !.rconns[v].owes = TRUE, !.rconns[v].resumed = st.tickets[v],
                             !.rconns[v].idleNow = FALSE, !.tickets[v] = FALSE]
    IN QListen(opened, v)

\* RQ17: a connection's receive is armed with its connect, before the connect has succeeded
\* (request rule 14).
ConnectRListening(st, v, queue) ==
    IF st.jammed THEN FailRequestsFrom(st, v, 0)
    ELSE QListen([st EXCEPT !.rconns[v].stage = "connecting", !.rconns[v].queue = queue,
                            !.rconns[v].idleNow = FALSE, !.rconns[v].connectLent = TRUE,
                            !.ops = Add(@, Op("rconnect", v))], v)

\* RQ18: the transport makes its first flight with the connect, before the connect has succeeded
\* (request rule 14).
ConnectROwing(st, v, queue) ==
    IF st.jammed THEN FailRequestsFrom(st, v, 0)
    ELSE [st EXCEPT !.rconns[v].stage = "connecting", !.rconns[v].queue = queue,
                    !.rconns[v].idleNow = FALSE, !.rconns[v].connectLent = TRUE,
                    !.rconns[v].owes = TRUE, !.ops = Add(@, Op("rconnect", v))]

\* RQ19: a send that went short is taken for a whole one, and its rest is lost (request rule 15).
QSendEndedWhole(st, op, outcome) ==
    LET v == op.target
        back == [[st EXCEPT !.ops = Remove(@, op)] EXCEPT !.rconns[v].lent = FALSE]
    IN IF ~op.current THEN back
       ELSE IF outcome = "failed" THEN FailRConn(back, v)
       ELSE IF back.rconns[v].stage = "closing" /\ ~back.rconns[v].owes /\ ~back.rconns[v].made
            THEN ClosedR(back, v)
       ELSE back

\* RQ20: a receive that ended with no octets is armed again, and the connection stays up (request
\* rule 15).
QRecvEndedAgain(st, op, outcome) ==
    LET finished == [st EXCEPT !.ops = Remove(@, op)] IN
    IF ~op.current THEN finished
    ELSE IF outcome \in {"exhausted", "ended"} THEN QListen(finished, op.target)
    ELSE FailRConn(finished, op.target)

===============================================================================
