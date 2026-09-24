---------------------------- MODULE EngineMutants -----------------------------
\* The engine's TLS rules broken on purpose, one operator each, as docs/mutations.md's TM1 to TM3
\* and R8a to R8d broke the Lean model. A configuration in mutants/ puts one in place of the rule
\* with TLC's `Rule <- Mutant`, and TLC must find the check that catches it.
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

===============================================================================
