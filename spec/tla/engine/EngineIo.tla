------------------------------- MODULE EngineIo -------------------------------
\* The engine's sockets and sends, as spec/lean/Spec/EngineSockets.lean had them: a socket per
\* server with its receive, the port replaced once it has carried its share while the old one
\* drains, a receive or a replacement the moment refused asked for again at the next drive, and
\* the sends of both transports, which lend the slot's buffer (docs/design.md §19 step 13, the
\* stream's rules 6, 7 and 9 and the datagram's rules 1 to 5; §21, TLS rules 2 and 5).
EXTENDS EngineTable

-------------------------------------------------------------------------------
\* Receives.

\* Whether server v's socket, the current one or the draining one, has its receive armed.
Listening(st, v, draining) ==
    \E op \in DOMAIN st.ops :
        op.kind = "receiveFrom" /\ op.target = v /\ op.draining = draining /\ op.current

Receiving(st, k) == \E op \in DOMAIN st.ops : op.kind = "receive" /\ op.target = k /\ op.current

\* Arms a receive on server v's socket unless the loop refuses it; the next drive asks again.
Listen(st, v, draining) ==
    IF st.jammed THEN st
    ELSE [st EXCEPT !.ops = Add(@, [Op("receiveFrom", v) EXCEPT !.draining = draining])]

ArmReceive(st, k) == IF st.jammed THEN st ELSE [st EXCEPT !.ops = Add(@, Op("receive", k))]

-------------------------------------------------------------------------------
\* Sockets.

\* Moves every slot's record of server v's socket `older` to `newer`.
AgeSockets(st, v, older, newer) ==
    LET sl == st.slots IN
    [st EXCEPT !.slots = [l \in DOMAIN sl |->
        IF sl[l].sentFrom = {<<v, older>>} THEN [sl[l] EXCEPT !.sentFrom = {<<v, newer>>}]
        ELSE sl[l]]]

\* Whether server v's draining socket is still owed an answer, or the end of a send from it.
DrainNeeded(st, v) ==
    \E l \in 0..Slots - 1 :
        LET sl == st.slots[l] IN
        sl.sentFrom = {<<v, "draining">>} /\
        (sl.busy \/ (sl.lookup # {} /\ Get(sl.lookup).stage = "awaitingUdp" /\
                     ServerOf(st, l) = v))

\* Closes server v's draining socket: its receive cancelled, the socket gone.
CloseDrain(st, v) ==
    LET cancelled == [st EXCEPT !.ops = MapBag(@, LAMBDA op :
            IF op.kind = "receiveFrom" /\ op.target = v /\ op.draining
            THEN [op EXCEPT !.current = FALSE] ELSE op)]
    IN [AgeSockets(cancelled, v, "draining", "gone") EXCEPT !.socks[v].draining = FALSE]

\* Replaces server v's port unless opens fail now; the old one drains with its receive.
Rotate(st, v) ==
    IF st.starved THEN st
    ELSE
    LET moved == [st EXCEPT !.ops = MapBag(@, LAMBDA op :
            IF op.kind = "receiveFrom" /\ op.target = v /\ ~op.draining /\ op.current
            THEN [op EXCEPT !.draining = TRUE] ELSE op)]
        aged == [AgeSockets(moved, v, "current", "draining") EXCEPT
                    !.socks[v] = [NoSock EXCEPT !.draining = TRUE]]
    IN Listen(aged, v, FALSE)

CloseIfDrained(st, v) ==
    IF st.socks[v].draining /\ ~DrainNeeded(st, v) THEN CloseDrain(st, v) ELSE st

RECURSIVE TendSocketsFrom(_, _)
TendSocketsFrom(st, v) ==
    IF v >= Sockets THEN st
    ELSE
    LET closed == CloseIfDrained(st, v)
        rotated == IF closed.socks[v].retiring /\ ~closed.socks[v].draining
                   THEN Rotate(closed, v) ELSE closed
        drained == CloseIfDrained(rotated, v)
        current == IF Listening(drained, v, FALSE) THEN drained ELSE Listen(drained, v, FALSE)
        older == IF current.socks[v].draining /\ ~Listening(current, v, TRUE)
                 THEN Listen(current, v, TRUE) ELSE current
    IN TendSocketsFrom(older, v + 1)

\* What a drive does last, server by server: a draining socket nothing is owed closed, a retiring
\* port replaced, and a receive armed on each socket that has none.
TendSockets(st) == TendSocketsFrom(st, 0)

\* Whether a connection reads what its server sends: while it handshakes and once it is up.
Reads(stage) == stage \in {"handshaking", "up"}

RECURSIVE TendConnsFrom(_, _)
TendConnsFrom(st, k) ==
    IF k >= Conns THEN st
    ELSE TendConnsFrom(IF Reads(st.conns[k].stage) /\ ~Receiving(st, k) THEN ArmReceive(st, k)
                       ELSE st, k + 1)

TendConns(st) == TendConnsFrom(st, 0)

-------------------------------------------------------------------------------
\* Sends.

\* Sends the head of connection k's queue unless a send is in flight; a query is sealed as it goes
\* (TLS rule 2), and a send the loop refuses fails the connection (the stream's rule 9).
Pump(st, k) ==
    IF InFlight(st, k) \/ st.conns[k].queue = <<>> THEN st
    ELSE IF st.jammed THEN FailConn(st, k)
    ELSE
    LET entry == Head(st.conns[k].queue) IN
    IF entry.kind = "query"
    THEN [[st EXCEPT !.conns[k].sealed = 1] EXCEPT !.ops = Add(@, Op("send", entry.slot))]
    ELSE [st EXCEPT !.ops = Add(@, Op("sendRecords", k))]

\* The session made records: sealed now, after what is sealed and ahead of every query that is not;
\* behind an entry of the session's own records that has not started, they join it (TLS rule 2).
MakeRecords(st, k) ==
    LET c == st.conns[k] IN
    IF c.sealed >= 2 /\ c.sealed <= Len(c.queue) /\ c.queue[c.sealed] = Records
    THEN [st EXCEPT !.conns[k].owes = FALSE]
    ELSE Pump([st EXCEPT !.conns[k].queue = Take(@, c.sealed) \o <<Records>> \o Drop(@, c.sealed),
                         !.conns[k].sealed = @ + 1, !.conns[k].owes = FALSE], k)

\* The query joins its connection's queue, lending its buffer from now (the stream's rule 9).
SubmitStream(st, l, k) ==
    Pump([st EXCEPT !.slots[l].busy = TRUE, !.conns[k].queue = Append(@, Query(l))], k)

RECURSIVE CloseIdleFrom(_, _)
CloseIdleFrom(st, k) ==
    IF k >= Conns THEN st
    ELSE
    LET c == st.conns[k]
        closed == IF c.stage \in {"closed", "closing"} \/ c.users # 0 \/ c.idleNow THEN st
                  ELSE IF Tls /\ c.stage = "up"
                  THEN MakeRecords([st EXCEPT !.conns[k].stage = "closing"], k)
                  ELSE Shut(st, k)
    IN CloseIdleFrom(closed, k + 1)

\* Closes every connection nobody has used since before this instant (rule 4); over TLS one that
\* is up says close_notify first and closes once it has gone (TLS rule 5).
CloseIdle(st) == CloseIdleFrom(st, 0)

\* The query goes out from the current socket of the lookup's server, which counts it.
SubmitDatagram(st, l) ==
    LET v == ServerOf(st, l) IN
    IF st.jammed THEN TableEvent(st, l, "sendFailed")
    ELSE
    LET lent == [st EXCEPT !.slots[l].busy = TRUE, !.slots[l].sentFrom = {<<v, "current">>},
                           !.ops = Add(@, Op("sendTo", l))]
        sent == lent.socks[v].sent + 1
    IN [lent EXCEPT !.socks[v].sent = sent,
                    !.socks[v].retiring = @ \/ (PerPort > 0 /\ sent >= PerPort)]

\* The lookup's query goes out, or waits for the buffer (rule 6), on the lookup's own transport.
Send(st, l) ==
    LET sl == st.slots[l] IN
    IF sl.busy THEN [st EXCEPT !.slots[l].held = TRUE, !.slots[l].heldCurrent = TRUE]
    ELSE IF sl.lookup = {} THEN st
    ELSE IF Get(sl.lookup).stage = "queryReady" THEN SubmitDatagram(st, l)
    ELSE IF sl.conn # {} /\ st.conns[Get(sl.conn)].stage = "up"
    THEN SubmitStream(st, l, Get(sl.conn))
    ELSE TableEvent(st, l, "tcpFailed")

===============================================================================
