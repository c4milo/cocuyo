----------------------------- MODULE EngineTrace ------------------------------
\* The engine's walks for the replay (tools/spec_replay/engine_replay.zig): TLC's simulation mode
\* takes seeded random walks through the model, and `Emit` writes each state as the replay reads
\* it, the way the Lean walker before it wrote them. A walk is not bounded as the check is:
\* it ends at its depth. `event` is the token of the event that led to the state, which the replay
\* applies to the code; an operation is named by its token, since the model's are a bag.
EXTENDS Engine, TLC

VARIABLE event

-------------------------------------------------------------------------------
\* How the replay spells things.

Flag(b, c) == IF b THEN c ELSE "-"

RECURSIVE Join(_, _)
\* The strings of `seq` with `sep` between them.
Join(seq, sep) ==
    IF seq = <<>> THEN "" ELSE IF Len(seq) = 1 THEN Head(seq) ELSE Head(seq) \o sep \o Join(Tail(seq), sep)

NumbersToken(seq) == "[" \o Join([i \in 1..Len(seq) |-> ToString(seq[i])], ",") \o "]"

StageToken(stage) ==
    CASE stage = "queryReady" -> "query_ready" [] stage = "awaitingUdp" -> "awaiting_udp"
      [] stage = "tcpNeeded" -> "tcp_needed" [] stage = "connectingTcp" -> "connecting_tcp"
      [] stage = "tcpReady" -> "tcp_ready" [] stage = "awaitingTcp" -> "awaiting_tcp"
      [] stage = "done" -> "done" [] stage = "failed" -> "failed"

ErrToken(err) ==
    CASE err = "nameNotFound" -> "name_not_found" [] err = "noData" -> "no_data"
      [] err = "timeout" -> "timeout" [] err = "allServersFailed" -> "all_servers_failed"
      [] err = "chainTooLong" -> "chain_too_long" [] err = "canceled" -> "canceled"
      [] err = "noServers" -> "no_servers"

\* A lookup, as spec/lean/Spec/Tokens.lean's `stateToken` spells it.
LookupToken(lk) ==
    IF lk.stage = "done" THEN "done - -"
    ELSE IF lk.stage = "failed" THEN "failed " \o ErrToken(lk.err) \o " -"
    ELSE StageToken(lk.stage) \o " " \o ToString(lk.server) \o "/" \o ToString(lk.round) \o "/" \o
         ToString(lk.candidate) \o "/" \o ToString(lk.hops) \o " " \o Flag(lk.edns, "E") \o
         Flag(lk.hadNoData, "N") \o Flag(lk.serverFailed, "F") \o Flag(lk.cookieRetried, "K")

SentToken(sl) ==
    IF sl.sentFrom = {} THEN "-"
    ELSE LET from == Get(sl.sentFrom) IN
         ToString(from[1]) \o (CASE from[2] = "current" -> "c" [] from[2] = "draining" -> "d"
                                 [] from[2] = "gone" -> "g")

SlotToken(sl) ==
    IF sl.lookup = {} THEN "free " \o Flag(sl.busy, "B") \o " u" \o SentToken(sl)
    ELSE LookupToken(Get(sl.lookup)) \o " o" \o NumbersToken(sl.order) \o " c" \o
         (IF sl.conn = {} THEN "-" ELSE ToString(Get(sl.conn))) \o " u" \o SentToken(sl) \o " " \o
         Flag(sl.busy, "B") \o Flag(sl.held, "H") \o Flag(sl.reported, "R")

EntryToken(e) == IF e.kind = "query" THEN ToString(e.slot) ELSE "r"

ConnToken(c) ==
    c.stage \o " s" \o ToString(c.server) \o " u" \o ToString(c.users) \o Flag(c.idleNow, "I") \o
    Flag(c.partSent, "P") \o " q[" \o Join([i \in 1..Len(c.queue) |-> EntryToken(c.queue[i])], ",") \o
    "]" \o (IF Tls THEN " k" \o ToString(c.sealed) \o Flag(c.resumed, "M") ELSE "")

SockToken(sk) == "open s" \o ToString(sk.sent) \o Flag(sk.retiring, "R") \o Flag(sk.draining, "D")

\* An operation: its kind's letter, M for a draining socket's receive still current, its target,
\* and whether it is current.
Letter(op) ==
    IF op.kind = "receiveFrom" /\ op.draining /\ op.current THEN "M"
    ELSE CASE op.kind = "connect" -> "C" [] op.kind = "receive" -> "R" [] op.kind = "send" -> "S"
           [] op.kind = "sendTo" -> "D" [] op.kind = "receiveFrom" -> "L"
           [] op.kind = "sendRecords" -> "T"

OpToken(op) == Letter(op) \o ToString(op.target) \o (IF op.current THEN "*" ELSE "x")

\* The order the operations are written in, which the replay sorts its own by: the letter's place
\* in CRSDLMT, then the target, then the stale before the current.
LetterRank(op) ==
    CASE Letter(op) = "C" -> 0 [] Letter(op) = "R" -> 1 [] Letter(op) = "S" -> 2
      [] Letter(op) = "D" -> 3 [] Letter(op) = "L" -> 4 [] Letter(op) = "M" -> 5
      [] Letter(op) = "T" -> 6
OpKey(op) == (LetterRank(op) * 256 + op.target) * 2 + (IF op.current THEN 1 ELSE 0)

RECURSIVE Copies(_, _)
Copies(x, n) == IF n = 0 THEN <<>> ELSE <<x>> \o Copies(x, n - 1)

RECURSIVE OpsTokens(_, _)
\* Every operation of `ops` among `left`, in key order, each written once for each copy.
OpsTokens(ops, left) ==
    IF left = {} THEN <<>>
    ELSE LET first == CHOOSE op \in left : \A other \in left : OpKey(op) <= OpKey(other)
         IN Copies(OpToken(first), ops[first]) \o OpsTokens(ops, left \ {first})

\* The waiting lookups, grouped by the ticks they have left, soonest first.
WaitGroups(st) ==
    LET waiting == WaitingSlots(st)
        lefts == {st.slots[l].remaining : l \in waiting}
        RECURSIVE Groups(_)
        Groups(rest) ==
            IF rest = {} THEN <<>>
            ELSE LET least == Least(rest)
                     members == {l \in waiting : st.slots[l].remaining = least}
                     sorted == [i \in 1..Cardinality(members) |->
                                    CHOOSE l \in members :
                                        Cardinality({m \in members : m < l}) = i - 1]
                 IN <<NumbersToken(sorted)>> \o Groups(rest \ {least})
    IN Groups(lefts)

Line(st) ==
    Join([l \in 1..Slots |-> SlotToken(st.slots[l - 1])], " ; ") \o " | " \o
    Join([k \in 1..Conns |-> ConnToken(st.conns[k - 1])], " ; ") \o " | " \o
    Join([v \in 1..Sockets |-> SockToken(st.socks[v - 1])], " ; ") \o " | " \o
    Join(OpsTokens(st.ops, DOMAIN st.ops), " ") \o " | " \o
    "r" \o NumbersToken(st.ready) \o " q" \o NumbersToken(st.results) \o " t" \o
    (IF st.lastTaken = {} THEN "-" ELSE ToString(Get(st.lastTaken))) \o
    " w[" \o Join(WaitGroups(st), ",") \o "]" \o
    " f" \o NumbersToken([v \in 1..Servers |-> st.failures[v - 1]]) \o
    " e" \o NumbersToken(st.free) \o " " \o Flag(st.jammed, "J") \o Flag(st.starved, "Z") \o
    (IF Tls THEN " tk[" \o Join([v \in 1..Servers |-> IF st.tickets[v - 1] THEN "1" ELSE "0"], ",") \o "]"
     ELSE "")

EventToken(e) ==
    CASE e.kind \in {"start", "take", "expire", "idle", "jam", "starve"} -> e.kind
      [] e.kind = "cancel" -> "cancel:" \o ToString(e.slot)
      [] e.kind = "finish" -> "finish:" \o OpToken(e.op) \o ":" \o e.outcome
      [] e.kind = "message" -> "message:" \o OpToken(e.op) \o ":" \o ToString(e.slot) \o ":" \o e.reply
      [] e.kind = "tls" -> "tls:" \o OpToken(e.op) \o ":" \o e.step
      [] e.kind = "lapse" -> "lapse:" \o ToString(e.server)
      [] e.kind = "straggle" -> "straggle:" \o OpToken(e.op)

Transport == IF Tls THEN "tls" ELSE IF UseTcp THEN "tcp" ELSE "udp"

-------------------------------------------------------------------------------
\* The walks.

TraceInit == Init /\ event = "init"

\* Writes the state the walk is in. TLC's simulation evaluates the next-state relation once for each
\* state a walk takes, and an invariant for every successor it considers, so it is written here;
\* a walk's first line names its configuration.
Emit ==
    /\ TLCGet("level") = 1 =>
          PrintT("config " \o ToString(Slots) \o " " \o ToString(Conns) \o " " \o Transport \o " " \o
                 ToString(PerPort))
    /\ PrintT(ToString(TLCGet("level") - 1) \o " " \o event \o " " \o Line(s))

\* The function `f`, held whole. TLC holds `[x \in S |-> e]` as the expression and stacks each
\* EXCEPT on it as another layer. A check writes each state it keeps out whole, but a walk keeps
\* none, so each step would build on the layers of every step before it, and a walk of 200 events
\* took minutes. TLC's `@@` builds its result whole, and `<< >>` adds nothing to it.
Whole(f) == f @@ << >>

\* The state with each of its functions held whole.
WholeState(st) ==
    [st EXCEPT !.slots = Whole(@), !.conns = Whole(@), !.socks = Whole(@), !.ops = Whole(@),
               !.failures = Whole(@), !.tickets = Whole(@)]

TraceNext ==
    /\ Emit
    /\ \E e \in Enabled(s) :
          LET t == WholeState(Step(s, e)) IN
          s' = t /\ broken' = Broken(s, e, t) /\ event' = EventToken(e)

===============================================================================
