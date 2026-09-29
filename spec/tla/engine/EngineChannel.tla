---------------------------- MODULE EngineChannel -----------------------------
\* The engine's DoH over colibri's channel, written from request rules 18 to 25 of docs/design.md
\* §24: a channel for each server, and two links for each channel, a QUIC link over a datagram
\* socket and a TCP link over a stream socket, which the engine opens and closes when the channel
\* says.
\*
\* colibri is abstracted to what its channel tells the engine at a read: open a link, close one,
\* owe octets on one, a ticket of a link's transport, an exchange's end, one held while a link's
\* send is in flight, and closed once shut down with nothing left. Which link it opens when, which
\* connection takes the exchanges and what ends an exchange are colibri's own, and colibri's model
\* holds them (its decision 105), so here the channel may say any of them whenever its calls allow
\* it. `connected` changes nothing the engine does, since HTTP/3, HTTP/2 and HTTP/1.1 carry DoH
\* alike (rule 20), so it is left out; so are the octets, and the channel's instant, which only
\* makes a link owe octets. Link i is channel i \div 2's: its QUIC link when i is even, its TCP link
\* when odd. A link's steps name the link in the event's `server`, and a channel's steps the
\* channel.
EXTENDS EngineRequest

-------------------------------------------------------------------------------
\* Links.

LinkServer(i) == i \div 2
IsTcp(i) == i % 2 = 1
LinksOf(v) == {2 * v, 2 * v + 1}

\* The kinds of a link's operations.
LinkOps == {"lsend", "lrecv", "lconnect"}

LReceiving(st, i) == \E op \in DOMAIN st.ops : op.kind = "lrecv" /\ op.target = i /\ op.current
LSending(st, i) == \E op \in DOMAIN st.ops : op.kind = "lsend" /\ op.target = i /\ op.current

\* Arms link i's receive unless the loop refuses it; the next drive asks again.
LListen(st, i) == IF st.jammed THEN st ELSE [st EXCEPT !.ops = Add(@, Op("lrecv", i))]

\* Link i's socket closes: its current operations are left to the loop to end, and its buffer and
\* its address stay lent until their operations' final events, whichever incarnation made them
\* (request rules 8 and 14).
ShutLink(st, i) ==
    LET k == st.links[i] IN
    [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
        IF op.kind \in LinkOps /\ op.target = i THEN [op EXCEPT !.current = FALSE] ELSE op)]
     EXCEPT !.links[i] = [NoLink EXCEPT !.lent = k.lent, !.connectLent = k.connectLent]]

\* Link i's socket ended, and the channel is told: it ends what that connection held as it decides,
\* and says so at a read (rule 19).
LinkGone(st, i) == [ShutLink(st, i) EXCEPT !.asked[i] = FALSE]

\* Link i's connection starts: its receive armed, its first flight owed, and its transport's ticket
\* spent (rule 23).
StartLink(st, i) ==
    LListen([st EXCEPT !.links[i].state = "running", !.links[i].owes = TRUE,
                       !.links[i].resumed = st.linkTickets[i], !.linkTickets[i] = FALSE], i)

\* The channel asked for link i (rule 19). A socket of an earlier incarnation still closing is left
\* to end. A datagram socket opens, and the channel's QUIC connection starts. A stream socket
\* connects first, and waits while a connect of an earlier opening still borrows the link's address
\* (request rule 14). A socket the system refuses, and a connect the loop refuses, end the link.
LinkOpen(st, i) ==
    LET shut == ShutLink(st, i) IN
    IF IsTcp(i) /\ shut.links[i].connectLent THEN [shut EXCEPT !.links[i].state = "reopening"]
    ELSE IF st.starved \/ (IsTcp(i) /\ st.jammed) THEN LinkGone(shut, i)
    ELSE IF IsTcp(i)
    THEN [shut EXCEPT !.links[i].state = "connecting", !.links[i].connectLent = TRUE,
                      !.ops = Add(@, Op("lconnect", i))]
    ELSE StartLink(shut, i)

\* The channel closed link i: its connection writes nothing more and reads nothing more, and its
\* socket closes once what the link keeps to send has gone (rule 19). One with nothing to send, and
\* one that connects or waits to, closes at once.
LinkClose(st, i) ==
    IF st.links[i].state = "running" /\ (st.links[i].made \/ LSending(st, i))
    THEN [[st EXCEPT !.ops = MapBag(@, LAMBDA op :
             IF op.kind = "lrecv" /\ op.target = i THEN [op EXCEPT !.current = FALSE] ELSE op)]
          EXCEPT !.links[i].state = "closing", !.links[i].owes = FALSE]
    ELSE ShutLink(st, i)

\* Whether a link, as `k`, has octets to send and its buffer to send them from: the ones it kept, or
\* ones the channel owes. A closing link sends only what it kept.
LSends(k) == k.state \in {"running", "closing"} /\ ~k.lent /\ (k.made \/ k.owes)

\* Link i's octets go, whose state before the drive's tending was `k`: the ones kept from a refusal
\* or a short send, or else ones the channel makes now. Ones the loop refuses are kept (request
\* rules 8 and 15).
LSend(st, k, i) ==
    LET made == IF k.made THEN st ELSE [st EXCEPT !.links[i].made = TRUE, !.links[i].owes = FALSE]
    IN IF st.jammed THEN made
       ELSE [made EXCEPT !.links[i].made = FALSE, !.links[i].lent = TRUE,
                         !.ops = Add(@, Op("lsend", i))]

RECURSIVE TendLinksFrom(_, _)
TendLinksFrom(st, i) ==
    IF i >= 2 * CServers THEN st
    ELSE
    LET k == st.links[i]
        listened == IF k.state = "running" /\ ~LReceiving(st, i) THEN LListen(st, i) ELSE st
    IN TendLinksFrom(IF LSends(k) THEN LSend(listened, k, i) ELSE listened, i + 1)

\* What a drive does last, link by link: a receive armed on each running link that has none, and
\* octets sent when the buffer is back (rule 19, request rules 8 and 15).
TendLinks(st) == TendLinksFrom(st, 0)

-------------------------------------------------------------------------------
\* Channels.

\* The requests on channel v: its exchanges, and those waiting for the next channel.
CUsers(st, v) == Cardinality(st.chans[v].exchanges) + Len(st.chans[v].queue)

\* Channel v went idle at this instant if nothing is left on it.
Idled(st, v) == [st EXCEPT !.chans[v].idleNow = @ \/ CUsers(st, v) = 0]

\* Slot l's request leaves its channel: out of the queue if it waits, and its exchange cancelled if
\* the channel holds it, whose memory is the engine's again at once (rule 21, request rule 6). What
\* the channel held of it tells nobody, and goes with it.
DropExchange(st, l) ==
    IF st.reqs[l] = {} THEN st
    ELSE
    LET v == RequestOf(st, l).server IN
    Idled([st EXCEPT !.reqs[l] = {}, !.chans[v].queue = SelectSeq(@, LAMBDA x : x # l),
                     !.chans[v].exchanges = @ \ {l}, !.chans[v].held = {h \in @ : h.slot # l}], v)

RECURSIVE CancelLeftCFrom(_, _)
CancelLeftCFrom(st, l) ==
    IF l >= Slots THEN st
    ELSE CancelLeftCFrom(IF st.reqs[l] # {} /\ ~CurrentRequest(st, l) THEN DropExchange(st, l)
                         ELSE st, l + 1)

\* Every request whose lookup has left it is cancelled (request rule 6).
CancelLeftC(st) == CancelLeftCFrom(st, 0)

\* Slot l's exchange on channel v ended: a response carrying a DNS message, or an end that fails it
\* (rule 22). Its lookup hears only if the request is still its attempt.
ExchangeEnded(st, v, l, r) ==
    LET replied == LookupEvent(st, l, "reply", r)
        reached == IF ~CurrentRequest(st, l) THEN st
                   ELSE IF r = "failed" THEN TableEvent(st, l, "requestFailed")
                   ELSE IF replied[2] = "accepted" THEN Settle(replied[1], l) ELSE replied[1]
    IN Idled([reached EXCEPT !.reqs[l] = {}, !.chans[v].exchanges = @ \ {l}], v)

\* The engine reads channel v, which tells first what it held: an exchange's end (rule 17).
TellHeldC(st, v) ==
    LET c == st.chans[v] IN
    IF c.held = {} THEN st
    ELSE LET h == Get(c.held) IN ExchangeEnded([st EXCEPT !.chans[v].held = {}], v, h.slot, h.reply)

\* Link i's socket ended: the channel is told, and read (rule 17).
LinkEnded(st, i) == TellHeldC(LinkGone(st, i), LinkServer(i))

\* The drive takes slot l's request onto its server's channel whatever the channel's state, and
\* tells the lookup it went out (request rule 3). A closed channel opens with it as its exchange, an
\* open one takes it as an exchange at once, and one shutting down keeps it for the next (rules 18,
\* 21 and 24). An earlier request of the slot's is cancelled first. Then the engine reads the
\* channel, which says at that read what the request moved, its first link to open among it, and
\* tells first what it held (rule 17).
ChanTake(st, l) ==
    LET v == ServerOf(st, l)
        cleared == DropExchange(st, l)
        told == TableEvent(cleared, l, "sent")
        taken == [told EXCEPT !.reqs[l] = {[server |-> v,
                                            attempt |-> Attempt(Get(told.slots[l].lookup))]}]
        c == taken.chans[v]
        placed == CASE c.stage = "closed" -> [taken EXCEPT !.chans[v].stage = "open",
                                                           !.chans[v].exchanges = {l},
                                                           !.chans[v].idleNow = FALSE]
                    [] c.stage = "open" -> [taken EXCEPT !.chans[v].exchanges = @ \cup {l}]
                    [] OTHER -> [taken EXCEPT !.chans[v].queue = Append(@, l)]
    IN TellHeldC(placed, v)

\* The channel said closed: shut down, with no exchange left and every link closed. Its slot is
\* free, and a new channel opens for the requests that waited (rule 24).
ChanClosed(st, v) ==
    LET q == st.chans[v].queue
        freed == [st EXCEPT !.chans[v] = NoChan]
    IN IF q = <<>> THEN freed
       ELSE [freed EXCEPT !.chans[v].stage = "open",
                          !.chans[v].exchanges = {q[i] : i \in 1..Len(q)}]

RECURSIVE CloseIdleCFrom(_, _)
CloseIdleCFrom(st, v) ==
    IF v >= CServers THEN st
    ELSE
    LET c == st.chans[v]
        idle == c.stage = "open" /\ CUsers(st, v) = 0 /\ ~c.idleNow
    IN CloseIdleCFrom(IF idle THEN [st EXCEPT !.chans[v].stage = "shutting"] ELSE st, v + 1)

\* A channel with no request on it since before this instant shuts down: it ends each connection as
\* its protocol ends one, closes each link, then says closed (rule 24).
CloseIdleC(st) == CloseIdleCFrom(st, 0)

\* The channel a step names: a link's steps name the link, and the rest the channel.
StepChannel(step, n) ==
    IF step \in {"open", "close", "octets", "newTicket"} THEN LinkServer(n) ELSE n

\* What a channel says at a read, after what it held (rule 17): open or close link n, owe octets on
\* it, or a ticket of its transport; slot l's exchange ended with reply r, or held; or closed.
ChanStep(st, step, n, l, r) ==
    LET told == TellHeldC(st, StepChannel(step, n)) IN
    CASE step = "open" -> LinkOpen([told EXCEPT !.asked[n] = TRUE], n)
      [] step = "close" -> LinkClose([told EXCEPT !.asked[n] = FALSE], n)
      [] step = "octets" -> [told EXCEPT !.links[n].owes = TRUE]
      [] step = "newTicket" -> [told EXCEPT !.linkTickets[n] = TRUE]
      [] step = "finished" -> ExchangeEnded(told, n, l, r)
      [] step = "hold" -> [told EXCEPT !.chans[n].held = {[slot |-> l, reply |-> r]}]
      [] step = "closed" -> ChanClosed(told, n)

-------------------------------------------------------------------------------
\* Link events.

\* A link's send ended: its buffer comes back. A send that failed ends the link. Over TCP one that
\* went short keeps its rest, to go before anything the channel makes after it (request rule 15). A
\* closing link with nothing left to send closes. Then the engine reads the channel, which tells
\* first what it held (rule 17).
LSendEnded(st, op, outcome) ==
    LET i == op.target
        back == [[st EXCEPT !.ops = Remove(@, op)] EXCEPT !.links[i].lent = FALSE]
        ended == CASE outcome = "failed" -> LinkGone(back, i)
                   [] outcome = "short" -> [back EXCEPT !.links[i].made = TRUE]
                   [] back.links[i].state = "closing" /\ ~back.links[i].made -> ShutLink(back, i)
                   [] OTHER -> back
    IN IF ~op.current THEN back ELSE TellHeldC(ended, LinkServer(i))

\* A link's receive ended: one that ran out is armed again. One that failed, and over TCP one that
\* ended with no octets, the server's end of the stream, end the link (rule 19, request rule 15).
LRecvEnded(st, op, outcome) ==
    LET finished == [st EXCEPT !.ops = Remove(@, op)] IN
    IF ~op.current THEN finished
    ELSE IF outcome = "exhausted" THEN LListen(finished, op.target)
    ELSE LinkEnded(finished, op.target)

\* A link's connect ended, and the loop gives the address back (request rule 14). The current
\* opening's success starts the channel's TCP connection, and its failure ends the link. An earlier
\* opening's end opens the link that waited for it, and an opening that fails there ends the link
\* as any end does: the channel is told, and read (rule 19).
LConnectEnded(st, op, succeeded) ==
    LET i == op.target
        back == [st EXCEPT !.ops = Remove(@, op), !.links[i].connectLent = FALSE]
        reopened == LinkOpen(back, i)
    IN IF ~op.current
       THEN (IF back.links[i].state # "reopening" THEN back
             ELSE IF reopened.links[i].state = "down" THEN TellHeldC(reopened, LinkServer(i))
             ELSE reopened)
       ELSE IF ~succeeded THEN LinkEnded(back, i)
       ELSE StartLink(back, i)

-------------------------------------------------------------------------------
\* What must hold (rules 18 to 25).

\* A link's socket is the channel's: it connects, waits to or runs exactly while the channel has
\* asked for it and not closed it, and once the channel closed it, it reads nothing and sends only
\* what it kept, closing once that has gone (rule 19).
LinksAsked(st) ==
    \A i \in 0..2 * CServers - 1 :
        LET k == st.links[i]
            current(kind) ==
                Count(st.ops, LAMBDA op : op.kind = kind /\ op.target = i /\ op.current)
        IN /\ st.asked[i] = (k.state \in {"connecting", "reopening", "running"})
           /\ (k.state \in {"down", "reopening"}) =>
                  (current("lrecv") + current("lsend") + current("lconnect") = 0 /\ ~k.owes /\
                   ~k.made)
           /\ (k.state = "connecting") =>
                  (current("lconnect") = 1 /\ current("lrecv") + current("lsend") = 0 /\ ~k.owes /\
                   ~k.made)
           /\ (k.state = "running") =>
                  (current("lconnect") = 0 /\ current("lrecv") <= 1 /\ current("lsend") <= 1)
           /\ (k.state = "closing") =>
                  (current("lconnect") + current("lrecv") = 0 /\ ~k.owes /\
                   (k.made \/ current("lsend") = 1))

\* A link's buffer is lent exactly when a send of it is in flight, and over TCP its address exactly
\* when a connect of it is, one at most of each, of any incarnation (request rules 8 and 14). A link
\* waits to connect only while an earlier opening's connect is in flight.
LinkLent(st) ==
    \A i \in 0..2 * CServers - 1 :
        LET k == st.links[i]
            sends == Count(st.ops, LAMBDA op : op.kind = "lsend" /\ op.target = i)
            connects == Count(st.ops, LAMBDA op : op.kind = "lconnect" /\ op.target = i)
        IN /\ sends <= 1 /\ k.lent = (sends = 1)
           /\ connects <= 1 /\ k.connectLent = (connects = 1)
           /\ (k.state # "reopening" \/ k.connectLent)

\* A request slot is free, or its request is an exchange on its server's channel or waits for the
\* next one, never both, and whatever a channel holds is a request of its server's. Only a channel
\* that shuts down keeps requests for the next, and a closed one holds nothing (rules 21 and 24).
ExchangesPlaced(st) ==
    ~Channel \/
    /\ \A l \in 0..Slots - 1 :
          st.reqs[l] = {} \/
          LET c == st.chans[RequestOf(st, l).server]
          IN c.stage # "closed" /\ (Contains(c.queue, l) # (l \in c.exchanges))
    /\ \A v \in 0..CServers - 1 :
          LET c == st.chans[v] IN
          /\ Distinct(c.queue)
          /\ (c.queue = <<>> \/ c.stage = "shutting")
          /\ (c.stage # "closed" \/ c.exchanges = {})
          /\ {h.slot : h \in c.held} \subseteq c.exchanges
          /\ \A l \in c.exchanges \cup {c.queue[i] : i \in 1..Len(c.queue)} :
                st.reqs[l] # {} /\ RequestOf(st, l).server = v

\* A channel that shuts down takes no new exchange: a request taken meanwhile waits for the next
\* (rule 24).
ShutTakesNone(before, st) ==
    \A v \in 0..CServers - 1 :
        before.chans[v].stage # "shutting" \/ st.chans[v].stage # "shutting" \/
        st.chans[v].exchanges \subseteq before.chans[v].exchanges

\* What a channel holds, it holds only while a send of one of its links is in flight: the send's end
\* reads it (rule 17).
ChanHeldWhileSending(st) ==
    \A v \in 0..CServers - 1 : st.chans[v].held = {} \/ \E i \in LinksOf(v) : LSending(st, i)

\* After a drive with nothing refused, every running link has its receive armed.
LListening(st) == \A i \in 0..2 * CServers - 1 : st.links[i].state # "running" \/ LReceiving(st, i)

\* A link whose connection started at this event, resuming, spent its transport's ticket (rule 23).
LinkTicketSpent(before, st) ==
    \A i \in 0..2 * CServers - 1 :
        LET k == st.links[i] IN
        ~(k.state = "running" /\ k.resumed /\ before.links[i].state # "running") \/
        ~st.linkTickets[i]

\* A link's socket that ends fails no request itself: the channel decides what that fails, and says
\* so at a read (rule 19). The end the channel held, and told first at the same read, is its own
\* (rule 17).
LinkEndFailsNone(before, e, st) ==
    ~(e.kind = "finish" /\ e.op.kind \in LinkOps /\ e.op.current) \/
    \A l \in 0..Slots - 1 :
        before.reqs[l] = {} \/ st.reqs[l] # {} \/
        l \in UNION {{h.slot : h \in before.chans[v].held} : v \in 0..CServers - 1}

===============================================================================
