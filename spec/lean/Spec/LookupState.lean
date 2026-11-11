/-!
# The lookup's state, and the policies its transitions share

The types of `Spec.Lookup`, the configuration and the state, and the retry, search-list and reply
policies of docs/design.md §5, which `Spec.Lookup`'s steps read. Split from `Spec.Lookup` by the
file-length rule.
-/
namespace Spec.Lookup

/-- The eight states of §5, and `awaitingKeys`, where a validating lookup waits for the keys a
message needs (docs/design.md §25, Stage B: what the lookup does with it). -/
inductive Stage where
  | queryReady | awaitingUdp | tcpNeeded | connectingTcp | tcpReady | awaitingTcp | done | failed
  | awaitingKeys
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- How a lookup fails. -/
inductive Err where
  | nameNotFound | noData | timeout | allServersFailed | chainTooLong | canceled | noServers
  /-- A name longer than a name can be. A server says so with YXDOMAIN (§16 decision 57). -/
  | nameTooLong
  /-- A validating lookup's passes ran out after a bogus message, or its walk proved one
  (docs/design.md §25). -/
  | bogus
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- Why a transport failed the lookup: the reason the caller passes with `on_tcp_failed` and
`on_request_failed` (docs/design.md §5, The cause of a failure; §16 decision 51). -/
inductive Reason where
  /-- The connect failed. -/
  | connect
  /-- The TLS handshake failed, or over DoQ the QUIC handshake. -/
  | handshake
  /-- No server took part: no socket, no free connection slot, or no TCP at all. -/
  | «local»
  /-- A connection that was up failed, or a send on it. -/
  | closed
  /-- Over DoH, an HTTP response that holds no DNS message. -/
  | status
  /-- Over DoH or DoQ, a stream that the server reset. -/
  | reset
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- What a server gave when it failed the lookup: a reply's rcode, as the model's replies name it,
or the reason the caller passed. -/
inductive What where
  /-- SERVFAIL, REFUSED or NOTIMP. -/
  | servfail
  /-- FORMERR to a query without EDNS0. -/
  | formerr
  /-- BADCOOKIE that advances the server: over a stream after its retry, or over DoH or DoQ. -/
  | badcookie
  /-- A connection or a request that failed, and why. -/
  | reason (r : Reason)
  /-- A message the validator called bogus (docs/design.md §25). -/
  | bogus
  /-- The walk for the keys a message needed: every server of one of its questions failed. -/
  | keys
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- What made a server fail the lookup, and that server: the cause the lookup keeps, of the last
such failure (docs/design.md §5, The cause of a failure; §16 decisions 45 and 51). The server is a
position in the order, as the state's `server` is. -/
structure Cause where
  server : Nat
  what : What
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- What a datagram or a stream message is, once §7's checks and §5's rcode policy have read it. -/
inductive Reply where
  /-- It fails a check of §7: it is not this lookup's response, and the wait stands. -/
  | unmatched
  /-- Records of the type asked for, or a chain in the message that ends in them. -/
  | answer
  /-- A chain that ends in a CNAME with no record of the type asked for. -/
  | cname
  | nxdomain
  | nodata
  /-- YXDOMAIN: a DNAME substitution made the name too long (RFC 6672 §2.2). -/
  | yxdomain
  /-- SERVFAIL, REFUSED or NOTIMP. -/
  | servfail
  | formerr
  /-- TC=1 with NOERROR and no records, which is what a truncated answer over UDP carries. Since
  2026-10-14 it also stands for a datagram that the buffer cut, when the lookup waits over UDP and
  not over DoH or DoQ. That datagram moves the lookup as TC=1 does, once it passes the checks of a
  cut datagram (docs/design.md §7, A datagram that the buffer cut). A cut datagram is `unmatched`
  everywhere else. The replay hands a cut datagram to each lookup that this reply or `unmatched`
  reaches, and requires the same move (spec/README.md). -/
  | truncated
  /-- BADCOOKIE (RFC 7873 §5.3). -/
  | badcookie
  deriving DecidableEq, Repr, Inhabited

/-- What the validator says of a message the lookup acts on (docs/design.md §25, step 11). -/
inductive Verdict where
  | secure | insecure | bogus
  /-- The keys the message needs are not held yet. -/
  | keysWanted
  deriving DecidableEq, Repr, Inhabited

/-- How the walk for a message's keys failed (docs/design.md §25, walk rules 7 and 11). -/
inductive Walked where
  /-- It proved the message wrong. -/
  | bogus
  /-- One of its questions went unanswered. -/
  | timeout
  /-- Every server of one of its questions failed. -/
  | failed
  deriving DecidableEq, Repr, Inhabited

/-- Whether a configuration relies on the AD bit of a response, and from which servers
(docs/design.md §25, Stage A rule 1). -/
inductive Mode where
  /-- The bit means nothing. The default. -/
  | ignored
  /-- The bit counts from a server over TLS, HTTPS or QUIC, which strict mode authenticated. -/
  | encrypted
  /-- The bit counts from every server. -/
  | always
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- What the caller can tell a lookup, and asking it what to do. -/
inductive Event where
  /-- A poll before the deadline. -/
  | poll
  /-- A poll at or past the deadline. -/
  | expire
  | sent
  | sendFailed
  | tcpConnected
  /-- A connection failed, and why (docs/design.md §16 decision 51). -/
  | tcpFailed (r : Reason)
  /-- A request over DoH or DoQ ended without an answer, and why: an HTTP status that is not 2xx,
  a stream the server reset, or the connection lost (docs/design.md §22, §23). -/
  | requestFailed (r : Reason)
  /-- A reply whose message has AD clear. -/
  | reply (r : Reply)
  /-- A reply whose message has AD set, the server's word that it validated the answer and the
  authority sections (RFC 4035 §3.2.3; docs/design.md §25, Stage A). -/
  | replyAd (r : Reply)
  /-- A reply the lookup acts on, and what the validator says of its message (docs/design.md §25,
  step 11). -/
  | replyChecked (r : Reply) (v : Verdict)
  /-- A reply to an earlier try that is still open: the server at position `p`, over a stream or not,
  the reply, its AD bit and the validator's verdict when it gave one (docs/design.md §5, Tries kept
  open). -/
  | earlier (p : Nat) (stream : Bool) (r : Reply) (ad : Bool) (v : Option Verdict)
  /-- The connection of an earlier try at position `p` failed, or its request did, and why. -/
  | earlierFailed (p : Nat) (stream : Bool) (r : Reason)
  /-- The walk ended with the keys held, or with an insecure delegation. -/
  | keysReady
  /-- The walk failed. -/
  | keysFailed (w : Walked)
  | cancel
  deriving DecidableEq, Repr, Inhabited

/-- What a lookup answers: an action for a poll, a verdict for a reply, nothing for the rest. -/
inductive Out where
  | sendUdp | connectTcp | sendTcp | sendRequest | waitUntilNs | done
  | failed (e : Err)
  | accepted | ignored
  | none
  deriving DecidableEq, Repr, Inhabited

/-- The configuration a lookup runs under, reduced to what its transitions read. `candidates`
counts the names the search list gives (§5), the name itself included. -/
structure Config where
  servers : Nat
  attempts : Nat
  candidates : Nat
  hopsMax : Nat
  useTcp : Bool
  /-- Every query is a request of its own, over DoH or DoQ (docs/design.md §22, §23), which
  never goes with `useTcp`. -/
  request : Bool := false
  /-- Which kind of request: DoQ's QUIC rather than DoH's HTTP. No transition reads it, since the two
  move alike; the transcript names it, so the replay asks servers of that kind. -/
  quic : Bool := false
  /-- Whether the AD bit is relied on (docs/design.md §25, Stage A rule 1). -/
  authenticatedData : Mode := .ignored
  /-- Every server is spoken to over TLS, which strict mode authenticated (docs/design.md §21). A
  request, over DoH or DoQ, is encrypted whatever this says. -/
  encrypted : Bool := false
  /-- The table handed the lookup a validator (docs/design.md §25, Stage B). -/
  validate : Bool := false
  deriving Repr

structure State where
  stage : Stage
  /-- The current server's position in the order, and the passes over the order completed. -/
  server : Nat
  round : Nat
  candidate : Nat
  /-- CNAMEs followed across messages (§5, CNAME policy). -/
  hops : Nat
  edns : Bool
  hadNoData : Bool
  /-- The cause of the last server failure, or none while no server failed the lookup. Whether
  there is one decides the failure when the attempts run out (§5, retry policy): a server answered
  SERVFAIL, REFUSED or NOTIMP, FORMERR without EDNS0, or BADCOOKIE over a stream after its retry or
  over DoH or DoQ, or it refused the lookup: a connection, a handshake or a request failed (§16
  decision 25). Each such failure replaces it, and nothing clears it (§16 decision 45). -/
  cause : Option Cause
  /-- Whether this server already answered BADCOOKIE once and was asked again (RFC 7873 §5.3),
  over a datagram or over a stream. -/
  cookieRetried : Bool
  /-- A send was handed out by a poll and the caller has not yet said how it went. -/
  offered : Bool
  err : Err
  /-- The queries sent for the current name to the server at each position in the order: over
  UDP or as a DoH or DoQ request, and over a stream. A send counts at `sent`. A new name, the next
  candidate or a CNAME's target, starts each count again at zero (docs/design.md §5, retry
  policy; §16 decision 58). -/
  datagrams : List Nat
  streams : List Nat
  /-- The tries of the current name still open at each position, over UDP or as a DoH or DoQ
  request, and over a stream (docs/design.md §5, Tries kept open; §16 decision 66). A try opens at
  `sent`. It closes at a reply to it that moves the lookup on, at a failure of its connection or
  its request, and at a new name. The current try is one of them while the lookup waits on it. -/
  openDatagrams : List Nat
  openStreams : List Nat
  /-- Rule 3's conjunction: AD set on every message the lookup acted on, while the configuration
  relies on the bit (docs/design.md §25, Stage A). Once clear it stays clear. -/
  authentic : Bool
  /-- The times the lookup waited for keys for the current name (docs/design.md §25, step 11). -/
  asks : Nat
  /-- Stage B's conjunction: every message the lookup acted on was validated secure. Once clear it
  stays clear. -/
  secure : Bool
  deriving DecidableEq, Repr, Hashable

/-- Where a lookup stands before each query: every query over TCP when the configuration says so
(§19 step 11), UDP otherwise. -/
def fresh (c : Config) : Stage := if c.useTcp then .tcpNeeded else .queryReady

def fail (s : State) (e : Err) : State := { s with stage := .failed, err := e, offered := false }

/-- The most queries a lookup sends one server over one transport for one name: a query and two
retries. "A resolver MUST NOT retry a given query to a server address over a given DNS transport
more than twice" (RFC 9520 §3.1; docs/design.md §16 decision 58). -/
def queriesMax : Nat := 3

/-- The times a lookup waits for keys for one name: `key_asks_max` (docs/design.md §25). -/
def keyAsksMax : Nat := 2

/-- No query sent yet to any server, for a new name. -/
def unsent (c : Config) : List Nat := List.replicate c.servers 0

/-- The queries sent for the current name to the server at position `p`, over a stream or not. -/
def sentTo (s : State) (stream : Bool) (p : Nat) : Nat :=
  (if stream then s.streams else s.datagrams).getD p 0

/-- Whether the current server has had its queries for the current name over a stream or not, so
that the lookup may not ask it again over that transport (RFC 9520 §3.1). -/
def spent (s : State) (stream : Bool) : Bool := decide (queriesMax ≤ sentTo s stream s.server)

/-- One more query sent to the server at position `p`. -/
def bump (l : List Nat) (p : Nat) : List Nat := l.set p (l.getD p 0 + 1)

def init (c : Config) : State :=
  let s : State := { stage := fresh c, server := 0, round := 0, candidate := 0, hops := 0,
                     edns := true, hadNoData := false, cause := none,
                     cookieRetried := false, offered := false, err := .timeout,
                     datagrams := unsent c, streams := unsent c, openDatagrams := unsent c,
                     openStreams := unsent c, authentic := true, asks := 0, secure := true }
  if c.servers = 0 then fail s .noServers else s

/-- The current server failed the lookup with `w`: the cause, `w` and that server, replaces the one
the lookup held, and nothing else changes (§5, The cause of a failure). -/
def keep (s : State) (w : What) : State := { s with cause := some { server := s.server, what := w } }

/-- The server at position `p` failed one of the lookup's earlier tries with `w`. The cause names
that server, and the lookup stays where it is (docs/design.md §5, Tries kept open). -/
def keepAt (s : State) (p : Nat) (w : What) : State := { s with cause := some { server := p, what := w } }

/-- The tries of the current name open at position `p`, over a stream or not. -/
def openAt (s : State) (stream : Bool) (p : Nat) : Nat :=
  (if stream then s.openStreams else s.openDatagrams).getD p 0

/-- One try fewer open at position `p`, over a stream or not. -/
def closeTry (s : State) (stream : Bool) (p : Nat) : State :=
  if stream then { s with openStreams := s.openStreams.set p (openAt s true p - 1) }
  else { s with openDatagrams := s.openDatagrams.set p (openAt s false p - 1) }

/-- A later pass that reaches a server with an open try of the name over a stream sends no query.
It waits on that try, whose query is still on its connection: RFC 1035 §4.2.1 asks for a
retransmission over UDP alone (docs/design.md §5, Tries kept open). -/
def waitOn (c : Config) (t : State) : State :=
  if c.useTcp && decide (0 < openAt t true t.server) then { t with stage := .awaitingTcp } else t

/-- How a lookup ends when its passes run out: `bogus` when a bogus message is the cause it holds,
`allServersFailed` for every other cause, and `timeout` with none (§5, retry policy;
docs/design.md §25). -/
def exhausted (s : State) : Err :=
  match s.cause with
  | some { what := .bogus, .. } => .bogus
  | some _ => .allServersFailed
  | none => .timeout

/-- The next server, then the next pass, then failure (§5, retry policy). EDNS0 is back on: that a
server does not speak it is a fact about that server (RFC 6891 §6.2.2). A server that has had its
queries for the name over the transport the lookup starts on is passed over, and the walk goes on
to the next (RFC 9520 §3.1; §16 decision 58). -/
def advanceServer (c : Config) (s : State) : State :=
  if _h : s.server + 1 < c.servers then
    let t := { s with server := s.server + 1, stage := fresh c, edns := true,
                      cookieRetried := false, offered := false }
    if spent t c.useTcp then advanceServer c t else waitOn c t
  else if _h2 : s.round + 1 < c.attempts then
    let t := { s with server := 0, round := s.round + 1, stage := fresh c, edns := true,
                      cookieRetried := false, offered := false }
    if spent t c.useTcp then advanceServer c t else waitOn c t
  else
    fail { s with round := s.round + 1 } (exhausted s)
termination_by (c.attempts - s.round, c.servers - s.server)
decreasing_by
  · exact Prod.Lex.right _ (by omega)
  · exact Prod.Lex.left _ _ (by omega)

/-- The same server asked again, `t`, over a stream or not: a retry of the query (§5's table).
When that server has had its queries for the name over that transport, the lookup does not ask it
again. It keeps `w`, the reply that asked for the retry, as the cause when that reply has one, and
moves to the next server (RFC 9520 §3.1; §16 decision 58). -/
def retry (c : Config) (s t : State) (stream : Bool) (w : Option What) : State :=
  if spent s stream then advanceServer c (match w with | some w => keep s w | none => s) else t

/-- The next search candidate, which starts the walk over the servers again, then failure
(§5, search list policy). -/
def nextCandidate (c : Config) (s : State) (noData : Bool) : State :=
  let t := { s with hadNoData := s.hadNoData || noData }
  if t.candidate + 1 < c.candidates then
    { t with candidate := t.candidate + 1, server := 0, round := 0, hops := 0, stage := fresh c,
             edns := true, cookieRetried := false, offered := false, datagrams := unsent c,
             streams := unsent c, openDatagrams := unsent c, openStreams := unsent c, asks := 0 }
  else
    fail t (if t.hadNoData then .noData else .nameNotFound)

/-- A reply to a lookup that is waiting for one, over UDP or over a stream (§5's table). -/
def onReply (c : Config) (s : State) (stream : Bool) : Reply → State × Out
  | .unmatched => (s, .ignored)
  -- TC=1 sends a datagram's server to TCP. On a stream the bit means nothing and the message is
  -- read as if it were clear: NOERROR with no records, which is NODATA.
  | .truncated =>
    if stream then (nextCandidate c s true, .accepted)
    else (retry c s { s with stage := .tcpNeeded } true none, .accepted)
  | .answer => ({ s with stage := .done }, .accepted)
  | .cname =>
    if s.hops + 1 > c.hopsMax then (fail s .chainTooLong, .accepted)
    else ({ s with hops := s.hops + 1, stage := fresh c, datagrams := unsent c,
                   streams := unsent c, openDatagrams := unsent c, openStreams := unsent c,
                   asks := 0 }, .accepted)
  | .nxdomain => (nextCandidate c s false, .accepted)
  | .nodata => (nextCandidate c s true, .accepted)
  -- Each server applies the same DNAME, so the lookup ends: no next server and no next candidate
  -- (§16 decision 57).
  | .yxdomain => (fail s .nameTooLong, .accepted)
  | .servfail => (advanceServer c (keep s .servfail), .accepted)
  -- FORMERR to a query without EDNS0 is the server failing, as SERVFAIL is. Under validation
  -- EDNS0 is never turned off, so FORMERR fails the server at once (docs/design.md §25, Stage B
  -- rule 4).
  | .formerr =>
    if s.edns && !c.validate then (retry c s { s with edns := false, stage := fresh c } c.useTcp (some .formerr),
                    .accepted)
    else (advanceServer c (keep s .formerr), .accepted)
  -- Once more with the cookie just learned (RFC 7873 §5.3), over the transport the lookup is on:
  -- the server's one retry, whichever transport takes it. Again over UDP, then over TCP; again
  -- over a stream, the server has failed. A query over DoH or DoQ carries no cookie, so there is
  -- none to retry with, and the server has failed at once (docs/design.md §19 step 10).
  | .badcookie =>
    if stream then
      if c.request || s.cookieRetried then (advanceServer c (keep s .badcookie), .accepted)
      else (retry c s { s with cookieRetried := true, stage := .tcpNeeded } true (some .badcookie),
            .accepted)
    else if s.cookieRetried then
      (retry c s { s with stage := .tcpNeeded } true (some .badcookie), .accepted)
    else
      (retry c s { s with cookieRetried := true, stage := fresh c } c.useTcp (some .badcookie),
        .accepted)

end Spec.Lookup
