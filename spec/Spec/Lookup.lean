/-!
# The lookup state machine

`Lookup` of docs/design.md §5, written from the design and never from the Zig source
(spec/CONTRACT.md). A response is abstracted to what §7's checks and §5's rcode policy make of
it; time is abstracted to whether a poll comes before its deadline or at it; the server order of
§19 step 12 is abstracted to a position in it. What the abstraction keeps is every transition of
§5's table, the retry policy, the search-list policy and the CNAME policy.
-/
namespace Spec.Lookup

/-- The eight states of §5. -/
inductive Stage where
  | queryReady | awaitingUdp | tcpNeeded | connectingTcp | tcpReady | awaitingTcp | done | failed
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- How a lookup fails. -/
inductive Err where
  | nameNotFound | noData | timeout | allServersFailed | chainTooLong | canceled | noServers
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
  /-- SERVFAIL, REFUSED or NOTIMP. -/
  | servfail
  | formerr
  /-- TC=1 with NOERROR and no records, which is what a truncated answer over UDP carries. -/
  | truncated
  /-- BADCOOKIE (RFC 7873 §5.3). -/
  | badcookie
  deriving DecidableEq, Repr, Inhabited

/-- What the caller can tell a lookup, and asking it what to do. -/
inductive Event where
  /-- A poll before the deadline. -/
  | poll
  /-- A poll at or past the deadline. -/
  | expire
  | sent
  | sendFailed
  | tcpConnected
  | tcpFailed
  /-- The HTTP exchange of a query over DoH ended without an answer: a status that is not 2xx,
  or the exchange lost (docs/design.md §22). -/
  | httpsFailed
  | reply (r : Reply)
  | cancel
  deriving DecidableEq, Repr, Inhabited

/-- What a lookup answers: an action for a poll, a verdict for a reply, nothing for the rest. -/
inductive Out where
  | sendUdp | connectTcp | sendTcp | sendHttps | wait | done
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
  /-- Every server speaks DoH (docs/design.md §22), which never goes with `useTcp`. -/
  https : Bool := false
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
  /-- Whether a server answered SERVFAIL, REFUSED or NOTIMP, which decides the failure when the
  attempts run out (§5, retry policy). -/
  serverFailed : Bool
  /-- Whether this server already answered BADCOOKIE once and was asked again (RFC 7873 §5.3). -/
  cookieRetried : Bool
  /-- A send was handed out by a poll and the caller has not yet said how it went. -/
  offered : Bool
  err : Err
  deriving DecidableEq, Repr, Hashable

/-- Where a lookup stands before each query: every query over TCP when the configuration says so
(§19 step 11), UDP otherwise. -/
def fresh (c : Config) : Stage := if c.useTcp then .tcpNeeded else .queryReady

def fail (s : State) (e : Err) : State := { s with stage := .failed, err := e, offered := false }

def init (c : Config) : State :=
  let s : State := { stage := fresh c, server := 0, round := 0, candidate := 0, hops := 0,
                     edns := true, hadNoData := false, serverFailed := false,
                     cookieRetried := false, offered := false, err := .timeout }
  if c.servers = 0 then fail s .noServers else s

/-- The next server, then the next pass, then failure (§5, retry policy). EDNS0 is back on: that a
server does not speak it is a fact about that server (RFC 6891 §6.2.2). -/
def advanceServer (c : Config) (s : State) : State :=
  if s.server + 1 < c.servers then
    { s with server := s.server + 1, stage := fresh c, edns := true, cookieRetried := false,
             offered := false }
  else if s.round + 1 < c.attempts then
    { s with server := 0, round := s.round + 1, stage := fresh c, edns := true,
             cookieRetried := false, offered := false }
  else
    fail { s with round := s.round + 1 } (if s.serverFailed then .allServersFailed else .timeout)

/-- The next search candidate, which starts the walk over the servers again, then failure
(§5, search list policy). -/
def nextCandidate (c : Config) (s : State) (noData : Bool) : State :=
  let t := { s with hadNoData := s.hadNoData || noData }
  if t.candidate + 1 < c.candidates then
    { t with candidate := t.candidate + 1, server := 0, round := 0, hops := 0, stage := fresh c,
             edns := true, cookieRetried := false, offered := false }
  else
    fail t (if t.hadNoData then .noData else .nameNotFound)

/-- A reply to a lookup that is waiting for one, over UDP or over a stream (§5's table). -/
def onReply (c : Config) (s : State) (stream : Bool) : Reply → State × Out
  | .unmatched => (s, .ignored)
  -- TC=1 sends a datagram's server to TCP. On a stream the bit means nothing and the message is
  -- read as if it were clear: NOERROR with no records, which is NODATA.
  | .truncated =>
    if stream then (nextCandidate c s true, .accepted)
    else ({ s with stage := .tcpNeeded }, .accepted)
  | .answer => ({ s with stage := .done }, .accepted)
  | .cname =>
    if s.hops + 1 > c.hopsMax then (fail s .chainTooLong, .accepted)
    else ({ s with hops := s.hops + 1, stage := fresh c }, .accepted)
  | .nxdomain => (nextCandidate c s false, .accepted)
  | .nodata => (nextCandidate c s true, .accepted)
  | .servfail => (advanceServer c { s with serverFailed := true }, .accepted)
  -- FORMERR to a query without EDNS0 is the server failing, as SERVFAIL is.
  | .formerr =>
    if s.edns then ({ s with edns := false, stage := fresh c }, .accepted)
    else (advanceServer c { s with serverFailed := true }, .accepted)
  -- Once more with the cookie just learned, then over TCP; over TCP, the server has failed.
  | .badcookie =>
    if stream then (advanceServer c { s with serverFailed := true }, .accepted)
    else if s.cookieRetried then ({ s with stage := .tcpNeeded }, .accepted)
    else ({ s with cookieRetried := true, stage := fresh c }, .accepted)

/-- A poll: the action the lookup wants now. A query over DoH is ready as a datagram is, one
request an attempt, and goes as an HTTP request (docs/design.md §22). -/
def poll (c : Config) (s : State) : State × Out :=
  match s.stage with
  | .queryReady => ({ s with offered := true }, if c.https then .sendHttps else .sendUdp)
  | .tcpNeeded => ({ s with stage := .connectingTcp }, .connectTcp)
  | .tcpReady => ({ s with offered := true }, .sendTcp)
  | .awaitingUdp | .connectingTcp | .awaitingTcp => (s, .wait)
  | .done => (s, .done)
  | .failed => (s, .failed s.err)

def waiting (s : Stage) : Bool :=
  match s with
  | .awaitingUdp | .connectingTcp | .awaitingTcp => true
  | _ => false

def ended (s : Stage) : Bool :=
  match s with
  | .done | .failed => true
  | _ => false

/-- Whether the lookup is on a stream: connecting, ready to send on one, or awaiting its answer. -/
def onStream (s : Stage) : Bool :=
  match s with
  | .connectingTcp | .tcpReady | .awaitingTcp => true
  | _ => false

/-- One event, and what the lookup answers. -/
def step (c : Config) (s : State) : Event → State × Out
  | .poll => poll c s
  | .expire => if waiting s.stage then poll c (advanceServer c s) else poll c s
  | .sent =>
    match s.stage with
    | .queryReady => ({ s with stage := .awaitingUdp, offered := false }, .none)
    | .tcpReady => ({ s with stage := .awaitingTcp, offered := false }, .none)
    | _ => (s, .none)
  | .sendFailed =>
    match s.stage with
    | .queryReady | .tcpReady => (advanceServer c s, .none)
    | _ => (s, .none)
  | .tcpConnected =>
    match s.stage with
    | .connectingTcp => ({ s with stage := .tcpReady }, .none)
    | _ => (s, .none)
  | .tcpFailed => if onStream s.stage then (advanceServer c s, .none) else (s, .none)
  -- An HTTP failure is the server's: the next one (docs/design.md §22).
  | .httpsFailed =>
    if c.https ∧ s.stage = .awaitingUdp then (advanceServer c s, .none) else (s, .none)
  | .reply r =>
    match s.stage with
    -- Over DoH an answer is read as one over a stream: there is nowhere else to ask.
    | .awaitingUdp => onReply c s c.https r
    | .awaitingTcp => onReply c s true r
    | _ => (s, .ignored)
  | .cancel => if ended s.stage then (s, .none) else (fail s .canceled, .none)

/-- The events a caller may deliver to a `Lookup`, by the contract of §4: a poll at any time, a
poll past the deadline while the lookup waits, `on_sent` and `on_send_failed` only for a send a
poll handed out, `on_tcp_connected` while it connects, `on_tcp_failed` while it is on a stream,
`on_https_failed` while it waits on an HTTP exchange, a datagram at any time, and a cancel until
it ends. `Resolver.cancel` takes a cancel after the end
as well, which `step` answers with nothing. -/
def enabled (c : Config) (s : State) : List Event :=
  let replies := [Reply.unmatched, .answer, .cname, .nxdomain, .nodata, .servfail, .formerr,
                  .truncated, .badcookie].map Event.reply
  [Event.poll]
    ++ (if waiting s.stage then [Event.expire] else [])
    ++ (if s.offered then [Event.sent, .sendFailed] else [])
    ++ (if s.stage = .connectingTcp then [Event.tcpConnected] else [])
    ++ (if onStream s.stage then [Event.tcpFailed] else [])
    ++ (if c.https ∧ s.stage = .awaitingUdp then [Event.httpsFailed] else [])
    ++ (if waiting s.stage then replies else [Event.reply .unmatched])
    ++ (if ended s.stage then [] else [Event.cancel])

end Spec.Lookup
