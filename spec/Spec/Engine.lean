import Spec.Lookup

/-!
# The engine

The engine of docs/design.md §19 step 13, written from the stream's rules and the datagram's
rules there, the TLS rules of §21, and rotor's decision 5, never from the Zig source
(spec/README.md). Each lookup is the model of `Spec.Lookup`; around them sit the table's slots,
its free list and its ready list (§11), the connections, the sockets, and the operations the loop
holds. A configuration asks every query over TCP, every query over TLS, or every query over UDP
with no answer truncated. A TLS session is abstracted to the records it makes and the steps its
handshake takes, and the model counts no octet of either.

Time moves in ticks, each the idle close's wait, and only when the caller says it passes or a
deadline arrives; every other event comes at the instant of the one before it. A lookup waits
`timeoutTicks` ticks, and the model keeps how many it has left, and whether each connection went
idle at the current instant, and nothing more of the clock. It also leaves out the bytes of a
message (a reply is what the table makes of it), the datagram path, the timer, and the cache,
which no lookup here asks twice.
-/
namespace Spec.Engine

abbrev LState := Spec.Lookup.State

/-- A connection's life. Over TLS it handshakes between its connect and its first query, and an
idle one closes after its `close_notify` has gone (§21, TLS rules 1 and 5). One whose resumed
handshake failed waits, its lookups still on it, to connect again in full once the loop gives its
slot back (TLS rule 8). -/
inductive Stage where
  | closed | connecting | handshaking | up | closing | reopening
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- What waits to go out on a stream: a lookup's query, or records the TLS session made of its own
accord, which are sealed when made (§21, TLS rule 2). -/
inductive Entry where
  | query (l : Nat)
  | records
  deriving DecidableEq, Repr, Inhabited, Hashable

def Entry.isQuery : Entry → Bool
  | .query _ => true | .records => false

structure Conn where
  stage : Stage := .closed
  /-- The configured server it goes to. -/
  server : Nat := 0
  users : Nat := 0
  /-- Whether it went idle, or came up, at the current instant: the idle close spares it. An
  instant lasts until time next moves (`tick`). -/
  idleNow : Bool := false
  /-- What waits to go out on it, oldest first; the head's is the one send in flight (the
  stream's rule 9). -/
  queue : List Entry := []
  /-- How many entries at the front of the queue are sealed: the head once it is in flight, and
  the records the session made after it (§21, TLS rule 2). -/
  sealed : Nat := 0
  /-- Whether some of the head's message went out and not all: its rest is in flight. -/
  partSent : Bool := false
  /-- Whether the session was given something it must answer and has not sealed the answer: a
  flight, the handshake's end, a KeyUpdate. Nothing leaves an event owing (§21, TLS rule 2). -/
  owes : Bool := false
  /-- Whether this opening resumes with a ticket rather than handshaking in full (TLS rule 8). -/
  resumed : Bool := false
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- A stream's connect, receive and send; a datagram's send and a socket's receive; and a TLS
session's records sent from the connection's own buffer. -/
inductive OpKind where
  | connect | receive | send | sendTo | receiveFrom | sendRecords
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- An operation the loop holds. `current` is whether the engine still expects it: for a connect
or a receive, whether its incarnation or generation is still its connection's or its socket's
(the stream's rule 2, the datagram's rule 2); for a send, whether the attempt that made it is
still the lookup's (rule 7). -/
structure Op where
  kind : OpKind
  /-- The connection slot of a connect, a stream's receive or a send of records, the server of a
  socket's receive, the table slot of a send. -/
  target : Nat
  current : Bool
  /-- For a socket's receive: whether it is the draining socket's (the datagram's rule 4). -/
  draining : Bool := false
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- A server's sockets (the datagram's rules 1 and 4): the one every query leaves from, and
whether an older one drains beside it. -/
structure Sock where
  /-- The queries the current port has carried. -/
  sent : Nat := 0
  /-- The current port has carried its share, and is replaced as soon as no older one drains. -/
  retiring : Bool := false
  /-- An older socket drains, keeping its receive for the answers to its queries. -/
  draining : Bool := false
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- Which of its server's sockets a slot's last datagram left from, as that socket stands now. -/
inductive Age where
  | current | draining | gone
  deriving DecidableEq, Repr, Inhabited, Hashable

structure Slot where
  lookup : Option LState := none
  /-- The configured server at each position of the lookup's walk, fixed at its first poll;
  empty before it. -/
  order : List Nat := []
  conn : Option Nat := none
  /-- The send buffer is lent to the loop (rule 6). -/
  busy : Bool := false
  /-- A send is held until the buffer comes back (rule 6). -/
  held : Bool := false
  /-- Whether the attempt that asked for the held send is still the lookup's: when the buffer
  comes back, a held send goes out if it is, and is dropped if not (rule 6). -/
  heldCurrent : Bool := false
  reported : Bool := false
  /-- Its deadline has come, and its next poll is the expiry. -/
  expired : Bool := false
  /-- The ticks left before its deadline, while it waits; zero while it does not. -/
  remaining : Nat := 0
  /-- The server and the socket its last datagram left from. It outlives the lookup, because a
  send in flight from a freed slot still holds the socket open. -/
  sentFrom : Option (Nat × Age) := none
  deriving DecidableEq, Repr, Inhabited, Hashable

structure State where
  slots : List Slot
  conns : List Conn
  /-- The loop's operations, oldest first. -/
  ops : List Op
  /-- The table's ready list, oldest first (§11). -/
  ready : List Nat
  /-- The table's free slots, the next to be taken first. -/
  free : List Nat
  /-- The ends reported and not yet taken, oldest first. -/
  results : List Nat
  /-- The slot of the result handed out last, freed at the next take. -/
  lastTaken : Option Nat
  /-- Each configured server's consecutive failures (§19 step 12). -/
  failures : List Nat
  socks : List Sock
  /-- The loop refuses every submission during the next event, as a full ring does. -/
  jammed : Bool
  /-- Every socket the engine opens during the next event fails to open. -/
  starved : Bool
  /-- Whether each configured server has a ticket kept for its next connection (TLS rule 8). -/
  tickets : List Bool
  deriving DecidableEq, Repr, Hashable

structure Config where
  servers : Nat
  slots : Nat
  conns : Nat
  /-- The polls one drive makes at most, as the code bounds it. -/
  pollsMax : Nat
  /-- The ticks a lookup waits for its server. -/
  timeoutTicks : Nat
  /-- Every query over TCP, or every query over UDP. -/
  useTcp : Bool
  /-- `udp_queries_per_port`: the queries a port carries before it is replaced; zero for never. -/
  perPort : Nat
  /-- Every server speaks TLS, so every query goes on a stream (§21). -/
  tls : Bool := false
  deriving Repr

def lookupConfig (c : Config) : Spec.Lookup.Config :=
  { servers := c.servers, attempts := 1, candidates := 1, hopsMax := 8, useTcp := c.useTcp || c.tls }

/-- What the table makes of one message on a stream. -/
inductive Reply where
  | answer | servfail | nxdomain | unmatched
  deriving DecidableEq, Repr, Inhabited, Hashable

def Reply.toLookup : Reply → Spec.Lookup.Reply
  | .answer => .answer | .servfail => .servfail | .nxdomain => .nxdomain
  | .unmatched => .unmatched

/-- How an operation ends, as rotor decision 5, rule 2 allows it to. A receive also ends when
its group has no buffer left, which is not a broken connection. -/
inductive Outcome where
  | ok | failed | canceled | exhausted
  /-- A send that moved some of its bytes and not all (rotor: "may be fewer than the buffer
  holds"). -/
  | short
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- What the session makes of the records a TLS connection receives: during the handshake, a
flight to answer, the handshake's end with the client's last flight, or a failure (a record it
refuses, a certificate or a name that does not verify); once up, a KeyUpdate to answer, or a
ticket for the next connection. -/
inductive TlsStep where
  | flight | done | failed | rekey | ticket
  deriving DecidableEq, Repr, Inhabited, Hashable

inductive Event where
  | start
  | take
  | cancel (slot : Nat)
  /-- Time passes to the soonest deadline. -/
  | expire
  /-- One tick passes: the idle close's wait. -/
  | idle
  /-- The operation at this position in `ops` ends. -/
  | finish (op : Nat) (outcome : Outcome)
  /-- A message on the receive at this position, for the lookup in `slot`. -/
  | message (op : Nat) (slot : Nat) (reply : Reply)
  /-- A datagram or a chunk on a receive that is gone, before its end (rotor decision 5,
  rule 2): the receive stays. -/
  | straggle (op : Nat)
  /-- The session's step on the records the receive at this position brought. -/
  | tls (op : Nat) (step : TlsStep)
  /-- The ticket kept for this server reaches its lifetime, or 7 days (TLS rule 8). -/
  | lapse (server : Nat)
  /-- The loop refuses every submission during the next event. -/
  | jam
  /-- Every socket open fails during the next event. -/
  | starve
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- A socket per server, each with its receive armed, server by server; none over TLS, which asks
nothing of a datagram (§21, TLS rule 9). -/
def init (c : Config) : State :=
  let sockets := if c.tls then 0 else c.servers
  { slots := List.replicate c.slots {}, conns := List.replicate c.conns {},
    ops := (List.range sockets).map fun v => { kind := .receiveFrom, target := v, current := true },
    ready := [], free := List.range c.slots, results := [], lastTaken := none,
    failures := List.replicate c.servers 0, socks := List.replicate sockets {},
    jammed := false, starved := false, tickets := List.replicate c.servers false }

/-! ## Small helpers over lists by position -/

def slotAt (s : State) (l : Nat) : Slot := s.slots.getD l {}
def connAt (s : State) (k : Nat) : Conn := s.conns.getD k {}
def setSlot (s : State) (l : Nat) (f : Slot → Slot) : State :=
  { s with slots := s.slots.set l (f (slotAt s l)) }
def setConn (s : State) (k : Nat) (f : Conn → Conn) : State :=
  { s with conns := s.conns.set k (f (connAt s k)) }
def sockAt (s : State) (v : Nat) : Sock := s.socks.getD v {}
def setSock (s : State) (v : Nat) (f : Sock → Sock) : State :=
  { s with socks := s.socks.set v (f (sockAt s v)) }

def isSend (kind : OpKind) : Bool := kind = .send ∨ kind = .sendTo

def waiting (st : Spec.Lookup.Stage) : Bool := Spec.Lookup.waiting st
def onStream (st : Spec.Lookup.Stage) : Bool := Spec.Lookup.onStream st

/-- The configured server a slot's lookup is asking now. -/
def serverOf (s : State) (l : Nat) : Nat :=
  let slot := slotAt s l
  match slot.lookup with
  | some lk => slot.order.getD lk.server 0
  | none => 0

/-! ## The table -/

/-- Puts a slot at the back of the ready list, unless it is on it already. -/
def offer (s : State) (l : Nat) : State :=
  if s.ready.contains l then s else { s with ready := s.ready ++ [l] }

/-- What an event leaves behind: a lookup with something to do goes on the ready list. -/
def settle (s : State) (l : Nat) : State :=
  match (slotAt s l).lookup with
  | some lk => if waiting lk.stage then s else offer s l
  | none => s

/-- The lookup no longer waits. -/
def unwait (s : State) (l : Nat) : State :=
  setSlot s l (fun slot => { slot with remaining := 0 })

/-- The lookup began a wait at this instant: its whole timeout is ahead of it. -/
def arm (c : Config) (s : State) (l : Nat) : State :=
  setSlot s l (fun slot => { slot with remaining := c.timeoutTicks })

def recordFailure (s : State) (server : Nat) : State :=
  { s with failures := s.failures.set server (min 255 (s.failures.getD server 0 + 1)) }

def recordSuccess (s : State) (server : Nat) : State :=
  { s with failures := s.failures.set server 0 }

/-- The servers sorted by their failures, stably, so equals keep the configured order: insertion
sort, as the code sorts (§19 step 12, with rotation and the retry promotion off). -/
def sortByFailures (failures : List Nat) (n : Nat) : List Nat :=
  let key (i : Nat) := failures.getD i 0
  let insert (i : Nat) (sorted : List Nat) : List Nat :=
    let (before, after) := sorted.span (fun j => key j ≤ key i)
    before ++ i :: after
  (List.range n).foldl (fun sorted i => insert i sorted) []

/-- The attempt a lookup is on: what changes when it draws a new transaction. -/
def attempt (lk : LState) : Nat × Nat × Nat × Nat × Bool × Bool :=
  (lk.server, lk.round, lk.candidate, lk.hops, lk.edns, lk.cookieRetried)

/-- The lookup moved on: its send in flight speaks for nobody, and a send it held is to be
dropped when the buffer comes back (rules 6 and 7). -/
def forgetAttempt (s : State) (l : Nat) : State :=
  let s := setSlot s l (fun slot => { slot with heldCurrent := false })
  { s with ops := s.ops.map fun op =>
      if isSend op.kind ∧ op.target = l then { op with current := false } else op }

/-- One event on one lookup, through the table: the lookup moves, the servers learn what it
says of them, the lookup's wait follows it, and the table settles it. -/
def lookupEvent (c : Config) (s : State) (l : Nat) (e : Spec.Lookup.Event) : State × Spec.Lookup.Out :=
  match (slotAt s l).lookup with
  | none => (s, .none)
  | some lk =>
    let server := serverOf s l
    let (lk', out) := Spec.Lookup.step (lookupConfig c) lk e
    let s := match e with
      | .sendFailed =>
        if lk.stage = .tcpReady ∨ lk.stage = .queryReady then recordFailure s server else s
      | .tcpFailed => if onStream lk.stage then recordFailure s server else s
      | .expire => if waiting lk.stage then recordFailure s server else s
      | .reply r => if out = .accepted ∧ r ≠ .unmatched then recordSuccess s server else s
      | _ => s
    let s := setSlot s l (fun slot => { slot with lookup := some lk' })
    let rearmed := out = .connectTcp ∨
      (e = .sent ∧ (lk'.stage = .awaitingTcp ∨ lk'.stage = .awaitingUdp))
    let s := if waiting lk'.stage ∧ ¬rearmed then s else
      setSlot s l (fun slot => { slot with expired := false })
    let s := if waiting lk'.stage then (if rearmed then arm c s l else s) else unwait s l
    -- A new transaction, or an end: the attempt's send speaks for nobody (rule 7).
    let s := if attempt lk' ≠ attempt lk ∨ Spec.Lookup.ended lk'.stage then forgetAttempt s l
      else s
    (s, out)

/-- `lookupEvent` for the events the table settles after: every one but a poll. -/
def tableEvent (c : Config) (s : State) (l : Nat) (e : Spec.Lookup.Event) : State :=
  settle (lookupEvent c s l e).1 l

/-! ## The connections -/

/-- Every current operation of a connection slot is left to the loop to end: it is cancelled,
and its event, whenever it comes, names an incarnation that is gone (rule 2). -/
def cancelOps (s : State) (k : Nat) : State :=
  { s with ops := s.ops.map fun op =>
      if (op.kind = .connect ∨ op.kind = .receive ∨ op.kind = .sendRecords) ∧ op.target = k then
        { op with current := false }
      else op }

/-- Whether a send of slot `l`'s buffer is in flight. -/
def sending (s : State) (l : Nat) : Bool := s.ops.any fun op => isSend op.kind ∧ op.target = l

/-- Whether connection `k`'s current incarnation has a send of its records in flight. -/
def recordsInFlight (s : State) (k : Nat) : Bool :=
  s.ops.any fun op => op.kind = .sendRecords ∧ op.target = k ∧ op.current

/-- Whether connection `k` has its one send in flight: its head's (the stream's rule 9). -/
def inFlight (s : State) (k : Nat) : Bool :=
  match (connAt s k).queue.head? with
  | some (.query l) => sending s l
  | some .records => recordsInFlight s k
  | none => false

/-- The queries waiting on connection `k`, by slot. -/
def queued (s : State) (k : Nat) : List Nat :=
  (connAt s k).queue.filterMap fun
    | .query l => some l
    | .records => none

/-- Closes connection `k`. A query in its queue that is not being sent gives its buffer back; the
one in flight keeps it until its send's final event. -/
def shut (s : State) (k : Nat) : State :=
  let s := (queued s k).foldl (fun s l =>
    if sending s l then s else setSlot s l (fun slot => { slot with busy := false })) s
  setConn (cancelOps s k) k (fun _ => {})

/-- The lookup leaves its connection (rules 3 and 4). A query of its that waits in the queue and
has not started goes with it, and gives its buffer back (rule 9). -/
def release (s : State) (l : Nat) : State :=
  match (slotAt s l).conn with
  | none => s
  | some k =>
    let s := setSlot s l (fun slot => { slot with conn := none })
    let waiting := (connAt s k).queue.contains (.query l) ∧ ¬sending s l
    let s := if waiting then setSlot s l (fun slot => { slot with busy := false }) else s
    setConn s k fun conn =>
      let users := conn.users - 1
      { conn with users, idleNow := conn.idleNow || users = 0,
                  queue := if waiting then conn.queue.filter (· ≠ .query l) else conn.queue }

def firstIndex (xs : List α) (p : α → Bool) : Option Nat :=
  (List.range xs.length).find? fun i => match xs[i]? with
    | some x => p x
    | none => false

/-- Whether the loop still holds memory of slot `k`'s, of whichever incarnation: the address a
connect borrows, or the records a send of the session's borrows, until its final event (rule 10,
and §21's TLS rule 3). -/
def borrowed (s : State) (k : Nat) : Bool :=
  s.ops.any fun op => (op.kind = .connect ∨ op.kind = .sendRecords) ∧ op.target = k

/-- A slot for a new connection: the first closed one, or else the first nobody uses, closed to
make room (rule 1); never one whose memory the loop still borrows (rule 10). A TLS connection is
never closed to make room (§21, TLS rule 6). -/
def freeConn (c : Config) (s : State) : Option Nat × State :=
  let ks := List.range s.conns.length
  match ks.find? fun k => (connAt s k).stage = .closed ∧ ¬borrowed s k with
  | some k => (some k, s)
  | none =>
    if c.tls then (none, s) else
    match ks.find? fun k => (connAt s k).users = 0 ∧ ¬borrowed s k with
    | some k => (some k, shut s k)
    | none => (none, s)

/-- Opens a connection to `server` in a free slot: its socket, then its connect, either of
which the moment may refuse. Over TLS it resumes with the server's ticket when one is kept, and
spends it: a ticket is used once (TLS rule 8). -/
def openConn (c : Config) (s : State) (server : Nat) : Option Nat × State :=
  match freeConn c s with
  | (none, s) => (none, s)
  | (some k, s) =>
    if s.starved ∨ s.jammed then (none, s) else
    let resumed := c.tls ∧ s.tickets.getD server false
    let s := { s with tickets := if resumed then s.tickets.set server false else s.tickets }
    let s := setConn s k fun _ => { stage := .connecting, server, resumed }
    (some k, { s with ops := s.ops ++ [{ kind := .connect, target := k, current := true }] })

/-- The connection to `server` a lookup may join: not one that is closing (§21, TLS rule 5). -/
def findConn (s : State) (server : Nat) : Option Nat :=
  firstIndex s.conns fun conn => conn.stage ≠ .closed ∧ conn.stage ≠ .closing ∧ conn.server = server

/-- The lookup asks for a stream to its server (rule 1). -/
def want (c : Config) (s : State) (l : Nat) : State :=
  let server := serverOf s l
  let (at?, s) := match (slotAt s l).conn with
    | some k => (some k, s)
    | none =>
      match findConn s server with
      | some k => (some k, s)
      | none => openConn c s server
  match at? with
  | none => tableEvent c s l .tcpFailed
  | some k =>
    let s := if (slotAt s l).conn = some k then s else
      let s := setSlot s l (fun slot => { slot with conn := some k })
      setConn s k (fun conn => { conn with users := conn.users + 1 })
    if (connAt s k).stage = .up then tableEvent c s l .tcpConnected else s

/-- Tells every lookup on the connection, slot by slot, that it is up or that it failed. -/
def tellAll (c : Config) (s : State) (k : Nat) (connected : Bool) : State :=
  (List.range c.slots).foldl (fun s l =>
    let slot := slotAt s l
    match slot.lookup with
    | some lk =>
      if slot.conn = some k ∧ onStream lk.stage then
        tableEvent c s l (if connected then .tcpConnected else .tcpFailed)
      else s
    | none => s) s

/-- The connection is no good: every lookup on it is told, and leaves it, and it is closed. -/
def failConn (c : Config) (s : State) (k : Nat) : State :=
  let s := tellAll c s k false
  let s := { s with slots := s.slots.map fun slot =>
    if slot.conn = some k then { slot with conn := none } else slot }
  shut s k


end Spec.Engine
