import Spec.Lookup

/-!
# The engine's streams

The engine of docs/design.md §19 step 13 under every query over TCP, written from the stream's
rules there and from rotor's decision 5, never from the Zig source (spec/README.md). Each lookup
is the model of `Spec.Lookup`; around them sit the table's slots, its free list and its ready
list (§11), the connections, and the operations the loop holds.

Time moves in ticks, each the idle close's wait, and only when the caller says it passes or a
deadline arrives; every other event comes at the instant of the one before it. A lookup waits
`timeoutTicks` ticks, and the model keeps how many it has left, and whether each connection went
idle at the current instant, and nothing more of the clock. It also leaves out the bytes of a
message (a reply is what the table makes of it), the datagram path, the timer, and the cache,
which no lookup here asks twice.
-/
namespace Spec.Engine

abbrev LState := Spec.Lookup.State

inductive Stage where
  | closed | connecting | up
  deriving DecidableEq, Repr, Inhabited, Hashable

structure Conn where
  stage : Stage := .closed
  /-- The configured server it goes to. -/
  server : Nat := 0
  users : Nat := 0
  /-- Whether it went idle, or came up, at the current instant: the idle close spares it. An
  instant lasts until time next moves (`tick`). -/
  idleNow : Bool := false
  deriving DecidableEq, Repr, Inhabited, Hashable

inductive OpKind where
  | connect | receive | send
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- An operation the loop holds. `current` is whether the engine still expects it: for a connect
or a receive, whether its incarnation is still the slot's (rule 2); for a send, whether the
attempt that made it is still the lookup's (rule 7). -/
structure Op where
  kind : OpKind
  /-- The connection slot of a connect or a receive, the table slot of a send. -/
  target : Nat
  current : Bool
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
  deriving DecidableEq, Repr, Hashable

structure Config where
  servers : Nat
  slots : Nat
  conns : Nat
  /-- The polls one drive makes at most, as the code bounds it. -/
  pollsMax : Nat
  /-- The ticks a lookup waits for its server. -/
  timeoutTicks : Nat
  deriving Repr

def lookupConfig (c : Config) : Spec.Lookup.Config :=
  { servers := c.servers, attempts := 1, candidates := 1, hopsMax := 8, useTcp := true }

/-- What the table makes of one message on a stream. -/
inductive Reply where
  | answer | servfail | nxdomain | unmatched
  deriving DecidableEq, Repr, Inhabited, Hashable

def Reply.toLookup : Reply → Spec.Lookup.Reply
  | .answer => .answer | .servfail => .servfail | .nxdomain => .nxdomain
  | .unmatched => .unmatched

/-- How an operation ends, as rotor decision 5, rule 2 allows it to. -/
inductive Outcome where
  | ok | failed | canceled
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
  deriving DecidableEq, Repr, Inhabited, Hashable

def init (c : Config) : State :=
  { slots := List.replicate c.slots {}, conns := List.replicate c.conns {}, ops := [],
    ready := [], free := List.range c.slots, results := [], lastTaken := none,
    failures := List.replicate c.servers 0 }

/-! ## Small helpers over lists by position -/

def slotAt (s : State) (l : Nat) : Slot := s.slots.getD l {}
def connAt (s : State) (k : Nat) : Conn := s.conns.getD k {}
def setSlot (s : State) (l : Nat) (f : Slot → Slot) : State :=
  { s with slots := s.slots.set l (f (slotAt s l)) }
def setConn (s : State) (k : Nat) (f : Conn → Conn) : State :=
  { s with conns := s.conns.set k (f (connAt s k)) }

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
      if op.kind = .send ∧ op.target = l then { op with current := false } else op }

/-- One event on one lookup, through the table: the lookup moves, the servers learn what it
says of them, the lookup's wait follows it, and the table settles it. -/
def lookupEvent (c : Config) (s : State) (l : Nat) (e : Spec.Lookup.Event) : State × Spec.Lookup.Out :=
  match (slotAt s l).lookup with
  | none => (s, .none)
  | some lk =>
    let server := serverOf s l
    let (lk', out) := Spec.Lookup.step (lookupConfig c) lk e
    let s := match e with
      | .sendFailed => if lk.stage = .tcpReady then recordFailure s server else s
      | .tcpFailed => if onStream lk.stage then recordFailure s server else s
      | .expire => if waiting lk.stage then recordFailure s server else s
      | .reply r => if out = .accepted ∧ r ≠ .unmatched then recordSuccess s server else s
      | _ => s
    let s := setSlot s l (fun slot => { slot with lookup := some lk' })
    let rearmed := out = .connectTcp ∨ (e = .sent ∧ lk'.stage = .awaitingTcp)
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
      if op.kind ≠ .send ∧ op.target = k then { op with current := false } else op }

def shut (s : State) (k : Nat) : State :=
  setConn (cancelOps s k) k (fun _ => {})

/-- The lookup leaves its connection (rules 3 and 4). -/
def release (s : State) (l : Nat) : State :=
  match (slotAt s l).conn with
  | none => s
  | some k =>
    let s := setSlot s l (fun slot => { slot with conn := none })
    setConn s k fun conn =>
      let users := conn.users - 1
      { conn with users, idleNow := conn.idleNow || users = 0 }

def firstIndex (xs : List α) (p : α → Bool) : Option Nat :=
  (List.range xs.length).find? fun i => match xs[i]? with
    | some x => p x
    | none => false

/-- A slot for a new connection: the first closed one, or else the first nobody uses, closed to
make room (rule 1). -/
def freeConn (s : State) : Option Nat × State :=
  match firstIndex s.conns (·.stage = .closed) with
  | some k => (some k, s)
  | none =>
    match firstIndex s.conns (·.users = 0) with
    | some k => (some k, shut s k)
    | none => (none, s)

def openConn (s : State) (server : Nat) : Option Nat × State :=
  match freeConn s with
  | (none, s) => (none, s)
  | (some k, s) =>
    let s := setConn s k fun _ => { stage := .connecting, server }
    (some k, { s with ops := s.ops ++ [{ kind := .connect, target := k, current := true }] })

def findConn (s : State) (server : Nat) : Option Nat :=
  firstIndex s.conns fun conn => conn.stage ≠ .closed ∧ conn.server = server

/-- The lookup asks for a stream to its server (rule 1). -/
def want (c : Config) (s : State) (l : Nat) : State :=
  let server := serverOf s l
  let (at?, s) := match (slotAt s l).conn with
    | some k => (some k, s)
    | none =>
      match findConn s server with
      | some k => (some k, s)
      | none => openConn s server
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

/-- Closes every connection nobody has used since before this instant (rule 4). -/
def closeIdle (s : State) : State :=
  (List.range s.conns.length).foldl (fun s k =>
    let conn := connAt s k
    if conn.stage ≠ .closed ∧ conn.users = 0 ∧ ¬conn.idleNow then shut s k else s) s

/-! ## Sends -/

def submitSend (s : State) (l : Nat) : State :=
  let s := setSlot s l (fun slot => { slot with busy := true })
  { s with ops := s.ops ++ [{ kind := .send, target := l, current := true }] }

/-- The lookup's query goes out on its connection, or waits for the buffer (rule 6). -/
def send (c : Config) (s : State) (l : Nat) : State :=
  let slot := slotAt s l
  if slot.busy then setSlot s l (fun slot => { slot with held := true, heldCurrent := true }) else
  match slot.conn with
  | some k => if (connAt s k).stage = .up then submitSend s l else tableEvent c s l .tcpFailed
  | none => tableEvent c s l .tcpFailed

end Spec.Engine
