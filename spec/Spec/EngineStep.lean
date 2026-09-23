import Spec.Engine

/-!
# The engine's drive, its events, and what must hold

The second half of the engine model of `Spec.Engine`: the drive that polls the table and acts on
what each lookup wants, the events the caller and the loop deliver, the events they may deliver
in each state, and the invariants every reachable state must keep. Split from `Spec/Engine.lean`
by the file-length rule.
-/
namespace Spec.Engine

/-! ## The drive -/

def report (s : State) (l : Nat) : State × Bool :=
  if (slotAt s l).reported then (s, false) else
  let s := setSlot s l (fun slot => { slot with reported := true })
  let s := release s l
  ({ s with results := s.results ++ [l] }, true)

/-- What the drive does with one lookup's poll. Returns whether the lookup moved on. -/
def act (c : Config) (s : State) (l : Nat) (out : Spec.Lookup.Out) : State × Bool :=
  -- Rule 3: off the connection unless it streams to that connection's server.
  let s := match (slotAt s l).conn, (slotAt s l).lookup with
    | some k, some lk =>
      if onStream lk.stage ∧ (connAt s k).server = serverOf s l then s else release s l
    | _, _ => s
  match out with
  | .connectTcp => (want c s l, true)
  | .sendTcp => (send c s l, true)
  | .done | .failed _ => report s l
  | _ => (s, true)

/-- One poll of the lookup at the head of the ready list: its order fixed at its first poll, its
expiry if its deadline came, and the table's answer. -/
def pollOne (c : Config) (s : State) (l : Nat) : State × Spec.Lookup.Out :=
  let slot := slotAt s l
  match slot.lookup with
  | none => (s, .none)
  | some lk =>
    let s := if slot.order = [] ∧ ¬Spec.Lookup.ended lk.stage then
      setSlot s l (fun slot => { slot with order := sortByFailures s.failures c.servers }) else s
    let e : Spec.Lookup.Event := if slot.expired ∧ waiting lk.stage then .expire else .poll
    let s := setSlot s l (fun slot => { slot with expired := false })
    lookupEvent c s l e

/-- Polls the table until nothing is left to do or the bound is reached, as the code's drive
does. -/
def drive (c : Config) (s : State) : State :=
  let rec go (fuel polls refused : Nat) (s : State) : State :=
    match fuel with
    | 0 => s
    | fuel + 1 =>
      if polls ≥ c.pollsMax ∨ refused > (s.slots.filter (·.lookup.isSome)).length then s else
      match s.ready with
      | [] => s
      | l :: rest =>
        let s := { s with ready := rest }
        let (s, out) := pollOne c s l
        if out = .wait then go fuel polls refused s else
        let (s, moved) := act c s l out
        go fuel (polls + 1) (if moved then 0 else refused + 1) s
  go (4 * c.slots * (c.servers + 2) + 8) 0 0 s

/-! ## Events -/

def removeOp (s : State) (i : Nat) : State := { s with ops := s.ops.eraseIdx i }

/-- A send ended: the buffer comes back, the attempt that made it hears how it went if it is
still the lookup's, and a held send goes out (rules 6 and 7). -/
def sendEnded (c : Config) (s : State) (i : Nat) (op : Op) (ok : Bool) : State :=
  let l := op.target
  let s := removeOp s i
  let s := setSlot s l (fun slot => { slot with busy := false })
  let s := if op.current then tableEvent c s l (if ok then .sent else .sendFailed) else s
  let slot := slotAt s l
  let s := setSlot s l (fun slot => { slot with held := false, heldCurrent := false })
  if slot.held ∧ slot.heldCurrent then send c s l else s

def connectEnded (c : Config) (s : State) (i : Nat) (op : Op) (ok : Bool) : State :=
  let k := op.target
  let s := removeOp s i
  if ¬op.current then s else
  if ok then
    let s := setConn s k (fun conn => { conn with stage := .up, idleNow := true })
    let s := { s with ops := s.ops ++ [{ kind := .receive, target := k, current := true }] }
    tellAll c s k true
  else failConn c s k

def receiveEnded (c : Config) (s : State) (i : Nat) (op : Op) : State :=
  let s := removeOp s i
  if op.current then failConn c s op.target else s

/-- A message on a stream, which the table hands to the lookup it is for; an accepted one
settles it. -/
def message (c : Config) (s : State) (l : Nat) (r : Reply) : State :=
  let (s, out) := lookupEvent c s l (.reply r.toLookup)
  if out = .accepted then settle s l else s

/-- The ticks to the soonest deadline, when a lookup waits. -/
def soonest (s : State) : Option Nat :=
  s.slots.foldl (fun best slot =>
    match slot.lookup with
    | some lk =>
      if waiting lk.stage then some (match best with | some b => min b slot.remaining | none => slot.remaining)
      else best
    | none => best) none

/-- `ticks` pass. Every lookup whose deadline they reach is offered, slot by slot, as the table
offers the lookups whose wait has run out (§11). -/
def pass (c : Config) (s : State) (ticks : Nat) : State :=
  (List.range c.slots).foldl (fun s l =>
    let slot := slotAt s l
    match slot.lookup with
    | some lk =>
      if ¬waiting lk.stage then s else
      let left := slot.remaining - ticks
      let s := setSlot s l (fun slot => { slot with remaining := left })
      if left = 0 then offer (setSlot s l (fun slot => { slot with expired := true })) l else s
    | none => s) s

def start (s : State) (c : Config) : State :=
  match s.free with
  | [] => s
  | l :: rest =>
    let s := { s with free := rest }
    let s := setSlot s l fun slot =>
      { slot with lookup := some (Spec.Lookup.init (lookupConfig c)), order := [], conn := none,
                  held := false, heldCurrent := false, reported := false, expired := false }
    offer s l

def take (s : State) : State :=
  let s := match s.lastTaken with
    | some l =>
      let s := { s with ready := s.ready.filter (· ≠ l), free := l :: s.free, lastTaken := none }
      let s := forgetAttempt s l
      setSlot s l (fun slot => { slot with lookup := none, order := [], expired := false })
    | none => s
  match s.results with
  | [] => s
  | l :: rest => { s with results := rest, lastTaken := some l }

/-- Time moves: nothing went idle at the new instant yet. -/
def tick (s : State) : State :=
  { s with conns := s.conns.map ({ · with idleNow := false }) }

/-- One event, and the drive that follows it. -/
def step (c : Config) (s : State) (e : Event) : State :=
  let s := match e with
    | .expire | .idle => tick s
    | _ => s
  match e with
  | .start => drive c (start s c)
  | .take => take s
  | .cancel l => drive c (match (slotAt s l).lookup with
    | some lk => if Spec.Lookup.ended lk.stage then s else tableEvent c s l .cancel
    | none => s)
  | .expire => closeIdle (drive c (pass c s ((soonest s).getD 0)))
  | .idle => closeIdle (drive c (pass c s 1))
  | .finish i outcome =>
    match s.ops[i]? with
    | none => s
    | some op =>
      let ok := outcome = .ok
      drive c <| match op.kind with
        | .send => sendEnded c s i op ok
        | .connect => connectEnded c s i op ok
        | .receive => receiveEnded c s i op
  | .message _ l r => drive c (message c s l r)

/-! ## What the caller and the loop may do -/

/-- The events the environment may deliver: a start while a slot is free, a take while a result
waits, a cancel of a running lookup, the oldest deadline, the idle close when something is idle,
any end of any operation the loop holds as rule 2 allows it, and a message for a lookup whose
query went out on a connection that is up. -/
def enabled (c : Config) (s : State) : List Event :=
  let starts := if s.free ≠ [] then [Event.start] else []
  let takes := if s.results ≠ [] ∨ s.lastTaken.isSome then [Event.take] else []
  let cancels := (List.range c.slots).filterMap fun l =>
    match (slotAt s l).lookup with
    | some lk => if Spec.Lookup.ended lk.stage then none else some (Event.cancel l)
    | none => none
  let expires := if (soonest s).isSome then [Event.expire] else []
  let idles := if s.conns.any (fun conn => conn.stage ≠ .closed ∧ conn.users = 0) then [Event.idle]
    else []
  let finishes := (List.range s.ops.length).flatMap fun i =>
    match s.ops[i]? with
    | some op =>
      if op.current then
        match op.kind with
        | .receive => [Event.finish i .failed]
        | _ => [Event.finish i .ok, Event.finish i .failed]
      else
        match op.kind with
        | .send => [Event.finish i .ok, Event.finish i .failed]
        | _ => [Event.finish i .ok, Event.finish i .failed, Event.finish i .canceled]
    | none => []
  let messages := (List.range s.ops.length).flatMap fun i =>
    match s.ops[i]? with
    | some op =>
      if op.kind = .receive ∧ op.current then
        (List.range c.slots).flatMap fun l =>
          let slot := slotAt s l
          match slot.lookup with
          | some lk =>
            if slot.conn = some op.target ∧ lk.stage = .awaitingTcp then
              [Reply.answer, .servfail, .nxdomain, .unmatched].map (Event.message i l)
            else []
          | none => []
      else []
    | none => []
  starts ++ takes ++ cancels ++ expires ++ idles ++ finishes ++ messages

/-! ## What must hold in every state -/

/-- A connection's users are exactly the lookups on it (rule 4). -/
def usersCounted (s : State) : Bool :=
  (List.range s.conns.length).all fun k =>
    (connAt s k).users = (s.slots.filter (·.conn = some k)).length

/-- A lookup is on a connection that is open, only while it streams to that connection's server,
unless it is on the ready list to be put right at its next poll (rule 3). -/
def attachedRight (s : State) : Bool :=
  (List.range s.slots.length).all fun l =>
    match (slotAt s l).conn with
    | none => true
    | some k =>
      (connAt s k).stage != .closed &&
      (s.ready.contains l ||
        match (slotAt s l).lookup with
        | some lk => onStream lk.stage && (connAt s k).server == serverOf s l
        | none => false)

/-- A slot's buffer is lent to one send at most, and is lent exactly when a send holds it
(rule 6). -/
def buffersLent (s : State) : Bool :=
  (List.range s.slots.length).all fun l =>
    let sends := (s.ops.filter fun op => op.kind == .send && op.target == l).length
    sends ≤ 1 && ((slotAt s l).busy == (sends == 1))

/-- A connection slot has one current operation while it is open and none while it is closed:
the connect while it connects, the receive once it is up (rules 1 and 2). -/
def opsCurrent (s : State) : Bool :=
  (List.range s.conns.length).all fun k =>
    let current := s.ops.filter fun op => op.kind ≠ .send ∧ op.target = k ∧ op.current
    match (connAt s k).stage with
    | .closed => current = []
    | .connecting => current.map (·.kind) = [.connect]
    | .up => current.map (·.kind) = [.receive]

/-- Nothing is left on the ready list when a drive ends: every lookup the events gave something
to do was polled (rule 8). -/
def driveDone (s : State) : Bool := s.ready = []

def invariants (s : State) : List (String × Bool) :=
  [("users counted", usersCounted s), ("attached right", attachedRight s),
   ("buffers lent", buffersLent s), ("ops current", opsCurrent s),
   ("drive done", driveDone s)]

end Spec.Engine
