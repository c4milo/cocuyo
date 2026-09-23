import Spec.EngineStep
import Spec.Tokens
import Std.Data.HashSet

/-!
# Walking the engine model

Breadth first from `init`, every event `enabled` allows in every state reached, each state walked
once. Every state reached is checked against `invariants`, and the first that fails one is
reported with the events that lead to it, which breadth first makes a shortest such path.

The walk is bounded: a state whose loop holds more than `opsMax` operations, or whose servers
count more than `failuresMax` failures, is checked but not walked further. Without a bound the
graph is infinite: nothing makes the loop end a cancelled operation soon, and failures count on.
-/
namespace Spec.Engine

structure Bounds where
  opsMax : Nat
  failuresMax : Nat
  sentMax : Nat

def within (b : Bounds) (s : State) : Bool :=
  s.ops.length ≤ b.opsMax ∧ s.failures.all (· ≤ b.failuresMax) ∧ s.socks.all (·.sent ≤ b.sentMax)

structure Found where
  states : Nat
  transitions : Nat
  /-- The first invariant broken, with the events that break it. -/
  broken : Option (String × List Event)

partial def walk (c : Config) (b : Bounds) : IO Found := do
  let first := init c
  let mut seen : Std.HashSet State := ({} : Std.HashSet State).insert first
  let mut frontier : Array (State × List Event) := #[(first, [])]
  let mut states := 1
  let mut transitions := 0
  while frontier.size > 0 do
    let mut next : Array (State × List Event) := #[]
    for (s, path) in frontier do
      for e in enabled c s do
        let t := step c s e
        transitions := transitions + 1
        let path' := e :: path
        match (invariants s e t).find? (!·.2) with
        | some (name, _) =>
          return { states, transitions, broken := some (name, path'.reverse) }
        | none => pure ()
        unless seen.contains t do
          seen := seen.insert t
          states := states + 1
          if within b t then next := next.push (t, path')
    frontier := next
  return { states, transitions, broken := none }

end Spec.Engine

/-! ## The transcript the replay reads -/

namespace Spec.Engine
open Spec.Lookup (flag stateToken)

def listToken (xs : List Nat) : String := "[" ++ ",".intercalate (xs.map toString) ++ "]"

def stageName : Stage → String
  | .closed => "closed" | .connecting => "connecting" | .up => "up"

/-- A slot: free, with whether its buffer is still lent; or its lookup, the order of its walk,
its connection, and whether its buffer is lent, a send is held and its end was reported. -/
def slotToken (sl : Slot) : String :=
  match sl.lookup with
  | none => s!"free {flag sl.busy 'B'}"
  | some lk =>
    let conn := match sl.conn with
      | some k => toString k
      | none => "-"
    s!"{stateToken lk} o{listToken sl.order} c{conn} " ++
      flag sl.busy 'B' ++ flag sl.held 'H' ++ flag sl.reported 'R'

def connToken (conn : Conn) : String :=
  s!"{stageName conn.stage} s{conn.server} u{conn.users}" ++ flag conn.idleNow 'I'

def opToken (op : Op) : String :=
  let kind := match op.kind with
    | .connect => "C" | .receive => "R" | .send => "S" | .sendTo => "D" | .receiveFrom => "L"
  kind ++ toString op.target ++ (if op.current then "*" else "x")

/-- The waiting lookups, grouped by the ticks they have left, soonest first. -/
def waitGroups (s : State) : List (List Nat) :=
  let waiting := (List.range s.slots.length).filterMap fun l =>
    let slot := slotAt s l
    match slot.lookup with
    | some lk => if waiting lk.stage then some (slot.remaining, l) else none
    | none => none
  let lefts := (waiting.map (·.1)).eraseDups.mergeSort (· ≤ ·)
  lefts.map fun left => (waiting.filter (·.1 = left)).map (·.2)

/-- A server's socket: open with the queries its port has carried and whether it is retiring,
or none. -/
def sockToken (sock : Sock) : String :=
  if sock.isOpen then s!"open s{sock.sent}" ++ flag sock.retiring 'R' else "none"

/-- The whole of a state, as the replay spells the Zig engine's. -/
def stateLine (s : State) : String :=
  " ; ".intercalate (s.slots.map slotToken) ++ " | " ++
  " ; ".intercalate (s.conns.map connToken) ++ " | " ++
  " ; ".intercalate (s.socks.map sockToken) ++ " | " ++
  " ".intercalate (s.ops.map opToken) ++ " | " ++
  s!"r{listToken s.ready} q{listToken s.results} t" ++
  (match s.lastTaken with | some l => toString l | none => "-") ++
  " w[" ++ ",".intercalate ((waitGroups s).map listToken) ++ "]" ++
  s!" f{listToken s.failures} e{listToken s.free} " ++ flag s.jammed 'J' ++ flag s.starved 'Z'

def outcomeToken : Outcome → String
  | .ok => "ok" | .failed => "failed" | .canceled => "canceled" | .exhausted => "exhausted"

def replyName : Reply → String
  | .answer => "answer" | .servfail => "servfail" | .nxdomain => "nxdomain"
  | .unmatched => "unmatched"

def eventToken : Event → String
  | .start => "start" | .take => "take" | .cancel l => s!"cancel:{l}" | .expire => "expire"
  | .idle => "idle" | .finish i o => s!"finish:{i}:{outcomeToken o}"
  | .message i l r => s!"message:{i}:{l}:{replyName r}"
  | .straggle i => s!"straggle:{i}" | .jam => "jam" | .starve => "starve"

/-! ## Walks that look for what they have not seen -/

/-- splitmix64, for walks the same from the same seed. -/
def mix (x : UInt64) : UInt64 :=
  let z := x + 0x9e3779b97f4a7c15
  let z := (z ^^^ (z >>> 30)) * 0xbf58476d1ce4e5b9
  let z := (z ^^^ (z >>> 27)) * 0x94d049bb133111eb
  z ^^^ (z >>> 31)

/-- Writes `count` walks of at most `length` events from `init`. Each step takes an event that
leads to a state no walk has reached, when there is one, and any event otherwise, the seed
choosing among them. Every state a walk reaches is checked against the invariants. Returns the
events written and the states reached. -/
def walks (out : IO.FS.Stream) (c : Config) (seed : UInt64) (count length : Nat) :
    IO (Nat × Nat) := do
  let mut word := seed
  let mut seen : Std.HashSet State := {}
  let mut events := 0
  for _ in [0:count] do
    let mut s := init c
    seen := seen.insert s
    out.putStrLn s!"config {c.slots} {c.conns} {if c.useTcp then "tcp" else "udp"} {c.perPort}"
    out.putStrLn s!"0 init {stateLine s}"
    for depth in [1:length + 1] do
      let choices := enabled c s
      if choices.isEmpty then break
      let fresh := choices.filter fun e => !seen.contains (step c s e)
      let pool := if fresh.isEmpty then choices else fresh
      word := mix word
      let e := pool.getD (word.toNat % pool.length) .take
      let t := step c s e
      if let some (name, _) := (invariants s e t).find? (!·.2) then
        throw <| IO.userError s!"the model breaks {name} at {eventToken e}, depth {depth}"
      seen := seen.insert t
      out.putStrLn s!"{depth} {eventToken e} {stateLine t}"
      events := events + 1
      s := t
  return (events, seen.size)

end Spec.Engine
