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
  /-- The kinds of event taken, one bit each by `eventBit`. -/
  events : Nat := 0
  /-- The connection stages reached, one bit each by `stageBit`, and two facts of TLS beside them:
  a connection that opened resuming, and a ticket kept. -/
  stages : Nat := 0

/-! ## One state for every order of the loop's operations

The model reads `ops` as a multiset. Every rule reads it by `any`, `all`, a count or an element-wise
map; an operation joins at the end; and an event names one by its position, over every position
`enabled` enumerates, and the step takes it out wherever it is. So two states whose operations
differ only in their order have the same futures and the same invariants, and the walk counts
them as one: it looks a state up by its operations sorted, and walks the state as the step left
it, so a path it reports is one the model takes. -/

def kindRank : OpKind → Nat
  | .connect => 0 | .receive => 1 | .send => 2 | .sendTo => 3 | .receiveFrom => 4
  | .sendRecords => 5

/-- A total order on operations: by kind, target, and the two flags. -/
def opLe (a b : Op) : Bool :=
  if kindRank a.kind != kindRank b.kind then kindRank a.kind < kindRank b.kind
  else if a.target != b.target then a.target < b.target
  else if a.current != b.current then !a.current
  else !a.draining || b.draining

/-- A state with its operations sorted: the one the walk looks it up by. -/
def canon (s : State) : State := { s with ops := s.ops.mergeSort opLe }

/-! ## What a walk reached -/

def eventBit : Event → Nat
  | .start => 0 | .take => 1 | .cancel _ => 2 | .expire => 3 | .idle => 4
  | .finish _ .ok => 5 | .finish _ .failed => 6 | .finish _ .canceled => 7
  | .finish _ .exhausted => 8 | .finish _ .short => 9
  | .message _ _ .answer => 10 | .message _ _ .servfail => 11 | .message _ _ .nxdomain => 12
  | .message _ _ .unmatched => 13 | .straggle _ => 14
  | .tls _ .flight => 15 | .tls _ .done => 16 | .tls _ .failed => 17 | .tls _ .rekey => 18
  | .tls _ .ticket => 19 | .lapse _ => 20 | .jam => 21 | .starve => 22

def eventNames : List String :=
  ["start", "take", "cancel", "expire", "idle", "finish:ok", "finish:failed", "finish:canceled",
   "finish:exhausted", "finish:short", "message:answer", "message:servfail", "message:nxdomain",
   "message:unmatched", "straggle", "tls:flight", "tls:done", "tls:failed", "tls:rekey",
   "tls:ticket", "lapse", "jam", "starve"]

def stageBit : Stage → Nat
  | .closed => 0 | .connecting => 1 | .handshaking => 2 | .up => 3 | .closing => 4
  | .reopening => 5

def stageNames : List String :=
  ["closed", "connecting", "handshaking", "up", "closing", "reopening", "resumed", "ticket kept"]

/-- The stages and TLS facts `s` shows, as `Found.stages` counts them. -/
def stagesOf (s : State) : Nat :=
  let conns := s.conns.foldl (fun m conn =>
    m ||| (1 <<< stageBit conn.stage) ||| (if conn.resumed then 1 <<< 6 else 0)) 0
  conns ||| (if s.tickets.any id then 1 <<< 7 else 0)

/-- The names of `names` whose bits `mask` lacks. -/
def missing (names : List String) (mask : Nat) : List String :=
  (names.zip (List.range names.length)).filterMap fun (name, bit) =>
    if mask &&& (1 <<< bit) == 0 then some name else none

/-- What `s` leads to, up to the order of the loop's operations: each successor sorted, and the
invariants its event breaks. -/
def successors (c : Config) (s : State) : List (State × List String) :=
  (enabled c s).map fun e =>
    let t := step c s e
    (canon t, ((invariants s e t).filter (!·.2)).map (·.1))

/-- Whether `s` and its sort agree: as many events, the same successors once sorted, and the same
invariants broken, taken as sets. -/
def agrees (c : Config) (s : State) : Bool :=
  let mine := successors c s
  let sorted := successors c (canon s)
  mine.length == sorted.length && mine.all (sorted.contains ·) && sorted.all (mine.contains ·)

/-- The check the walk's counting rests on. It walks the graph whole, a state and its sort as two,
and asks every state it reaches whether it and its sort agree. At these bounds that is every state
there is, so a walk within them may count the two as one; beyond them it is evidence, and a rule
that read the operations' order would break it here first. Returns the states checked, and the
first that disagrees with the events that reach it. -/
partial def canonCheck (c : Config) (b : Bounds) : IO (Nat × Option (List Event)) := do
  let first := init c
  let mut seen : Std.HashSet State := ({} : Std.HashSet State).insert first
  let mut frontier : Array (State × List Event) := #[(first, [])]
  let mut checked := 0
  while frontier.size > 0 do
    let mut next : Array (State × List Event) := #[]
    for (s, path) in frontier do
      checked := checked + 1
      unless agrees c s do return (checked, some path.reverse)
      for e in enabled c s do
        let t := step c s e
        unless seen.contains t do
          seen := seen.insert t
          if within b t then next := next.push (t, e :: path)
          else
            checked := checked + 1
            unless agrees c t do return (checked, some (e :: path).reverse)
    frontier := next
  return (checked, none)

partial def walk (c : Config) (b : Bounds) : IO Found := do
  let first := init c
  let mut seen : Std.HashSet State := ({} : Std.HashSet State).insert (canon first)
  let mut frontier : Array (State × List Event) := #[(first, [])]
  let mut states := 1
  let mut transitions := 0
  let mut events := 0
  let mut stages := stagesOf first
  while frontier.size > 0 do
    let mut next : Array (State × List Event) := #[]
    for (s, path) in frontier do
      for e in enabled c s do
        let t := step c s e
        transitions := transitions + 1
        events := events ||| (1 <<< eventBit e)
        let path' := e :: path
        match (invariants s e t).find? (!·.2) with
        | some (name, _) =>
          return { states, transitions, broken := some (name, path'.reverse), events, stages }
        | none => pure ()
        let key := canon t
        unless seen.contains key do
          seen := seen.insert key
          states := states + 1
          stages := stages ||| stagesOf t
          if within b t then next := next.push (t, path')
    frontier := next
  return { states, transitions, broken := none, events, stages }

end Spec.Engine

/-! ## The transcript the replay reads -/

namespace Spec.Engine
open Spec.Lookup (flag stateToken)

def listToken (xs : List Nat) : String := "[" ++ ",".intercalate (xs.map toString) ++ "]"

def stageName : Stage → String
  | .closed => "closed" | .connecting => "connecting" | .handshaking => "handshaking"
  | .up => "up" | .closing => "closing" | .reopening => "reopening"

def entryToken : Entry → String
  | .query l => toString l | .records => "r"

def ageToken : Age → String
  | .current => "c" | .draining => "d" | .gone => "g"

/-- A slot: free, with whether its buffer is still lent and the socket its last datagram left
from; or its lookup, the order of its walk, its connection, that socket, and whether its buffer
is lent, a send is held and its end was reported. -/
def slotToken (sl : Slot) : String :=
  let sent := match sl.sentFrom with
    | some (v, a) => s!"{v}{ageToken a}"
    | none => "-"
  match sl.lookup with
  | none => s!"free {flag sl.busy 'B'} u{sent}"
  | some lk =>
    let conn := match sl.conn with
      | some k => toString k
      | none => "-"
    s!"{stateToken lk} o{listToken sl.order} c{conn} u{sent} " ++
      flag sl.busy 'B' ++ flag sl.held 'H' ++ flag sl.reported 'R'

/-- A connection. Over TLS it also shows how many of its queue's entries are sealed. -/
def connToken (tls : Bool) (conn : Conn) : String :=
  s!"{stageName conn.stage} s{conn.server} u{conn.users}" ++ flag conn.idleNow 'I' ++
    flag conn.partSent 'P' ++ " q[" ++ ",".intercalate (conn.queue.map entryToken) ++ "]" ++
    (if tls then s!" k{conn.sealed}" ++ flag conn.resumed 'M' else "")

def opToken (op : Op) : String :=
  let kind := match op.kind with
    | .connect => "C" | .receive => "R" | .send => "S" | .sendTo => "D" | .receiveFrom => "L"
    | .sendRecords => "T"
  -- A receive that is gone is spelt as the code can see it: it names no socket any more.
  let kind := if op.kind = .receiveFrom ∧ op.draining ∧ op.current then "M" else kind
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

/-- A server's sockets: the queries the current port has carried, whether it is retiring, and
whether an older one drains. -/
def sockToken (sock : Sock) : String :=
  s!"open s{sock.sent}" ++ flag sock.retiring 'R' ++ flag sock.draining 'D'

/-- The whole of a state, as the replay spells the Zig engine's. -/
def stateLine (s : State) (tls : Bool := false) : String :=
  " ; ".intercalate (s.slots.map slotToken) ++ " | " ++
  " ; ".intercalate (s.conns.map (connToken tls)) ++ " | " ++
  " ; ".intercalate (s.socks.map sockToken) ++ " | " ++
  " ".intercalate (s.ops.map opToken) ++ " | " ++
  s!"r{listToken s.ready} q{listToken s.results} t" ++
  (match s.lastTaken with | some l => toString l | none => "-") ++
  " w[" ++ ",".intercalate ((waitGroups s).map listToken) ++ "]" ++
  s!" f{listToken s.failures} e{listToken s.free} " ++ flag s.jammed 'J' ++ flag s.starved 'Z' ++
  (if tls then " tk[" ++ ",".intercalate (s.tickets.map fun t => if t then "1" else "0") ++ "]" else "")

def outcomeToken : Outcome → String
  | .ok => "ok" | .failed => "failed" | .canceled => "canceled" | .exhausted => "exhausted"
  | .short => "short"

def replyName : Reply → String
  | .answer => "answer" | .servfail => "servfail" | .nxdomain => "nxdomain"
  | .unmatched => "unmatched"

def tlsStepName : TlsStep → String
  | .flight => "flight" | .done => "done" | .failed => "failed" | .rekey => "rekey"
  | .ticket => "ticket"

def eventToken : Event → String
  | .start => "start" | .take => "take" | .cancel l => s!"cancel:{l}" | .expire => "expire"
  | .idle => "idle" | .finish i o => s!"finish:{i}:{outcomeToken o}"
  | .message i l r => s!"message:{i}:{l}:{replyName r}"
  | .tls i t => s!"tls:{i}:{tlsStepName t}" | .lapse v => s!"lapse:{v}"
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
def walks (out : IO.FS.Stream) (c : Config) (seed : UInt64) (count length : Nat)
    (keep : Nat → Bool := fun _ => true) : IO (Nat × Nat) := do
  let mut word := seed
  let mut seen : Std.HashSet State := {}
  let mut events := 0
  -- Only the walks `keep` names are written, and the others are walked all the same, so a walk
  -- written alone is the walk the whole run has at its place.
  let sink := IO.FS.Stream.ofBuffer (← IO.mkRef {})
  for index in [0:count] do
    let out := if keep index then out else sink
    let mut s := init c
    seen := seen.insert s
    let transport := if c.tls then "tls" else if c.useTcp then "tcp" else "udp"
    out.putStrLn s!"config {c.slots} {c.conns} {transport} {c.perPort}"
    out.putStrLn s!"0 init {stateLine s c.tls}"
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
      out.putStrLn s!"{depth} {eventToken e} {stateLine t c.tls}"
      events := events + 1
      s := t
  return (events, seen.size)

end Spec.Engine
