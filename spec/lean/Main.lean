import Spec
import Spec.Tokens
import Spec.EngineWalk
import Spec.AddressWalk
import Std.Data.HashSet

/-!
# The transcript

`cocuyo-spec all <cname_hops_max>` walks, for each configuration below, every state the model can
reach from `init`, depth first, and writes one line per event it tries: the depth, the event,
what the model answers and the state it lands in (`stateToken`). Every event `enabled` allows is
tried in every state reached, and a state reached a second time is not walked again, so each
transition of the reachable graph is written once. The line still names the state it reached, so
the replay checks the Zig lookup arrived at the same one by the second path as well.
`cname_hops_max` is the library's, which the model takes as given; the first line records it,
and the replay refuses a transcript written for another.

`tools/spec_replay/replay.zig` drives the Zig `Lookup` down the same tree and fails on the first
line that differs. `gate` writes the slice of it that `zig build test` replays, committed as
`tools/spec_replay/lookup_gate.txt`, and `check` is how `zig build spec` shows that file is still
the one the model writes.
-/
open Spec.Lookup

/-- What makes two states the same for the walk. An ended state answers the same to everything
whatever its counters say (`ended_absorbing`), so its stage and its error are all of it. -/
def key (s : State) : State :=
  if ended s.stage then
    { s with server := 0, round := 0, candidate := 0, hops := 0, edns := true, hadNoData := false,
             serverFailed := false, cookieRetried := false, offered := false }
  else s

/-- Writes the events tried from `s`, and walks each state not seen before. Returns the lines
written and the deepest line. -/
partial def walk (out : IO.FS.Stream) (c : Config) (seen : IO.Ref (Std.HashSet State))
    (s : State) (depth : Nat) : IO (Nat × Nat) := do
  let mut lines := 0
  let mut deepest := depth
  for e in enabled c s do
    let (t, o) := step c s e
    out.putStrLn s!"{depth + 1} {eventToken e} {outToken o} {stateToken t}"
    lines := lines + 1
    deepest := max deepest (depth + 1)
    unless (← seen.get).contains (key t) do
      seen.modify (·.insert (key t))
      let (more, deeper) ← walk out c seen t (depth + 1)
      lines := lines + more
      deepest := max deepest deeper
  return (lines, deepest)

/-- The configurations `all` walks: none, one, two or three servers; one to three attempts and
search candidates; every query over UDP, over TCP, over DoH or over DoQ (docs/design.md §22,
§23). -/
def configsAll (hops : Nat) : List Config := Id.run do
  let mut all := [{ servers := 0, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false }]
  let transports := [(false, false, false), (true, false, false), (false, true, false), (false, true, true)]
  for servers in [1, 2, 3] do
    for attempts in [1, 2, 3] do
      for candidates in [1, 2, 3] do
        for (useTcp, request, quic) in transports do
          all := all ++ [{ servers, attempts, candidates, hopsMax := hops, useTcp, request, quic }]
  return all

/-- The configurations `gate` walks: the slice `zig build test` replays without Lean. One
server, one attempt and one name reach every reply in every state, the whole CNAME chain, the
TCP path, the DoH path and the DoQ path. -/
def configsGate (hops : Nat) : List Config :=
  [{ servers := 0, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := true },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false, request := true },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false, request := true,
     quic := true }]

/-- Writes the transcript of `configs` to `out`. Returns the events written and the deepest. -/
def transcript (out : IO.FS.Stream) (hops : Nat) (configs : List Config) : IO (Nat × Nat) := do
  out.putStrLn s!"hops {hops}"
  let mut total := 0
  let mut deepest := 0
  for c in configs do
    out.putStrLn s!"config {c.servers} {c.attempts} {c.candidates} {transportToken c}"
    let s := init c
    out.putStrLn s!"0 init none {stateToken s}"
    let seen ← IO.mkRef (({} : Std.HashSet State).insert (key s))
    let (lines, depth) ← walk out c seen s 0
    total := total + lines
    deepest := max deepest depth
  return (total, deepest)

/-- The engine walks `zig build test` replays, committed as `tools/spec_replay/engine_gate.txt`:
the seed, the walks in each configuration, and the most events in one. -/
def engineGate : Nat × Nat × Nat := (1, 10, 40)

/-- Walks of the full run (`engine-walks 1 2000 200`) the gate keeps as well, each named by its
configuration's place in `engineConfigs` and its own place among that configuration's walks:
each is where the full run caught a mutation of the engine that the short slice misses
(docs/mutations.md). -/
def engineGatePicks : List (Nat × Nat) := [(6, 120), (6, 329), (6, 392)]

/-- The full run's seed and walk length, which a picked walk is regenerated with. -/
def engineFull : Nat × Nat := (1, 200)

/-- The engine configurations: every query over TCP with one or two slots and one or two
connections, every query over UDP with one or two slots and a port replaced every two queries,
and every query over TLS with one or two slots and a connection for each server (§21, TLS rule
6). -/
def engineConfigs : List Spec.Engine.Config :=
  let tcp := [(1, 1), (1, 2), (2, 1), (2, 2)].map fun (slots, conns) =>
    { servers := 2, slots, conns, pollsMax := 1000, timeoutTicks := 2, useTcp := true, perPort := 0 }
  let udp := [1, 2].map fun slots =>
    { servers := 2, slots, conns := 1, pollsMax := 1000, timeoutTicks := 2, useTcp := false,
      perPort := 2 }
  let tls := [1, 2].map fun slots =>
    { servers := 2, slots, conns := 2, pollsMax := 1000, timeoutTicks := 2, useTcp := true,
      perPort := 0, tls := true }
  tcp ++ udp ++ tls

/-- The walks `engineGatePicks` names, each regenerated from its configuration's first walk. -/
def engineGatePicked (out : IO.FS.Stream) : IO Unit := do
  let (seed, length) := engineFull
  for (config, walk) in engineGatePicks do
    match engineConfigs[config]? with
    | some c =>
      let _ ← Spec.Engine.walks out c seed.toUInt64 (walk + 1) length (· = walk)
    | none => throw <| IO.userError s!"no engine configuration {config}"

/-- The engine's walks, in each configuration. -/
def engineWalks (out : IO.FS.Stream) (seed count length : Nat) (quiet : Bool) : IO Nat := do
  let mut total := 0
  for c in engineConfigs do
    let (slots, conns) := (c.slots, c.conns)
    let (events, states) ← Spec.Engine.walks out c seed.toUInt64 count length
    unless quiet do IO.eprintln s!"config {slots} {conns}: {events} events, {states} states"
    total := total + events
  return total

/-- Whether the file at `path` holds exactly what `write` writes. -/
def same (path : String) (write : IO.FS.Stream → IO Unit) : IO Bool := do
  let buffer ← IO.mkRef ({} : IO.FS.Stream.Buffer)
  write (IO.FS.Stream.ofBuffer buffer)
  return (← IO.FS.readBinFile path) == (← buffer.get).data

def usage : String :=
  "usage: cocuyo-spec all <cname_hops_max>\n" ++
  "       cocuyo-spec gate <cname_hops_max>\n" ++
  "       cocuyo-spec engine <tcp|udp|tls> <slots> <connections> [<ops_max> <failures_max>]\n" ++
  "       cocuyo-spec engine-walks <seed> <walks> <length>\n" ++
  "       cocuyo-spec engine-gate\n" ++
  "       cocuyo-spec walks | walks-gate\n" ++
  "       cocuyo-spec check <cname_hops_max> <lookup gate> <walks gate>"

/-- The configuration `engine` and the canon check walk: two servers, over `transport`. -/
def engineConfig (transport : String) (slots conns : Nat) : Spec.Engine.Config :=
  let stream := transport = "tcp" ∨ transport = "tls"
  { servers := 2, slots, conns, pollsMax := 1000, timeoutTicks := 2, useTcp := stream,
    perPort := if stream then 0 else 2, tls := transport = "tls" }

/-- Walks one engine configuration breadth first, within `opsMax` operations in flight and
`failuresMax` failures a server. -/
def engineCheck (transport slots conns : String) (opsMax failuresMax : Nat) : IO UInt32 := do
  let c := engineConfig transport slots.toNat! conns.toNat!
  -- A TLS configuration has a connection slot for each server (§21, TLS rule 6).
  if c.tls ∧ c.conns < c.servers then
    IO.eprintln s!"a TLS configuration needs {c.servers} connections"; return 2
  let found ← Spec.Engine.walk c { opsMax, failuresMax, sentMax := 3 }
  IO.println s!"{found.states} states, {found.transitions} transitions"
  let events := Spec.Engine.missing Spec.Engine.eventNames found.events
  let stages := Spec.Engine.missing Spec.Engine.stageNames found.stages
  IO.println s!"events never taken: {if events.isEmpty then "none" else ", ".intercalate events}"
  IO.println s!"stages never reached: {if stages.isEmpty then "none" else ", ".intercalate stages}"
  match found.broken with
  | none => IO.println "every invariant holds"; return 0
  | some (name, path) =>
    IO.println s!"broken: {name}"
    for e in path do IO.println s!"  {repr e}"
    return 1

/-- The claim `Spec.Engine.walk` counts by, that a state and its operations sorted are one, checked
on every state of three small graphs whole: one for each transport (spec/README.md). -/
def canonChecks : IO Bool := do
  let runs := [("tcp", 1, 1, 4, 1), ("udp", 1, 1, 3, 1), ("tls", 1, 2, 2, 0)]
  for (transport, slots, conns, opsMax, failuresMax) in runs do
    let c := engineConfig transport slots conns
    let (checked, broken) ← Spec.Engine.canonCheck c { opsMax, failuresMax, sentMax := 3 }
    match broken with
    | none => IO.eprintln s!"canon: {transport} agrees in all {checked} states"
    | some path =>
      IO.eprintln s!"canon: {transport} disagrees with its sort after {path.length} events:"
      for e in path do IO.eprintln s!"  {repr e}"
      return false
  return true

def main (args : List String) : IO UInt32 := do
  match args with
  | [mode, hops] =>
    let configs ← match mode with
      | "all" => pure (configsAll hops.toNat!)
      | "gate" => pure (configsGate hops.toNat!)
      | _ => do IO.eprintln usage; return 2
    let (total, deepest) ← transcript (← IO.getStdout) hops.toNat! configs
    IO.eprintln s!"{total} events, {deepest} deep"
    return 0
  | ["engine", transport, slots, conns] => engineCheck transport slots conns 6 2
  | ["engine", transport, slots, conns, ops, failures] =>
    engineCheck transport slots conns ops.toNat! failures.toNat!
  | ["engine-probe", transport, slots, conns, seed, count, length] =>
    -- Seeded walks over one configuration, for a quick look before the breadth-first walk.
    let stream := transport = "tcp" ∨ transport = "tls"
    let c : Spec.Engine.Config :=
      { servers := 2, slots := slots.toNat!, conns := conns.toNat!, pollsMax := 1000,
        timeoutTicks := 2, useTcp := stream, perPort := if stream then 0 else 2,
        tls := transport = "tls" }
    let sink := IO.FS.Stream.ofBuffer (← IO.mkRef {})
    let (events, states) ← Spec.Engine.walks sink c seed.toNat!.toUInt64 count.toNat! length.toNat!
    IO.println s!"{events} events, {states} states, every invariant holds"
    return 0
  | ["engine-walks", seed, count, length] =>
    let total ← engineWalks (← IO.getStdout) seed.toNat! count.toNat! length.toNat! false
    IO.eprintln s!"{total} events"
    return 0
  | ["walks"] =>
    let total ← Spec.Walks.transcript (← IO.getStdout) Spec.Walks.forwardAll
    IO.eprintln s!"{total} events"
    return 0
  | ["walks-gate"] =>
    let _ ← Spec.Walks.transcript (← IO.getStdout) Spec.Walks.forwardGate
    return 0
  | ["engine-gate"] =>
    let (seed, count, length) := engineGate
    let _ ← engineWalks (← IO.getStdout) seed count length true
    engineGatePicked (← IO.getStdout)
    return 0
  | ["check", hops, lookupPath, walksPath] =>
    unless ← canonChecks do return 1
    let lookupSame ← same lookupPath fun out => do
      let _ ← transcript out hops.toNat! (configsGate hops.toNat!)
    unless lookupSame do
      IO.eprintln s!"{lookupPath} is not the slice the model writes: run `cocuyo-spec gate {hops}`"
    let walksSame ← same walksPath fun out => do
      let _ ← Spec.Walks.transcript out Spec.Walks.forwardGate
    unless walksSame do
      IO.eprintln s!"{walksPath} is not the slice the model writes: run `cocuyo-spec walks-gate`"
    return if lookupSame ∧ walksSame then 0 else 1
  | _ =>
    IO.eprintln usage
    return 2
