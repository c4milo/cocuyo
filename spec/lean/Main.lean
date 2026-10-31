import Spec
import Spec.Tokens
import Spec.AddressWalk
import Std.Data.HashSet

/-!
# The transcript

`cocuyo-spec all <cname_hops_max>` walks, for each configuration below, every state the model can
reach from `init`, depth first, and writes one line per event it tries: the depth, the event,
what the model answers, and the state it lands in with its cause (`lineToken`). Every event
`enabled` allows is tried in every state reached, and a state reached a second time is not walked
again, so each transition of the reachable graph is written once. The line still names the state
it reached, so the replay checks the Zig lookup arrived at the same one by the second path as
well.
`cname_hops_max` is the library's, which the model takes as given; the first line records it,
and the replay refuses a transcript written for another.

`tools/spec_replay/replay.zig` drives the Zig `Lookup` down the same tree and fails on the first
line that differs. `gate` writes the slice of it that `zig build test` replays, committed as
`tools/spec_replay/lookup_gate.txt`, and `check` is how `zig build spec` shows that file is still
the one the model writes.
-/
open Spec.Lookup

/-- What makes two states the same for the walk. An ended state answers the same to everything
whatever its counters say (`ended_absorbing`), so its stage and its error are all of it. Its cause
is not part of it either: each line below an ended state repeats the cause, which the line that
reached the state checked already. On the last pass the lookup does not ask a server before the
current one again for the name, so the counts of those servers are not part of it either
(docs/design.md §16 decision 58). -/
def key (c : Config) (s : State) : State :=
  if ended s.stage then
    { s with server := 0, round := 0, candidate := 0, hops := 0, edns := true, hadNoData := false,
             cause := none, cookieRetried := false, offered := false, datagrams := [],
             streams := [] }
  else if s.round + 1 < c.attempts then s
  else
    let behind (l : List Nat) := l.mapIdx fun p n => if p < s.server then 0 else n
    { s with datagrams := behind s.datagrams, streams := behind s.streams }

/-- Writes the events tried from `s`, and walks each state not seen before. Returns the lines
written and the deepest line. -/
partial def walk (out : IO.FS.Stream) (c : Config) (seen : IO.Ref (Std.HashSet State))
    (s : State) (depth : Nat) : IO (Nat × Nat) := do
  let mut lines := 0
  let mut deepest := depth
  for e in enabled c s do
    let (t, o) := step c s e
    out.putStrLn s!"{depth + 1} {eventToken e} {outToken o} {lineToken c t}"
    lines := lines + 1
    deepest := max deepest (depth + 1)
    unless (← seen.get).contains (key c t) do
      seen.modify (·.insert (key c t))
      let (more, deeper) ← walk out c seen t (depth + 1)
      lines := lines + more
      deepest := max deepest deeper
  return (lines, deepest)

/-- The configurations that rely on the AD bit (docs/design.md §25, Stage A): one server, one
pass, one name or two, over UDP and over DoH, under `encrypted` and under `always`. Over UDP,
`encrypted` relies on no server, and over DoH it does. Two names reach a negative that moves the
walk on, and each reaches a chain across messages. -/
def authenticatedAll (hops : Nat) : List Config := Id.run do
  let mut all := []
  for mode in [Mode.encrypted, .always] do
    for request in [false, true] do
      for candidates in [1, 2] do
        all := all ++ [{ servers := 1, attempts := 1, candidates, hopsMax := hops, useTcp := false,
                         request, authenticatedData := mode }]
  return all

/-- The configurations `all` walks: none, one, two or three servers; one to three attempts and
search candidates; every query over UDP, over TCP, over DoH or over DoQ (docs/design.md §22,
§23). Since 2026-10-27 a state holds the queries each server got (§16 decision 58), so two states
that differ in a count alone are walked apart. Several servers over several passes multiply the
counts, over UDP most, where TC=1 adds a stream to each datagram. So two servers over several
passes walk one name over UDP, and three servers over several passes walk one name over a stream
or a request alone. One server reaches each rule of the bound, and two servers reach a server
passed over in the middle of a pass and at the start of the next. -/
def configsAll (hops : Nat) : List Config := Id.run do
  let mut all := [{ servers := 0, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false }]
  let transports := [(false, false, false), (true, false, false), (false, true, false), (false, true, true)]
  for servers in [1, 2, 3] do
    for attempts in [1, 2, 3] do
      for candidates in [1, 2, 3] do
        for (useTcp, request, quic) in transports do
          let udp := !useTcp && !request
          let walked :=
            servers = 1 || attempts = 1 ||
              (servers = 2 && (!udp || candidates = 1)) ||
              (servers = 3 && attempts = 2 && !udp && candidates = 1)
          if walked then
            all := all ++ [{ servers, attempts, candidates, hopsMax := hops, useTcp, request, quic }]
  return all ++ authenticatedAll hops

/-- The configurations `gate` walks: the slice `zig build test` replays without Lean. One
server, one attempt and one name reach every reply in every state, the whole CNAME chain, the
TCP path, the DoH path and the DoQ path. One pass ends a lookup at its first server failure.
So one server with two passes over DoH is walked too. There a lookup runs with a cause, and a
second cause replaces the first (docs/design.md §5, The cause of a failure). Two servers and one
pass over DoQ are walked last: there a cause names a server that the lookup is not on at its end
(docs/design.md §16 decision 51). -/
def configsGate (hops : Nat) : List Config :=
  [{ servers := 0, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := true },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false, request := true },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false, request := true,
     quic := true },
   { servers := 1, attempts := 2, candidates := 1, hopsMax := hops, useTcp := false, request := true },
   { servers := 2, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false, request := true,
     quic := true },
   -- Rule 3 of docs/design.md §25 over UDP under `always`, where the bit counts, and under
   -- `encrypted`, where it does not; and over DoH under `encrypted`, with two names.
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false,
     authenticatedData := .always },
   { servers := 1, attempts := 1, candidates := 1, hopsMax := hops, useTcp := false,
     authenticatedData := .encrypted },
   { servers := 1, attempts := 1, candidates := 2, hopsMax := hops, useTcp := false, request := true,
     authenticatedData := .encrypted }]

/-- Writes the transcript of `configs` to `out`. Returns the events written and the deepest. -/
def transcript (out : IO.FS.Stream) (hops : Nat) (configs : List Config) : IO (Nat × Nat) := do
  out.putStrLn s!"hops {hops}"
  let mut total := 0
  let mut deepest := 0
  for c in configs do
    out.putStrLn s!"config {c.servers} {c.attempts} {c.candidates} {transportToken c} {modeToken c.authenticatedData}"
    let s := init c
    out.putStrLn s!"0 init none {lineToken c s}"
    let seen ← IO.mkRef (({} : Std.HashSet State).insert (key c s))
    let (lines, depth) ← walk out c seen s 0
    total := total + lines
    deepest := max deepest depth
  return (total, deepest)

/-- Whether the file at `path` holds exactly what `write` writes. -/
def same (path : String) (write : IO.FS.Stream → IO Unit) : IO Bool := do
  let buffer ← IO.mkRef ({} : IO.FS.Stream.Buffer)
  write (IO.FS.Stream.ofBuffer buffer)
  return (← IO.FS.readBinFile path) == (← buffer.get).data

def usage : String :=
  "usage: cocuyo-spec all <cname_hops_max> [<out>]\n" ++
  "       cocuyo-spec gate <cname_hops_max> [<out>]\n" ++
  "       cocuyo-spec walks | walks-gate\n" ++
  "       cocuyo-spec check <cname_hops_max> <lookup gate> <walks gate>"

/-- Writes the transcript of `mode` to `out`, and says how large it is. -/
def write (mode hops : String) (out : IO.FS.Stream) : IO UInt32 := do
  let configs ← match mode with
    | "all" => pure (configsAll hops.toNat!)
    | "gate" => pure (configsGate hops.toNat!)
    | _ => do IO.eprintln usage; return 2
  let (total, deepest) ← transcript out hops.toNat! configs
  IO.eprintln s!"{total} events, {deepest} deep"
  return 0

def main (args : List String) : IO UInt32 := do
  match args with
  | [mode, hops] => write mode hops (← IO.getStdout)
  -- The build names a file: the full transcript is more than one write to a pipe's capture may
  -- carry (2,198,581,460 octets on 2026-10-27, past macOS's 2^31 - 1 for one `write`).
  | [mode, hops, path] =>
    IO.FS.withFile path .write fun handle => do
      let code ← write mode hops (IO.FS.Stream.ofHandle handle)
      handle.flush
      return code
  | ["walks"] =>
    let total ← Spec.Walks.transcript (← IO.getStdout) Spec.Walks.forwardAll
    IO.eprintln s!"{total} events"
    return 0
  | ["walks-gate"] =>
    let _ ← Spec.Walks.transcript (← IO.getStdout) Spec.Walks.forwardGate
    return 0
  | ["check", hops, lookupPath, walksPath] =>
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
