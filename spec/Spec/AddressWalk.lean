import Spec.Address
import Std.Data.HashSet

/-!
# Walking the `getaddrinfo` walks

Every state `AddressLookup`'s model and `NameLookup`'s reach from `init`, depth first, each
state walked once, with its invariants checked, written as a transcript `tools/spec_replay/`
replays: a line per event tried, with the depth, the event and the walk's whole state after it.
-/
namespace Spec.Address

def sourceToken : Source → String
  | .file => "file" | .dns => "dns"

def resultToken : Result → String
  | .answer => "answer" | .nameNotFound => "name_not_found" | .noData => "no_data"
  | .hard => "hard" | .canceled => "canceled"

def pendToken : Pend → String
  | .idle => "-" | .running => "run"
  | .arrived r => s!"arr/{resultToken r}" | .done r => s!"done/{resultToken r}"

def endToken : Option End → String
  | none => "-"
  | some (.answered none) => "answered/-"
  | some (.answered (some r)) => s!"answered/{resultToken r}"
  | some (.failed r) => s!"failed/{resultToken r}"

def flag (b : Bool) (c : Char) : String := if b then c.toString else "-"

def stateLine (s : State) : String :=
  s!"s{s.source} c{s.candidate} a:{pendToken s.a} q:{pendToken s.aaaa} " ++
    flag s.sawNoData 'N' ++ flag s.cancelled 'C' ++ s!" e:{endToken s.ended} o{s.others}"

def familyToken : Family → String
  | .a => "a" | .aaaa => "q"

def eventToken : Event → String
  | .arrive f r => s!"arrive:{familyToken f}:{resultToken r}"
  | .deliver f => s!"deliver:{familyToken f}"
  | .cancel => "cancel" | .steal => "steal" | .giveBack => "give_back"

def sourcesToken (sources : List Source) : String := ",".intercalate (sources.map sourceToken)

/-- Writes the events tried from `s` and walks each state not seen before; the first invariant a
state breaks is thrown with the depth it came at. -/
partial def walk (out : IO.FS.Stream) (c : Config) (seen : IO.Ref (Std.HashSet State))
    (s : State) (depth : Nat) : IO Nat := do
  let mut lines := 0
  for e in enabled c s do
    let t := step c s e
    if let some (name, _) := (invariants c t).find? (!·.2) then
      throw <| IO.userError s!"the address model breaks {name} at {eventToken e}, depth {depth + 1}"
    out.putStrLn s!"{depth + 1} {eventToken e} {stateLine t}"
    lines := lines + 1
    unless (← seen.get).contains t do
      seen.modify (·.insert t)
      lines := lines + (← walk out c seen t (depth + 1))
  return lines

end Spec.Address

namespace Spec.Name

open Spec.Address (resultToken pendToken endToken flag sourcesToken)

def stateLine (s : State) : String :=
  s!"s{s.source} p:{pendToken s.pend} " ++ flag s.sawNoData 'N' ++ flag s.cancelled 'C' ++
    s!" e:{endToken s.ended}"

def eventToken : Event → String
  | .arrive r => s!"arrive:{resultToken r}" | .deliver => "deliver" | .cancel => "cancel"

partial def walk (out : IO.FS.Stream) (c : Config) (seen : IO.Ref (Std.HashSet State))
    (s : State) (depth : Nat) : IO Nat := do
  let mut lines := 0
  for e in enabled s do
    let t := step c s e
    if let some (name, _) := (invariants t).find? (!·.2) then
      throw <| IO.userError s!"the name model breaks {name} at {eventToken e}, depth {depth + 1}"
    out.putStrLn s!"{depth + 1} {eventToken e} {stateLine t}"
    lines := lines + 1
    unless (← seen.get).contains t do
      seen.modify (·.insert t)
      lines := lines + (← walk out c seen t (depth + 1))
  return lines

end Spec.Name

namespace Spec.Walks

open Spec.Address (Source)

/-- The source orders a walk is given, with whether the hosts table holds the name. -/
def orders : List (List Source × Bool) :=
  [([.dns], false), ([.file, .dns], false), ([.file, .dns], true), ([.dns, .file], false),
   ([.dns, .file], true)]

/-- Every family asked: both, `A` alone, `AAAA` alone. -/
def families : List (String × Bool × Bool) := [("both", true, true), ("a", true, false), ("aaaa", false, true)]

/-- One forward configuration: the sources and the hosts table, the candidates, the family by
name with what it asks, and the table's slots. -/
abbrev Forward := List Source × Bool × Nat × (String × Bool × Bool) × Nat

/-- Every forward configuration: one to three candidates, each family asked, a table of two or
three slots. -/
def forwardAll : List Forward := Id.run do
  let mut all := []
  for (sources, hostsHas) in orders do
    for candidates in [1, 2, 3] do
      for family in families do
        for slots in [2, 3] do
          all := all ++ [(sources, hostsHas, candidates, family, slots)]
  return all

/-- The slice `zig build test` replays: DNS alone with two candidates and both families, which
is where the pair's two ends race and the table can fill between them, and the hosts table
first and holding the name. -/
def forwardGate : List Forward :=
  [([.dns], false, 2, ("both", true, true), 2), ([.file, .dns], true, 1, ("both", true, true), 2)]

/-- Writes the transcript of `forward`'s configurations and every reverse one. Returns the
events. -/
def transcript (out : IO.FS.Stream) (forward : List Forward) : IO Nat := do
  let mut total := 0
  for (sources, hostsHas, candidates, (family, asksA, asksAaaa), slots) in forward do
    let c : Spec.Address.Config := { sources, hostsHas, candidates, asksA, asksAaaa, slots }
    out.putStrLn s!"address {Spec.Address.sourcesToken sources} {hostsHas} {candidates} {family} {slots}"
    let s := Spec.Address.init c
    out.putStrLn s!"0 init {Spec.Address.stateLine s}"
    let seen ← IO.mkRef (({} : Std.HashSet Spec.Address.State).insert s)
    total := total + (← Spec.Address.walk out c seen s 0)
  for (sources, hostsHas) in orders do
    let c : Spec.Name.Config := { sources, hostsHas }
    out.putStrLn s!"name {Spec.Address.sourcesToken sources} {hostsHas}"
    let s := Spec.Name.init c
    out.putStrLn s!"0 init {Spec.Name.stateLine s}"
    let seen ← IO.mkRef (({} : Std.HashSet Spec.Name.State).insert s)
    total := total + (← Spec.Name.walk out c seen s 0)
  return total

end Spec.Walks
