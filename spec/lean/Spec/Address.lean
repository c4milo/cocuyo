/-!
# The `getaddrinfo` walks

`AddressLookup` and `NameLookup` of docs/design.md §19 step 14, written from the walk's rules
there, never from the Zig source (spec/README.md). A lookup the walk starts is abstracted to how
it ends, which the model of `Spec.Lookup` already answers for; what is left is the order the
ends come in, the order the consumer hands them over in, the walk's own cancels, and other
consumers taking the table's free slots between two of them.

An end arrives when the lookup settles in the table, and is delivered when the consumer hands it
to `on_event`; the two are apart, since a cancel reaches a lookup that has not settled and not
one that has (`Resolver.cancel`).
-/
namespace Spec.Address

inductive Source where
  | file | dns
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- How one lookup ends. `hard` is every failure that says nothing about the name: a timeout,
the servers failing. -/
inductive Result where
  | answer | nameNotFound | noData | hard | canceled
  deriving DecidableEq, Repr, Inhabited, Hashable

/-- One family's lookup: not started, or released; in flight; settled with its end not yet
handed over; handed over, its slot still held until the pair ends (rule 1). -/
inductive Pend where
  | idle | running | arrived (r : Result) | done (r : Result)
  deriving DecidableEq, Repr, Inhabited, Hashable

inductive End where
  | answered (half : Option Result)
  | failed (r : Result)
  deriving DecidableEq, Repr, Inhabited, Hashable

structure Config where
  sources : List Source
  /-- Whether the hosts table holds the name in a family asked for. -/
  hostsHas : Bool
  /-- The search candidates the name has. -/
  candidates : Nat
  asksA : Bool
  asksAaaa : Bool
  /-- The table's slots. -/
  slots : Nat
  deriving Repr

inductive Family where
  | a | aaaa
  deriving DecidableEq, Repr, Inhabited, Hashable

structure State where
  source : Nat
  candidate : Nat
  a : Pend
  aaaa : Pend
  sawNoData : Bool
  cancelled : Bool
  ended : Option End
  /-- The table's slots other consumers hold. -/
  others : Nat
  deriving DecidableEq, Repr, Hashable

inductive Event where
  | arrive (f : Family) (r : Result)
  | deliver (f : Family)
  | cancel
  /-- Another consumer starts a lookup in a free slot. -/
  | steal
  /-- Another consumer releases a slot it held. -/
  | giveBack
  deriving DecidableEq, Repr, Inhabited, Hashable

def pendOf (s : State) : Family → Pend
  | .a => s.a | .aaaa => s.aaaa

def setPend (s : State) (f : Family) (p : Pend) : State :=
  match f with
  | .a => { s with a := p } | .aaaa => { s with aaaa := p }

def other : Family → Family
  | .a => .aaaa | .aaaa => .a

def holds : Pend → Bool
  | .idle => false | _ => true

/-- The slots the walk holds. -/
def held (s : State) : Nat := (if holds s.a then 1 else 0) + (if holds s.aaaa then 1 else 0)

def free (c : Config) (s : State) : Nat := c.slots - s.others - held s

def resultOf : Pend → Option Result
  | .done r => some r | _ => none

/-! ## The walk -/

/-- Starts the pair of the current candidate: a lookup a family asked. -/
def startPair (c : Config) (s : State) : State :=
  { s with a := if c.asksA then .running else .idle, aaaa := if c.asksAaaa then .running else .idle }

/-- The sources from `source` on (rule 6): the hosts table answers when it holds the name, DNS
starts its first candidate, and the sources gone end the walk empty. -/
def nextSource (c : Config) (s : State) : State :=
  let rec go (fuel : Nat) (s : State) : State :=
    match fuel with
    | 0 => s
    | fuel + 1 =>
      match c.sources[s.source]? with
      | none => { s with ended := some (.failed (if s.sawNoData then .noData else .nameNotFound)) }
      | some .file =>
        let s := { s with source := s.source + 1 }
        if c.hostsHas then { s with ended := some (.answered none) } else go fuel s
      | some .dns =>
        let s := { s with source := s.source + 1, candidate := 0 }
        if c.candidates > 0 then startPair c s else go fuel s
  go (c.sources.length + 1) s

def nextCandidate (c : Config) (s : State) : State :=
  let s := { s with candidate := s.candidate + 1 }
  if s.candidate < c.candidates then startPair c s else nextSource c s

/-- A failure that is neither negative: what ends the walk, or rides along an answer. -/
def hardOf (p : Pend) : Option Result :=
  match resultOf p with
  | some .nameNotFound | some .noData | some .answer | none => none
  | some r => some r

/-- Both ends of the pair are in (rule 5). Its slots are released together, then: the consumer's
cancel ends the walk; an answer ends it answered; `NameNotFound` moves on; any other failure but
`NoData` ends it; else the next candidate. -/
def endPair (c : Config) (s : State) : State :=
  let ra := resultOf s.a
  let rq := resultOf s.aaaa
  let answered := ra = some .answer ∨ rq = some .answer
  let notFound := ra = some .nameNotFound ∨ rq = some .nameNotFound
  let hard := (hardOf s.a).orElse fun _ => hardOf s.aaaa
  let s' := { s with a := .idle, aaaa := .idle }
  if s.cancelled then { s' with ended := some (.failed .canceled) }
  else if answered then { s' with ended := some (.answered hard) }
  else if notFound then nextCandidate c s'
  else match hard with
    | some r => { s' with ended := some (.failed r) }
    | none => nextCandidate c s'

def settled : Pend → Bool
  | .idle | .done _ => true
  | _ => false

/-- A cancel reaches a lookup still in flight and settles it `Canceled`; one that has settled
keeps its end (rule 4, `Resolver.cancel`). -/
def cancelPend : Pend → Pend
  | .running => .arrived .canceled
  | p => p

/-- The consumer hands over one end (rules 3 and 4). -/
def deliver (c : Config) (s : State) (f : Family) : State :=
  match pendOf s f with
  | .arrived r =>
    let s := setPend s f (.done r)
    let s := if r = .noData then { s with sawNoData := true } else s
    let s := if r = .nameNotFound then setPend s (other f) (cancelPend (pendOf s (other f))) else s
    if settled s.a ∧ settled s.aaaa then endPair c s else s
  | _ => s

def init (c : Config) : State :=
  nextSource c { source := 0, candidate := 0, a := .idle, aaaa := .idle, sawNoData := false,
                 cancelled := false, ended := none, others := 0 }

def step (c : Config) (s : State) : Event → State
  | .arrive f r => match pendOf s f with
    | .running => setPend s f (.arrived r)
    | _ => s
  | .deliver f => deliver c s f
  | .cancel =>
    if s.ended.isSome then s else
    { s with cancelled := true, a := cancelPend s.a, aaaa := cancelPend s.aaaa }
  | .steal => if free c s > 0 then { s with others := s.others + 1 } else s
  | .giveBack => if s.others > 0 then { s with others := s.others - 1 } else s

/-- A lookup in flight ends any way but `Canceled`, which only a cancel settles it with; an end
that has arrived is handed over; the consumer cancels a walk that runs; other consumers take
and give back slots. -/
def enabled (c : Config) (s : State) : List Event :=
  let ends (f : Family) : List Event :=
    match pendOf s f with
    | .running => [Result.answer, .nameNotFound, .noData, .hard].map (Event.arrive f)
    | .arrived _ => [Event.deliver f]
    | _ => []
  ends .a ++ ends .aaaa ++
    (if s.ended.isNone then [Event.cancel] else []) ++
    (if free c s > 0 then [Event.steal] else []) ++
    (if s.others > 0 then [Event.giveBack] else [])

/-! ## What must hold -/

def invariants (c : Config) (s : State) : List (String × Bool) :=
  [ -- Rule 1: two slots at most, none once over, and never more than the table has.
    ("two slots", held s ≤ 2),
    ("none held at the end", s.ended.isNone || held s == 0),
    ("within the table", held s + s.others ≤ c.slots),
    -- Rule 2: a walk that runs waits for an end.
    ("waits for something", s.ended.isSome || !(settled s.a && settled s.aaaa)) ]

end Spec.Address

/-!
# The reverse walk

`NameLookup`: one lookup, the hosts table and DNS in the `lookups` order.
-/
namespace Spec.Name

open Spec.Address (Source Result Pend End)

structure Config where
  sources : List Source
  hostsHas : Bool
  deriving Repr

structure State where
  source : Nat
  pend : Pend
  sawNoData : Bool
  cancelled : Bool
  ended : Option End
  deriving DecidableEq, Repr, Hashable

inductive Event where
  | arrive (r : Result)
  | deliver
  | cancel
  deriving DecidableEq, Repr, Inhabited, Hashable

def nextSource (c : Config) (s : State) : State :=
  let rec go (fuel : Nat) (s : State) : State :=
    match fuel with
    | 0 => s
    | fuel + 1 =>
      match c.sources[s.source]? with
      | none => { s with ended := some (.failed (if s.sawNoData then .noData else .nameNotFound)) }
      | some .file =>
        let s := { s with source := s.source + 1 }
        if c.hostsHas then { s with ended := some (.answered none) } else go fuel s
      | some .dns => { s with source := s.source + 1, pend := .running }
  go (c.sources.length + 1) s

/-- The end handed over: the consumer's cancel ends the walk `Canceled` whatever it was; an
answer ends it answered; `NameNotFound` or `NoData` moves on; any other failure ends it. -/
def deliver (c : Config) (s : State) : State :=
  match s.pend with
  | .arrived r =>
    let s := { s with pend := .idle }
    if s.cancelled ∨ r = .canceled then { s with ended := some (.failed .canceled) }
    else match r with
      | .answer => { s with ended := some (.answered none) }
      | .nameNotFound => nextSource c s
      | .noData => nextSource c { s with sawNoData := true }
      | r => { s with ended := some (.failed r) }
  | _ => s

def init (c : Config) : State :=
  nextSource c { source := 0, pend := .idle, sawNoData := false, cancelled := false, ended := none }

def step (c : Config) (s : State) : Event → State
  | .arrive r => match s.pend with
    | .running => { s with pend := .arrived r }
    | _ => s
  | .deliver => deliver c s
  | .cancel =>
    if s.ended.isSome then s else
    { s with cancelled := true, pend := Spec.Address.cancelPend s.pend }

def enabled (s : State) : List Event :=
  (match s.pend with
    | .running => [Result.answer, .nameNotFound, .noData, .hard].map Event.arrive
    | .arrived _ => [Event.deliver]
    | _ => []) ++
  (if s.ended.isNone then [Event.cancel] else [])

def invariants (s : State) : List (String × Bool) :=
  [("none held at the end", s.ended.isNone || s.pend == .idle),
   ("waits for something", s.ended.isSome || s.pend != .idle)]

end Spec.Name
