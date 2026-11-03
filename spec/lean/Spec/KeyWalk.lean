/-!
# The walk for a message's keys

The walk of docs/design.md §25 (Stage B: where the keys come from; step 12), written from the
design and never from the Zig source (spec/README.md). A name is its labels from the root down,
so an ancestor is a prefix. Verification is abstracted: the validator's verdict on an answer is the
answer itself, and a server may answer anything. A secure verdict is one the store's keys gave, so
the model accepts one only for a question asked under keys the store holds.

The store keeps what the walks learned, and may lose any entry, as a full store replaces one. The
model keeps a ghost beside it, `proven`: every entry that ever entered, which nothing removes. The
theorems are stated over the ghost, since an entry the store lost may have backed one it kept.
-/
namespace Spec.KeyWalk

/-- A name, as its labels from the root down: the root is `[]`, and a child adds a label. -/
abbrev Name := List Nat

/-- Whether `z` is `n` or an ancestor of it. -/
def above (z n : Name) : Prop := z <+: n

/-- Whether `z` is a proper ancestor of `n`. -/
def strictlyAbove (z n : Name) : Prop := z <+: n ∧ z.length < n.length

instance (z n : Name) : Decidable (above z n) := inferInstanceAs (Decidable (z <+: n))

/-- What the store holds of zones: their validated DNSKEY sets, validated DS sets whose keys have
not come, and insecure delegations (§25). -/
structure Entries where
  keys : List Name
  ds : List Name
  insecure : List Name
  deriving DecidableEq, Repr

/-- The questions a walk asks: a name's DS set, or a zone's DNSKEY set. -/
inductive Asking where
  | ds | dnskey
  deriving DecidableEq, Repr

inductive Phase where
  | asking | done | failed
  deriving DecidableEq, Repr

/-- One walk: its target, the name it asks of now and what it asks, the zone whose keys it stands
in, and the questions it asked (§25, walk rules 1 to 3). -/
structure Walk where
  target : Name
  probe : Name
  asking : Asking
  zone : Name
  questions : Nat
  phase : Phase
  deriving DecidableEq, Repr

structure Config where
  anchors : List Name
  /-- `chain_questions_max` (§25, walk rule 10). -/
  questionsMax : Nat

structure State where
  store : Entries
  /-- Every entry that ever entered the store. -/
  proven : Entries
  walk : Walk
  deriving DecidableEq, Repr

/-- What the validator made of the answer to the walk's question (§25, walk rules 4 to 7 and 11). -/
inductive Answer where
  /-- A DS set at the probe, secure under the keys of the zone the walk stands in. -/
  | dsSet
  /-- A secure proof that the probe exists and is no delegation, or is an empty non-terminal. -/
  | noDelegation
  /-- A signed answer that proves nothing at the probe: its verdict is bogus for its proof alone,
  as NSD's answer at an empty non-terminal under Opt-Out is (§25, walk rule 6). -/
  | unproven
  /-- A secure proof of a delegation with no DS at the probe, or an insecure answer. -/
  | unsigned
  /-- A secure proof that the probe does not exist. -/
  | nameError
  /-- The DNSKEY set, a key of which matched the anchor or the held DS set and signed it. -/
  | keysMatched
  /-- The DNSKEY set, which matched nothing or verified under no matched key. -/
  | keysRefused
  /-- The question went unanswered, or every server failed. -/
  | failed
  deriving DecidableEq, Repr

/-- What the caller can tell the model: an answer to the walk's question, or the store losing
an entry of a zone. -/
inductive Event where
  | answer (a : Answer)
  | evictKeys (z : Name)
  | evictDs (z : Name)
  | evictInsecure (z : Name)
  deriving DecidableEq, Repr

/-- The name one label below `zone` toward `target`. -/
def below (zone target : Name) : Name := target.take (zone.length + 1)

def fail (s : State) : State := { s with walk := { s.walk with phase := .failed } }

def finish (s : State) : State := { s with walk := { s.walk with phase := .done } }

/-- Whether the walk is over: the store holds the target's keys, or an insecure delegation at or
above it (walk rule 8). -/
def reached (s : State) : Bool :=
  s.store.keys.contains s.walk.target || s.store.insecure.any (fun i => decide (above i s.walk.target))

/-- The walk's next question once it stands in `zone`: done when the target is reached, the
target's own DNSKEY set when the target is the zone below, else the DS set of the next name down.
A probe past the target is a walk for data with no signature that reached the name asked inside a
signed zone, which fails (walk rule 8). -/
def next (s : State) : State :=
  if reached s then finish s
  else if s.walk.zone.length ≥ s.walk.target.length then fail s
  else
    let p := below s.walk.zone s.walk.target
    let asking := if s.store.ds.contains p then Asking.dnskey else .ds
    { s with walk := { s.walk with probe := p, asking := asking } }

/-- Adds `z` to a list once. -/
def add (l : List Name) (z : Name) : List Name := if l.contains z then l else z :: l

/-- An answer to the walk's question, asked under the keys of `s.walk.zone`. A DS set or an
insecure delegation enters the store and the ghost (walk rules 4 and 5), and a DNSKEY set enters
only when an anchor or a held DS set names the zone (rule 4). The question counts, and past
`questionsMax` the walk fails (rule 10). -/
def answered (c : Config) (s : State) (a : Answer) : State :=
  let w := s.walk
  let t := { s with walk := { w with questions := w.questions + 1 } }
  if t.walk.questions > c.questionsMax then fail t
  -- A DS question is answered under the keys of the zone the walk stands in: a secure verdict
  -- comes from keys the store holds, and without them the answer proves nothing (rule 9).
  else if w.asking = .ds && !s.store.keys.contains w.zone then fail t
  else
    match w.asking, a with
    | .ds, .dsSet =>
      { t with store := { t.store with ds := add t.store.ds w.probe },
               proven := { t.proven with ds := add t.proven.ds w.probe },
               walk := { t.walk with asking := .dnskey } }
    -- The probe exists and is no delegation: the next label, in the same zone (rule 6). At the
    -- target, a walk for data with no signature reached the name asked inside a signed zone
    -- (rule 8).
    -- An answer that proves nothing at the probe moves the walk on the same way, since nothing
    -- of it enters the store (rule 6).
    | .ds, .noDelegation | .ds, .unproven =>
      if w.probe.length ≥ w.target.length then fail t
      else { t with walk := { t.walk with probe := below w.probe w.target } }
    | .ds, .unsigned =>
      finish { t with store := { t.store with insecure := add t.store.insecure w.probe },
                      proven := { t.proven with insecure := add t.proven.insecure w.probe } }
    | .dnskey, .keysMatched =>
      if c.anchors.contains w.probe || s.store.ds.contains w.probe then
        next { t with store := { t.store with keys := add t.store.keys w.probe },
                      proven := { t.proven with keys := add t.proven.keys w.probe },
                      walk := { t.walk with zone := w.probe } }
      else fail t
    | _, _ => fail t

/-- One event. An ended walk takes no answer; the store may lose an entry at any time. -/
def step (c : Config) (s : State) : Event → State
  | .answer a => if s.walk.phase = .asking then answered c s a else s
  | .evictKeys z => { s with store := { s.store with keys := s.store.keys.erase z } }
  | .evictDs z => { s with store := { s.store with ds := s.store.ds.erase z } }
  | .evictInsecure z => { s with store := { s.store with insecure := s.store.insecure.erase z } }

/-- The deepest of `zones` at or above `target`, if any. -/
def deepest (zones : List Name) (target : Name) : Option Name :=
  (zones.filter (fun z => decide (above z target))).foldl
    (fun best z => match best with
      | none => some z
      | some b => if b.length < z.length then some z else some b) none

/-- A walk for `target` over the store the earlier walks left: it stands in the deepest zone whose
keys the store holds, or enters the deepest anchor above the target by asking its DNSKEY set
(walk rule 2). With neither, the name is under no anchor, which is insecure, and the walk is done.
The ghost carries over, since an entry an earlier walk made may back one this walk makes. -/
def begin (c : Config) (s : State) (target : Name) : State :=
  let blank : Walk := { target, probe := [], asking := .ds, zone := [], questions := 0,
                        phase := .asking }
  let t : State := { s with walk := blank }
  match deepest s.store.keys target with
  | some z => next { t with walk := { blank with zone := z } }
  | none =>
    match deepest c.anchors target with
    | some a => { t with walk := { blank with zone := a, probe := a, asking := .dnskey } }
    | none => finish t

/-- Before any walk: an empty store, and no walk running. -/
def init : State :=
  { store := ⟨[], [], []⟩, proven := ⟨[], [], []⟩,
    walk := { target := [], probe := [], asking := .ds, zone := [], questions := 0,
              phase := .done } }

/-- What the caller can do between walks as well: begin a walk once the last one ended. -/
def run (c : Config) (s : State) : List (Option Name ⊕ Event) → State
  | [] => s
  | .inl (some t) :: rest => run c (if s.walk.phase = .asking then s else begin c s t) rest
  | .inl none :: rest => run c s rest
  | .inr e :: rest => run c (step c s e) rest

end Spec.KeyWalk
