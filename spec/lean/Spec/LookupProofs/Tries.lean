import Spec.Lookup

/-!
# Tries kept open

The lemmas the proofs of `Spec.LookupProofs` and the files beside it share about the tries a
lookup keeps open (docs/design.md §5, Tries kept open; §16 decision 66): a later pass that waits on
an open stream try, a try closed, and a reply or a failure of an earlier try. Split from
`Spec.LookupProofs` by the file-length rule.
-/
namespace Spec.Lookup

/-- A property that rule 3's flag does not touch holds after `clear` when it held before: `clear`
changes that flag alone (docs/design.md §25, Stage A). -/
theorem clear_keeps (P : State → Prop) (c : Config) (a d : Bool) (t : State)
    (hP : ∀ u : State, P u → P { u with authentic := false }) (h : P t) : P (clear c a d t) := by
  unfold clear
  split
  · exact hP t h
  · exact h

/-- A later pass that waits on an open stream try changes the stage alone. -/
@[simp] theorem waitOn_fields (c : Config) (t : State) :
    (waitOn c t).server = t.server ∧ (waitOn c t).round = t.round ∧
      (waitOn c t).candidate = t.candidate ∧ (waitOn c t).hops = t.hops ∧
      (waitOn c t).cause = t.cause ∧ (waitOn c t).datagrams = t.datagrams ∧
      (waitOn c t).streams = t.streams ∧ (waitOn c t).edns = t.edns ∧
      (waitOn c t).cookieRetried = t.cookieRetried ∧ (waitOn c t).offered = t.offered ∧
      (waitOn c t).asks = t.asks ∧ (waitOn c t).authentic = t.authentic ∧
      (waitOn c t).secure = t.secure ∧ (waitOn c t).err = t.err ∧
      (waitOn c t).hadNoData = t.hadNoData ∧ (waitOn c t).openDatagrams = t.openDatagrams ∧
      (waitOn c t).openStreams = t.openStreams := by
  unfold waitOn; split <;> simp

@[simp] theorem waitOn_server (c : Config) (t : State) : (waitOn c t).server = t.server :=
  (waitOn_fields c t).1
@[simp] theorem waitOn_round (c : Config) (t : State) : (waitOn c t).round = t.round :=
  (waitOn_fields c t).2.1
@[simp] theorem waitOn_candidate (c : Config) (t : State) : (waitOn c t).candidate = t.candidate :=
  (waitOn_fields c t).2.2.1
@[simp] theorem waitOn_hops (c : Config) (t : State) : (waitOn c t).hops = t.hops :=
  (waitOn_fields c t).2.2.2.1
@[simp] theorem waitOn_cause (c : Config) (t : State) : (waitOn c t).cause = t.cause :=
  (waitOn_fields c t).2.2.2.2.1
@[simp] theorem waitOn_datagrams (c : Config) (t : State) : (waitOn c t).datagrams = t.datagrams :=
  (waitOn_fields c t).2.2.2.2.2.1
@[simp] theorem waitOn_streams (c : Config) (t : State) : (waitOn c t).streams = t.streams :=
  (waitOn_fields c t).2.2.2.2.2.2.1
@[simp] theorem waitOn_edns (c : Config) (t : State) : (waitOn c t).edns = t.edns :=
  (waitOn_fields c t).2.2.2.2.2.2.2.1
@[simp] theorem waitOn_cookieRetried (c : Config) (t : State) :
    (waitOn c t).cookieRetried = t.cookieRetried := (waitOn_fields c t).2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_offered (c : Config) (t : State) : (waitOn c t).offered = t.offered :=
  (waitOn_fields c t).2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_asks (c : Config) (t : State) : (waitOn c t).asks = t.asks :=
  (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_authentic (c : Config) (t : State) : (waitOn c t).authentic = t.authentic :=
  (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_secure (c : Config) (t : State) : (waitOn c t).secure = t.secure :=
  (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_err (c : Config) (t : State) : (waitOn c t).err = t.err :=
  (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_hadNoData (c : Config) (t : State) : (waitOn c t).hadNoData = t.hadNoData :=
  (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_openDatagrams (c : Config) (t : State) :
    (waitOn c t).openDatagrams = t.openDatagrams := (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.1
@[simp] theorem waitOn_openStreams (c : Config) (t : State) :
    (waitOn c t).openStreams = t.openStreams := (waitOn_fields c t).2.2.2.2.2.2.2.2.2.2.2.2.2.2.2.2

/-- The stage a later pass waits in: the one it starts in, or `awaitingTcp` under `useTcp` when an
open stream try of the name is at its server. -/
theorem waitOn_stage (c : Config) (t : State) :
    (waitOn c t).stage = t.stage ∨ (c.useTcp = true ∧ (waitOn c t).stage = .awaitingTcp) := by
  unfold waitOn; split
  · rename_i h; simp at h; exact Or.inr ⟨h.1, rfl⟩
  · exact Or.inl rfl

/-- A later pass that waits on an open stream try does not fail the lookup. -/
theorem waitOn_failed (c : Config) (t : State) (h : (waitOn c t).stage = .failed) :
    t.stage = .failed := by
  unfold waitOn at h; split at h <;> simp_all

@[simp] theorem closeTry_stage (s : State) (b : Bool) (p : Nat) : (closeTry s b p).stage = s.stage := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_server (s : State) (b : Bool) (p : Nat) : (closeTry s b p).server = s.server := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_round (s : State) (b : Bool) (p : Nat) : (closeTry s b p).round = s.round := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_candidate (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).candidate = s.candidate := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_hops (s : State) (b : Bool) (p : Nat) : (closeTry s b p).hops = s.hops := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_cause (s : State) (b : Bool) (p : Nat) : (closeTry s b p).cause = s.cause := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_datagrams (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).datagrams = s.datagrams := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_streams (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).streams = s.streams := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_edns (s : State) (b : Bool) (p : Nat) : (closeTry s b p).edns = s.edns := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_cookieRetried (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).cookieRetried = s.cookieRetried := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_offered (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).offered = s.offered := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_asks (s : State) (b : Bool) (p : Nat) : (closeTry s b p).asks = s.asks := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_authentic (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).authentic = s.authentic := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_secure (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).secure = s.secure := by unfold closeTry; split <;> rfl
@[simp] theorem closeTry_err (s : State) (b : Bool) (p : Nat) : (closeTry s b p).err = s.err := by
  unfold closeTry; split <;> rfl
@[simp] theorem closeTry_hadNoData (s : State) (b : Bool) (p : Nat) :
    (closeTry s b p).hadNoData = s.hadNoData := by unfold closeTry; split <;> rfl

/-- A message of an earlier try, read under validation: what `onReply` makes of it, with Stage B's
flag cleared, or the try closed with its server the cause, or the wait for keys. -/
theorem earlierChecked_of (c : Config) (t : State) (p : Nat) (stream : Bool) (r : Reply)
    (v : Verdict) (Q : State → Prop) (O : Out → Prop)
    (hon : Q (onReply c t stream r).1) (hout : O (onReply c t stream r).2) (hacc : O .accepted)
    (hsec : ∀ u, Q u → Q { u with secure := false })
    (hkeep : ∀ w, Q (keepAt t p w))
    (hkeys : t.asks < keyAsksMax → Q { t with stage := .awaitingKeys, asks := t.asks + 1 }) :
    Q (earlierChecked c t p stream r v).1 ∧ O (earlierChecked c t p stream r v).2 := by
  cases v <;> simp only [earlierChecked]
  · exact ⟨hon, hout⟩
  · exact ⟨hsec _ hon, hout⟩
  · exact ⟨hkeep _, hacc⟩
  · split
    · rename_i hlt; exact ⟨hkeys hlt, hacc⟩
    · exact ⟨hkeep _, hacc⟩

/-- A reply to an earlier try: what `onReply` makes of a reply the lookup acts on, from the state
with that try closed, with the flags cleared and the send handed out dropped, or the try closed
with its server the cause, or the lookup failed, or the wait for keys while the name has one left.
So a property of each holds of it. -/
theorem earlierHeard_acts_of (c : Config) (s : State) (p : Nat) (stream : Bool) (r : Reply)
    (ad : Bool) (v : Option Verdict) (Q : State → Prop) (O : Out → Prop)
    (hon : actsOn (stream || c.request) r = true →
      Q (onReply c (closeTry s stream p) (stream || c.request) r).1)
    (hout : actsOn (stream || c.request) r = true →
      O (onReply c (closeTry s stream p) (stream || c.request) r).2) (hacc : O .accepted)
    (hoff : ∀ u, Q u → Q { u with offered := false })
    (hclear : ∀ u, Q u → Q { u with authentic := false })
    (hsec : ∀ u, Q u → Q { u with secure := false })
    (hclose : Q (closeTry s stream p))
    (hkeep : ∀ w, Q (keepAt (closeTry s stream p) p w))
    (hfail : Q (fail (closeTry s stream p) .nameTooLong))
    (hkeys : s.asks < keyAsksMax →
      Q { closeTry s stream p with stage := .awaitingKeys, asks := s.asks + 1 }) :
    Q (earlierHeard c s p stream r ad v).1 ∧ O (earlierHeard c s p stream r ad v).2 := by
  have moved : ∀ q : State × Out, Q q.1 → O q.2 →
      Q (if q.1.stage = s.stage then q.1 else { q.1 with offered := false }) ∧ O q.2 := by
    intro q hq ho; refine ⟨?_, ho⟩; split
    · exact hq
    · exact hoff _ hq
  unfold earlierHeard
  dsimp only
  split
  · rename_i hact
    split
    · have e := earlierChecked_of c (closeTry s stream p) p (stream || c.request) r
        (v.getD .insecure) Q O (hon hact) (hout hact) hacc hsec hkeep
        (fun hlt => by simpa using hkeys (by simpa using hlt))
      exact moved _ e.1 e.2
    · exact moved (clear c true ad (onReply c (closeTry s stream p) (stream || c.request) r).1,
        (onReply c (closeTry s stream p) (stream || c.request) r).2)
        (clear_keeps Q c _ _ _ hclear (hon hact)) (hout hact)
  · refine ⟨?_, hacc⟩
    cases r <;> simp only [passed]
    all_goals first | exact hclose | exact hkeep _ | exact hfail

/-- `earlierHeard_acts_of` for a property that holds of every reply's `onReply`. -/
theorem earlierHeard_of (c : Config) (s : State) (p : Nat) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (Q : State → Prop) (O : Out → Prop)
    (hon : Q (onReply c (closeTry s stream p) (stream || c.request) r).1)
    (hout : O (onReply c (closeTry s stream p) (stream || c.request) r).2) (hacc : O .accepted)
    (hoff : ∀ u, Q u → Q { u with offered := false })
    (hclear : ∀ u, Q u → Q { u with authentic := false })
    (hsec : ∀ u, Q u → Q { u with secure := false })
    (hclose : Q (closeTry s stream p))
    (hkeep : ∀ w, Q (keepAt (closeTry s stream p) p w))
    (hfail : Q (fail (closeTry s stream p) .nameTooLong))
    (hkeys : Q { closeTry s stream p with stage := .awaitingKeys, asks := s.asks + 1 }) :
    Q (earlierHeard c s p stream r ad v).1 ∧ O (earlierHeard c s p stream r ad v).2 :=
  earlierHeard_acts_of c s p stream r ad v Q O (fun _ => hon) (fun _ => hout) hacc hoff hclear hsec
    hclose hkeep hfail (fun _ => hkeys)

@[simp] theorem keepAt_stage (s : State) (p : Nat) (w : What) : (keepAt s p w).stage = s.stage := rfl

theorem earlierFailed_stage (s : State) (p : Nat) (b : Bool) (r : Reason) :
    (earlierFailed s p b r).stage = s.stage := by
  unfold earlierFailed; split <;> simp [keepAt]

end Spec.Lookup
