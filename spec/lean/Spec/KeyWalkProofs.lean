import Spec.KeyWalk

/-!
# What the walk for keys guarantees

The theorems of docs/design.md §25's walk model (The models; step 12):

- `keys_chain`: whenever the store holds a zone's keys, there is a path from an anchor to that
  zone on which each DS set was validated under the keys of a zone above it, and each DNSKEY set
  matched a validated DS set or the anchor.
- `insecure_proven`: the store holds an insecure delegation only after a proof validated under
  keys it held, at a zone on such a path.
- `walk_bounded`: a walk that still asks has asked `chain_questions_max` questions at most, and
  each answer counts one, so it ends within that bound.

Each holds of every state that any sequence of walks and evictions reaches from the empty store.
-/
namespace Spec.KeyWalk

/-! ## Names on the target's path -/

theorem below_above (z t : Name) : above (below z t) t := List.take_prefix _ _

theorem below_length (z t : Name) (h : z.length < t.length) : (below z t).length = z.length + 1 := by
  simp [below, List.length_take]; omega

theorem strictly_below (z t : Name) (hz : above z t) (h : z.length < t.length) :
    strictlyAbove z (below z t) := by
  refine ⟨?_, by rw [below_length z t h]; omega⟩
  obtain ⟨u, rfl⟩ := hz
  simp only [below]
  rw [List.take_append, List.take_of_length_le (by omega)]
  exact List.prefix_append _ _

theorem prefix_trans_strict (y z w : Name) (h1 : strictlyAbove y z) (h2 : above z w) :
    strictlyAbove y w :=
  ⟨h1.1.trans h2, Nat.lt_of_lt_of_le h1.2 h2.length_le⟩

/-! ## The ghost backs every entry -/

theorem mem_add (l : List Name) (z x : Name) : x ∈ add l z ↔ x = z ∨ x ∈ l := by
  unfold add
  split
  · rename_i h
    constructor
    · intro hx; exact Or.inr hx
    · rintro (rfl | hx)
      · simpa using h
      · exact hx
  · simp

/-- Every entry the ghost holds rests on what the walk saw: a zone's keys on an anchor or a DS
set, a DS set and an insecure delegation on the keys of a zone above them. And the store holds
nothing the ghost does not. -/
def Backed (c : Config) (s : State) : Prop :=
  (∀ z ∈ s.proven.keys, z ∈ c.anchors ∨ z ∈ s.proven.ds) ∧
  (∀ z ∈ s.proven.ds, ∃ y ∈ s.proven.keys, strictlyAbove y z) ∧
  (∀ z ∈ s.proven.insecure, ∃ y ∈ s.proven.keys, strictlyAbove y z) ∧
  (∀ z ∈ s.store.keys, z ∈ s.proven.keys) ∧
  (∀ z ∈ s.store.ds, z ∈ s.proven.ds) ∧
  (∀ z ∈ s.store.insecure, z ∈ s.proven.insecure)

/-- What a walk that asks knows of where it stands: its probe lies on the target's path, and a DS
question's probe lies below the zone whose keys answer it. -/
def Shape (s : State) : Prop :=
  s.walk.phase = .asking →
    above s.walk.probe s.walk.target ∧ above s.walk.zone s.walk.target ∧
      (s.walk.asking = .ds → strictlyAbove s.walk.zone s.walk.probe)

def Good (c : Config) (s : State) : Prop := Backed c s ∧ Shape s

theorem init_good (c : Config) : Good c init := by
  refine ⟨⟨?_, ?_, ?_, ?_, ?_, ?_⟩, ?_⟩ <;> simp [init, Shape]

/-! ## No move breaks them -/

/-- A change of the walk alone keeps the store, the ghost and so `Backed`. -/
theorem backed_walk (c : Config) (s : State) (w : Walk) (h : Backed c s) :
    Backed c { s with walk := w } := h

theorem good_fail (c : Config) (s : State) (h : Backed c s) : Good c (fail s) :=
  ⟨h, fun hp => by simp [fail] at hp⟩

theorem good_finish (c : Config) (s : State) (h : Backed c s) : Good c (finish s) :=
  ⟨h, fun hp => by simp [finish] at hp⟩

/-- `next` keeps the invariants of a walk that stands in a zone on its target's path. -/
theorem next_good (c : Config) (s : State) (h : Backed c s) (hz : above s.walk.zone s.walk.target) :
    Good c (next s) := by
  unfold next
  split
  · exact good_finish c s h
  · split
    · exact good_fail c s h
    · rename_i _ hlen
      have hl : s.walk.zone.length < s.walk.target.length := by omega
      refine ⟨h, fun _ => ?_⟩
      simp only
      exact ⟨below_above _ _, hz, fun _ => strictly_below _ _ hz hl⟩

theorem deepest_above (zones : List Name) (t z : Name) (h : deepest zones t = some z) :
    z ∈ zones ∧ above z t := by
  unfold deepest at h
  have key : ∀ (l : List Name) (acc : Option Name),
      (∀ b, acc = some b → b ∈ zones ∧ above b t) →
      (∀ x ∈ l, x ∈ zones ∧ above x t) →
      ∀ r, l.foldl (fun best z => match best with
        | none => some z
        | some b => if b.length < z.length then some z else some b) acc = some r →
        r ∈ zones ∧ above r t := by
    intro l
    induction l with
    | nil => intro acc hacc _ r hr; exact hacc r hr
    | cons x xs ih =>
      intro acc hacc hl r hr
      simp only [List.foldl_cons] at hr
      refine ih _ ?_ (fun y hy => hl y (List.mem_cons_of_mem _ hy)) r hr
      intro b hb
      cases acc with
      | none => simp at hb; subst hb; exact hl x (List.mem_cons_self ..)
      | some a =>
        simp only at hb
        split at hb
        · simp at hb; subst hb; exact hl x (List.mem_cons_self ..)
        · simp at hb; subst hb; exact hacc a rfl
  refine key _ none (fun b hb => by simp at hb) (fun x hx => ?_) z h
  simp only [List.mem_filter, decide_eq_true_eq] at hx
  exact hx

theorem begin_good (c : Config) (s : State) (t : Name) (h : Backed c s) : Good c (begin c s t) := by
  unfold begin
  dsimp only
  split
  · rename_i z hz
    obtain ⟨_, ha⟩ := deepest_above _ _ _ hz
    exact next_good c _ h ha
  · split
    · rename_i a ha
      obtain ⟨_, hab⟩ := deepest_above _ _ _ ha
      exact ⟨h, fun _ => ⟨hab, hab, fun hd => by simp at hd⟩⟩
    · exact good_finish c _ h

/-- A DS set or an insecure delegation at the probe, which a zone whose keys the store holds and
which lies above it answered, keeps the ghost backed. -/
theorem backed_add_ds (c : Config) (s : State) (z : Name) (h : Backed c s) (y : Name)
    (hy : y ∈ s.store.keys) (hyz : strictlyAbove y z) :
    Backed c { s with store := { s.store with ds := add s.store.ds z },
                      proven := { s.proven with ds := add s.proven.ds z } } := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨fun x hx => ?_, fun x hx => ?_, h3, h4, fun x hx => ?_, h6⟩
  · rcases h1 x hx with ha | hd
    · exact Or.inl ha
    · exact Or.inr ((mem_add _ _ _).2 (Or.inr hd))
  · rcases (mem_add _ _ _).1 hx with rfl | hd
    · exact ⟨y, h4 y hy, hyz⟩
    · exact h2 x hd
  · rcases (mem_add _ _ _).1 hx with rfl | hd
    · exact (mem_add _ _ _).2 (Or.inl rfl)
    · exact (mem_add _ _ _).2 (Or.inr (h5 x hd))

theorem backed_add_insecure (c : Config) (s : State) (z : Name) (h : Backed c s) (y : Name)
    (hy : y ∈ s.store.keys) (hyz : strictlyAbove y z) :
    Backed c { s with store := { s.store with insecure := add s.store.insecure z },
                      proven := { s.proven with insecure := add s.proven.insecure z } } := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨h1, h2, fun x hx => ?_, h4, h5, fun x hx => ?_⟩
  · rcases (mem_add _ _ _).1 hx with rfl | hd
    · exact ⟨y, h4 y hy, hyz⟩
    · exact h3 x hd
  · rcases (mem_add _ _ _).1 hx with rfl | hd
    · exact (mem_add _ _ _).2 (Or.inl rfl)
    · exact (mem_add _ _ _).2 (Or.inr (h6 x hd))

/-- A DNSKEY set at `z`, which an anchor or a DS set the store holds names, keeps it backed. -/
theorem backed_add_keys (c : Config) (s : State) (z : Name) (h : Backed c s)
    (hz : z ∈ c.anchors ∨ z ∈ s.store.ds) :
    Backed c { s with store := { s.store with keys := add s.store.keys z },
                      proven := { s.proven with keys := add s.proven.keys z } } := by
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  refine ⟨fun x hx => ?_, fun x hx => ?_, fun x hx => ?_, fun x hx => ?_, h5, h6⟩
  · rcases (mem_add _ _ _).1 hx with rfl | hk
    · rcases hz with ha | hd
      · exact Or.inl ha
      · exact Or.inr (h5 x hd)
    · exact h1 x hk
  · obtain ⟨y, hy, hyx⟩ := h2 x hx
    exact ⟨y, (mem_add _ _ _).2 (Or.inr hy), hyx⟩
  · obtain ⟨y, hy, hyx⟩ := h3 x hx
    exact ⟨y, (mem_add _ _ _).2 (Or.inr hy), hyx⟩
  · rcases (mem_add _ _ _).1 hx with rfl | hk
    · exact (mem_add _ _ _).2 (Or.inl rfl)
    · exact (mem_add _ _ _).2 (Or.inr (h4 x hk))

theorem answered_good (c : Config) (s : State) (a : Answer) (g : Good c s)
    (hp : s.walk.phase = .asking) : Good c (answered c s a) := by
  obtain ⟨h, hs⟩ := g
  obtain ⟨hprobe, hzone, hds⟩ := hs hp
  unfold answered
  dsimp only
  split
  · exact good_fail c _ h
  split
  · exact good_fail c _ h
  rename_i _ hguard
  cases hw : s.walk.asking <;> cases a <;> simp only
  all_goals first
    | exact good_fail c _ h
    | skip
  · -- A DS set.
    have hk : s.walk.zone ∈ s.store.keys := by simpa [hw] using hguard
    refine ⟨backed_add_ds c _ _ h _ hk (hds hw), fun _ => ?_⟩
    exact ⟨hprobe, hzone, fun hd => by simp at hd⟩
  · -- No delegation: the next label.
    split
    · exact good_fail c _ h
    · rename_i hlen
      refine ⟨h, fun _ => ⟨below_above _ _, hzone, fun _ => ?_⟩⟩
      exact prefix_trans_strict _ _ _ (hds hw) (strictly_below _ _ hprobe (by omega)).1
  · -- An answer that proves nothing: the next label, as for no delegation.
    split
    · exact good_fail c _ h
    · rename_i hlen
      refine ⟨h, fun _ => ⟨below_above _ _, hzone, fun _ => ?_⟩⟩
      exact prefix_trans_strict _ _ _ (hds hw) (strictly_below _ _ hprobe (by omega)).1
  · -- An unsigned delegation.
    have hk : s.walk.zone ∈ s.store.keys := by simpa [hw] using hguard
    exact good_finish c _ (backed_add_insecure c _ _ h _ hk (hds hw))
  · -- A DNSKEY set.
    split
    · rename_i hbasis
      have hz : s.walk.probe ∈ c.anchors ∨ s.walk.probe ∈ s.store.ds := by simpa using hbasis
      exact next_good c _ (backed_add_keys c _ _ h hz) hprobe
    · exact good_fail c _ h

theorem step_good (c : Config) (s : State) (e : Event) (g : Good c s) : Good c (step c s e) := by
  obtain ⟨h, hs⟩ := g
  obtain ⟨h1, h2, h3, h4, h5, h6⟩ := h
  cases e with
  | answer a =>
    simp only [step]
    split
    · rename_i hp; exact answered_good c s a ⟨⟨h1, h2, h3, h4, h5, h6⟩, hs⟩ hp
    · exact ⟨⟨h1, h2, h3, h4, h5, h6⟩, hs⟩
  | evictKeys z =>
    exact ⟨⟨h1, h2, h3, fun x hx => h4 x (List.mem_of_mem_erase hx), h5, h6⟩, hs⟩
  | evictDs z =>
    exact ⟨⟨h1, h2, h3, h4, fun x hx => h5 x (List.mem_of_mem_erase hx), h6⟩, hs⟩
  | evictInsecure z =>
    exact ⟨⟨h1, h2, h3, h4, h5, fun x hx => h6 x (List.mem_of_mem_erase hx)⟩, hs⟩

/-- Every state that walks and evictions reach from the empty store keeps the invariants. -/
theorem run_good (c : Config) (es : List (Option Name ⊕ Event)) : Good c (run c init es) := by
  have key : ∀ (es : List (Option Name ⊕ Event)) (s : State), Good c s → Good c (run c s es) := by
    intro es
    induction es with
    | nil => intro s g; exact g
    | cons e rest ih =>
      intro s g
      rcases e with (_ | t) | e
      · exact ih s g
      · simp only [run]
        split
        · exact ih s g
        · exact ih _ (begin_good c s t g.1)
      · exact ih _ (step_good c s e g)
  exact key es init (init_good c)

/-! ## The theorems -/

/-- A path of trust to `z` within the ghost `p`: `z` is an anchor, or its DS set was validated
under the keys of a zone above it, itself at the end of such a path (§25, The models). -/
inductive Chain (c : Config) (p : Entries) : Name → Prop
  | anchor {z : Name} : z ∈ c.anchors → Chain c p z
  | link {y z : Name} : Chain c p y → y ∈ p.keys → strictlyAbove y z → z ∈ p.ds → Chain c p z

theorem chain_of_backed (c : Config) (s : State) (h : Backed c s) :
    ∀ z, z ∈ s.proven.keys → Chain c s.proven z
  | z, hz =>
    match h.1 z hz with
    | .inl ha => .anchor ha
    | .inr hd =>
      match h.2.1 z hd with
      | ⟨y, hy, hyz⟩ =>
        have : y.length < z.length := hyz.2
        .link (chain_of_backed c s h y hy) hy hyz hd
termination_by z => z.length

/-- Whenever the store holds a zone's keys, there is a path from an anchor to that zone on which
each DS set was validated under the keys of a zone above it and each DNSKEY set matched a
validated DS set, whatever the servers answered and whatever the store lost (§25, The models). -/
theorem keys_chain (c : Config) (es : List (Option Name ⊕ Event)) (z : Name)
    (hz : z ∈ (run c init es).store.keys) : Chain c (run c init es).proven z := by
  have g := run_good c es
  exact chain_of_backed c _ g.1 z (g.1.2.2.2.1 z hz)

/-- The store holds an insecure delegation only after a proof validated under keys it held, of a
zone above it at the end of a path of trust (§25, The models). -/
theorem insecure_proven (c : Config) (es : List (Option Name ⊕ Event)) (z : Name)
    (hz : z ∈ (run c init es).store.insecure) :
    ∃ y, strictlyAbove y z ∧ Chain c (run c init es).proven y := by
  have g := run_good c es
  obtain ⟨y, hy, hyz⟩ := g.1.2.2.1 z (g.1.2.2.2.2.2 z hz)
  exact ⟨y, hyz, chain_of_backed c _ g.1 y hy⟩

/-- A walk that still asks has asked `questionsMax` questions at most. -/
def Bounded (c : Config) (s : State) : Prop :=
  s.walk.phase = .asking → s.walk.questions ≤ c.questionsMax

theorem next_questions (s : State) : (next s).walk.questions = s.walk.questions := by
  unfold next; split
  · rfl
  · split <;> rfl

theorem next_phase (s : State) (h : (next s).walk.phase = .asking) : s.walk.phase = .asking := by
  unfold next at h; split at h
  · simp [finish] at h
  · split at h
    · simp [fail] at h
    · exact h

/-- Each answer counts one question, whatever it moves the walk to. -/
theorem answered_questions (c : Config) (s : State) (a : Answer) :
    (answered c s a).walk.questions = s.walk.questions + 1 := by
  unfold answered
  dsimp only
  split
  · simp [fail]
  split
  · simp [fail]
  cases s.walk.asking <;> cases a <;> simp only
  all_goals (try split) <;> simp [fail, finish, next_questions]

/-- An answer past `questionsMax` fails the walk. -/
theorem answered_past (c : Config) (s : State) (a : Answer) (h : s.walk.questions + 1 > c.questionsMax) :
    (answered c s a).walk.phase = .failed := by
  unfold answered
  simp [h, fail]

theorem answered_bounded (c : Config) (s : State) (a : Answer) :
    Bounded c (answered c s a) := by
  intro hp
  rw [answered_questions]
  by_cases h : s.walk.questions + 1 > c.questionsMax
  · rw [answered_past c s a h] at hp; simp at hp
  · omega

theorem begin_questions (c : Config) (s : State) (t : Name) : (begin c s t).walk.questions = 0 := by
  unfold begin
  dsimp only
  split
  · rw [next_questions]
  · split <;> simp [finish]

theorem begin_bounded (c : Config) (s : State) (t : Name) : Bounded c (begin c s t) := by
  intro _
  rw [begin_questions]
  omega

/-- A walk that still asks has asked `chain_questions_max` questions at most, whatever the servers
answer, and each answer to a walk that asks counts one, so a walk ends within that many answers
(§25, walk rule 10). -/
theorem walk_bounded (c : Config) (es : List (Option Name ⊕ Event)) :
    Bounded c (run c init es) := by
  have key : ∀ (es : List (Option Name ⊕ Event)) (s : State), Bounded c s → Bounded c (run c s es) := by
    intro es
    induction es with
    | nil => intro s b; exact b
    | cons e rest ih =>
      intro s b
      rcases e with (_ | t) | e
      · exact ih s b
      · simp only [run]
        split
        · exact ih s b
        · exact ih _ (begin_bounded c s t)
      · refine ih _ ?_
        cases e with
        | answer a =>
          simp only [step]
          split
          · exact answered_bounded c s a
          · exact b
        | evictKeys _ | evictDs _ | evictInsecure _ => exact b
  exact key es init (fun hp => by simp [init] at hp)

theorem answer_counts (c : Config) (s : State) (a : Answer) (hp : s.walk.phase = .asking) :
    (step c s (.answer a)).walk.questions = s.walk.questions + 1 := by
  simp only [step, hp, if_true]
  exact answered_questions c s a

end Spec.KeyWalk
