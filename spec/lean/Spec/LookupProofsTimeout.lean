import Spec.LookupProofs

/-!
# What `Timeout` means

`Timeout` promises that every try went unanswered (docs/design.md §5, retry policy; §16
decision 25). Stated the other way round, which the model can prove: a lookup that a server
refused never ends in `timeout`, whatever it hears afterwards. A refusal is a connection or a
handshake that failed while the lookup was on a stream, or a request over DoH or DoQ that ended
without an answer. The proof carries a mark, `Marked`, from the refusal to the end.
-/
namespace Spec.Lookup

/-- An event that is a server refusing the lookup, delivered while the lookup can take it. -/
def Refusal (c : Config) (s : State) (e : Event) : Prop :=
  (e = .tcpFailed ∧ onStream s.stage = true) ∨
    (e = .requestFailed ∧ c.request = true ∧ s.stage = .awaitingUdp)

/-- A lookup a server failed: the flag that decides the failure is set, and a lookup that has
failed did not fail with `timeout`. -/
def Marked (s : State) : Prop := s.serverFailed = true ∧ (s.stage = .failed → s.err ≠ .timeout)

/-- The states a list of events leads a lookup through, one after the other. -/
def run (c : Config) (s : State) : List Event → State
  | [] => s
  | e :: es => run c (step c s e).1 es

theorem fresh_ne_failed (c : Config) : fresh c ≠ .failed := by
  unfold fresh; split <;> simp

theorem marked_advanceServer (c : Config) (s : State) (h : s.serverFailed = true) :
    Marked (advanceServer c s) := by
  unfold advanceServer
  split
  · exact ⟨h, fun hf => absurd hf (fresh_ne_failed c)⟩
  · split
    · exact ⟨h, fun hf => absurd hf (fresh_ne_failed c)⟩
    · simp [Marked, fail, h]

theorem marked_nextCandidate (c : Config) (s : State) (b : Bool) (h : s.serverFailed = true) :
    Marked (nextCandidate c s b) := by
  unfold nextCandidate
  dsimp only
  split
  · exact ⟨h, fun hf => absurd hf (fresh_ne_failed c)⟩
  · refine ⟨h, fun _ => ?_⟩
    simp only [fail]
    split <;> simp

theorem marked_poll (c : Config) (s : State) (m : Marked s) : Marked (poll c s).1 := by
  obtain ⟨h, ht⟩ := m
  unfold poll
  cases hs : s.stage <;> simp_all [Marked]

theorem marked_onReply (c : Config) (s : State) (stream : Bool) (r : Reply) (m : Marked s)
    (hs : s.stage ≠ .failed) : Marked (onReply c s stream r).1 := by
  obtain ⟨h, _⟩ := m
  have hadv : ∀ t : State, t.serverFailed = true → Marked (advanceServer c t) :=
    marked_advanceServer c
  cases r with
  | unmatched => exact ⟨h, fun hf => absurd hf hs⟩
  | truncated =>
    simp only [onReply]
    split
    · exact marked_nextCandidate c s true h
    · exact ⟨h, fun hf => absurd hf (by simp)⟩
  | answer => exact ⟨h, fun hf => absurd hf (by simp [onReply])⟩
  | cname =>
    simp only [onReply]
    split
    · exact ⟨h, fun _ => by simp [fail]⟩
    · exact ⟨h, fun hf => absurd hf (fresh_ne_failed c)⟩
  | nxdomain => exact marked_nextCandidate c s false h
  | nodata => exact marked_nextCandidate c s true h
  | servfail => exact hadv _ rfl
  | formerr =>
    simp only [onReply]
    split
    · exact ⟨h, fun hf => absurd hf (fresh_ne_failed c)⟩
    · exact hadv _ rfl
  | badcookie =>
    simp only [onReply]
    split
    · exact hadv _ rfl
    · split
      · exact ⟨h, fun hf => absurd hf (by simp)⟩
      · exact ⟨h, fun hf => absurd hf (fresh_ne_failed c)⟩

/-- A marked lookup stays marked, whatever the caller tells it. -/
theorem marked_step (c : Config) (s : State) (e : Event) (m : Marked s) :
    Marked (step c s e).1 := by
  by_cases hend : ended s.stage = true
  · rw [ended_absorbing c s e hend]; exact m
  have hs : s.stage ≠ .failed := fun hf => hend (by simp [ended, hf])
  obtain ⟨h, ht⟩ := m
  have hadv : ∀ t : State, t.serverFailed = true → Marked (advanceServer c t) :=
    marked_advanceServer c
  cases e with
  | poll => exact marked_poll c s ⟨h, ht⟩
  | expire =>
    simp only [step]
    split
    · exact marked_poll c _ (hadv s h)
    · exact marked_poll c s ⟨h, ht⟩
  | sent => cases hst : s.stage <;> simp_all [step, Marked]
  | sendFailed =>
    cases hst : s.stage <;> simp only [step, hst] <;>
      first | exact hadv s h | exact ⟨h, ht⟩
  | tcpConnected => cases hst : s.stage <;> simp_all [step, Marked]
  | tcpFailed =>
    simp only [step]
    split
    · exact hadv _ rfl
    · exact ⟨h, ht⟩
  | requestFailed =>
    simp only [step]
    split
    · exact hadv _ rfl
    · exact ⟨h, ht⟩
  | reply r =>
    cases hst : s.stage <;> simp only [step, hst]
    all_goals first
      | exact marked_onReply c s _ r ⟨h, ht⟩ hs
      | exact ⟨h, ht⟩
  | cancel =>
    simp only [step]
    split
    · exact ⟨h, ht⟩
    · exact ⟨h, fun _ => by simp [fail]⟩

/-- A refusal marks the lookup. -/
theorem refusal_marks (c : Config) (s : State) (e : Event) (r : Refusal c s e) :
    Marked (step c s e).1 := by
  rcases r with ⟨he, hs⟩ | ⟨he, hc, hs⟩
  · subst he; simp only [step, hs]; exact marked_advanceServer c _ rfl
  · subst he; simp only [step, hc, hs]; exact marked_advanceServer c _ rfl

/-- A lookup that a server refused, its connection, its handshake or its request failing, never
ends in `timeout`, whatever it hears afterwards (§5, retry policy; §16 decision 25). -/
theorem refused_never_timeout (c : Config) (s : State) (e : Event) (es : List Event)
    (r : Refusal c s e) (hf : (run c (step c s e).1 es).stage = .failed) :
    (run c (step c s e).1 es).err ≠ .timeout := by
  have key : ∀ (es : List Event) (t : State), Marked t → Marked (run c t es) := by
    intro es
    induction es with
    | nil => intro t m; exact m
    | cons e' rest ih => intro t m; exact ih _ (marked_step c t e' m)
  exact (key es _ (refusal_marks c s e r)).2 hf

end Spec.Lookup
