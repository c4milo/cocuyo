import Spec.LookupProofs.Timeout

/-!
# Three queries of one name to one server over one transport

"A resolver MUST NOT retry a given query to a server address over a given DNS transport more than
twice (i.e., three queries in total)" (RFC 9520 §3.1). `Config.attempts` counts the passes over
the servers, and FORMERR and BADCOOKIE each add a retry inside a pass. So the lookup counts the
queries that each server got for the current name over each transport, and asks no server again
over a transport where its count is at `queriesMax` (docs/design.md §5, retry policy; §16
decision 58). The proof shows that no count passes `queriesMax`, whatever the caller tells the
lookup.
-/
namespace Spec.Lookup

/-- Whether a stage's query goes on a stream: the stages before a send over TCP. -/
def streamStage : Stage → Bool
  | .tcpNeeded | .connectingTcp | .tcpReady => true
  | _ => false

/-- The stages that come before a send: the lookup sends its server a query from each of them,
unless the next server or the end comes first. -/
def beforeSend (s : Stage) : Prop :=
  s = .queryReady ∨ s = .tcpNeeded ∨ s = .connectingTcp ∨ s = .tcpReady

/-- What the bound needs of a state: no count passes `queriesMax`, and a lookup that comes before
a send has a query left for its server over the transport of that send. -/
def Bounded (s : State) : Prop :=
  (∀ p, sentTo s false p ≤ queriesMax ∧ sentTo s true p ≤ queriesMax) ∧
    (beforeSend s.stage → spent s (streamStage s.stage) = false)

theorem streamStage_fresh (c : Config) : streamStage (fresh c) = c.useTcp := by
  unfold fresh; cases c.useTcp <;> rfl

theorem unsent_zero (c : Config) (p : Nat) : (unsent c).getD p 0 = 0 := by
  simp [unsent, List.getD_eq_getElem?_getD, List.getElem?_replicate]
  split <;> rfl

theorem sentTo_unsent (s : State) (c : Config) (hd : s.datagrams = unsent c)
    (hs : s.streams = unsent c) (b : Bool) (p : Nat) : sentTo s b p = 0 := by
  unfold sentTo
  cases b <;> simp only [hd, hs, ↓reduceIte, Bool.false_eq_true] <;> exact unsent_zero c p

/-- A new name has no query sent to any server, so each count is zero. -/
theorem bounded_unsent (s : State) (c : Config) (hd : s.datagrams = unsent c)
    (hs : s.streams = unsent c) : Bounded s := by
  refine ⟨fun p => ?_, fun _ => ?_⟩
  · simp only [sentTo_unsent s c hd hs, queriesMax]; omega
  · simp only [spent, sentTo_unsent s c hd hs, queriesMax]; decide

/-- The next server leaves the counts as they were, and stands on a server with a query left over
the transport it starts on, or ends the lookup (RFC 9520 §3.1). -/
theorem advanceServer_ready (c : Config) (s : State) :
    (advanceServer c s).stage = .failed ∨
      ((advanceServer c s).stage = fresh c ∧ spent (advanceServer c s) c.useTcp = false) := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

theorem advanceServer_bounded (c : Config) (s : State) (h : Bounded s) :
    Bounded (advanceServer c s) := by
  obtain ⟨_, _, hd, hs⟩ := advanceServer_counts c s
  refine ⟨fun p => ?_, fun hb => ?_⟩
  · have := h.1 p
    simp only [sentTo, hd, hs] at this ⊢
    exact this
  · rcases advanceServer_ready c s with hf | ⟨hf, hsp⟩
    · simp [beforeSend, hf] at hb
    · rw [hf, streamStage_fresh]; exact hsp

theorem keep_bounded (s : State) (w : What) (h : Bounded s) : Bounded (keep s w) := h

theorem fail_bounded (s : State) (e : Err) (h : Bounded s) : Bounded (fail s e) :=
  ⟨h.1, fun hb => by simp [fail, beforeSend] at hb⟩

/-- A state with the counts and the server of `s` and a stage of the same transport. -/
theorem bounded_same (s t : State) (h : Bounded s) (hd : t.datagrams = s.datagrams)
    (hs : t.streams = s.streams) (hp : t.server = s.server)
    (hb : beforeSend t.stage → spent s (streamStage t.stage) = false) : Bounded t := by
  refine ⟨fun p => ?_, fun b => ?_⟩
  · have := h.1 p
    simp only [sentTo, hd, hs] at this ⊢
    exact this
  · have := hb b
    simp only [spent, sentTo, hd, hs, hp] at this ⊢
    exact this

/-- A retry asks the same server again only when it has a query left over the retry's transport. -/
theorem retry_bounded (c : Config) (s t : State) (b : Bool) (w : Option What) (h : Bounded s)
    (hd : t.datagrams = s.datagrams) (hs : t.streams = s.streams) (hp : t.server = s.server)
    (hb : streamStage t.stage = b) : Bounded (retry c s t b w) := by
  unfold retry
  split
  · cases w with
    | none => exact advanceServer_bounded c s h
    | some k => exact advanceServer_bounded c _ (keep_bounded s k h)
  · rename_i hsp
    exact bounded_same s t h hd hs hp (fun _ => by rw [hb]; simpa using hsp)

theorem nextCandidate_bounded (c : Config) (s : State) (b : Bool) (h : Bounded s) :
    Bounded (nextCandidate c s b) := by
  unfold nextCandidate
  dsimp only
  split
  · exact bounded_unsent _ c rfl rfl
  · exact fail_bounded _ _ h

theorem poll_bounded (c : Config) (s : State) (h : Bounded s) : Bounded (poll c s).1 := by
  unfold poll
  cases hs : s.stage <;> simp only
  all_goals first
    | exact h
    | exact bounded_same s _ h rfl rfl rfl (fun _ => by simpa [hs, streamStage] using h.2 (by simp [beforeSend, hs]))
    | exact bounded_same s _ h rfl rfl rfl (fun hb => by simp [beforeSend] at hb)
    | exact bounded_same s _ h rfl rfl rfl (fun _ => by simpa [hs] using h.2 (by simp [beforeSend, hs]))

theorem onReply_bounded (c : Config) (s : State) (stream : Bool) (r : Reply) (h : Bounded s) :
    Bounded (onReply c s stream r).1 := by
  have hadv : ∀ w, Bounded (advanceServer c (keep s w)) :=
    fun w => advanceServer_bounded c _ (keep_bounded s w h)
  cases r with
  | unmatched => exact h
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_bounded c s true h
    · exact retry_bounded c s _ _ _ h rfl rfl rfl rfl
  | answer => exact bounded_same s _ h rfl rfl rfl (fun hb => by simp [onReply, beforeSend] at hb)
  | cname =>
    simp only [onReply]
    split
    · exact fail_bounded _ _ h
    · exact bounded_unsent _ c rfl rfl
  | nxdomain => exact nextCandidate_bounded c s false h
  | nodata => exact nextCandidate_bounded c s true h
  | yxdomain => exact fail_bounded s .nameTooLong h
  | servfail => exact hadv _
  | formerr =>
    simp only [onReply]
    split
    · exact retry_bounded c s _ _ _ h rfl rfl rfl (streamStage_fresh c)
    · exact hadv _
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact hadv _
      · exact retry_bounded c s _ _ _ h rfl rfl rfl rfl
    · split
      · exact retry_bounded c s _ _ _ h rfl rfl rfl rfl
      · exact retry_bounded c s _ _ _ h rfl rfl rfl (streamStage_fresh c)

/-- One more query sent to the server at `p`, which had fewer than `queriesMax`. -/
theorem bump_le (l : List Nat) (p q : Nat) (hl : ∀ q, l.getD q 0 ≤ queriesMax)
    (hp : l.getD p 0 < queriesMax) : (bump l p).getD q 0 ≤ queriesMax := by
  have hq := hl q
  simp only [bump, List.getD_eq_getElem?_getD, List.getElem?_set] at hp hq ⊢
  split
  · split <;> simp_all <;> omega
  · exact hq

/-- No event breaks the bound. -/
theorem step_bounded (c : Config) (s : State) (e : Event) (h : Bounded s) :
    Bounded (step c s e).1 := by
  cases e with
  | poll => exact poll_bounded c s h
  | expire =>
    simp only [step]
    split
    · exact poll_bounded c _ (advanceServer_bounded c s h)
    · exact poll_bounded c s h
  | sent =>
    cases hs : s.stage <;> simp only [step, hs]
    all_goals first
      | exact h
      | skip
    · have hp := h.2 (by simp [beforeSend, hs])
      simp only [hs, streamStage, spent, sentTo, decide_eq_false_iff_not, Nat.not_le] at hp
      refine ⟨fun q => ⟨?_, (h.1 q).2⟩, fun hb => by simp [beforeSend] at hb⟩
      exact bump_le _ _ _ (fun q => (h.1 q).1) hp
    · have hp := h.2 (by simp [beforeSend, hs])
      simp only [hs, streamStage, spent, sentTo, decide_eq_false_iff_not, Nat.not_le] at hp
      refine ⟨fun q => ⟨(h.1 q).1, ?_⟩, fun hb => by simp [beforeSend] at hb⟩
      exact bump_le _ _ _ (fun q => (h.1 q).2) hp
  | sendFailed =>
    cases hs : s.stage <;> simp only [step, hs] <;>
      first | exact advanceServer_bounded c s h | exact h
  | tcpConnected =>
    cases hs : s.stage <;> simp only [step, hs]
    all_goals first
      | exact h
      | exact bounded_same s _ h rfl rfl rfl
          (fun _ => by simpa [hs, streamStage] using h.2 (by simp [beforeSend, hs]))
  | tcpFailed _ =>
    simp only [step]
    split
    · exact advanceServer_bounded c _ (keep_bounded s _ h)
    · exact h
  | requestFailed _ =>
    simp only [step]
    split
    · exact advanceServer_bounded c _ (keep_bounded s _ h)
    · exact h
  | reply r | replyAd r =>
    cases hs : s.stage <;> simp only [step, heard, clear, hs] <;> try split
    all_goals first
      | exact onReply_bounded c s _ r h
      | exact h
  | cancel =>
    simp only [step]
    split
    · exact h
    · exact fail_bounded s _ h

theorem init_bounded (c : Config) : Bounded (init c) := by
  unfold init
  split
  · exact fail_bounded _ _ (bounded_unsent _ c rfl rfl)
  · exact bounded_unsent _ c rfl rfl

/-- No server gets more than `queriesMax` queries of one name over one transport, whatever the
caller tells the lookup and whatever `Config.attempts` says (RFC 9520 §3.1; docs/design.md §16
decision 58). -/
theorem sends_bounded (c : Config) (es : List Event) (p : Nat) :
    sentTo (run c (init c) es) false p ≤ queriesMax ∧
      sentTo (run c (init c) es) true p ≤ queriesMax := by
  have key : ∀ (es : List Event) (t : State), Bounded t → Bounded (run c t es) := by
    intro es
    induction es with
    | nil => intro t h; exact h
    | cons e rest ih => intro t h; exact ih _ (step_bounded c t e h)
  exact (key es _ (init_bounded c)).1 p

end Spec.Lookup
