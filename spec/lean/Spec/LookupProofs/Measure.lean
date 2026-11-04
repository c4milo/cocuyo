import Spec.LookupProofs

/-!
# A lookup cannot retry forever

The measure every send lowers and nothing raises, and the counters it reads staying inside the
configuration: properties docs/design.md §5 promises of `Lookup`, proved of the model. Split
from `Spec.LookupProofs` by the file-length rule.
-/
namespace Spec.Lookup

/-! ## A lookup cannot retry forever

Every send lowers a measure that nothing raises: the search candidates left, then the CNAME hops
left, then the passes over the servers left, then the servers left in this pass, then the sends
left to this server in this transaction. The last counts what one server can still be asked: a
datagram and then, after TC=1, the stream, each once with EDNS0 and once more without it after
FORMERR (§5's table), and once more after a first BADCOOKIE (RFC 7873 §5.3). Compared lexicographically, the measure lives in a well-founded order, so a
lookup makes finitely many sends whatever its servers answer (§5, retry policy). -/

/-- The sends a stage has left before the lookup must hear back: a query still to send over UDP
counts two, one for the datagram and one for the stream TC=1 can send it to. A wait for keys
counts six, more than the rest of a server's phase can hold, so the query asked again when the
keys come lowers it. -/
def stagePhase : Stage → Nat
  | .queryReady => 2
  | .awaitingUdp | .tcpNeeded | .connectingTcp | .tcpReady => 1
  | .awaitingTcp | .done | .failed => 0
  | .awaitingKeys => 6

/-- The sends left to the current server in this transaction. Each wait for keys left for the name
counts seven, more than a wait itself, so entering one lowers it (docs/design.md §25, step 11). -/
def phase (s : State) : Nat :=
  7 * (keyAsksMax - s.asks) + (if s.edns then 2 else 0) + (if s.cookieRetried then 0 else 1) +
    stagePhase s.stage

def measure (c : Config) (s : State) : Nat × Nat × Nat × Nat × Nat :=
  (c.candidates - s.candidate, c.hopsMax + 1 - s.hops, c.attempts - s.round,
   c.servers - s.server, phase s)

def LexLe : Nat × Nat × Nat × Nat × Nat → Nat × Nat × Nat × Nat × Nat → Prop
  | (a1, a2, a3, a4, a5), (b1, b2, b3, b4, b5) =>
    a1 < b1 ∨ (a1 = b1 ∧ (a2 < b2 ∨ (a2 = b2 ∧ (a3 < b3 ∨ (a3 = b3 ∧
      (a4 < b4 ∨ (a4 = b4 ∧ a5 ≤ b5)))))))

def LexLt : Nat × Nat × Nat × Nat × Nat → Nat × Nat × Nat × Nat × Nat → Prop
  | (a1, a2, a3, a4, a5), (b1, b2, b3, b4, b5) =>
    a1 < b1 ∨ (a1 = b1 ∧ (a2 < b2 ∨ (a2 = b2 ∧ (a3 < b3 ∨ (a3 = b3 ∧
      (a4 < b4 ∨ (a4 = b4 ∧ a5 < b5)))))))

/-- While a lookup runs, its counters stay inside its configuration. -/
def Good (c : Config) (s : State) : Prop :=
  ended s.stage = true ∨
    (s.server < c.servers ∧ s.round < c.attempts ∧ s.candidate < c.candidates ∧ s.hops ≤ c.hopsMax)

/-- A configuration a lookup can run under: a server, an attempt and a name to ask. -/
def Sane (c : Config) : Prop := 1 ≤ c.servers ∧ 1 ≤ c.attempts ∧ 1 ≤ c.candidates

theorem lexLe_refl (a : Nat × Nat × Nat × Nat × Nat) : LexLe a a := by
  obtain ⟨a1, a2, a3, a4, a5⟩ := a
  simp [LexLe]

theorem phase_ended_le (s : State) (e : Err) : phase (fail s e) ≤ phase s := by
  unfold phase fail
  cases s.edns <;> cases s.cookieRetried <;> cases s.stage <;> simp [stagePhase]

theorem phase_done_le (s : State) : phase { s with stage := .done } ≤ phase s := by
  unfold phase
  cases s.edns <;> cases s.cookieRetried <;> cases s.stage <;> simp [stagePhase]

/-- A step that moves no counter and does not raise the sends left leaves the measure no higher. -/
theorem lexLe_of_phase (c : Config) (s t : State) (h1 : t.candidate = s.candidate)
    (h2 : t.hops = s.hops) (h3 : t.round = s.round) (h4 : t.server = s.server)
    (hp : phase t ≤ phase s) : LexLe (measure c t) (measure c s) := by
  simp only [measure, LexLe]
  omega

theorem lexLt_trans (a b d : Nat × Nat × Nat × Nat × Nat) (h1 : LexLt a b) (h2 : LexLt b d) :
    LexLt a d := by
  obtain ⟨a1, a2, a3, a4, a5⟩ := a
  obtain ⟨b1, b2, b3, b4, b5⟩ := b
  obtain ⟨d1, d2, d3, d4, d5⟩ := d
  simp only [LexLt] at h1 h2 ⊢
  omega

/-- The next server lowers the measure, and so does each server it passes over (RFC 9520 §3.1). -/
theorem advanceServer_lt (c : Config) (s : State) (h : s.round < c.attempts) :
    LexLt (measure c (advanceServer c s)) (measure c s) := by
  revert h
  fun_induction advanceServer c s <;> intro h
  · rename_i ih
    exact lexLt_trans _ _ _ (ih h) (by simp +zetaDelta [measure, LexLt]; omega)
  · simp +zetaDelta [measure, LexLt]; omega
  · rename_i ih
    exact lexLt_trans _ _ _ (ih (by simp +zetaDelta; omega))
      (by simp +zetaDelta [measure, LexLt]; omega)
  · simp +zetaDelta [measure, LexLt]; omega
  · simp [measure, LexLt, fail]; omega

theorem nextCandidate_le (c : Config) (s : State) (b : Bool) :
    LexLe (measure c (nextCandidate c s b)) (measure c s) := by
  unfold nextCandidate
  dsimp only
  split
  · simp [measure, LexLe]; omega
  · simp [measure, LexLe, phase, stagePhase, fail]

theorem lexLt_le (a b : Nat × Nat × Nat × Nat × Nat) (h : LexLt a b) : LexLe a b := by
  obtain ⟨a1, a2, a3, a4, a5⟩ := a
  obtain ⟨b1, b2, b3, b4, b5⟩ := b
  simp only [LexLt, LexLe] at h ⊢
  omega

theorem lexLe_trans (a b d : Nat × Nat × Nat × Nat × Nat) (h1 : LexLe a b) (h2 : LexLe b d) :
    LexLe a d := by
  obtain ⟨a1, a2, a3, a4, a5⟩ := a
  obtain ⟨b1, b2, b3, b4, b5⟩ := b
  obtain ⟨d1, d2, d3, d4, d5⟩ := d
  simp only [LexLe] at h1 h2 ⊢
  omega

theorem poll_le (c : Config) (s : State) : LexLe (measure c (poll c s).1) (measure c s) := by
  unfold poll
  cases hs : s.stage <;> simp [measure, LexLe, phase, stagePhase, hs]

theorem onReply_le (c : Config) (s : State) (stream : Bool) (r : Reply) (g : s.round < c.attempts)
    (_hh : s.hops ≤ c.hopsMax) (hst : stream = false → s.stage = .awaitingUdp) :
    LexLe (measure c (onReply c s stream r).1) (measure c s) := by
  -- A retry that the bound forbids moves on as the next server does (RFC 9520 §3.1).
  have hretry : ∀ (t : State) (b : Bool) (w : Option What),
      LexLe (measure c t) (measure c s) → LexLe (measure c (retry c s t b w)) (measure c s) := by
    intro t b w ht
    refine retry_of c s t b w (fun x => LexLe (measure c x) (measure c s)) ht (fun u hu => ?_)
    rcases hu with rfl | ⟨k, rfl⟩
    · exact lexLt_le _ _ (advanceServer_lt c _ g)
    · exact lexLt_le _ _ (advanceServer_lt c _ g)
  cases r with
  | unmatched => exact lexLe_refl _
  | truncated =>
    cases stream
    · have hs := hst rfl
      simp only [onReply]
      exact hretry _ _ _ (by simp [measure, LexLe, phase, stagePhase, hs])
    · exact nextCandidate_le c s true
  | answer => exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_done_le s)
  | cname =>
    simp only [onReply]
    split
    · exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_ended_le s .chainTooLong)
    · simp [measure, LexLe]; omega
  | nxdomain => exact nextCandidate_le c s false
  | nodata => exact nextCandidate_le c s true
  | yxdomain => exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_ended_le s .nameTooLong)
  | servfail => exact lexLt_le _ _ (advanceServer_lt c _ g)
  | formerr =>
    simp only [onReply]
    split
    · rename_i he'
      have he : s.edns = true := by revert he'; cases s.edns <;> simp
      refine hretry _ _ _ ?_
      simp only [measure, LexLe, phase, he, fresh]
      cases s.cookieRetried <;> cases c.useTcp <;> cases s.stage <;> simp [stagePhase]
    · exact lexLt_le _ _ (advanceServer_lt c _ g)
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact lexLt_le _ _ (advanceServer_lt c _ g)
      · -- The retry over the stream spends the server's one retry for the stream's send.
        rename_i hr
        have hk : s.cookieRetried = false := by
          cases hc : s.cookieRetried <;> simp_all
        refine hretry _ _ _ ?_
        simp only [measure, LexLe, phase, hk]
        cases s.edns <;> cases s.stage <;> simp [stagePhase]
    · rename_i hstream
      have hs := hst (by simpa using hstream)
      split
      · rename_i hr
        exact hretry _ _ _ (by simp [measure, LexLe, phase, stagePhase, hs, hr])
      · rename_i hr
        refine hretry _ _ _ ?_
        simp only [measure, LexLe, phase, hs, hr, fresh]
        cases s.edns <;> cases c.useTcp <;> simp [stagePhase]

/-- Closing a try moves no counter the measure reads. -/
@[simp] theorem measure_closeTry (c : Config) (s : State) (b : Bool) (p : Nat) :
    measure c (closeTry s b p) = measure c s := by
  simp [measure, phase]

/-- A reply the lookup acts on raises nothing, in whatever stage it comes: it ends the lookup,
follows a CNAME, or moves to the next name. An earlier try's reply comes so (docs/design.md §5,
Tries kept open). -/
theorem onReply_acts_le (c : Config) (s : State) (stream : Bool) (r : Reply)
    (ha : actsOn stream r = true) : LexLe (measure c (onReply c s stream r).1) (measure c s) := by
  cases r with
  | answer => exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_done_le s)
  | cname =>
    simp only [onReply]
    split
    · exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_ended_le s .chainTooLong)
    · simp [measure, LexLe]; omega
  | nxdomain => exact nextCandidate_le c s false
  | nodata => exact nextCandidate_le c s true
  | truncated =>
    cases stream
    · simp [actsOn] at ha
    · exact nextCandidate_le c s true
  | _ => simp [actsOn] at ha

/-- A retry of the same server, to a state no higher, or the next server, is no higher. -/
theorem retry_le (c : Config) (s t : State) (b : Bool) (w : Option What) (g : s.round < c.attempts)
    (ht : LexLe (measure c t) (measure c s)) : LexLe (measure c (retry c s t b w)) (measure c s) := by
  refine retry_of c s t b w (fun x => LexLe (measure c x) (measure c s)) ht (fun u hu => ?_)
  rcases hu with rfl | ⟨k, rfl⟩
  · exact lexLt_le _ _ (advanceServer_lt c _ g)
  · exact lexLt_le _ _ (advanceServer_lt c _ g)

/-- A reply read under validation raises nothing: a bogus message is the next server or a retry
over TCP, and a wait for keys spends one of the name's waits, which counts more than the wait. -/
theorem reading_le (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (g : s.round < c.attempts) (hh : s.hops ≤ c.hopsMax)
    (hst : stream = false → s.stage = .awaitingUdp) :
    LexLe (measure c (reading c s stream r ad v).1) (measure c s) := by
  have hrej : LexLe (measure c (rejected c s stream)) (measure c s) := by
    unfold rejected
    split
    · exact lexLt_le _ _ (advanceServer_lt c _ g)
    · rename_i hs'
      have hs := hst (by simpa using hs')
      exact retry_le c s _ _ _ g (by simp [measure, LexLe, phase, stagePhase, hs])
  exact (reading_of c s stream r ad v (fun x => LexLe (measure c x) (measure c s)) (fun _ => True)
    (onReply_le c s stream r g hh hst) trivial trivial (fun _ h => h) (fun _ h => h) hrej
    (fun hlt => by simp [keyAsksMax] at hlt; simp [measure, LexLe, phase, stagePhase, keyAsksMax]; omega)).1

/-- No event raises the measure. -/
theorem step_le (c : Config) (s : State) (e : Event) (g : Good c s) :
    LexLe (measure c (step c s e).1) (measure c s) := by
  rcases g with hend | ⟨_, h2, _, h4⟩
  · rw [ended_absorbing c s e hend]; exact lexLe_refl _
  · cases e with
    | poll => exact poll_le c s
    | expire =>
      simp only [step]
      split
      · exact lexLe_trans _ _ _ (poll_le c _) (lexLt_le _ _ (advanceServer_lt c s h2))
      · exact poll_le c s
    | sent => cases hs : s.stage <;> simp [step, measure, LexLe, phase, stagePhase, hs]
    | sendFailed =>
      cases hs : s.stage <;> simp only [step, hs] <;>
        first | exact lexLt_le _ _ (advanceServer_lt c s h2) | exact lexLe_refl _
    | tcpConnected => cases hs : s.stage <;> simp [step, measure, LexLe, phase, stagePhase, hs]
    | tcpFailed _ =>
      simp only [step]
      split
      · exact lexLt_le _ _ (advanceServer_lt c _ h2)
      · exact lexLe_refl _
    | requestFailed _ =>
      simp only [step]
      split
      · exact lexLt_le _ _ (advanceServer_lt c _ h2)
      · exact lexLe_refl _
    | reply r | replyAd r | replyChecked r _ =>
      -- The reply closes the current try first, which moves nothing the measure reads.
      have key : ∀ u : State, measure c u = measure c s → u.round = s.round → u.hops = s.hops →
          ∀ b ad v, (b = false → u.stage = .awaitingUdp) →
          LexLe (measure c (reading c u b r ad v).1) (measure c s) := by
        intro u hm hr hh b ad v hb
        have e := reading_le c u b r ad v (by rw [hr]; exact h2) (by rw [hh]; exact h4) hb
        rwa [hm] at e
      cases hs : s.stage <;> simp only [step, heard, hs]
      all_goals first
        | (split <;> exact key _ (by simp) (by simp) (by simp) _ _ _ (fun _ => by simpa using hs))
        | (split <;> exact key _ (by simp) (by simp) (by simp) _ _ _ (fun h => absurd h (by simp)))
        | exact lexLe_refl _
    | earlier p stream r ad v =>
      simp only [step]
      split
      · exact lexLe_refl _
      · have same : ∀ u : State, measure c u = measure c s → LexLe (measure c u) (measure c s) :=
          fun u hu => hu ▸ lexLe_refl _
        exact (earlierHeard_acts_of c s p stream r ad v (fun x => LexLe (measure c x) (measure c s))
          (fun _ => True)
          (fun hact => by
            have e := onReply_acts_le c (closeTry s stream p) _ r hact
            rwa [measure_closeTry] at e)
          (fun _ => trivial) trivial (fun _ h => h) (fun _ h => h) (fun _ h => h)
          (same _ (by simp))
          (fun _ => same _ (by simp [measure, phase, keepAt]))
          (lexLe_of_phase c s _ (by simp [fail]) (by simp [fail]) (by simp [fail]) (by simp [fail])
            (by have := phase_ended_le (closeTry s stream p) .nameTooLong
                simp only [phase, closeTry_asks, closeTry_edns, closeTry_cookieRetried,
                  closeTry_stage] at this ⊢
                exact this))
          (fun hlt => by
            simp [measure, LexLe, phase, keyAsksMax] at hlt ⊢
            cases s.stage <;> simp [stagePhase] <;> omega)).1
    | earlierFailed p stream r =>
      simp only [step]
      split
      · exact lexLe_refl _
      · have e : measure c (earlierFailed s p stream r) = measure c s := by
          unfold earlierFailed; split <;> first | rfl | simp [measure, phase, keepAt]
        rw [e]; exact lexLe_refl _
    | keysReady =>
      simp only [step]
      split
      · rename_i hk
        unfold keysCame
        refine retry_le c s _ _ _ h2 ?_
        simp only [measure, LexLe, phase, hk, fresh]
        cases c.useTcp <;> simp [stagePhase]
      · exact lexLe_refl _
    | keysFailed w =>
      simp only [step]
      split
      · cases w <;> simp only [walkFailed] <;>
          exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_ended_le _ _)
      · exact lexLe_refl _
    | cancel =>
      simp only [step]
      split
      · exact lexLe_refl _
      · exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_ended_le s .canceled)

/-- Every send lowers the measure. -/
theorem sent_lt (c : Config) (s : State) (h : s.stage = .queryReady ∨ s.stage = .tcpReady) :
    LexLt (measure c (step c s .sent).1) (measure c s) := by
  rcases h with h | h <;> simp [step, measure, LexLt, phase, stagePhase, h]

/-- The measure's order is well-founded: it is the lexicographic order on five naturals. With
`step_le` and `sent_lt`, a lookup under a sane configuration makes finitely many sends, whatever
its servers answer and whatever order the caller's events come in. -/
theorem lexLt_wf : WellFounded LexLt := by
  let r := Prod.lex Nat.lt_wfRel (Prod.lex Nat.lt_wfRel (Prod.lex Nat.lt_wfRel
    (Prod.lex Nat.lt_wfRel Nat.lt_wfRel)))
  refine Subrelation.wf (r := r.rel) ?_ r.wf
  intro a b h
  obtain ⟨a1, a2, a3, a4, a5⟩ := a
  obtain ⟨b1, b2, b3, b4, b5⟩ := b
  simp only [LexLt] at h
  rcases h with h | ⟨rfl, h | ⟨rfl, h | ⟨rfl, h | ⟨rfl, h⟩⟩⟩⟩
  · exact Prod.Lex.left _ _ h
  · exact Prod.Lex.right _ (Prod.Lex.left _ _ h)
  · exact Prod.Lex.right _ (Prod.Lex.right _ (Prod.Lex.left _ _ h))
  · exact Prod.Lex.right _ (Prod.Lex.right _ (Prod.Lex.right _ (Prod.Lex.left _ _ h)))
  · exact Prod.Lex.right _ (Prod.Lex.right _ (Prod.Lex.right _ (Prod.Lex.right _ h)))

end Spec.Lookup
