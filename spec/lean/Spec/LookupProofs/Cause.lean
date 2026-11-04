import Spec.LookupProofs.Timeout
import Spec.LookupProofs.CauseOpen

/-!
# What a failure says of its cause

`AllServersFailed` rests on a server that failed the lookup, and `Timeout` on none (docs/design.md
§5, The cause of a failure; §16 decision 45). So a lookup that fails with `allServersFailed` holds
a cause, and a lookup that fails with `timeout` holds none. A cause names the server that gave it
(§16 decision 51), and that server is one of the configuration's. `init` gives all three, and no
event breaks them, so each state that a lookup reaches has them. The model holds no memory: a
failure that the memory of §20 recalls has no cause and sends no query (§16 decision 61, §17
question 89), so these theorems cover a lookup that went out.
-/
namespace Spec.Lookup

/-- What the error of a failed lookup says of its cause. `bogus` rests on a bogus message, or a
walk that proved one, which the cause holds as `allServersFailed`'s cause is held (docs/design.md
§25, step 11). -/
def CauseFits (s : State) : Prop :=
  s.stage = .failed →
    (s.err = .allServersFailed → s.cause.isSome = true) ∧ (s.err = .timeout → s.cause = none) ∧
      (s.err = .bogus → s.cause.isSome = true)

theorem advanceServer_fits (c : Config) (s : State) : CauseFits (advanceServer c s) := by
  fun_induction advanceServer c s
  · rename_i ih; exact ih
  · intro hf; exact absurd (waitOn_failed c _ hf) (by simpa +zetaDelta using fresh_ne_failed c)
  · rename_i ih; exact ih
  · intro hf; exact absurd (waitOn_failed c _ hf) (by simpa +zetaDelta using fresh_ne_failed c)
  · simp only [CauseFits, fail, exhausted]
    split <;> simp_all

theorem nextCandidate_fits (c : Config) (s : State) (b : Bool) :
    CauseFits (nextCandidate c s b) := by
  unfold nextCandidate CauseFits
  dsimp only
  split
  · intro hf; exact absurd hf (fresh_ne_failed c)
  · intro _
    simp only [fail]
    split <;> simp

theorem fail_fits (s : State) (e : Err) (h1 : e ≠ .allServersFailed) (h2 : e ≠ .timeout)
    (h3 : e ≠ .bogus := by simp) : CauseFits (fail s e) := by
  simp [CauseFits, fail, h1, h2, h3]

/-- A reply read under validation keeps the fit: a bogus message moves the server and keeps its
cause, and a wait for keys ends nothing. -/
theorem reading_fits (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (hon : CauseFits (onReply c s stream r).1) :
    CauseFits (reading c s stream r ad v).1 := by
  have running : ∀ t : State, t.stage ≠ .failed → CauseFits t := fun t ht hf => absurd hf ht
  have hrej : CauseFits (rejected c s stream) := by
    unfold rejected
    split
    · exact advanceServer_fits c _
    · exact retry_of c s _ _ _ CauseFits (running _ (by simp)) (fun u _ => advanceServer_fits c u)
  exact (reading_of c s stream r ad v CauseFits (fun _ => True) hon trivial trivial
    (fun _ h => h) (fun _ h => h) hrej (fun _ => running _ (by simp))).1

/-- The walk's failure fits: `bogus` and `allServersFailed` keep a cause, and `timeout` comes only
while there is none. -/
theorem walkFailed_fits (s : State) (w : Walked) : CauseFits (walkFailed s w) := by
  cases w
  · simp [walkFailed, CauseFits, fail, keep]
  · simp only [walkFailed, CauseFits, fail]
    split <;> simp_all
  · simp [walkFailed, CauseFits, fail, keep]

theorem poll_fits (c : Config) (s : State) (h : CauseFits s) : CauseFits (poll c s).1 := by
  unfold poll
  cases hs : s.stage <;> simp_all [CauseFits]

theorem onReply_fits (c : Config) (s : State) (stream : Bool) (r : Reply) (h : CauseFits s) :
    CauseFits (onReply c s stream r).1 := by
  have running : ∀ t : State, t.stage ≠ .failed → CauseFits t := fun t ht hf => absurd hf ht
  have hretry : ∀ (t : State) (b : Bool) (w : Option What), t.stage ≠ .failed →
      CauseFits (retry c s t b w) :=
    fun t b w hn => retry_of c s t b w CauseFits (running t hn) (fun u _ => advanceServer_fits c u)
  cases r with
  | unmatched => exact h
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_fits c s true
    · exact hretry _ _ _ (by simp)
  | answer => exact running _ (by simp [onReply])
  | cname =>
    simp only [onReply]
    split
    · exact fail_fits s .chainTooLong (by simp) (by simp)
    · exact running _ (fresh_ne_failed c)
  | nxdomain => exact nextCandidate_fits c s false
  | nodata => exact nextCandidate_fits c s true
  | yxdomain => exact fail_fits s .nameTooLong (by simp) (by simp)
  | servfail => exact advanceServer_fits c _
  | formerr =>
    simp only [onReply]
    split
    · exact hretry _ _ _ (fresh_ne_failed c)
    · exact advanceServer_fits c _
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact advanceServer_fits c _
      · exact hretry _ _ _ (by simp)
    · split
      · exact hretry _ _ _ (by simp)
      · exact hretry _ _ _ (fresh_ne_failed c)

/-- No event breaks what a failure says of its cause. -/
theorem step_fits (c : Config) (s : State) (e : Event) (h : CauseFits s) :
    CauseFits (step c s e).1 := by
  by_cases hend : ended s.stage = true
  · rw [ended_absorbing c s e hend]; exact h
  have running : ∀ t : State, t.stage ≠ .failed → CauseFits t := fun t ht hf => absurd hf ht
  cases e with
  | poll => exact poll_fits c s h
  | expire =>
    simp only [step]
    split
    · exact poll_fits c _ (advanceServer_fits c s)
    · exact poll_fits c s h
  | sent => cases hst : s.stage <;> simp_all [step, CauseFits]
  | sendFailed =>
    cases hst : s.stage <;> simp only [step, hst] <;>
      first | exact advanceServer_fits c s | exact h
  | tcpConnected => cases hst : s.stage <;> simp_all [step, CauseFits]
  | tcpFailed _ =>
    simp only [step]
    split
    · exact advanceServer_fits c _
    · exact h
  | requestFailed _ =>
    simp only [step]
    split
    · exact advanceServer_fits c _
    · exact h
  | reply r | replyAd r | replyChecked r _ =>
    have hc : ∀ b p, CauseFits (closeTry s b p) := fun b p => by simpa [CauseFits] using h
    cases hst : s.stage <;> simp only [step, heard, hst]
    all_goals first
      | (split
         · exact reading_fits c s _ r _ _ (onReply_fits c s _ r h)
         · exact reading_fits c _ _ r _ _ (onReply_fits c _ _ r (hc _ _)))
      | exact h
  | earlier p stream r ad v =>
    simp only [step]
    split
    · exact h
    · have hc : CauseFits (closeTry s stream p) := by simpa [CauseFits] using h
      have hs : s.stage ≠ .failed := fun hf => hend (by simp [ended, hf])
      exact (earlierHeard_of c s p stream r ad v CauseFits (fun _ => True)
        (onReply_fits c _ _ r hc) trivial trivial (fun _ h => h) (fun _ h => h) (fun _ h => h) hc
        (fun _ => running _ (by simpa [keepAt] using hs))
        (fail_fits _ .nameTooLong (by simp) (by simp)) (running _ (by simp))).1
  | earlierFailed p stream r =>
    simp only [step]
    split
    · exact h
    · have hs : s.stage ≠ .failed := fun hf => hend (by simp [ended, hf])
      exact running _ (by rw [earlierFailed_stage]; exact hs)
  | keysReady =>
    simp only [step]
    split
    · exact retry_of c s _ _ _ CauseFits (running _ (fresh_ne_failed c))
        (fun u _ => advanceServer_fits c u)
    · exact h
  | keysFailed w =>
    simp only [step]
    split
    · exact walkFailed_fits s w
    · exact h
  | cancel =>
    simp only [step]
    split
    · exact h
    · exact fail_fits s .canceled (by simp) (by simp)

theorem init_fits (c : Config) : CauseFits (init c) := by
  unfold init
  split
  · exact fail_fits _ .noServers (by simp) (by simp)
  · intro hf; exact absurd hf (fresh_ne_failed c)

/-- The server a cause names is one of the configuration's. A cause names the position the lookup
was on when the server failed it (`keep`), and that position stays inside the configuration while
the lookup runs. -/
def ServerFits (c : Config) (s : State) : Prop :=
  (ended s.stage = false → s.server < c.servers) ∧ (∀ k, s.cause = some k → k.server < c.servers)

/-- A cause that `keep` writes names a server of the configuration. The proof reads no more of
`keep` than that its cause is the state's, or a new one whose server the arithmetic bounds, so a
`keep` that a mutation changed reaches the replay's check, and not a proof that stops. -/
theorem keep_server (c : Config) (s : State) (w : What) (h : ServerFits c s)
    (hs : s.server < c.servers) : ServerFits c (keep s w) := by
  refine ⟨fun _ => hs, fun k hk => ?_⟩
  have old := h.2
  simp only [keep] at hk
  cases hc : s.cause <;> (try rw [hc] at hk) <;> (try simp_all) <;> (try subst hk) <;>
    (try simp_all) <;> omega

theorem advanceServer_server (c : Config) (s : State) (h : ServerFits c s)
    (hs : s.server < c.servers) : ServerFits c (advanceServer c s) := by
  refine ⟨advanceServer_inside c s (by omega), fun k hk => h.2 k ?_⟩
  rw [← advanceServer_cause c s]
  exact hk

theorem nextCandidate_server (c : Config) (s : State) (b : Bool) (h : ServerFits c s)
    (hs : s.server < c.servers) : ServerFits c (nextCandidate c s b) := by
  obtain ⟨_, hk⟩ := h
  unfold nextCandidate
  dsimp only
  split
  · exact ⟨fun _ => by simp; omega, hk⟩
  · exact ⟨fun hf => by simp [fail, ended] at hf, hk⟩

theorem poll_server (c : Config) (s : State) (h : ServerFits c s) : ServerFits c (poll c s).1 := by
  have h1 : (poll c s).1.server = s.server := by unfold poll; cases s.stage <;> simp
  have h2 : (poll c s).1.cause = s.cause := by unfold poll; cases s.stage <;> simp
  have h3 : ended (poll c s).1.stage = ended s.stage := by
    unfold poll; cases hs : s.stage <;> simp [hs, ended]
  exact ⟨fun hn => h1 ▸ h.1 (h3 ▸ hn), fun k hk => h.2 k (h2 ▸ hk)⟩

theorem onReply_server (c : Config) (s : State) (stream : Bool) (r : Reply) (h : ServerFits c s)
    (hs : s.server < c.servers) : ServerFits c (onReply c s stream r).1 := by
  have same : ∀ t : State, t.server = s.server → t.cause = s.cause → ServerFits c t :=
    fun t h1 h2 => ⟨fun _ => h1 ▸ hs, fun k hk => h.2 k (h2 ▸ hk)⟩
  have ends : ∀ e : Err, ServerFits c (fail s e) :=
    fun e => ⟨fun hf => by simp [fail, ended] at hf, h.2⟩
  have hadv : ∀ w : What, ServerFits c (advanceServer c (keep s w)) :=
    fun w => advanceServer_server c _ (keep_server c s w h hs) hs
  -- A retry asks the same server again, or moves on as the next server does.
  have hretry : ∀ (t : State) (b : Bool) (w : Option What), t.server = s.server →
      t.cause = s.cause → ServerFits c (retry c s t b w) := by
    intro t b w h1 h2
    refine retry_of c s t b w (ServerFits c) (same t h1 h2) (fun u hu => ?_)
    rcases hu with rfl | ⟨k, rfl⟩
    · exact advanceServer_server c _ h hs
    · exact hadv k
  cases r with
  | unmatched => exact h
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_server c s true h hs
    · exact hretry _ _ _ rfl rfl
  | answer => exact same _ rfl rfl
  | cname =>
    simp only [onReply]
    split
    · exact ends _
    · exact same _ rfl rfl
  | nxdomain => exact nextCandidate_server c s false h hs
  | nodata => exact nextCandidate_server c s true h hs
  | yxdomain => exact ends _
  | servfail => exact hadv _
  | formerr =>
    simp only [onReply]
    split
    · exact hretry _ _ _ rfl rfl
    · exact hadv _
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact hadv _
      · exact hretry _ _ _ rfl rfl
    · split
      · exact hretry _ _ _ rfl rfl
      · exact hretry _ _ _ rfl rfl

/-- A reply read under validation keeps the cause, and the position, inside the configuration. -/
theorem reading_server (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (h : ServerFits c s) (hs : s.server < c.servers) :
    ServerFits c (reading c s stream r ad v).1 := by
  have same : ∀ t : State, t.server = s.server → t.cause = s.cause → ServerFits c t :=
    fun t h1 h2 => ⟨fun _ => h1 ▸ hs, fun k hk => h.2 k (h2 ▸ hk)⟩
  have hrej : ServerFits c (rejected c s stream) := by
    unfold rejected
    split
    · exact advanceServer_server c _ (keep_server c s .bogus h hs) hs
    · refine retry_of c s _ _ _ (ServerFits c) (same _ rfl rfl) (fun u hu => ?_)
      rcases hu with rfl | ⟨k, rfl⟩
      · exact advanceServer_server c _ h hs
      · exact advanceServer_server c _ (keep_server c s k h hs) hs
  exact (reading_of c s stream r ad v (ServerFits c) (fun _ => True) (onReply_server c s stream r h hs)
    trivial trivial (fun _ h => h) (fun _ h => h) hrej (fun _ => same _ rfl rfl)).1

/-- No event moves a cause, or the lookup's position, outside the configuration. -/
theorem step_server (c : Config) (s : State) (e : Event) (h : ServerFits c s) (ho : OpenFits c s) :
    ServerFits c (step c s e).1 := by
  by_cases hend : ended s.stage = true
  · rw [ended_absorbing c s e hend]; exact h
  have hs : s.server < c.servers := h.1 (by simpa using hend)
  have same : ∀ t : State, t.server = s.server → t.cause = s.cause → ServerFits c t :=
    fun t h1 h2 => ⟨fun _ => h1 ▸ hs, fun k hk => h.2 k (h2 ▸ hk)⟩
  have hadv : ∀ w : What, ServerFits c (advanceServer c (keep s w)) :=
    fun w => advanceServer_server c _ (keep_server c s w h hs) hs
  cases e with
  | poll => exact poll_server c s h
  | expire =>
    simp only [step]
    split
    · exact poll_server c _ (advanceServer_server c s h hs)
    · exact poll_server c s h
  | sent => cases hst : s.stage <;> simp only [step, hst] <;> exact same _ rfl rfl
  | sendFailed =>
    cases hst : s.stage <;> simp only [step, hst] <;>
      first | exact advanceServer_server c s h hs | exact h
  | tcpConnected => cases hst : s.stage <;> simp only [step, hst] <;> exact same _ rfl rfl
  | tcpFailed _ =>
    simp only [step]
    split
    · exact advanceServer_server c _ (keep_server c _ _ (same _ rfl rfl) hs) hs
    · exact h
  | requestFailed _ =>
    simp only [step]
    split
    · exact advanceServer_server c _
        (keep_server c _ _ (same _ (by simp) (by simp)) (by simpa using hs))
        (by simpa [keep] using hs)
    · exact h
  | reply r | replyAd r | replyChecked r _ =>
    have hc : ∀ b p, ServerFits c (closeTry s b p) := fun b p => same _ (by simp) (by simp)
    cases hst : s.stage <;> simp only [step, heard, hst]
    all_goals first
      | (split
         · exact reading_server c s _ r _ _ h hs
         · exact reading_server c _ _ r _ _ (hc _ _) (by simpa using hs))
      | exact h
  | earlier p stream r ad v =>
    simp only [step]
    split
    · exact h
    · rename_i hn
      have hp : p < c.servers := lt_of_open c s stream p ho (by intro hz; exact hn (Or.inr hz))
      have hc : ServerFits c (closeTry s stream p) := same _ (by simp) (by simp)
      have hk : ∀ w, ServerFits c (keepAt (closeTry s stream p) p w) := fun w =>
        ⟨fun _ => by simpa [keepAt] using hs, fun k hk => by simp [keepAt] at hk; subst hk; exact hp⟩
      exact (earlierHeard_of c s p stream r ad v (ServerFits c) (fun _ => True)
        (onReply_server c _ _ r hc (by simpa using hs)) trivial trivial (fun _ h => h)
        (fun _ h => h) (fun _ h => h) hc hk
        ⟨fun hf => by simp [fail, ended] at hf, fun k hk => h.2 k (by simpa [fail] using hk)⟩
        (same _ (by simp) (by simp))).1
  | earlierFailed p stream r =>
    simp only [step]
    split
    · exact h
    · rename_i hn
      have hp : p < c.servers := lt_of_open c s stream p ho (by intro hz; exact hn (Or.inr hz))
      unfold earlierFailed
      split
      · exact ⟨fun _ => by simpa [keepAt] using hs, fun k hk => by simp [keepAt] at hk; subst hk; exact hp⟩
      · exact ⟨fun _ => by simpa [keepAt] using hs, fun k hk => by simp [keepAt] at hk; subst hk; exact hp⟩
  | keysReady =>
    simp only [step]
    split
    · refine retry_of c s _ _ _ (ServerFits c) (same _ rfl rfl) (fun u hu => ?_)
      rcases hu with rfl | ⟨k, rfl⟩
      · exact advanceServer_server c _ h hs
      · exact hadv k
    · exact h
  | keysFailed w =>
    simp only [step]
    split
    · cases w <;> simp only [walkFailed]
      · exact ⟨fun hf => by simp [fail, ended] at hf, (keep_server c s .bogus h hs).2⟩
      · exact ⟨fun hf => by simp [fail, ended] at hf, h.2⟩
      · exact ⟨fun hf => by simp [fail, ended] at hf, (keep_server c s .keys h hs).2⟩
    · exact h
  | cancel =>
    simp only [step]
    split
    · exact h
    · exact ⟨fun hf => by simp [fail, ended] at hf, h.2⟩

theorem init_server (c : Config) : ServerFits c (init c) := by
  unfold init
  split
  · exact ⟨fun hf => by simp [fail, ended] at hf, fun k hk => by simp [fail] at hk⟩
  · rename_i hc
    exact ⟨fun _ => by simp; omega, fun k hk => by simp at hk⟩

/-- A lookup that fails with `allServersFailed` holds the cause of the last server failure, and one
that fails with `timeout` holds none, whatever the caller tells it (§5, The cause of a failure;
§16 decision 45). The cause it holds names one of the configuration's servers (§16 decision
51). -/
theorem failure_cause (c : Config) (es : List Event) :
    CauseFits (run c (init c) es) ∧ ServerFits c (run c (init c) es) := by
  have key : ∀ (es : List Event) (t : State), CauseFits t ∧ ServerFits c t ∧ OpenFits c t →
      CauseFits (run c t es) ∧ ServerFits c (run c t es) ∧ OpenFits c (run c t es) := by
    intro es
    induction es with
    | nil => intro t h; exact h
    | cons e rest ih =>
      intro t h
      exact ih _ ⟨step_fits c t e h.1, step_server c t e h.2.1 h.2.2, step_open c t e h.2.2⟩
  have k := key es _ ⟨init_fits c, init_server c, init_open c⟩
  exact ⟨k.1, k.2.1⟩

end Spec.Lookup
