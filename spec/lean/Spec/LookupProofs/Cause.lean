import Spec.LookupProofs.Timeout

/-!
# What a failure says of its cause

`AllServersFailed` rests on a server that failed the lookup, and `Timeout` on none (docs/design.md
§5, The cause of a failure; §16 decision 45). So a lookup that fails with `allServersFailed` holds
a cause, and a lookup that fails with `timeout` holds none. A cause names the server that gave it
(§16 decision 51), and that server is one of the configuration's. `init` gives all three, and no
event breaks them, so each state that a lookup reaches has them.
-/
namespace Spec.Lookup

/-- What the error of a failed lookup says of its cause. -/
def CauseFits (s : State) : Prop :=
  s.stage = .failed →
    (s.err = .allServersFailed → s.cause.isSome = true) ∧ (s.err = .timeout → s.cause = none)

theorem advanceServer_fits (c : Config) (s : State) : CauseFits (advanceServer c s) := by
  fun_induction advanceServer c s
  · rename_i ih; exact ih
  · intro hf; exact absurd hf (fresh_ne_failed c)
  · rename_i ih; exact ih
  · intro hf; exact absurd hf (fresh_ne_failed c)
  · simp only [CauseFits, fail]
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

theorem fail_fits (s : State) (e : Err) (h1 : e ≠ .allServersFailed) (h2 : e ≠ .timeout) :
    CauseFits (fail s e) := by
  simp [CauseFits, fail, h1, h2]

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
  | reply r =>
    cases hst : s.stage <;> simp only [step, hst]
    all_goals first
      | exact onReply_fits c s _ r h
      | exact h
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

/-- No event moves a cause, or the lookup's position, outside the configuration. -/
theorem step_server (c : Config) (s : State) (e : Event) (h : ServerFits c s) :
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
    · exact hadv _
    · exact h
  | requestFailed _ =>
    simp only [step]
    split
    · exact hadv _
    · exact h
  | reply r =>
    cases hst : s.stage <;> simp only [step, hst]
    all_goals first
      | exact onReply_server c s _ r h hs
      | exact h
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
  have key : ∀ (es : List Event) (t : State), CauseFits t ∧ ServerFits c t →
      CauseFits (run c t es) ∧ ServerFits c (run c t es) := by
    intro es
    induction es with
    | nil => intro t h; exact h
    | cons e rest ih => intro t h; exact ih _ ⟨step_fits c t e h.1, step_server c t e h.2⟩
  exact key es _ ⟨init_fits c, init_server c⟩

end Spec.Lookup
