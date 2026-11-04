import Spec.LookupProofs

/-!
# A position with a try open is a server of the configuration

Each list of the tries a lookup keeps open has one entry for each server, so an earlier try's
reply names a server of the configuration, and so does the cause it gives (docs/design.md §5,
Tries kept open). `Spec.LookupProofs.Cause` reads it. Split from `Spec.LookupProofs.Cause` by the
file-length rule.
-/
namespace Spec.Lookup

/-- Each list of open tries has one entry for each server of the configuration. So a position at
which a try is open is one of the configuration's (`lt_of_open`). -/
def OpenFits (c : Config) (s : State) : Prop :=
  s.openDatagrams.length = c.servers ∧ s.openStreams.length = c.servers

theorem lt_of_getD_pos (l : List Nat) (p : Nat) (h : 0 < l.getD p 0) : p < l.length := by
  rcases Nat.lt_or_ge p l.length with hl | hl
  · exact hl
  · simp [List.getD_eq_getElem?_getD, List.getElem?_eq_none hl] at h

/-- A position with an earlier try open is a server of the configuration. -/
theorem lt_of_open (c : Config) (s : State) (b : Bool) (p : Nat) (ho : OpenFits c s)
    (h : earlierOpen s b p ≠ 0) : p < c.servers := by
  have hp : 0 < openAt s b p := by
    unfold earlierOpen at h; dsimp only at h; split at h <;> omega
  cases b
  · rw [← ho.1]; exact lt_of_getD_pos _ _ (by simpa [openAt] using hp)
  · rw [← ho.2]; exact lt_of_getD_pos _ _ (by simpa [openAt] using hp)

theorem closeTry_open (c : Config) (s : State) (b : Bool) (p : Nat) (h : OpenFits c s) :
    OpenFits c (closeTry s b p) := by
  unfold closeTry OpenFits; split <;> simp [h.1, h.2]

theorem advanceServer_open (c : Config) (s : State) :
    (advanceServer c s).openDatagrams = s.openDatagrams ∧
      (advanceServer c s).openStreams = s.openStreams := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

theorem advanceServer_openFits (c : Config) (s : State) (h : OpenFits c s) :
    OpenFits c (advanceServer c s) := by
  obtain ⟨a, b⟩ := advanceServer_open c s; exact ⟨a ▸ h.1, b ▸ h.2⟩

theorem nextCandidate_open (c : Config) (s : State) (b : Bool) (h : OpenFits c s) :
    OpenFits c (nextCandidate c s b) := by
  unfold nextCandidate
  dsimp only
  split
  · simp [OpenFits, unsent]
  · simpa [OpenFits, fail] using h

theorem onReply_open (c : Config) (s : State) (stream : Bool) (r : Reply) (h : OpenFits c s) :
    OpenFits c (onReply c s stream r).1 := by
  have same : ∀ t : State, t.openDatagrams = s.openDatagrams → t.openStreams = s.openStreams →
      OpenFits c t := fun t h1 h2 => ⟨h1 ▸ h.1, h2 ▸ h.2⟩
  have hadv : ∀ w : What, OpenFits c (advanceServer c (keep s w)) :=
    fun w => advanceServer_openFits c _ h
  have hretry : ∀ (t : State) (b : Bool) (w : Option What), t.openDatagrams = s.openDatagrams →
      t.openStreams = s.openStreams → OpenFits c (retry c s t b w) := by
    intro t b w h1 h2
    refine retry_of c s t b w (OpenFits c) (same t h1 h2) (fun u hu => ?_)
    rcases hu with rfl | ⟨k, rfl⟩
    · exact advanceServer_openFits c _ h
    · exact hadv k
  cases r with
  | unmatched => exact h
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_open c s true h
    · exact hretry _ _ _ rfl rfl
  | answer => exact same _ rfl rfl
  | cname =>
    simp only [onReply]
    split
    · exact same _ rfl rfl
    · simp [OpenFits, unsent]
  | nxdomain => exact nextCandidate_open c s false h
  | nodata => exact nextCandidate_open c s true h
  | yxdomain => exact same _ rfl rfl
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

theorem reading_open (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (h : OpenFits c s) : OpenFits c (reading c s stream r ad v).1 := by
  have same : ∀ t : State, t.openDatagrams = s.openDatagrams → t.openStreams = s.openStreams →
      OpenFits c t := fun t h1 h2 => ⟨h1 ▸ h.1, h2 ▸ h.2⟩
  have hrej : OpenFits c (rejected c s stream) := by
    unfold rejected
    split
    · exact advanceServer_openFits c _ h
    · refine retry_of c s _ _ _ (OpenFits c) (same _ rfl rfl) (fun u hu => ?_)
      rcases hu with rfl | ⟨k, rfl⟩
      · exact advanceServer_openFits c _ h
      · exact advanceServer_openFits c _ h
  exact (reading_of c s stream r ad v (OpenFits c) (fun _ => True) (onReply_open c s stream r h)
    trivial trivial (fun _ h => h) (fun _ h => h) hrej (fun _ => same _ rfl rfl)).1

/-- No event leaves a list of open tries without an entry for each server. -/
theorem step_open (c : Config) (s : State) (e : Event) (h : OpenFits c s) :
    OpenFits c (step c s e).1 := by
  have hpoll : ∀ t : State, OpenFits c t → OpenFits c (poll c t).1 := by
    intro t ht; unfold poll; cases t.stage <;> exact ht
  cases e with
  | poll => exact hpoll s h
  | expire =>
    simp only [step]
    split
    · exact hpoll _ (advanceServer_openFits c s h)
    · exact hpoll s h
  | sent =>
    cases hst : s.stage <;> simp only [step, hst] <;> first | exact h | simp [OpenFits, bump, h.1, h.2]
  | sendFailed =>
    cases hst : s.stage <;> simp only [step, hst] <;>
      first | exact advanceServer_openFits c s h | exact h
  | tcpConnected => cases hst : s.stage <;> simp only [step, hst] <;> exact h
  | tcpFailed _ =>
    simp only [step]
    split
    · exact advanceServer_openFits c _ (by simpa [OpenFits, keep] using h)
    · exact h
  | requestFailed _ =>
    simp only [step]
    split
    · exact advanceServer_openFits c _ (let o := closeTry_open c s false s.server h; ⟨o.1, o.2⟩)
    · exact h
  | reply r | replyAd r | replyChecked r _ =>
    cases hst : s.stage <;> simp only [step, heard, hst]
    all_goals first
      | (split
         · exact reading_open c s _ r _ _ h
         · exact reading_open c _ _ r _ _ (closeTry_open c s _ _ h))
      | exact h
  | earlier p stream r ad v =>
    simp only [step]
    split
    · exact h
    · have hc := closeTry_open c s stream p h
      exact (earlierHeard_of c s p stream r ad v (OpenFits c) (fun _ => True)
        (onReply_open c _ _ r hc) trivial trivial (fun _ h => h) (fun _ h => h) (fun _ h => h) hc
        (fun _ => ⟨hc.1, hc.2⟩) ⟨hc.1, hc.2⟩ ⟨hc.1, hc.2⟩).1
  | earlierFailed p stream r =>
    simp only [step]
    split
    · exact h
    · unfold earlierFailed; split
      · simpa [OpenFits, keepAt] using h
      · exact (let o := closeTry_open c s false p h; ⟨o.1, o.2⟩)
  | keysReady =>
    simp only [step]
    split
    · refine retry_of c s _ _ _ (OpenFits c) h (fun u hu => ?_)
      rcases hu with rfl | ⟨k, rfl⟩
      · exact advanceServer_openFits c _ h
      · exact advanceServer_openFits c _ h
    · exact h
  | keysFailed w =>
    simp only [step]
    split
    · cases w <;> exact ⟨h.1, h.2⟩
    · exact h
  | cancel =>
    simp only [step]
    split
    · exact h
    · exact ⟨h.1, h.2⟩

theorem init_open (c : Config) : OpenFits c (init c) := by
  unfold init; split <;> simp [OpenFits, fail, unsent]

end Spec.Lookup
