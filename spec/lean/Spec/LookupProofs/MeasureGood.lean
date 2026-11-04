import Spec.LookupProofs.Measure

/-!
# The counters stay inside the configuration

The invariant `Good` of `Spec.LookupProofs.Measure`: while a lookup runs, its server, its pass, its
name and its hops stay inside its configuration. Split from `Spec.LookupProofs.Measure` by the
file-length rule.
-/
namespace Spec.Lookup

theorem advanceServer_good (c : Config) (s : State) (hc : Sane c) (hr : s.round < c.attempts)
    (hh : s.hops ≤ c.hopsMax) (hk : s.candidate < c.candidates) : Good c (advanceServer c s) := by
  obtain ⟨hs1, _, _⟩ := hc
  unfold Good
  cases hn : ended (advanceServer c s).stage
  · have h1 := advanceServer_inside c s hs1 hn
    have h2 := advanceServer_round c s hr hn
    obtain ⟨h3, h4, _, _⟩ := advanceServer_counts c s
    right; exact ⟨h1, h2, h3 ▸ hk, h4 ▸ hh⟩
  · left; rfl

theorem nextCandidate_good (c : Config) (s : State) (b : Bool) (hc : Sane c) :
    Good c (nextCandidate c s b) := by
  obtain ⟨hs1, ha1, _⟩ := hc
  unfold nextCandidate Good
  dsimp only
  split
  · right; simp; omega
  · left; simp [fail, ended]

theorem poll_good (c : Config) (s : State) (g : Good c s) : Good c (poll c s).1 := by
  rcases g with hend | ⟨h1, h2, h3, h4⟩
  · left; unfold poll; cases hs : s.stage <;> simp_all [ended]
  · right; unfold poll; cases hs : s.stage <;> simp_all

theorem onReply_good (c : Config) (s : State) (stream : Bool) (r : Reply) (hc : Sane c)
    (h1 : s.server < c.servers) (h2 : s.round < c.attempts) (h3 : s.candidate < c.candidates)
    (h4 : s.hops ≤ c.hopsMax) : Good c (onReply c s stream r).1 := by
  have gs : Good c s := Or.inr ⟨h1, h2, h3, h4⟩
  -- A retry keeps every counter, or moves on as the next server does (RFC 9520 §3.1).
  have hretry : ∀ (t : State) (b : Bool) (w : Option What), t.server = s.server →
      t.round = s.round → t.candidate = s.candidate → t.hops = s.hops →
      Good c (retry c s t b w) := by
    intro t b w e1 e2 e3 e4
    refine retry_of c s t b w (Good c) (Or.inr ⟨e1 ▸ h1, e2 ▸ h2, e3 ▸ h3, e4 ▸ h4⟩)
      (fun u hu => ?_)
    rcases hu with rfl | ⟨k, rfl⟩
    · exact advanceServer_good c _ hc h2 h4 h3
    · exact advanceServer_good c _ hc h2 h4 h3
  cases r with
  | unmatched => exact gs
  | truncated =>
    cases stream
    · exact hretry _ _ _ rfl rfl rfl rfl
    · exact nextCandidate_good c s true hc
  | answer => left; simp [onReply, ended]
  | cname =>
    simp only [onReply]
    split
    · left; simp [fail, ended]
    · rename_i hn
      exact Or.inr ⟨h1, h2, h3, by show s.hops + 1 ≤ c.hopsMax; omega⟩
  | nxdomain => exact nextCandidate_good c s false hc
  | nodata => exact nextCandidate_good c s true hc
  | yxdomain => left; simp [onReply, fail, ended]
  | servfail => exact advanceServer_good c _ hc h2 h4 h3
  | formerr =>
    simp only [onReply]
    split
    · exact hretry _ _ _ rfl rfl rfl rfl
    · exact advanceServer_good c _ hc h2 h4 h3
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact advanceServer_good c _ hc h2 h4 h3
      · exact hretry _ _ _ rfl rfl rfl rfl
    · split
      · exact hretry _ _ _ rfl rfl rfl rfl
      · exact hretry _ _ _ rfl rfl rfl rfl

/-- A reply read under validation keeps the counters inside the configuration. -/
theorem reading_good (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (hc : Sane c) (h1 : s.server < c.servers) (h2 : s.round < c.attempts)
    (h3 : s.candidate < c.candidates) (h4 : s.hops ≤ c.hopsMax) :
    Good c (reading c s stream r ad v).1 := by
  have hrej : Good c (rejected c s stream) := by
    unfold rejected
    split
    · exact advanceServer_good c _ hc h2 h4 h3
    · refine retry_of c s _ _ _ (Good c) (Or.inr ⟨h1, h2, h3, h4⟩) (fun u hu => ?_)
      rcases hu with rfl | ⟨k, rfl⟩
      · exact advanceServer_good c _ hc h2 h4 h3
      · exact advanceServer_good c _ hc h2 h4 h3
  exact (reading_of c s stream r ad v (Good c) (fun _ => True)
    (onReply_good c s stream r hc h1 h2 h3 h4) trivial trivial (fun _ h => h) (fun _ h => h) hrej
    (fun _ => Or.inr ⟨h1, h2, h3, h4⟩)).1

theorem init_good (c : Config) (hc : Sane c) : Good c (init c) := by
  obtain ⟨hs1, ha1, hc1⟩ := hc
  unfold init Good
  split
  · left; simp [fail, ended]
  · right; simp; omega

/-- A lookup started under a sane configuration keeps its counters inside it, whatever happens. -/
theorem step_good (c : Config) (s : State) (e : Event) (hc : Sane c) (g : Good c s) :
    Good c (step c s e).1 := by
  rcases g with hend | ⟨h1, h2, h3, h4⟩
  · rw [ended_absorbing c s e hend]; exact Or.inl hend
  · have gs : Good c s := Or.inr ⟨h1, h2, h3, h4⟩
    cases e with
    | poll => exact poll_good c s gs
    | expire =>
      simp only [step]
      split
      · exact poll_good c _ (advanceServer_good c s hc h2 h4 h3)
      · exact poll_good c s gs
    | sent => cases hs : s.stage <;> simp_all [step, Good]
    | sendFailed =>
      cases hs : s.stage <;> simp only [step, hs] <;>
        first | exact advanceServer_good c s hc h2 h4 h3 | exact gs
    | tcpConnected => cases hs : s.stage <;> simp_all [step, Good]
    | tcpFailed _ =>
      simp only [step]
      split
      · exact advanceServer_good c _ hc h2 h4 h3
      · exact gs
    | requestFailed _ =>
      simp only [step]
      split
      · exact advanceServer_good c _ hc h2 h4 h3
      · exact gs
    | reply r | replyAd r | replyChecked r _ =>
      cases hs : s.stage <;> simp only [step, heard, hs]
      all_goals first
        | (split
           · exact reading_good c s _ r _ _ hc h1 h2 h3 h4
           · exact reading_good c _ _ r _ _ hc (by simpa using h1) (by simpa using h2)
               (by simpa using h3) (by simpa using h4))
        | exact gs
    | earlier p stream r ad v =>
      simp only [step]
      split
      · exact gs
      · have inside : ∀ u : State, u.server = s.server → u.round = s.round →
            u.candidate = s.candidate → u.hops = s.hops → Good c u :=
          fun u e1 e2 e3 e4 => Or.inr ⟨e1 ▸ h1, e2 ▸ h2, e3 ▸ h3, e4 ▸ h4⟩
        exact (earlierHeard_of c s p stream r ad v (Good c) (fun _ => True)
          (onReply_good c _ _ r hc (by simpa using h1) (by simpa using h2) (by simpa using h3)
            (by simpa using h4))
          trivial trivial (fun _ h => h) (fun _ h => h) (fun _ h => h)
          (inside _ (by simp) (by simp) (by simp) (by simp))
          (fun _ => inside _ (by simp [keepAt]) (by simp [keepAt]) (by simp [keepAt]) (by simp [keepAt]))
          (Or.inl (by simp [fail, ended]))
          (inside _ (by simp) (by simp) (by simp) (by simp))).1
    | earlierFailed p stream r =>
      simp only [step]
      split
      · exact gs
      · unfold earlierFailed
        split
        · exact Or.inr ⟨h1, h2, h3, h4⟩
        · exact Or.inr ⟨by simpa [keepAt] using h1, by simpa [keepAt] using h2,
            by simpa [keepAt] using h3, by simpa [keepAt] using h4⟩
    | keysReady =>
      simp only [step]
      split
      · unfold keysCame
        refine retry_of c s _ _ _ (Good c) (Or.inr ⟨h1, h2, h3, h4⟩) (fun u hu => ?_)
        rcases hu with rfl | ⟨k, rfl⟩
        · exact advanceServer_good c _ hc h2 h4 h3
        · exact advanceServer_good c _ hc h2 h4 h3
      · exact gs
    | keysFailed w =>
      simp only [step]
      split
      · left; cases w <;> simp [walkFailed, fail, ended]
      · exact gs
    | cancel =>
      simp only [step]
      split
      · exact gs
      · left; simp [fail, ended]

end Spec.Lookup
