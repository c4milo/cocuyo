import Spec.LookupProofs.Timeout

/-!
# When a lookup ends `authenticated`

Stage A of docs/design.md §25. A lookup ends `authenticated` when the configuration relies on the
AD bit, and every message the lookup acted on had it set (rule 3): each link of a CNAME chain that
spans messages, each negative that moved it to the next search candidate, and the message that
ended it. Three theorems hold it:

- `ignored_unchecked`: under `ignored`, no end is `authenticated`, whatever the servers say.
- `authentic_run`: once rule 3's conjunction is clear, no event sets it again.
- `reply_clears`: a message without AD that the lookup acts on clears it, when the configuration
  relies on the bit.

So a lookup that ends `authenticated` acted on no message without AD.
-/
namespace Spec.Lookup

/-- Under `ignored` the AD bit means nothing, so no end is `authenticated` (RFC 4035 §4.6). -/
theorem ignored_unchecked (c : Config) (s : State) (h : c.authenticatedData = .ignored) :
    security c s = .unchecked := by
  simp [security, relied, h]

/-- An end that is `authenticated` rests on a configuration that relies on the bit, and on rule 3's
conjunction. -/
theorem authenticated_of (c : Config) (s : State) (h : security c s = .authenticated) :
    relied c = true ∧ s.authentic = true := by
  unfold security at h
  split at h
  · rename_i hc; simpa using hc
  · simp at h

theorem advanceServer_authentic (c : Config) (s : State) :
    (advanceServer c s).authentic = s.authentic := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

theorem nextCandidate_authentic (c : Config) (s : State) (b : Bool) :
    (nextCandidate c s b).authentic = s.authentic := by
  unfold nextCandidate
  dsimp only
  split <;> simp [fail]

theorem retry_authentic (c : Config) (s t : State) (b : Bool) (w : Option What)
    (ht : t.authentic = s.authentic) : (retry c s t b w).authentic = s.authentic := by
  refine retry_of c s t b w (fun u => u.authentic = s.authentic) ht (fun u hu => ?_)
  rcases hu with rfl | ⟨k, rfl⟩
  · exact advanceServer_authentic c _
  · rw [advanceServer_authentic]; rfl

/-- A reply moves the lookup and leaves rule 3's conjunction where it was: `heard` alone clears
it. -/
theorem onReply_authentic (c : Config) (s : State) (stream : Bool) (r : Reply) :
    (onReply c s stream r).1.authentic = s.authentic := by
  cases r with
  | unmatched => rfl
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_authentic c s true
    · exact retry_authentic c s _ _ _ rfl
  | answer => rfl
  | cname => simp only [onReply]; split <;> simp [fail]
  | nxdomain => exact nextCandidate_authentic c s false
  | nodata => exact nextCandidate_authentic c s true
  | yxdomain => simp [onReply, fail]
  | servfail => simp only [onReply]; rw [advanceServer_authentic]; rfl
  | formerr =>
    simp only [onReply]
    split
    · exact retry_authentic c s _ _ _ rfl
    · rw [advanceServer_authentic]; rfl
  | badcookie =>
    simp only [onReply]
    split
    · split
      · rw [advanceServer_authentic]; rfl
      · exact retry_authentic c s _ _ _ rfl
    · split
      · exact retry_authentic c s _ _ _ rfl
      · exact retry_authentic c s _ _ _ rfl

theorem clear_authentic (c : Config) (a d : Bool) (t : State)
    (h : (clear c a d t).authentic = true) : t.authentic = true := by
  unfold clear at h
  split at h
  · simp at h
  · exact h

theorem poll_authentic (c : Config) (s : State) : (poll c s).1.authentic = s.authentic := by
  unfold poll
  cases s.stage <;> rfl

/-- No event sets rule 3's conjunction again once it is clear. -/
theorem step_authentic (c : Config) (s : State) (e : Event)
    (h : (step c s e).1.authentic = true) : s.authentic = true := by
  cases e with
  | poll => simp only [step] at h; rwa [poll_authentic] at h
  | expire =>
    simp only [step] at h
    split at h
    · rwa [poll_authentic, advanceServer_authentic] at h
    · rwa [poll_authentic] at h
  | sent => cases hs : s.stage <;> simp_all [step]
  | sendFailed =>
    cases hs : s.stage <;> simp only [step, hs] at h <;> first
      | rwa [advanceServer_authentic] at h
      | exact h
  | tcpConnected => cases hs : s.stage <;> simp_all [step]
  | tcpFailed _ =>
    simp only [step] at h
    split at h
    · rw [advanceServer_authentic] at h; exact h
    · exact h
  | requestFailed _ =>
    simp only [step] at h
    split at h
    · rw [advanceServer_authentic] at h; exact h
    · exact h
  | reply r | replyAd r =>
    cases hs : s.stage <;> simp only [step, heard, hs] at h <;> first
      | (have := clear_authentic c _ _ _ h; rwa [onReply_authentic] at this)
      | exact h
  | cancel =>
    simp only [step] at h
    split at h
    · exact h
    · exact h

/-- Whatever the caller tells a lookup, a clear conjunction stays clear: an end that is
`authenticated` began from a state where the conjunction held, and passed no message that cleared
it. -/
theorem authentic_run (c : Config) (s : State) (es : List Event)
    (h : (run c s es).authentic = true) : s.authentic = true := by
  induction es generalizing s with
  | nil => exact h
  | cons e rest ih => exact step_authentic c s e (ih _ h)

/-- A message without AD that the lookup acts on, while it waits for one, clears rule 3's
conjunction when the configuration relies on the bit (docs/design.md §25, Stage A rule 3). Over
UDP, DoH and DoQ the lookup waits in `awaitingUdp`, and over a stream in `awaitingTcp`. -/
theorem reply_clears (c : Config) (s : State) (r : Reply) (hr : relied c = true) :
    (s.stage = .awaitingUdp → actsOn c.request r = true →
      (step c s (.reply r)).1.authentic = false) ∧
    (s.stage = .awaitingTcp → actsOn true r = true →
      (step c s (.reply r)).1.authentic = false) := by
  constructor
  · intro hs ha; simp [step, heard, clear, hs, ha, hr]
  · intro hs ha; simp [step, heard, clear, hs, ha, hr]

/-- A run over two lists is the run over the second from where the first left the lookup. -/
theorem run_append (c : Config) (t : State) (pre rest : List Event) :
    run c t (pre ++ rest) = run c (run c t pre) rest := by
  induction pre generalizing t with
  | nil => rfl
  | cons e more ih => exact ih _

/-- A lookup that ends `authenticated` acted on no message without AD: at no point of its run did a
reply without AD reach it, waiting, of a kind it acts on. -/
theorem authenticated_needs_ad (c : Config) (pre es : List Event) (r : Reply)
    (h : security c (run c (init c) (pre ++ Event.reply r :: es)) = .authenticated) :
    ¬ (((run c (init c) pre).stage = .awaitingUdp ∧ actsOn c.request r = true) ∨
        ((run c (init c) pre).stage = .awaitingTcp ∧ actsOn true r = true)) := by
  intro hs
  obtain ⟨hr, ha⟩ := authenticated_of c _ h
  rw [run_append] at ha
  have hafter : (step c (run c (init c) pre) (.reply r)).1.authentic = true :=
    authentic_run c _ es ha
  have hclear := reply_clears c (run c (init c) pre) r hr
  rcases hs with ⟨hst, hact⟩ | ⟨hst, hact⟩
  · rw [hclear.1 hst hact] at hafter; simp at hafter
  · rw [hclear.2 hst hact] at hafter; simp at hafter

end Spec.Lookup
