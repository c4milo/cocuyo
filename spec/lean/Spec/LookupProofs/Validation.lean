import Spec.LookupProofs.Security

/-!
# What a validating lookup promises

Stage B of docs/design.md §25, step 11, and the theorems "The models" names:

- `keys_wait_sends_nothing`: a lookup that waits for keys asks for nothing to be sent, whatever
  the caller tells it.
- `secure_run` and `checked_clears`: Stage B's conjunction, once clear, stays clear, and a message
  the validator calls insecure, or one the lookup takes with no verdict, clears it. So
  `secure_needs_secure`: an end that is `secure` met no such message.
- `bogus_adds_nothing`: a message the validator calls bogus moves the lookup to no other name,
  adds no hop, no NODATA and no answer, and leaves the conjunction where it was.
- `validate_edns`: a validating lookup never sends a query without EDNS0.

The measure that proves every lookup ends still falls at every send: `step_le`, `sent_lt` and
`lexLt_wf` cover the new state and events (`LookupProofs/Measure.lean`).
-/
namespace Spec.Lookup

/-- A send the lookup may ask for. -/
def Sends (o : Out) : Prop := o = .sendUdp ∨ o = .connectTcp ∨ o = .sendTcp ∨ o = .sendRequest

/-- A reply answers `accepted` or `ignored`, whatever it moves. -/
theorem onReply_out (c : Config) (s : State) (b : Bool) (r : Reply) :
    (onReply c s b r).2 = .accepted ∨ (onReply c s b r).2 = .ignored := by
  cases r <;> simp only [onReply] <;> (try split) <;> (try split) <;> simp

/-- A lookup that waits for keys asks for nothing to be sent: its poll says `wait`, no deadline
bounds it, and every other event answers nothing or ignores a reply (docs/design.md §25). -/
theorem keys_wait_sends_nothing (c : Config) (s : State) (e : Event)
    (h : s.stage = .awaitingKeys) : ¬ Sends (step c s e).2 := by
  cases e
  case earlier p stream r ad v =>
    simp only [step]
    split
    · simp [Sends]
    · exact (earlierHeard_of c s p stream r ad v (fun _ => True) (¬ Sends ·) trivial
        (by rcases onReply_out c (closeTry s stream p) (stream || c.request) r with o | o <;>
              simp [o, Sends])
        (by simp [Sends]) (fun _ _ => trivial) (fun _ _ => trivial) (fun _ _ => trivial) trivial
        (fun _ => trivial) trivial trivial).2
  case earlierFailed p stream r => simp only [step]; split <;> simp [Sends]
  all_goals simp [step, h, poll, waiting, heard, onStream, Sends] <;> split <;> simp

/-! ## Secure only when every message was -/


theorem advanceServer_secure (c : Config) (s : State) :
    (advanceServer c s).secure = s.secure := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

theorem retry_secure (c : Config) (s t : State) (b : Bool) (w : Option What)
    (ht : t.secure = s.secure) : (retry c s t b w).secure = s.secure := by
  refine retry_of c s t b w (fun u => u.secure = s.secure) ht (fun u hu => ?_)
  rcases hu with rfl | ⟨k, rfl⟩
  · exact advanceServer_secure c _
  · rw [advanceServer_secure]; rfl

theorem nextCandidate_secure (c : Config) (s : State) (b : Bool) :
    (nextCandidate c s b).secure = s.secure := by
  unfold nextCandidate
  dsimp only
  split <;> simp [fail]

/-- A reply moves the lookup and leaves Stage B's conjunction where it was. -/
theorem onReply_secure (c : Config) (s : State) (stream : Bool) (r : Reply) :
    (onReply c s stream r).1.secure = s.secure := by
  cases r with
  | unmatched => rfl
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_secure c s true
    · exact retry_secure c s _ _ _ rfl
  | answer => rfl
  | cname => simp only [onReply]; split <;> simp [fail]
  | nxdomain => exact nextCandidate_secure c s false
  | nodata => exact nextCandidate_secure c s true
  | yxdomain => simp [onReply, fail]
  | servfail => simp only [onReply]; rw [advanceServer_secure]; rfl
  | formerr =>
    simp only [onReply]
    split
    · exact retry_secure c s _ _ _ rfl
    · rw [advanceServer_secure]; rfl
  | badcookie =>
    simp only [onReply]
    split
    · split
      · rw [advanceServer_secure]; rfl
      · exact retry_secure c s _ _ _ rfl
    · split
      · exact retry_secure c s _ _ _ rfl
      · exact retry_secure c s _ _ _ rfl

theorem rejected_secure (c : Config) (s : State) (stream : Bool) :
    (rejected c s stream).secure = s.secure := by
  unfold rejected
  split
  · rw [advanceServer_secure]; rfl
  · exact retry_secure c s _ _ _ rfl

theorem reading_secure (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (h : (reading c s stream r ad v).1.secure = true) : s.secure = true :=
  (reading_of c s stream r ad v (fun x => x.secure = true → s.secure = true) (fun _ => True)
    (fun hx => by rwa [onReply_secure] at hx) trivial trivial (fun _ hu hx => hu hx)
    (fun _ _ hx => by simp at hx) (fun hx => by rwa [rejected_secure] at hx)
    (fun _ hx => hx)).1 h

theorem poll_secure (c : Config) (s : State) : (poll c s).1.secure = s.secure := by
  unfold poll
  cases s.stage <;> rfl

/-- No event sets Stage B's conjunction again once it is clear. -/
theorem step_secure (c : Config) (s : State) (e : Event) (h : (step c s e).1.secure = true) :
    s.secure = true := by
  cases e with
  | poll => simp only [step] at h; rwa [poll_secure] at h
  | expire =>
    simp only [step] at h
    split at h
    · rwa [poll_secure, advanceServer_secure] at h
    · rwa [poll_secure] at h
  | sent => cases hs : s.stage <;> simp_all [step]
  | sendFailed =>
    cases hs : s.stage <;> simp only [step, hs] at h <;> first
      | rwa [advanceServer_secure] at h
      | exact h
  | tcpConnected => cases hs : s.stage <;> simp_all [step]
  | tcpFailed _ | requestFailed _ =>
    simp only [step] at h
    split at h
    · rw [advanceServer_secure] at h; exact h
    · exact h
  | reply r | replyAd r | replyChecked r _ =>
    cases hs : s.stage <;> simp only [step, heard, hs] at h <;> first
      | (split at h <;> simpa using reading_secure c _ _ r _ _ h)
      | exact h
  | earlier p stream r ad v =>
    simp only [step] at h
    split at h
    · exact h
    · exact (earlierHeard_of c s p stream r ad v (fun x => x.secure = true → s.secure = true)
        (fun _ => True) (fun hx => by rwa [onReply_secure, closeTry_secure] at hx) trivial
        trivial (fun _ hu hx => hu hx) (fun _ hu hx => hu hx) (fun _ _ hx => by simp at hx)
        (fun hx => by simpa using hx) (fun _ hx => by simpa [keepAt] using hx)
        (fun hx => by simpa [fail] using hx) (fun hx => by simpa using hx)).1 h
  | earlierFailed p stream r =>
    simp only [step] at h
    split at h
    · exact h
    · unfold earlierFailed at h; split at h <;> simpa [keepAt] using h
  | keysReady =>
    simp only [step] at h
    split at h
    · unfold keysCame at h
      have e := retry_secure c s { s with stage := fresh c } c.useTcp none rfl
      simp only at h
      rwa [e] at h
    · exact h
  | keysFailed w =>
    simp only [step] at h
    split at h
    · cases w <;> simpa [walkFailed, fail, keep] using h
    · exact h
  | cancel =>
    simp only [step] at h
    split at h <;> exact h

/-- Whatever the caller tells a lookup, a clear conjunction stays clear. -/
theorem secure_run (c : Config) (s : State) (es : List Event)
    (h : (run c s es).secure = true) : s.secure = true := by
  induction es generalizing s with
  | nil => exact h
  | cons e rest ih => exact step_secure c s e (ih _ h)

/-- Under validation, a message the lookup acts on clears Stage B's conjunction when the validator
calls it insecure, and when it comes with no verdict, while the lookup waits for it: over UDP, DoH
and DoQ in `awaitingUdp`, and over a stream in `awaitingTcp`. -/
theorem checked_clears (c : Config) (s : State) (r : Reply) (hv : c.validate = true)
    (e : Event) (he : e = .replyChecked r .insecure ∨ e = .reply r) :
    (s.stage = .awaitingUdp → actsOn c.request r = true → (step c s e).1.secure = false) ∧
    (s.stage = .awaitingTcp → actsOn true r = true → (step c s e).1.secure = false) := by
  rcases he with rfl | rfl <;> constructor <;> intro hs ha <;>
    simp [step, heard, reading, checked, hs, ha, hv]

/-- An end that is `secure` rests on a validating configuration and on the conjunction. -/
theorem secure_of (c : Config) (s : State) (h : security c s = .secure) :
    c.validate = true ∧ s.secure = true := by
  unfold security at h
  split at h
  · rename_i hv; split at h <;> simp_all
  · split at h <;> simp at h

/-- A lookup that ends `secure` met no message it acts on that the validator called insecure, nor
one it took with no verdict, at any point of its run while it waited for one. -/
theorem secure_needs_secure (c : Config) (pre es : List Event) (r : Reply) (e : Event)
    (he : e = .replyChecked r .insecure ∨ e = .reply r)
    (h : security c (run c (init c) (pre ++ e :: es)) = .secure) :
    ¬ (((run c (init c) pre).stage = .awaitingUdp ∧ actsOn c.request r = true) ∨
        ((run c (init c) pre).stage = .awaitingTcp ∧ actsOn true r = true)) := by
  intro hs
  obtain ⟨hv, hsec⟩ := secure_of c _ h
  rw [run_append] at hsec
  have hafter : (step c (run c (init c) pre) e).1.secure = true := secure_run c _ es hsec
  have hclear := checked_clears c (run c (init c) pre) r hv e he
  rcases hs with ⟨hst, hact⟩ | ⟨hst, hact⟩
  · rw [hclear.1 hst hact] at hafter; simp at hafter
  · rw [hclear.2 hst hact] at hafter; simp at hafter

/-- A message of an open earlier try that the validator calls insecure, one the lookup acts on,
clears Stage B's conjunction as the current try's does (docs/design.md §5, Tries kept open; §25,
Stage B). -/
theorem earlier_checked_clears (c : Config) (s : State) (p : Nat) (stream : Bool) (r : Reply)
    (hv : c.validate = true) (hn : ended s.stage = false) (ho : earlierOpen s stream p ≠ 0)
    (ha : actsOn (stream || c.request) r = true) :
    (step c s (.earlier p stream r false (some .insecure))).1.secure = false := by
  simp only [step, earlierHeard, hn, ho, ha, hv]
  simp only [Bool.false_eq_true, false_or, if_false, if_true, Option.getD_some, earlierChecked]
  by_cases hst : (onReply c (closeTry s stream p) (stream || c.request) r).1.stage = s.stage <;>
    simp [hst]

/-- A lookup that ends `secure` met no message of an earlier try that the validator called
insecure. -/
theorem secure_needs_secure_earlier (c : Config) (pre es : List Event) (p : Nat) (stream : Bool)
    (r : Reply)
    (h : security c (run c (init c) (pre ++ Event.earlier p stream r false (some .insecure) :: es)) =
      .secure) :
    ¬ (ended (run c (init c) pre).stage = false ∧ earlierOpen (run c (init c) pre) stream p ≠ 0 ∧
        actsOn (stream || c.request) r = true) := by
  intro ⟨hn, ho, hact⟩
  obtain ⟨hv, hsec⟩ := secure_of c _ h
  rw [run_append] at hsec
  have hafter := secure_run c _ es hsec
  rw [earlier_checked_clears c _ p stream r hv hn ho hact] at hafter
  simp at hafter

/-! ## A bogus message adds nothing -/

/-- A message the validator calls bogus, one the validating lookup acts on and waits for, moves
the lookup to no other name, adds no CNAME hop and no NODATA, ends it in no answer, and leaves Stage B's conjunction where it was. Only the server, or
the transport, changes (docs/design.md §25, Stage B: what the lookup does with it). -/
theorem bogus_adds_nothing (c : Config) (s : State) (r : Reply) (hv : c.validate = true)
    (hw : (s.stage = .awaitingUdp ∧ actsOn c.request r = true) ∨
      (s.stage = .awaitingTcp ∧ actsOn true r = true)) :
    let t := (step c s (.replyChecked r .bogus)).1
    t.candidate = s.candidate ∧ t.hops = s.hops ∧ t.hadNoData = s.hadNoData ∧
      t.secure = s.secure ∧ t.stage ≠ .done := by
  have hadv : ∀ u : State, u.candidate = s.candidate → u.hops = s.hops →
      u.hadNoData = s.hadNoData → u.secure = s.secure →
      (advanceServer c u).candidate = s.candidate ∧ (advanceServer c u).hops = s.hops ∧
        (advanceServer c u).hadNoData = s.hadNoData ∧ (advanceServer c u).secure = s.secure ∧
        (advanceServer c u).stage ≠ .done := by
    intro u h1 h2 h3 h4
    obtain ⟨a1, a2, _, _⟩ := advanceServer_counts c u
    have a3 : (advanceServer c u).hadNoData = u.hadNoData := by
      fun_induction advanceServer c u <;> simp_all +zetaDelta [fail]
    refine ⟨a1.trans h1, a2.trans h2, a3.trans h3, (advanceServer_secure c u).trans h4, ?_⟩
    rcases advanceServer_stage c u with hs | ⟨_, hs⟩ | hs <;> rw [hs]
    · unfold fresh; split <;> simp
    · simp
    · simp
  -- The reply closes the current try first, which changes none of these counters.
  have hrej : ∀ (u : State) (stream : Bool), u.candidate = s.candidate → u.hops = s.hops →
      u.hadNoData = s.hadNoData → u.secure = s.secure → let t := rejected c u stream
      t.candidate = s.candidate ∧ t.hops = s.hops ∧ t.hadNoData = s.hadNoData ∧
        t.secure = s.secure ∧ t.stage ≠ .done := by
    intro u stream h1 h2 h3 h4
    unfold rejected
    split
    · exact hadv _ h1 h2 h3 h4
    · refine retry_of c u _ _ _ (fun t => t.candidate = s.candidate ∧ t.hops = s.hops ∧
        t.hadNoData = s.hadNoData ∧ t.secure = s.secure ∧ t.stage ≠ .done)
        ⟨h1, h2, h3, h4, by simp⟩ (fun w hw => ?_)
      rcases hw with rfl | ⟨k, rfl⟩
      · exact hadv _ h1 h2 h3 h4
      · exact hadv _ h1 h2 h3 h4
  have hr : r ≠ .unmatched := by
    rintro rfl; rcases hw with ⟨_, ha⟩ | ⟨_, ha⟩ <;> simp [actsOn] at ha
  rcases hw with ⟨hs, ha⟩ | ⟨hs, ha⟩ <;>
    simp only [step, heard, hs, if_neg hr, reading, hv, closeTry_stage, ha, Bool.and_self,
      ↓reduceIte, Option.getD_some, checked] <;>
    exact hrej _ _ (by simp) (by simp) (by simp) (by simp)

/-! ## EDNS0 stays on -/

theorem advanceServer_edns (c : Config) (s : State) (h : s.edns = true) :
    (advanceServer c s).edns = true := by
  revert h
  fun_induction advanceServer c s <;> intro h <;> simp_all +zetaDelta [fail]

theorem retry_edns (c : Config) (s t : State) (b : Bool) (w : Option What) (h : s.edns = true)
    (ht : t.edns = true) : (retry c s t b w).edns = true := by
  refine retry_of c s t b w (fun u => u.edns = true) ht (fun u hu => ?_)
  rcases hu with rfl | ⟨k, rfl⟩
  · exact advanceServer_edns c _ h
  · exact advanceServer_edns c _ h

theorem nextCandidate_edns (c : Config) (s : State) (b : Bool) (h : s.edns = true) :
    (nextCandidate c s b).edns = true := by
  unfold nextCandidate
  dsimp only
  split <;> simp [fail, h]

theorem onReply_edns (c : Config) (s : State) (stream : Bool) (r : Reply) (hv : c.validate = true)
    (h : s.edns = true) : (onReply c s stream r).1.edns = true := by
  cases r with
  | unmatched | answer => simpa [onReply] using h
  | truncated =>
    simp only [onReply]
    split
    · exact nextCandidate_edns c s true h
    · exact retry_edns c s _ _ _ h h
  | cname => simp only [onReply]; split <;> simp [fail, h]
  | nxdomain => exact nextCandidate_edns c s false h
  | nodata => exact nextCandidate_edns c s true h
  | yxdomain => simp [onReply, fail, h]
  | servfail => exact advanceServer_edns c _ h
  | formerr =>
    simp only [onReply, hv]
    simp only [Bool.not_true, Bool.and_false, Bool.false_eq_true, ↓reduceIte]
    exact advanceServer_edns c _ h
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact advanceServer_edns c _ h
      · exact retry_edns c s _ _ _ h h
    · split
      · exact retry_edns c s _ _ _ h h
      · exact retry_edns c s _ _ _ h h

theorem reading_edns (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) (hv : c.validate = true) (h : s.edns = true) :
    (reading c s stream r ad v).1.edns = true := by
  have hrej : (rejected c s stream).edns = true := by
    unfold rejected
    split
    · exact advanceServer_edns c _ h
    · exact retry_edns c s _ _ _ h h
  exact (reading_of c s stream r ad v (fun x => x.edns = true) (fun _ => True)
    (onReply_edns c s stream r hv h) trivial trivial (fun _ hu => hu) (fun _ hu => hu) hrej
    (fun _ => h)).1

/-- A validating lookup keeps EDNS0 on, whatever the caller tells it (docs/design.md §25, Stage
B rule 4). -/
theorem step_edns (c : Config) (s : State) (e : Event) (hv : c.validate = true)
    (h : s.edns = true) : (step c s e).1.edns = true := by
  have hpoll : ∀ t : State, t.edns = true → (poll c t).1.edns = true := by
    intro t ht; unfold poll; cases t.stage <;> exact ht
  cases e with
  | poll => exact hpoll s h
  | expire =>
    simp only [step]
    split
    · exact hpoll _ (advanceServer_edns c s h)
    · exact hpoll s h
  | sent => cases hs : s.stage <;> simp_all [step]
  | sendFailed =>
    cases hs : s.stage <;> simp only [step, hs] <;> first
      | exact advanceServer_edns c s h
      | exact h
  | tcpConnected => cases hs : s.stage <;> simp_all [step]
  | tcpFailed _ | requestFailed _ =>
    simp only [step]
    split
    · exact advanceServer_edns c _ h
    · exact h
  | reply r | replyAd r | replyChecked r _ =>
    cases hs : s.stage <;> simp only [step, heard, hs] <;> first
      | (split <;> exact reading_edns c _ _ r _ _ hv (by simpa using h))
      | exact h
  | earlier p stream r ad v =>
    simp only [step]
    split
    · exact h
    · exact (earlierHeard_of c s p stream r ad v (fun x => x.edns = true) (fun _ => True)
        (onReply_edns c _ _ r hv (by simpa using h)) trivial trivial (fun _ hu => hu)
        (fun _ hu => hu) (fun _ hu => hu) (by simpa using h) (fun _ => by simpa [keepAt] using h)
        (by simpa [fail] using h) (by simpa using h)).1
  | earlierFailed p stream r =>
    simp only [step]
    split
    · exact h
    · unfold earlierFailed; split <;> simpa [keepAt] using h
  | keysReady =>
    simp only [step]
    split
    · exact retry_edns c s _ _ _ h h
    · exact h
  | keysFailed w =>
    simp only [step]
    split
    · cases w <;> simp [walkFailed, fail, keep, h]
    · exact h
  | cancel =>
    simp only [step]
    split
    · exact h
    · simp [fail, h]

/-- A validating lookup never sends a query without EDNS0: every state it reaches has it on. -/
theorem validate_edns (c : Config) (es : List Event) (hv : c.validate = true) :
    (run c (init c) es).edns = true := by
  have key : ∀ (es : List Event) (t : State), t.edns = true → (run c t es).edns = true := by
    intro es
    induction es with
    | nil => intro t h; exact h
    | cons e rest ih => intro t h; exact ih _ (step_edns c t e hv h)
  exact key es _ (by unfold init; split <;> simp [fail])

end Spec.Lookup
