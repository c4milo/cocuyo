import Spec.Lookup

/-!
# What the lookup state machine guarantees

Each theorem is a property docs/design.md promises of `Lookup`, proved of the model in
`Spec.Lookup`. The sequence check (`spec/lean/Main.lean`, `zig build spec`) is what ties the model
to the Zig code; these tie the model to the promises.
-/
namespace Spec.Lookup

/-- A cause kept is a cause held, whatever the server gave. -/
theorem keep_isSome (s : State) (w : What) : (keep s w).cause.isSome = true := by
  unfold keep
  cases s.cause <;> rfl

/-- A property that rule 3's flag does not touch holds after `clear` when it held before: `clear`
changes that flag alone (docs/design.md §25, Stage A). -/
theorem clear_keeps (P : State → Prop) (c : Config) (a d : Bool) (t : State)
    (hP : ∀ u : State, P u → P { u with authentic := false }) (h : P t) : P (clear c a d t) := by
  unfold clear
  split
  · exact hP t h
  · exact h

/-! ## An ended lookup stays ended -/

/-- A lookup that is done or has failed is changed by nothing: every poll returns the same end,
every reply is ignored, and a cancel leaves the end standing (§5's last row; the cancel rule of
`Resolver.cancel`). -/
theorem ended_absorbing (c : Config) (s : State) (e : Event) (h : ended s.stage = true) :
    (step c s e).1 = s := by
  cases e <;> cases hs : s.stage <;> simp_all [step, heard, poll, ended, waiting, onStream]

/-- A cancel after the end changes nothing, and says nothing. -/
theorem cancel_after_end (c : Config) (s : State) (h : ended s.stage = true) :
    step c s .cancel = (s, .none) := by
  simp [step, h]

/-- A cancel before the end fails the lookup as cancelled. -/
theorem cancel_before_end (c : Config) (s : State) (h : ended s.stage = false) :
    (step c s .cancel).1.stage = .failed ∧ (step c s .cancel).1.err = .canceled := by
  simp [step, h, fail]

/-! ## Every query over TCP means no datagram, ever -/

/-- A state a lookup under `use_tcp` can be in: never one that sends or awaits a datagram. -/
def NoUdp (s : State) : Prop := s.stage ≠ .queryReady ∧ s.stage ≠ .awaitingUdp

theorem fresh_tcp (c : Config) (h : c.useTcp = true) : fresh c = .tcpNeeded := by
  simp [fresh, h]

theorem init_noUdp (c : Config) (h : c.useTcp = true) : NoUdp (init c) := by
  unfold init NoUdp fail
  split <;> simp [fresh, h]

/-- After either advance a lookup stands where it stands before any query, or has failed. -/
theorem advanceServer_stage (c : Config) (s : State) :
    (advanceServer c s).stage = fresh c ∨ (advanceServer c s).stage = .failed := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

/-- The next server keeps the cause, the name, the hops and the queries each server got. -/
theorem advanceServer_cause (c : Config) (s : State) : (advanceServer c s).cause = s.cause := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

theorem advanceServer_counts (c : Config) (s : State) :
    (advanceServer c s).candidate = s.candidate ∧ (advanceServer c s).hops = s.hops ∧
      (advanceServer c s).datagrams = s.datagrams ∧ (advanceServer c s).streams = s.streams := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail]

/-- A lookup that the next server leaves running is on a server of the configuration. -/
theorem advanceServer_inside (c : Config) (s : State) (hs : 0 < c.servers) :
    ended (advanceServer c s).stage = false → (advanceServer c s).server < c.servers := by
  fun_induction advanceServer c s <;> simp_all +zetaDelta [fail, ended]

/-- A lookup that the next server leaves running is on a pass of the configuration. -/
theorem advanceServer_round (c : Config) (s : State) (hr : s.round < c.attempts) :
    ended (advanceServer c s).stage = false → (advanceServer c s).round < c.attempts := by
  revert hr
  fun_induction advanceServer c s <;> intro hr
  · rename_i ih; exact ih hr
  · intro _; simpa using hr
  · rename_i ih; exact ih (by simp +zetaDelta; omega)
  · intro _; simp +zetaDelta; omega
  · simp [fail, ended]

/-- A retry is the state it names, or the next server after the current one, with the cause the
reply gave when it gave one (RFC 9520 §3.1). So a property of both holds of the retry. -/
theorem retry_of (c : Config) (s t : State) (b : Bool) (w : Option What) (P : State → Prop)
    (ht : P t) (ha : ∀ u : State, (u = s ∨ ∃ k, u = keep s k) → P (advanceServer c u)) :
    P (retry c s t b w) := by
  unfold retry
  split
  · cases w with
    | none => exact ha s (Or.inl rfl)
    | some k => exact ha _ (Or.inr ⟨k, rfl⟩)
  · exact ht

theorem nextCandidate_stage (c : Config) (s : State) (b : Bool) :
    (nextCandidate c s b).stage = fresh c ∨ (nextCandidate c s b).stage = .failed := by
  unfold nextCandidate fail
  dsimp only
  split <;> simp

theorem noUdp_of_stage (c : Config) (s : State) (h : c.useTcp = true)
    (hs : s.stage = fresh c ∨ s.stage = .failed) : NoUdp s := by
  rcases hs with hs | hs <;> simp [NoUdp, hs, fresh, h]

theorem poll_noUdp (c : Config) (s : State) (inv : NoUdp s) :
    NoUdp (poll c s).1 ∧ (poll c s).2 ≠ .sendUdp := by
  obtain ⟨hq, ha⟩ := inv
  unfold poll NoUdp
  cases hs : s.stage <;> simp_all

theorem onReply_noUdp (c : Config) (s : State) (stream : Bool) (r : Reply) (h : c.useTcp = true)
    (inv : NoUdp s) : NoUdp (onReply c s stream r).1 ∧ (onReply c s stream r).2 ≠ .sendUdp := by
  have hadv : ∀ t, NoUdp (advanceServer c t) := fun t => noUdp_of_stage c _ h (advanceServer_stage c t)
  have hnxt : ∀ t b, NoUdp (nextCandidate c t b) :=
    fun t b => noUdp_of_stage c _ h (nextCandidate_stage c t b)
  cases r with
  | unmatched => exact ⟨inv, by simp [onReply]⟩
  | truncated =>
    cases stream
    · exact ⟨retry_of c s _ _ _ NoUdp (by simp [NoUdp]) (fun u _ => hadv u), by simp [onReply]⟩
    · exact ⟨hnxt s true, by simp [onReply]⟩
  | answer => exact ⟨by simp [onReply, NoUdp], by simp [onReply]⟩
  | cname =>
    simp only [onReply]
    split
    · exact ⟨by simp [NoUdp, fail], by simp⟩
    · exact ⟨by simp [NoUdp, fresh, h], by simp⟩
  | nxdomain => exact ⟨hnxt s false, by simp [onReply]⟩
  | nodata => exact ⟨hnxt s true, by simp [onReply]⟩
  | yxdomain => exact ⟨by simp [onReply, NoUdp, fail], by simp [onReply]⟩
  | servfail => exact ⟨hadv _, by simp [onReply]⟩
  | formerr =>
    simp only [onReply]
    split
    · exact ⟨retry_of c s _ _ _ NoUdp (by simp [NoUdp, fresh, h]) (fun u _ => hadv u), by simp⟩
    · exact ⟨hadv _, by simp⟩
  | badcookie =>
    simp only [onReply]
    split
    · split
      · exact ⟨hadv _, by simp⟩
      · exact ⟨retry_of c s _ _ _ NoUdp (by simp [NoUdp]) (fun u _ => hadv u), by simp⟩
    · split
      · exact ⟨retry_of c s _ _ _ NoUdp (by simp [NoUdp]) (fun u _ => hadv u), by simp⟩
      · exact ⟨retry_of c s _ _ _ NoUdp (by simp [NoUdp, fresh, h]) (fun u _ => hadv u), by simp⟩

/-- Under `use_tcp` (§19 step 11), a lookup never asks for a datagram to be sent, whatever the
caller tells it: every state it reaches is one of the stream states or an end. -/
theorem useTcp_never_udp (c : Config) (s : State) (e : Event) (h : c.useTcp = true)
    (inv : NoUdp s) : NoUdp (step c s e).1 ∧ (step c s e).2 ≠ .sendUdp := by
  have hadv : ∀ t, NoUdp (advanceServer c t) := fun t => noUdp_of_stage c _ h (advanceServer_stage c t)
  obtain ⟨hq, ha⟩ := inv
  cases e with
  | poll => exact poll_noUdp c s ⟨hq, ha⟩
  | expire =>
    simp only [step]
    split
    · exact poll_noUdp c _ (hadv s)
    · exact poll_noUdp c s ⟨hq, ha⟩
  | sent => cases hs : s.stage <;> simp_all [step, NoUdp]
  | sendFailed =>
    cases hs : s.stage <;> simp only [step, hs] <;> first | exact ⟨hadv s, by simp⟩ | exact ⟨⟨hq, ha⟩, by simp⟩ | simp_all
  | tcpConnected => cases hs : s.stage <;> simp_all [step, NoUdp]
  | tcpFailed _ =>
    simp only [step]
    split
    · exact ⟨hadv _, by simp⟩
    · exact ⟨⟨hq, ha⟩, by simp⟩
  | requestFailed _ =>
    simp only [step]
    split
    · exact ⟨hadv _, by simp⟩
    · exact ⟨⟨hq, ha⟩, by simp⟩
  | reply r | replyAd r =>
    cases hs : s.stage <;> simp only [step, heard, hs]
    all_goals first
      | exact (fun ⟨h1, h2⟩ => ⟨clear_keeps NoUdp c _ _ _ (fun _ h => h) h1, h2⟩)
          (onReply_noUdp c s _ r h ⟨hq, ha⟩)
      | exact ⟨⟨hq, ha⟩, by simp⟩
      | simp_all
  | cancel =>
    simp only [step]
    split
    · exact ⟨⟨hq, ha⟩, by simp⟩
    · exact ⟨by simp [NoUdp, fail], by simp⟩

/-! ## Over DoH or DoQ, no stream and no datagram -/

/-- A state a lookup over DoH or DoQ can be in: never one that connects, sends or waits on a
stream. -/
def NoStream (s : State) : Prop :=
  s.stage ≠ .tcpNeeded ∧ s.stage ≠ .connectingTcp ∧ s.stage ≠ .tcpReady ∧ s.stage ≠ .awaitingTcp

/-- What a lookup over DoH or DoQ never asks for: a datagram, a connection or a stream's send. -/
def NotPlain (o : Out) : Prop := o ≠ .sendUdp ∧ o ≠ .connectTcp ∧ o ≠ .sendTcp

theorem noStream_of_stage (c : Config) (s : State) (h : c.useTcp = false)
    (hs : s.stage = fresh c ∨ s.stage = .failed) : NoStream s := by
  rcases hs with hs | hs <;> simp [NoStream, hs, fresh, h]

theorem init_noStream (c : Config) (h : c.useTcp = false) : NoStream (init c) := by
  unfold init NoStream fail
  split <;> simp [fresh, h]

theorem poll_request (c : Config) (s : State) (hh : c.request = true) (inv : NoStream s) :
    NoStream (poll c s).1 ∧ NotPlain (poll c s).2 := by
  obtain ⟨h1, h2, h3, h4⟩ := inv
  unfold poll NoStream NotPlain
  cases hs : s.stage <;> simp_all

theorem onReply_noStream (c : Config) (s : State) (r : Reply) (hh : c.request = true)
    (h : c.useTcp = false) (inv : NoStream s) :
    NoStream (onReply c s true r).1 ∧ NotPlain (onReply c s true r).2 := by
  have hadv : ∀ t, NoStream (advanceServer c t) :=
    fun t => noStream_of_stage c _ h (advanceServer_stage c t)
  have hnxt : ∀ t b, NoStream (nextCandidate c t b) :=
    fun t b => noStream_of_stage c _ h (nextCandidate_stage c t b)
  cases r with
  | unmatched => exact ⟨inv, by simp [onReply, NotPlain]⟩
  | truncated => exact ⟨hnxt s true, by simp [onReply, NotPlain]⟩
  | answer => exact ⟨by simp [onReply, NoStream], by simp [onReply, NotPlain]⟩
  | cname =>
    simp only [onReply]
    split
    · exact ⟨by simp [NoStream, fail], by simp [NotPlain]⟩
    · exact ⟨by simp [NoStream, fresh, h], by simp [NotPlain]⟩
  | nxdomain => exact ⟨hnxt s false, by simp [onReply, NotPlain]⟩
  | nodata => exact ⟨hnxt s true, by simp [onReply, NotPlain]⟩
  | yxdomain => exact ⟨by simp [onReply, NoStream, fail], by simp [onReply, NotPlain]⟩
  | servfail => exact ⟨hadv _, by simp [onReply, NotPlain]⟩
  | formerr =>
    simp only [onReply]
    split
    · exact ⟨retry_of c s _ _ _ NoStream (by simp [NoStream, fresh, h]) (fun u _ => hadv u),
        by simp [NotPlain]⟩
    · exact ⟨hadv _, by simp [NotPlain]⟩
  -- No cookie went out, so there is none to retry with: the server has failed.
  | badcookie =>
    have e : onReply c s true .badcookie = (advanceServer c (keep s .badcookie), .accepted) := by
      simp [onReply, hh]
    rw [e]
    exact ⟨hadv _, by simp [NotPlain]⟩

/-- Over DoH or DoQ (docs/design.md §22, §23), a lookup never asks for a datagram, a connection
or a stream's send, whatever the caller tells it: every query it makes is a request of its own. -/
theorem request_never_stream (c : Config) (s : State) (e : Event) (hh : c.request = true)
    (ht : c.useTcp = false) (inv : NoStream s) :
    NoStream (step c s e).1 ∧ NotPlain (step c s e).2 := by
  have hadv : ∀ t, NoStream (advanceServer c t) :=
    fun t => noStream_of_stage c _ ht (advanceServer_stage c t)
  have none : NotPlain Out.none := by simp [NotPlain]
  have ignored : NotPlain Out.ignored := by simp [NotPlain]
  obtain ⟨h1, h2, h3, h4⟩ := inv
  have keep : NoStream s := ⟨h1, h2, h3, h4⟩
  cases e with
  | poll => exact poll_request c s hh keep
  | expire =>
    simp only [step]
    split
    · exact poll_request c _ hh (hadv s)
    · exact poll_request c s hh keep
  | sent => cases hs : s.stage <;> simp_all [step, NoStream, NotPlain]
  | sendFailed =>
    cases hs : s.stage <;> simp only [step, hs] <;>
      first | exact ⟨hadv s, none⟩ | exact ⟨keep, none⟩ | simp_all
  | tcpConnected => cases hs : s.stage <;> simp_all [step, NoStream, NotPlain]
  | tcpFailed _ =>
    simp only [step]
    split
    · exact ⟨hadv _, none⟩
    · exact ⟨keep, none⟩
  | requestFailed _ =>
    simp only [step]
    split
    · exact ⟨hadv _, none⟩
    · exact ⟨keep, none⟩
  | reply r | replyAd r =>
    cases hs : s.stage <;> simp only [step, heard, hs]
    all_goals first
      | (rw [hh]; exact (fun ⟨h1, h2⟩ => ⟨clear_keeps NoStream c _ _ _ (fun _ h => h) h1, h2⟩)
          (onReply_noStream c s r hh ht keep))
      | exact ⟨keep, ignored⟩
      | simp_all
  | cancel =>
    simp only [step]
    split
    · exact ⟨keep, none⟩
    · exact ⟨by simp [NoStream, fail], none⟩

/-! ## A deadline ends `tcpReady` -/

/-- A lookup ready to send on a stream waits for its deadline too (docs/design.md §5; §16 decision
52). The caller may deliver the deadline in `tcpReady`, and after it the lookup is not in
`tcpReady`, whatever the configuration. So a send that never ends holds no lookup past it. -/
theorem tcpReady_expires (c : Config) (s : State) (h : s.stage = .tcpReady) :
    Event.expire ∈ enabled c s ∧ (step c s .expire).1.stage ≠ .tcpReady := by
  refine ⟨by simp [enabled, h, waiting], ?_⟩
  simp only [step, h, waiting, if_true]
  rcases advanceServer_stage c s with hs | hs
  · unfold fresh at hs
    split at hs <;> simp [poll, hs]
  · simp [poll, hs]

end Spec.Lookup
