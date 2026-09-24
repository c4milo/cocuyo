import Spec.Lookup

/-!
# What the lookup state machine guarantees

Each theorem is a property docs/design.md promises of `Lookup`, proved of the model in
`Spec.Lookup`. The sequence check (`spec/Main.lean`, `zig build spec`) is what ties the model to
the Zig code; these tie the model to the promises.
-/
namespace Spec.Lookup

/-! ## An ended lookup stays ended -/

/-- A lookup that is done or has failed is changed by nothing: every poll returns the same end,
every reply is ignored, and a cancel leaves the end standing (§5's last row; the cancel rule of
`Resolver.cancel`). -/
theorem ended_absorbing (c : Config) (s : State) (e : Event) (h : ended s.stage = true) :
    (step c s e).1 = s := by
  cases e <;> cases hs : s.stage <;> simp_all [step, poll, ended, waiting, onStream]

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
  unfold advanceServer fail
  split
  · simp
  · split <;> simp

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
    · exact ⟨by simp [onReply, NoUdp], by simp [onReply]⟩
    · exact ⟨hnxt s true, by simp [onReply]⟩
  | answer => exact ⟨by simp [onReply, NoUdp], by simp [onReply]⟩
  | cname =>
    simp only [onReply]
    split
    · exact ⟨by simp [NoUdp, fail], by simp⟩
    · exact ⟨by simp [NoUdp, fresh, h], by simp⟩
  | nxdomain => exact ⟨hnxt s false, by simp [onReply]⟩
  | nodata => exact ⟨hnxt s true, by simp [onReply]⟩
  | servfail => exact ⟨hadv _, by simp [onReply]⟩
  | formerr =>
    simp only [onReply]
    split
    · exact ⟨by simp [NoUdp, fresh, h], by simp⟩
    · exact ⟨hadv _, by simp⟩
  | badcookie =>
    simp only [onReply]
    split
    · exact ⟨hadv _, by simp⟩
    · split
      · exact ⟨by simp [NoUdp], by simp⟩
      · exact ⟨by simp [NoUdp, fresh, h], by simp⟩

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
  | tcpFailed =>
    simp only [step]
    split
    · exact ⟨hadv s, by simp⟩
    · exact ⟨⟨hq, ha⟩, by simp⟩
  | requestFailed =>
    simp only [step]
    split
    · exact ⟨hadv s, by simp⟩
    · exact ⟨⟨hq, ha⟩, by simp⟩
  | reply r =>
    cases hs : s.stage <;> simp only [step, hs]
    all_goals first
      | exact onReply_noUdp c s _ r h ⟨hq, ha⟩
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

theorem onReply_noStream (c : Config) (s : State) (r : Reply) (h : c.useTcp = false)
    (inv : NoStream s) : NoStream (onReply c s true r).1 ∧ NotPlain (onReply c s true r).2 := by
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
  | servfail => exact ⟨hadv _, by simp [onReply, NotPlain]⟩
  | formerr =>
    simp only [onReply]
    split
    · exact ⟨by simp [NoStream, fresh, h], by simp [NotPlain]⟩
    · exact ⟨hadv _, by simp [NotPlain]⟩
  | badcookie => exact ⟨hadv _, by simp [onReply, NotPlain]⟩

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
  | tcpFailed =>
    simp only [step]
    split
    · exact ⟨hadv s, none⟩
    · exact ⟨keep, none⟩
  | requestFailed =>
    simp only [step]
    split
    · exact ⟨hadv s, none⟩
    · exact ⟨keep, none⟩
  | reply r =>
    cases hs : s.stage <;> simp only [step, hs]
    all_goals first
      | (rw [hh]; exact onReply_noStream c s r ht keep)
      | exact ⟨keep, ignored⟩
      | simp_all
  | cancel =>
    simp only [step]
    split
    · exact ⟨keep, none⟩
    · exact ⟨by simp [NoStream, fail], none⟩

/-! ## A lookup cannot retry forever

Every send lowers a measure that nothing raises: the search candidates left, then the CNAME hops
left, then the passes over the servers left, then the servers left in this pass, then the sends
left to this server in this transaction. The last counts what one server can still be asked: a
datagram and then, after TC=1, the stream, each once with EDNS0 and once more without it after
FORMERR (§5's table), and once more after a first BADCOOKIE (RFC 7873 §5.3). Compared lexicographically, the measure lives in a well-founded order, so a
lookup makes finitely many sends whatever its servers answer (§5, retry policy). -/

/-- The sends a stage has left before the lookup must hear back: a query still to send over UDP
counts two, one for the datagram and one for the stream TC=1 can send it to. -/
def stagePhase : Stage → Nat
  | .queryReady => 2
  | .awaitingUdp | .tcpNeeded | .connectingTcp | .tcpReady => 1
  | .awaitingTcp | .done | .failed => 0

/-- The sends left to the current server in this transaction. -/
def phase (s : State) : Nat :=
  (if s.edns then 2 else 0) + (if s.cookieRetried then 0 else 1) + stagePhase s.stage

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

theorem advanceServer_lt (c : Config) (s : State) (h : s.round < c.attempts) :
    LexLt (measure c (advanceServer c s)) (measure c s) := by
  unfold advanceServer
  split
  · simp [measure, LexLt]; omega
  · split
    · simp [measure, LexLt]; omega
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
  cases r with
  | unmatched => exact lexLe_refl _
  | truncated =>
    cases stream
    · have hs := hst rfl
      simp [onReply, measure, LexLe, phase, stagePhase, hs]
    · exact nextCandidate_le c s true
  | answer => exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_done_le s)
  | cname =>
    simp only [onReply]
    split
    · exact lexLe_of_phase c s _ rfl rfl rfl rfl (phase_ended_le s .chainTooLong)
    · simp [measure, LexLe]; omega
  | nxdomain => exact nextCandidate_le c s false
  | nodata => exact nextCandidate_le c s true
  | servfail =>
    simp only [onReply]
    have h := advanceServer_lt c { s with serverFailed := true } g
    have e : measure c { s with serverFailed := true } = measure c s := rfl
    rw [e] at h
    exact lexLt_le _ _ h
  | formerr =>
    simp only [onReply]
    split
    · rename_i he
      simp only [measure, LexLe, phase, he, fresh]
      cases s.cookieRetried <;> cases c.useTcp <;> cases s.stage <;> simp [stagePhase]
    · exact lexLt_le _ _ (advanceServer_lt c { s with serverFailed := true } g)
  | badcookie =>
    simp only [onReply]
    split
    · exact lexLt_le _ _ (advanceServer_lt c { s with serverFailed := true } g)
    · rename_i hstream
      have hs := hst (by simpa using hstream)
      split
      · rename_i hr
        simp [measure, LexLe, phase, stagePhase, hs, hr]
      · rename_i hr
        simp only [measure, LexLe, phase, hs, hr, fresh]
        cases s.edns <;> cases c.useTcp <;> simp [stagePhase]

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
    | tcpFailed =>
      simp only [step]
      split
      · exact lexLt_le _ _ (advanceServer_lt c s h2)
      · exact lexLe_refl _
    | requestFailed =>
      simp only [step]
      split
      · exact lexLt_le _ _ (advanceServer_lt c s h2)
      · exact lexLe_refl _
    | reply r =>
      cases hs : s.stage <;> simp only [step, hs]
      · exact lexLe_refl _
      · exact onReply_le c s c.request r h2 h4 (fun _ => hs)
      · exact lexLe_refl _
      · exact lexLe_refl _
      · exact lexLe_refl _
      · exact onReply_le c s true r h2 h4 (fun h => absurd h (by simp))
      · exact lexLe_refl _
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

/-! ### The counters stay inside the configuration -/

theorem advanceServer_good (c : Config) (s : State) (hc : Sane c) (hr : s.round < c.attempts)
    (hh : s.hops ≤ c.hopsMax) (hk : s.candidate < c.candidates) : Good c (advanceServer c s) := by
  obtain ⟨hs1, ha1, _⟩ := hc
  unfold advanceServer Good
  split
  · right; simp; omega
  · split
    · right; simp; omega
    · left; simp [fail, ended]

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
  cases r with
  | unmatched => exact gs
  | truncated =>
    cases stream
    · exact Or.inr ⟨h1, h2, h3, h4⟩
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
  | servfail => exact advanceServer_good c _ hc h2 h4 h3
  | formerr =>
    simp only [onReply]
    split
    · exact Or.inr ⟨h1, h2, h3, h4⟩
    · exact advanceServer_good c _ hc h2 h4 h3
  | badcookie =>
    simp only [onReply]
    split
    · exact advanceServer_good c _ hc h2 h4 h3
    · split
      · exact Or.inr ⟨h1, h2, h3, h4⟩
      · exact Or.inr ⟨h1, h2, h3, h4⟩

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
    | tcpFailed =>
      simp only [step]
      split
      · exact advanceServer_good c s hc h2 h4 h3
      · exact gs
    | requestFailed =>
      simp only [step]
      split
      · exact advanceServer_good c s hc h2 h4 h3
      · exact gs
    | reply r =>
      cases hs : s.stage <;> simp only [step, hs]
      · exact gs
      · exact onReply_good c s c.request r hc h1 h2 h3 h4
      · exact gs
      · exact gs
      · exact gs
      · exact onReply_good c s true r hc h1 h2 h3 h4
      · exact gs
      · exact gs
    | cancel =>
      simp only [step]
      split
      · exact gs
      · left; simp [fail, ended]

end Spec.Lookup
