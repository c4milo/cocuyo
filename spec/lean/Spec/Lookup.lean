import Spec.LookupState

/-!
# The lookup state machine

`Lookup` of docs/design.md §5, written from the design and never from the Zig source
(spec/CONTRACT.md). A response is abstracted to what §7's checks and §5's rcode policy make of
it; time is abstracted to whether a poll comes before its deadline or at it; the server order of
§19 step 12 is abstracted to a position in it. What the abstraction keeps is every transition of
§5's table, the retry policy, the search-list policy and the CNAME policy.
-/
namespace Spec.Lookup

/-- Whether a response over the configuration's transport may be read for its AD bit. "A resolver
MUST disregard the meaning of the CD and AD bits in a response unless the response was obtained by
using a secure channel or the resolver was specifically configured to regard the message header
bits without using a secure channel" (RFC 4035 §4.6; docs/design.md §25, Stage A rule 1). -/
def relied (c : Config) : Bool :=
  -- A validating stub SHOULD NOT examine AD (RFC 4035 §4.9.3; docs/design.md §25, Stage B rule 3).
  if c.validate then false else
  match c.authenticatedData with
  | .ignored => false
  | .encrypted => c.encrypted || c.request
  | .always => true

/-- Whether the lookup acts on a reply's message: it takes its records, follows its CNAME, or
moves on its denial, which over a stream a truncated message is (docs/design.md §25, Stage A
rule 3). -/
def actsOn (stream : Bool) : Reply → Bool
  | .answer | .cname | .nxdomain | .nodata => true
  | .truncated => stream
  | _ => false

/-- A message the lookup acted on, with AD set or not: a message without it clears rule 3's
conjunction, when the configuration relies on the bit. -/
def clear (c : Config) (acts ad : Bool) (t : State) : State :=
  if acts && relied c && !ad then { t with authentic := false } else t

/-- What is known of where an answer came from (docs/design.md §25). -/
inductive Security where
  | unchecked | insecure | authenticated | secure
  deriving DecidableEq, Repr, Inhabited

/-- The security of a lookup's end: `authenticated` when the configuration relies on the bit and
every message it acted on had AD set, and `unchecked` otherwise (docs/design.md §25, Stage A rule
3). It means something for an answer, and for the two negatives. -/
def security (c : Config) (s : State) : Security :=
  if c.validate then (if s.secure then .secure else .insecure)
  else if relied c && s.authentic then .authenticated else .unchecked

/-- What an end reports, as `Answer.security` and `Failure.security` do: the security of an answer,
and of the two negatives, `unchecked` for every other failure, and nothing while the lookup runs
(docs/design.md §25). -/
def reported (c : Config) (s : State) : Option Security :=
  match s.stage with
  | .done => some (security c s)
  | .failed => some (if s.err = .nameNotFound ∨ s.err = .noData then security c s else .unchecked)
  | _ => none

/-- A poll: the action the lookup wants now. A query over DoH or DoQ is ready as a datagram is,
one request a transaction, and goes as an HTTP request or a QUIC stream (docs/design.md §22,
§23). -/
def poll (c : Config) (s : State) : State × Out :=
  match s.stage with
  | .queryReady => ({ s with offered := true }, if c.request then .sendRequest else .sendUdp)
  | .tcpNeeded => ({ s with stage := .connectingTcp }, .connectTcp)
  | .tcpReady => ({ s with offered := true }, .sendTcp)
  | .awaitingUdp | .connectingTcp | .awaitingTcp | .awaitingKeys => (s, .wait)
  | .done => (s, .done)
  | .failed => (s, .failed s.err)

/-- Whether a deadline bounds the stage, so that a poll at or past it moves the lookup on. Since
2026-10-24 `tcpReady` waits for the deadline that `tcpConnected` arms, and the query's send does
not stop it (docs/design.md §5; §16 decision 52). -/
def waiting (s : Stage) : Bool :=
  match s with
  | .awaitingUdp | .connectingTcp | .tcpReady | .awaitingTcp => true
  | _ => false

/-- Whether the caller may deliver each kind of reply, and not the unmatched reply alone. `step`
reads a reply only in `awaitingUdp` and `awaitingTcp`, and ignores it in each other stage.
`listens` holds the three stages that `waiting` held until 2026-10-24. So the replies enabled in
each stage stay as they were, and the transcript only grows. `connectingTcp` keeps every kind for
that reason alone, since `step` ignores a reply there. In `tcpReady` no query went out whole, so
only the unmatched reply comes. -/
def listens (s : Stage) : Bool :=
  match s with
  | .awaitingUdp | .connectingTcp | .awaitingTcp => true
  | _ => false

def ended (s : Stage) : Bool :=
  match s with
  | .done | .failed => true
  | _ => false

/-- Whether the lookup is on a stream: connecting, ready to send on one, or awaiting its answer. -/
def onStream (s : Stage) : Bool :=
  match s with
  | .connectingTcp | .tcpReady | .awaitingTcp => true
  | _ => false

/-- The reasons a caller may give a failed connection (§16 decision 51): what failed before the
lookup was told the connection is up, and `closed` after. The model holds no TLS, so `handshake`
never comes here. -/
def tcpReasons (s : Stage) : List Reason :=
  if s = .connectingTcp then [.connect, .«local»] else [.closed]

/-- The reasons a caller may give a failed request (§16 decision 51): over DoQ no connect and no
HTTP status, and over DoH each reason. -/
def requestReasons (c : Config) : List Reason :=
  if c.quic then [.handshake, .«local», .closed, .reset]
  else [.connect, .handshake, .«local», .closed, .status, .reset]

/-- A message the validator called bogus moves nothing but the server: over UDP the same server is
asked over TCP, as TC=1 asks it, and over a stream, DoH or DoQ the next server is (docs/design.md
§25, step 11). -/
def rejected (c : Config) (s : State) (stream : Bool) : State :=
  if stream then advanceServer c (keep s .bogus)
  else retry c s { s with stage := .tcpNeeded } true (some .bogus)

/-- A message the lookup acts on, and the validator's verdict on it. A secure one moves the lookup
as it would unvalidated, and an insecure one too, clearing the conjunction. A bogus one moves the
server alone. One whose keys are wanted waits for them, `keyAsksMax` times for a name, and past
that reads as bogus (docs/design.md §25, step 11). -/
def checked (c : Config) (s : State) (stream : Bool) (r : Reply) : Verdict → State × Out
  | .secure => onReply c s stream r
  | .insecure => let p := onReply c s stream r; ({ p.1 with secure := false }, p.2)
  | .bogus => (rejected c s stream, .accepted)
  | .keysWanted =>
    if s.asks < keyAsksMax then ({ s with stage := .awaitingKeys, asks := s.asks + 1 }, .accepted)
    else (rejected c s stream, .accepted)

/-- A reply to a lookup that is waiting for one, over UDP or over a stream, its message's AD bit
`ad`, and the validator's verdict `v` when it gave one. Under validation a message the lookup acts
on with no verdict counts as insecure: the lookup took it unvalidated. -/
def reading (c : Config) (s : State) (stream : Bool) (r : Reply) (ad : Bool) (v : Option Verdict) :
    State × Out :=
  if c.validate && actsOn stream r then checked c s stream r (v.getD .insecure)
  else let p := onReply c s stream r; (clear c (actsOn stream r) ad p.1, p.2)

/-- A reply, its message's AD bit `ad` and its verdict `v`, to a lookup in stage `s.stage`: read
where the lookup waits for one, and ignored elsewhere. -/
def heard (c : Config) (s : State) (r : Reply) (ad : Bool) (v : Option Verdict) : State × Out :=
  -- A reply to the current try closes it, whatever it says: the try was answered.
  let answered (stream : Bool) := if r = .unmatched then s else closeTry s stream s.server
  match s.stage with
  -- Over DoH or DoQ an answer is read as one over a stream: there is nowhere else to ask.
  | .awaitingUdp => reading c (answered false) c.request r ad v
  | .awaitingTcp => reading c (answered true) true r ad v
  | _ => (s, .ignored)

/-- The tries open at position `p` over a stream or not, the current try left out. -/
def earlierOpen (s : State) (stream : Bool) (p : Nat) : Nat :=
  let current := p = s.server ∧
    ((s.stage = .awaitingUdp ∧ stream = false) ∨ (s.stage = .awaitingTcp ∧ stream = true))
  openAt s stream p - (if current then 1 else 0)

/-- What a reply to an earlier try that the lookup does not act on does: it closes that try, and its
server's failure is the cause. YXDOMAIN ends the lookup, as each server gives it (§16 decision 57).
TC=1 over UDP closes the try alone, since its server answered. -/
def passed (t : State) (p : Nat) : Reply → State
  | .servfail => keepAt t p .servfail
  | .formerr => keepAt t p .formerr
  | .badcookie => keepAt t p .badcookie
  | .yxdomain => fail t .nameTooLong
  | _ => t

/-- A message of an earlier try that the lookup acts on, and the validator's verdict. A secure or an
insecure one moves the lookup as the current try's would. A bogus one closes the try alone, its
server the cause, and the lookup waits on its current try (docs/design.md §5, Tries kept open). -/
def earlierChecked (c : Config) (t : State) (p : Nat) (stream : Bool) (r : Reply) :
    Verdict → State × Out
  | .secure => onReply c t stream r
  | .insecure => let q := onReply c t stream r; ({ q.1 with secure := false }, q.2)
  | .bogus => (keepAt t p .bogus, .accepted)
  | .keysWanted =>
    if t.asks < keyAsksMax then ({ t with stage := .awaitingKeys, asks := t.asks + 1 }, .accepted)
    else (keepAt t p .bogus, .accepted)

/-- A reply to an open earlier try at position `p`, over a stream or not (docs/design.md §5, Tries
kept open). It closes that try. One the lookup acts on moves it as the current try's would. A send
a poll handed out is the lookup's no more once the stage moves, as the engine reads it (§19 step 13,
stream rule 7). -/
def earlierHeard (c : Config) (s : State) (p : Nat) (stream : Bool) (r : Reply) (ad : Bool)
    (v : Option Verdict) : State × Out :=
  let t := closeTry s stream p
  let reads := stream || c.request
  let moved (q : State × Out) : State × Out :=
    (if q.1.stage = s.stage then q.1 else { q.1 with offered := false }, q.2)
  if actsOn reads r then
    if c.validate then moved (earlierChecked c t p reads r (v.getD .insecure))
    else let q := onReply c t reads r; moved (clear c true ad q.1, q.2)
  else (passed t p r, .accepted)

/-- The connection of an earlier try at position `p` failed, which closes every stream try on it, or
an earlier request failed, which closes that try. The server's failure is the cause. -/
def earlierFailed (s : State) (p : Nat) (stream : Bool) (r : Reason) : State :=
  let t := if stream then { s with openStreams := s.openStreams.set p 0 } else closeTry s false p
  keepAt t p (.reason r)

/-- The keys came: the same server is asked again over the transport the lookup starts on, as a
retry asks it (docs/design.md §25, step 11). The wait was counted when it began. -/
def keysCame (c : Config) (s : State) : State :=
  retry c s { s with stage := fresh c } c.useTcp none

/-- The walk failed, and the lookup ends with its failure. A walk's question that went unanswered
ends the lookup `timeout` only while no server failed it, so `timeout` keeps its promise that
every try went unanswered (§16 decision 25). -/
def walkFailed (s : State) : Walked → State
  | .bogus => fail (keep s .bogus) .bogus
  | .failed => fail (keep s .keys) .allServersFailed
  | .timeout => fail s (if s.cause.isSome then .allServersFailed else .timeout)

/-- One event, and what the lookup answers. -/
def step (c : Config) (s : State) : Event → State × Out
  | .poll => poll c s
  | .expire => if waiting s.stage then poll c (advanceServer c s) else poll c s
  | .sent =>
    match s.stage with
    | .queryReady =>
      ({ s with stage := .awaitingUdp, offered := false, datagrams := bump s.datagrams s.server,
                 openDatagrams := bump s.openDatagrams s.server }, .none)
    | .tcpReady =>
      ({ s with stage := .awaitingTcp, offered := false, streams := bump s.streams s.server,
                 openStreams := bump s.openStreams s.server }, .none)
    | _ => (s, .none)
  | .sendFailed =>
    match s.stage with
    | .queryReady | .tcpReady => (advanceServer c s, .none)
    | _ => (s, .none)
  | .tcpConnected =>
    match s.stage with
    | .connectingTcp => ({ s with stage := .tcpReady }, .none)
    | _ => (s, .none)
  -- A connection or a handshake that failed is the server refusing the lookup, which counts as
  -- SERVFAIL does (§16 decision 25). The cause is the reason the caller gave (§16 decision 51).
  -- It closes every stream try on that connection.
  | .tcpFailed r =>
    if onStream s.stage then
      (advanceServer c (keep { s with openStreams := s.openStreams.set s.server 0 } (.reason r)),
        .none)
    else (s, .none)
  -- An HTTP or a QUIC failure is the server's: the next one (docs/design.md §22, §23), counted as
  -- the stream's is.
  | .requestFailed r =>
    if c.request ∧ s.stage = .awaitingUdp then
      (advanceServer c (keep (closeTry s false s.server) (.reason r)), .none)
    else (s, .none)
  | .reply r => heard c s r false none
  | .replyAd r => heard c s r true none
  | .replyChecked r v => heard c s r false (some v)
  | .earlier p stream r ad v =>
    if ended s.stage ∨ earlierOpen s stream p = 0 then (s, .ignored)
    else earlierHeard c s p stream r ad v
  | .earlierFailed p stream r =>
    if ended s.stage ∨ earlierOpen s stream p = 0 then (s, .none)
    else (earlierFailed s p stream r, .none)
  | .keysReady => if s.stage = .awaitingKeys then (keysCame c s, .none) else (s, .none)
  | .keysFailed w => if s.stage = .awaitingKeys then (walkFailed s w, .none) else (s, .none)
  | .cancel => if ended s.stage then (s, .none) else (fail s .canceled, .none)

/-- The replies and the failures that may come for the lookup's open earlier tries: at each
position and over each transport where one is open, every reply the lookup reads but the unmatched
one, with each verdict under validation and with AD where the bit counts, and the failure of the
connection or the request (docs/design.md §5, Tries kept open). A connection the lookup is on
fails with `tcpFailed`, so its tries are not offered here. -/
def earlierEvents (c : Config) (s : State) : List Event :=
  let kinds := [Reply.answer, .cname, .nxdomain, .nodata, .yxdomain, .servfail, .formerr,
                .truncated, .badcookie]
  (List.range c.servers).flatMap fun p => [false, true].flatMap fun stream =>
    if earlierOpen s stream p = 0 then [] else
    let reads := stream || c.request
    let replies := if c.validate then
        kinds.flatMap fun r => if actsOn reads r then
          [Verdict.secure, .insecure, .bogus, .keysWanted].map fun v => Event.earlier p stream r false (some v)
        else [Event.earlier p stream r false none]
      else kinds.map fun r => Event.earlier p stream r false none
    let authentic := if c.authenticatedData = .ignored || c.validate then []
      else (kinds.filter (actsOn reads)).map fun r => Event.earlier p stream r true none
    let failures :=
      if stream then (if onStream s.stage ∧ p = s.server then [] else [Event.earlierFailed p true .closed])
      else if c.request then (requestReasons c).map (Event.earlierFailed p false) else []
    replies ++ authentic ++ failures

/-- The events a caller may deliver to a `Lookup`, by the contract of §4: a poll at any time, a
poll past the deadline while a deadline bounds the lookup, `on_sent` and `on_send_failed` only for
a send a poll handed out, `on_tcp_connected` while it connects, `on_tcp_failed` while it is on a
stream, `on_request_failed` while it waits on a request, a datagram at any time, and a cancel
until it ends. `Resolver.cancel` takes a cancel after the end as well, which `step` answers with
nothing. -/
def enabled (c : Config) (s : State) : List Event :=
  let replies := [Reply.unmatched, .answer, .cname, .nxdomain, .nodata, .yxdomain, .servfail,
                  .formerr, .truncated, .badcookie].map Event.reply
  -- A message the lookup acts on may have AD set. Under `ignored` the bit changes nothing, and the
  -- walk leaves it out.
  let authentic := if c.authenticatedData = .ignored || c.validate then []
    else [Reply.answer, .cname, .nxdomain, .nodata, .truncated].map Event.replyAd
  -- Under validation a message the lookup acts on comes with each verdict, and never without one.
  let stream := s.stage = .awaitingTcp || c.request
  let all := [Reply.unmatched, .answer, .cname, .nxdomain, .nodata, .yxdomain, .servfail,
              .formerr, .truncated, .badcookie]
  let plain := if c.validate then (all.filter (fun r => !actsOn stream r)).map Event.reply
    else replies
  let verdicts := if c.validate then
      ((all.filter (actsOn stream)).flatMap fun r =>
        [Verdict.secure, .insecure, .bogus, .keysWanted].map (Event.replyChecked r))
    else []
  [Event.poll]
    ++ (if waiting s.stage then [Event.expire] else [])
    ++ (if s.offered then [Event.sent, .sendFailed] else [])
    ++ (if s.stage = .connectingTcp then [Event.tcpConnected] else [])
    ++ (if onStream s.stage then (tcpReasons s.stage).map Event.tcpFailed else [])
    ++ (if c.request ∧ s.stage = .awaitingUdp then (requestReasons c).map Event.requestFailed
        else [])
    ++ (if listens s.stage then plain ++ verdicts ++ authentic else [Event.reply .unmatched])
    ++ (if s.stage = .awaitingKeys then
          [Event.keysReady, .keysFailed .bogus, .keysFailed .timeout, .keysFailed .failed]
        else [])
    ++ (if ended s.stage then [] else earlierEvents c s)
    ++ (if ended s.stage then [] else [Event.cancel])

end Spec.Lookup
