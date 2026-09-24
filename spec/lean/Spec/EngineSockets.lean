import Spec.Engine

/-!
# The engine's sockets and sends

The datagram's rules of docs/design.md §19 step 13 for the model of `Spec.Engine`: a socket per
server with its receive, the port replaced as soon as it has carried its share while the old one
drains, and a replacement or a receive the moment refused asked for again at the next drive. And the sends of both transports,
which lend the slot's buffer (the stream's rules 6 and 7).
-/
namespace Spec.Engine

/-! ## Receives -/

/-- Whether server `v`'s socket, the current one or the draining one, has its receive armed. -/
def listening (s : State) (v : Nat) (draining : Bool) : Bool :=
  s.ops.any fun op =>
    op.kind = .receiveFrom ∧ op.target = v ∧ op.draining = draining ∧ op.current

/-- Whether connection `k` has its receive armed. -/
def receiving (s : State) (k : Nat) : Bool :=
  s.ops.any fun op => op.kind = .receive ∧ op.target = k ∧ op.current

/-- Arms a receive on server `v`'s current or draining socket, unless the loop refuses it; then
the next drive asks again (the datagram's rules 1 and 5). -/
def listen (s : State) (v : Nat) (draining : Bool) : State :=
  if s.jammed then s else
  { s with ops := s.ops ++ [{ kind := .receiveFrom, target := v, current := true, draining }] }

/-- Arms connection `k`'s receive, unless the loop refuses it; then the next drive asks again. -/
def armReceive (s : State) (k : Nat) : State :=
  if s.jammed then s else
  { s with ops := s.ops ++ [{ kind := .receive, target := k, current := true }] }

/-! ## Sockets -/

/-- Moves every slot's record of server `v`'s socket `older` to `newer`. -/
def age (s : State) (v : Nat) (older newer : Age) : State :=
  { s with slots := s.slots.map fun slot =>
      if slot.sentFrom = some (v, older) then { slot with sentFrom := some (v, newer) } else slot }

/-- Whether server `v`'s draining socket is still owed something: an answer to a lookup that
sent from it and waits on its server, or the end of a send from it that holds a slot's buffer. -/
def drainNeeded (s : State) (v : Nat) : Bool :=
  (List.range s.slots.length).any fun l =>
    let slot := slotAt s l
    slot.sentFrom == some (v, .draining) &&
      (slot.busy || match slot.lookup with
        | some lk => lk.stage == .awaitingUdp && serverOf s l == v
        | none => false)

/-- Closes server `v`'s draining socket: its receive cancelled, the socket gone. -/
def closeDrain (s : State) (v : Nat) : State :=
  let s := { s with ops := s.ops.map fun op =>
    if op.kind = .receiveFrom ∧ op.target = v ∧ op.draining then { op with current := false }
    else op }
  setSock (age s v .draining .gone) v fun sock => { sock with draining := false }

/-- Replaces server `v`'s port: a new socket opened, unless opens fail now, and the old one left
to drain with its receive (the datagram's rule 4). -/
def rotate (s : State) (v : Nat) : State :=
  if s.starved then s else
  let s := { s with ops := s.ops.map fun op =>
    if op.kind = .receiveFrom ∧ op.target = v ∧ ¬op.draining ∧ op.current then
      { op with draining := true }
    else op }
  let s := setSock (age s v .current .draining) v fun _ => { draining := true }
  listen s v false

/-- Closes server `v`'s draining socket when nothing is owed on it any more. -/
def closeIfDrained (s : State) (v : Nat) : State :=
  if (sockAt s v).draining ∧ ¬drainNeeded s v then closeDrain s v else s

/-- What a drive does last, server by server: a draining socket nothing is owed closed, which
makes room for a retiring port to be replaced; the replaced one closed at once if nothing is
owed on it either; and a receive armed on each socket that has none. -/
def tendSockets (c : Config) (s : State) : State :=
  (List.range s.socks.length).foldl (fun s v =>
    let s := closeIfDrained s v
    let s := if (sockAt s v).retiring ∧ ¬(sockAt s v).draining then rotate s v else s
    let s := closeIfDrained s v
    let s := if listening s v false then s else listen s v false
    if (sockAt s v).draining ∧ ¬listening s v true then listen s v true else s) s

/-- Whether a connection reads what its server sends: while it handshakes and once it is up. -/
def reads (stage : Stage) : Bool := stage = .handshaking ∨ stage = .up

/-- Every connection that reads gets its receive, if the loop refused it before. -/
def tendConns (s : State) : State :=
  (List.range s.conns.length).foldl (fun s k =>
    if reads (connAt s k).stage ∧ ¬receiving s k then armReceive s k else s) s

/-! ## Sends -/

/-- Sends the head of connection `k`'s queue unless a send is in flight. A query is sealed as it
goes (§21, TLS rule 2). A send the loop refuses fails the connection: the stream cannot go on
without it (the stream's rule 9). -/
def pump (c : Config) (s : State) (k : Nat) : State :=
  if inFlight s k then s else
  match (connAt s k).queue.head? with
  | none => s
  | some entry =>
    if s.jammed then failConn c s k else
    match entry with
    | .query l =>
      let s := setConn s k fun conn => { conn with sealed := 1 }
      { s with ops := s.ops ++ [{ kind := .send, target := l, current := true }] }
    | .records => { s with ops := s.ops ++ [{ kind := .sendRecords, target := k, current := true }] }

/-- The session made records: sealed now, they go after what is sealed already and ahead of every
query that is not. Behind an entry of the session's own records that has not started, they join
it (§21, TLS rule 2). -/
def makeRecords (c : Config) (s : State) (k : Nat) : State :=
  let conn := connAt s k
  if conn.sealed ≥ 2 ∧ conn.queue[conn.sealed - 1]? = some .records then
    setConn s k fun conn => { conn with owes := false }
  else
  let s := setConn s k fun conn =>
    { conn with queue := conn.queue.take conn.sealed ++ [.records] ++ conn.queue.drop conn.sealed,
                sealed := conn.sealed + 1, owes := false }
  pump c s k

/-- The query joins its connection's queue, lending its buffer from now, and goes at once when
nothing is ahead of it (the stream's rule 9). -/
def submitStream (c : Config) (s : State) (l k : Nat) : State :=
  let s := setSlot s l (fun slot => { slot with busy := true })
  let s := setConn s k (fun conn => { conn with queue := conn.queue ++ [.query l] })
  pump c s k

/-- Closes every connection nobody has used since before this instant (rule 4). A TLS connection
that is up makes its `close_notify` and closes once that has gone; one still handshaking has no
session to close (§21, TLS rule 5). -/
def closeIdle (c : Config) (s : State) : State :=
  (List.range s.conns.length).foldl (fun s k =>
    let conn := connAt s k
    if conn.stage = .closed ∨ conn.stage = .closing ∨ conn.users ≠ 0 ∨ conn.idleNow then s else
    if c.tls ∧ conn.stage = .up then
      makeRecords c (setConn s k fun conn => { conn with stage := .closing }) k
    else shut s k) s

/-- The query goes out from the current socket of the lookup's server, which counts it. -/
def submitDatagram (c : Config) (s : State) (l : Nat) : State :=
  let v := serverOf s l
  if s.jammed then tableEvent c s l .sendFailed else
  let s := setSlot s l (fun slot => { slot with busy := true, sentFrom := some (v, .current) })
  let s := { s with ops := s.ops ++ [{ kind := .sendTo, target := l, current := true }] }
  setSock s v fun sock =>
    let sent := sock.sent + 1
    { sock with sent, retiring := sock.retiring ∨ (c.perPort > 0 ∧ sent ≥ c.perPort) }

/-- The lookup's query goes out, or waits for the buffer (rule 6). Which transport is the
lookup's own: a query ready over UDP, or ready on a stream. -/
def send (c : Config) (s : State) (l : Nat) : State :=
  let slot := slotAt s l
  if slot.busy then setSlot s l (fun slot => { slot with held := true, heldCurrent := true }) else
  match slot.lookup with
  | some lk =>
    if lk.stage = .queryReady then submitDatagram c s l else
    match slot.conn with
    | some k => if (connAt s k).stage = .up then submitStream c s l k else tableEvent c s l .tcpFailed
    | none => tableEvent c s l .tcpFailed
  | none => s

end Spec.Engine
