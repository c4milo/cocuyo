import Spec.Engine

/-!
# The engine's sockets and sends

The datagram's rules of docs/design.md §19 step 13 for the model of `Spec.Engine`: a socket per
server with its receive, the port replaced once it has carried its share, and a socket or a
receive the moment refused asked for again at the next drive. And the sends of both transports,
which lend the slot's buffer (the stream's rules 6 and 7).
-/
namespace Spec.Engine

/-! ## Receives -/

/-- Whether server `v`'s socket has its receive armed. -/
def listening (s : State) (v : Nat) : Bool :=
  s.ops.any fun op => op.kind = .receiveFrom ∧ op.target = v ∧ op.current

/-- Whether connection `k` has its receive armed. -/
def receiving (s : State) (k : Nat) : Bool :=
  s.ops.any fun op => op.kind = .receive ∧ op.target = k ∧ op.current

/-- Arms server `v`'s receive, unless the loop refuses it; then the next drive asks again
(the datagram's rule 1). -/
def listen (s : State) (v : Nat) : State :=
  if s.jammed then s else
  { s with ops := s.ops ++ [{ kind := .receiveFrom, target := v, current := true }] }

/-- Arms connection `k`'s receive, unless the loop refuses it; then the next drive asks again. -/
def armReceive (s : State) (k : Nat) : State :=
  if s.jammed then s else
  { s with ops := s.ops ++ [{ kind := .receive, target := k, current := true }] }

/-! ## Sockets -/

/-- Opens server `v`'s socket on a new port and arms its receive, unless opens fail now. -/
def openSock (s : State) (v : Nat) : State :=
  if s.starved then s else listen (setSock s v fun _ => {}) v

/-- Replaces server `v`'s port: its receive cancelled, its socket closed, another opened
(the datagram's rule 4). -/
def rotate (s : State) (v : Nat) : State :=
  let s := { s with ops := s.ops.map fun op =>
    if op.kind = .receiveFrom ∧ op.target = v then { op with current := false } else op }
  openSock (setSock s v fun _ => { isOpen := false }) v

/-- Whether a lookup waits on server `v`, or has a send in flight from its slot while it asks
`v`: a port is never taken from under either. -/
def waitedOn (s : State) (v : Nat) : Bool :=
  (List.range s.slots.length).any fun l =>
    let slot := slotAt s l
    match slot.lookup with
    | some lk => serverOf s l = v ∧ (slot.busy ∨ waiting lk.stage)
    | none => false

/-- What a drive does last, server by server: a retiring port nobody waits on replaced, a
server with no socket given one, an open socket with no receive given one. -/
def tendSockets (c : Config) (s : State) : State :=
  (List.range c.servers).foldl (fun s v =>
    let sock := sockAt s v
    let s := if sock.isOpen ∧ sock.retiring ∧ ¬waitedOn s v then rotate s v else s
    if ¬(sockAt s v).isOpen then openSock s v
    else if ¬listening s v then listen s v
    else s) s

/-- Every connection that is up gets its receive, if the loop refused it before. -/
def tendConns (s : State) : State :=
  (List.range s.conns.length).foldl (fun s k =>
    if (connAt s k).stage = .up ∧ ¬receiving s k then armReceive s k else s) s

/-! ## Sends -/

/-- The query goes out on the lookup's connection. -/
def submitStream (c : Config) (s : State) (l : Nat) : State :=
  if s.jammed then tableEvent c s l .sendFailed else
  let s := setSlot s l (fun slot => { slot with busy := true })
  { s with ops := s.ops ++ [{ kind := .send, target := l, current := true }] }

/-- The query goes out from the socket of the lookup's server, which counts it; a server with no
socket fails the send as any failed send (the datagram's rule 4). -/
def submitDatagram (c : Config) (s : State) (l : Nat) : State :=
  let v := serverOf s l
  if ¬(sockAt s v).isOpen ∨ s.jammed then tableEvent c s l .sendFailed else
  let s := setSlot s l (fun slot => { slot with busy := true })
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
    | some k => if (connAt s k).stage = .up then submitStream c s l else tableEvent c s l .tcpFailed
    | none => tableEvent c s l .tcpFailed
  | none => s

end Spec.Engine
