import Spec.Lookup

/-!
# How a transcript spells things

The tokens the transcripts of `Main.lean` write and `tools/spec_replay/` reads back: one
spelling each for the lookup's events, answers, stages and states. The engine's walks, which TLC
writes (`spec/tla/engine/EngineTrace.tla`), spell a lookup the same way.
-/
namespace Spec.Lookup

def replyToken : Reply → String
  | .unmatched => "unmatched" | .answer => "answer" | .cname => "cname"
  | .nxdomain => "nxdomain" | .nodata => "nodata" | .yxdomain => "yxdomain"
  | .servfail => "servfail"
  | .formerr => "formerr" | .truncated => "truncated" | .badcookie => "badcookie"

def reasonToken : Reason → String
  | .connect => "connect" | .handshake => "handshake" | .«local» => "local"
  | .closed => "closed" | .status => "status" | .reset => "reset"

def verdictToken : Verdict → String
  | .secure => "secure" | .insecure => "insecure" | .bogus => "bogus" | .keysWanted => "keys_wanted"

def walkedToken : Walked → String
  | .bogus => "bogus" | .timeout => "timeout" | .failed => "failed"

/-- A reply as an event spells it: its AD bit or its verdict, then the reply. -/
def heardToken (r : Reply) (ad : Bool) : Option Verdict → String
  | some v => "reply_" ++ verdictToken v ++ "_" ++ replyToken r
  | none => (if ad then "reply_ad_" else "reply_") ++ replyToken r

def eventToken : Event → String
  | .poll => "poll" | .expire => "expire" | .sent => "sent" | .sendFailed => "send_failed"
  | .tcpConnected => "tcp_connected" | .tcpFailed r => "tcp_failed_" ++ reasonToken r
  | .cancel => "cancel" | .requestFailed r => "request_failed_" ++ reasonToken r
  | .reply r => heardToken r false none
  | .replyAd r => heardToken r true none
  | .replyChecked r v => heardToken r false (some v)
  | .keysReady => "keys_ready"
  | .keysFailed w => "keys_failed_" ++ walkedToken w
  -- A reply to an earlier try names its position and its transport, then the reply as `reply_`
  -- spells it: `earlier_1_stream_reply_ad_answer`.
  | .earlier p stream r ad v =>
    s!"earlier_{p}_{if stream then "stream" else "datagram"}_" ++ heardToken r ad v
  | .earlierFailed p stream r =>
    s!"earlier_{p}_{if stream then "stream" else "datagram"}_failed_" ++ reasonToken r

def errToken : Err → String
  | .nameNotFound => "name_not_found" | .noData => "no_data" | .timeout => "timeout"
  | .allServersFailed => "all_servers_failed" | .chainTooLong => "chain_too_long"
  | .canceled => "canceled" | .noServers => "no_servers" | .nameTooLong => "name_too_long"
  | .bogus => "bogus"

def whatToken : What → String
  | .servfail => "servfail" | .formerr => "formerr" | .badcookie => "badcookie"
  | .reason r => reasonToken r
  | .bogus => "bogus" | .keys => "keys"

/-- A cause as the transcript writes it, what the server gave and then its position in the order,
as `servfail@1`, and `-` for none: the last column of a line. -/
def causeToken : Option Cause → String
  | none => "-"
  | some k => s!"{whatToken k.what}@{k.server}"

def outToken : Out → String
  | .sendUdp => "send_udp" | .connectTcp => "connect_tcp" | .sendTcp => "send_tcp"
  | .sendRequest => "send_request" | .wait => "wait" | .done => "done" | .failed e => "failed_" ++ errToken e
  | .accepted => "accepted" | .ignored => "ignored" | .none => "none"

def stageToken : Stage → String
  | .queryReady => "query_ready" | .awaitingUdp => "awaiting_udp" | .tcpNeeded => "tcp_needed"
  | .connectingTcp => "connecting_tcp" | .tcpReady => "tcp_ready"
  | .awaitingTcp => "awaiting_tcp" | .done => "done" | .failed => "failed"
  | .awaitingKeys => "awaiting_keys"

def modeToken : Mode → String
  | .ignored => "ignored" | .encrypted => "encrypted" | .always => "always"

/-- What an end reports, and `-` while the lookup runs. -/
def reportedToken : Option Security → String
  | none => "-"
  | some .unchecked => "unchecked"
  | some .insecure => "insecure"
  | some .authenticated => "authenticated"
  | some .secure => "secure"

/-- How a configuration's queries go, as the transcript's `config` line names it. -/
def transportToken (c : Config) : String :=
  if c.useTcp then "tcp" else if !c.request then "udp" else if c.quic then "quic" else "https"

def flag (b : Bool) (c : Char) : String := if b then c.toString else "-"

/-- A state as the transcript writes it, and as the replay reads the Zig lookup's back: the stage,
then for a lookup still running the server's position, the pass, the candidate and the hops, and
the flags EDNS0, NODATA seen, a server failed and the cookie retried. An ended lookup's counters
are nobody's business, so it writes its error instead. What a poll handed out and the caller has
not answered is the caller's to know, and it is not written. The engine's walks spell a lookup
the same way, and hold whether a server failed it, not the cause (spec/README.md). -/
def stateToken (s : State) : String :=
  match s.stage with
  | .done => "done - -"
  | .failed => s!"failed {errToken s.err} -"
  | st => s!"{stageToken st} {s.server}/{s.round}/{s.candidate}/{s.hops} " ++
      flag s.edns 'E' ++ flag s.hadNoData 'N' ++ flag s.cause.isSome 'F' ++ flag s.cookieRetried 'K'

/-- A state as the lookup's transcript writes it: `stateToken`, then the cause the lookup holds,
which a failed lookup reports (docs/design.md §5, The cause of a failure), then rule 3's
conjunction and what an end reports (docs/design.md §25, Stage A). -/
def lineToken (c : Config) (s : State) : String :=
  stateToken s ++ " " ++ causeToken s.cause ++ " " ++ flag s.authentic 'A' ++ " " ++
    reportedToken (reported c s)

end Spec.Lookup
