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
  | .nxdomain => "nxdomain" | .nodata => "nodata" | .servfail => "servfail"
  | .formerr => "formerr" | .truncated => "truncated" | .badcookie => "badcookie"

def eventToken : Event → String
  | .poll => "poll" | .expire => "expire" | .sent => "sent" | .sendFailed => "send_failed"
  | .tcpConnected => "tcp_connected" | .tcpFailed => "tcp_failed" | .cancel => "cancel"
  | .requestFailed => "request_failed" | .reply r => "reply_" ++ replyToken r

def errToken : Err → String
  | .nameNotFound => "name_not_found" | .noData => "no_data" | .timeout => "timeout"
  | .allServersFailed => "all_servers_failed" | .chainTooLong => "chain_too_long"
  | .canceled => "canceled" | .noServers => "no_servers"

def outToken : Out → String
  | .sendUdp => "send_udp" | .connectTcp => "connect_tcp" | .sendTcp => "send_tcp"
  | .sendRequest => "send_request" | .wait => "wait" | .done => "done" | .failed e => "failed_" ++ errToken e
  | .accepted => "accepted" | .ignored => "ignored" | .none => "none"

def stageToken : Stage → String
  | .queryReady => "query_ready" | .awaitingUdp => "awaiting_udp" | .tcpNeeded => "tcp_needed"
  | .connectingTcp => "connecting_tcp" | .tcpReady => "tcp_ready"
  | .awaitingTcp => "awaiting_tcp" | .done => "done" | .failed => "failed"

/-- How a configuration's queries go, as the transcript's `config` line names it. -/
def transportToken (c : Config) : String :=
  if c.useTcp then "tcp" else if !c.request then "udp" else if c.quic then "quic" else "https"

def flag (b : Bool) (c : Char) : String := if b then c.toString else "-"

/-- A state as the transcript writes it, and as the replay reads the Zig lookup's back: the stage,
then for a lookup still running the server's position, the pass, the candidate and the hops, and
the flags EDNS0, NODATA seen, a server failed and the cookie retried. An ended lookup's counters
are nobody's business, so it writes its error instead. What a poll handed out and the caller has
not answered is the caller's to know, and it is not written. -/
def stateToken (s : State) : String :=
  match s.stage with
  | .done => "done - -"
  | .failed => s!"failed {errToken s.err} -"
  | st => s!"{stageToken st} {s.server}/{s.round}/{s.candidate}/{s.hops} " ++
      flag s.edns 'E' ++ flag s.hadNoData 'N' ++ flag s.serverFailed 'F' ++ flag s.cookieRetried 'K'

end Spec.Lookup
