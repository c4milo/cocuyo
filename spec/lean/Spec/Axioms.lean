import Spec.LookupProofs.Measure
import Spec.LookupProofs.MeasureGood
import Spec.LookupProofs.Timeout
import Spec.LookupProofs.Cause
import Spec.LookupProofs.Bound
import Spec.LookupProofs.Security
import Spec.LookupProofs.Validation
import Spec.KeyWalkProofs

/-!
# What the proofs rest on

Each theorem of `Spec.LookupProofs`, of the modules under it and of `Spec.KeyWalkProofs`, with
the axioms its proof uses, pinned. A proof left unfinished compiles to `sorryAx`, which would
change a line below and fail `lake build`. The three that may appear are the ones every Lean proof about functions and
propositions uses: `propext`, `Classical.choice` and `Quot.sound`.
-/
namespace Spec.Lookup

/-- info: 'Spec.Lookup.ended_absorbing' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms ended_absorbing

/-- info: 'Spec.Lookup.cancel_after_end' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms cancel_after_end

/-- info: 'Spec.Lookup.cancel_before_end' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms cancel_before_end

/-- info: 'Spec.Lookup.tcpReady_expires' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms tcpReady_expires

/-- info: 'Spec.Lookup.useTcp_never_udp' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms useTcp_never_udp

/-- info: 'Spec.Lookup.request_never_stream' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms request_never_stream

/-- info: 'Spec.Lookup.step_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_le

/-- info: 'Spec.Lookup.sent_lt' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms sent_lt

/-- info: 'Spec.Lookup.lexLt_wf' does not depend on any axioms -/
#guard_msgs in #print axioms lexLt_wf

/-- info: 'Spec.Lookup.init_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms init_good

/-- info: 'Spec.Lookup.step_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_good

/-- info: 'Spec.Lookup.refused_never_timeout' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms refused_never_timeout

/-- info: 'Spec.Lookup.failure_cause' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms failure_cause

/-- info: 'Spec.Lookup.sends_bounded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms sends_bounded

/-- info: 'Spec.Lookup.ignored_unchecked' depends on axioms: [propext] -/
#guard_msgs in #print axioms ignored_unchecked

/-- info: 'Spec.Lookup.authentic_run' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms authentic_run

/-- info: 'Spec.Lookup.reply_clears' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms reply_clears

/-- info: 'Spec.Lookup.authenticated_needs_ad' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms authenticated_needs_ad

/-- info: 'Spec.Lookup.keys_wait_sends_nothing' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms keys_wait_sends_nothing

/-- info: 'Spec.Lookup.secure_run' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms secure_run

/-- info: 'Spec.Lookup.checked_clears' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms checked_clears

/-- info: 'Spec.Lookup.secure_needs_secure' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms secure_needs_secure

/-- info: 'Spec.Lookup.bogus_adds_nothing' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms bogus_adds_nothing

/-- info: 'Spec.Lookup.validate_edns' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms validate_edns

end Spec.Lookup

namespace Spec.KeyWalk

/-- info: 'Spec.KeyWalk.run_good' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms run_good

/-- info: 'Spec.KeyWalk.keys_chain' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms keys_chain

/-- info: 'Spec.KeyWalk.insecure_proven' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms insecure_proven

/-- info: 'Spec.KeyWalk.walk_bounded' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms walk_bounded

/-- info: 'Spec.KeyWalk.answer_counts' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms answer_counts

end Spec.KeyWalk
