import Spec.LookupProofs

/-!
# What the proofs rest on

Each theorem of `Spec.LookupProofs` with the axioms its proof uses, pinned. A proof left
unfinished compiles to `sorryAx`, which would change a line below and fail `lake build`. The three
that may appear are the ones every Lean proof about functions and propositions uses: `propext`,
`Classical.choice` and `Quot.sound`.
-/
namespace Spec.Lookup

/-- info: 'Spec.Lookup.ended_absorbing' depends on axioms: [propext] -/
#guard_msgs in #print axioms ended_absorbing

/-- info: 'Spec.Lookup.cancel_after_end' depends on axioms: [propext] -/
#guard_msgs in #print axioms cancel_after_end

/-- info: 'Spec.Lookup.cancel_before_end' depends on axioms: [propext] -/
#guard_msgs in #print axioms cancel_before_end

/-- info: 'Spec.Lookup.useTcp_never_udp' depends on axioms: [propext] -/
#guard_msgs in #print axioms useTcp_never_udp

/-- info: 'Spec.Lookup.exchange_never_stream' depends on axioms: [propext] -/
#guard_msgs in #print axioms exchange_never_stream

/-- info: 'Spec.Lookup.step_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_le

/-- info: 'Spec.Lookup.sent_lt' depends on axioms: [propext] -/
#guard_msgs in #print axioms sent_lt

/-- info: 'Spec.Lookup.lexLt_wf' does not depend on any axioms -/
#guard_msgs in #print axioms lexLt_wf

/-- info: 'Spec.Lookup.init_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms init_good

/-- info: 'Spec.Lookup.step_good' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms step_good

end Spec.Lookup
