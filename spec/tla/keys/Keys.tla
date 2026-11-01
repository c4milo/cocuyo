----------------------------- MODULE Keys -----------------------------
\* The table's part of the walks for keys: docs/design.md §25 step 12, written from the design and
\* never from the Zig source (spec/README.md). The table validates, so it keeps `Reserved` slots
\* that only a walk's question may take, and asks each walk's questions as lookups of its own.
\* `spec/lean/Spec/KeyWalk.lean` is the model of one walk; here a walk is its phase, its target
\* and its count of questions, and the server may give any verdict.
\*
\* A slot is free, a consumer's lookup, or a walk's. A consumer's lookup asks, waits for keys, or
\* ended: its end waits for the consumer, who takes it and later frees the slot. A walk's lookup
\* asks, and the table frees its slot when the answer comes. The consumer sees nothing of it.
\*
\* `Mutant` names the rule a configuration of `mutants/` breaks, and is "none" everywhere else.
EXTENDS Naturals, FiniteSets

CONSTANTS
    Slots,        \* the table's slots
    Reserved,     \* `trust_slots_min`
    WalksMax,     \* `walks_max`
    Targets,      \* the names a message may want keys for
    QuestionsMax, \* `chain_questions_max`
    KeyAsksMax,   \* `key_asks_max`
    StartsMax,    \* the walk's bound on the consumer's lookups
    Mutant

VARIABLES slots, walks, starts

vars == <<slots, walks, starts>>

SlotIds == 0..(Slots - 1)
WalkIds == 0..(WalksMax - 1)
\* A slot's walk when it names none.
NoWalk == WalksMax

FreeSlot == [kind |-> "free", stage |-> "none", walk |-> NoWalk, asks |-> 0]
FreeWalk == [phase |-> "free", target |-> 0, questions |-> 0]

Lesser(a, b) == IF a < b THEN a ELSE b

Free == {l \in SlotIds : slots[l].kind = "free"}
Walking == {l \in SlotIds : slots[l].kind = "walk"}

\* Whether a free slot may go to the consumer: after it does, the free slots and the slots the
\* walks hold still make `Reserved` (§25, the table's part).
ConsumerMay == Free # {} /\ Cardinality(Free) + Lesser(Cardinality(Walking), Reserved) > Reserved

\* The walk that runs for `t`, and the walks that run for nothing.
Running(t) == {w \in WalkIds : walks[w].phase # "free" /\ walks[w].target = t}
Idle == {w \in WalkIds : walks[w].phase = "free"}

-------------------------------------------------------------------------------
\* The consumer's side.

\* The consumer starts a lookup, in a free slot it may take.
Start(l) ==
    /\ starts < StartsMax
    /\ slots[l].kind = "free"
    /\ Mutant = "KT1" \/ ConsumerMay
    /\ slots' = [slots EXCEPT ![l] = [kind |-> "lookup", stage |-> "asking", walk |-> NoWalk, asks |-> 0]]
    /\ starts' = starts + 1
    /\ UNCHANGED walks

\* The consumer cancels a lookup that has not ended. A walk it waited on runs on.
Cancel(l) ==
    /\ slots[l].kind = "lookup"
    /\ slots[l].stage \in {"asking", "awaitingKeys"}
    /\ slots' = [slots EXCEPT ![l].stage = "ended", ![l].walk = NoWalk]
    /\ UNCHANGED <<walks, starts>>

\* The consumer takes the end a poll offers. The poll reads the slot's stage alone, so the table
\* must never leave a walk's lookup ended.
Take(l) ==
    /\ slots[l].stage = "ended"
    /\ slots' = [slots EXCEPT ![l].stage = "offered"]
    /\ UNCHANGED <<walks, starts>>

Release(l) ==
    /\ slots[l].stage = "offered"
    /\ slots' = [slots EXCEPT ![l] = FreeSlot]
    /\ UNCHANGED <<walks, starts>>

-------------------------------------------------------------------------------
\* A consumer's lookup and its messages.

\* A message the lookup acts on, or a failure: secure, insecure, bogus past its servers, a
\* timeout. Each ends the lookup, as far as the walks are concerned.
Acted(l) ==
    /\ slots[l].kind = "lookup"
    /\ slots[l].stage = "asking"
    /\ slots' = [slots EXCEPT ![l].stage = "ended"]
    /\ UNCHANGED <<walks, starts>>

Wait(l, w) == slots' = [slots EXCEPT ![l].stage = "awaitingKeys", ![l].walk = w, ![l].asks = @ + 1]

\* The validator answers `keys_wanted` for `t`. The lookup joins the walk that runs for `t`, or a
\* new one (walk rule 10). With every walk busy, or past `key_asks_max`, the message reads as
\* bogus, and the lookup ends.
KeysWanted(l, t) ==
    /\ slots[l].kind = "lookup"
    /\ slots[l].stage = "asking"
    /\ UNCHANGED starts
    /\ IF slots[l].asks >= KeyAsksMax THEN
           slots' = [slots EXCEPT ![l].stage = "ended"] /\ UNCHANGED walks
       ELSE IF Running(t) # {} /\ Mutant # "KT7" THEN
           Wait(l, CHOOSE w \in Running(t) : TRUE) /\ UNCHANGED walks
       ELSE IF Idle # {} THEN
           LET w == CHOOSE w \in Idle : TRUE IN
           /\ Wait(l, w)
           /\ walks' = [walks EXCEPT ![w] = [phase |-> "asking", target |-> t, questions |-> 0]]
       ELSE IF Mutant = "KT5" THEN
           Wait(l, NoWalk) /\ UNCHANGED walks
       ELSE
           slots' = [slots EXCEPT ![l].stage = "ended"] /\ UNCHANGED walks

-------------------------------------------------------------------------------
\* The walks, under the table.

\* The table takes walk `w`'s question at a poll and asks it in a free slot, a reserved one too.
Ask(w, l) ==
    /\ walks[w].phase = "asking"
    /\ slots[l].kind = "free"
    /\ Mutant # "KT2" \/ ConsumerMay
    /\ slots' = [slots EXCEPT ![l] = [kind |-> "walk", stage |-> "asking", walk |-> w, asks |-> 0]]
    /\ walks' = [walks EXCEPT ![w].phase = "asked"]
    /\ UNCHANGED starts

\* What the walk makes of its answer: another question, its target reached, or a failure, the
\* question's own among them (walk rules 7, 8 and 11). A walk's lookup never waits for keys.
Outcomes == IF Mutant = "KT4" THEN {"more", "ready", "failed", "wait"} ELSE {"more", "ready", "failed"}

\* The answer to a walk's question, or its failure. The table hands it to the walker and frees the
\* slot, and the consumer never sees it.
WalkAnswer(l, o) ==
    /\ slots[l].kind = "walk"
    /\ slots[l].stage = "asking"
    /\ UNCHANGED starts
    /\ LET w == slots[l].walk
           q == walks[w].questions + 1
       IN IF o = "wait" THEN
              slots' = [slots EXCEPT ![l].stage = "awaitingKeys"] /\ UNCHANGED walks
          ELSE
              /\ slots' = CASE Mutant = "KT3" -> [slots EXCEPT ![l].stage = "ended"]
                            [] Mutant = "KT6" -> slots
                            [] OTHER -> [slots EXCEPT ![l] = FreeSlot]
              \* Rule 10: past `chain_questions_max` questions the walk fails.
              /\ walks' = [walks EXCEPT ![w].questions = q,
                                        ![w].phase = IF o # "more" THEN o
                                                     ELSE IF q >= QuestionsMax THEN "failed"
                                                     ELSE "asking"]

WalkAnswered(l) == \E o \in Outcomes : WalkAnswer(l, o)

\* A walk ended: the table hands `on_keys_ready` or `on_keys_failed` to each lookup that waits on
\* it, and to no other, and frees the walk.
HandEnd(w) ==
    /\ walks[w].phase \in {"ready", "failed"}
    /\ slots' = [l \in SlotIds |->
                    IF slots[l].kind = "lookup" /\ slots[l].stage = "awaitingKeys"
                       /\ (Mutant = "KT8" \/ slots[l].walk = w)
                    THEN [slots[l] EXCEPT !.stage = IF walks[w].phase = "ready" THEN "asking" ELSE "ended",
                                          !.walk = NoWalk]
                    ELSE slots[l]]
    /\ walks' = [walks EXCEPT ![w] = FreeWalk]
    /\ UNCHANGED starts

-------------------------------------------------------------------------------
\* The specification.

Init ==
    /\ slots = [l \in SlotIds |-> FreeSlot]
    /\ walks = [w \in WalkIds |-> FreeWalk]
    /\ starts = 0

Next ==
    \/ \E l \in SlotIds :
           \/ Start(l) \/ Cancel(l) \/ Take(l) \/ Release(l) \/ Acted(l) \/ WalkAnswered(l)
           \/ \E t \in 1..Targets : KeysWanted(l, t)
           \/ \E w \in WalkIds : Ask(w, l)
    \/ \E w \in WalkIds : HandEnd(w)

\* The table and the servers move; the consumer need not. A server that never answers is a
\* timeout, which is an answer here.
Fairness ==
    /\ \A w \in WalkIds : WF_vars(\E l \in SlotIds : Ask(w, l)) /\ WF_vars(HandEnd(w))
    /\ \A l \in SlotIds : WF_vars(WalkAnswered(l))

Spec == Init /\ [][Next]_vars /\ Fairness

-------------------------------------------------------------------------------
\* What must hold.

TypeOK ==
    /\ \A l \in SlotIds :
           /\ slots[l].kind \in {"free", "lookup", "walk"}
           /\ slots[l].walk \in WalkIds \cup {NoWalk}
           /\ slots[l].asks \in 0..KeyAsksMax
    /\ \A w \in WalkIds :
           /\ walks[w].phase \in {"free", "asking", "asked", "ready", "failed"}
           /\ walks[w].target \in 0..Targets
    /\ starts \in 0..StartsMax

\* A walk's lookups never reach the consumer.
NoWalkOffered == \A l \in Walking : slots[l].stage \notin {"ended", "offered"}

\* The free slots and the slots the walks hold make `Reserved`, so a walk always finds a slot
\* once the walks before it leave theirs.
ReservedKept == Cardinality(Free) + Lesser(Cardinality(Walking), Reserved) >= Reserved

\* A walk asks one question at a time, in one slot.
WalkSlotsOwned ==
    /\ \A l \in Walking : slots[l].walk \in WalkIds /\ walks[slots[l].walk].phase = "asked"
    /\ \A w \in WalkIds : walks[w].phase = "asked" => Cardinality({l \in Walking : slots[l].walk = w}) = 1

\* A lookup that waits for keys waits on a walk that runs.
WaitersWalked ==
    \A l \in SlotIds :
        slots[l].kind = "lookup" /\ slots[l].stage = "awaitingKeys" =>
            slots[l].walk \in WalkIds /\ walks[slots[l].walk].phase # "free"

\* One walk serves every lookup that waits for its target (walk rule 10).
OneWalkATarget ==
    \A v, w \in WalkIds :
        v # w /\ walks[v].phase # "free" /\ walks[w].phase # "free" => walks[v].target # walks[w].target

QuestionsBounded == \A w \in WalkIds : walks[w].questions <= QuestionsMax

\* A lookup that waits for keys is asked again or fails: it never waits forever.
WaitEnds ==
    \A l \in SlotIds :
        (slots[l].kind = "lookup" /\ slots[l].stage = "awaitingKeys") ~> (slots[l].stage # "awaitingKeys")

\* A lookup is asked again only when the walk it waited on reached its target.
AskedOnlyWhenReady ==
    [][\A l \in SlotIds :
          (slots[l].kind = "lookup" /\ slots[l].stage = "awaitingKeys" /\ slots'[l].stage = "asking") =>
              walks[slots[l].walk].phase = "ready"]_vars

===============================================================================
