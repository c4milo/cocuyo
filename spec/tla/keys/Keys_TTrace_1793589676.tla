---- MODULE Keys_TTrace_1793589676 ----
EXTENDS Sequences, TLCExt, Toolbox, Keys, Naturals, TLC

_expression ==
    LET Keys_TEExpression == INSTANCE Keys_TEExpression
    IN Keys_TEExpression!expression
----

_trace ==
    LET Keys_TETrace == INSTANCE Keys_TETrace
    IN Keys_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        walks = ((0 :> [phase |-> "asking", target |-> 1, questions |-> 1]))
        /\
        slots = ((0 :> [kind |-> "lookup", stage |-> "awaitingKeys", walk |-> 0, asks |-> 1] @@ 1 :> [kind |-> "free", stage |-> "none", walk |-> 1, asks |-> 0]))
        /\
        held = ((0 :> TRUE @@ 1 :> TRUE))
        /\
        starts = (1)
    )
----

_init ==
    /\ walks = _TETrace[1].walks
    /\ starts = _TETrace[1].starts
    /\ held = _TETrace[1].held
    /\ slots = _TETrace[1].slots
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ walks  = _TETrace[i].walks
        /\ walks' = _TETrace[j].walks
        /\ starts  = _TETrace[i].starts
        /\ starts' = _TETrace[j].starts
        /\ held  = _TETrace[i].held
        /\ held' = _TETrace[j].held
        /\ slots  = _TETrace[i].slots
        /\ slots' = _TETrace[j].slots

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("Keys_TTrace_1793589676.json", _TETrace)

=============================================================================

 Note that you can extract this module `Keys_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `Keys_TEExpression.tla` file takes precedence 
  over the module `Keys_TEExpression` below).

---- MODULE Keys_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, Keys, Naturals, TLC

expression == 
    [
        \* To hide variables of the `Keys` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        walks |-> walks
        ,starts |-> starts
        ,held |-> held
        ,slots |-> slots
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_walksUnchanged |-> walks = walks'
        
        \* Format the `walks` variable as Json value.
        \* ,_walksJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(walks)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_walksModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].walks # _TETrace[s-1].walks
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE Keys_TETrace ----
\*EXTENDS IOUtils, Keys, TLC
\*
\*trace == IODeserialize("Keys_TTrace_1793589676.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE Keys_TETrace ----
EXTENDS Keys, TLC

trace == 
    <<
    ([walks |-> (0 :> [phase |-> "free", target |-> 0, questions |-> 0]),slots |-> (0 :> [kind |-> "free", stage |-> "none", walk |-> 1, asks |-> 0] @@ 1 :> [kind |-> "free", stage |-> "none", walk |-> 1, asks |-> 0]),held |-> (0 :> FALSE @@ 1 :> FALSE),starts |-> 0]),
    ([walks |-> (0 :> [phase |-> "free", target |-> 0, questions |-> 0]),slots |-> (0 :> [kind |-> "lookup", stage |-> "asking", walk |-> 1, asks |-> 0] @@ 1 :> [kind |-> "free", stage |-> "none", walk |-> 1, asks |-> 0]),held |-> (0 :> TRUE @@ 1 :> FALSE),starts |-> 1]),
    ([walks |-> (0 :> [phase |-> "asking", target |-> 1, questions |-> 0]),slots |-> (0 :> [kind |-> "lookup", stage |-> "awaitingKeys", walk |-> 0, asks |-> 1] @@ 1 :> [kind |-> "free", stage |-> "none", walk |-> 1, asks |-> 0]),held |-> (0 :> TRUE @@ 1 :> FALSE),starts |-> 1]),
    ([walks |-> (0 :> [phase |-> "asked", target |-> 1, questions |-> 0]),slots |-> (0 :> [kind |-> "lookup", stage |-> "awaitingKeys", walk |-> 0, asks |-> 1] @@ 1 :> [kind |-> "walk", stage |-> "asking", walk |-> 0, asks |-> 0]),held |-> (0 :> TRUE @@ 1 :> TRUE),starts |-> 1]),
    ([walks |-> (0 :> [phase |-> "asking", target |-> 1, questions |-> 1]),slots |-> (0 :> [kind |-> "lookup", stage |-> "awaitingKeys", walk |-> 0, asks |-> 1] @@ 1 :> [kind |-> "free", stage |-> "none", walk |-> 1, asks |-> 0]),held |-> (0 :> TRUE @@ 1 :> TRUE),starts |-> 1])
    >>
----


=============================================================================

---- CONFIG Keys_TTrace_1793589676 ----
CONSTANTS
    Slots = 2
    Reserved = 1
    WalksMax = 1
    Targets = 2
    QuestionsMax = 2
    KeyAsksMax = 2
    StartsMax = 3
    Mutant = "KT9"

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Sun Nov 01 22:21:16 EST 2026