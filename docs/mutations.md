# Mutations

A test must fail when the code it covers is broken (CLAUDE.md non-negotiable 9). Every check lands
with its mutation: break the check on purpose, run the narrowest test target that should catch it,
and record `CAUGHT` or `NOT CAUGHT` here and in the body of the commit that adds the check. A
`NOT CAUGHT` means a test is missing, and the missing test is written before the step is called
done.

This matters more here than in most libraries, because half the code rejects malformed input, and
a rejection that silently stopped rejecting would pass a suite built only from well-formed
captures.

Status values: `planned` means the check does not exist yet, so neither does the mutation.

## Step 1, core

Every check `core` carries, each broken on purpose against `zig build test-core`. Thirteen
mutations, thirteen `CAUGHT`. Two of them needed a test written first, because the check and a
loosened version of it agreed on every case the suite already had: M7 needed a name whose labels
reach 253 octets, where reserving the root octet is the only thing that makes one more label an
error, and M9 needed a candidate of exactly 255 octets, which a bound written `>=` would refuse.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| M1 | accept an empty label | `validate_label` | `from_text` refuses `a..b` and `.a` | CAUGHT |
| M2 | accept a 64-octet label | `validate_label` | the label-at-63 and label-at-64 cases | CAUGHT |
| M3 | accept a byte above printable ASCII | `validate_label` | the non-ASCII name case | CAUGHT |
| M4 | accept a backslash | `validate_label` | the escape case, which v1 refuses on input | CAUGHT |
| M5 | stop escaping the separator on output | `write_byte` | the escaped-dot case | CAUGHT |
| M6 | stop escaping a byte outside printable ASCII | `write_byte` | the `\000` and `\255` cases | CAUGHT |
| M7 | stop reserving the root octet | `append_label` | the 253-octet boundary test | CAUGHT |
| M8 | accept one octet past the limit | `terminate` | the name-at-255 test | CAUGHT |
| M9 | refuse a candidate of exactly the limit | `concat` | the concat-to-255 test | CAUGHT |
| M10 | compare case-sensitively | `Name.equal` | the RFC 4343 case test | CAUGHT |
| M11 | call the empty name relative | `is_absolute` | the root-is-absolute test | CAUGHT |
| M12 | write the v6 nibbles high first | `name_reverse` | the ip6.arpa text test | CAUGHT |
| M13 | keep leading zeros in an octet | `write_decimal` | the octet-width test | CAUGHT |

One check has no mutation here, because the mutation is a lint finding rather than a test failure:
`label_count` walks under `constants.labels_max`, and rewriting that loop as `while (true)` is
refused by the unbounded-loop rule before any test runs.

## Step 2, the codec

Every check the header, the name decoder, the question compare, the query builder and the OPT
record carry, broken against `zig build test-wire`. Fourteen mutations, fourteen `CAUGHT` — one
of them only after a test was written for it.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| W1 | a pointer may point forwards | strictly backwards, RFC 1035 §4.1.4 | the forwards-pointer test | CAUGHT |
| W2 | the hop bound allows one more hop | `compression_hops_max` | the seventeen-pointer chain | CAUGHT |
| W3 | a reserved label kind is read as a label | the kind bits | the `01` and `10` cases | CAUGHT |
| W4 | a label may run past the end of the message | `copy_label`'s bound | the truncated-label test | CAUGHT |
| W5 | `skip` follows the pointer instead of ending | `skip`'s contract | the skip offsets | CAUGHT |
| W6 | the case mixer walks bytes, not labels | `mix_case` | **a test written for it** | CAUGHT |
| W7 | the case mixer reuses one word of entropy | `mix_case` | the 96-letter test | CAUGHT |
| W8 | the question compare folds case | RFC 5452 §9.2, DNS-0x20 | the flipped-letter test | CAUGHT |
| W9 | the question compare skips the type | §7 check 5 | the wrong-type test | CAUGHT |
| W10 | the question compare skips the length check | §7 check 1 | the short-message test | CAUGHT |
| W11 | a query sets no recursion-desired bit | RFC 1035 §4.1.1 | the query corpus, byte for byte | CAUGHT |
| W12 | the TCP length prefix counts itself | RFC 7766 §8 | the TCP prefix test | CAUGHT |
| W13 | the EDNS version check is dropped | RFC 6891 §6.1.3 | the version test | CAUGHT |
| W14 | an unknown rcode reads as no_error | RFC 6895 §2.3 | the rcode-15 test | CAUGHT |

W6 is the one worth reading twice. `mix_case` walking `name.bytes[offset..]` rather than
`name.bytes[offset + 1 ..]` cases every letter of a label but the last, and it passed every test
in the file: the length octets stayed put, because a length octet is never a letter, and enough
letters still changed for the counting tests. What it broke was invisible until a test pinned that
*each* letter position can take either case over many seeds. A weaker 0x20 is exactly the kind of
bug that never shows up as a failure in the field, only as a resolver that is easier to spoof than
it claims.

## Step 2, the parse side

The record walk and the answer walk, broken against `zig build test-wire`. Eleven mutations,
eleven `CAUGHT` — three only after the tests and fixtures they needed were written.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| R1 | the walk trusts the count past the end | §7, no count is a reason to read | the lying-count fixture | CAUGHT |
| R2 | the rdlength bound is loose by one | RFC 1035 §4.1.3 | **a fixture written for it** | CAUGHT |
| R3 | an A record's rdata width is unchecked | RFC 1035 §3.4.1 | the three-octet address | CAUGHT |
| R4 | the `records_max` bound is dropped | §12 | the truncated-walk test | CAUGHT |
| R5 | an rdata name need not fill its rdata | RFC 1035 §3.3 | the padded and short rdata fixtures | CAUGHT |
| R6 | a record is taken whatever its owner | RFC 5452 §6 | the injected-record fixture | CAUGHT |
| R7 | the CNAME chain bound is doubled | RFC 1034 §3.6.2, §12 | the hop-bound test | CAUGHT |
| R8 | records are taken with no room left | §9 | **the seventeen-record fixture** | CAUGHT |
| R9 | the TTL reported is the largest | §4 `Answer.ttl_seconds` | **the fixture's TTLs, made to differ** | CAUGHT |
| R10 | a response with two questions is accepted | RFC 1035 §4.1.2 | the qdcount test | CAUGHT |
| R11 | a moved chain reports no_data | §5 CNAME policy | the chain-incomplete test | CAUGHT |

Three of these earned their keep twice. R2 showed that an rdlength of 400 cannot catch a bound
that is loose by one, so the corpus gained a record whose rdata ends exactly one octet past the
message. R9 showed that a fixture whose records all carry TTL 60 cannot tell the smallest TTL from
the largest, so the CNAME's target now carries 300. And R7 found dead code rather than a missing
test: the hop check inside the loop was unreachable, because the loop's own condition and the
error after it already bounded the chain. The check was removed and the mutation moved to the
bound that does the work.

## Step 3, the state machine

The lookup's checks and transitions, broken against `zig build test-resolver`. Sixteen mutations,
sixteen `CAUGHT` — two after a test was written, and one of those after a fixture that could reach
the path at all.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| S1 | the transaction id is not checked | §7 check 2 | the wrong-id test | CAUGHT |
| S2 | the source address is not checked | §7 check 3, RFC 5452 §4.4 | the other-server test | CAUGHT |
| S3 | the source port is not compared | §7 check 3, RFC 5452 §4.5 | the wrong-port test | CAUGHT |
| S4 | the question section is not compared | §7 check 5, RFC 5452 §9.1 | the other-name test | CAUGHT |
| S5 | the qname goes out uncased | RFC 5452 §9.2 | the folded-case test | CAUGHT |
| S6 | a response is read whatever the state | §5 | the after-settled test | CAUGHT |
| S7 | truncation over TCP is obeyed | RFC 7766 §5 | **a test written for it** | CAUGHT |
| S8 | a malformed answer fails the lookup | §16 decision 10 | the malformed-section test | CAUGHT |
| S9 | a failed chain walk leaves the name moved | §5 CNAME policy | **the CNAME-loop fixture** | CAUGHT |
| S10 | NXDOMAIN moves to the next server | §5 search policy | the candidate walk test | CAUGHT |
| S11 | FORMERR does not turn EDNS0 off | RFC 6891 §6.2.2 | the FORMERR test | CAUGHT |
| S12 | a chain re-query keeps its transaction | §7 entropy | the new-transaction test | CAUGHT |
| S13 | the deadline is not armed on a send | §5 retry policy | the wait test | CAUGHT |
| S14 | the wait ends one instant late | §5 retry policy | the poll-at-the-deadline test | CAUGHT |
| S15 | the server index does not wrap | §5 retry policy | the every-server test | CAUGHT |
| S16 | a settled lookup can time out | §5 | the settled-lookup test | CAUGHT |

S9 is the interesting one. The collector moves the chain's name in place, and the state machine
restores it when the walk then fails — but no message could reach that path: a malformed record
fails the first pass, before the chain has moved anywhere. The path that reaches it is a CNAME
chain that *loops*, where every pass succeeds and the hop bound is what finally stops it. With the
restore removed, the lookup is left asking the next server about a name halfway around the loop,
which is a name the caller never mentioned. The fixture is now two CNAMEs pointing at each other.

## Step 4, the table

The slot table, the key table and the demultiplexer, broken against `zig build test-resolver`.
Eleven mutations: ten `CAUGHT`, and one deliberate `NOT CAUGHT` explained below. Two of the ten
needed tests written for them, and one of those found a bug rather than a gap.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| T1 | the probe stops at the first tombstone | §11 key table | the tombstone-chain test | CAUGHT |
| T2 | a candidate is offered without its id | §11 key table | the same-index test | CAUGHT |
| T3 | the probe stops at the first refusal | §4 demultiplexing | **the colliding-id test** | CAUGHT |
| T4 | a new transaction is not re-keyed | §11 re-keying | the retry-then-answer test | CAUGHT |
| T5 | a released slot keeps its generation | §4 handles | the generation test | CAUGHT |
| T6 | a released slot's key is left behind | §4 release | the released-slot test | CAUGHT |
| T7 | a released slot is not freed | §4 release | the churn test | CAUGHT |
| T8 | the poll does not rotate | §4 poll | the rotation test | CAUGHT |
| T9 | an event does not drop the deadline cache | §11 one timer | **the late-deadline test** | CAUGHT |
| T10 | the deadline reported is the latest | §11 one timer | the two-lookup test | CAUGHT |
| T11 | the assertion guarding a free slot | §4 | nothing, by design | NOT CAUGHT |

T9 found a bug, not a gap. The deadline cache was invalidated where the table could see a change,
but a caller told a *lookup* its query had gone out by reaching through `lookup_of`, which armed a
deadline the table never learned about. The table then handed out a timer running past that
lookup's timeout. The fix is that every event is now the table's own entry point, and the
mutation that would have hidden it — dropping the invalidation — is caught by a test where a fresh
lookup's wait is shorter than the one already cached.

T3 is the collision case. Two live lookups can draw the same sixteen-bit id, and the datagram then
has two candidates. The test forces the collision and aims the datagram at the candidate that is
*second* in the chain, because a walk that stopped at the first refusal would pass the earlier
test and drop this answer.

T11 stays uncaught on purpose. `deliver` asserts that the slot a key names is occupied, and
nothing can reach it while `release` tombstones the key it held — so removing the assertion changes
no behaviour any test can see. That is what an assertion is for: it covers the programmer error of
a corrupted key table, where the alternative is reading a lookup that is `undefined`. An
assertion whose removal a test can see would have been a check.

## Step 5, the config parser

The `resolv.conf` parser and the address text parser it needs, broken against
`zig build test-config`. Eighteen mutations, eighteen `CAUGHT` — four after the tests and the two
dead checks the mutations found.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| C1 | a quad of three octets is accepted | the dotted quad | the short-quad test | CAUGHT |
| C2 | an octet over 255 is truncated | RFC 1035 §3.4.1 | the 256 test | CAUGHT |
| C3 | a leading zero is read as decimal | the octal ambiguity | the `010` test | CAUGHT |
| C4 | an empty group is accepted | RFC 4291 §2.2 | the double-`::` test | CAUGHT |
| C5 | a `::` may stand for no groups | RFC 4291 §2.2 | **a test written for it** | CAUGHT |
| C6 | an address of seven groups is accepted | RFC 4291 §2.2 | the seven-group test | CAUGHT |
| C7 | a dotted quad may appear anywhere | RFC 4291 §2.2 form 3 | the misplaced-quad test | CAUGHT |
| C8 | a group of five digits is accepted | RFC 4291 §2.2 | the `12345::1` test | CAUGHT |
| C9 | a non-digit in an octet is accepted | the dotted quad | the `1.2.3.x` test | CAUGHT |
| C10 | an unknown option stops the line | §10 | **the interleaved options test** | CAUGHT |
| C11 | a search line adds to the previous | `resolv.conf(5)` | the last-line-wins test | CAUGHT |
| C12 | no nameserver means no server | §10 | the empty-file test | CAUGHT |
| C13 | a malformed nameserver takes a slot | §10 | the bad-address test | CAUGHT |
| C14 | a comment is read as a keyword | `resolv.conf(5)` | the comment test | CAUGHT |
| C15 | the line bound is doubled | §12 | the long-file test | CAUGHT |
| C16 | servers past the limit are written | §12 | the too-many-servers test | CAUGHT |
| C17 | a timeout of zero is kept | §10 | the `timeout:0` test | CAUGHT |
| C18 | a value over the limit is refused | `resolv.conf(5)` | the clamping test | CAUGHT |

Two mutations found dead code rather than missing tests, which is the third and fourth time in
this tree. The parser refused a zone index, a bracketed address and a prefix length with a scan
for `%`, `[`, `]` and `/` — and no input could reach it, because none of those four is a digit and
the group and octet parsers refuse them wherever they appear. The same for a second `::`: it
leaves an empty group between two colons, and an empty group is already not a group. Both checks
are gone and the tests that pinned their behaviour stayed, because the behaviour is what matters
and it is still there.

C10 is the one that needed a better test rather than a new one. The options test had the unknown
options last, where a parser that stopped at the first one it did not recognise behaves exactly
like one that skips them. They now sit between the options that matter.

## Planned, step 6

| # | Mutation | Check it breaks | Expected to be caught by | Status |
| --- | --- | --- | --- | --- |
| 1 | accept a compression pointer that points forwards | design §8, strictly backwards | the crafted-loop message test | planned |
| 2 | drop the strictly-backwards rule, keep the hop bound | design §8, both bounds | the pointer-loop and name-length tests | planned |
| 3 | match on transaction id alone | design §7, check 5 | the spoofed-question test | planned |
| 4 | skip the source endpoint compare | design §7, check 3 | the off-path spoof test | planned |
| 5 | compare the question case-insensitively | design §7, DNS-0x20 | the 0x20 test | planned |
| 6 | trust `ancount` past the end of the message | design §7, parsing | the lying-count test | planned |
| 7 | accept an `A` whose owner is not in the chain | design §5, CNAME policy | the injected-record test | planned |
| 8 | off-by-one in the rdlength bound | design §8, record walking | the truncated-rdata test | planned |
| 9 | remove the CNAME hop bound | design §5, `cname_hops_max` | the chain-loop script | planned |
| 10 | re-arm the deadline on an ignored datagram | design §7, the wait stands | the flood test | planned |
| 11 | keep the same transaction id across a CNAME re-query | design §5, new transaction | the re-query entropy test | planned |
| 12 | advance the search candidate on SERVFAIL | design §5, rcode mapping | the policy table test | planned |

## The build's own mutation

`zig build lint` runs the rules twice: over the tree, which must be clean, and over a canary tree
written into the build cache that holds one violation of every rule, which must exit 1 and name
each rule on stdout. A clean tree cannot show that a rule is live — a run that dropped a rule
passes a tree that rule would have passed anyway. The canary is the mutation, and it is wired into
`build/lint.zig` rather than recorded here, because it runs on every build.

`zig build graph-check` is the same idea for the module graph: it compiles a fixture that imports
`config` from a module of the `resolver` shape and requires the compiler to reject it, with a
positive control importing `core` that must compile, so a failure means what it says.
