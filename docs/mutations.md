# Mutations

A test must fail when the code it covers is broken (CLAUDE.md non-negotiable 10). Every check lands
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
| W4 | a label may run past the end of the message | `copy_label`'s bound, `label_at`'s since 2026-10-14 (NS6) | the truncated-label test | CAUGHT |
| W5 | `skip` follows the pointer instead of ending | `skip`'s contract until 2026-10-14, when it became the contract: W5 was written again (The skip follows each pointer) | the skip offsets | CAUGHT |
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
sixteen `CAUGHT` — three after a test was written, one of those after a fixture that could reach
the path at all, and S8 again on 2026-09-24, below.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| S1 | the transaction id is not checked | §7 check 2 | the wrong-id test | CAUGHT |
| S2 | the source address is not checked | §7 check 3, RFC 5452 §4.4 | the other-server test | CAUGHT |
| S3 | the source port is not compared | §7 check 3, RFC 5452 §4.5 | the wrong-port test | CAUGHT |
| S4 | the question section is not compared | §7 check 5, RFC 5452 §9.1 | the other-name test | CAUGHT |
| S5 | the qname goes out uncased | RFC 5452 §9.2 | the folded-case test | CAUGHT |
| S6 | a response is read whatever the state | §5 | the after-settled test | CAUGHT |
| S7 | truncation over TCP is obeyed | RFC 7766 §5 | **a test written for it** | CAUGHT |
| S8 | a malformed answer fails the lookup | §16 decision 10 | the malformed-section test; since 2026-09-24 the wrong-length address test | CAUGHT |
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

S8 was `NOT CAUGHT` when it was run again on 2026-09-24. The malformed-section test's record
reaches past the message, and since step 10 the scan for the OPT record refuses it first, walking
every record by its length. So the answer's collection, whose failure S8 breaks, was no longer
reached. The wrong-length address test was written for it: an A record of three octets passes the
scan and fails the collection (RFC 1035 §3.4.1), and it catches S8.

## The lookup's and `getaddrinfo`'s mutations as data

2026-09-24. The mutations of the sections above that break the lookup and its transports, and
the `getaddrinfo` shape and its walks, were written again as data: `tools/mutations/lookup.zon`
holds 64 and `tools/mutations/address.zon` 35. Only descriptions had been kept, so most were
rebuilt from them against the code as it is, and a rebuilt one is the mutation kept now:

- Step 3 and the Lean model's replay: the sixteen of the state machine, and S1 to S9 and G1 of the
  replay.
- DoH's DNS half: DH1 to DH21.
- An answer's TTL and DoQ's DNS half: TT1 to TT8 and QU1 to QU9.
- Step 14: A1 to A24 but A6, whose code step 15 replaced, and H1 to H6; and the walks' A1 to A3
  and N1 to N3.

The Lean model's own mutations, M1, M2, P1 and DM1 to DM3, break the model and its proofs rather
than the code. `tools/mutations/lean.zon` holds them, and each is run against `zig build
spec-lean`, the Lean half of `zig build spec` with no TLC. `zig build mutations -- <set>` runs a set, each mutation against the step its row
names. Run on 2026-09-24, all 105 were caught where the data says, S8 of step 3 after the test
above was written. The six of the model took 23 seconds.

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
dead checks the mutations found. §19 step 14 moved the address parser and its tests to `core`,
so C1 to C9 break against `zig build test-core` since.

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

## Step 6, the example

The example is a check of its own: `zig build test` compiles it, so an API change that breaks it
fails the build, and running it resolves a real name against a real server. That is where the one
finding of this step came from, and it is the kind of finding no unit test was going to produce.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| E1 | a chain name keeps cocuyo's own case | §7 DNS-0x20 | **the compressed-suffix test** | CAUGHT |

Running the example against the live network printed `www.github.com is github.cOm.` The capital
was cocuyo's. DNS-0x20 randomises the case of the question, the server compressed the CNAME's
target to a pointer into the question it echoed, and the target therefore decoded wearing the
randomisation cocuyo had applied. Case is insignificant in DNS (RFC 1035 §2.3.3), so nothing was
wrong on the wire, but a caller reading `github.cOm` would reasonably think something had broken.

A chain name is now folded to lowercase when 0x20 is on, and the fixture that pins it is a CNAME
whose rdata is `host.` followed by a pointer at the `com` label of the echoed question. The test
runs sixteen seeds, because whether a given seed capitalises anything in that suffix is a matter
of which bits it drew.

## Step 7, the bench

A benchmark is a check too: a row is only worth reading if the case does what its name says, so
the harness's arithmetic and every case's behaviour are pinned by tests in `bench/`, and those
tests were broken against `zig build test-tools`. Eight mutations, eight `CAUGHT` — three only
after the review that preceded them changed the harness.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| B1 | the median is read one sample off | `summarise` | **the summary test, through the harness** | CAUGHT |
| B2 | a sample is picoseconds per sample, not per run | `sample` | the per-run test | CAUGHT |
| B3 | the wrong-question reply echoes the right question | the row's name | **the check-by-check verdict test** | CAUGHT |
| B4 | the CNAME case stops restoring the chain | the row's name | **the run-twice assertion** | CAUGHT |
| B5 | the rotation does not wrap | the cold-slot row | the thousand-turn test, by bounds | CAUGHT |
| B6 | `unheld_id` returns the first id without walking | the stray rows | **the forced-collision test** | CAUGHT |
| B7 | `unique_handle` returns the first lookup whatever its id | the accepted rows | **the forced-collision test** | CAUGHT |
| B8 | the round trip skips `init` and reuses one lookup | the round-trip row | the answer test, by an assertion | CAUGHT |

B1 was a test that tested itself: the median test sorted an array and indexed it with the same
expression the harness used, so a change to the harness could not fail it. The summary is now a
function, and the test calls it.

B6 and B7 are guards against a probability. Two of 1024 lookups drawing one sixteen-bit id, or
a stray id happening to be held, does not occur for the fixed seed, so mutating the *call sites*
to take the first value on trust changes nothing a test can see: they are equivalent mutants for
this seed. What can be tested is the guard itself under a collision the test forces, and that is
what the two forced-collision tests do.

The review before these mutations — four reviewers, twenty-one findings, none of them verified
by the refuters, which the session's usage limit killed — was verified by hand instead, and
changed the harness in five ways: the clock became `CLOCK_UPTIME_RAW`, because `CLOCK_MONOTONIC`
on this macOS steps a whole microsecond and had quantised every figure at 5 ps; the round-trip row
gained `init` and lost an 856-octet copy it had been hiding; a cold-slot row was added, because the
layout question of §11 had been closed with a hot-cache number that could not see a cache line;
the `resolv.conf` case stopped parsing a comptime constant; and the harness spins for a second
before its first case, because two of three runs had measured the tail of the gate's test
binaries in their first rows.

## The comparison against c-ares

`zig build bench-cares` runs its own tests before it times anything, and those tests are what
make the comparison a comparison: they show both sides are looking at the same bytes. Broken
against `zig build test-cares`. Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| K1 | c-ares advertises a payload size one octet off | the byte-identity test | the query bytes differ | CAUGHT |
| K2 | c-ares asks for AAAA where cocuyo asks for A | the byte-identity test | the query bytes differ | CAUGHT |
| K3 | the c-ares walk counts every record, not the A records | the record-count test | the CNAME case counts two | CAUGHT |
| K4 | the c-ares walk reads no address at all | the record-count test | nothing is counted | CAUGHT |

K1 and K2 are the mutations that matter. The byte-identity test says c-ares and cocuyo write the
same query for the same question, octet for octet; a comparison whose two sides built different
queries would be timing two different things and calling the ratio a result. Every octet of the
OPT record is in that test's reach, and K1 shows one octet is enough to fail it.

## Step 8, the cache

The cache of design §18 and the negative TTL it needs. The wire side, `wire.response.negative_ttl_seconds`,
was broken against `zig build test-wire`; the resolver side, `Failure.negative_ttl_seconds`,
against `zig build test-resolver`; the cache against `zig build test-cache`; and the word fold
the hash reads, `Name.fold_word`, against `zig build test-core`. Forty-seven mutations,
forty-six `CAUGHT` and one that found redundant code — two of the cache's only after their tests
were sharpened.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| N1 | the negative TTL is the SOA minimum, not capped by the record's TTL | RFC 2308 §5 | the min test | CAUGHT |
| N2 | an SOA's fixed fields may fall short of its rdata | the rdlength bound | **a fixture with one octet too many** | CAUGHT |
| N3 | the authority walk starts at the answers | RFC 2308 §2 | the answer-then-SOA fixture | CAUGHT |
| N4 | a message with no SOA reports the cap instead of zero | §18, zero is not cached | the no-SOA test | CAUGHT |
| N5 | the section start is summed in an octet again | the u8 overflow of step 2 | the maximal-name fixture | CAUGHT |
| N6 | NXDOMAIN does not record the TTL | §18 | the NXDOMAIN failure test | CAUGHT |
| N7 | NODATA does not record the TTL | RFC 2308 §2.2 | the NODATA failure test | CAUGHT |
| N8 | every failure carries zero | §18 | the failure tests | CAUGHT |
| N9 | every failure carries the TTL | §18, only a negative answer | the timeout test | CAUGHT |
| N10 | a malformed SOA reads as one second | §18, zero is not cached | the broken-SOA test | CAUGHT |
| Q1 | a hit does not set the visited bit | §18, SIEVE | the bit test | CAUGHT |
| Q2 | an entry expires one instant late | §18 | the boundary test | CAUGHT |
| Q3 | an expired entry is never evicted on a get | §18 | the expiry test | CAUGHT |
| Q4 | a hit reports the TTL put, not what is left | §18 | the remaining-TTL test | CAUGHT |
| Q5 | a truncated answer is cached | §18 | the refusal test | CAUGHT |
| Q6 | a TTL of zero is cached | §18 | the refusal test | CAUGHT |
| Q7 | the cap is not applied | §18 | the cap test | CAUGHT |
| Q8 | a put for a held question inserts a duplicate | §18, in place | the in-place test, by `len` | CAUGHT |
| Q9 | a replacement does not set the bit | §18 | the in-place test | CAUGHT |
| Q10 | a new entry is born visited | §18, SIEVE | the bit test, by its neighbours | CAUGHT |
| Q11 | the stored name is not folded | §18, the key | the folded-name test | CAUGHT |
| Q12 | the hash is not folded | §18, the key | the case-insensitive hit | CAUGHT |
| Q13 | the hash ignores the type | §18, the key | the hash test | CAUGHT |
| Q14 | the hash ignores the flag | §18, the key | the hash test | CAUGHT |
| Q15 | an eviction keeps the key | the index | `find`'s own assertion, on a free slot | CAUGHT |
| Q16 | an eviction leaves the hand on the slot | §18 | the hand-moves-on test | CAUGHT |
| Q17 | a flush keeps the keys | §18 | the flush test | CAUGHT |
| Q18 | a refused put keeps its slot | §18 | **the probe test, at one slot over the bound** | CAUGHT |
| Q19 | a negative TTL of zero is cached | §18 | `insert`'s own assertion | CAUGHT |
| Q20 | `find` ignores the flag | §18, the key | **the direct `find` test** | CAUGHT |
| Q21 | the hand evicts a visited entry | §18, SIEVE | the survives-one-sweep test | CAUGHT |
| Q22 | the hand never clears the bit | §18, SIEVE | the not-two-sweeps test | CAUGHT |
| Q23 | the hand ignores expiry | §18 | the expired-on-sight test | CAUGHT |
| Q24 | the hand is not saved | §18 | the hand-keeps-its-place test | CAUGHT |
| Q25 | the hand restarts at the oldest | §18 | the hand-keeps-its-place test | CAUGHT |
| Q26 | the sweep bound is one pass | §18 | the every-entry-visited test | CAUGHT |
| Q27 | the probe bound is off by one | §12 | the seventeenth-entry test | CAUGHT |
| Q28 | a walk goes past an empty entry | the index | the stops-at-empty test | CAUGHT |
| Q29 | a removal empties rather than tombstones | the index | the tombstone test | CAUGHT |
| Q30 | an insert skips tombstones | the index | the reuse test, by position | CAUGHT |
| Q31 | the hand does not wrap | §18, SIEVE | the not-two-sweeps test | CAUGHT |
| Q32 | an unlink drops the older link | the chain | the middle-unlink test | CAUGHT |
| Q33 | `find` ignores the type | §18, the key | the direct `find` test | CAUGHT |
| Q34 | the hash ignores the name's length | §18, the key | nothing: **the length was redundant, and is gone** | CAUGHT |
| M14 | the word fold folds past `Z` | `Name.fold_word` | the every-octet test | CAUGHT |
| M15 | the word fold folds an octet past ASCII | `Name.fold_word` | the every-octet test | CAUGHT |
| M16 | the word fold folds below `A` | `Name.fold_word` | the every-octet test | CAUGHT |

Q18 and Q20 survived the first run. Q18 leaked the slot of a refused put, and the probe test ran
on a table of thirty-two slots, where one lost slot changes nothing a test reads; it now runs on
a table of seventeen, one more than the bound, where the leak leaves the table one short of full
and the next put trips the sweep's own assertion. Q20 dropped the `absolute` compare from `find`,
and nothing noticed because the hash already mixes the flag, so the two forms of a name never
meet in one chain; the compare is still there because a hash is not a proof, and a test now calls
`find` with the other form's hash to show it.

Q34 is the fifth mutation in this tree to find code with nothing to do. The hash mixed the name's
length in, and dropping it changed no test, because it could not: the last chunk of a name is
zero-padded to eight octets, and a name ends at its root octet, so no valid name is another's
zero padding and the octets alone tell every two names apart. The length is gone, with the
argument in the hash's comment.

## Step 9, every record type

Design §19 step 9: the decoders of `src/wire/rdata/`, the copy of `record_copy.zig` that writes
names out in full, the collector's `ANY` and `CNAME` rules, and `Kind` itself. Broken against
`zig build test-wire`, and the two on `Kind` against `zig build test-core`. Thirty-two mutations,
thirty-two `CAUGHT` — one after its fixture was rewritten.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| D1 | a stored name accepts a compression pointer | RFC 3597 §4, the stored form | the pointer test | CAUGHT |
| D2 | a name need not fill its rdata | RFC 1035 §3.3 | the trailing-octet test | CAUGHT |
| D3 | a character-string may run past the rdata | RFC 1035 §3.3 | the short TXT test, by the crash | CAUGHT |
| D4 | an empty TXT is accepted | RFC 1035 §3.3.14 | the empty-rdata test | CAUGHT |
| D5 | HINFO need not fill its rdata | RFC 1035 §3.3.2 | the trailing test | CAUGHT |
| D6 | MX need not fill its rdata | RFC 1035 §3.3.9 | the trailing test | CAUGHT |
| D7 | SRV reads its port at the weight | RFC 2782 | the port test | CAUGHT |
| D8 | SOA reads refresh at retry | RFC 1035 §3.3.13 | the counters test | CAUGHT |
| D9 | NAPTR need not fill its rdata | RFC 3403 §4.1 | the trailing test | CAUGHT |
| D10 | SIG needs no fixed fields | RFC 2535 §4.1 | the short test, by the crash | CAUGHT |
| D11 | SVCB keys may repeat or fall | RFC 9460 §2.2 | the ordering tests | CAUGHT |
| D12 | an SVCB parameter may run past the rdata | RFC 9460 §2.2 | the ends-inside test | CAUGHT |
| D13 | an SVCB port of any length | RFC 9460 §7.2 | the format tests | CAUGHT |
| D14 | an empty alpn-id | RFC 9460 §7.1 | the format tests | CAUGHT |
| D15 | mandatory may list itself | RFC 9460 §8 | the format tests | CAUGHT |
| D16 | TLSA reads its selector at the usage | RFC 6698 §2.1 | the fields test | CAUGHT |
| D17 | a URI with an empty target | RFC 7553 §4.5 | the empty-target test | CAUGHT |
| D18 | a CAA with an empty tag | RFC 8659 §4.1 | the tag tests | CAUGHT |
| D19 | a CAA tag with any character | RFC 8659 §4.1 | the tag tests | CAUGHT |
| D20 | an OPT option may run past the rdata | RFC 6891 §6.1.2 | the short test | CAUGHT |
| D21 | the MX layout has no name | RFC 3597 §4 | the copy test, by the pointer left in | CAUGHT |
| D22 | the copy ignores octets after the last field | RFC 1035 §3.3 | the trailing-octet test | CAUGHT |
| D23 | a name may run past its record | the record's bounds | **the SVCB-into-next-record test** | CAUGHT |
| D24 | the copy never checks its room | the buffer | the does-not-fit test, by the crash | CAUGHT |
| D25 | an ANY question follows a CNAME | RFC 1034 §3.6.2 | the ANY-at-an-alias test | CAUGHT |
| D26 | a CNAME question follows the CNAME | RFC 1034 §3.6.2 | the CNAME-question test | CAUGHT |
| D27 | no bound on the records kept | `records_kept_max` | the thirty-three test, by the crash | CAUGHT |
| D28 | a kept record loses its type | §19, ANY | the ANY test | CAUGHT |
| D29 | a kept record's TTL is not noted | §18, the cache's TTL | the MX test | CAUGHT |
| D30 | PTR names stored as rdata | §19, storage | the storage test | CAUGHT |
| D31 | OPT is queryable | RFC 6891 §6.1.1 | the queryable test | CAUGHT |
| D32 | the SVCB layout has no name | RFC 9460 §2.2 | the layout test | CAUGHT |

D23 survived its first fixture, an MX whose name ran past the record and the message together:
the name decoder failed on the message's end by itself, and the exact-consumption check of D22
covers every layout without `rest` besides. The check earns its keep where `rest` follows the
name, so the fixture is now an SVCB whose target runs into the record after it, where nothing
else would notice: the copy would keep `foo.example.com` and take the parameters from past the
record's end.

## Step 10, DNS cookies

Design §19 step 10: the COOKIE option written into and read out of the OPT record, the OPT
record found across a response's three sections, the per-server table, and check 6 of §7 with
what follows it. Broken against `zig build test-wire` and `zig build test-resolver`. Twenty
mutations, twenty `CAUGHT` — one after a test was added for it.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| O1 | the option's length omits the server cookie | RFC 7873 §4 | the long-form test | CAUGHT |
| O2 | a nine-octet option is accepted | RFC 7873 §5.2.2 | the lengths test | CAUGHT |
| O3 | the last of two COOKIE options is taken | RFC 7873 §5.3 | the first-of-two test | CAUGHT |
| O4 | an OPT owned by a name is accepted | RFC 6891 §6.1.2 | the bad-owner test | CAUGHT |
| O5 | the OPT is sought in the answer section alone | RFC 6891 §6.1.1 | the additional-section test | CAUGHT |
| O6 | the record's size ignores the server cookie | `query_bytes_max` | the largest-query test | CAUGHT |
| O7 | a wrong client cookie is accepted | RFC 7873 §5.3 | the wrong-cookie test | CAUGHT |
| O8 | a missing cookie is accepted once expected | RFC 7873 §5.3 | the no-cookie-after test | CAUGHT |
| O9 | a missing cookie is rejected before any is learned | RFC 7873 §5.3 | the no-cookie-before test | CAUGHT |
| O10 | the server cookie is never learned | RFC 7873 §5.3 | the next-query test | CAUGHT |
| O11 | BADCOOKIE moves to the next server | RFC 7873 §5.3 | the retry test | CAUGHT |
| O12 | a second BADCOOKIE is retried again | RFC 7873 §5.3 | the TCP test | CAUGHT |
| O13 | BADCOOKIE over TCP is retried forever | §19 step 10 | the next-server test | CAUGHT |
| O14 | the rcode's high bits are ignored | RFC 6891 §6.1.3 | every BADCOOKIE test | CAUGHT |
| O15 | a query carries no cookie | RFC 7873 §5.1 | the first-query test | CAUGHT |
| O16 | the client cookie ignores the server's address | RFC 7873 §4.1 | the per-server test | CAUGHT |
| O17 | the client cookie ignores the seed | RFC 7873 §4.1 | the per-seed test | CAUGHT |
| O18 | the retry flag is never reset | §19 step 10 | the next-server test | CAUGHT |
| O19 | a cookie is learned from an answer to a query without EDNS | RFC 7873 §5.1 | **the EDNS-off test** | CAUGHT |
| O20 | BADVERS is collected as an answer | RFC 6891 §6.1.3 | the policy table test | CAUGHT |

O19 survived the first run. The guard says a lookup that sent no OPT record learns nothing from
a cookie that comes back anyway, so the next lookup does not expect a cookie it never sent; the
test that shows it is a lookup without EDNS answered with a cookie, accepted, and a server table
that expects nothing after.

## Step 11, configuration parity and the hosts file

Design §19 step 11: the knobs c-ares has and cocuyo lacked, the `Server` type with its TCP port,
`use-vc` and the default-server option of `resolv.conf`, the two environment appliers, and the
hosts file. Broken against `zig build test-core`, `test-wire`, `test-resolver` and
`test-config`. Twenty-three mutations, twenty-three `CAUGHT`. §19 step 14 moved the hosts table
and its tests to `core`, so P15, P16, P17 and P21 break against `zig build test-core` since.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| P1 | a restart ignores `use_tcp` | §19 step 11 | the re-query over TCP | CAUGHT |
| P2 | `init` ignores `use_tcp` | §19 step 11 | the first state | CAUGHT |
| P3 | a truncated answer always goes to TCP | `ignore_truncation` | the taken-as-is test | CAUGHT |
| P4 | the RD bit is always set | RFC 1035 §4.1.1, `recursion_desired` | the query flags | CAUGHT |
| P5 | a server's error always moves on | `check_response` | the policy table and the failure test | CAUGHT |
| P6 | `primary` asks every server | §19 step 11 | the count test | CAUGHT |
| P7 | a TCP port of its own is ignored | §19 step 11 | the endpoint tests | CAUGHT |
| P8 | the timeout cap is the constant | `timeout_ns_max` | the cap test | CAUGHT |
| P9 | no server is no failure | `NoServers` | the empty-list test | CAUGHT |
| P10 | `use-vc` is not an option | `resolv.conf(5)` | the option test | CAUGHT |
| P11 | the default server ignores the option | `NO_DFLT_SVR` | the none test | CAUGHT |
| P12 | `RES_OPTIONS` drops `use-vc` | §19 step 11 | the applier test | CAUGHT |
| P13 | `LOCALDOMAIN` keeps the old list | §19 step 11 | the applier test | CAUGHT |
| P14 | a comment is read as names | `hosts(5)` | the word-in-a-comment test | CAUGHT |
| P15 | an alias is not searched | `hosts(5)` | the alias test | CAUGHT |
| P16 | names compare case-sensitively | RFC 1035 §2.3.3 | the `DB` test | CAUGHT |
| P17 | the family filter is ignored | §19 step 11 | the IPv6-only find | CAUGHT |
| P18 | entries are unbounded | `hosts_entries_max` | the bound test, by the crash | CAUGHT |
| P19 | names on a line are unbounded | `hosts_names_per_entry_max` | the bound test, by the crash | CAUGHT |
| P20 | an address alone is an entry | `hosts(5)` | the entry count | CAUGHT |
| P21 | a reverse lookup matches any address | §19 step 11 | the other-address test | CAUGHT |
| P22 | check 3 expects the UDP port over TCP | §7 check 3 | the TCP-port test | CAUGHT |
| P23 | the server walk ignores `primary` | §19 step 11 | the primary test | CAUGHT |

## Step 12, server failover

Design §19 step 12: the failure count and instant per server, the order a lookup walks, and the
retry of a failed server with a real query. Broken against `zig build test-resolver`. Fifteen
mutations, fifteen `CAUGHT` — one after a test was extended for it.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| F1 | a timeout is not a failure | §19 step 12 | the next-lookup test | CAUGHT |
| F2 | a failed send is not a failure | §19 step 12 | the failed-send test | CAUGHT |
| F3 | a failed connection is not a failure | §19 step 12 | the failed-connect test | CAUGHT |
| F4 | an answer does not reset the count | §19 step 12 | the reset tests | CAUGHT |
| F5 | the servers are not sorted | §19 step 12 | the order test | CAUGHT |
| F6 | the sort is not stable | §19 step 12 | the order test | CAUGHT |
| F7 | rotation reaches past the fewest-failures group | §19 step 12 | the rotation test | CAUGHT |
| F8 | the retry ignores the delay | `failover_retry_delay_ns` | the promotion test | CAUGHT |
| F9 | the retry ignores the chance | `failover_retry_chance` | the chance tests | CAUGHT |
| F10 | the retry never happens | §19 step 12 | the promotion test | CAUGHT |
| F11 | failures do not count up | §19 step 12 | the counter test | CAUGHT |
| F12 | the instant is not recorded | §19 step 12 | the counter test | CAUGHT |
| F13 | the walk ignores the order | §19 step 12 | the order tests | CAUGHT |
| F14 | a failure names the walk position | `Failure.server_index` | the configured-server test | CAUGHT |
| F15 | the order is recomputed every poll | §19 step 12 | **the poll after the timeout** | CAUGHT |

F15 survived until the first failover test polled once more after its timeout: with the order
recomputed around the failure just recorded, the walk position that meant the second server
came to mean the first again, and the second server's answer was no longer the lookup's.

## Step 13, the twin and the engine's UDP path

Design §19 step 13, the first slice: the deterministic twin of rotor's loop in `src/sim/`, and
the engine over it in `io/`, with one UDP socket per server, a buffer group, one timer and the
cache in front. The twin is broken against `zig build test-sim`, the engine against
`zig build test-io`, which compiles the engine with the twin as its `rotor`. Eighteen mutations,
eighteen `CAUGHT`, four of them written the day their bugs were found.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| V1 | a tick never moves the clock | the virtual clock | the timer test | CAUGHT |
| V2 | cancel delivers nothing | rotor decision 5, rule 1 | the cancelled-receive test | CAUGHT |
| V3 | a datagram is delivered before it is due | the delay | the buffer-when-due test | CAUGHT |
| V4 | a stream chunk is not consumed | the stream framing | an assertion, under the chunked-stream test | CAUGHT |
| V5 | the server ignores its drop rate | the loss script | the down-server test | CAUGHT |
| V6 | a timer fires at once | the timer's instant | the timer test | CAUGHT |
| V7 | cancel treats an unfired timer as ended | rotor decision 5, rule 5 | **the cancelled-timer test** | CAUGHT |
| V8 | the cancelled timer's fire stays queued | rotor decision 5, rule 1 | the cancelled-timer test | CAUGHT |
| I1 | a result is reported twice | one result per lookup | the results ring's bound | CAUGHT |
| I2 | the cache is not asked | §18, in front of `start` | the cache-hit test | CAUGHT |
| I3 | the timer is never armed | §19 step 13, one timer | the down-server test | CAUGHT |
| I4 | a taken slot is never released | `take` frees the last | the first lookup test | CAUGHT |
| I5 | a datagram's source port is not handed on | §7 check 3 | the group-runs-dry test | CAUGHT |
| I6 | a failed send is not told to the table | §19 step 12 | the failed-send test | CAUGHT |
| I7 | an answer is not cached | §18, put at the end | the cache-hit test | CAUGHT |
| I8 | an ended receive is not armed again | the multishot's end | the group-runs-dry test | CAUGHT |
| I9 | a stale timer's end is taken for the current one | the timer's generation | **the moved-timer test** | CAUGHT |
| I10 | a fired timer keeps its recorded due | the timer's due | **the early-fire test** | CAUGHT |

V7 found a bug in the twin. Its `cancel` refused any operation with a final event queued, and a
timer's fire is queued the moment it is submitted, so the twin never cancelled a timer: the
engine's tests passed against a loop that fired every timer it was told to forget. rotor cancels
an unfired timer at once (decision 5, rule 5, and its own test says so), so the twin now counts
an operation as ended only when its final event is due, and withdraws a fire still ahead.

I9 was the bug V7 was hiding. When the deadline moves, the engine cancels the old timer and arms
a new one, and the old one's `Canceled` end arrives after that (rotor decision 5, rule 2). The
engine took it for the current timer's and dropped the new handle, so `deinit` could not cancel
the timer it had lost, and a drain waited for it to fire. The timer's `user_data` now carries a
generation, and an end from an earlier one is nothing. I10 is the companion: a fired timer clears
its recorded due, so a caller whose clock is a nanosecond behind the loop's gets the timer armed
again at the next drive instead of a deadline nobody is waiting for.

I1 and V4 are caught by an assertion rather than a test's own check. A second report of the
same lookup overfills the results ring, whose capacity is the table's, and the push asserts it
has room; a chunk delivered twice overfills the reader's frame, which the delivery asserts fits.

One defect of this slice had no check to mutate and no test to catch it, and the end-to-end
comparison of step 15 found it: `drive` polled the table up to 4096 times per call, and a lookup
that has ended and waits for `take` answers every poll with its end again, so every drive spun
through 4096 polls over it. That was 4 ms a lookup ReleaseSafe and 10 in Debug. A drive is now
one rotation over the engine's slots. Nothing observable on the twin changed, so no row was
added; the numbers of design §11 before and after are its proof.

## Step 14, the `getaddrinfo` shape

Design §19 step 14: `AddressLookup` above the table, after the address text parser and the hosts
table moved to `core`. Broken against `zig build test-resolver`. Twenty-four mutations,
twenty-four `CAUGHT`, one after a test was written for it.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| A1 | the families walk the search list on their own | the lockstep walk | the lockstep test | CAUGHT |
| A2 | a name that does not exist leaves the other family running | RFC 1035 §4.1.1 | the early-end test | CAUGHT |
| A3 | NODATA seen is forgotten at the end of the walk | §5's rule | the nothing-found test | CAUGHT |
| A4 | a hard failure on one family is dropped | §19 step 14 | the hard-failure test | CAUGHT |
| A5 | the half that failed is not reported | `partial` | the timed-out-half test | CAUGHT |
| A6 | the families come back in arrival order | `getaddrinfo(3)`'s order | the IPv6-first test | CAUGHT, then retired |
| A7 | `v4_mapped` maps for any family | `getaddrinfo(3)` | the IPv6-first test | CAUGHT |
| A8 | the mapped `A` comes back beside an `AAAA` without `all` | `getaddrinfo(3)` | the mapped test | CAUGHT |
| A9 | `all` is ignored | `getaddrinfo(3)` | the mapped test | CAUGHT |
| A10 | the candidate's own name is never the canonical one | `canonical_name` | the canonical test | CAUGHT |
| A11 | the chain's end is not taken as the canonical name | `canonical_name` | the canonical test | CAUGHT |
| A12 | the hosts table is never consulted | `Config.lookups` | the table-first test | CAUGHT |
| A13 | the table is consulted first whatever the order | `Config.lookups` | the DNS-first test | CAUGHT |
| A14 | the table answers in a family that was not asked | §19 step 14 | the family-lacking test | CAUGHT |
| A15 | the table's official name is not the canonical one | `canonical_name` | the table-first test | CAUGHT |
| A16 | a numeric host is queried anyway | `getaddrinfo(3)` | the numeric test | CAUGHT |
| A17 | `numeric_host` does not insist | `AI_NUMERICHOST` | the numeric test | CAUGHT |
| A18 | a numeric host of another family is answered anyway | §19 step 14 | the numeric test | CAUGHT |
| A19 | a pair short of a slot leaks the first | §19 step 14 | the slot-short test | CAUGHT |
| A20 | a lookup's slot is never released | two slots at most | the lockstep test | CAUGHT |
| A21 | a full table is not marked truncated | `truncated` | the full-table test | CAUGHT |
| A22 | `v4_mapped` does not widen the table's ask | §19 step 14 | the family-lacking test | CAUGHT |
| A23 | the join keeps the larger TTL | `ttl_seconds` | the IPv6-first test | CAUGHT |
| A24 | the consumer's cancel is not the outcome | `cancel` | **the cancel-after-answer test** | CAUGHT |

A24 survived the first run: with nothing answered, a cancelled pair ends `Canceled` through the
hard-failure path all the same, so the check that puts the consumer's cancel first only shows
once one family has answered. The test for that case was written, and the mutation fell.

A6 was retired the same day by step 15: the join now keeps the order received, so that
`no_sort` means what it says, and IPv6 comes first through rule 6 of the ordering, which L7 and
L18 below break.

The harness taught something too. The table harness of the resolver's fixtures built every reply
with a clean header, whatever rcode the test named, so an NXDOMAIN it sent arrived as NOERROR
with no records, which is NODATA; the first run of the early-end test failed for that. It now
writes the rcode the way the lookup harness does, and asserts the reply needs no OPT record.

## Step 15, the ordering

Design §19 step 15: RFC 6724 §6 as a pure function over routes the consumer supplies, and the
hook in `AddressLookup`. Broken against `zig build test-core` and `test-resolver`. Nineteen
mutations, nineteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| L1 | rule 1 ignores a destination known unreachable | RFC 6724 §6 rule 1 | the unusable test | CAUGHT |
| L2 | rule 1 ignores a missing source | RFC 6724 §6 rule 1 | the unusable test | CAUGHT |
| L3 | rule 2, matching scope, never decides | RFC 6724 §6 rule 2 | the RFC's examples | CAUGHT |
| L4 | rule 3, deprecated sources, never decides | RFC 6724 §6 rule 3 | the RFC's examples | CAUGHT |
| L5 | rule 4, home addresses, never decides | RFC 6724 §6 rule 4 | the RFC's examples | CAUGHT |
| L6 | rule 5, matching label, never decides | RFC 6724 §6 rule 5 | the RFC's examples | CAUGHT |
| L7 | rule 6, precedence, never decides | RFC 6724 §6 rule 6 | the RFC's examples | CAUGHT |
| L8 | rule 7, native transport, never decides | RFC 6724 §6 rule 7 | the encapsulation test | CAUGHT |
| L9 | rule 8, smaller scope, never decides | RFC 6724 §6 rule 8 | the RFC's examples | CAUGHT |
| L10 | rule 9, longest prefix, never decides | RFC 6724 §6 rule 9 | the RFC's examples | CAUGHT |
| L11 | the rules run out of order | RFC 6724 §6, "applied in order" | the RFC's examples | CAUGHT |
| L12 | the sort is not stable | RFC 6724 §6 rule 10 | the no-route test | CAUGHT |
| L13 | the policy table takes the first match | RFC 6724 §2.1, longest prefix | the RFC's examples | CAUGHT |
| L14 | an IPv4 address is looked up unmapped | RFC 6724 §3.2 | the RFC's examples | CAUGHT |
| L15 | IPv4 loopback and link-local are global | RFC 6724 §3.2 | the scopes test | CAUGHT |
| L16 | the common prefix is not capped | RFC 6724 §2.2 | the common-prefix test | CAUGHT |
| L17 | a multicast address's scope is not its own | RFC 4291 §2.7 | the scopes test | CAUGHT |
| L18 | the address lookup does not order its answer | §19 step 15 | the IPv6-first test | CAUGHT |
| L19 | `no_sort` is ignored | `ARES_AI_NOSORT` | the order-received test | CAUGHT |

The nine worked examples of RFC 6724 §10.2 are the gate the design asked for, and they carry
most of the table: each is run the wrong way round, so the sort has to move one address, and
both ways through `compare`, so a rule that decides the wrong way is seen twice.

## The ready list and the deadline bound

Design §11 and §16 decisions 20 and 21: the lookups with something to do kept on a list threaded
through the slots, and the soonest deadline kept as a bound. Broken against
`zig build test-resolver`. Eight mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| Y1 | the poll walks the table instead of taking from the list | §11 the ready list | the offered-once test | CAUGHT |
| Y2 | a slot is linked onto the list twice | §11 the ready list | **the offered-twice test** | CAUGHT |
| Y3 | a freed slot is left on the list | §4 release | the released-slot test | CAUGHT |
| Y4 | an event never offers the lookup it moved | §11 the ready list | the address-lookup walk | CAUGHT |
| Y5 | a wait that runs out offers nobody | §5 the retry | the wait-runs-out test | CAUGHT |
| Y6 | the deadline bound keeps the later instant | §11 the bound | the one-deadline test | CAUGHT |
| Y7 | an expiry offers every lookup that is waiting | §11 the bound | the bound test | CAUGHT |
| Y8 | a slot taken off the list keeps its flag | §11 the ready list | the churn test | CAUGHT |

Y2 needed a test of its own. Without the guard a slot is linked to itself, the list runs through
it for ever, and the caller is told the same thing twice; every other test acts on what it is
told the first time and never asks again, so none of them noticed.

## Step 13, the stream

Design §19 step 13's second slice: one connection per server, the queries of every lookup that
needs it pipelined onto it, the length-prefixed framing of RFC 7766 §8, and the idle close of
§6.2.3. Broken against `zig build test-io`, which runs the engine on the twin. Eleven mutations,
eleven `CAUGHT`, four of them only after the scenario was sharpened.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| X1 | a truncated answer never reaches the stream | RFC 7766 §5 | the truncated test | CAUGHT |
| X2 | the framing ignores the length prefix | RFC 7766 §8 | the truncated test | CAUGHT |
| X3 | every lookup opens a connection of its own | RFC 7766 §6.2.1.1 | **the shared-connection test** | CAUGHT |
| X4 | a refused connect leaves its lookups attached | §19 step 13 | the refused test | CAUGHT |
| X5 | an idle connection is never closed | RFC 7766 §6.2.3 | the idle test | CAUGHT |
| X6 | a connection in use is closed for being old | RFC 7766 §6.2.3 | **the busy-connection test** | CAUGHT |
| X7 | a chunk that does not fit is written anyway | the frame bound | **the small-buffer test** | CAUGHT |
| X8 | the receive is not armed again when the multishot ends | the stream receive | **the group-runs-dry test** | CAUGHT |
| X9 | a stream answer names the server's datagram port | §7 check 3 | the TCP-port test | CAUGHT |
| X10 | a connection tells every lookup, not only those on it | §19 step 13 | the moved-on test | CAUGHT |
| X11 | a group with no buffer left is taken for a broken connection | the stream receive | the group-runs-dry test | CAUGHT |

X8 and X11 are the two halves of one bug the tests found before a mutation did. A stream is cut
into chunks the reader does not choose, and the twin's are as small as one octet, so a group of
eight buffers runs dry inside a single answer. The engine took the `BuffersExhausted` that ends
the multishot for a broken connection and tore it down, and the lookup waited out its timeout.
The group running dry is now the ordinary end of a receive, and the receive is armed again.

Four mutations needed the scenario sharpened before they had anywhere to bite: a second server
that is down, so a lookup that opened a connection of its own has nothing to fail over to (X3);
an answer that takes longer than the idle time (X6); a connection whose message buffer is too
small for an ordinary answer, which the caller now sizes (X7); and a group of two buffers with
several lookups on it (X8). Each of those is a knob a caller has, so none of them is a fixture
the library would not otherwise carry.

## Step 13, the rest of the engine

Design §19 step 13: `cancel_all` and `reinit`, the port rotation of `Config.udp_queries_per_port`,
the local address of `Config.local_address`, and the three guards that ignore an event for
something that is gone. Broken against `zig build test-io`. Ten mutations, nine `CAUGHT` and one
`NOT CAUGHT` by design.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| Z1 | a port carries more queries than the caller allows | `udp_queries_per_port` | the rotation test | CAUGHT |
| Z2 | a port is taken from a query that is waiting | §19 step 13 | the rotation test | CAUGHT |
| Z3 | a count of zero rotates all the same | c-ares's default | the idle-connection test | CAUGHT |
| Z4 | the local address the caller named is ignored | `local_address` | the binding test | CAUGHT |
| Z5 | a local address of another family is bound anyway | `local_address` | **the wrong-family test** | CAUGHT |
| Z6 | `cancel_all` leaves the lookups running | `ares_cancel` | the cancel-all test | CAUGHT |
| Z7 | a send the engine is not waiting for is acted on | the stale-send guard | the reinit test | CAUGHT |
| Z8 | a receive from a socket that is gone is acted on | the receive's generation | the reinit and rotation tests | CAUGHT |
| Z9 | `reinit` keeps the answers the old servers gave | `ares_reinit` | the reinit test | CAUGHT |
| Z10 | `reinit` is taken with lookups still in flight | the idle assertion | nothing, by design | NOT CAUGHT |

Z10 stays uncaught on purpose, as T11 does. `reinit` asserts that nothing is in flight, because a
handle from the old table names a slot the new one has never heard of, and that is programmer
error rather than an operational failure (CLAUDE.md non-negotiable 3). A test that tripped it
would halt rather than fail.

Z5 needed the test to say what it expected rather than what it did not. The socket bound an
address of the wrong family happily, since the octets of an IPv6 address make a perfectly
well-formed IPv4 one; what says the rule held is that the socket is bound unspecified.

Z7 and Z8 are the guards that `reinit` and a replaced port need: the loop still holds events for
sockets and lookups that are gone, and each carries a generation or a flag that says so. They are
the same shape as the timer's generation of the first slice, and they were written because the
tests crashed without them, not after a mutation.

## Step 10, the other EDNS0 options

Design §19 step 10's rest: a typed reader for the name server identifier (RFC 5001), the client
subnet (RFC 7871), the padding (RFC 7830) and the extended errors (RFC 8914). None of them changes
what a lookup does; the state machine acts on the cookie alone. Broken against
`zig build test-wire`. Eight mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| G1 | a reader takes an option of another code | RFC 6891 §6.1.2 | the identifier and subnet tests | CAUGHT |
| G2 | padding may appear twice | RFC 7830 §3 | the twice test | CAUGHT |
| G3 | a client subnet of any family is read | RFC 7871 §6 | the wrong-shape test | CAUGHT |
| G4 | a prefix longer than the address is allowed | RFC 7871 §6 | the wrong-shape test | CAUGHT |
| G5 | the address octets are not counted | RFC 7871 §6 | the wrong-shape test | CAUGHT |
| G6 | a bit set past the prefix is allowed | RFC 7871 §6 | the wrong-shape test | CAUGHT |
| G7 | an extended error shorter than its code is read | RFC 8914 §2 | the extended error test | CAUGHT |
| G8 | the extended error's text starts at its code | RFC 8914 §2 | the extended error test | CAUGHT |

G4 needed a fixture that only it could refuse. The first one carried a prefix too long for the
family and too few octets for the prefix, so the length check caught it whatever the bound said;
the fixture now carries exactly the octets its prefix needs.

## Step 14, the reverse lookup

Design §19 step 14's `NameLookup`, which settles §17 question 12. Broken against
`zig build test-resolver`. Six mutations, six `CAUGHT`. H6 was `NOT CAUGHT` until the cleanup of
2026-09-23 wrote a test for it: no test had handed a `NameLookup` an end that was not its own.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| H1 | the hosts table is never consulted | `Config.lookups` | the table-first test | CAUGHT |
| H2 | the sources are tried in the order they are written | `Config.lookups` | the DNS-first test | CAUGHT |
| H3 | a failure ends the walk rather than trying the next source | §19 step 14 | the DNS-first test | CAUGHT |
| H4 | a cancel is answered by the next source | §19 step 14 | the cancel test | CAUGHT |
| H5 | the question is built for a name rather than an address | `Question.from_address` | the PTR question test | CAUGHT |
| H6 | an end for another lookup's handle is taken | an end reaches only its own lookup | **the other-lookup test** | CAUGHT |

One check went the other way and was removed. A lookup that is done carries a name, because a
response with no record of the type asked for is NODATA and the state machine fails it (§5), so
the branch that handled an answer with no names could not be reached. It is an assertion now,
which is what a claim about the code's own callers is (CLAUDE.md non-negotiable 3).

## Step 13, the socket buffers

Design §19 step 13's last knob: `Config.socket_receive_bytes` and `socket_send_bytes`, which rotor
0.2.0 made expressible. Broken against `zig build test-io`. Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| J1 | the receive buffer is never sized | `socket_receive_bytes` | the sizes test | CAUGHT |
| J2 | the send buffer is never sized | `socket_send_bytes` | the sizes test | CAUGHT |
| J3 | a size of zero is asked for anyway | the default, which leaves the kernel's | every test with no size | CAUGHT |
| J4 | a size the kernel refuses fails the socket | §19 step 13 | **the capped-or-refused test** | CAUGHT |

J4 needed the twin to refuse rather than cap. rotor measured both kernels: Linux doubles a request
and caps it, macOS grants it and then refuses once the socket is already large. The twin caps up to
one bound and refuses above a second, so a test can drive each, and the refusal is what says the
engine keeps a socket whose size it could not set.

## Step 16, the cache under the table

Design §20: the table asks a `Memory` the caller supplies, and `cocuyo.remembered_by` fills one
in from a `Cache`. Broken against `zig build test-resolver` and `zig build test-cocuyo`. Six
mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| L1 | ask the memory at every poll rather than once | §20, asked once and before the query | the first-poll test, polled twice | CAUGHT |
| L2 | write an end back at every poll that produces it | §20, written once | the written-once test | CAUGHT |
| L3 | write back a lookup the memory itself answered | §20, a recall is not a write | the first-poll test | CAUGHT |
| L4 | report the life the answer was given, not what is left | §20, a recalled answer reports the time it has | the first-poll test | CAUGHT |
| L5 | remember any failure | RFC 2308 §5, two negatives and nothing else | the mapping test and the cancel test | CAUGHT |
| L6 | hand back the life the cache was given | §20, `Hit.ttl_seconds` is what is left | the glue's round-trip test | CAUGHT |

L1 was `NOT CAUGHT` at first. Every test polled a hit once, and the stub the written-once test
used held nothing, so a second ask found nothing to trip over. The test now offers the lookup
again and polls it twice with the memory holding an answer, which is the shape a caller that has
not yet read its answer produces.

## The chain's end in the cache

Design §17 question 13, answered yes: a slot keeps the end of the CNAME chain that reached its
answers, and `Remembered` carries it both ways. Broken against `zig build test-cache`,
`zig build test-resolver` and `zig build test-cocuyo`. Seven mutations, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| U1 | the cache never keeps the chain's end | §18, a hit is what was put | the chain's-end hit test | CAUGHT |
| U2 | a hit never reports the chain's end | §18, a hit is what was put | the chain's-end hit test | CAUGHT |
| U3 | a put in place keeps the old chain's end | §18, a put in place replaces the whole entry | the put-in-place chain's-end test | CAUGHT |
| U4 | the table writes no chain's end | §20, what is written is what the lookup reached | the written-with-the-chain's-end test | CAUGHT |
| U5 | a recalled lookup drops the chain's end | §20, a recall answers as a lookup that went out | the recalled chain's-end test | CAUGHT |
| U6 | the glue drops the chain's end on the way back | §20, `remembered_by` hands back what it holds | the glue's chain's-end test | CAUGHT |
| U7 | the glue drops the chain's end on the way in | §20, `remembered_by` keeps what it is given | the glue's chain's-end test | CAUGHT |

U3 is the one a test written for U1 alone would miss. The mutant drops the call from the path
that replaces an entry in place, so the entry keeps the chain's end its first put gave it. The
test puts one question three times — through one chain, through another, then through none — and
reads the hit after each of the last two.

## SIEVE against S3-FIFO, W-TinyLFU, expected hits, c-ares's rule and the optimal

Design §18: `bench/cache_policy/` models SIEVE, the control, with an expiry index it can take
expired entries first by, and S3-FIFO, W-TinyLFU, expected hits and c-ares's rule beside it;
`bench/cache_trace.zig` replays the optimal. Broken against `zig build test-tools`. Thirty-seven
mutations, thirty-seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| F1 | under the old rule, a get keeps an expired entry it should evict | the old rule, as it was | **a test written for it** | CAUGHT |
| F2 | the hand stays on an entry that is gone | the model answers as the cache does | the control test | CAUGHT |
| F3 | a renewal in place renews nothing | the entry lives again | the control test | CAUGHT |
| F4 | S3-FIFO promotes at the threshold, not above it | Algorithm 1 line 23 | the threshold test | CAUGHT |
| F5 | a name moved to M keeps its bits | S3-FIFO §4.1, bits cleared on the move | the threshold test | CAUGHT |
| F6 | an expired name in S is ghosted | expiry is taken on sight, and leaves no ghost | the expired-on-sight test | CAUGHT |
| F7 | the frequency is not capped | Algorithm 1 line 3 | the cap test | CAUGHT |
| F8 | G holds one ghost fewer | S3-FIFO §4.1, G as long as M | the ghost-length test | CAUGHT |
| F9 | a ghost asked for again goes to S | Algorithm 1 lines 10 and 11 | the ghost-return test | CAUGHT |
| F10 | S3-FIFO's renewal counts no use | a renewal is a use, in every model | the S3-FIFO renewal test | CAUGHT |
| F11 | SIEVE's hand passes a visited entry that has expired | §18, expiry on sight | the control test | CAUGHT |
| F12 | SIEVE's renewal leaves the bit | the cache's put in place sets it | the control test | CAUGHT |
| F13 | c-ares's fetch drains nothing | every fetch drains what has expired | the drain test | CAUGHT |
| F14 | the heap puts a later key above an earlier one | the skip list's expiry order | the optimal's newcomer test | CAUGHT |
| F15 | the peak is not counted | what c-ares's rule holds is reported | the hit-inside-its-TTL test | CAUGHT |
| B1 | a request after expiry counts as useful | a dead name is worth nothing | the worth test | CAUGHT |
| B2 | the optimal admits every newcomer | the bound covers admission | the optimal's newcomer test | CAUGHT |
| B3 | the optimal keeps the name needed latest | Belady's rule | the worth test | CAUGHT |
| B4 | expired first takes the soonest entry though it is live | only an expired entry skips the hand | the live-soonest test | CAUGHT |
| B5 | a key moved earlier is not sifted up | the heap's order | the heap test | CAUGHT |
| B6 | a renewal leaves the expiry order stale | expired first follows a renewal | the renewal test | CAUGHT |
| W1 | a tie goes to the newcomer | the victim keeps a tie (§3.1) | the turned-away test | CAUGHT |
| W2 | the counters never halve | the reset (§3.3) | the halving test | CAUGHT |
| W3 | the halving zeroes the record count | the count is divided too (§3.3) | the halving test | CAUGHT |
| W4 | the counters have no cap | W / C (§3.4.1) | the halving test | CAUGHT |
| W5 | a hit in probation does not promote | segmented LRU (§2.1) | the promotion test | CAUGHT |
| W6 | protected overflows without demoting | segmented LRU (§2.1) | the promotion test | CAUGHT |
| W7 | an expired victim is not special | an expired name loses the contest | the expired-victim test | CAUGHT |
| W8 | an expired newcomer is not dropped | an expired name loses the contest | the expired-newcomer test | CAUGHT |
| W9 | a hit is not recorded | every arrival is counted (§3.4.2) | the takes-its-place test | CAUGHT |
| H1 | worth ignores the time left | worth is count times time left | the expired-entry test | CAUGHT |
| H2 | reuse counts every ask | a name asked once is worth nothing | the reuse test | CAUGHT |
| H3 | an admission tie goes to the newcomer | the entry held keeps a tie | the admission test | CAUGHT |
| H4 | the least is the first entry read | the eviction takes the least worth | the asked-often test | CAUGHT |
| H5 | a renewal renews nothing | renewed where it stands | the expired-entry test | CAUGHT |
| H6 | a drawn eviction reads everything | only the drawn entries are read | the drawn-eviction test | CAUGHT |
| H7 | admission is never asked | a newcomer worth no more is turned away | the admission test | CAUGHT |

F11 was `NOT CAUGHT` when the models first landed. The control test then ran the old rule, and a
hand that clears an expired entry's bit and takes it on the next pass changed too little over a
short trace to show. A test was written that states the rule, as the cache's own
`cache_sweep.zig` test does, and it stays.

F1 went the other way. The control test caught it while it ran the old rule. Once §17 question 14
moved the control to the new rule, nothing ran the old rule's get on a table with room to spare,
and a full table hides the mutant: the hand evicts the expired entry the get should have removed.
It was `NOT CAUGHT` until a test with a free slot was written for it. Moving a test's subject
can lose a catch as quietly as deleting the test would.

F2, F11, B1 and H4 also failed to compile on their first try, because each left a name unused. A
mutant the compiler refuses has tested nothing, so each is run with the name discarded. H3's
tie had no test when the model was written; one was added before the mutation ran. B2's
first form did not put the newcomer in at all, which is a different bug; it is run as the
optimal that makes room before it admits, which is the one it names.

## The real log

Design §18: `bench/log_csv.zig` reads the Mendeley c4n7fckkz3 DNS log, and `bench/log_replay.zig`
replays it through the cache, the models and the optimal, over `bench/trace_recording.zig`.
Broken against `zig build test-tools`. Fourteen mutations, fourteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| L1 | attack rows are kept | injected traffic is not a workload | the log test | CAUGHT |
| L2 | names keep their case | RFC 1035 §2.3.3, as clarified by RFC 4343 | the log test | CAUGHT |
| L3 | a trailing dot is kept | one name, one index | the row test | CAUGHT |
| L4 | time may go backward | a replay's clock never decreases | the backward test | CAUGHT |
| L5 | an unknown flag reads as benign | a row is refused unless it says | the refused-row test | CAUGHT |
| L6 | by rank puts the least asked first | the most asked takes the shortest TTL | the TTL rule test | CAUGHT |
| L7 | a client's names keep their global index | a client's names are renumbered | the client test | CAUGHT |
| L8 | the link walks forward | each question links to the next | the bound test | CAUGHT |
| L9 | the busiest clients are the least busy | the busiest are replayed | the client test | CAUGHT |
| L10 | the hash rule ignores the hash | TTL unrelated to popularity | the TTL rule test | CAUGHT |
| L11 | a name is refused past 254 characters | RFC 1035 §5.1, `\DDD` is four for one | **a test written for it** | CAUGHT |
| L12 | exactly nine in ten is not a loop | the loop rule's share | the loop test | CAUGHT |
| L13 | the loop rule ignores its minimum | a loop asks often | the loop test | CAUGHT |
| L14 | a looping client's questions are kept | a loop is not a workload | the loop test | CAUGHT |

L12 to L14 check the rule that sets aside a client stuck in a loop: the log's busiest client asks
`samba.local.local` 6.78 million times in a day, and every policy hits it. L14 failed to compile on
its first try, and was run with the name discarded.

L11 is the one the log itself found. The first replay stopped on 53 rows whose names write each
octet of a tunnelling payload as `\DDD`: over 254 characters in text and within 255 octets on
the wire. The limit was on the text, where it should have been on what the text stands for.

## A cancel after the end

`Resolver.cancel` leaves a lookup that has already ended alone, so its answer or failure stands
and is offered once. Before, a cancel that reached an ended lookup tripped `Lookup.cancel`'s
assertion: an `AddressLookup` or `NameLookup` cancelled between an answer's arrival and its
routing, and an engine's `deinit` with an answer not yet taken, each stopped the program.
Found by the altitude review of `/simplify` on 2026-09-23. Broken against `zig build
test-resolver`. Three mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| C1 | a cancel reaches a lookup that has ended | an ended lookup keeps its end | the table, address and name cancel tests | CAUGHT |
| C2 | `NameLookup.cancel` does not mark the walk | a cancel's outcome is `Canceled` | the name cancel test | CAUGHT |
| C3 | an answer that comes after a cancel is taken | a cancel's outcome is `Canceled` | the name cancel test | CAUGHT |

## A cache hit over TCP, and a lookup that ended first

The table asks the memory only about a lookup that has not ended, and a recall accepts both of
the states a lookup stands in before its first query: ready to build it, or waiting for its
connection when every query goes over TCP. Before, a cache hit with `use_tcp`, and a hit for a
lookup cancelled before its first poll, each tripped the recall's assertion; the engine always
installs a cache, so with `use_tcp` its first remembered answer stopped the program. Found by
the altitude review of `/simplify` on 2026-09-23. Broken against `zig build test-resolver`. Two
mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| M1 | a lookup that has ended is asked about | an ended lookup has its end | the ended-first test | CAUGHT |
| M2 | only a lookup ready to build its query may be recalled | a TCP lookup starts waiting for its connection | the TCP recall test | CAUGHT |

## The Lean model and the replay

`zig build spec` checks `Lookup` against the model in spec/ (docs/design.md §5, The model), and
`zig build test` replays the committed slice of it. The code mutations S1 to S9 were run against
`zig build test-resolver`, `zig build test-tools` and `zig build spec`, and each is caught by
the gate and by `zig build spec`. The slice holds one server, so it misses what only a second
server or a second name can show: S4 to S7 are caught in the gate by unit tests, and S5 to S7
needed theirs written. S3 is caught in the gate by the slice alone. S1 and S6 are the two
defects the replay found, put back. The model and proof mutations M1, M2 and P1 are caught by
`zig build spec`. Thirteen mutations, thirteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| S1 | a chain past `cname_hops_max` is ignored | a chain past the bound fails `ChainTooLong` | the slice, at line 83; the loop and the across-messages tests | CAUGHT |
| S2 | TC=1 over TCP is ignored | TC=1 means nothing on a stream | the slice; the TC-over-TCP test | CAUGHT |
| S3 | a connection attempt never expires | the deadline covers `connecting_tcp` | the slice, at line 111 | CAUGHT |
| S4 | the next server keeps the cookie retry | one BADCOOKIE retry per server | the BADCOOKIE test; the full replay | CAUGHT |
| S5 | the next name keeps the pass | the next name starts at the first pass | the next-candidate test; the full replay | CAUGHT |
| S6 | EDNS0 stays off at the next server | EDNS0 off for one server | the FORMERR failover test; the full replay | CAUGHT |
| S7 | EDNS0 stays off at the next name | EDNS0 off for one server | the next-candidate test; the full replay | CAUGHT |
| S8 | FORMERR without EDNS0 is taken as BADCOOKIE | FORMERR without EDNS0 is a server failure | the slice, at line 107; the FORMERR test | CAUGHT |
| S9 | a second BADCOOKIE is retried again | the second goes to TCP | the slice, at line 205; the BADCOOKIE test | CAUGHT |
| M1 | the model keeps EDNS0 off at the next server | the model is the design | the full replay, at line 270,627 | CAUGHT |
| M2 | the model ignores TC=1 over a stream | the model is the design | the proofs, which no longer type-check | CAUGHT |
| P1 | `sent_lt` proved by `sorry` | every theorem rests on the standard axioms | `Spec/Axioms.lean`'s pin | CAUGHT |
| G1 | the committed slice edited by hand | the slice is the model's | the slice's replay; the check in `zig build spec` | CAUGHT |

## The engine model and its replay

The engine's streams against the model of their rules (docs/design.md §19 step 13, Checked on
2026-09-23). Each fix was broken on purpose and run against `zig build test-io`, the engine's own
tests on the twin, `zig build test-tools`, which replays the committed walks, and `zig build
spec`, which replays 1.6 million events. The committed walks catch all eight, which the engine's
own tests alone did not: E1, E2, E4, E6, E7 and E8 were `NOT CAUGHT` by `zig build test-io`. E8
needed a check the state line does not make, that every buffer an event hands the engine is back
in its group when the event is over. E7 is in the table, and the test it came with catches it as
well. R1 was found by review, not by the model. Nine mutations, nine `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| E1 | an event for an opening that is gone is applied | rule 2, the incarnation | the committed walks, by an assertion; the full walks | CAUGHT |
| E2 | a lookup stays on a connection it no longer streams to | rule 3 | the committed walks, at line 5; the full walks | CAUGHT |
| E3 | a new lookup forgets its slot's buffer is lent | rule 6 | the committed walks; the twin tests | CAUGHT |
| E4 | a send's completion speaks to whatever holds the slot | rule 7 | the committed walks, by an assertion; the full walks | CAUGHT |
| E5 | a held send is dropped | rule 6 | the committed walks; the twin tests | CAUGHT |
| E6 | the drive stops after one poll a slot | rule 8 | the committed walks; the full walks | CAUGHT |
| E7 | the table misses the deadline of a wait a poll starts | §11, the bound | the connect-deadline test of `table_ready.zig`; the committed walks | CAUGHT |
| E8 | a stale event keeps its buffer | rule 2, the buffer | the committed walks' buffer check | CAUGHT |
| R1 | `reinit` builds a cache it never puts under the table | §20, the cache under the table | the twin's cache tests | CAUGHT |

## The engine walk's counting

Issue #8, 2026-09-24. The Lean walker of the engine model counted a state and its loop operations
sorted as one state, which is sound only while the model reads `ops` as a multiset. `cocuyo-spec
check` walked three small graphs whole, one for each transport, and asked every state whether it
and its sort agreed. Broken in `spec/lean/Spec/EngineStep.lean` by giving the model an
order-dependent rule. Two mutations, two `CAUGHT`. The walker and its check retired the same day,
with the Lean engine model: the TLA+ model holds its operations as a bag, so the claim is its own.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CN1 | only the first operation in the list may end | the model reads `ops` as a multiset | the canon check, TCP, after one event | CAUGHT |
| CN2 | an ending takes the first operation of its kind, not the one the event names | the model reads `ops` as a multiset | the canon check, TCP, after one event | CAUGHT |

## The engine's datagrams

The datagram's rules against the same model (docs/design.md §19 step 13). Broken against
`zig build test-io`, `zig build test-tools` and `zig build spec`. The committed walks caught U1,
U2, U4, U6 and U7. U3 was `NOT CAUGHT` by them, since no committed walk refuses a port's
replacement and then sends to its server; the full walks caught it, and the twin test written
for it catches it in the gate. A mutation that stopped clearing a receive's armed flag at its
end was caught by nothing, because the arming sets the flag either way, so the line was removed
rather than kept. Six mutations, six `CAUGHT`. U3 and U4 checked the missing-socket path of the
first rule 4, which the draining rotation below removed: a server always has a socket now, and
W4 checks what took its place.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| U1 | a receive a replaced socket left behind keeps its datagram's buffer | rules 2 and 3 | the committed walks' buffer check; the full walks | CAUGHT |
| U2 | a socket's receive the loop refused is never asked for again | rule 1 | the committed walks; the full walks | CAUGHT |
| U3 | a send goes to a server whose socket could not be opened | rule 4 | the missing-socket twin test; the full walks, by an assertion | CAUGHT |
| U4 | a server whose socket could not be opened is never given one | rule 4 | the missing-socket twin test; the committed walks | CAUGHT |
| U6 | a connection's receive the loop refused is never asked for again | rule 1 | the committed walks; the full walks | CAUGHT |
| U7 | a port is replaced under a lookup waiting on it | rule 4 | the rotation twin test; the committed walks | CAUGHT |

## A port replaced under load

The datagram's rule 4 as §17 question 15's answer made it (docs/design.md §19 step 13): a port
that has carried its share is replaced at once and the old socket drains. Broken against `zig
build test-io`, `zig build test-tools` and `zig build spec`. The committed walks and the full
walks caught all seven; the twin tests caught five, and W5 and W6 only through the walks. Seven
mutations, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| W1 | a port that has carried its share is never replaced | rule 4, the replacement | the rotation twin test; the committed walks | CAUGHT |
| W2 | a replaced socket is closed at once, and its answers are lost | rule 4, the drain | the rotation twin test; the committed walks | CAUGHT |
| W3 | a draining socket is never closed | rule 4, the close | the rotation twin test; the committed walks | CAUGHT |
| W4 | a replacement that cannot open leaves the server no socket | rule 4, the order | the stays-in-use twin test, by an assertion | CAUGHT |
| W5 | a draining socket's refused receive is never asked for again | rule 5 | the committed walks | CAUGHT |
| W6 | a draining socket's ended receive is armed on the current one | rule 5 | the committed walks | CAUGHT |
| W7 | a query does not record the socket it left from | rule 4, what is owed | the rotation twin test; the committed walks | CAUGHT |

## chapulin's session

Design §21 steps 5 and 6: `io/io_chapulin.zig`, chapulin's record transport behind the session interface.
Broken against `zig build test-chapulin`, which starts sessions without a network, and
`tools/dot_live/run.sh`, which resolves through the three public resolvers and must be refused
twice. Neither runs in the gate: both need a chapulin checkout, and the live check needs the
network. CH5 was `NOT CAUGHT` by either, because the engine hands chapulin one whole record at a
time and chapulin takes it whole: a record taken in part is a programmer's error, so the check is
now an assertion. Eight mutations, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CH1 | the hostname keeps the root label's dot | the name chapulin checks | the live check | CAUGHT |
| CH2 | a handshake step leaves chapulin's flight uncollected | §21, the session collects at once | the live check | CAUGHT |
| CH3 | chapulin draws randomness with no stream behind it | §21, the seeded stream | the start test, by a panic; the live check | CAUGHT |
| CH4 | the pins never reach chapulin | RFC 8310 §6.3, SPKI + IP | the start test | CAUGHT |
| CH5 | a record chapulin took in part is taken for whole | the whole-record rule | nothing: **a programmer's error, now an assertion** | NOT CAUGHT |
| CH6 | "no record yet" is taken for a failure | chapulin's `CH_RECORD_AGAIN` | the live check | CAUGHT |
| CH7 | the anchors never reach chapulin | RFC 8310 §8.1, the chain | the live check | CAUGHT |
| CH8 | chapulin is given no clock | RFC 8310 §8.1, the dates | the live check | CAUGHT |

## Resumption, live

Design §21 step 6, 2026-09-24: `tools/dot_live/run.sh` resolves two names through each resolver,
the second over a connection that spends the first one's ticket, and requires one resolver at
least to resume. Broken against the live check. DL2 is ET4 again, and the live check cannot see
what it breaks: the lookup's retry opens a new connection, which handshakes in full because the
ticket is spent, so the second name still resolves. What ET4 breaks is that the decline counts
no failure against the server, which the ticket twin test and the picked walk 8573 see. With
chapulin at `20df0b8` all three resolvers resume, and the example reads whether a handshake
resumed from chapulin's `psk_selected`, which DL3 breaks. Three mutations, two `CAUGHT` by the
live check and the third by the gate.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DL1 | a ticket is never kept | TLS rule 8 | the live check: no resolver resumed | CAUGHT |
| DL2 | a resumed handshake that fails fails the connection | TLS rule 8, forgiven | not the live check; the ticket twin test and walk 8573, as ET4 | CAUGHT |
| DL3 | the session never says it resumed | the resumed handshake, read from chapulin | the live check: no resolver resumed | CAUGHT |

## Google's two roots, live

2026-10-01. The DoT live check failed two runs in nine and the DoH live check one in seven, each
time through Google alone, with every lookup ending in `AllServersFailed`. Google holds
certificates for `dns.google` from two issuers: WR2, under GTS Root R1, and WE2, which Google's
repository serves under GlobalSign ECC Root CA - R4. Certificate Transparency held 21 of each, and
which chain a connection is shown depends on the frontend it reaches. Both checks trusted GTS Root
R1 alone, so strict mode refused a WE2 frontend, as it must. Both now trust the two roots, and
report the chain a server shows beside any failure. Every frontend reached from here shows WR2,
so GR2 is the mutation this machine can see, and GR1 is the one CI saw.

2026-10-11, a correction to the paragraph above. WE2 is issued by GTS Root R4. GlobalSign ECC
Root CA - R4 issued neither chain, so the change of 2026-10-01 left a WE2 frontend refused: CI's
DoT check in 1 scheduled run of 11 since then and its DoH check in 4 of 11. Each of those five
logs prints the WE2 chain under GTS Root R4 beside the failure. The three failed runs before
2026-10-01 print no chain, because the checks printed none until that day. That those three met
a WE2 frontend is inferred from the five later logs: no log shows it. Both checks now hand in
GTS Root R1 and GTS Root R4 (design §21 step 6).

The change is to the two scripts and to no check of the Zig code, so the table gains no row.
Its two rows now name the roots the checks hand in, and what was seen:

- GR1 credited the three runs before 2026-10-01. It now credits the five later ones. Each
  handed in GTS Root R1 and GlobalSign ECC Root CA - R4. No certificate of the WE2 chain names
  that second root as its issuer, so for that chain each run was a run with GTS Root R1 alone.
  chapulin's walk over a WE2 chain captured from a Google frontend agrees: it ends in
  `unknown_ca` with those two roots, and with GTS Root R1 alone. A copy of each script with GTS
  Root R1 alone passed here, where every frontend that answers DNS shows WR2.
- GR2 named GlobalSign ECC Root CA - R4 alone, a root the checks no longer hand in. It now
  names GTS Root R4 alone. A copy of each script with that one change, run here, failed both of
  its lookups through Google with `AllServersFailed`, printed the WR2 chain beside the first,
  and exited 2.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| GR1 | Google is trusted with GTS Root R1 alone | a WE2 frontend is answered | CI's DoH runs of 2026-10-04, 10-06, 10-08 and 10-10 and DoT run of 10-05, each refused with the WE2 chain printed | CAUGHT |
| GR2 | Google is trusted with GTS Root R4 alone | a WR2 frontend is answered | a copy of each live check here, which fails through Google with the WR2 chain printed | CAUGHT |

## chapulin's staging bound

Design §21, 2026-09-24. chapulin's `CH_TX_STAGE` for a webpki build grew to 2,394 octets, plus 2
for a second cipher suite, once its resumed hello offered signature schemes. cocuyo staged at
most a number of its own, 2,048, below it. By the owner's ruling the session now stages exactly
`CH_TX_STAGE`, read from chapulin's header, so it follows every change to chapulin's hello, and a
connection's records buffer is held at compile time to fit it beside a query sealed at its
longest. CK1 broke the number cocuyo kept, which is gone, and is retired. Broken against `zig
build test-chapulin`. One mutation, one `CAUGHT`, by the build.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CK2 | `tls_records_out_bytes` down to 2,700, below 2,807 | the staging beside a sealed query | the build with `-Dchapulin` | CAUGHT |

## chapulin's build record

Design §21, 2026-09-24. cocuyo reads chapulin's headers with the defines `io/io_chapulin.zig`
writes, and links an object built by the command `build/dot.zig` gives. Nothing checked that the
two agree. Since chapulin `b29ab76` the object exports `ch_build`, its build record, and every
session compares it with the headers' view when it starts. It was first made in the session's
context, which a context written as a literal would skip; the review of the same day moved it. Broken against `zig build
test-chapulin`. CB3 removes the comparison, and no test can catch it: every object a test here
links is the one the headers describe, so none can show a session refusing another. Three
mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CB1 | the import defines `CH_EXPORTER`, which the object was not built with | the object matches the headers | the build-record test; the session test, stopped at its start | CAUGHT |
| CB2 | any build record is taken for a match | a record that differs is refused | the build-record test | CAUGHT |
| CB3 | a session never compares the record | the comparison is made | nothing: **the object linked always matches** | NOT CAUGHT |

Since chapulin `0c201b7` each object names its build record after its transport, so one image can
link the record object beside the QUIC object: the record object's is `ch_build_record`, which
`io/io_chapulin.zig` names, since translate-c cannot read the macro that maps `ch_build` to it.
CB1 and CB2 were broken again against it on 2026-09-25, and both are still `CAUGHT`. chapulin
`ca80351` renamed the transports the same day, for what TLS runs over and who does the I/O, and
the record is `ch_build_info_tcp_nonblocking` since. CB1 and CB2 were broken again against it,
and both are still `CAUGHT`.

## chapulin's randomness during a handshake

Design §21, 2026-09-25. chapulin draws randomness when a handshake starts, and once it speaks
P-256, when a HelloRetryRequest asks for that group. So the session points `ch_rand_bytes` at the
engine's stream for every call of the handshake, where it once did for the start alone. Broken
against `zig build test-chapulin` and the live check. RS1 is `NOT CAUGHT`: chapulin draws nowhere
but the start yet, so no test can tell. Issue #13 is the test to write when cocuyo pins a chapulin
with the P-256 retry draw. One mutation, `NOT CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RS1 | the stream is unset during the handshake's records | chapulin may draw during any call of the handshake | nothing yet: **chapulin draws only at the start, issue #13** | NOT CAUGHT |

## The engine over TLS

Design §21 step 5, the engine's side of it: the TLS rules in `io/`, driven with the twin's
session. Broken against `zig build test-io`, `zig build test-tools`, and `zig build spec` for any
the first two missed. The twin tests caught nine and the committed walks nine; ET8, ET10, ET11
and ET14 were `NOT CAUGHT` by either, and caught by the full walks only. ET14 needed the model to
send a record to a closing connection first, which it never did. The committed gate now keeps
the full run's walks that caught those four (`engineGatePicks`), and catches them. Fourteen
mutations, fourteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| ET1 | lookups hear the connection is up at the connect, before the handshake | TLS rule 1 | the refused-handshake twin test; the committed walks | CAUGHT |
| ET2 | the session's records go to the back of the queue | TLS rule 2 | the committed walks | CAUGHT |
| ET3 | records made behind a waiting records entry take an entry of their own | TLS rule 2, two entries | the committed walks | CAUGHT |
| ET4 | a declined ticket fails the connection | TLS rule 8 | the ticket twin test | CAUGHT |
| ET5 | a spent ticket stays kept | TLS rule 8, used once | the ticket twin test; the seven-day test | CAUGHT |
| ET6 | an idle TLS connection closes without `close_notify` | TLS rule 5, RFC 9846 §6.1 | the `close_notify` twin test; the committed walks | CAUGHT |
| ET7 | a TLS configuration opens UDP sockets | TLS rule 9 | the first TLS twin test; the committed walks | CAUGHT |
| ET8 | a TLS connection is closed to make room | TLS rule 6 | the picked walk 392 | CAUGHT |
| ET9 | a records send's end leaves its slot borrowed | TLS rule 3 | the twin tests; the committed walks, by an assertion | CAUGHT |
| ET10 | a reopening connection takes its old opening's events for its own | TLS rule 8 | the picked walk 120, by an assertion | CAUGHT |
| ET11 | a reopening connection connects while its old records are in flight | TLS rules 3 and 8 | the picked walk 120, by an assertion | CAUGHT |
| ET12 | a record longer than 2^14 + 256 octets is waited for | RFC 9846 §5.2 | the record-length test | CAUGHT |
| ET13 | a ticket older than seven days is spent | RFC 9846 §4.7.1 | the seven-day test | CAUGHT |
| ET14 | a closing connection reads what the peer sends | TLS rule 5 | the picked walk 329, by an assertion | CAUGHT |

## The TLS rules in the engine model

Design §21's engine rules, held by the model before any engine code speaks TLS. The code has
nothing to break yet, so these mutations break the model, and the invariants must catch them:
each run is `cocuyo-spec engine-probe tls 2 2 1 2000 200`. TM3 was `NOT CAUGHT` at first. No
invariant said the client's last flight goes before the first query, so the `answered`
invariant was written for it, and it catches TM3. Rule 8, resumption, came the same day with
three invariants of its own, and R8a to R8d break it; each was probed over seeds 1, 7 and 42.
Seven mutations, seven `CAUGHT`. The engine's own mutations come with its code, in step 5.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TM1 | the session's records go to the back of the queue, behind queries not yet sealed | TLS rule 2, records in sealed order | `sealed in order`, at depth 194 | CAUGHT |
| TM2 | a slot is opened again while a send of its records is in flight | TLS rule 3 | `borrow kept`, at depth 50 | CAUGHT |
| TM3 | the handshake's end tells the lookups without sealing the client's last flight | TLS rules 1 and 2 | `answered`, at depth 33 | CAUGHT |
| R8a | a declined ticket fails the connection | TLS rule 8 | `decline forgiven`, at depth 154 | CAUGHT |
| R8b | a connection that resumes leaves its server's ticket kept | TLS rule 8, used once | `ticket spent`, at depth 153 | CAUGHT |
| R8c | the connection opened again resumes again | TLS rule 8, in full | `reopened in full`, at depth 154 | CAUGHT |
| R8d | the connection opened again takes its slot while the loop still holds its records | TLS rules 3 and 8 | `borrow kept`, at depth 154 | CAUGHT |

## The engine model in TLA+

Issue #9, 2026-09-24. The TLS rules the Lean model's mutations broke (TM1 to TM3, R8a to R8d
above), broken again in `spec/tla/engine/EngineMutants.tla`, each put in its rule's place by a
configuration in `spec/tla/engine/mutants/`. TLC walks breadth first, so each counterexample is a
shortest one, where the Lean probes found them 33 to 194 events deep. Two mutants first called
the rule they replace, and so themselves; each is whole now. Eight mutations, eight `CAUGHT`,
TQ1 once its check was written.

| # | Mutation | Caught by | Counterexample | Status |
| --- | --- | --- | --- | --- |
| TM1 | the session's records go behind queries not yet sealed | `sealed in order` | 6 states | CAUGHT |
| TM2 | a slot is opened again while a send of its records is in flight | `borrow kept` | 4 states | CAUGHT |
| TM3 | the handshake's end tells the lookups without sealing the last flight | `answered` | 4 states | CAUGHT |
| R8a | a declined ticket fails the connection | `decline forgiven` | 13 states | CAUGHT |
| R8b | a connection that resumes leaves its server's ticket kept | `ticket spent` | 10 states | CAUGHT |
| R8c | the connection opened again resumes again | `reopened in full` | 14 states | CAUGHT |
| R8d | the connection opened again takes its slot while its records are held | `borrow kept` | 13 states | CAUGHT |
| TQ1 | a lookup that leaves keeps its waiting query queued | `queued for its lookup`, with two lookups | 5 states | CAUGHT |

TQ1 came with the configurations of two lookups, the same day. It is the stream's rule 9 as the
code's SQ6 broke it. It was `NOT CAUGHT` at first: over TCP with two lookups it changed the states
TLC reached, 1,199,595 against 758,374, and broke no check, because the model removed a waiting
query without any check saying it must. The check `queued for its lookup` was written for it, and
catches it. With one lookup TQ1 is equivalent, since no query ever waits on a plain stream.

## The engine replay on TLC's walks

Issue #9's stage 4, 2026-09-24: the engine replay follows walks TLC takes through the TLA+ model
(spec/README.md) instead of the Lean walker's. Every engine mutation of the sections above was
broken again against `zig build spec-engine -Dengine-walks=<file>` over three sets of walks. The
first is the committed short walks, ten of forty events in each configuration. The second is the
seven committed picked walks. The third is TLC's full run, 2,000 walks of 200 events in each
configuration, 3.2 million events.

TLC's walks are uniformly random. The Lean walker's took, at each step, an event leading to a
state no walk had reached when there was one. So the short walks miss nine mutations that the full
run catches. For each of the nine, the committed picked walks keep the first walk of the full run
that catches it, and the picked walks catch all nine; ET4, ET10 and ET11 share walk 8573. A walk
is numbered by its place in the full run, from 1 in the configurations' order.

The full run catches ET4, ET5 and W4, which only the twin tests caught before. It misses SQ4,
which the Lean committed walks caught. The model gives a message one short send at most, and
`advance` ends a message on the octets its send had left, so counting from the last send alone
differs only on a second short send. The short-send twin test catches it, as it catches SQ3.
ET12 and ET13 are out of the model's reach, as before.

Four mutations retired. The draining rotation removed the code U3 and U4 broke, and U5 was taken
out of its table. U7 broke the rule that a port is never replaced under a waiting lookup, and §17
question 15's answer replaced that rule; W2 breaks the drain that took its place. E1, E4, ET3,
U1, U2, CR1, CR2 and CR4 were written again for the code as it stands. SQ1 to SQ10, whose diffs
were not kept, were written again from their descriptions.

Forty-seven mutations, forty-seven `CAUGHT`: forty-three by the walks, and ET12, ET13, SQ3 and
SQ4 by `zig build test-io`.

| # | Mutation | The short walks | The full run | Status |
| --- | --- | --- | --- | --- |
| E1 | an event for an opening that is gone is applied | an assertion | an assertion | CAUGHT |
| E2 | a lookup stays on a connection it no longer streams to | walk 8 | walk 1 | CAUGHT |
| E3 | a new lookup forgets its slot's buffer is lent | no | walk 79, picked | CAUGHT |
| E4 | a send's completion speaks to whatever holds the slot | no | walk 359, picked | CAUGHT |
| E5 | a held send is dropped | no | walk 51, picked | CAUGHT |
| E6 | the drive stops after one poll a slot | walk 1 | walk 1 | CAUGHT |
| E7 | the table misses the deadline of a wait a poll starts | walk 8 | walk 1 | CAUGHT |
| E8 | a stale event keeps its buffer | walk 1, the buffer check | walk 1 | CAUGHT |
| ET1 | lookups hear the connection is up before the handshake | walk 42 | walk 8001 | CAUGHT |
| ET2 | the session's records go to the back of the queue | walk 42 | walk 8001 | CAUGHT |
| ET3 | records made behind a waiting records entry take one of their own | walk 48 | walk 8006 | CAUGHT |
| ET4 | a declined ticket fails the connection | no | walk 8573, picked | CAUGHT |
| ET5 | a spent ticket stays kept | no | walk 8095, picked | CAUGHT |
| ET6 | an idle TLS connection closes without `close_notify` | walk 48 | walk 8001 | CAUGHT |
| ET7 | a TLS configuration opens UDP sockets | walk 41 | walk 8001 | CAUGHT |
| ET8 | a TLS connection is closed to make room | no | walk 8279, picked | CAUGHT |
| ET9 | a records send's end leaves its slot borrowed | walk 42 | walk 8001 | CAUGHT |
| ET10 | a reopening connection takes its old opening's events | no | walk 8573, by an assertion, picked | CAUGHT |
| ET11 | a reopening connection connects while its old records are in flight | no | walk 8573, by an assertion, picked | CAUGHT |
| ET12 | a record longer than 2^14 + 256 octets is waited for | no: the record-length test | no | CAUGHT |
| ET13 | a ticket older than seven days is spent | no: the seven-day test | no | CAUGHT |
| ET14 | a closing connection reads what the peer sends | an assertion | an assertion | CAUGHT |
| SQ1 | the head goes out while a send is in flight | an assertion | an assertion | CAUGHT |
| SQ2 | a short send is taken for a whole one | walk 9 | walk 2 | CAUGHT |
| SQ3 | the rest is sent from the message's start | no: the short-send twin test | no | CAUGHT |
| SQ4 | the octets sent are counted from the last send alone | no: the short-send twin test | no | CAUGHT |
| SQ5 | a failed send leaves the connection up | walk 1 | walk 1 | CAUGHT |
| SQ6 | a lookup that leaves keeps its waiting query queued | no | walk 4011, picked | CAUGHT |
| SQ7 | a closed connection keeps its waiting queries' buffers lent | walk 29 | walk 9 | CAUGHT |
| SQ8 | a lookup that leaves takes its started query with it | walk 6 | walk 3 | CAUGHT |
| SQ9 | a send the loop refuses leaves the queue stuck | walk 29 | walk 9 | CAUGHT |
| SQ10 | a whole send does not let the next go | walk 38 | walk 4007 | CAUGHT |
| U1 | a receive a replaced socket left behind keeps its datagram's buffer | walk 64, the buffer check | walk 12001 | CAUGHT |
| U2 | a socket's receive the loop refused is never asked for again | walk 1 | walk 1 | CAUGHT |
| U6 | a connection's receive the loop refused is never asked for again | walk 9 | walk 7 | CAUGHT |
| W1 | a port that has carried its share is never replaced | walk 61 | walk 12001 | CAUGHT |
| W2 | a replaced socket is closed at once, and its answers are lost | walk 61 | walk 12001 | CAUGHT |
| W3 | a draining socket is never closed | walk 61 | walk 12001 | CAUGHT |
| W4 | a replacement that cannot open leaves the server no socket | an assertion | an assertion | CAUGHT |
| W5 | a draining socket's refused receive is never asked for again | walk 68 | walk 12001 | CAUGHT |
| W6 | a draining socket's ended receive is armed on the current one | walk 61 | walk 12001 | CAUGHT |
| W7 | a query does not record the socket it left from | walk 61 | walk 12001 | CAUGHT |
| CR1 | a closed slot is taken while its connect is in flight | walk 4 | walk 19 | CAUGHT |
| CR2 | a slot nobody uses is taken while its connect is in flight | walk 4 | walk 1 | CAUGHT |
| CR3 | a connect's event leaves its slot marked | walk 4 | walk 1 | CAUGHT |
| CR4 | closing a slot forgets its connect is in flight | walk 4 | an assertion | CAUGHT |
| CR5 | a connect's submission does not mark its slot | walk 4 | walk 1 | CAUGHT |

The mutations are kept as data since the same day: `tools/mutations/engine.zon` holds each one's
edits and the check that must catch it, and `zig build mutations -- engine` runs them again. It has
TLC write the full run, breaks the engine each way, and replays the short walks, then, for a
mutation they miss, the full run and the picked walks. It names the full run's first walk that
catches each miss, and a replay that panics names its walk too, so the picks are chosen again in
one run after the model changes. Run over all 47 on the full run above, every one was caught
where the data says.

The replay's own checks, and the tool's, broken against `zig build test-tools`, and the build's
comparisons against `zig build spec-engine`. Six mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TK1 | an event's operation is the oldest, whatever its token | an event names its operation | the short walks | CAUGHT |
| TK2 | the engine's operations are written in the order they were submitted | the model's order | the short walks | CAUGHT |
| TK3 | a current operation is written before a stale one | the model's order | the short walks | CAUGHT |
| TW1 | a picked walk is numbered from 0 | picks count from 1 | the tool's pick test | CAUGHT |
| D1 | the committed short walks lose their last line | the short walks are TLC's | `spec-engine`, the comparison | CAUGHT |
| D2 | the committed picked walks lose their last line | the picked walks are TLC's | `spec-engine`, the comparison | CAUGHT |

The tool, then `tools/engine_mutations.zig` and now `tools/mutations.zig`, broken against `zig
build test-tools`. EM4 broke a line that could
never matter, since the tool runs the full run only when the short walks miss, and the line was
removed. EM7 came with the sets of the lookup and `getaddrinfo`, whose mutations a build step
catches. EM8 to EM10 came with the review of the same day. It found that a set ran with no check
of its own checks, so a missing `lake` made every Lean mutation look caught, and that a compile
error was told from a failed test by the text after it. EM8 is shown by a run and not by a test,
since the baseline runs builds. EM11 and EM12 came on 2026-09-26. The baseline replayed the short
walks alone, so a picked walk or a full run that failed anyway counted every mutation that reached
it: a full run written before a fix to the model caught RT1 at its walk 4092. Each is shown by a
run against a file with one line of one walk changed: the tool stops before any mutation, and
without the check it counts E3 caught at the changed walk. Twelve mutations: eight `CAUGHT`, EM4's
line removed, and EM8, EM11 and EM12 shown by runs.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| EM1 | the files are put back first edit first | a file two edits share ends as it began | the put-back test | CAUGHT |
| EM2 | an edit applies wherever its text occurs | an edit's text occurs once | the put-back test | CAUGHT |
| EM3 | an edit that cannot apply leaves the edits before it | nothing is left edited | the put-back test | CAUGHT |
| EM4 | a mutation the short walks catch is picked too | only a miss is picked | nothing: **the line was dead, and is removed** | NOT CAUGHT |
| EM5 | the replay's walk is not read | a miss names its walk | the walk test | CAUGHT |
| EM6 | a picked mutation must be caught by the picked walks alone | the short walks may catch it now | the pick test | CAUGHT |
| EM7 | a mutation caught by a step counts as caught whatever the step did | a step that misses is a miss | the pick test, since the step sets | CAUGHT |
| EM8 | a set runs without its checks run first on the tree as it is | a check that fails anyway proves nothing | no unit test: the run with no `lake` on the path, where `spec-lean` fails before any mutation | NOT CAUGHT |
| EM9 | any file's `line:column: error:` is taken for the compiler's | a compile error is a Zig file's | the walk test | CAUGHT |
| EM10 | a `<section>/<id>` name matches whatever the section | an id two sections share is named by its section | the naming test | CAUGHT |
| EM11 | the baseline replays the short walks alone | a picked walk that fails anyway proves nothing | no unit test: the run with walk 1 of the picks changed, where E3 is counted caught at picked walk 1 and not 3 | NOT CAUGHT |
| EM12 | the full run is read without a replay with nothing mutated first | a full run that fails anyway proves nothing | no unit test: the run with walk 2 of the full run changed, where E3 is counted caught at walk 2 and not 8046 | NOT CAUGHT |

## A refusal is a failure

Design §16 decision 25, ruled on 2026-09-24 (issue #11). A connection or a handshake that
failed, and a request over DoH or DoQ that ended without an answer, count as the server failing
the lookup, as SERVFAIL does. A lookup whose passes run out after one ends in
`AllServersFailed`, and `Timeout` means every try went unanswered. `refused_never_timeout` states
that promise in the Lean model.

RF1 and RF2 break the model, against `zig build spec-lean`, and fail that theorem alone. The
older proofs were written again to name no flag, so a mark dropped is the new theorem's to find.
RF3 and RF4 break the code, against `zig build test-resolver`. The committed slices catch both
as well, and RF3 fails the twin's TLS test and the live check, where both refusals ended in
`Timeout`. RF5 breaks the lookup the engine model carries, against `zig build spec-engine`. DM3
was written again, since the line it breaks changed. Five mutations, five `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RF1 | the model counts a failed connection as silence | decision 25 | `refused_never_timeout` | CAUGHT |
| RF2 | the model counts a failed request as silence | decision 25 | `refused_never_timeout` | CAUGHT |
| RF3 | a failed connection is counted as silence | §5, retry policy | the refusal test, the twin's TLS refusal test, both replays, the live check | CAUGHT |
| RF4 | a failed request is counted as silence | §5, retry policy | the failed-request test, the lookup's replay | CAUGHT |
| RF5 | the engine model counts a failed connection as silence | decision 25 | `spec-engine`, the comparison | CAUGHT |

## A connect's address

The stream's rule 10 (docs/design.md §19 step 13): a connect borrows its slot's address until
its final event, so the slot is not opened again before then. The model's new invariant broke on
the code as it stood, in two events. Broken against `zig build test-io`, `zig build test-tools`
and `zig build spec`. The committed walks catch all five; the twin tests catch none, since none
of them opens a slot again while a connect is out. Five mutations, five `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CR1 | a closed slot is taken while its connect is in flight | rule 10 | the committed walks, at line 76 | CAUGHT |
| CR2 | a slot nobody uses is taken while its connect is in flight | rule 10 | the committed walks, at line 10 | CAUGHT |
| CR3 | a connect's event leaves its slot marked | rule 10, the slot comes back | the committed walks, at line 30 | CAUGHT |
| CR4 | closing a slot forgets its connect is in flight | rule 10 | the committed walks, at line 76 | CAUGHT |
| CR5 | a connect's submission does not mark its slot | rule 10 | the committed walks, at line 10 | CAUGHT |

## SPKI pins

Design §21: a TLS server is known by its name, its SPKI pins, or both, and a pin's base64 text
is read strictly. Broken against `zig build test-core` and `zig build test-config`. PN3 was `NOT
CAUGHT`: base64 with its padding decodes to 32 octets only from 44 characters, so the length check
said what the size check says. It is gone. PN5 shows which of the two carries the weight: without
it the decoder writes past the pin. Five mutations, four `CAUGHT`, and the fifth's check removed.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| PN1 | a TLS server with neither a name nor a pin is valid | RFC 8310 §5, a strict client authenticates | the name-or-pins test | CAUGHT |
| PN2 | a TLS server may carry more pins than the bound | `spki_pins_max` | the name-or-pins test | CAUGHT |
| PN3 | a pin's text of another length is decoded | RFC 7858 §4.2, one length | nothing: **the size check says the same, and the length check is gone** | CAUGHT |
| PN4 | a pin is read in the URL-safe alphabet | RFC 4648 §4 | the refusal test; the Appendix A test | CAUGHT |
| PN5 | a text that decodes to another size is read | RFC 7858 §4.2, 32 octets | the refusal test, by a bounds panic | CAUGHT |

## DoT's configuration and padding

Design §21 steps 2 and 3: servers speak TLS all together or not at all, a TLS server's queries go
on the stream to its TLS port, and they are padded to a whole block. Broken against `zig build
test-core`, `test-wire` and `test-resolver`. Seven mutations, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DT1 | the padding leaves out the option's own header | RFC 8467 §4.1, a whole block | the padded-query test; the TLS lookup test | CAUGHT |
| DT2 | a lookup never pads | §21, padding on TLS | the TLS lookup test | CAUGHT |
| DT3 | a lookup pads every query | RFC 7830 §6, padding only when encrypted | the `use_tcp` lookup test | CAUGHT |
| DT4 | a list that mixes TLS and cleartext is valid | RFC 8310 §5.1, all or none | the all-or-none test | CAUGHT |
| DT5 | TLS servers leave the lookup on datagrams | §21, every query on the stream | the all-or-none test; the TLS lookup test | CAUGHT |
| DT6 | a TLS server's stream goes to its cleartext port | RFC 8310 §5.1 | the all-or-none test; the TLS lookup test | CAUGHT |
| DT7 | the padding octets are left as the buffer held them | RFC 7830 §3, zero octets | the padded-query test | CAUGHT |

## DoQ's DNS half

Design §23: servers speak QUIC all together, and a query over DoQ is a request of its own in
DoH's shape, with the length prefix RFC 9250 §4.2 gives every DoQ message. DoH's
`send_https`, `on_https_answer` and `on_https_failed` became `send_request`,
`on_request_answer` and `on_request_failed` by the owner's ruling, so DH1 to DH21 name the
checks by their first names. Broken against `zig build test-core` and `test-resolver`. Nine
mutations, nine `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| QU1 | a server naming TLS and QUIC agrees with itself | §23, one kind a server | the QUIC config test | CAUGHT |
| QU2 | a QUIC configuration sends no requests | §23 | the query-shape test | CAUGHT |
| QU3 | a DoQ message goes without its length prefix | RFC 9250 §4.2 | the query-shape test | CAUGHT |
| QU4 | a DoQ query carries the transaction id | RFC 9250 §4.2.1, ID 0 | the query-shape test | CAUGHT |
| QU5 | a DoQ query mixes the name's case | §23, DoH's shape | the query-shape test | CAUGHT |
| QU6 | a DoQ query carries the server's cookie | §23, DoH's shape | the query-shape test | CAUGHT |
| QU7 | TC=1 over DoQ sends the lookup to TCP | §23, read as a stream | the stream-reading test, by an assertion | CAUGHT |
| QU8 | a datagram answers a lookup over DoQ | §23, no datagram | the datagram test | CAUGHT |
| QU9 | a lookup over DoQ asks for a datagram | §23, `send_request` | the query-shape test | CAUGHT |

## An answer's TTL

Issues #1 and #2, fixed on 2026-09-24. A record with a TTL of zero kept the answer's TTL at zero
only when nothing came after it: `note_ttl` read zero as "nothing noted yet". And a CNAME chain
that spanned messages kept only the last message's TTLs, for the answer and for a negative at the
chain's end. Broken against `zig build test-wire` and `test-resolver`. TT8 first stopped the
build with an unused parameter and was rewritten to discard it. Eight mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TT1 | zero reads as "nothing noted", as before the fix | RFC 1035 §3.2.1, zero is not cached | the zero-TTL test | CAUGHT |
| TT2 | an empty collection's smallest TTL is zero | the smallest of nothing is the largest | every collecting test | CAUGHT |
| TT3 | a negative's TTL ignores the CNAMEs in its own message | RFC 1035 §3.2.1, the chain bounds the end | the negative chain test | CAUGHT |
| TT4 | nothing is bounded by the chain earlier messages moved | RFC 1035 §3.2.1 | the chain test | CAUGHT |
| TT5 | an answer is not bounded by the chain | RFC 1035 §3.2.1 | the chain test | CAUGHT |
| TT6 | a second alias forgets the first one's TTL | RFC 1035 §3.2.1 | the chain test, over three messages | CAUGHT |
| TT7 | a DoH answer loses its `Age` after the chain bounds it | RFC 8484 §5.1, each message its own `Age` | the DoH chain test | CAUGHT |
| TT8 | a negative's TTL is not bounded by the chain | RFC 1035 §3.2.1, RFC 2308 §5 | the negative chain test | CAUGHT |

## DoH's DNS half

Design §22: servers speak DoH all together, a query over DoH is cache-friendly, an answer comes
by its transaction's number and loses its `Age`, and an HTTP failure fails the server. Broken
against `zig build test-core`, `test-wire` and `test-resolver`, and DH8, DH9, DH15, DH16, DH18
and DH21 against the lookup replay alone (`zig build test-tools`). The replay catches DH8, DH15
and DH18. The model abstracts a transaction's number and delivers no datagram over DoH, so the
other three are the unit tests' alone. DH8 and DH21 first stopped the build with an unused
parameter; they were rewritten to discard it. Twenty-one mutations, twenty-one `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DH1 | a server naming both TLS and HTTPS agrees with itself | §22, one kind a server | the all-together test, by `transport`'s assertion | CAUGHT |
| DH2 | the `dns` variable is standard base64 | RFC 8484 §6, base64url | RFC 8484 §4.1.1's dash test | CAUGHT |
| DH3 | the `dns` variable keeps its padding | RFC 8484 §6, no `=` | RFC 4648 §10's vectors | CAUGHT |
| DH4 | a query over DoH carries the transaction id | RFC 8484 §4.1, ID 0 | the query-shape test | CAUGHT |
| DH5 | a query over DoH mixes the name's case | §22, the same octets | the query-shape test | CAUGHT |
| DH6 | a query over DoH carries the server's cookie | §22, no cookie | the query-shape test | CAUGHT |
| DH7 | a query over DoH goes unpadded | RFC 8467 §4.1 | the query-shape test | CAUGHT |
| DH8 | an answer to any transaction is taken | §22, the answer by transaction | the table's DoH test; the replay | CAUGHT |
| DH9 | a new transaction keeps the old number | §22, the answer by transaction | the table's failure test | CAUGHT |
| DH10 | an answer's TTL keeps its `Age` | RFC 8484 §5.1 | the `Age` test | CAUGHT |
| DH11 | an `Age` past the TTL wraps it | RFC 8484 §5.1, never below zero | the `Age` test | CAUGHT |
| DH12 | a kept record's TTL keeps its `Age` | RFC 8484 §5.1 | the kept-record test | CAUGHT |
| DH13 | NXDOMAIN's negative TTL keeps its `Age` | RFC 8484 §5.1, RFC 2308 §5 | the kept-record test | CAUGHT |
| DH14 | NODATA's negative TTL keeps its `Age` | RFC 8484 §5.1, RFC 2308 §5 | the kept-record test | CAUGHT |
| DH15 | TC=1 over DoH sends the lookup to TCP | §22, read as a stream | the stream-reading test; the replay | CAUGHT |
| DH16 | a datagram answers a lookup over DoH | §22, no datagram | the table's DoH test; the datagram test | CAUGHT |
| DH17 | an HTTP failure counts no failure | §22, the server's failure | the HTTP-failure test | CAUGHT |
| DH18 | a lookup over DoH asks for a datagram | §22, `send_https` | the table's DoH test; the replay | CAUGHT |
| DH19 | the table does not follow an accepted DoH answer | §4, every event through the table | the table's DoH test | CAUGHT |
| DH20 | the table does not follow an HTTP failure | §4, every event through the table | the table's failure test | CAUGHT |
| DH21 | an HTTP failure for a transaction left moves the lookup | §22, the answer by transaction | the HTTP-failure test | CAUGHT |

The lookup model's DoH rules, broken in `spec/lean/Spec/Lookup.lean`. Each fails a proof, so the
transcript tool does not build. Each was then replayed against the code from a copy of `spec/`
without the proofs, and the replay refused each at its first DoH line. DM3 breaks only proof
scripts written against the rule's shape: no theorem states that an HTTP failure moves the
lookup on, and the replay is what holds it. Three mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DM1 | a reply over DoH is read as a datagram's | §22, read as a stream | `https_never_stream`; the replay, TC=1 after a chain | CAUGHT |
| DM2 | a poll over DoH asks for a datagram | §22, `send_https` | `poll_https`, the lemma under `https_never_stream`; the replay, the first poll | CAUGHT |
| DM3 | an HTTP failure changes nothing | §22, the next server | the replay, the first `https_failed`; the proofs' scripts alone | CAUGHT |

## One send a stream

The stream's rule 9 (docs/design.md §19 step 13): a connection carries one send at a time, and a
short send finishes its message before the next starts. Broken against `zig build test-io`, `zig
build test-tools` and `zig build spec`. The committed walks caught eight. SQ3 is out of their
reach, since the model counts no octets; the short-send twin test, where every send moves five
octets, catches it. SQ6 was `NOT CAUGHT` by the gate at first, and caught by the full walks; the
queued-cancel twin test was written for it and catches it in the gate. Ten mutations, ten
`CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| SQ1 | the head goes out while a send is in flight | one send a stream | the committed walks; the twin tests, by an assertion | CAUGHT |
| SQ2 | a short send is taken for a whole one | the rest goes first | the short-send twin test; the committed walks | CAUGHT |
| SQ3 | the rest is sent from the message's start | the rest goes first | the short-send twin test | CAUGHT |
| SQ4 | the octets sent are counted from the last send alone | the rest goes first | the short-send twin test; the committed walks | CAUGHT |
| SQ5 | a failed send leaves the connection up | a failed send fails the connection | the committed walks | CAUGHT |
| SQ6 | a lookup that leaves keeps its waiting query queued | a waiting query leaves with its lookup | the queued-cancel twin test; the full walks | CAUGHT |
| SQ7 | a closed connection keeps its waiting queries' buffers lent | the buffers come back | the committed walks | CAUGHT |
| SQ8 | a lookup that leaves takes its started query with it | a started message is sent to its end | the committed walks | CAUGHT |
| SQ9 | a send the loop refuses leaves the queue stuck | a refused send fails the connection | the committed walks | CAUGHT |
| SQ10 | a whole send does not let the next go | the next one goes | the committed walks; the shared-connection twin test | CAUGHT |

## The `getaddrinfo` walks

`AddressLookup` and `NameLookup` against the model of their rules (docs/design.md §19 step 14,
The walk's rules). Broken against `zig build test-resolver`, `zig build test-tools`, which
replays the committed slice of the walks' transcript, and `zig build spec`, which replays all of
it. A1 and N1 put back the two defects the rules found. The committed slice catches all six; the
unit tests miss A3, which only the replay reaches. Six mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| A1 | each slot is released at its own lookup's end | rule 1 | the fills-the-table test; the committed slice, at line 4 | CAUGHT |
| A2 | a name that does not exist leaves the other family running | rule 4 | the name-does-not-exist test; the committed slice | CAUGHT |
| A3 | `NameNotFound` beside an answer moves the walk on | rule 5 | the committed slice, at line 19 | CAUGHT |
| N1 | a reverse walk moves on after any failure | the reverse walk's failure rule | the reverse server-failure test; the full transcript | CAUGHT |
| N2 | a reverse walk forgets NODATA | the reverse walk's `NoData` | the reverse server-failure test; the full transcript | CAUGHT |
| N3 | a cancel after the answer came keeps the answer | the reverse walk's cancel | the cancel-after-answer test; the full transcript | CAUGHT |

## The epoll check

`tools/epoll_check/run.sh`, run by CI's `epoll` job: the rotor example must resolve inside a
container where io_uring is refused, over rotor's epoll fallback. A probe in the container must
first see io_uring refused, which is the control: without it, a pass under a profile that allowed
io_uring would prove nothing. One mutation, one `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| P1 | rotor pinned back to 0.2.0, which has no epoll fallback | the example resolves where io_uring is refused | the check: the example fails `PermissionDenied` | CAUGHT |

## The search-order recorder

Design §5, §17 question 7: `tools/search_order/recorder.zig` answers the resolvers the probe
watches, so what it answers decides what the probe sees. Broken against `zig build test-tools`.
Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| S1 | a name no case lists gets NOERROR | every other name is NXDOMAIN | the reply test | CAUGHT |
| S2 | names keep their case | the log reads one name one way | the question test | CAUGHT |
| S3 | the reply is not marked a response | RFC 1035 §4.1.1, QR | **a test written for it** | CAUGHT |
| S4 | SERVFAIL reads as NXDOMAIN | a case's rcode is the one sent | the reply test | CAUGHT |

S3 was `NOT CAUGHT` at first: no test read the header's flags, and a resolver drops a reply that
is not marked as one, so the probe would have recorded timeouts where the libraries walk on.

## The expired entry keeps its slot

Design §17 question 14, answered yes: a get that finds its entry expired misses and leaves it,
and the put after the miss renews it where it stands. Broken against `zig build test-cache`.
Three mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| E1 | a get evicts an expired entry again | the miss keeps the slot | the expired-miss test and the renewal test | CAUGHT |
| E2 | a get hands back an expired entry | a hit is a live entry | the expired-miss test and the renewal test | CAUGHT |
| E3 | a put over an expired entry goes in as new | the renewal happens in place | **the renewal test** | CAUGHT |

E3 is the change itself put back one call later: the get leaves the entry, and the put evicts it
and inserts the name at the newest end. Only a test that reads where the entry stands after the
put can tell the two apart.

## The end-to-end driver

The comparison's own driver, not the library: `bench/end_to_end/rotor_loop.zig`. Broken against
`zig build test-cares`. One mutation, one `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| K1 | start the next lookup before taking the result that frees its slot | §19 step 15, the driver keeps `in_flight` going | the one-at-a-time test | CAUGHT |
| K2 | let a start that happens inside a start make its own query | the c-ares driver's trampoline | the start-inside-a-start test | CAUGHT |
| K3 | start another lookup while the channel is being destroyed | the c-ares driver's stop flag | the row-is-over test | CAUGHT |
| R1 | let go of a slot with a plain store, erasing a start owed meanwhile | the handoff loses no answer | the let-go test | CAUGHT |
| R2 | let a start that finds the slot held leave no word | the holder learns a start is owed | the start-inside-a-start test | CAUGHT |
| R3 | report the slot let go although a start is owed | the holder issues for an answer that came | the settle test | CAUGHT |
| R4 | keep starting lookups after the row is over | no query on a channel being destroyed | the row-is-over test | CAUGHT |
| X1 | let go of a slot with a plain store | exactly one actor issues after an answer | the let-go and settle tests | CAUGHT |
| X2 | let `take` look only once | the answer's second look finds the slot idle | **the every-order test** | CAUGHT |
| X3 | mark a start owed with a plain store | a mark lands only on a held slot | **the every-order test** | CAUGHT |
| X4 | take an idle slot by a load and then a store | each step is one atomic operation | nothing | NOT CAUGHT |
| X5 | put the claim counter back as a plain integer | no claim is lost or given twice | **the two-thread claim test** | CAUGHT |

The bug this records was real and it hid for a day. With several lookups in flight the others keep
the loop busy and no test saw anything; with one, every iteration that took a result left nothing
outstanding, and the tick under it waited out `tick_wait_ns_max`. That is one second a lookup, so
the table's first row would have taken five hours rather than a second, and the run looked hung.
The test runs one at a time and bounds the run's wall time, because a lookup's latency is read
when its result is taken, which is before the wait.

K2 is the same shape on the other side. c-ares answers some queries before `ares_query_dnsrec`
returns — `ares_send_nolock` calls the callback itself — and that callback started the next
lookup, so a run of inline answers was recursion with a frame per lookup. It aborted at 20,000
with a ten-thousand-frame trace, one run in five. No run can be made to answer inline on demand,
so the test drives the guard directly rather than the shape that trips it.

R1 to R4 replace K2's two flags. The callback and the holder could each decide the other would
start the next lookup, and a slot went idle with its answer unissued: a lost wakeup, found by
reading the code after the owner asked whether the stall was the harness's. Each slot now has one
owner state that changes only by compare-and-exchange. The first run of these mutations left two
`NOT CAUGHT`, and both were equivalent mutants — a fast path and a second stop check that other
lines already covered. They were deleted rather than tested.

X1 to X4 are the races the handoff could have, run against `every_order`, which interleaves
the answer's `take` and the holder's `settle` step by step in every order there is — three —
using the real steps, copied per branch. X2 is why it exists: `take` looks twice because the
holder can let go between the looks, and no example-based test could put it there. X4 is not
caught and is kept as the tool's boundary: `every_order` treats each step as atomic, so it
proves the protocol and cannot prove a step is one atomic operation. Here the mutant is also
harmless, since only one actor ever takes an idle slot. ThreadSanitizer would not see it either:
an atomic load and an atomic store are not a data race, only a lost update, and a data race is
what it reports.

X5 is the race the counter had before it was made atomic. The sanitizer did not see it put back,
because no test ran a callback while the main thread was still claiming its first batch, and a
sanitizer judges only the accesses a run makes. The claim test runs two threads claiming at once.
On arm64 macOS, with no sanitizer, it caught the mutant in 3 runs of 3 by an index claimed twice;
on Linux the sanitizer reports the plain counter whether or not a claim was lost.

K3 came out of the same crash, which K2 did not cure. Destroying a channel fails the queries
still on it, each failure reaches the callback, and the callback started another lookup on the
channel that was going away. Its first test was vacuous: with nothing left to claim, the slot's
flags read the same whether the guard was there or not, and only counting the claims tells them
apart. That is the second `NOT CAUGHT` of the day to come from a test that watched the wrong
thing rather than from a missing test.

## The end-to-end driver on a schedule

Design §11, 2026-09-29 (c4milo/cocuyo#5). pepegrillo's method asks a unit that waits on I/O for
its percentiles under a load sent on a schedule, since a driver that starts a lookup when another
ends sends nothing while a stack stalls. The comparison's driver now sends each lookup when it is
due, whether or not the stack has answered, and measures its latency from then. The rows add the
99.9th percentile, the slowest lookup, how late the lookups went out, and the stack's system calls
and context switches per lookup. The responder moved to a process of its own, so that none of its
calls is counted with the stack's. Broken against `zig build test-cares` on macOS. Twenty
mutations: nineteen `CAUGHT`, and one that changes nothing a test can see.

c-ares's lookups now go out from the main thread, and its callback only records, so the handoff
between the two threads went. These mutations broke code that is gone, and retire with it:

- K2, the trampoline that kept a start inside a start from making its own query.
- K3 and R4, the stop flag that kept a callback from starting a lookup on a channel being
  destroyed.
- R1 to R3 and X1 to X4, the handoff of a slot between the callback and its holder.
- X5, the claim counter the two threads shared.

K1 has no counterpart a test can see. The loop now reads its wait after it has taken the results
and started what is due, so starting first costs one more pass that returns at once, and never a
wait. SC6 is that mutant. It is equivalent, and the comment on the loop now says why the order is
kept.

SC2 and SC7 are caught by a safety check rather than by the test's own bound: a lookup started
before it is due makes its lateness negative, and the subtraction that records it overflows.
SC11 is caught by a hang, which the run's timeout stopped: without its deadline, the wait for room
never ends once c-ares has the most out.

Three guards have no mutation: the receive timeout and the parent check that end a responder a
crashed test left behind, and the deadline on the responder's start. No test can crash the
process that runs it, or start a responder that never serves.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| SC1 | cocuyo's tick waits out `tick_wait_ns_max` whatever is due | the loop wakes when a lookup is due | the on-schedule test | CAUGHT |
| SC2 | cocuyo starts a lookup before it is due | the schedule | the on-schedule test, by the lateness overflowing | CAUGHT |
| SC3 | cocuyo's latency runs from when the lookup went out | latency from the due time | the queue test | CAUGHT |
| SC4 | cocuyo starts a due lookup with no room for it | the most out at once | the queue test | CAUGHT |
| SC5 | cocuyo records no lateness | the driver's part of the latency | the queue test | CAUGHT |
| SC6 | cocuyo starts due lookups before taking the results that free their room | none: the wait is read after both | nothing | NOT CAUGHT, equivalent |
| SC7 | c-ares's lookups go out before they are due | the schedule | the on-schedule test, by the lateness overflowing | CAUGHT |
| SC8 | c-ares's latency runs from when the lookup went out | latency from the due time | the queue test | CAUGHT |
| SC9 | c-ares sends a due lookup with no room for it | the most out at once | the room test | CAUGHT |
| SC10 | c-ares records no lateness | the driver's part of the latency | the queue test | CAUGHT |
| SC11 | the wait for room has no deadline | a c-ares that holds a query ends the row | the room test, by a hang | CAUGHT |
| SC12 | a percentile is read a place low | the 99.9th is the twentieth slowest of 20,000 | the permille test | CAUGHT |
| SC13 | lookups fall due at twice the rate | the period | the schedule's tests | CAUGHT |
| SC14 | a rate's row allows one lookup out | the most out at once | the schedule's tests | CAUGHT |
| SC15 | the wait wraps once the due time has passed | a lookup already due waits for nothing | the schedule's tests | CAUGHT |
| SC16 | a 32-bit counter's growth ignores the wrap | macOS's counters are `integer_t` | the wrap test | CAUGHT |
| SC17 | the context switches are read from one reading | the kernel's counts | the count test | CAUGHT |
| SC18 | the unix system calls are left out | the kernel's counts | the count test | CAUGHT |
| SC19 | the responder is a thread of this process, as it was | none of the responder's calls is counted | the responder's own-process test | CAUGHT |
| SC20 | a count per lookup drops its decimals | two decimals a lookup | the per-lookup test | CAUGHT |

## A row of cache hits

Design §11, 2026-09-30. The comparison's rows ask a new name every time, so neither stack's cache
answers any of them. A last row asks 64 names in turn after asking each once, so both caches
answer every lookup. cocuyo's engine answers from its cache inside `start`, and c-ares inside
`ares_query_dnsrec`, so each driver counts a lookup answered before its start returns as a hit:
cocuyo's takes a result right after each start, and c-ares's callback runs on the thread that
sends. The tests require every lookup of the row to be a hit, with the responder hearing each name
once, and every lookup of the other rows to reach the responder. Broken against
`zig build test-cares` on macOS, with SC1 to SC20 run again over the changed drivers.
Seven mutations, seven `CAUGHT`. SC1 to SC20 gave what they gave before, SC6 equivalent still.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| H1 | repeated names never repeat | the row asks what the cache holds | the cache-hit tests, each hit and the responder's count | CAUGHT |
| H2 | cocuyo's row of repeated names asks none of them first | the cache holds every name before the row | cocuyo's cache-hit test | CAUGHT |
| H3 | cocuyo takes no result right after a start | a hit is taken where it is ready, and counted | cocuyo's cache-hit test | CAUGHT |
| H4 | c-ares's row of repeated names asks none of them first | the cache holds every name before the row | c-ares's cache-hit test | CAUGHT |
| H5 | a c-ares hit is told by a callback on the other thread | a hit is answered inside `ares_query_dnsrec` | c-ares's cache-hit test | CAUGHT |
| H6 | a hit's time keeps the wait before it | the row times a hit from its start | the start-to-result test | CAUGHT |
| H7 | a hit's time prints the wrong thousandths of a microsecond | microseconds to the nanosecond | the microseconds test | CAUGHT |

## Costs held at zero

2026-09-30 (c4milo/cocuyo#35). Two costs on the hot paths are none today, and a change that makes
either one some is a step that an exact check catches where no timing can.

A cache hit through the engine makes no system call and never blocks. The comparison's tests run
n hits and 2n hits and require the kernel's counts not to grow: system calls on macOS, and on
Linux the switches of a thread that blocked, which `bench/end_to_end/kernel.zig` now reads apart.
Broken against `zig build test-cares` on macOS.

The hot paths' ReleaseSafe code calls `memset` or `bzero` only where `tools/fill_check/fill_check.zig`
knows it does. `zig build fill-check`, in the gate, compiles `tools/fill_check/fill_probe.zig` for
x86-64 Linux and arm64 macOS, splits the assembly into functions, follows each probe's calls past
the panic handlers, and counts the calls to a fill. Its first run found every path but the cache's
get reaching one. Each is either a fill c4milo/cocuyo#34 found, of the answers' storage, which
`response.collect` and the table's poll reach as well as the paths #34 named, or the zeros of the
EDNS padding (RFC 7830 §3). They are known until #34 removes them. Broken against
`zig build test-tools` and `zig build fill-check`.

Twelve mutations, twelve `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| ZC1 | the engine's start makes a system call | a cache hit makes none | the no-system-call test | CAUGHT |
| FC1 | a tail call to a fill is not counted | a jump to `memset` is a call | the call test, and the check on four paths | CAUGHT |
| FC2 | the walk follows no call | a fill in a callee counts | the callee test, and the check on every path with a fill | CAUGHT |
| FC3 | the walk enters the panic handlers | a failed check's fills are not the path's | the callee test, and the check on every path | CAUGHT |
| FC4 | an ELF basic block's label starts a function | only `.type` names a function | the basic-block test, and the check on x86-64 | CAUGHT |
| FC5 | `bzero` is not a fill | Darwin's zero fill is one | the call and basic-block tests, and the check on arm64 | CAUGHT |
| FC6 | a fill that went passes | the known list follows the code | the comparison test | CAUGHT |
| FC7 | a known probe that is gone passes | the known list follows the code | the comparison test | CAUGHT |
| FC8 | assembly with no probe passes | a check that read nothing fails | the refusal test | CAUGHT |
| FC9 | a cache hit fills a scratch buffer it leaves undefined | no new fill on a hot path | the check on x86-64; arm64 writes 512 octets with stores of its own | CAUGHT |
| FC10 | Mach-O's private functions are not read | a stripped build names its functions `l_` | the call, basic-block and comparison tests, and the check on arm64 | CAUGHT |
| FC11 | ELF's local functions keep their prefix | a stripped build names its functions `.L` | the call, basic-block and callee tests, and the check on x86-64 | CAUGHT |

## The answers keep the type of the question

Design §16 decision 34, 2026-09-30 (c4milo/cocuyo#34). The answers' union is an `extern union`, and
`Answers` carries `kind`, the type of the question it answers, so changing lists writes `kind` and
none of the storage. A lookup started in its slot sets every field but its answers, through a value
of the other fields that the compiler checks whole, and a negative put resets the slot's answers in
place. The fill check's known fills fell, on both targets, to the zeros of the EDNS padding and
`Lookup.init`. Broken against `zig build test-wire`, `test-resolver`, `test-cache` and `fill-check`.
Seven mutations, seven `CAUGHT`.

A value of those fields that leaves one out does not build, so no mutation of it can run: the
compiler refuses it, which is what the value is for. The reads of `items` assert `kind`, where the
build's hidden tag checked the member before. Dropping one of those assertions is not in the table:
no correct caller reads the wrong list, so no test reaches it, as none reached the hidden tag's
check.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| AK1 | `reset` changes lists by assigning the union whole | no write where nothing reads | the list-change test, and the fill check | CAUGHT |
| AK2 | `assign` changes lists by assigning the union whole before it copies | no write past what is copied | the copy test, and the fill check | CAUGHT |
| AK3 | a lookup started in place writes its answers' storage | the slot's last answers are left | the in-place test, and the fill check | CAUGHT |
| AK4 | a negative put fills a local and copies it | a negative entry resets the slot's answers | the fill check | CAUGHT |
| AK5 | a negative put leaves the slot's answers as they were | a negative entry holds no records | the negative-over-answered test | CAUGHT |
| AK6 | `reset` leaves the kind as it was | the kind names the list in use | the kind's assertions, across the codec's tests | CAUGHT |
| AK7 | `assign` leaves the kind as it was | the kind names the list in use | the copy test, and the cache's PTR and MX tests | CAUGHT |

## The benchmark programs' own memset

2026-09-30. On Linux every `memset` a Zig 0.16 program calls is compiler_rt's, which stores one
octet at a time, so `bench` and `bench-cares` now export the one of pepegrillo's recipe
(`bench/memset.zig`; `performance_zig.md`, "Copies and fills", at 8b5f8b2). A test fills every
length up to three blocks and one, and 4 KiB, from an unaligned start inside a guarded buffer. The
fill check reads the function on x86-64 Linux and arm64 macOS and requires it to call no `memset`:
a loop the compiler turned into one would call itself. Broken against `zig build test-tools` and
`zig build fill-check`. Eight mutations: seven `CAUGHT`, and one that changes nothing today.

`nm` over each program's ReleaseSafe build for x86-64 and arm64 Linux puts `memset` at the address
of `memset.memset`, where before it was at compiler_rt's. A program built the same way over a C
shared library that calls `memset` showed the library's calls reaching glibc's on both targets: the
program's definition takes the hidden visibility of compiler_rt's, so the dynamic linker never
offers it outside the program. c-ares is a shared library on CI's runner too, so its calls reach
glibc's.

MS7 is equivalent today. Without the barrier in the block loop, the compiler keeps the vector
stores as a loop on both targets; the fill check would read the call on the day it made one. The
export has no mutation of its own: removing it changes only what the Linux rows cost, and `nm`
shows it.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| MS1 | the last block is not stored | every octet of the fill is set | the fill test | CAUGHT |
| MS2 | the last block ends an octet past the fill | no octet past the fill is set | the fill test | CAUGHT |
| MS3 | the loop steps two blocks at a time | every octet of the fill is set | the fill test | CAUGHT |
| MS4 | the octet stored is the value's second | the low octet of the value is stored (C11 §7.24.6.1) | the fill test | CAUGHT |
| MS5 | a short fill stores every octet at the first | every octet of the fill is set | the fill test | CAUGHT |
| MS6 | the fill returns no address | the fill returns its destination | the fill test | CAUGHT |
| MS7 | the block loop has no barrier | the function calls no `memset` | nothing: the compiler keeps the loop | NOT CAUGHT, equivalent |
| MS8 | the short loop has no barrier | the function calls no `memset` | the fill check, on x86-64 and arm64 | CAUGHT |

## The responder counts a reply before it sends it

2026-09-30. CI's engine job failed on 0fcb750: the test of the responder's own process read 99
answers after its 100th reply. The responder counted a reply after sending it, so the reply could
reach the test before the count moved. It now counts first, and takes the count back when a send
fails. A new test reads the count after each of ten thousand replies. Broken against
`zig build test-cares` on macOS: in six runs with the old order, the first short count came
between the 286th and the 471st reply. One mutation, `CAUGHT` in every run.

The count taken back after a failed send has no mutation: no test can make a send on the loopback
fail.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RO1 | the responder counts a reply after it sends it | a process that has a reply reads a count that holds it | the count test, in six runs of six | CAUGHT |

## The engine under the fill check

2026-10-01. The fill check reads the engine of `io/` over rotor, built ReleaseSafe as a consumer
builds it by default: its start, its completions and its take. Its first run found a TCP
connection's reset filling 66,168 bytes at every opening and shut, since it assigned the whole slot
and the frame is `undefined`; the same assignment wrote over the address a cancelled connect still
borrows (design §19 step 13, the stream's rule 10). A reset now sets each field to its default but
the frame, the address, the queue's entries and the TLS records (`io/io_reset.zig`). What the
engine reaches besides is the EDNS padding the library's probes know, and one fill of rotor's on
each target that no lookup pays. Broken against `zig build test-io` and `zig build fill-check`.
Nine mutations, nine `CAUGHT`.

A small field written in place, as the address is, compiles to stores and no `memset`, so the fill
check misses EF4 and the reset's own test catches it.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| EF1 | a reset assigns the whole slot again | a reset writes no buffer, and fills nothing | the reset test, and the check on both targets | CAUGHT |
| EF2 | a reset assigns the whole queue | the queue's entries keep their bytes | the reset test, and the check on both targets | CAUGHT |
| EF3 | a reset writes the frame | the frame keeps its bytes | the reset test, and the check on both targets | CAUGHT |
| EF4 | a reset writes the address | a connect's borrowed address is not written | the reset test | CAUGHT |
| EF5 | a reset clears the incarnation | an opening's events are told from the last's | the reset test | CAUGHT |
| EF6 | a TLS reset assigns the whole state | the records keep their bytes | the TLS reset test | CAUGHT |
| EF7 | a TLS reset writes the records in | the records keep their bytes | the TLS reset test | CAUGHT |
| EF8 | a reset writes the fields kept too | a field kept keeps its value | the helper's, the reset's and the TLS reset's tests | CAUGHT |
| EF9 | a reset sets no field | every other field goes back to its default | seven tests, the engine's TCP and TLS paths among them | CAUGHT |

## rotor's mode

2026-10-01. rotor's build gives its modules the mode a dependent asks for, and Debug when asked for
none. cocuyo's build asked for none, so the comparison compiled rotor `-ODebug` under a ReleaseSafe
engine, and the README told a consumer to do the same. The comparison now asks for rotor's release
build, the examples follow `-Drelease`, and the README asks for it. The comparison and the fill
check refuse to build over a rotor of any other mode. Broken against `zig build bench-cares` and
`zig build fill-check`. Two mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RM1 | the comparison's rotor is asked for no mode | the comparison times a ReleaseSafe rotor | the build, which refuses the comparison | CAUGHT |
| RM2 | the fill check's rotor is asked for no mode | the fill check reads a ReleaseSafe rotor | the build, which refuses the check | CAUGHT |

## The sanitizer's own control

`-Dsanitize-thread` puts the comparison's tests under ThreadSanitizer on Linux. On 2026-09-22 a
planted race — two threads writing one plain integer after a barrier — passed under it, both
alone and through the build. Zig 0.16 builds Debug for x86_64 Linux with its own backend, which
instruments no access and says nothing about it. LLVM instruments. The tests and a control built
from `bench/end_to_end/race_control.zig` now share one backend setting, and the build requires
the control's report, exit status 66, before the tests run.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| T1 | build the sanitized tests on the default backend again | the sanitizer instruments the tests | the build's control, which exits 0 | CAUGHT |

## Planned, later steps

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

## The buffer group's alignment

rotor asks for a buffer group's memory at 64 KiB, and no platform delivers it to a global: the
object file keeps the promise and the loader slides the image by a page, 16 KiB on arm64 macOS.
The group's storage used to claim the 64 KiB in its type. Debug computed on the real address and
failed at the alignment assert; ReleaseSafe believed the type, folded the arithmetic that finds
the aligned window, and reached `unreachable` — the abort that looked like a `pthread_join` in a
trace whose frames were all wrong. The storage now claims nothing, and the window is found at
run time.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| N1 | let the datagram group's storage claim 64 KiB again | the storage claims no more than a page | `zig build test-io` refuses to compile | CAUGHT |

## The lint's own names

A rule's list of forbidden names is checked by nothing when a name in it has moved or gone: the
tree passes either way, which is how `std.crypto.random` and `std.net` sat in two lists guarding
nothing. Since 2026-09-22 each list is asserted at compile time against the standard library it
names, so the next Zig release that moves something fails the build with the entry in the
message rather than dropping a guard in silence.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| M1 | put `std.crypto.random` back in the determinism list | the list names what exists | `zig build test-tools` refuses to compile | CAUGHT |

## The build's own mutation

`zig build lint` runs the rules twice: over the tree, which must be clean, and over a canary tree
written into the build cache that holds one violation of every rule, which must exit 1 and name
each rule on stdout. A clean tree cannot show that a rule is live — a run that dropped a rule
passes a tree that rule would have passed anyway. The canary is the mutation, and it is wired into
`build/lint.zig` rather than recorded here, because it runs on every build.

`zig build graph-check` is the same idea for the module graph: it compiles a fixture that imports
`config` from a module of the `resolver` shape and requires the compiler to reject it, with a
positive control importing `core` that must compile, so a failure means what it says.

`zig build consumer-check` is the third: `test/consumer/` is a package that depends on cocuyo by
relative path, and the check builds it twice. Once as it stands, which must build and is the
control; once with `-Dreach-inside`, which asks for `sim` and must fail, because the build
registers `cocuyo` and no other name (design §20). Neither run is recorded as a mutation here,
for the same reason the canary is not: both run on every build.

## The file-length rule over the models

`spec/lean/Spec/LookupProofs.lean` reached 549 lines with no rule reading it: the file-length rule
read `.zig` and `.sh` files, and the lint walked no directory under `spec/`. Since 2026-09-24 the
rule reads `.lean` and `.tla` files too, the lint walks `spec/`, and the proofs are split into
`LookupProofs.lean` and two modules under `LookupProofs/`. Broken against `zig build test-tools`
and `zig build lint`. FL3 was `NOT CAUGHT`, as dropping any other directory from the lint's list
was: a clean tree holds nothing for the dropped directory to find. Since 2026-09-25
`tools/lint_coverage.zig` reads every tracked file `git ls-files` names, and fails on each one
whose extension a rule or the complexity score reads and which neither is handed, `test/`'s
fixtures apart (c4milo/cocuyo#12). Its first run read `build.zig` as unread by the rules, which it
passes, so the rules read it now. FL5 to FL7 are its own. Seven mutations, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| FL0 | a model grows past 500 lines | the length limit | `zig build lint`, naming the file | CAUGHT |
| FL1 | the rule leaves `.lean` files unread | a model is bounded | the models' fixture test | CAUGHT |
| FL2 | the rule's scope leaves `spec/` out | a model is bounded | the models' fixture test | CAUGHT |
| FL3 | the lint walks no directory under `spec/` | a model is bounded | the coverage check, naming each model | CAUGHT |
| FL5 | the complexity score walks no directory under `tools/` | a tool's functions are scored | the coverage check | CAUGHT |
| FL6 | the rules are not handed CLAUDE.md | it renders as written | the coverage check | CAUGHT |
| FL7 | a directory whose name starts like a walked one counts as walked | a path is under a directory | the coverage check's own test | CAUGHT |

## The resolver in the caller's loop

Design §24 step 2, 2026-09-25. The engine is exported as `cocuyo_rotor`, its type `Resolver`,
with its `rotor` import left for the consumer to bind. `test/consumer/` builds a program that
binds its own rotor and runs the resolver on its loop beside a timer of its own. Broken against
`zig build test-io` and `zig build consumer-check`. EX2 was `NOT CAUGHT` at first: the consumer
depends on cocuyo by path, and a path dependency reads the whole tree, so a path the manifest
left out was invisible to it. The build now refuses to compile when a registered module's root
is not under a shipped path, which catches EX2 and its twin for `src/` in every build. Five
mutations, five `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TG1 | `apply` does not read the tag | another component's event goes back untouched | the foreign-event test | CAUGHT |
| EX1 | `cocuyo_rotor` is not registered | a consumer can import the resolver | `consumer-check`, the control | CAUGHT |
| EX2 | the manifest does not ship `io/` | a fetched package holds the resolver | the build, at compile time | CAUGHT |
| EX2b | the manifest does not ship `src/` | a fetched package holds the library | the build, at compile time | CAUGHT |
| EX3 | the consumer binds no rotor into `cocuyo_rotor` | the loop is the consumer's type | `consumer-check`, the control | CAUGHT |

## chapulin's hooks, once in an image

Design §24 step 2, 2026-09-25. `ch_rand_bytes` and `ch_assert_fail` moved out of the DoT session
into `chapulin_hooks`, a module the image binds once for every user of chapulin, with a
thread-local stream each user enters around the calls that can draw. HK3 was first caught by a
link error rather than a test. The tests never call `handshake`, so with `start`'s use gone
nothing referenced the module, and its exports were never emitted. The session now references
the module whenever it is linked, and HK3 is caught by the start test. HK4 removes that
reference, and nothing here catches it, since every program that links the session also starts
one. Broken against `zig build test-chapulin_hooks` and `zig build test-chapulin`. Four
mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| HK1 | the stream is one global rather than one a thread | a thread per core draws from its own | the two-thread test, by the assertion in `enter` | CAUGHT |
| HK2 | `enter` sets no stream | a draw comes from the stream entered | the draw test, by the hook's panic | CAUGHT |
| HK3 | the session enters no stream when it starts | chapulin draws when a handshake starts | the session test, by the hook's panic | CAUGHT |
| HK4 | the session does not reference the hooks module | the image links the hooks with the session | nothing: **every program here starts a session** | NOT CAUGHT |

## No state every thread shares

Design §24 step 2, 2026-09-25. pepegrillo's `global_state` rule, at `6fcb273`, reports a
container-level `var` that is not `threadlocal`. cocuyo runs it over `src/` and `io/`, and its
canary tree holds one. pepegrillo's own commit records GS1 to GS6, the rule's checks. The first
run here found five shared `var`s. Four were test fixtures, and the fifth was the twin's network,
which two threads' loops would have reset under each other. All five are thread-local now.
Broken against `zig build test-tools` and `zig build lint`. Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| GC1 | the rule's scope leaves `io/` out | the engine keeps no shared state | the scope test | CAUGHT |
| GC2 | the rule is not registered | every rule checks the build | the registered-rules test, and the canary | CAUGHT |
| GC3 | the canary holds no shared `var` | the canary shows the rule is live | the canary run | CAUGHT |
| GC4 | the twin's network is shared by every thread again | a thread per core shares nothing | `zig build lint` | CAUGHT |

## The request rules in the engine model

Design §24 step 3, 2026-09-25. The engine model gains requests over DoQ and DoH:
`spec/tla/engine/EngineRequest.tla`, three request configurations, and eight checks. Each
mutant in `spec/tla/engine/mutants/` puts one operator of `EngineMutants.tla` in place of the
rule's, and TLC must find the check that catches it. All run on one server and one lookup except
RQ9. There, time moves while a request is on a connection only when another connection is idle,
so it needs two servers. Every new check is caught by one mutant at least. RQ12 to RQ15 came on
2026-09-25 with request rule 13, a GOAWAY that drains its connection (c4milo/cocuyo#17), and four
checks, one each; RQ14 and RQ15 need two lookups, one on a stream and one that waits. RQ16 to
RQ20 came on 2026-09-26 with request rules 14 to 16, the request connection over TCP that DoH
over HTTP/2 runs on (c4milo/cocuyo#18), and four checks. Each runs on one server and one lookup
over TCP, and RQ17 and RQ18 break the same check from two sides, the receive and the first flight.
Writing the model moved rule 14: a connection that waits for an earlier opening's connect opens at
that connect's end, since opening at the drive's end left a request the loop refused failed after
the drive had polled. RQ21 and RQ22 came the same day with request rule 17, the transport read
after it moves (c4milo/cocuyo#18), and one check. Each runs on one server and one lookup over TCP.
RQ21 breaks the check. RQ22 leaves a request waiting on a connection that is up, which `streams
when up` catches before the new check does. Writing the rule changed `goaway fails none`: the
stream colibri held, and told first at the read that brings a GOAWAY, is not the GOAWAY's to fail.
Twenty-two mutations, twenty-two `CAUGHT`.

Writing the model again moved every walk TLC takes. TLC's simulation draws on its random stream as
it enumerates a quantifier's set, a check's included, so any change to what the model evaluates
changes the walks. The committed walks were written again, and every engine mutation was run
against them: each is caught. ET3, ET6 and ET14, which the old short walks caught, are caught at
walk 12005 of the full run. The picked walks are the full run's 6, 41, 4046, 8011, 9182, 12005,
12070, 12900 and 13842, and each mutation the picks are for is caught by them.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RQ1 | a request its lookup left is never cancelled | request rule 6 | requests current | CAUGHT |
| RQ2 | the handshake's end is taken whatever protocol it negotiated | request rule 2 | up on protocol | CAUGHT |
| RQ3 | a request opens its stream before its connection is up | request rule 4 | streams when up | CAUGHT |
| RQ4 | a connection that fails tells none of its requests | request rule 7 | requests placed | CAUGHT |
| RQ5 | a datagram is sent while the buffer is lent to the one before | request rule 8 | datagram lent | CAUGHT |
| RQ6 | a connection that closes forgets its buffer is lent | request rule 8 | datagram lent | CAUGHT |
| RQ7 | a connection that resumes leaves its server's ticket kept | request rule 10 | request ticket spent | CAUGHT |
| RQ8 | a receive the loop refused is not armed again | the datagram's rule 1 | listening | CAUGHT |
| RQ9 | a connection closes for idleness with requests on it | request rule 9 | streams when up | CAUGHT |
| RQ10 | a connection that closes still owes a datagram | request rule 7 | closed empty | CAUGHT |
| RQ11 | a receive is armed beside the one that is current | the datagram's rule 1 | receive current | CAUGHT |
| RQ12 | a GOAWAY fails its connection | request rule 13 | goaway fails none | CAUGHT |
| RQ13 | a draining connection stays open once its last stream has ended | request rule 13 | draining has streams | CAUGHT |
| RQ14 | a connection that fails while it drains fails the requests that wait | request rule 13 | waiting kept | CAUGHT |
| RQ15 | a request taken while its connection drains opens a stream on it | request rule 13 | drain shrinks | CAUGHT |
| RQ16 | a slot opens again while a connect of an earlier opening still borrows its address | request rule 14 | connect lent | CAUGHT |
| RQ17 | a receive is armed with the connect, before the connect has succeeded | request rule 14 | connect first | CAUGHT |
| RQ18 | the transport makes its first flight with the connect, before it has succeeded | request rule 14 | connect first | CAUGHT |
| RQ19 | a send that went short is taken for a whole one, and its rest is lost | request rule 15 | rest first | CAUGHT |
| RQ20 | a receive that ended with no octets is armed again, and the connection stays up | request rule 15 | ended closes | CAUGHT |
| RQ21 | a send's end reads nothing of the transport, which keeps what it held | request rule 17 | held while sending | CAUGHT |
| RQ22 | a request held back waits, and the drain the transport holds is not read | request rule 17 | streams when up | CAUGHT |

## DoQ in the engine

Design §24 step 4, 2026-09-25. The engine carries DoQ over its request transport:
`io/io_request.zig`, `io/io_request_connection.zig` and `io/io_request_events.zig`, driven on the
twin's QUIC, `sim.quic`. DQ5 was `NOT CAUGHT` at first. A lookup that moves to the next server
takes a new request, which drops the old one itself, so only a lookup that leaves and takes none
needs the drive's cancel. A cancelled lookup does, and its test was written. Each mutation was
broken against `zig build test-io`. Thirteen mutations, thirteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DQ1 | the handshake's end is taken whatever protocol it negotiated | request rule 2, RFC 9250 §4.1 | the other-protocol test | CAUGHT |
| DQ2 | a DoQ answer's prefix is not held to the stream's end | request rule 5, RFC 9250 §4.2, §4.3.3 | the message test, and the malformed-answer test | CAUGHT |
| DQ3 | a DoQ answer's ID is not held to 0 | request rule 5, RFC 9250 §4.3.3 | the message test, and the malformed-answer test | CAUGHT |
| DQ4 | an answer longer than the buffer is read | request rule 5 | the tiny-buffer test, by the slice's bound | CAUGHT |
| DQ5 | a request its lookup left is never cancelled by the drive | request rule 6 | the cancelled-lookup test | CAUGHT |
| DQ6 | a request goes on an idle connection near its negotiated timeout | request rule 9, RFC 9250 §4.4 | the near-timeout test | CAUGHT |
| DQ7 | an idle connection never closes | request rule 9 | the idle-close and ticket tests | CAUGHT |
| DQ8 | a datagram is sent while the buffer is lent to the one before | request rule 8 | the exhaustion and near-timeout tests, by the send's assertion | CAUGHT |
| DQ9 | an event of an opening that is gone is taken as the current one's | the stream's rule 2 | the ticket and near-timeout tests | CAUGHT |
| DQ10 | a closing connection reads what arrives | request rule 9 | the closing test | CAUGHT |
| DQ11 | a receive that ran out of buffers fails its connection | the datagram's rule 1 | the exhaustion test | CAUGHT |
| DQ12 | a connection that fails tells none of its requests | request rule 7 | the malformed-answer, refused-socket and tiny-buffer tests | CAUGHT |
| DQ13 | a datagram whose send failed leaves its connection standing | request rules 7 and 8 | the failed-send test | CAUGHT |

## Requests on the model's walks

Design §24 step 4, 2026-09-25. The replay walks the request configurations, one slot or two and
two servers, over the twin's QUIC. The run now has ten configurations, and the two request ones
come first, so every walk the section on TLC's walks names comes 4,000 later: its walk 51 is walk
4051, and 8573 is 12573. The seven walks it picked are byte for byte the ones TLC writes there.
ET5's edit no longer applied once the ticket's lapse moved into `fresh`, and was written again; it
is caught at walk 12095, as it was at 8095.

Each mutation below breaks the request path the way one of the model's mutants breaks its rule
(RQ1 to RQ11), or the datagram the loop refused, and was broken against the committed walks and
TLC's full run, 20,000 walks and 4,020,000 events. The short walks miss RW6 and RW10, so the
picked walks keep walks 7 and 37 as well, nine in all. Eleven mutations, eleven `CAUGHT`.

| # | Mutation | The short walks | The full run | Status |
| --- | --- | --- | --- | --- |
| RW1 | a request its lookup left is never cancelled by the drive | walk 2 | not run | CAUGHT |
| RW2 | the handshake's end is taken whatever protocol it negotiated | walk 6 | not run | CAUGHT |
| RW3 | a connection that fails tells none of its requests | walk 1 | not run | CAUGHT |
| RW4 | a datagram is sent while the buffer is lent to the one before | walk 2 | not run | CAUGHT |
| RW5 | a connection that closes forgets its buffer is lent | walk 2 | not run | CAUGHT |
| RW6 | a connection that resumes leaves its server's ticket kept | no | walk 37, picked | CAUGHT |
| RW7 | a receive the loop refused is not armed again | walk 2 | not run | CAUGHT |
| RW8 | a connection closes for idleness with requests on it | walk 2 | not run | CAUGHT |
| RW9 | a connection that closes keeps the datagram the loop refused | walk 1 | not run | CAUGHT |
| RW10 | an event of an opening that is gone is taken as the current one's | no | walk 7, picked | CAUGHT |
| RW11 | a datagram the loop refused is dropped | walk 1 | not run | CAUGHT |

## An engine with no TCP connection

c4milo/cocuyo#14, 2026-09-25. An engine built with `tcp_connections = 0`, which DoQ alone needs,
did not compile: the TCP path indexed an array of none. Each TCP entry point now returns at compile
time when the engine keeps no connection, and a lookup that asks for a stream is told it failed.
The DoQ tests run on such an engine, and so do the replay's request walks. Broken against `zig
build test-io`. Two mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| NT1 | an engine with no connection leaves a lookup that asks for a stream waiting | the lookup fails over at once | the no-TCP test | CAUGHT |
| NT2 | an entry point indexes the connections of an engine that keeps none | an engine of none compiles | the build | CAUGHT |

## A responder on the twin's QUIC port

Design §24 step 4, colibri over the twin, 2026-09-25. The twin is in `src/`, which depends on
nothing, so a colibri server cannot live in it. A test puts a responder on a scripted server's QUIC
port instead: the twin hands it every datagram sent there, delivers what it answers with, and wakes
it at its deadline. Broken against `zig build test-sim`. Three mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RP1 | a datagram to a QUIC port goes to the twin's QUIC though a responder is there | the responder hears what is sent to its port | the echo-responder test | CAUGHT |
| RP2 | the twin never wakes a responder | a responder is woken at its deadline | the echo-responder test | CAUGHT |
| RP3 | the clock does not stop at a responder's deadline | the deadline comes before later deliveries | the echo-responder test | CAUGHT |

## colibri under the request interface

Design §24 step 4, 2026-09-25. `cocuyo_quic` puts colibri's QUIC, at `d2c1431`, under the engine's
request interface, over a session that encrypts nothing. Nine tests run the engine over colibri's
client and colibri's server on the twin, and two run a client and a server in memory. QC2 and QC4
were `NOT CAUGHT` at first: the drain test cancelled each lookup while its connection handshook,
so no stream was ever opened, and it was written again to open one. The code a third check guarded
was removed instead: an answer longer than the engine's buffer fails its connection, so reading the
rest of it served nothing. QC3 was `NOT CAUGHT` too: colibri's server acknowledges a request in the
packet that answers it, so the client never held an answer whose request was unacknowledged. The
unacknowledged-answer test turns that packet's ACK frame into PADDING, which the session that
encrypts nothing leaves in the clear, so colibri sends the request again at its probe timeout
(c4milo/cocuyo#15). Broken against `zig build test-io` and `zig build test-cocuyo_quic`. Eight
mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| QC1 | the connection's own close is told as the connection ending | a request taken while it closes reopens it (request rule 9) | the held-close test | CAUGHT |
| QC2 | a cancelled stream is not drained | its place in colibri's table comes back | the drain test | CAUGHT |
| QC3 | a request's bytes are freed once its answer is told | colibri reads them until the server has them | the unacknowledged-answer test: the request's stream never closes | CAUGHT |
| QC4 | a stream with no credit fails the connection | a request waits for credit (request rule 4) | the drain test | CAUGHT |
| QC5 | a cancel sends no STOP_SENDING | RFC 9250 §4.3.1 | the STOP_SENDING test, and the drain test | CAUGHT |
| QC6 | colibri's deadline is never read | the engine's timer covers colibri's (request rule 11) | the loss test, and the held-close test | CAUGHT |
| QC7 | the handshake's end is never told | the connection comes up | every test over colibri | CAUGHT |
| QC8 | the test server takes a new connection on a reused socket for the old one | a reopening is heard | the held-close test | CAUGHT |

## chapulin under colibri

Design §24 step 4, 2026-09-25. `io/io_chapulin_quic.zig` puts chapulin's QUIC object, at
`3a3fa40`, behind colibri's TLS provider and packet suite. What it checks of its own is its build
record and the servers chapulin's QUIC mode can reach: one with a name and anchors, never one
known by pins. The rest is chapulin's, and `tools/doq_live/run.sh` shows it against AdGuard and
NextDNS: both answered over DoQ and resumed, and a wrong name and a wrong root each ended in
`AllServersFailed`. Broken against `zig build -Dchapulin=<checkout> test-chapulin-quic`. Three
mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CQ1 | a server known by SPKI pins is started | chapulin's QUIC mode takes no pins | the refusal test | CAUGHT |
| CQ2 | a server known by no name is started | chapulin's QUIC mode checks a hostname | the refusal test, by chapulin's own assertion | CAUGHT |
| CQ3 | the build record is not compared | the object is the one the headers describe | the build-record test | CAUGHT |

## A DoT server known by pins alone

2026-09-25. The DoT session gave chapulin the context's anchors whatever the server, so a server
known by pins alone, RFC 8310 §6.3's "SPKI + IP", reached chapulin with anchors and no hostname,
which chapulin refuses at its start (its webpki_cfg.c): every lookup to it ended in
`AllServersFailed`. The session gives such a server its pins and nothing else. The test that
starts one beside a context of anchors was run on the code before the fix, which is PA1, and
failed. Broken against `zig build -Dchapulin=<checkout> test-chapulin`. One mutation, one `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| PA1 | a server with no name gets the context's anchors and clock | a server known by pins alone starts | the pins-beside-anchors test | CAUGHT |

## A DoH server's URI template

Design §24 step 5, 2026-09-25. The engine splits a DoH server's template into the port its
connection goes to, the name its certificate is checked against, the authority and the path's
template (`io/io_request_template.zig`). `cocuyo_quic` expands the path with `dns`, the one
variable defined (`io/io_quic_template.zig`). Four checks were `NOT CAUGHT` at first. UT8 was a
refusal of the `#` operator that nothing needed: a character that is not an operator is read as a
varname's, and `#` is none, so the refusal was removed and UT8 became the operator table gaining
`#`. UT18 and UT19 had no test, and UT5 none for a port Zig's parser takes and a URI does not,
`+443` or `4_43`: each now has one. The split's are broken against `zig build test-io`, and the
expansion's against `zig build test-cocuyo_quic`. Twenty-three mutations, twenty-three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| UT1 | any scheme is taken | DoH is https alone (RFC 8484 §5) | the authority refusals | CAUGHT |
| UT2 | the scheme is compared by case | schemes are case-insensitive (RFC 3986 §3.1) | the case and port test | CAUGHT |
| UT3 | the host's characters are not checked | no userinfo (RFC 9114 §4.3.1), no IP literal | the authority refusals | CAUGHT |
| UT4 | an IPv4 address is taken as a host | the session checks a name (RFC 3986 §3.2.2) | the authority refusals | CAUGHT |
| UT5 | a port's characters are not checked | `port = *DIGIT` (RFC 3986 §3.2.3), where Zig's parser takes `+` and `_` | the authority refusals | CAUGHT |
| UT6 | an expression does not end the authority | the TLS name cannot change with a query | the operator test | CAUGHT |
| UT7 | a `#` literal is copied | a fragment is not part of the request | the path refusals | CAUGHT |
| UT8 | the operator table gains `#` | a fragment is not part of the request | the path refusals | CAUGHT |
| UT9 | a prefix on `dns` is taken | a prefix would cut the query | the path refusals | CAUGHT |
| UT10 | a template with no `dns` is taken | a GET carries the query only there (RFC 8484 §4.1) | the path refusals | CAUGHT |
| UT11 | a named operator writes no `dns=` | Appendix A's `named` | RFC 8484's example, the operator test | CAUGHT |
| UT12 | a second variable takes `first` again | Appendix A's `sep` | the operator test | CAUGHT |
| UT13 | an empty path stays empty | `:path` is `/` at least (RFC 9114 §4.3.1) | the operator test | CAUGHT |
| UT14 | an expansion may carry on the authority | the path starts with `/` or `?` | the path refusals | CAUGHT |
| UT15 | a character past ASCII is copied as it is | it goes pct-encoded (RFC 6570 §3.1) | the literal test | CAUGHT |
| UT16 | every ASCII literal is taken | the characters §2.1 excludes | the path refusals | CAUGHT |
| UT17 | variable names are compared in any case | names are case-sensitive (§2.3) | the path refusals | CAUGHT |
| UT18 | a `%` literal is not checked | `pct-encoded` (RFC 3986 §2.1) | the path refusals | CAUGHT |
| UT19 | a dec-octet may have a leading zero | `dec-octet` (RFC 3986 §3.2.2) | the registered-name test | CAUGHT |
| UT20 | a varspec that is none is skipped | `varspec` (RFC 6570 §2.3) | the path refusals | CAUGHT |
| UT21 | port 0 is taken | no datagram goes to it | the authority refusals | CAUGHT |
| UT22 | an empty port is refused | it is 443 (RFC 9110 §4.2.2) | the case and port test | CAUGHT |
| UT23 | a template with no port goes to 853 | it goes to 443 (RFC 9110 §4.2.2, RFC 9114 §3.1) | RFC 8484's split, the port 443 test | CAUGHT |

## DoH in the engine

Design §24 step 5, 2026-09-25. The engine speaks DoH over the twin: a connection on `h3` to its
template's port, an answer with its `Age`, and a failed request for a response that is not 2xx or
does not hold a DNS message, which counts against its server. The twin's scripted servers answer a
request on `h3` as a response, whose status, `Age` and media type their scripts give. Broken
against `zig build test-io`. Eight mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DE1 | a DoH connection wants `doq` | its protocol is `h3` (RFC 9114 §3.2) | the DoH answer test | CAUGHT |
| DE2 | any status carries an answer | a 2xx alone does (RFC 8484 §4.2.1) | the non-2xx test | CAUGHT |
| DE3 | a 1xx carries an answer | 2xx starts at 200 (RFC 9110 §15.3) | the non-2xx test | CAUGHT |
| DE4 | a 3xx carries an answer | 2xx ends at 299 (RFC 9110 §15.3) | the non-2xx test | CAUGHT |
| DE5 | content that is not a DNS message is taken | request rule 12 | the media type test | CAUGHT |
| DE6 | the `Age` is dropped | TTLs are lowered by it (RFC 8484 §5.1) | the `Age` test | CAUGHT |
| DE7 | a DoH connection goes to 443 whatever its template says | the template's port (RFC 9114 §3.1) | the DoH answer test | CAUGHT |
| DE8 | a connection goes to its endpoint's port | the port its opening chose | the DoQ answer test | CAUGHT |

## What a DoH response says of its content

Design §24 step 5, 2026-09-25. `io/io_quic_response.zig` reads a DoH response's `Age` (RFC 9111
§5.1, §1.2.2), and whether its content is a DNS message in no content coding: its `Content-Type`
(RFC 8484 §6, RFC 9110 §8.3.1) and each `Content-Encoding` line (RFC 9110 §8.4). Broken against
`zig build test-cocuyo_quic`. Eleven mutations, eleven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| HR1 | an `Age` list is read whole | its first member counts (RFC 9111 §5.1) | the `Age` test | CAUGHT |
| HR2 | an `Age` that is not digits is read | an invalid `Age` is ignored (§5.1) | the `Age` test | CAUGHT |
| HR3 | an `Age` too long to parse is 0 | it is 2^31 (§1.2.2) | the 2^31 test | CAUGHT |
| HR4 | an `Age` past 2^31 wraps | it is 2^31 (§1.2.2) | the 2^31 test | CAUGHT |
| HR5 | no `Content-Type` is a DNS message | the recipient may assume octets (RFC 9110 §8.3) | the media type test | CAUGHT |
| HR6 | the media type is compared by case | type and subtype are case-insensitive (§8.3.1) | the media type test | CAUGHT |
| HR7 | a parameter is read as the subtype | parameters follow `;` (§8.3.1) | the media type test | CAUGHT |
| HR8 | a coding is compared by case | codings are case-insensitive (§8.4.1) | the coding test | CAUGHT |
| HR9 | an empty member is a coding | empty list elements are ignored (§5.6.1.2) | the coding test | CAUGHT |
| HR10 | only the first coding is read | every coding applied is listed (§8.4) | the coding test | CAUGHT |
| HR11 | a longer media type that starts the same is taken | the type is `application/dns-message` (RFC 8484 §6) | the media type test | CAUGHT |

## colibri's HTTP/3 under the request interface

Design §24 step 5, 2026-09-25. `cocuyo_quic` speaks DoH over colibri's `h3` when its options ask
(`io/io_quic_h3.zig`): the GET, the answer buffers a request waits for, the response's status,
`Age` and media type, a cancel, a GOAWAY and the idle close. Seven tests run a client against
colibri's `h3` server in memory, and nine the engine over both on the twin. Four were `NOT CAUGHT`
at first. QH2 and QH18, `h3` never started or its streams never sent, go unseen by colibri's
server, which answers without the client's SETTINGS, so a test now requires them to arrive (RFC
9114 §6.2.1). QH21, the idle close with DoQ's code, needed the server to keep the code it heard.
QH16 needed more answered requests on one connection than it has slots. And one check guarded
nothing: an interim response's fields are written over by the final one's, which always comes, so
skipping it was removed. QC1 to QC8 were broken again after the streams and the test server
changed under them, and each is still `CAUGHT`. Broken against `zig build test-cocuyo_quic` and
`zig build test-io`. Twenty mutations, twenty `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| QH1 | a DoH connection lets the server open no unidirectional stream | RFC 9114 §6.2 asks for 3 | the in-memory GET test | CAUGHT |
| QH2 | `h3` is never started | SETTINGS go first on the control stream (RFC 9114 §6.2.1) | the in-memory GET test | CAUGHT |
| QH3 | a request takes a buffer another holds | a request waits for a free one | the buffer test, the more-lookups test | CAUGHT |
| QH4 | `:path` may be indexed | its N bit (RFC 9204 §4.5.4, request rule 12) | the GET's lines test | CAUGHT |
| QH5 | the GET asks for `gzip` | `accept-encoding: identity` (request rule 12) | the GET's lines test | CAUGHT |
| QH6 | the `Age` is not read | TTLs are lowered by it (RFC 8484 §5.1) | the in-memory response test, the engine's `Age` test | CAUGHT |
| QH7 | a coding is not read | a coded answer is no DNS message (request rule 12) | the in-memory response test, the engine's fail-over test | CAUGHT |
| QH9 | content past the buffer is not counted | the engine fails an answer too long (request rule 5) | the past-the-buffer test | CAUGHT |
| QH10 | a cancel keeps its answer buffer | the buffer comes back | the buffer test | CAUGHT |
| QH11 | a cancel keeps its request slot | the slot comes back | the cancelled-lookups test | CAUGHT |
| QH12 | a stream past a GOAWAY is left open | the server will not process it (RFC 9114 §5.2) | the GOAWAY reset test | CAUGHT |
| QH13 | a request opens after a GOAWAY | the server takes no new stream (§5.2) | the GOAWAY reset test | CAUGHT |
| QH14 | a GOAWAY closes at once | the answers it promised come first (§5.2) | the engine's GOAWAY test | CAUGHT |
| QH15 | an answered stream keeps its buffer | the buffer comes back | the in-memory GOAWAY test, the more-lookups test | CAUGHT |
| QH16 | a stream's sending half is never read | a slot comes back once the server has its GET | the more-lookups test | CAUGHT |
| QH17 | a slot comes back once its answer is told | colibri reads its bytes until the server has them | the unacknowledged-answer tests | CAUGHT |
| QH18 | colibri reads `h3`'s streams from the slots | `h3` serves its own (colibri decision 79) | the in-memory GET test | CAUGHT |
| QH19 | a template too long is taken | its GET must fit a slot | the template-too-long test | CAUGHT |
| QH20 | a GOAWAY closes while answers are still due | the close waits for them | the engine's GOAWAY test | CAUGHT |
| QH21 | the idle close carries DOQ_NO_ERROR | H3_NO_ERROR (RFC 9114 §8.1) | the engine's idle test | CAUGHT |

## Pins over QUIC

2026-09-25. chapulin's QUIC mode takes pins as its record transport does since `3d5db4e` (its
decisions 64 and 65), so the DoQ session tells it what the DoT session does: a name with the
context's anchors and the clock, and pins as they are, a server known by pins alone getting no
anchors and no clock. The refusal CQ1 and CQ2 broke is gone, and with it those two mutations; CQ3
stands. The tests now start chapulin, which reads the configuration at its start. The live checks
resolve through AdGuard over DoQ and Cloudflare over DoT by each one's leaf key alone, with a
backup pin, and refuse each by the backup alone and by its issuer's key. Broken against `zig build
-Dchapulin=<checkout> test-chapulin-quic`. Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CP1 | a server known by pins alone gets the context's anchors | chapulin refuses pins beside anchors with no name (its decision 64) | the pins-alone test | CAUGHT |
| CP2 | the pins are not handed to chapulin | RFC 7858 §4.2, RFC 8310 §6.4 | the pins-alone test, the name-and-pins test | CAUGHT |
| CP3 | a name is not handed to chapulin | the leaf must carry it (RFC 8310 §6.4) | the name-and-pins test | CAUGHT |
| CP4 | a name gets no anchors | the chain is checked against them | the name-and-pins test | CAUGHT |

## Two engines on two threads

Design §24 step 6, 2026-09-25. Two engines on two threads of one image, each on its own loop,
resolve at once: on the twin in the gate (`io/io_threads_test.zig`), whose scripted servers
answer each thread with a TTL of its own, and over rotor in `examples/threads_rotor.zig`. TP1 is
broken against `zig build test-io`, three runs of three. TP2 is broken against the example built
for aarch64 Linux with `-Dsanitize-thread` and run in a Debian container, where io_uring is
refused and rotor runs epoll; the sanitizer's planted race was reported there first, and the
example without the mutation ran with no report. Two mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TP1 | the twin's network is one for the process | each thread's servers are its own | the two-thread twin test | CAUGHT |
| TP2 | both threads drive one engine | an engine is its thread's alone | ThreadSanitizer over the example: a data race | CAUGHT |

## A GOAWAY drains the connection

Design §24, request rule 13, 2026-09-25 (c4milo/cocuyo#17). A GOAWAY drains its connection: its
streams go on until each is answered or reset, a request taken meanwhile waits, and once no stream
is left it closes and opens again for what waits. A failure while it drains or closes fails the
requests on its streams alone. The model gained the rule and four checks (RQ12 to RQ15 above). The
engine's side is broken against three tests on the twin (`io/io_request_drain_test.zig`), whose
scripted server sends GOAWAY once it has taken its first request, and against the model's walks.

The walks were written again from the new model. The short walks reach a GOAWAY three times, and
catch three of the six. The full run, 20,000 walks and 4,020,000 events, catches all six, and the
picked walks were chosen again from it: 2, 12, 48, 57, 4016, 5560, 8001, 12100, 12706 and 14128,
each the first walk of the run that catches a mutation the short walks miss. The picks catch every
mutation the section on TLC's walks and the one above give them, and SQ10, which the old short
walks caught and the new ones miss, is caught at walk 8001. Three edits no longer applied, and
were written again: ET7, now that sockets are left out for every encrypted configuration, ET13,
now that a ticket's seven-day cap is in `fresh`, and RW2, now that the protocol is the
configuration's. Each is caught as before. Six mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | The drain tests | The walks | Status |
| --- | --- | --- | --- | --- | --- |
| RW12 | a GOAWAY leaves the connection up | request rule 13 | the waiting and failing tests | short walk 2 | CAUGHT |
| RW13 | a connection that fails while it drains fails the requests that wait | request rule 13 | the failing test | full run walk 57, picked | CAUGHT |
| RW14 | a draining connection never closes | request rule 13 | the waiting and cancel tests | short walk 2 | CAUGHT |
| RW15 | a stream's answer does not close the connection it drained | request rule 13 | the waiting test | short walk 18 | CAUGHT |
| RW16 | a cancel does not close the connection it drained | request rules 6 and 13 | the cancel test | full run walk 2, picked | CAUGHT |
| RW17 | a failure while it drains fails the waiting requests with those on streams | request rule 13 | the failing test | full run walk 57, picked | CAUGHT |

## The request connection over TCP

Design §24 step 7a, 2026-09-26 (c4milo/cocuyo#18). The engine holds its request connections as
one set for each transport. The HTTP/2 set runs over TCP: a connection connects before it
handshakes, and a slot opened again while an earlier opening's connect is in flight waits for that
connect's end. A send may go short and its rest goes first, and a receive that ends with no
octets fails the connection (request rules 14 to 16). The twin's transport over TCP
(`src/sim/sim_quic_stream.zig`) carries the twin's QUIC items in frames on a connection to a
scripted server's HTTPS port, and a script can end the server's side of the stream. Eight tests
run the engine over it (`io/io_request_tcp_test.zig`). The walks will reach the same code once the
replay drives the TCP configurations. Nine mutations, nine `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TC1 | a slot connects again while a connect of an earlier opening is in flight | request rule 14 | the test of a connection idle while it connects | CAUGHT |
| TC2 | a connection's receive is armed, and its octets sent, before its connect has succeeded | request rule 14 | the first test, which looks while the connect is in flight | CAUGHT |
| TC3 | a send that went short is taken for a whole one, and its rest is lost | request rule 15 | the short send test | CAUGHT |
| TC4 | the rest of a send that went short is sent from the buffer's start | request rule 15 | the short send test | CAUGHT |
| TC5 | a receive that ended with no octets is armed again, and the connection stays up | request rule 15 | the test of the server's end of the stream | CAUGHT |
| TC6 | a connect that failed leaves its requests waiting on the connection | request rules 7 and 14 | the refused connect test | CAUGHT |
| TC7 | an idle connection that connects is left connecting | request rule 16 | the test of a connection idle while it connects | CAUGHT |
| TC8 | a connection that waited for an earlier opening's connect does not open at its end | request rule 14 | the test of a connection idle while it connects | CAUGHT |
| TC9 | a connection over TCP offers the protocol of a QUIC one | RFC 9113 §3.3 | the first test | CAUGHT |

## The request connection over TCP on the model's walks

Design §24 step 7a, 2026-09-26 (c4milo/cocuyo#18). The replay walks the model's two TCP
configurations over the twin's QUIC over TCP (spec/README.md). They come third and fourth of
twelve, so every walk after them comes 4,000 later. The picks of the section on TLC's walks moved
with them and are the same walks byte for byte: 4046, 8011, 9182, 12005, 12070, 12900 and 13842
are now 8046, 12011, 13182, 16005, 16070, 16900 and 17842, beside 6 and 41. The full run, 24,000
walks and 4,824,000 events, replays clean. Every mutation of the set is caught where it was
before, and each picked one at the same walk.

Writing the replay brought the model back to rule 14 in two steps, and the engine in one
(spec/README.md). Nine edits no longer applied once the request connections became a set of one
transport, and were written again: RW1, RW2, RW4, RW7, RW8, RW10, RW11, RW12 and RW15. RW10 was
written once more when its line changed, below. Each is caught as before.

RT1 widened the refusal in `current_of` to the current incarnation's events while its slot waits
to connect, or connects. No walk catches it, and none can: a slot waits only while an earlier
opening's connect is in flight, that opening never sent or received, and every connect starts a
new incarnation. The tool counted it caught at first, against a full run that failed anyway (the
section on the mutation tool, EM12). That part of the check is an assertion now, and RT1 is gone.

TC1 to TC9 were broken against the walks as well as `zig build test-io`. The short walks catch
eight of them in the TCP configurations. No walk sees TC4, since the model counts a send's octets
and does not read them, and the tests catch it. Nine mutations, nine `CAUGHT`.

| # | Mutation | The TCP tests | The walks | Status |
| --- | --- | --- | --- | --- |
| TC1 | a slot connects again while a connect of an earlier opening is in flight | CAUGHT | short walk 39 | CAUGHT |
| TC2 | a connection's receive is armed, and its octets sent, before its connect has succeeded | CAUGHT | short walk 22 | CAUGHT |
| TC3 | a send that went short is taken for a whole one, and its rest is lost | CAUGHT | short walk 40 | CAUGHT |
| TC4 | the rest of a send that went short is sent from the buffer's start | CAUGHT | no walk | CAUGHT |
| TC5 | a receive that ended with no octets is armed again, and the connection stays up | CAUGHT | short walk 24 | CAUGHT |
| TC6 | a connect that failed leaves its requests waiting on the connection | CAUGHT | short walk 25 | CAUGHT |
| TC7 | an idle connection that connects is left connecting | CAUGHT | short walk 28 | CAUGHT |
| TC8 | a connection that waited for an earlier opening's connect does not open at its end | CAUGHT | short walk 39 | CAUGHT |
| TC9 | a connection over TCP offers the protocol of a QUIC one | CAUGHT | short walk 24 | CAUGHT |

## colibri's HTTP/2 under the request interface

Design §24 step 7a, 2026-09-26 (c4milo/cocuyo#18). `cocuyo_h2` puts colibri's `h2` client under
the request interface, over a record-mode TLS provider (`io/io_h2.zig`): the GET, the answer
buffers, the response's status, `Age` and media type, a cancel, a GOAWAY, the stream identifiers
running out, and the idle close. The gate runs it over a provider that encrypts nothing
(`io/io_h2_plain.zig`) against colibri's HTTP/2 server (`io/io_h2_server.zig`).
`zig build test-cocuyo_h2` runs twenty-one tests, and `zig build test-io` eight of the engine over
both on the twin's TCP. Broken against those two steps.

What the mutations found:

- HT7 was a bug. The engine's GOAWAY test failed because a frame was dropped from the plaintext
  before its event was read. A GOAWAY after the answer in one record then wrote over the answer's
  content. The in-memory tests now check the answer octet for octet. The test server read in the
  same order, which is equivalent there: a request's field lines are colibri's decoded copy, and a
  GET server reads no DATA.
- Three checks guarded nothing, and were removed. colibri refuses a stream after a GOAWAY
  (RFC 9113 §6.8), and fails a connection whose GOAWAY names a higher last stream than before. And
  a provider writes one `close_notify` and returns 0 when asked again (colibri's `tls.VTable`), so
  HT19 breaks the plain provider's.
- `next` checked the stage twice, which hid HT4, and the second check is gone. A request that
  found the stream identifiers run out told the engine nothing; `next` tells it now (HT17).
- HT1, HT3, HT4, HT5, HT6, HT10, HT12, HT13, HT17, HT18 and HT22 needed tests, which were written.

Twenty-three mutations, twenty-three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| HT1 | a template whose longest GET does not fit is taken | its GET must fit a request | the template test | CAUGHT |
| HT2 | the connection preface is not written as the handshake ends | the preface goes first (RFC 9113 §3.4) | the test of a request made as the connection comes up | CAUGHT |
| HT3 | octets past the records buffer are taken | request rule 7 | the octets-past test | CAUGHT |
| HT4 | a closing connection reads on | request rule 9 | the closing test | CAUGHT |
| HT5 | the server's `close_notify` does not end the connection | RFC 9846 §6.1, request rule 7 | the `close_notify` test | CAUGHT |
| HT6 | a frame colibri refuses while its replies are full is not read again once they are written aside | colibri reads no frame while its replies have no room | the test of PINGs read whole | CAUGHT |
| HT7 | a frame is dropped from the plaintext before its event is read | the event's octets are the plaintext's | the in-memory GOAWAY test | CAUGHT |
| HT8 | a coding is not read | a coded answer is no DNS message (request rule 12) | the in-memory response test | CAUGHT |
| HT9 | the `Age` is not read | TTLs are lowered by it (RFC 8484 §5.1) | the in-memory response test | CAUGHT |
| HT10 | every GOAWAY is told | the connection drains once (request rule 13) | the in-memory GOAWAY test, the identifiers test | CAUGHT |
| HT11 | a stream above a GOAWAY's last is left open | it was never processed (RFC 9113 §6.8) | the in-memory GOAWAY test | CAUGHT |
| HT12 | content past an answer's buffer is not counted | the engine fails an answer too long (request rule 5) | the past-the-buffer test | CAUGHT |
| HT13 | a cancel keeps its answer buffer | the buffer comes back | the cancel test | CAUGHT |
| HT14 | a cancel sends no RST_STREAM | CANCEL (RFC 9113 §7, request rule 6) | the cancel test | CAUGHT |
| HT15 | the GET asks for `gzip` | `accept-encoding: identity` (request rule 12) | the GET's lines test | CAUGHT |
| HT16 | `:path` goes without indexing | never indexed (RFC 7541 §6.2.3, §7.1.3) | the GET's lines test | CAUGHT |
| HT17 | the stream identifiers running out is never told | the connection drains (RFC 9113 §5.1.1) | the identifiers test | CAUGHT |
| HT18 | the stream identifiers running out leaves no mark | the connection drains (RFC 9113 §5.1.1) | the identifiers test | CAUGHT |
| HT19 | the plain provider writes a `close_notify` each time it is asked | a second call returns 0 | the plain provider's record test, the in-memory idle test | CAUGHT |
| HT20 | an idle close sends no GOAWAY | RFC 9113 §9.1, request rule 9 | the in-memory idle test | CAUGHT |
| HT21 | frames are sealed before the handshake ends | the handshake's last flight goes first (RFC 9846 §4.4.4) | every engine test | CAUGHT |
| HT22 | a record is opened into less room than its plaintext needs | the record waits | the waiting-record test | CAUGHT |
| HT23 | the twin keeps the server of a socket a new connection reuses | a new connection is a new server | the engine's GOAWAY test | CAUGHT |

## The transport read after it moves

Design §24, request rule 17, 2026-09-26 (c4milo/cocuyo#18). Besides after each receive and each
expiry, the engine reads a request transport after the connection's send ends, and where the drive
takes a request the transport holds back. colibri's HTTP/2 reads no frame while the replies it owes
have no room. And a connection whose stream identifiers ran out says it drains only when read. The
model gained two moves and one check (RQ21 and RQ22 above). The replay's twin keeps a held item
until its next read, and refuses a request once its identifiers are spent. One engine test, over
the twin's TCP, spends a connection's identifiers under a request.

What writing it found:

- DoQ freed a cancelled stream's slot once its own side had ended, before the server's answer came.
  Nothing read that answer then, and colibri kept the stream's place in its table. The read at a
  send's end made it show: the DoQ test of cancelled streams failed once colibri's 128 places had
  run out. A slot is now freed once its answer or reset has been read (TR4).
- The read after a request held back was first at the drive's end, where waiting streams are asked
  for again. A lookup the read told of then waited for a drive that might not come, which the
  model's check that a drive ends with nothing ready caught. The read is where the drive takes the
  request now.
- A held reset can end a draining connection's last stream at the read that brings a GOAWAY. The
  connection closes then, and reads nothing more, as rule 9 has it. The replay found the twin still
  reading, and the model applying the GOAWAY to a closing connection. Both stop now.

The walks were written again from the new model, which draws its choices anew. The full run,
24,000 walks and 4,824,000 events, replays clean. The short walks miss TR1, TR2, TR3 and TR5, and
the full run catches each. The picks were chosen again from it, each the first walk that catches a
mutation the short walks miss: 3, 50, 4024, 4080, 4110, 5710, 8046, 12011, 13182, 16005, 16070,
16900 and 17842. RW6 and RW16 moved to walks 3 and 50, and the rest stayed where they were. The
picks catch every mutation of the set the short walks miss. Five mutations, five `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TR1 | a send's end reads nothing of the transport | request rule 17 | full run walk 4110, picked | CAUGHT |
| TR2 | a short send's end reads nothing of the transport | request rule 17 | full run walk 4080, picked | CAUGHT |
| TR3 | a request the transport holds back leaves it unread | request rule 17 | the held-back request test; full run walk 5710, picked | CAUGHT |
| TR4 | a cancelled DoQ stream frees its slot before its answer or reset is read | colibri keeps a stream's place until both its halves end | the test of streams the engine cancels | CAUGHT |
| TR5 | the twin tells a held answer for a stream the engine cancelled | a cancelled stream is told to nobody (request rule 6) | full run walk 4024, picked | CAUGHT |

## Every record type in the fuzz target

2026-09-26 (c4milo/cocuyo#23). Design §19's gate for the record types asks for the fuzz corpus
grown by each. The generator (`src/wire/fuzz_generate.zig`) built noise, and plausible headers,
questions and names, and no well-formed record of any type, so a typed view mostly met octets that
failed its first check. It now writes a response whose one answer is a record of each type the
codec reads, half of them whole and half with one octet of the rdata changed. A record written
whole must be taken whole: the copy takes it, and its view takes the copy. Every view now runs
over what the copy wrote, and one whose layout ends in a rest may refuse it, since the copy takes a
rest as it is.

The fuzz target's checks show only against a decoder that is wrong. So FZ1 to FZ5 each plant a
decoder bug the hand-built fixtures do not reach, run against `zig build test-wire` before this
change and after it: each went unseen before, and is caught after. FZ6 to FZ10 break the new
check's own lines. Ten mutations, ten `CAUGHT`.

| # | Planted decoder bug | Before | After | Status |
| --- | --- | --- | --- | --- |
| FZ1 | a TXT longer than twelve octets is refused | unseen | the fuzz gate | CAUGHT |
| FZ2 | a NAPTR with a regexp is refused | unseen | the fuzz gate | CAUGHT |
| FZ3 | an SVCB with an `ech` parameter is refused | unseen | the fuzz gate | CAUGHT |
| FZ4 | a critical CAA with a value is refused | unseen | the fuzz gate | CAUGHT |
| FZ5 | a SIG whose signature is longer than four octets is refused | unseen | the fuzz gate | CAUGHT |

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| FZ6 | a whole record's view may refuse its copy | a whole record is taken whole | the verdict test, the whole-record test | CAUGHT |
| FZ7 | the verdict does not check a record written whole | a whole record is taken whole | the verdict test | CAUGHT |
| FZ8 | no record is written whole | every type is written whole | the reach test | CAUGHT |
| FZ9 | one type is never written | every type is written | the reach test | CAUGHT |
| FZ10 | a view that refuses a rest fails the gate | a rest may be refused | the fuzz gate, the whole-record test | CAUGHT |

The gate's first part came the same day: fixtures from the RFCs' own examples, where an RFC gives
one, in `src/wire/rdata/fixtures.zig`. They are RFC 1035 §5.3's SOA and MX, whose SOA mailbox holds
a dot inside a label, and §6.4.1's HINFO. Then RFC 2782's SRV, RFC 3403 §6.1 and §6.2's NAPTRs,
one with a regexp and a root replacement, RFC 6698 §2.3's TLSAs, RFC 7553 §5.1's URI, and RFC
8659 §4.2's CAAs. TXT and SIG have no example to take. Each test reads every field back against
the example's presentation form. RX1 to RX3 each plant a decoder bug only an example reaches, run
before and after as FZ1 to FZ5 were. Three mutations, three `CAUGHT`.

| # | Planted decoder bug | Before | After | Status |
| --- | --- | --- | --- | --- |
| RX1 | a NAPTR whose replacement is the root is refused | unseen | the NAPTR examples' test | CAUGHT |
| RX2 | a label holding a dot is refused where a view reads a name | unseen | the SOA example's test, the fuzz gate | CAUGHT |
| RX3 | TLSA data is cut at thirty-two octets | unseen | the TLSA examples' test | CAUGHT |


## The codec against dnslib's reading

2026-09-26 (c4milo/cocuyo#22). The codec was tested against answers built by hand, and never
against another decoder's reading of the same octets. `zig build dnslib-check` holds it against
dnslib's test directory (`tools/dnslib/check.zig`): 66 responses real servers sent, each with
dnslib's reading of it in master-file form. `tools/dnslib/run.sh` fetches the directory at a pinned
commit and checks its tree first. Every record of every section is compared: its owner, TTL, class
and type, and its rdata through its type's view. 185 records agree. 128 are read through a view, 2
are compared as RFC 3597 §5's generic octets, and 55 are of types cocuyo does not name, copied
whole.

DL1 to DL8 plant decoder bugs, run under the check and under `zig build test-wire`. The check
catches all eight. The unit tests missed DL2 and DL7, which real responses reach and the hand-built
ones did not: a name whose pointer lands on a name that itself ends in a pointer, and a TTL above
65,535. `src/wire/name.zig` and `src/wire/record.zig` now hold a test of each. DT1 to DT12 break
the check's own lines, against its tests under `zig build test-tools`. Twenty mutations, twenty
`CAUGHT`.

| # | Planted decoder bug | The dnslib check | `zig build test-wire` | Status |
| --- | --- | --- | --- | --- |
| DL1 | a name's end moves with every pointer it follows | the copy's assertion that a name moves its cursor | the fuzz gate | CAUGHT |
| DL2 | a name follows one pointer and no more | 14 responses refused | unseen before; the hop bound's own count now | CAUGHT |
| DL3 | the copy writes a name as the message held it, pointers and all | 34 responses refused | the copy's tests | CAUGHT |
| DL4 | an SOA's retry is read from its refresh | 13 SOAs differ | the SOA tests | CAUGHT |
| DL5 | a NAPTR's flags are read from its services | 1 NAPTR differs | the NAPTR tests | CAUGHT |
| DL6 | a TLSA's usage is read from its selector | 1 TLSA differs | the TLSA test | CAUGHT |
| DL7 | a TTL is read as its low 16 bits | 8 TTLs differ | unseen before; the 32-bit TTL test now | CAUGHT |
| DL8 | a type cocuyo does not name is copied as SIG's layout | 9 responses refused | the unknown type's copy test | CAUGHT |

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DT1 | a TTL is not compared | the TTL agrees | the test of a line that differs | CAUGHT |
| DT2 | an owner is not compared | the owner agrees | the test of a line that differs | CAUGHT |
| DT3 | a section's records are not counted against its lines | each section holds what dnslib printed | the section test | CAUGHT |
| DT4 | octets after the last section pass | nothing follows the last record | the section test | CAUGHT |
| DT5 | the OPT pseudo-record is compared with a line | OPT is the message's, not a section's (RFC 6891 §6.1.1) | the OPT test | CAUGHT |
| DT6 | a TXT string left over in the rdata passes | every string agrees, in order | the strings test | CAUGHT |
| DT7 | hexadecimal that ends early passes | every octet agrees | the strings test | CAUGHT |
| DT8 | a mnemonic cocuyo names passes for a type it does not | the type agrees | the generic test | CAUGHT |
| DT9 | a generic rdata's length is not compared | RFC 3597 §5's length agrees | the generic test | CAUGHT |
| DT10 | an unnamed type's copy is not held to its rdata | a copy of an unnamed type is the rdata (RFC 3597 §4) | the copy test | CAUGHT |
| DT11 | a `\DDD` escape is read as the digit it starts with | RFC 1035 §5.1's escapes | the field test | CAUGHT |
| DT12 | a comment line is read as a record | a comment is no record | the file test, the OPT test | CAUGHT |

## Every transport against dnsproxy, and records beyond A

2026-09-26 (c4milo/cocuyo#20, #21). The interop check ran DoQ and DoH on HTTP/3 against AdGuard's
dnsproxy, and every check, interop and live, asked for A alone. The interop check now runs plain
DNS over UDP and over TCP, and DoT, beside them. Over each transport it asks for AAAA, MX, TXT and
HTTPS of one name at once, then for a CNAME to it, which `tools/interop/zone.zig` serves as
dnsproxy's upstream. Over plain DNS, dnsproxy's log must show the queries on the transport asked
for. The live checks ask each public resolver for the same four types of a name that has each.
IX1 to IX4 plant engine and codec bugs against the interop check, and LT1 one against the DoT live
check. Five mutations, five `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| IX1 | `use_tcp` is ignored, so a lookup asked over TCP goes over UDP | the transport asked for | dnsproxy's log, at both checks over TCP | CAUGHT |
| IX2 | a TXT record's strings stop at the first | every string of a TXT (RFC 1035 §3.3.14) | the types check, over every transport | CAUGHT |
| IX3 | a record's rest is copied one octet short | the copy takes the rdata whole | the types check, over every transport | CAUGHT |
| IX4 | the end of a CNAME chain is never said | the canonical name (RFC 1034 §3.6.2) | the types check, over every transport | CAUGHT |
| LT1 | IX3, against the DoT live check | the copy takes the rdata whole | the types check, through all three resolvers | CAUGHT |

The count of lines under each name refuses a record of another type, and no mutation shows it
here: no server in either check sends one under a question. Breaking the answer walk's type filter
(`role_of` in `src/wire/response.zig`) fails the codec's own tests, "a record of another type is not
an answer" among them.

## What the engine examples read

2026-09-26. The examples read a server as an address and a port after its last colon, trying the
whole text as an address first. `::1:8053` is itself an IPv6 address, so no example could name an
IPv6 server on a port of its own. `examples/server_text.zig` now reads a bracketed IPv6 address
and a port, as a URI writes one (RFC 3986 §3.2.2), for the DoT, DoQ, DoH and plain DNS examples.
Its tests and those of the question reader in `examples/answer_text.zig` run with the gate. Every
engine example resolved over IPv6 against dnsproxy on `::1`. EX2 went uncaught at first: no test
held text whose part before its last colon is an IPv6 address while the whole is none, and
`1:2:3:4:5:6:7:8:53` is such a test now. Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| EX1 | brackets take an IPv4 address | brackets hold IPv6 alone (RFC 3986 §3.2.2) | the refusal test | CAUGHT |
| EX2 | an IPv6 address takes a port without brackets | a port follows IPv6 in brackets alone | the refusal test, once it held nine groups | CAUGHT |
| EX3 | anything may follow the closing bracket | a colon and a port, or nothing | the refusal test | CAUGHT |
| EX4 | a question may ask for OPT | OPT is never a question (RFC 6891 §6.1.1) | the type test, by the assertion in `Question.from_text` | CAUGHT |

## The README's code

2026-09-26. The README's driving loop no longer compiled: two captures stood unused behind comments,
and its switch lacked the `send_request` action DoH and DoQ added. Nothing built it. `zig build
readme-check`, in the gate, now writes a package that depends on cocuyo and on the rotor it pins,
with each Zig block of the README inside the harness its marker names, builds it, and runs the
quick start, whose first action must be `send_udp` (`tools/readme_check.zig`). RC1 to RC3 break
the README or the library against the check, and RC4 to RC6 break the tool's reading of the
README against its tests. Six mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RC1 | the loop's `send_request` branch is gone, as it once was | the README's code compiles | the check: the package does not build | CAUGHT |
| RC2 | a `Config` asks for TCP by default | the quick start's first action is `send_udp` | the check: the first action is `connect_tcp` | CAUGHT |
| RC3 | a Zig block has no marker | every block is built | the check: the README is refused as unmarked | CAUGHT |
| RC4 | a harness may be named twice | each block has one harness | the tool's reading test | CAUGHT |
| RC5 | a marker may stand over prose | a marker names the block under it | the tool's reading test | CAUGHT |
| RC6 | `quick_start` passes for `quick-start` | a marker spells its harness one way | the tool's reading test | CAUGHT |

## The text parsers in a fuzz target

2026-09-26. The codec had a fuzz target and the text parsers had none: an address, a name, a
`resolv.conf`, a hosts file and an SPKI pin were checked only by the cases their tests spell out.
The second target (`src/config/fuzz/`, design §13) writes each whole, with one byte changed, as a
near miss, or as noise, and a DoH template has a seeded test of its own beside its splitter. The
design named `zig build fuzz` and `zig build fuzz-gate`, and neither existed; both do now.
Twenty million text seeds held.

TF1 to TF4 and TT1 each plant a parser bug the existing tests do not reach, run against the
module's tests before this change and after it. Before, each went unseen: TF1, TF2 and TF4 by the
core, config and resolver tests alike. After, each is caught. TC1 to TC3 break the target's own
checks, against its tests. Eight mutations, eight `CAUGHT`.

| # | Planted parser bug | Before | After | Status |
| --- | --- | --- | --- | --- |
| TF1 | an upper-case hex digit reads from `A` as zero | unseen | the text fuzz gate | CAUGHT |
| TF2 | a label refuses `~`, which is printable | unseen | the text fuzz gate | CAUGHT |
| TF3 | a hosts line keeps the CR of a CRLF ending in its last name, and loses the name | unseen | the text fuzz gate | CAUGHT |
| TF4 | a dotted quad after six written groups is refused | unseen | the text fuzz gate | CAUGHT |
| TT1 | a DoH template's host refuses `_`, which RFC 3986 §2.3 leaves unreserved | unseen | the template's fuzz test | CAUGHT |

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TC1 | a whole address is not compared with what was written | a whole text reads back as written | the verdict test | CAUGHT |
| TC2 | a pin the reader should refuse may be taken | a near miss is refused | the verdict test | CAUGHT |
| TC3 | no text is written whole | every parser is reached whole | the reach test, the generator's test | CAUGHT |

## Line coverage

2026-09-26. `zig build coverage` runs every module's tests under kcov and reads what it recorded
(`tools/coverage.zig`): 96.3% of the library's and the engine's 6,805 lines run, test code left
out, measured on arm64 Linux in a container. CI's `coverage` job builds kcov from a pinned release,
since Ubuntu 24.04 packages none, and pushes the README's badge to the `badges` branch. The figure
is a report, not a gate, so no floor holds it yet. CV1 to CV3 break the report's reading, against
its tests. Three mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CV1 | the lines after a file's `// Tests` marker count | test code is left out | the test-code test | CAUGHT |
| CV2 | a `*_test.zig` file counts | test code is left out | the test-code test | CAUGHT |
| CV3 | a line kcov never hit counts as run | a line runs when kcov hit it | the report's reading test | CAUGHT |

## The stream's failures on the twin

2026-09-26. Line coverage showed lines of `io/io_tcp_queue.zig` that no module's tests ran: a
query send that fails, the queries waiting behind a connection that fails, and a send's event for
a connection that is gone. The committed engine walks run them, in `zig build test-tools`, but
kcov did not run the replays then, and `zig build test-io` ran none of them. Two twin tests now
do: one makes a send fail, and one has the peer reset the connection while a send is in flight.
TQ2 is SQ5 and TQ3 is SQ7, measured again. Five mutations, five `CAUGHT`.

| # | Mutation | `test-io` before | `test-io` after | `test-tools` | Status |
| --- | --- | --- | --- | --- | --- |
| TQ1 | a failed query send keeps its buffer lent | unseen | the failed-send twin test | the committed walks | CAUGHT |
| TQ2 | a query send that moved nothing leaves the connection up | unseen | the failed-send twin test | the committed walks | CAUGHT |
| TQ3 | a closed connection keeps its waiting queries' buffers lent | unseen | the failed-send twin test | the committed walks | CAUGHT |
| TQ4 | a closed connection takes back the buffer of the send in flight | unseen | the mid-send twin test | the committed walks | CAUGHT |
| TQ5 | a send's event for a connection that is gone keeps its buffer lent | unseen | the mid-send twin test | the committed walks | CAUGHT |

## Answers the cache copies

2026-09-26. A put copies only the storage an answer's type uses (`wire.Answers.assign`). No test
in the gate put a PTR answer or a record-type one and read it back, and line coverage showed both
branches of the copy unrun. RA1 to RA4 break the copy. Each was run against `zig build test`
before `src/cache/cache_kinds_test.zig` existed, and against `zig build test-cache` after. Four
mutations, four unseen before, four `CAUGHT`.

| # | Mutation | Before | After | Status |
| --- | --- | --- | --- | --- |
| RA1 | a PTR answer's name is not copied | unseen | the PTR round trip | CAUGHT |
| RA2 | a record answer's rdata is not copied | unseen | the MX round trip | CAUGHT |
| RA3 | a record answer's references are not copied | unseen | the MX round trip, by the `Records.at` assertion | CAUGHT |
| RA4 | a record answer's octets in use are not carried over | unseen | the MX round trip, by the `Records.at` assertion | CAUGHT |

## The coverage report's total

2026-09-26. A report whose `<source>` led outside the tree counted no line and said 100.0% of 0
lines, which the badge would have shown. The total is now `library_total`, which refuses a report
with an area that counted no line. `zig build coverage` runs the model replays' tests as well,
since they drive the lookup and the engine down the committed walks. With them and the tests of
the two sections above, it measured 96.9% of 6,805 lines the same day, on arm64 Linux in a
container. CV4 and CV5 break the total, against `zig build test-tools`. Before, the total was summed
in `main`, which no test runs. Two mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CV4 | an area with no line counted is read as run | a report that read nothing is refused | the total test | CAUGHT |
| CV5 | the twin's lines count in the total | the twin stays out of the total | the total test | CAUGHT |

## The TLS session's failures

2026-09-26. Line coverage showed the engine's answers to a failing session unrun: a session that
cannot start, a query it cannot seal, a record it refuses, and the peer's close. The twin's session
does none of these, so a test wraps it in one that fails where the test says, and requires the
lookup to fail over before the first server's wait ends. A record the session refuses is what a
forged one gets, and it ends the connection (RFC 9846 §5.2). Each mutation was run against `zig
build test-io` and `zig build test-tools` before the test, and against `test-io` after. Four
mutations, four unseen by both before, four `CAUGHT`.

| # | Mutation | Before | After | Status |
| --- | --- | --- | --- | --- |
| TL1 | a session that cannot start leaves the connection handshaking | unseen | the failing-session test | CAUGHT |
| TL2 | a record the session refuses leaves the connection up | unseen | the failing-session test | CAUGHT |
| TL3 | the peer's close leaves the connection up | unseen | the failing-session test | CAUGHT |
| TL4 | a query the session cannot seal leaves the connection up | unseen | the failing-session test | CAUGHT |

## A QUIC connection the server closes

2026-09-26. Line coverage showed `io/io_quic_connection.zig` never telling the engine that the
server closed a connection: no test had colibri's server send CONNECTION_CLOSE (RFC 9000 §10.2). A
test now does, once an answer has come, and requires the connection to close, open anew to the
same server for the next lookup, and charge no server. QC1 was run against `zig build test-io`,
`zig build test-tools` and `zig build test-cocuyo_quic` before the test, and against `test-io`
after. One mutation, unseen before, `CAUGHT`.

| # | Mutation | Before | After | Status |
| --- | --- | --- | --- | --- |
| QC1 | a connection the server closed is not seen to have ended | unseen | the server-close test | CAUGHT |

## The format check in the gate

2026-09-26. `zig build fmt` checked formatting, and neither `zig build test` nor CI ran it, so a
trailing blank line in `tools/dnslib/check.zig` reached main in a6271ab. The gate now runs it. FM1
to FM4 plant a change `zig fmt` would undo, each against `zig build test`. FM4 is the one that
reached main, and went unseen before this change. Four mutations, four `CAUGHT`.

| # | Mutation | Before | After | Status |
| --- | --- | --- | --- | --- |
| FM1 | `build.zig` ends in a blank line | not run | the format check | CAUGHT |
| FM2 | two spaces before an `=` in `src/core/name.zig` | not run | the format check | CAUGHT |
| FM3 | a line of `io/io.zig` indented by one more space | not run | the format check | CAUGHT |
| FM4 | `tools/dnslib/check.zig` ends in a blank line again | unseen | the format check | CAUGHT |

## The coverage floor

2026-09-26. The coverage figure was a report, and a change that took tests away lowered the badge
and failed nothing. The report now refuses a total under 96.5%: CI measured 97.5% of 6,807 lines
on x86_64 Linux that day, and a container measured 96.9% on arm64 Linux. The gate runs the report
over two reports it writes, one that runs no line and one with no line at all, and requires each
refused with its reason, since the report's own tests do not run `main`. CF1 and CF2 break the
floor, against `zig build test-tools`. CF3 and CF4 break `main`, against `zig build test`. Four
mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CF1 | no total is under the floor | a total under the floor is refused | the floor test | CAUGHT |
| CF2 | a total at the floor is under it | a total at the floor passes | the floor test | CAUGHT |
| CF3 | `main` does not hold the floor | the report exits 1 under the floor | the gate's unrun report | CAUGHT |
| CF4 | `main` reads a report of no lines as 100% | a report that read nothing is refused | the gate's empty report | CAUGHT |

## `getaddrinfo`'s truncated flag

2026-09-26. A lookup that keeps `addresses_max` addresses of a larger round-robin name says so
with `Answer.truncated`, and the walk passes it on (`address_lookup_walk.zig`, `take_answer`). No
test sent the walk such an answer, so a walk that dropped the flag told its caller it had every
address, and one that set it on every answer told the caller more existed when none did. A test
now answers the walk with one more A record than a lookup keeps. The two-family test requires a
whole answer to say it is whole. AT1 was run against `zig build test-resolver`, `test-tools`,
`test-io` and `test-cocuyo` before, and AT2 against `test-resolver`. Both were run against
`test-resolver` after. Two mutations, unseen before, two `CAUGHT`.

| # | Mutation | Before | After | Status |
| --- | --- | --- | --- | --- |
| AT1 | a lookup's truncated answer is not passed on | unseen | the truncated-answer test | CAUGHT |
| AT2 | every answer is passed on as truncated | unseen | the two-family test | CAUGHT |

## Any type in a question

2026-09-26. `Kind` is open (docs/design.md §16 decision 31, c4milo/cocuyo#25). A question may
name any type but zero, OPT and the codes RFC 6895 §3.1 keeps for query and meta types, ANY
apart. `Question.from_text` refuses the rest with `UnqueryableType`. A lookup for a type cocuyo
does not name keeps its records with their rdata as the wire has it (RFC 3597 §3, §4). QK1 to QK7
break `Kind`, against `zig build test-core`. QK8 breaks the rdata layout, against `test-resolver`.
QK9 breaks the examples' generic type name, against `zig build test`. Nine mutations, nine
`CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| QK1 | the query and meta range is asked | RFC 3597 §2 | the queryable test | CAUGHT |
| QK2 | ANY is refused with the rest of its range | RFC 8482 | the registry-code test | CAUGHT |
| QK3 | type zero is asked | RFC 6895 §3.1 | the queryable test | CAUGHT |
| QK4 | OPT is asked | RFC 6891 §6.1.1 | the registry-code test | CAUGHT |
| QK5 | the range starts one code late, so 128 is asked | RFC 6895 §3.1 | the queryable test | CAUGHT |
| QK6 | `from_text` asks any type | the refusal is an error | the queryable test, by an assertion | CAUGHT |
| QK7 | `from_code` names every code | only named types have a view | the type-code test | CAUGHT |
| QK8 | an unnamed type's rdata is read as a name | RFC 3597 §4 | the unnamed-type lookup test, by an assertion | CAUGHT |
| QK9 | the examples do not read `TYPE<number>` | RFC 3597 §5 | the examples' generic-type test | CAUGHT |

## DoH over HTTP/2's failures

2026-09-26. Line coverage showed three of the HTTP/2 connection's answers unrun, and so untested:
a stream the server resets, a response that a trailer section ends (RFC 9113 §8.1), and a record
that does not open, which ends the connection (RFC 9846 §5.2). The test server now ends a response
with trailers when its script says so. The failover helper now requires the lookup to move on
before the first server's wait ends, since a lookup that waits it out lands on the next server
too. H1 to H3 were run against `zig build test-io` and `zig build test-cocuyo_h2` before and after.
Three mutations, three unseen before, three `CAUGHT`.

| # | Mutation | Before | After | Status |
| --- | --- | --- | --- | --- |
| H1 | a stream the server resets is not told to the engine | unseen | the failover test, by its time | CAUGHT |
| H2 | a trailer section does not end the response | unseen | the trailers test | CAUGHT |
| H3 | a record that does not open leaves the connection up | unseen | the unopenable-record test | CAUGHT |

## DoT over chapulin's Zig API

2026-09-26. The DoT session, `io/io_chapulin.zig`, moved from chapulin's headers and an object
built in a checkout onto chapulin's Zig API, whose module the `chapulin` dependency carries with its
object (c4milo/cocuyo#30). chapulin seals a query whole or not at all, and answers a KeyUpdate into
a buffer the session hands it, so the session's two callbacks and its flag for a send that did not
fit went. Two things are new: the session zeroes its copy of the ticket it resumes with, which it
did not before, and a named server with no anchors is judged by its pins with its name still sent,
which had no test. CT1 to CT6 break the session, against `zig build test-chapulin`. The live check
against Google, Cloudflare and Quad9 and the interop check against dnsproxy passed on it the same
day. Six mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CT1 | `wipe` keeps the copy of the ticket | the resumption secret is zeroed | the ticket-zeroing test | CAUGHT |
| CT2 | a server known by pins alone gets the context's anchors | RFC 8310 §6.3's SPKI + IP | the pins-alone test | CAUGHT |
| CT3 | the hostname keeps its root label's dot | chapulin takes a hostname | the named-server test | CAUGHT |
| CT4 | the clock ignores the time since the context's | the chain is checked at the caller's time | the named-server test | CAUGHT |
| CT5 | a named server with no anchors sends no name | its pins judge it, its name still sent | the named-and-pinned test | CAUGHT |
| CT6 | the build record check passes any record | an object built otherwise stops the program | the build-record test | CAUGHT |

## A refused handshake's alert

2026-09-27. A handshake the session refuses, not resumed, sends the session's fatal alert before
its connection closes (docs/design.md §21, TLS rule 4; RFC 9846 §6.2; c4milo/cocuyo#31). In the
model, `Refuse` tells and detaches every lookup on the connection, seals the alert as the session's
records are sealed, and closes the connection once the alert has gone, as an idle close does after
its `close_notify`. The check `refusal said` holds it. R4a puts the old close at once back, and TLC
over its mutant configuration found `refusal said` broken on a trace of five states. The
TLS mutants whose operator copies `TlsStep`, TM3 and R8a, refuse the same way, so each still
breaks its own rule alone. The committed walks were written again from the model, and TLC's full
run, 4,824,000 events over 24,000 walks, replays against the engine.

The engine's 79 mutations ran again against the new walks. 77 were caught as before. ET4's edit
named the line this change rewrote, so it was written again, and walk 16900 catches it. ET6's pick,
walk 16005, changed with the model, so walk 16006, which catches it, took its place in
`build/spec.zig`. ET15 and ET16 break the engine's refusal, against the short walks. AL1 to AL3
break the sessions and the twin's server, which no walk reads, against the tests named. Six
mutations of the refusal, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| R4a | a refused handshake closes its connection at once, its alert unsent | TLS rule 4 | `refusal said`, at depth 5 | CAUGHT |
| ET15 | the engine closes a refused handshake's connection at once, its alert unsent | TLS rule 4 | the short walks, walk 82 | CAUGHT |
| ET16 | a refused handshake's connection reads on, and never closes once its alert has gone | TLS rule 5 | the short walks, walk 82 | CAUGHT |
| AL1 | the twin's session stages no alert for a handshake it refuses | RFC 9846 §6.2 | the twin's refusal test, and the engine's | CAUGHT |
| AL2 | chapulin's session drops the alert chapulin staged | RFC 9846 §6.2 | the chapulin alert test | CAUGHT |
| AL3 | the twin's server hears a fatal alert as a close | the alert is counted | the twin's refusal test | CAUGHT |

## A record refused once up

2026-09-27. A connection that is up may now refuse a record, which the model's walks reach through
`TlsSteps`, and it fails as a refused handshake does, resumed or not: the server failed the lookups
on it (docs/design.md §21, TLS rule 4; RFC 9846 §6.2; c4milo/cocuyo#31). Its queries not yet sealed
leave the queue and give their buffers back, and what is sealed goes out ahead of the alert, whose
sequence number follows theirs (§5.3). `decline forgiven` now reads a resumed handshake alone, as
the step does, since a connection up may have resumed. TLC over the TLS configurations counted
68,678, 413,862 and 2,138,766 states for one slot and 1,687,238 for two, and TLC's full run, 4,824,000
events over 24,000 walks, replays against the engine. R4b keeps the unsealed queries queued, and
TLC found `refusal said` and `queued for its lookup` broken on a trace of eight states.

The engine's 83 mutations ran again against the new walks, and 78 were caught as they should be.
ET4, ET10 and ET11 each lost the picked walk that caught it, and walk 16478 catches all three. The
short walks miss ET17 and ET18, and walk 16008 catches both. Both walks joined the picks in
`build/spec.zig`, and the five are caught by the picked walks since. TL2's line changed, and it was
run again. AL5 is `NOT CAUGHT`: it needs a chapulin session that is up, and so a chapulin server in
the same process, which the gate has not. chapulin's package ships neither its test certificates
nor a server object, so the test waits on a harness of its own (c4milo/cocuyo#32). Nine
mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| R4b | a refusal leaves the queries not yet sealed queued behind the alert | TLS rule 4 | `refusal said`, `queued for its lookup`, at depth 8 | CAUGHT |
| ET17 | a record the session refuses once up closes the connection at once, its alert unsent | TLS rule 4 | the picked walks, walk 16008 | CAUGHT |
| ET18 | a refusal leaves the queries not yet sealed queued behind the alert | TLS rule 4 | the picked walks, walk 16008 | CAUGHT |
| ET4 | a declined ticket fails the connection | TLS rule 8 | the picked walks, walk 16478 | CAUGHT |
| ET10 | a reopening connection takes its old opening's events | TLS rule 8 | the picked walks, walk 16478 | CAUGHT |
| ET11 | a reopening connection connects while its old records are in flight | TLS rule 3 | the picked walks, walk 16478 | CAUGHT |
| AL4 | the twin's session stages no alert for a record refused once up | RFC 9846 §6.2 | the twin's refusal-once-up test | CAUGHT |
| TL2 | a record the session refuses leaves the connection up | RFC 9846 §5.2 | the failing-session test | CAUGHT |
| AL5 | chapulin's session drops the alert a failed `read` wrote | RFC 9846 §6.2 | nothing in the gate | NOT CAUGHT |

## DoT and DoQ over colibri's `tls`

2026-09-27. Both sessions moved onto colibri's `tls` module at colibri `a6a4791`, which carries
chapulin's objects (docs/design.md §16 decision 32): DoT over `tls.record.Client`, DoQ and DoH on
HTTP/3 over `tls.quic.Client`. colibri's `tls` links chapulin's TCP object beside its QUIC object,
and a program with cocuyo's own TCP object beside it did not link, so cocuyo pins no chapulin of
its own. The DoT session's checks were written again over colibri's calls, and three are new:
colibri writes a refused flight's alert into the output and `failure_written` counts it, a flight
that fills the staged octets fails the session, and a query colibri seals in part fails it. The
staged octets hold chapulin's longest ClientHello for colibri's object, 2,421 octets read from
chapulin's session.h, since colibri does not name the bound. CL1 to CL14 break the DoT session
against `zig build test-chapulin`, QL1 to QL9 the DoQ session against `zig build test-chapulin-quic`. The live checks against Google, Cloudflare and Quad9 over DoT,
AdGuard and NextDNS over DoQ, and Google and Cloudflare over DoH on HTTP/3 passed the same day, and
so did the interop check against dnsproxy.

CL9 to CL12 need a session that is up. CL9 needs a server whose `record_size_limit` holds less
than a query, and CL10 one that sends a KeyUpdate, and colibri's server does neither. CL11, and
CL12, which is AL5's check over colibri's calls, need only a server in the same process, which
colibri's objects hold. The owner ruled on 2026-09-27 that such a test is not worth its fixtures
(c4milo/cocuyo#32, closed): the TCP close that follows a `close_notify` fails the connection
anyway, and RFC 9846 §6.2 asks for the alert with a SHOULD. CL13 and QL8 need a HelloRetryRequest
for P-256, the one draw after a handshake starts (c4milo/cocuyo#13).
Twenty-three mutations, seventeen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CL1 | `wipe` keeps the copy of the ticket | the resumption secret is zeroed | the ticket-zeroing test | CAUGHT |
| CL2 | a server known by pins alone gets the context's anchors | RFC 8310 §6.3's SPKI + IP | every test that starts a session | CAUGHT |
| CL3 | the hostname keeps its root label's dot | chapulin takes a hostname | the named-server tests | CAUGHT |
| CL4 | the clock ignores the time since the context's | the chain is checked at the caller's time | the named-server test | CAUGHT |
| CL5 | a named server with no anchors sends no name | its pins judge it, its name still sent | the named-and-pinned test | CAUGHT |
| CL6 | the session enters no stream at its start | chapulin draws when a handshake starts | the hello test, by the hook's panic | CAUGHT |
| CL7 | a refused flight's alert is dropped | RFC 9846 §6.2 | the refused-handshake test | CAUGHT |
| CL8 | a flight that fills the staged octets is taken whole | the flight is staged whole | the full-staging test | CAUGHT |
| CL9 | a query sealed in part is taken whole | the query goes whole | nothing: **a server whose `record_size_limit` holds less than a query** | NOT CAUGHT |
| CL10 | a KeyUpdate's answer that cannot be staged is dropped | RFC 9846 §4.7.3 | nothing: **a server that sends a KeyUpdate** | NOT CAUGHT |
| CL11 | the peer's `close_notify` is taken for nothing | RFC 9846 §6.1 | nothing: **by the owner's ruling, c4milo/cocuyo#32** | NOT CAUGHT |
| CL12 | the alert a refused record raised is dropped | RFC 9846 §6.2 | nothing: **by the owner's ruling, c4milo/cocuyo#32** | NOT CAUGHT |
| CL13 | the handshake's records enter no stream | chapulin may draw during any call of the handshake | nothing: **c4milo/cocuyo#13** | NOT CAUGHT |
| CL14 | `tls_records_out_bytes` down to 2,800, below 2,829 | the staging beside a sealed query | the build of `test-chapulin` | CAUGHT |
| QL1 | the provider enters no stream at the transport parameters | chapulin draws when its session starts | the hello test, by the hook's panic | CAUGHT |
| QL2 | a server known by pins alone gets the context's anchors | RFC 8310 §6.3's SPKI + IP | the pins-alone test | CAUGHT |
| QL3 | the pins of a named server are not handed on | RFC 8310 §6.4, both must pass | the name-and-pins test | CAUGHT |
| QL4 | the hostname keeps its root label's dot | chapulin takes a hostname | the name tests | CAUGHT |
| QL5 | a named server with no anchors sends no name | its pins judge it, its name still sent | the named-and-pinned test | CAUGHT |
| QL6 | `wipe` keeps the copy of the ticket | the resumption secret is zeroed | the ticket-zeroing test | CAUGHT |
| QL7 | the clock ignores the time since the context's | the chain is checked at the caller's time | the clock test | CAUGHT |
| QL8 | the provider enters no stream when handshake octets arrive | chapulin may draw on a HelloRetryRequest | nothing: **c4milo/cocuyo#13** | NOT CAUGHT |
| QL9 | the session forgets it offered a ticket | a declined ticket is told from none | the ticket-zeroing test | CAUGHT |

## colibri's named TLS limits

2026-09-27. colibri `a4adcbc` names the limits cocuyo had read from chapulin's headers: the most
one client handshake call writes, `tls.record.Client.handshake_output_len_min`, chapulin's
`REC_HDR + CH_TX_HELLO`; the length of an alert record, `tls.record.alert_record_len`; and the most
anchors each configuration takes, `anchors_max`. The DoT session's staged octets are colibri's
bound now, and the 2,421 read from chapulin's session.h left `io/constants.zig`. An output that
long takes a whole flight in one call, which colibri tests with a ClientHello that offers a ticket.
So CL8's check, which failed a step whose flight filled the staged octets, would have refused a
good flight of exactly that length, and an assertion that each step has that much room took its
place. Broken against `zig build test-chapulin`. Two mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CL14 | `tls_records_out_bytes` down to 2,800, below 2,829 | the staging beside a sealed query | the build of `test-chapulin` | CAUGHT |
| CL15 | the staged octets one short of colibri's bound | a whole flight in one call | the hello test, by the assertion | CAUGHT |

## The sessions in the gate

2026-09-27. `zig build test` runs the DoT and DoQ sessions' tests over colibri's `tls` and builds
their examples, where before only `zig build test-chapulin`, `zig build test-chapulin-quic` and
the daily workflows did. cocuyo follows colibri's main, and a colibri that breaks a session now
fails the gate on the commit that moves the pin. GT3 is the break the DoQ example took when the
session moved onto colibri, which only a build by hand showed that day. GT1 to GT4 break the
sessions and the examples against `zig build test`. Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| GT1 | the DoT session enters no stream at its start | the session's tests run in the gate | the gate, by the hook's panic | CAUGHT |
| GT2 | the DoQ provider enters no stream at the transport parameters | the session's tests run in the gate | the gate, by the hook's panic | CAUGHT |
| GT3 | the DoQ example reads a field the session no longer has | the examples build in the gate | the gate, by the example's build | CAUGHT |
| GT4 | the DoT example reads chapulin's constants, which the session no longer exports | the examples build in the gate | the gate, by the example's build | CAUGHT |

## The engine's stream through colibri's `start`

2026-09-27. colibri `08d631e` builds chapulin's objects `RAND=session`, and each session's `start`
takes the source it draws from (colibri#71). Both sessions hand it the engine's stream, and
chapulin draws from it wherever it draws. So the DoQ session's forwarding provider and every
`enter` around a call went, and with them the code CL6, CL13, QL1, QL8 and HK1 to HK3 broke.
c4milo/cocuyo#13 asked for a test of a draw after the start, and every draw now comes from the one
source. The owner ruled the same day that `chapulin_hooks` keeps `ch_assert_fail` alone. RN3 is
HK4 again: with no `enter` left, the session's reference to the module is the only one, and
removing it leaves `ch_assert_fail` undefined when the tests link. Broken against `zig build
test-chapulin` and `zig build test-chapulin-quic`. Three mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RN1 | the DoT session hands colibri a stream of its own, not the context's | chapulin draws from the engine's stream | the hello test: another seed makes the same hello | CAUGHT |
| RN2 | the DoQ session hands colibri a stream of its own, not the context's | chapulin draws from the engine's stream | the hello test: another seed makes the same hello | CAUGHT |
| RN3 | the session does not reference the hooks module | the image links `ch_assert_fail` with the session | the build of `test-chapulin`, at link | CAUGHT |

## colibri's own connection errors, and its trailers

2026-09-27. colibri v0.3.0 (`587963f`, over chapulin `0adcf33`) ends a connection on its own
errors, writes a trailer section, and says which event ended a stream (colibri#68 and #69). Its
`receive` and `send` owe the CONNECTION_CLOSE for the error they return, so cocuyo's QUIC client
and its test server dropped the close they owed themselves. The HTTP/2 test server writes its
trailer section with colibri's `write_trailers`, in place of a frame it built by hand, and the
HTTP/2 adapter asks colibri's `Event.ended_stream()` whether an event ended a response, in place
of three checks of its own. HM1 breaks the adapter against `zig build test-cocuyo_h2`, and HM2
the server against `zig build test-io`, whose engine test over that server is the one that asks
for trailers. Two mutations, two `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| HM1 | the adapter never reports a response ended | a response ends with the event that carries END_STREAM | the GET tests of `cocuyo_h2` | CAUGHT |
| HM2 | the test server writes no trailer section though its script asks for one | a response may end with a trailer section (RFC 9113 §8.1) | the engine's trailers test | CAUGHT |

## The channel in the engine model

Design §24 step 7b, 2026-09-28 (decision 33). The engine model gains DoH over colibri's channel,
written from request rules 18 to 25 (`spec/tla/engine/EngineChannel.tla`): a channel for each
server, a QUIC link and a TCP link for each channel, which the engine opens and closes when the
channel says, and seven checks. Each mutant runs on one server and one lookup through a channel
(`mutants/CH*.cfg`), and TLC finds each, in 137 to 1,092 states.

Writing the model moved rule 19: a link's socket that ends is told to the channel, and the channel
is read then (rule 17). Without the read, an exchange's end the channel held waited on a send the
socket's close had taken away. And `link ticket spent` first read every link that was not running
before an event, so a closing link that had started with a ticket, and was given another, broke
it. It reads the link that starts at the event now.

The walks TLC takes did not move. The channel's sets are empty in every configuration the replay
walks, so TLC draws nothing more on its random stream there. `zig build spec-engine` found TLC's
walks the same as the committed ones, and the replay agreed with the model over all 4,824,000
events of the full run. The engine mutations were not run again. Ten mutations, ten `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CH1 | a link's socket that ends is not told to the channel, which still counts the link open | rule 19 | links asked | CAUGHT |
| CH2 | a QUIC link's open connects the TCP link beside it too, which the channel did not ask for | rule 19 | links asked | CAUGHT |
| CH3 | a link the channel closed still reads, and still sends what the channel owed on it | rule 19 | links asked | CAUGHT |
| CH4 | a request taken while its channel shuts down goes on that channel as an exchange | rule 24 | shutting takes none | CAUGHT |
| CH5 | a channel's close drops the requests that waited for the next, which opens none | rule 24 | exchanges placed | CAUGHT |
| CH6 | a link's send end reads nothing of the channel, which keeps what it held | rule 17 | channel held while sending | CAUGHT |
| CH7 | a link's connection starts with its transport's ticket and keeps it | rule 23 | link ticket spent | CAUGHT |
| CH8 | a link's socket that ends fails every request on its channel itself | rule 19 | link end fails none | CAUGHT |
| CH9 | a drive arms no receive on a running link that has none | rule 19 | listening | CAUGHT |
| CH10 | a TCP link opened again connects while an earlier connect still borrows its address | request rule 14 | link lent | CAUGHT |

## The engine's DoH over a channel

Design §24 step 7b, 2026-09-28 (decision 33). The engine carries DoH over a channel type in
`Options.doh`, request rules 18 to 25 (`io/io_channel.zig`, `io/io_channel_link.zig`), and the
twin's channel says the steps a test queues (`sim.channel`). Broken against `zig build test-io`,
whose fourteen tests of the engine over the twin's channel are `io/io_channel_test.zig` and
`io/io_channel_link_test.zig`. CE1 and CE17 break every test: a link opened with its channel, and
a timer that tells no channel its instant came. The reopening test first let a link that
connected at once pass, since it asked only for a new opening or a wait. It asks for the wait now,
on the first opening, and CE14 is caught. Eighteen mutations, eighteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CE1 | a link opens when its channel opens, before the channel says | rule 19 | a DoH lookup opens its server's channel with its request, and no link until the channel says | CAUGHT |
| CE2 | an exchange that ends in failure tells its lookup nothing | rule 22 | an exchange that fails fails its request once, as the server's failure | CAUGHT |
| CE3 | a request its lookup left is not cancelled on its channel | request rule 6 | a request its lookup left is cancelled on its channel | CAUGHT |
| CE4 | an exchange's end gives its room to no request that waits | rule 21 | a request waits for room on its channel, and becomes an exchange once one ends | CAUGHT |
| CE5 | a channel with no request on it never shuts down | rule 24 | an idle channel shuts down, and the next channel takes a request taken meanwhile | CAUGHT |
| CE6 | a request taken while its channel shuts down goes on it as an exchange | rule 24 | the same | CAUGHT |
| CE7 | a channel's close drops the requests that waited, and opens none | rule 24 | the same | CAUGHT |
| CE8 | a TCP link's connection starts with its connect, before it has succeeded | request rule 14 | a TCP link connects first, and its connection starts at the connect's end | CAUGHT |
| CE9 | a link's socket that ends is not told to the channel | rule 19 | a link's connect that fails is told to the channel, and fails no request itself | CAUGHT |
| CE10 | a link's socket that ends fails every request on its channel itself | rule 19 | the same | CAUGHT |
| CE11 | a link the channel closed shuts at once, dropping the octets it kept | rule 19 | a link the channel closes shuts its socket once the octets it kept have gone | CAUGHT |
| CE12 | a link's connection starts with no ticket, and the kept one stays | rule 23 | each transport's ticket is kept, and the next link of that transport spends it | CAUGHT |
| CE13 | a drive arms no receive on a running link that has none | the datagram's rule 1 | a running link whose receive the loop refused has it armed at the next drive | CAUGHT |
| CE14 | a TCP link connects while an earlier opening's connect still borrows its address | request rule 14 | a TCP link opened again while its earlier connect is in flight connects at that connect's end | CAUGHT |
| CE15 | a link's send end reads nothing of the channel | request rule 17 | the channel is read at a link's send end, and tells then what it held | CAUGHT |
| CE16 | a link's socket that ends is told to the channel, which is not read | rules 17 and 19 | the channel is read when a link's socket ends, and tells then what it held | CAUGHT |
| CE17 | the engine's timer tells no channel its instant came | rule 25 | every test of the engine over the twin's channel | CAUGHT |
| CE18 | a request goes on its channel whether the channel had room or not | rule 21 | a request waits for room on its channel, and becomes an exchange once one ends | CAUGHT |

## The channel on the model's walks

Design §24 step 7b, 2026-09-28 (decision 33). The replay walks the model's two channel
configurations, one slot or two and two servers, over the twin's channel (spec/README.md). They
come first of fourteen configurations, so every walk named before comes 4,000 later. The fifteen
picks moved with them and are the same walks byte for byte: 3 and 50 are now 4003 and 4050, and
17842 is 21842. The full run, 28,000 walks and 5,628,000 events, replays clean.

Writing the replay moved the model twice, to rules 17 and 19. The engine reads a channel after it
puts a request on it, and after a link that waited for an earlier connect fails to open at that
connect's end. The model read it at neither, so an end the channel held was told in the engine and
still held in the model. Both channel configurations hold at the same states as before, and TLC
finds CH1 to CH10 again, CH4 written with the read. The twin moved once: a new channel forgot that a
link the last one closed had started with a ticket, and it keeps what a test reads of the links now.

CE1 to CE18 were broken against the walks, and against `zig build test-io` again, now fifteen
tests. CE1 was written again once a channel's opening stopped counting as going idle, and breaks
seven of them. CE17 breaks every test but the cancelled request's, which needs no read the timer
brings. CE19 breaks the read after a request is put on a channel. No test caught it at first,
since none took a request while the channel held an end. The test that a request put on its
channel has the channel read catches it now.

The short walks catch thirteen. The full run catches CE12, CE14, CE15 and CE19, at walks 4, 13, 8
and 2002, which the picks keep, nineteen in all. The model gives a channel room for every request,
so no walk reaches CE4 or CE18, and the tests catch both. Nineteen mutations, nineteen `CAUGHT`.

| # | Mutation | The channel tests | The walks | Status |
| --- | --- | --- | --- | --- |
| CE1 | a link opens when its channel opens, before the channel says | CAUGHT | short walk 1 | CAUGHT |
| CE2 | an exchange that ends in failure tells its lookup nothing | CAUGHT | short walk 1 | CAUGHT |
| CE3 | a request its lookup left is not cancelled on its channel | CAUGHT | short walk 3 | CAUGHT |
| CE4 | an exchange's end gives its room to no request that waits | CAUGHT | no walk | CAUGHT |
| CE5 | a channel with no request on it never shuts down | CAUGHT | short walk 1 | CAUGHT |
| CE6 | a request taken while its channel shuts down goes on it as an exchange | CAUGHT | short walk 1 | CAUGHT |
| CE7 | a channel's close drops the requests that waited, and opens none | CAUGHT | short walk 1 | CAUGHT |
| CE8 | a TCP link's connection starts with its connect, before it has succeeded | CAUGHT | short walk 1 | CAUGHT |
| CE9 | a link's socket that ends is not told to the channel | CAUGHT | short walk 1 | CAUGHT |
| CE10 | a link's socket that ends fails every request on its channel itself | CAUGHT | short walk 2 | CAUGHT |
| CE11 | a link the channel closed shuts at once, dropping the octets it kept | CAUGHT | short walk 3 | CAUGHT |
| CE12 | a link's connection starts with no ticket, and the kept one stays | CAUGHT | walk 4, picked | CAUGHT |
| CE13 | a drive arms no receive on a running link that has none | CAUGHT | short walk 3 | CAUGHT |
| CE14 | a TCP link connects while an earlier opening's connect still borrows its address | CAUGHT | walk 13, picked | CAUGHT |
| CE15 | a link's send end reads nothing of the channel | CAUGHT | walk 8, picked | CAUGHT |
| CE16 | a link's socket that ends is told to the channel, which is not read | CAUGHT | short walk 18 | CAUGHT |
| CE17 | the engine's timer tells no channel its instant came | CAUGHT | short walk 1 | CAUGHT |
| CE18 | a request goes on its channel whether the channel had room or not | CAUGHT | no walk | CAUGHT |
| CE19 | a request put on its channel leaves the channel unread | NOT CAUGHT, then CAUGHT by the new test | walk 2002, picked | CAUGHT |

## cocuyo_doh over colibri's channel

Design §24 step 7b, 2026-09-28 (decision 33). `cocuyo_doh` puts colibri's `client.Channel`, at
v0.4.0, under the engine's DoH interface (`io/io_doh_channel.zig`): the GET as colibri's
exchange, the response read back, what the links read kept until the channel takes it, and the
tickets the links resume with. `zig build test-cocuyo_doh` runs sixteen tests, which link
chapulin:
- thirteen of the type against colibri's server in memory
- three of the engine over it on the twin, colibri's server answering over TLS on each scripted
  server's HTTPS port

Every server runs under the test identity in `io/testdata/`. No QUIC server listens yet, so each
test reaches TCP once the fallback delay has passed. HTTP/3 waits for colibri's server over QUIC,
which v0.5.0 carries.

What writing it found:
- The engine handed `start_link` a pointer into a copy of the kept ticket, which ended before the
  call read it. The twin reads only whether a ticket was offered, and the model reduces one to a
  flag, so nothing saw it. The engine now points into the ticket it spent, and offers the ticket's
  age, as RFC 9846 §4.3.11.1 asks, which the interface now carries (CE20).
- colibri's server wrote a response ahead of the SETTINGS its HTTP/2 session owed, when the
  request came with the handshake's end. RFC 9113 §3.4 has the SETTINGS go first, and colibri's
  client failed the connection. It is reported to colibri, and until it is fixed the test server
  writes what the session owes before it responds.
- DC13 was NOT CAUGHT at first: every failed exchange in the tests had a status of 0, which fails
  it anyway. The test of a stream the server resets after a 2xx head catches it now.
- DC16's first edit did not compile, and was written again.

Twenty-five mutations, twenty-five `CAUGHT`: CE20 by `zig build test-io`, and DC1 to DC24 by `zig
build test-cocuyo_doh`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DC1 | a template whose GET would not fit is taken | its GET fits a path | the template test | CAUGHT |
| DC2 | a request takes the first buffer whether it is free or not | rule 21 | the answer-buffers test, by an assertion | CAUGHT |
| DC3 | a cancelled exchange goes on in colibri | request rule 6 | the answer-buffers test | CAUGHT |
| DC4 | a cancelled exchange keeps its buffer | rule 21 | the answer-buffers test | CAUGHT |
| DC5 | a datagram longer than the buffer is copied | `doh_datagram_bytes` | the datagram test | CAUGHT |
| DC6 | a datagram the channel has not taken keeps its place | a datagram may be dropped | the datagram test | CAUGHT |
| DC7 | stream octets past the buffer are dropped, and the TCP link goes on | request rule 7 | the overrun test | CAUGHT |
| DC8 | an overrun TCP link is closed, and the channel is not told | rule 19 | the overrun test | CAUGHT |
| DC9 | a response of any status is an answer | RFC 8484 §4.2.1 | the failed-responses test | CAUGHT |
| DC10 | content of any media type is an answer | rule 22 | the failed-responses test | CAUGHT |
| DC11 | coded content is an answer | request rule 12 | the failed-responses test | CAUGHT |
| DC12 | an answer's `Age` is not read | RFC 8484 §5.1 | the HTTP/2 test | CAUGHT |
| DC13 | an exchange that ended without a whole response is an answer | rule 22 | the reset-after-head test | CAUGHT |
| DC14 | the GET's path may go into a table | request rule 12 | the GET test | CAUGHT |
| DC15 | the GET accepts a content coding | request rule 12 | the GET test | CAUGHT |
| DC16 | a link's connection offers no ticket | rule 23 | the ticket test | CAUGHT |
| DC17 | the copy a link resumed with outlives its connection | wiped once its connection has ended | the ticket test | CAUGHT |
| DC18 | wiping a channel leaves its connections up | `wipe` | the wipe test | CAUGHT |
| DC19 | a link goes to HTTPS's 443 whatever the template names | rule 18 | the HTTP/2 test | CAUGHT |
| DC20 | a link goes to the unspecified address | rule 18 | the engine's tests | CAUGHT |
| DC21 | the version a connection speaks is told to the engine as the TCP link's close | rule 20 | the engine's tests | CAUGHT |
| DC22 | a close the channel says is not told to the engine | rule 19 | the engine's idle test | CAUGHT |
| DC23 | a finished exchange keeps its buffer | rule 21 | the answer-buffers test | CAUGHT |
| DC24 | a named server is judged by pins alone, its anchors dropped | RFC 8310 §5 | every test that reaches a server | CAUGHT |
| CE20 | a link's ticket is offered at age 0 | RFC 9846 §4.3.11.1 | the ticket-age test of the engine over the twin's channel | CAUGHT |

## The DoH example and the interop check on colibri's channel

Design §24 step 7b, 2026-09-28. `example-doh-rotor` resolves through `cocuyo_doh`
(`examples/doh_rotor.zig`), and after each turn says how its connection handshook and which version
of HTTP it came up on, which the type now reports (`connected`). The live check runs the same
program. Through Cloudflare and Google it came up on HTTP/3, and the second turn resumed. The DoT
and DoQ examples each held the walk that reads a root's anchor, and it is `examples/root_text.zig`
now.

The interop check runs DoH against dnsproxy on HTTP/3, and against a second dnsproxy that listens
for HTTPS on TCP alone, where the channel comes up on HTTP/2 once the fallback delay has passed. On
each, three names resolve at once and a fourth over a connection that resumes, every turn on the
version asked for, and the typed records read. DC25 to DC27 break the report against `zig build
test-cocuyo_doh`, and IX5 to IX7 plant engine bugs against the interop check, run against dnsproxy
v0.85.0. Six mutations, six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DC25 | the version the channel came up on is not kept | `connected` | the HTTP/2 and HTTP/1.1 tests | CAUGHT |
| DC26 | a link that offered a ticket says it offered none | `connected` | the ticket test | CAUGHT |
| DC27 | a connection's resumption is read from the other transport's session | `connected` | the ticket test | CAUGHT |
| IX5 | a channel never tries QUIC first | rule 18 | the interop check over DoH on HTTP/3: both turns over h2 | CAUGHT |
| IX6 | a channel hands the engine no ticket | rule 23 | the interop check over DoH, on both versions: in full | CAUGHT |
| IX7 | the fallback delay never ends, so TCP opens only once QUIC has failed | rule 18 | the interop check over DoH on HTTP/2: every lookup timed out | CAUGHT |

## The TCP request connections removed

Design §24 step 7b, 2026-09-29 (decision 33). colibri's channel carries DoH, so `cocuyo_h2`, the
HTTP/3 half of `cocuyo_quic`, `Options.h2` and the engine's request connections over TCP went,
with their tests and the twin's QUIC over TCP. The request connections carry DoQ alone, as they
did before HTTP/2 came. The two reads rule 17 added to them went too: only HTTP/2 needed them, and
the channel keeps its own. The model lost `RStream` and its three configurations.

These mutations broke code that is gone, and retire with it:

- RQ16 to RQ22, the model's rules for request connections over TCP.
- TC1 to TC9, the engine's request connections over TCP.
- TR1 to TR3, the reads only HTTP/2 needed, and TR5, the twin's hold.
- HT1 to HT23, HM1, HM2 and H1 to H3: `cocuyo_h2`, its test server and their tests.
- QH1 to QH7 and QH9 to QH21, the HTTP/3 half, and DE1 to DE7, the engine's DoH over it. DE8
  stands, over DoQ.

What the removal found:

- TR4 went uncaught. The engine's test of cancelled DoQ streams caught it through the read at a
  send's end, which went. A test of `cocuyo_quic` now holds a cancelled stream's answer back and
  reads the connection before it comes, as a datagram without the answer or the timer would. The
  answer must still be read to its end, which ends the stream's receiving half (RFC 9000 §3.2).
- One engine test came over to the channel: a template the engine cannot read fails its server
  before its channel opens. CE21 breaks what it checks. No walk reaches it, since the model's
  channel always opens.
- RW2 and RW8 were written again for the code as it stands. DC21's edit had not applied since DC25
  changed its line, and was written again.

The walks were written again from the new model, which draws its choices anew. The full run,
24,000 walks and 4,824,000 events, replays clean. The picks were chosen again from it, each the
first walk that catches a mutation the short walks miss: 4, 8, 13, 2002, 4006, 4041, 8046, 12011,
13182, 16008, 16068, 16478 and 17842. Every mutation of the engine's set ran again, one hundred
and eighteen, and each is `CAUGHT`. The short walks catch sixty-five, the picks sixteen more, and
the steps thirty-seven.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RW2 | the handshake's end is taken whatever protocol it negotiated | RFC 9250 §4.1 | short walk 24 | CAUGHT |
| RW8 | a connection closes for idleness with requests on it | request rule 9 | short walk 22 | CAUGHT |
| TR4 | a cancelled DoQ stream frees its slot before its answer or reset is read | colibri keeps a stream's place until both its halves end | the held-answer test of `cocuyo_quic` | NOT CAUGHT, then CAUGHT |
| CE21 | a request whose channel cannot open is dropped, and not failed | request rule 7 | the unreadable-template test | CAUGHT |
| DC21 | the version a connection speaks is told to the engine as the TCP link's close | rule 20 | the engine's tests | CAUGHT |

## HTTP/3 against colibri's server, at v0.5.0

Design §24 step 7b, 2026-09-29. cocuyo pins colibri v0.5.0 (`bb9263e`), whose server speaks HTTP/3
over QUIC. `cocuyo_doh`'s tests gain a server over QUIC under the test identity
(`io/io_doh_channel_server_quic.zig`), and two tests of HTTP/3 against it: the type in memory, a
query answered and a second channel whose QUIC link resumes, and the engine over it on the twin.
The TCP test server takes colibri's new calls, and no longer writes the SETTINGS its HTTP/2
session owes ahead of a response: colibri writes the preface first since its `e3126a9`.

DC28 hands the channel a QUIC link's datagrams with no source address, which only a real QUIC
server shows, and both HTTP/3 tests catch it. DC1 to DC27 ran again at the tag, each against
`zig build test-cocuyo_doh`, now eighteen tests. Twenty-eight mutations, twenty-eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DC28 | the channel is handed its QUIC link's datagrams with no source address | colibri reads a datagram's source | both HTTP/3 tests | CAUGHT |

## The GOAWAY drain removed

Design §24, request rule 13, 2026-09-29 (c4milo/cocuyo#33). The request connections carry DoQ
alone since the TCP request connections went, and DoQ has no GOAWAY (RFC 9250). So `cocuyo_quic`
never said one came, and only the twin's QUIC did. The drain went from the design, the model and the
code: the `draining` stage, the `goaway` step, the `goaway` of the request interface's `Next`, the
twin's GOAWAY and the tests of the drain. What rule 13 said of a failure while the engine's own
close is going stands under rule 9: the connection fails none of the requests that wait, and opens
again for them. A closing connection has no request on a stream, since it closed only once it had
none, so failing only its streams' requests was failing none, and the engine now reopens it at
once.

These mutations broke code that is gone, and retire with it:

- RQ12, RQ13 and RQ15, the model's drain. RQ14 stands, for a connection that closes.
- RW12 and RW14 to RW16, the engine's drain.
- RW17, which failed the requests that wait on a closing connection along with those on its
  streams. It has none on a stream, so the code RW17 edited went, and RW13 breaks the same rule.

RW13 was written again for a connection that closes. The walks were written again from the new
model. The full run, 24,000 walks and 4,824,000 events, replays clean. The picks were chosen again
from it: 4, 8, 13, 2002, 4020, 4075, 8046, 12011, 13182, 16008, 16068, 16478 and 17842. RW6 falls
to the short walks now, and RW10 and RW13 take walks 4020 and 4075. Every mutation of the engine's
set ran again, one hundred and fourteen, and each is `CAUGHT`: sixty by the short walks, sixteen
by the picks, and thirty-eight by their steps.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| RW13 | a connection that fails while it closes fails the requests that wait | request rule 9 | full run walk 4075, picked | CAUGHT |

## Truncated answers kept out of the cache, and recalled TTLs aged

2026-10-08 (c4milo/cocuyo#39). Two defects in what the cache keeps and hands back. First, a UDP
answer with TC set that `ignore_truncation` takes as it is is now marked `truncated`. The
consumer is told, and `Cache.put` refuses it, as RFC 1035 §7.4 asks of a possibly partial set
(docs/design.md §18, §19 step 11). Second, a hit now ages every record's TTL, not only the
answer's smallest. The cache keeps the life it gave an entry, capped, as the answers' own TTL.
The lookup the cache answers lowers every TTL by that life less what is left (RFC 1035 §6.1.3;
design §18, §20 step 16).

Each mutation was broken against the targets its row names: `zig build test-resolver`,
`test-wire`, `test-cache` or `test-cocuyo`. TA4 first ran against `test-wire` and was not caught
there: `Answers.age` had no test in its own file, only callers in `resolver`. The test was written
in `src/wire/response_answers.zig`, and TA4 and TA5 ran against it. TA2 is caught by the new
test's expectation, and by the assertion that only `ignore_truncation` reads a truncated UDP
answer, under the TCP and DoH or DoQ tests. The eight are kept as data in
`tools/mutations/lookup.zon`, each against the first target its row names, and `zig build
mutations -- lookup` ran them again and caught all eight there. Eight mutations, eight `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TA1 | an answer `ignore_truncation` takes is not marked truncated | RFC 1035 §7.4 | the `ignore_truncation` test, `test-resolver` | CAUGHT |
| TA2 | TC marks the answer over a stream too | §19 step 11, TC over a stream read as nothing | the `ignore_truncation`-over-TCP test, the TCP and DoH or DoQ truncated tests, `test-resolver` | CAUGHT, then retired |
| TA3 | a hit sets the answer's smallest TTL alone, and each record keeps the TTL it was stored with | RFC 1035 §6.1.3 | the recalled-records test, `test-resolver`; the hit-through-the-table test, `test-cocuyo` | CAUGHT |
| TA4 | `Answers.age` lowers the smallest TTL alone | RFC 1035 §6.1.3, RFC 8484 §5.1 | the age test, `test-wire`; the recalled-records and DoH `Age` tests, `test-resolver` | CAUGHT |
| TA5 | `Answers.age` wraps a record's TTL past zero | RFC 1035 §6.1.3 | the age test, `test-wire` | CAUGHT |
| TA6 | a put keeps the answers' own TTL rather than the life the entry is given | §18 | the life-a-hit-holds test, `test-cache`; the hit-through-the-table test, `test-cocuyo` | CAUGHT |
| TA7 | a put in place keeps the TTL before the cap | §18 | the life-a-hit-holds test, `test-cache` | CAUGHT |
| TA8 | a new entry keeps the TTL before the cap | §18 | the life-a-hit-holds test, `test-cache`; the hit-through-the-table test, `test-cocuyo` | CAUGHT |

## Truncated answers marked on every channel, and a memory that reports more than it gave

2026-10-08 (c4milo/cocuyo#39, after review). Two changes to the fix above. First, an answer read
from a message with TC set is marked `truncated` on every channel, not only over UDP under
`ignore_truncation`. TC says the message was cut to fit its channel (RFC 1035 §4.1.1), and a
stream's limit is 65535 octets (RFC 9250 §4.6). Over DoH it can also say the server could not
get the full answer (RFC 8484 §10). Before this, the cache kept such an answer from a DoH proxy.
Second, a memory that reports more left than the answers' own TTL no longer trips an assertion.
Nothing is lowered, and the answer reports what the memory says (docs/design.md §5, §18, §20).

TA2 is retired: the rule it broke, an answer over a stream left unmarked, was the defect. TA1
and TA3 were written again for the new code and caught, TA1 by `test-resolver` and TA3 by
`test-resolver` and `test-cocuyo`. Each new mutation was broken against `zig build
test-resolver`. Then `zig build mutations -- lookup` ran TA1 and TA3 to TA12 again and caught all
eleven. Four new mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TA9 | TC over TCP leaves the answer unmarked | RFC 1035 §4.1.1, §7.4 | the TCP truncated test and the `use_tcp` truncated test, `test-resolver` | CAUGHT |
| TA10 | TC over DoH or DoQ leaves the answer unmarked | RFC 8484 §10, RFC 1035 §7.4 | the DoH or DoQ truncated test, `test-resolver` | CAUGHT |
| TA11 | the time spent is not held at zero, so a memory that reports more than it gave overflows it | §20, a memory's own TTL | the more-left-than-given test, by a panic, `test-resolver` | CAUGHT |
| TA12 | the answer reports the answers' own TTL, not the more a memory says is left | §20, a memory's own TTL | the more-left-than-given test, `test-resolver` | CAUGHT |

## A search walk's end bounded by every negative on the way

2026-10-08 (c4milo/cocuyo#38). A relative name walks the search list inside one `Lookup`, and
the table remembers the walk's end under the name as asked. Each candidate's NXDOMAIN or NODATA
replaced the negative TTL before it. So a walk whose candidates were all negative reported the
last one's negative TTL, not the smallest. An answer reached past negatives reported its own TTL.
Now the lookup keeps the smallest negative TTL of the walk. `Failure.negative_ttl_seconds`
reports it, and `Answer.ttl_seconds` is no larger than it. A negative with no SOA carries zero,
so the walk's end is one no cache keeps (RFC 2308 §5; docs/design.md §5, §18, §20). The bound
lives in the field that held the last negative TTL, so the lookup stays 3048 octets.

The seven are kept as data in `tools/mutations/lookup.zon`. `zig build mutations -- lookup`
broke each against `zig build test-resolver` and caught all seven. Each was then broken again by
hand, to name the tests that fail. WN4 is caught by the assertion in
`bound_walk`, under the all-negative walk test. DH13 and DH14 were written again for the new
code. DH14 and TT7 had stopped applying after the truncation fix above, and TT7 was written
again for that code. The tool ran DH13, DH14, TT5 and TT7 again and caught all four. Seven new
mutations, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| WN1 | NXDOMAIN replaces the walk's negative TTL rather than keeping the smaller | §5 search list policy, RFC 2308 §5 | the all-negative walk test and the no-SOA walk test, `test-resolver` | CAUGHT |
| WN2 | NODATA replaces the walk's negative TTL rather than keeping the smaller | §5 search list policy, RFC 2308 §5 | the all-negative walk test, `test-resolver` | CAUGHT |
| WN3 | the walk keeps the last candidate's negative TTL, as before #38 | §5 search list policy, RFC 2308 §5 | the all-negative walk test and the no-SOA walk test, `test-resolver` | CAUGHT |
| WN4 | the walk keeps the first candidate's negative TTL and ignores the rest | §5 search list policy, RFC 2308 §5 | the assertion in `bound_walk`, under the all-negative walk test, `test-resolver` | CAUGHT |
| WN5 | an answer past negative candidates keeps its own TTL, as before #38 | §5 search list policy, RFC 2308 §5 | the answer-past-negatives test, the no-SOA walk test and the table's walk-end test, `test-resolver` | CAUGHT |
| WN6 | the walk starts bounded at zero, so every answer is kept for nothing | §5 search list policy | every test that reads an answer's TTL: the matching-response, MX, chain, DoH `Age` and negative TTL tests, `test-resolver` | CAUGHT |
| WN7 | the walk bounds the answer the caller reads, and not the answers a memory is handed | §20, what the table remembers | the answer-past-negatives test and the table's walk-end test, `test-resolver` | CAUGHT |

## A search walk's end bounded by every negative on the way, after review

2026-10-08 (c4milo/cocuyo#38, after review). The doc of `Failure.negative_ttl_seconds` promised
the walk's smallest negative TTL for every failure, and `AddressLookup`'s failure is the same
struct. `AddressLookup` walks the search list with one absolute lookup per candidate, and its
failure carries its last lookup's negative TTL. The doc and design §4, §5 and §19 step 14 now
say which is which. §18 now says the bound is a TTL as each response carried it, not an instant.
`bound_walk` gained an assertion for the negative space: the walk moves on only while the lookup
runs.

WN8 was broken against `zig build test-resolver` by hand, to name the tests that fail. Then
`zig build mutations -- lookup` ran WN1 to WN8 and caught all eight. One new mutation, one
`CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| WN8 | the walk's bound asserts the lookup has settled rather than that it runs | §5 search list policy, the assertion that a settled lookup's end does not move | every test whose walk moves past a negative: the NXDOMAIN, NODATA and negative TTL tests, the DoH `Age` test and the table's walk-end test, by a panic, `test-resolver` | CAUGHT |

## SERVFAIL, REFUSED and NOTIMP counted against the server

2026-10-08 (c4milo/cocuyo#37). `Lookup.apply` reset a server's failure count for every response
that passed the checks of §7, before it read the rcode. So a server that answered SERVFAIL,
REFUSED or NOTIMP to every query kept a count of zero and stayed first in every lookup's order. A
response then ignored, for an rcode cocuyo does not know or a malformed answer section, had reset
the count and taught its cookie all the same. Now an answer that marks the lookup's server failure
counts against its server, as a timeout does. Any other answer the lookup accepts resets the
count, and a response the lookup ignores changes no server state (docs/design.md §19 step 12).
The engine model changed first: a `servfail` reply records a failure (`EngineTable.tla`).

FR1 to FR12 break the code. Each was broken by hand against `zig build test-resolver`, to name
the tests that fail. FR2, FR3, FR5 and FR6 were first written with a parameter left unused, which
does not compile, and were written again to discard it. The twelve are kept as data in
`tools/mutations/lookup.zon`, and `zig build mutations -- lookup` ran the whole set again: FR1 to
FR12 and every other mutation that still applies are `CAUGHT`. FR1 is caught by the replays too,
under `zig build test-tools`. FR13 breaks the model, and is kept in `tools/mutations/engine.zon`.

The walks were written again from the new model. The full run, 24,000 walks and 4,824,000
events, replays clean. Then `zig build mutations -- engine` ran every mutation of the engine's set
on it. RW13 was the one the picks missed: the full run catches it first at walk 4212 now, not
4075. So the picks are 4, 8, 13, 2002, 4020, 4212, 8046, 12011, 13182, 16008, 16068, 16478 and
17842, and the tool ran the twenty-two the picks must catch again and caught each. Of the 114
mutations that apply, fifty-nine fall to the short walks, sixteen to the picks and thirty-nine to
their steps, FR13 among them.

Seven mutations no longer apply, in the lookup set DH5, DH10 to DH12, QU5 and TT2, and in the
engine set CR4. The code they edit moved before this change, and each must be written again.
Thirteen new mutations, thirteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| FR1 | SERVFAIL, REFUSED, NOTIMP and BADVERS count as no failure at all: the count resets, and the lookup's failure goes unmarked | §19 step 12 | the SERVFAIL-counts, asked-last and SERVFAIL-moves tests, and the `primary`, failure-TTL and reverse-walk tests, which end in `Timeout` once no failure is marked, `test-resolver`; the engine's short and picked walks and the lookup's slice, `test-tools` | CAUGHT |
| FR2 | an answer that marks the server's failure records a success, and marks the lookup's failure still | §19 step 12 | the assertion in `heard`, under every test that hears a failing answer: the SERVFAIL, FORMERR, BADCOOKIE, count, `primary`, failure-TTL and reverse-walk tests, `test-resolver` | CAUGHT |
| FR3 | an answer's failure is recorded at instant zero, not the instant it came | §19 step 12, the instant `failover_retry_delay_ns` runs from | the SERVFAIL-counts test and the failing-answers test, `test-resolver` | CAUGHT |
| FR4 | an answer that marks no failure leaves the count as it stood | §19 step 12 | the assertion in `heard`, under the SERVFAIL-counts, any-other-answer, ignored-response and reverse-walk tests, `test-resolver` | CAUGHT |
| FR5 | BADCOOKIE over a stream resets the count | §19 step 12, RFC 7873 §5.3 | the BADCOOKIE test over TCP and the DoH or DoQ BADCOOKIE test, `test-resolver` | CAUGHT |
| FR6 | BADCOOKIE over UDP, which has TCP left to try, counts against the server | §19 step 12, RFC 7873 §5.3 | the BADCOOKIE test over UDP and the any-other-answer test, `test-resolver` | CAUGHT |
| FR7 | FORMERR from a server asked with EDNS0, which has EDNS0 left to drop, counts against it | §19 step 12, RFC 6891 §6.2.2 | the any-other-answer test, `test-resolver` | CAUGHT |
| FR8 | a response ignored for an rcode cocuyo does not know resets the count and teaches its cookie | §19 step 12, an ignored response changes nothing | the ignored-response test, `test-resolver` | CAUGHT |
| FR9 | a response ignored for a malformed answer section resets the count and teaches its cookie | §19 step 12, §16 decision 10 | the ignored-response test, `test-resolver` | CAUGHT |
| FR10 | the server's state hears the answer after the lookup moves on, so another server is charged | §19 step 12, the server that answered | the SERVFAIL-counts and asked-last tests, the BADCOOKIE tests over TCP and over DoH or DoQ, and the assertion that a settled lookup hears nothing, `test-resolver` | CAUGHT |
| FR11 | a CNAME chain too long, the server's answer, leaves the count as it stood | §19 step 12 | the any-other-answer test, `test-resolver` | CAUGHT |
| FR12 | a truncated answer over UDP leaves the count as it stood | §19 step 12 | the any-other-answer test, `test-resolver` | CAUGHT |
| FR13 | the engine model resets the count on SERVFAIL, as before #37 | §19 step 12 in the model | `zig build spec-engine`, whose walks from TLC differ from the committed ones | CAUGHT |
| RW13 | a connection that fails while it closes fails the requests that wait | request rule 9 | full run walk 4212, picked | CAUGHT |

## SERVFAIL, REFUSED and NOTIMP counted against the server, after review

2026-10-08 (c4milo/cocuyo#37, after review). Every way a lookup moves to the next server now
records a failure, and a SERVFAIL had been the one way that recorded none. So the five engine
configurations bounded at no failure no longer reach the second server, and their headers and
spec/README.md did not say so. TLC confirmed it with one more invariant in a copy of the model,
and both now say it. The doc of `heard` and design §19 step 12 now say that an ignored response
teaching no cookie departs from RFC 7873 §5.3. FR1's row above described its edit as the rule
before #37. The edit also leaves the lookup's failure unmarked, and its row and
`tools/mutations/lookup.zon` now say so. No check changed, so no mutation is new.

2026-10-09. The coverage came back. The configuration of one lookup over TLS at two operations
and no failure went, since `Engine_tls_1_2_bound_2_1` is the same configuration at one failure.
The other four went to one failure and were renamed for it: `Engine_tcp_2_2_bound_4_1`, checked
on each push, and `Engine_tls_1_2_bound_3_1`, `Engine_tls_2_2_bound_2_1` and
`Engine_udp_2_1_bound_4_1`, checked once a day. Each holds and reaches the second server again
(spec/README.md). No check changed, so no mutation is new.

The seven mutations the section above found no longer applying were written again for the code
where it moved: DH5 and QU5 to `lookup_init.zig`, DH10 to DH12 and TT2 to `response_answers.zig`,
and CR4 to the list of fields `restart` keeps in `io_tcp.zig`. `zig build mutations -- lookup`
ran the six of the lookup set, and `zig build mutations -- engine` ran CR4, which the short walks
catch at walk 55. Each was then broken again by hand, to name the tests that fail. The engine set
now splits 115 mutations: sixty to the short walks, sixteen to the picks and thirty-nine to their
steps. Seven mutations written again, seven `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DH5 | a query over DoH mixes the name's case | §22, the same octets | the DoH or DoQ query-shape test, `test-resolver` | CAUGHT |
| DH10 | an answer's TTL keeps its `Age` | RFC 8484 §5.1 | the `Age` test, and by a panic the memory's recall tests, `test-resolver` | CAUGHT |
| DH11 | an `Age` past the TTL wraps it | RFC 8484 §5.1, never below zero | the `Age` test, `test-resolver` | CAUGHT |
| DH12 | a kept record's TTL keeps its `Age` | RFC 8484 §5.1 | the kept-record `Age` test and the recalled-records test, `test-resolver` | CAUGHT |
| QU5 | a DoQ query mixes the name's case | §23, DoH's shape | the DoH or DoQ query-shape test, `test-resolver` | CAUGHT |
| TT2 | an empty collection's smallest TTL is zero | the smallest of nothing is the largest | the A record, CNAME-and-target and MX collecting tests, `test-wire` | CAUGHT |
| CR4 | closing a slot forgets its connect is in flight | rule 10 | the short walks, at walk 55; the slot-reset test, `test-io` | CAUGHT |

## A fresh client cookie until a server cookie pairs with it

2026-10-08 (c4milo/cocuyo#36). Each server's client cookie was made once, from the table's seed
and the server's address, and every query with EDNS0 carried it for the life of the table, whether
or not the server had ever answered with a server cookie. RFC 9018 §3 and §8.1 forbid that. Now a
query to a server whose server cookie is not known carries a fresh client cookie, drawn by its
transaction and mixed with the server's address and port and the transport. A server cookie is
kept with the client cookie that drew it, and later queries carry the pair. A server that answers
a fresh cookie without one is sent none for `cookie_silence_ns`, five minutes. The lookup records
the cookie its query carried, and check 6 compares the response with that record. A first
BADCOOKIE over a stream is retried on the stream with the fresh server cookie, where it advanced
the server before (docs/design.md §5, §7 and §19 step 10).

The design changed first, then the model: `onReply` in `spec/lean/Spec/Lookup.lean` retries a
first BADCOOKIE over TCP, and three proofs took the new branch, `request_never_stream`'s with the
hypothesis that the lookup is over DoH or DoQ. The slice was written again, 4,414 transitions
where it held 3,694. `zig build spec` replays the whole transcript, 2,680,454 transitions under
109 configurations, the engine's full run of 4,824,000 events, and the walks, and each agrees.
The engine model has no cookies and is unchanged.

CO1 to CO21 and CO25 to CO27 break the code, each by hand against `zig build test-resolver`, and
CO16 to CO18 against `zig build test-tools` too, to name the tests that fail. CO22 to CO24 break
the model, against `zig build spec-lean`. All are kept as data in `tools/mutations/lookup.zon` and
`tools/mutations/lean.zon`, and `zig build mutations` ran each again and caught it. Seven
mutations of the lookup set no longer applied, since the code they edit moved: DH18 and QU9,
which edit `poll`'s call to the query builders, and FR1 and FR4 to FR7, which edit
`fails_server` and `heard`. FR2 and FR3 applied and no longer compiled: they discard `now_ns`,
which `heard` now reads for the cookie as well. Each of the nine was written again, and broken
by hand to name the tests that fail. Then `zig build mutations` ran the whole of the lookup set,
121 mutations, the Lean set, 11, and the address set, 35, and every one is `CAUGHT`. The engine
set was not run again: the engine and its model are unchanged, and the full run of TLC's walks
replays clean. Twenty-seven new mutations, twenty-seven `CAUGHT`; nine written again, nine
`CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CO1 | a fresh client cookie leaves out the transaction's draw, so a server sees one cookie on every query | RFC 9018 §3, §8.1 | the per-transaction, response-checked-against-its-own-cookie and silence tests, and the fresh-cookie test of `servers.zig`, `test-resolver` | CAUGHT |
| CO2 | every transaction draws the same cookie entropy | RFC 9018 §3, 64 bits of entropy | the four-fresh-values test of `entropy.zig`, and the per-transaction, response-checked and silence tests, `test-resolver` | CAUGHT |
| CO3 | a fresh client cookie leaves out whether the query goes over a stream, so the TCP query after TC=1 repeats the UDP one's | RFC 9018 §8.1 | the per-transaction test and the fresh-cookie test of `servers.zig`, `test-resolver` | CAUGHT |
| CO4 | a fresh client cookie leaves out the server's address | RFC 9018 §3, a different cookie per server address | the fresh-cookie test of `servers.zig`, `test-resolver` | CAUGHT |
| CO5 | check 6 compares the client cookie with the server's pair, not the one the query carried | §7 check 6, RFC 7873 §5.3, §7.1 | every cookie test that answers with a cookie, and the any-other-answer test, `test-resolver` | CAUGHT |
| CO6 | a query that carries the pair records the client cookie it carried before | §7 check 6 | the pair test, `test-resolver` | CAUGHT |
| CO7 | the pair keeps a client cookie the server cookie did not answer | RFC 9018 §3 | the pair, response-checked and UDP BADCOOKIE tests, and the pair test of `servers.zig`, `test-resolver` | CAUGHT |
| CO8 | a later server cookie is not learned once a pair is kept | RFC 7873 §5.3 | the pair and response-checked tests, `test-resolver` | CAUGHT |
| CO9 | a response without a COOKIE option to a fresh cookie stands once the server has given a cookie since | RFC 7873 §5.3 | the response-checked test, through the assertion in `Servers.silence`, `test-resolver` | CAUGHT |
| CO10 | a query that carried no COOKIE option checks the response's | §7 check 6, none expected | seventeen tests whose server fell silent, the chain, failover, negative, request and address-lookup tests among them, `test-resolver` | CAUGHT |
| CO11 | a query that carried no COOKIE option learns the response's | RFC 7873 §5.3, nothing to check it against | the first-query and silence tests, and the assertion in `lookup_cookie.learn`, `test-resolver` | CAUGHT |
| CO12 | a server that answers a fresh cookie without one is never silenced | RFC 9018 §3 | the silence tests, `test-resolver` | CAUGHT |
| CO13 | a query through the silence carries a fresh cookie all the same | RFC 9018 §3 | the silence test and the silence test of `servers.zig`, `test-resolver` | CAUGHT |
| CO14 | the silence lasts half of `cookie_silence_ns` | `cookie_silence_ns`, RFC 9018 §3 | the silence test and the silence test of `servers.zig`, `test-resolver` | CAUGHT |
| CO15 | the silence outranks a pair learned through it | RFC 7873 §5.1, the pair once known | the learned-through-the-silence test and the silence test of `servers.zig`, `test-resolver` | CAUGHT |
| CO16 | a first BADCOOKIE over a stream advances the server, as before #36 | §5, RFC 7873 §5.3 | the `use_tcp` and truncated-TCP BADCOOKIE tests, `test-resolver`; the slice, at line 127, `test-tools` | CAUGHT |
| CO17 | the retry of a BADCOOKIE over the TCP truncation led to goes back to UDP | §5, the retry on the stream | the truncated-TCP BADCOOKIE test, `test-resolver`; the slice, at line 127, `test-tools` | CAUGHT |
| CO18 | the retry over a stream does not spend the server's retry | §5, one retry per server | the `use_tcp` and truncated-TCP BADCOOKIE tests, `test-resolver`; the slice, at line 127, `test-tools` | CAUGHT |
| CO19 | the retry over a stream keeps its transaction | §7, a re-query is a new transaction | the `use_tcp` BADCOOKIE test, `test-resolver` | CAUGHT |
| CO20 | BADCOOKIE over DoH or DoQ, where no cookie went, is retried | §5, §22, §23 | the DoH or DoQ BADCOOKIE test, `test-resolver` | CAUGHT |
| CO21 | the retry over a stream counts against the server | §19 step 12 | the `use_tcp` BADCOOKIE test, `test-resolver` | CAUGHT |
| CO22 | the model advances the server at a first BADCOOKIE over a stream, as before #36 | §5 in the model | `zig build spec-lean`: the committed slice is not the one the model writes | CAUGHT |
| CO23 | the model retries a BADCOOKIE over DoH or DoQ on a stream | §5, §22, §23 in the model | `zig build spec-lean`: `onReply_noStream`, under `request_never_stream`, no longer proves | CAUGHT |
| CO24 | the model's retry over a stream does not spend the server's retry | §5 in the model | `zig build spec-lean`: `onReply_le`, under `step_le`, no longer proves, since the retry would raise the measure | CAUGHT |
| CO25 | a response's client cookie is accepted whatever it is, its check now in `lookup_cookie.zig` | RFC 7873 §5.3 | the wrong-cookie test, `test-resolver` | CAUGHT |
| CO26 | a server cookie is never learned, its learning now in `lookup_cookie.zig` | RFC 7873 §5.3 | seven cookie tests, the pair, BADCOOKIE and no-cookie-after tests among them, `test-resolver` | CAUGHT |
| CO27 | a response without a COOKIE option to a fresh cookie is a discard before the server has given one | RFC 7873 §5.3 | every test whose answers carry no OPT record, the address-lookup tests among them, `test-resolver` | CAUGHT |
| DH18 | a lookup over DoH asks for a datagram, written again for `poll` handing the builders the instant | §22 | the DoH or DoQ request tests, `test-resolver` | CAUGHT |
| QU9 | a lookup over DoQ asks for a datagram, written again the same way | §23 | the DoH or DoQ request tests, `test-resolver` | CAUGHT |
| FR1 | SERVFAIL, REFUSED, NOTIMP and BADVERS count as no failure at all, written again for `bad_cookie_fails` | §19 step 12 | the SERVFAIL-counts, asked-last and SERVFAIL-moves tests, and the `primary`, failure-TTL and reverse-walk tests, `test-resolver` | CAUGHT |
| FR2 | an answer that marks the server's failure records a success, written again without discarding `now_ns` | §19 step 12 | the assertion in `heard`, `test-resolver` | CAUGHT |
| FR3 | an answer's failure is recorded at instant zero, written again without discarding `now_ns` | §19 step 12 | the SERVFAIL-counts test, `test-resolver` | CAUGHT |
| FR4 | an answer that marks no failure leaves the count as it stood, written again for `cookies.learn` | §19 step 12 | the assertion in `heard`, `test-resolver` | CAUGHT |
| FR5 | BADCOOKIE over a stream that fails the lookup over resets the count, written again for `bad_cookie_fails` | §19 step 12, RFC 7873 §5.3 | the UDP and `use_tcp` BADCOOKIE tests and the DoH or DoQ BADCOOKIE test, `test-resolver` | CAUGHT |
| FR6 | BADCOOKIE over UDP, which has TCP left to try, counts against the server, written again the same way | §19 step 12, RFC 7873 §5.3 | the UDP and `use_tcp` BADCOOKIE tests and the any-other-answer test, `test-resolver` | CAUGHT |
| FR7 | FORMERR from a server asked with EDNS0 counts against it, written again the same way | §19 step 12, RFC 6891 §6.2.2 | the any-other-answer test, `test-resolver` | CAUGHT |

## What a response teaches of cookies, after review

2026-10-09 (c4milo/cocuyo#36 and #37, after review). "If the COOKIE option Client Cookie is
correct, the client caches the Server Cookie provided, even if the response is an error response
(RCODE non-zero)" (RFC 7873 §5.3). The fix for #37 had a response the lookup then ignores, for an
rcode cocuyo does not know or a malformed answer section, teach no cookie, and recorded that as a
departure from §5.3. The owner ruled on 2026-10-09 that cocuyo follows §5.3. So `apply` now caches
the server cookie once the checks of §7 pass, before it reads the rcode or the answer section
(`lookup_cookie.learn`). An ignored response still changes no failure count. One without a COOKIE
option starts no silence: only `heard`, which an answer the lookup takes reaches, starts it
(`lookup_cookie.silence_if_missing`). Design §19 steps 10 and 12 changed first. The models hold
no server cookie and no silence, so neither changed, and the replays agree.

The review of #36 asked for a mutation on the guard that makes a client cookie echoed alone, with
no server cookie, teach nothing. CO32 breaks it, and the assertion in `Servers.learn`, which takes
a server cookie of 8 to 32 octets, catches it under every test that echoes a client cookie alone.
The tests of `lookup_cookie.zig` moved into that file from `lookup_cookie_test.zig`, which keeps
the tests of BADCOOKIE, and the resolver module's test block names it.

CO28 to CO34 were each broken by hand against `zig build test-resolver`, to name the tests that
fail. FR4 and CO12 no longer applied, since the silence moved out of `learn`, and each was written
again and broken by hand the same way. FR8's and FR9's edits still apply, and what they break
changed: an ignored response teaches its cookie by design now, so each resets the count and,
without a COOKIE option, starts the silence. Their rows in `tools/mutations/lookup.zon` say so.
Then `zig build mutations -- lookup` ran FR1 to FR12, CO1 to CO21 and CO25 to CO34, 43
mutations, and caught each. Seven new mutations, seven `CAUGHT`; two written again, two
`CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CO28 | an ignored response teaches no server cookie: the cookie is learned only from an answer the lookup takes, as #37 had it | RFC 7873 §5.3 | the ignored-response cookie test, both halves, `test-resolver` | CAUGHT |
| CO29 | a response ignored for an rcode cocuyo does not know teaches no server cookie | RFC 7873 §5.3 | the ignored-response cookie test, its unknown-rcode half, `test-resolver` | CAUGHT |
| CO30 | a response ignored for a malformed answer section teaches no server cookie: the cookie of an answer to collect waits for its answer section | RFC 7873 §5.3 | the ignored-response cookie test, its malformed half, `test-resolver` | CAUGHT |
| CO31 | an ignored response without a COOKIE option starts the silence | §19 step 10, the silence needs an answer the lookup took | the ignored-response silence test, `test-resolver` | CAUGHT |
| CO32 | a client cookie echoed alone, with no server cookie, is learned as a pair | RFC 7873 §5.3, no server cookie provided | the assertion in `Servers.learn`, by a panic under the per-transaction test and the truncated-TCP BADCOOKIE test, `test-resolver` | CAUGHT |
| CO33 | a response that carries a COOKIE option starts the silence too | RFC 9018 §3 | ten tests: the per-transaction test, and by the assertion in `Servers.silence` the pair, response-checked, wrong-cookie, no-cookie-after, learned-through-the-silence, any-other-answer and three BADCOOKIE tests, `test-resolver` | CAUGHT |
| CO34 | a response to a query that carried no COOKIE option starts the silence, or moves its end | RFC 9018 §3, no client cookie went unanswered | the silence test, `test-resolver` | CAUGHT |
| CO12 | a server that answers a fresh cookie without one is never silenced, written again for `silence_if_missing` | RFC 9018 §3 | the silence, learned-through-the-silence and ignored-response silence tests, `test-resolver` | CAUGHT |
| FR4 | an answer that marks no failure leaves the count as it stood, written again for `silence_if_missing` | §19 step 12 | the assertion in `heard`, by a panic under the `use_tcp` BADCOOKIE, SERVFAIL-counts, any-other-answer, ignored-response and reverse-walk tests, `test-resolver` | CAUGHT |

## Each server's wait from its measured latency

2026-10-09. The owner ruled that each server's wait comes from its measured latency, with the
numbers c-ares's features page gives (design §5, §16 decision 36). A sample is the time from a
transaction's send to a response the lookup accepts for it, on any transport. `Servers` keeps
each server's samples in five windows (`servers_latency.zig`). A server waits `timeout_ns` until
it has 3 samples, and then five times the average of the shortest window that holds 3. The wait
is clamped to 250 ms and the cap, the cap winning, and doubles per pass. `timeout_ns` defaults to
2 seconds and `timeout_ns_max` to 5, and a `resolv.conf` or `RES_OPTIONS` `timeout:` longer than
the cap raises it. Design §5, §10, §12 and §19 changed first. The models leave the wait's length
out, so neither changed, and the replays agree; the engine replay's configuration caps its wait
at the model's two ticks (spec/README.md).

S13's edit no longer applied, since `on_sent` arms its deadline through `lookup_poll.arm` now,
and it was written again. DT9, DT10 and DT19 did not compile as first written, each leaving a
capture or a parameter unused, and were written again so that they compile. Then `zig build
mutations -- lookup` ran S13 and DT1 to DT29, each against the step it names, and caught each.
Each was also broken by hand, to name the tests that fail. Twenty-nine new mutations,
twenty-nine `CAUGHT`; one written again, one `CAUGHT`.

On review, a test came to pin the size of `Servers`, 1488 octets, which design §9 states and no
test held. DT30 grows a server's state by a word, and only that test fails. Then `zig build
mutations -- lookup` ran S13 and DT1 to DT30 again, and caught each. One new mutation, one
`CAUGHT`.

The tests the table names: in `lookup_latency_test.zig`, the third-sample, doubling,
ignored-response, resent-query, truncated-then-TCP, TLS, DoH or DoQ, and failed-send tests; in
`servers_latency.zig`, the three-samples, shortest-window, day-apart, long-sample and halving
tests; in `lookup_policy.zig`, the configured-wait, measured-wait and doubling tests; the memory-hit
test of `table_memory.zig`; the cap test of `lookup_config_test.zig`; the large-timeout test of
`resolv_conf.zig`; the defaults test of `config.zig`; and the size test of `servers.zig`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DT1 | an accepted response takes no sample | §5, a sample per accepted response | the memory-hit test, and the third-sample, doubling, ignored-response, resent-query, truncated-then-TCP, TLS, and DoH or DoQ tests, `test-resolver` | CAUGHT |
| DT2 | a sample is measured from instant zero, not from its query's send | §5, a sample from its transaction's send | the third-sample, doubling, resent-query, truncated-then-TCP, TLS, and DoH or DoQ tests, `test-resolver` | CAUGHT |
| DT3 | a send does not keep its instant, so every sample is measured from instant zero | §5, a sample from its transaction's send | the same six tests, `test-resolver` | CAUGHT |
| DT4 | a response takes a sample before §7's checks, so an unmatched one does too | §5, §16 decision 10 | the memory-hit test, and the third-sample, ignored-response, resent-query, truncated-then-TCP and TLS tests, `test-resolver` | CAUGHT |
| DT5 | a response that passes §7's checks takes a sample before its rcode and answer section are read | §5, §16 decision 10 | the memory-hit test, and the third-sample, ignored-response, resent-query, truncated-then-TCP, TLS, and DoH or DoQ tests, `test-resolver` | CAUGHT |
| DT6 | an answer the memory recalled takes a sample | §5, no query and no sample | the memory-hit test, `test-resolver` | CAUGHT |
| DT7 | a DoH or DoQ request that failed takes a sample | §5, no answer and no sample | the DoH or DoQ test, `test-resolver` | CAUGHT |
| DT8 | a send that failed takes a sample | §5, no answer and no sample | the failed-send test, `test-resolver` | CAUGHT |
| DT9 | a window whose span has passed is not started again at its next sample | §5, the window spans | the shortest-window and day-apart tests, `test-resolver` | CAUGHT |
| DT10 | a window whose span has passed is read all the same | §5, the window spans | the shortest-window test, `test-resolver` | CAUGHT |
| DT11 | a window's span ends one nanosecond late | §5, the window spans | the shortest-window test, at 130 seconds, `test-resolver` | CAUGHT |
| DT12 | the window since the table was built is read, whatever a shorter one holds | §5, the shortest window with 3 samples | the shortest-window test, `test-resolver` | CAUGHT |
| DT13 | the window since the table was built passes like the others | §5, a window with no span | the five tests of `servers_latency.zig`, and the third-sample, doubling and truncated-then-TCP tests, `test-resolver` | CAUGHT |
| DT14 | a window with one sample is read | `latency_samples_min` | the assertion in `average`, by a panic under the shortest-window and day-apart tests, `test-resolver` | CAUGHT |
| DT15 | a server with one sample has its wait read from samples | `latency_samples_min` | the assertion in `average`, by a panic under 33 tests, the three-samples test among them, `test-resolver` | CAUGHT |
| DT16 | a sum that would pass 2^64 is not halved first | §5, the bound on a sum | the halving test, by an integer overflow, `test-resolver` | CAUGHT |
| DT17 | a sum that would pass 2^64 halves its count down, which can raise the average | §5, the bound on a sum | the halving test, `test-resolver` | CAUGHT |
| DT18 | a sample longer than the longest wait is kept whole | `timeout_ns_max` | the assertion in `add`, by a panic under the long-sample test, `test-resolver` | CAUGHT |
| DT19 | the wait ignores the samples and is always the configured one | RFC 1035 §4.2.1, §5 | the measured-wait test, and the third-sample and doubling tests, `test-resolver` | CAUGHT |
| DT20 | a measured wait is four times the average, not five | `latency_wait_multiplier` | the measured-wait test, and the third-sample and doubling tests, `test-resolver` | CAUGHT |
| DT21 | the wait has no floor | `timeout_ns_min` | the configured-wait and measured-wait tests, `test-resolver` | CAUGHT |
| DT22 | the floor wins over a cap below it | §5, the caller's cap | the assertion in `wait_ns`, by a panic under the measured-wait test, `test-resolver` | CAUGHT |
| DT23 | the doubled wait is not capped | `Config.timeout_ns_max` | the doubling test of `lookup_policy.zig`, the cap test, and the doubling test of `lookup_latency_test.zig`, `test-resolver` | CAUGHT |
| DT24 | the wait does not double per pass | §5, doubled per pass | the two doubling tests, the cap test, and the deadline-after-the-cache test of `table_ready.zig`, `test-resolver` | CAUGHT |
| DT25 | the deadline is armed from the first server's wait, not the current one's | §5, each server's own wait | the third-sample test, `test-resolver` | CAUGHT |
| DT26 | a `timeout:` longer than the cap leaves the cap | §10 | the assertion in `apply_option`, by a panic under the large-timeout test and the text fuzz gate, `test-config` | CAUGHT |
| DT27 | a `timeout:` sets the cap to itself, lowering a larger one | §10 | the large-timeout test, `test-config` | CAUGHT |
| DT28 | the default cap is 30 seconds, as before 2026-10-09 | `timeout_ns_max_default` | the defaults test, `test-core` | CAUGHT |
| DT29 | the default wait is 5 seconds, as before 2026-10-09 | `timeout_ns_default` | the defaults test, `test-core` | CAUGHT |
| DT30 | a server's state grows by a word, and the size design §9 gives the table goes stale | §9, the size of `Servers` | the size test of `servers.zig`, `test-resolver` | CAUGHT |
| S13 | the deadline is not armed on a send, written again for `lookup_poll.arm` | §5 retry policy | 39 tests, the wait test of `lookup_poll.zig` among them, `test-resolver` | CAUGHT |

## A server that changes the case

2026-10-09. The owner ruled that DNS-0x20 stays on by default (design §16 decision 5) and falls
back for each server on its own (design §7, A server that changes the case). A response that passes
checks 1 to 4 and check 6, whose question is the one a mixed query asked with every letter small,
marks its server. The response is ignored all the same, and the wait stands (decision 10). From
then on every query to that server carries the name in lowercase, until the `Servers` table is
built again. A mixed name always carries a capital: a draw that leaves every letter small is drawn
again, up to `case_draws_max` draws, and then the first letter is made a capital. So no echo of a
mixed query cocuyo sent is in lowercase, and none marks a server. A lookup records whether the
query it built mixed the case, and check 5 compares a response with that query's name. Design §4,
§5, §7, §9, §12, §16 decision 5, §19 and §24 changed first. Neither model changed. The Lean model
leaves entropy out, and a reply that differs in case alone is an unmatched reply, with the wait
standing; the engine's TLA+ model has no letter case. `zig build spec-lean` and the replays of
`zig build test` agree.

As first built, an echo in any other case marked its server. The review of the same day found
that two lookups of one name to one server whose transactions drew one id, or a late answer
reaching a retry that drew its query's id, marked a server that echoes the case as sent, with no
attacker. The mark was narrowed to an echo in lowercase, every mixed name made to carry a capital,
and a marked server asked in lowercase. A chain name is folded under 0x20 again whatever the query
carried. CM3, CM7, CM9, CM11, CM12 and CM13 were written again for that code, and CM18 to CM23
are new. S4's and S5's edits no longer applied, since check 5's line became a block and
`cased_name` reads what the query recorded, so both were written again. CM4 did not compile as
first written, leaving the OPT record unused, and was written again so that it compiles. Then
`zig build mutations -- lookup` ran CM1 to CM23, S4, S5, DH5 and QU5, each against the step it
names, and caught each. DH5 and QU5 edit the flag the query's choice reads, so they ran again
unchanged. Each was also broken by hand, against `test-resolver` and, for the codec's, against
`test-wire` too, to name the tests that fail. Twenty-three mutations, twenty-three `CAUGHT`; four
run again, four `CAUGHT`.

The tests the table names: in `lookup_case_test.zig`, the lowercasing test (a server that
lowercases is marked, the wait stands, and the retry and a new lookup go in lowercase), the
other-server, more-than-case, other-echo (another lookup's mixed echo, and one in capitals),
late-echo, check-6, owed-cookie, unmixed-query, in-flight, capitals, chain-capitals, folded-case
and nobody-asked tests; the lowercase test of `src/wire/question.zig`; the redraw, one-letter and
letterless tests of `src/wire/name.zig`; the marked-alone test of `servers.zig`; the
name-on-the-wire test of `lookup_init_test.zig`; and the cross-talk test of `table.zig`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CM1 | the mark is never made | §7, the mark | the lowercasing, other-server, more-than-case, other-echo, check-6 and in-flight tests, `test-resolver` | CAUGHT |
| CM2 | a response in another case marks its server though the query did not mix the case | §7, only a query that mixed | the unmixed-query test, `test-resolver` | CAUGHT |
| CM3 | the mark does not compare the question with the one asked in lowercase, so another question marks | RFC 1035 §2.3.3, RFC 4343 §3, §7 the mark | the more-than-case, other-echo and late-echo tests, `test-resolver` | CAUGHT |
| CM4 | the mark skips check 6, so a wrong or a missing cookie marks | RFC 7873 §5.3, §7 check 6 | the check-6 and owed-cookie tests, `test-resolver` | CAUGHT |
| CM5 | a malformed OPT record is read as none, and marks | RFC 7873 §5.2.2, §7 check 6 | the check-6 test, `test-resolver` | CAUGHT |
| CM6 | a query mixes the case whatever its server's mark | §7, a marked server is asked in lowercase | the lowercasing, capitals and chain-capitals tests, `test-resolver` | CAUGHT |
| CM7 | check 5 compares with the server's mark at the response, not with what the query sent | §7, the query's record | the in-flight test, `test-resolver` | CAUGHT |
| CM8 | the mark lands on the first server, not the one that answered | §7, that server alone | the other-server test, `test-resolver` | CAUGHT |
| CM9 | the lowercase compare compares exactly | §7, the mark | the lowercase test, `test-wire`; six tests of `test-resolver`, the lowercasing test among them | CAUGHT |
| CM10 | the lowercase compare ignores the type | §7, the type compares exactly | the lowercase test, `test-wire`; the more-than-case test, `test-resolver` | CAUGHT |
| CM11 | the lowercase compare ignores the class | §7, the class compares exactly | the lowercase test, `test-wire` | CAUGHT |
| CM12 | check 5 takes the question echoed in lowercase, so the response that marks is the answer too | RFC 5452 §9.1, §7 check 5, decision 10 | eight tests, the folded-case and lowercasing tests among them, `test-resolver` | CAUGHT |
| CM13 | a chain name is folded only when the query mixed the case, so a server asked in lowercase keeps its capitals | §7, a chain name's case | the chain-capitals test, `test-resolver` | CAUGHT |
| CM14 | a query does not record whether it mixed the case | §7, the query's record | nine tests, the late-echo and name-on-the-wire tests among them, `test-resolver` | CAUGHT |
| CM15 | a table starts with every server marked | §7, a server is marked by its own reply | twelve tests, the marked-alone test among them, `test-resolver` | CAUGHT |
| CM16 | the mark lands on every server | §7, that server alone | the marked-alone and other-server tests, `test-resolver` | CAUGHT |
| CM17 | an answer the lookup takes clears its server's mark | §7, for the life of the table | the lowercasing and chain-capitals tests, `test-resolver` | CAUGHT |
| CM18 | the lowercase compare takes the name echoed in any case, so another mixed query's echo marks | §7, only an echo in lowercase marks | the other-echo and late-echo tests, `test-resolver`; the lowercase test, `test-wire` | CAUGHT |
| CM19 | a letter drawn small counts as a capital, so a draw that leaves every letter small stands | §7 Entropy, a capital in every mixed name | the redraw and one-letter tests, `test-wire`; the other-echo test, `test-resolver` | CAUGHT |
| CM20 | a draw is repeated from the word the first started from, so it leaves every letter small again | §7 Entropy, each draw from the next word | the redraw test, `test-wire` | CAUGHT |
| CM21 | the first letter is not made a capital once every draw left the name small | `case_draws_max` | the one-letter test, `test-wire` | CAUGHT |
| CM22 | a name without a letter is drawn again as one left small | §7 Entropy | the letterless test, `test-wire`, by a panic at the `unreachable` past the last draw | CAUGHT |
| CM23 | a server marked as one that lowercases the name is asked for the name as held | §7, a marked server is asked in lowercase | the capitals test, `test-resolver` | CAUGHT |
| S4 | the question section is not compared, written again for check 5's block | RFC 5452 §9.1 | eleven tests, the cross-talk test of `table.zig` and the nobody-asked test among them, `test-resolver` | CAUGHT |
| S5 | the qname goes out uncased, written again for the query's record | §7 DNS-0x20 | nine tests, the late-echo and name-on-the-wire tests among them, `test-resolver` | CAUGHT |

## A try that ran out as a latency sample

2026-10-09. The owner ruled, in answer to design §17 question 26, that a try that ran out counts
as a latency sample as long as the wait it used (design §5, §16 decision 36). When a lookup's
deadline passes in `awaiting_udp`, which holds DoH and DoQ requests too, or in `awaiting_tcp`, the
server it waited on takes one sample, from the send to the deadline, before the lookup moves on
(`ran_out` in `src/resolver/lookup_poll.zig`). A connect that ran out, a failed send, a failed
connection or handshake, a failed request and a lookup cancelled take none. Design §5, §16
decision 36 and §17 question 26 changed first. Neither model changed: the Lean model leaves time
and the wait's length out, and the TLA+ engine model holds no latency. `zig build spec-lean` and
the replays of `zig build test` agree.

Two tests of `lookup_latency_test.zig` described the rule before it and were written again. The
doubling test let a try run out at 1.5 seconds and expected the next pass to wait 3. That try is a
sample now, which makes the average 600 ms, so the next pass waits 6 seconds, under a cap raised
to 30 seconds so that the doubling still shows. The resent-query test required the silent first
server to hold no sample, and now requires it to hold one, of 2 seconds. Both tests are named in
the rows of DT1 to DT5, DT19, DT20, DT23 and DT24, so those were broken by hand again, and the
tests their rows name still catch each.

Each of DT31 to DT39 was broken by hand against `test-resolver`, to name the tests that fail.
Then `zig build mutations -- lookup` ran DT31 to DT39, and S3, S14 and S16, whose edits are in
`expired` beside the new function, and caught each. The name S3 matches two rows, the state
machine's and the Lean model's, and the tool ran both. It ran DT1 to DT30 again too, for the two
tests written again, and caught each. Nine new mutations, nine `CAUGHT`; thirty-four run again,
thirty-four `CAUGHT`.

The tests the table names, all in `lookup_latency_test.zig` but two: the ran-out test (one sample
as long as its wait, on its own server, a later pass's doubled, and a poll that comes 7 ms late),
the TLS test (a try over TLS that ran out, and a connect that ran out), the DoH or DoQ test, the
failed-connection test (a connection that failed and a lookup cancelled), the slowed test (a
record of 3 answers in 50 ms, then 600 ms), the long-record test (a record of 100), the
never-answers test, and the doubling and resent-query tests written again; and the hard-failure
and timed-out-family tests of `address_lookup_test.zig`, which move the clock a minute on.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DT31 | a try that ran out takes no sample | §5, a try that ran out is a sample | thirteen tests: the ran-out, TLS, DoH or DoQ, slowed, long-record, never-answers, doubling and resent-query tests, and the five the review added, `test-resolver` | CAUGHT |
| DT32 | a try that ran out is measured to the poll that found it, not to its deadline | §5, from the send to the deadline | the ran-out test; the assertion in `ran_out`, by a panic under the hard-failure and timed-out-family tests, `test-resolver` | CAUGHT |
| DT33 | a later pass's try that ran out counts its wait before the doubling | §5, a doubled wait counts as that | the ran-out, long-record, never-answers and doubling tests, `test-resolver` | CAUGHT |
| DT34 | a connect that ran out takes a sample too, measured from a send that was not its own | §5, no query went out | the TLS test, `test-resolver` | CAUGHT |
| DT35 | a try over TCP or TLS that ran out takes no sample | §5, `awaiting_tcp` as `awaiting_udp` | the TLS test, `test-resolver` | CAUGHT |
| DT36 | a DoH or DoQ request that ran out takes no sample | §5, `awaiting_udp` holds requests too | the DoH or DoQ test, `test-resolver` | CAUGHT |
| DT37 | the sample lands on the first configured server, not the one that ran out | §5, the server the lookup waited on | the ran-out and TLS tests, `test-resolver` | CAUGHT |
| DT38 | a connection or a handshake that failed takes a sample | §5, no wait for an answer was measured | the failed-connection test, `test-resolver` | CAUGHT |
| DT39 | a lookup cancelled while it waits takes a sample of what it waited | §5, a lookup cancelled is no sample | the failed-connection test, `test-resolver` | CAUGHT |

The review of the same day found two faults in design §5. It said an off-path attacker who
cannot pass §7's checks cannot move a server's wait, which held only while an accepted response
was the only sample. And it gave some of the rule's costs without a test, and left others out.
§5 now says what an attacker who makes answers go missing can do to a wait. It adds the costs to
failover's probes, to DoH and DoQ beside DoT, and to the 0x20 fallback, and gives each number a
test. §5 also has the `awaiting_tcp` deadline row it lacked, and §17 asks two questions of the
costs. No check changed, so no mutation was added.

Five tests back the numbers: the lost-datagram and minute-restart tests of
`lookup_latency_test.zig`, the lowercase and other-case tests of `lookup_case_test.zig`, and the
probe test of `lookup_failover_test.zig`. Each fails under a row already in these tables, run
against `test-resolver` by hand to name the tests, then by `zig build mutations -- lookup`,
which caught all three. DT31 fails all five, DT9 the minute-restart test, and DT21 the
lost-datagram, minute-restart and probe tests.

## Sums at the most their operands reach

2026-10-10. A lookup for a name of 242 octets or more panicked when its own server's answer
arrived. `section_matches` in `src/wire/question.zig` held the header's twelve octets in a
constant with no type and added a name's length to it. A name's length is held in an octet
(`core.Name.len`), so the sums were made in that octet. The offset of the class overflowed from a
name of 242 octets, since 12, 242 and 2 are 256, and the offset of the type from 244. Both are
read once the echoed name matches, so the answer to such a name was a panic, "integer overflow",
in a safe build. `matches_lowercase` shares the two reads, so a lowercase echo reached them too.
RFC 1035 §2.3.4 allows names of 255 octets. The line dates from 23fd425, of 2026-09-21, and is in
every release, v0.1.0 to v0.5.0.

Nothing caught it. No test asked a name past 241 octets and took its answer. The codec's fuzz
generator wrote one question name that parsed as a question of class IN, `example.com`, 13
octets.

Two audits of the same day searched the tree for the same fault: a constant with no type added
to a narrow value an input sets, and a sum no limit bounds. This change fixes what they found:

- `deliver` in `io/io_tcp.zig` summed a stream's length prefix and its own two octets in the
  `u16` the prefix reads as (RFC 1035 §4.2.2). A prefix of 65534 or 65535 overflowed it: a panic
  of the engine on two octets from a server a lookup has a stream to, in the clear or inside a
  DoT record, before any check of design §7 runs. Since 886a4e8, of 2026-09-22, in v0.1.0 to
  v0.5.0.
- A connection's frame held `tcp_message_bytes` octets, the prefix among them. So the longest
  message it assembled was two octets shorter than that option says, and a message of 65534 or
  65535 octets failed its connection. The engine's DoQ answer buffer had the same length for the
  same stream. Each now holds the prefix beside the message. This was a wrong result and no
  panic, since 886a4e8 for TCP and DoT, and since v0.2.0 for DoQ. Design §19 step 13 and §24
  request rule 5 said each buffer was `tcp_message_bytes` long, and now say what it holds.
- `promote_retry` in `src/resolver/lookup_order.zig` summed the instant of a server's failure
  and `failover_retry_delay_ns` without saturating. The delay has no limit but its type's, and
  the largest `u64`, the way to say never, panicked at the first poll of a lookup once a server
  had failed. The value is the caller's own, never a response's. Since 8829548, of 2026-09-22.
- The plain QUIC session of `io/io_quic_plain.zig` summed an ALPN length and its own octet in a
  `u8`, and a handshake message's length and its frame in a `u24`. An ALPN length of 255, and a
  message length of 2^24 - 4 or more, panicked. The session encrypts nothing and is for tests,
  but `cocuyo_quic` exports it and its `Options.Session` defaults to it. Since 8b9fa5b, of
  2026-09-25, in v0.2.0 to v0.5.0.
- The twin had the fault three times: `record_len` in `src/sim/sim_tls.zig`, `read_item` in
  `src/sim/sim_quic.zig` and `answer_sealed` in `src/sim/sim_loop_perform.zig`. Only a test's own
  octets reach them. The audits could not reach the third. A scenario test now does, with a data
  record whose plaintext is a prefix of 65534 and no message.
- The fuzz generator's pointer maze masked the high bits of each target with the two bits that
  say pointer, so every pointer aimed at offsets 0 to 255 (RFC 1035 §4.1.4).

Each sum now has its type written where the narrow value is read, and the failover sum
saturates. `core.constants.header_bytes` and `tcp_prefix_bytes` keep no type: both are used
across the tree, and a type on either is the owner's to rule. The owner ruled on 2026-10-13, and
since then both are a `usize` (A type on every integer constant, below).
`wire.header.message_len` still returns a `u16`, so a driver of a caller's own that adds the
prefix's two octets to it has the engine's fault. Its comment and design §5 now say to widen it
first.

A review of the same day found one more panic on a peer's octets in the plain session, and it is
no sum. A client owed a Finished for each Finished it heard, and a server a whole flight for each
ClientHello, into the 512 octets a level holds, and an assertion alone bounded them. A client's
provider given 129 Finished panicked. So did a server's given a second hello, when its flight
was at its longest, 281 octets. Both were shown at the provider, as the tests of the session's
two sums go, and not through colibri's connection. Each side now refuses the second message with
`unexpected_message`, the alert for a message out of its order (RFC 9846 §4). So a side owes
each of its messages once, and the assertion holds whatever a peer sends. The reach is that of
the session's two sums, and the lines date from 8b9fa5b too.

The codec's fuzz generator has an eighth strategy, `long_question`: a plausible header and a
question of class IN, of a type cocuyo asks, whose name is 192 to 255 octets long. A test of
`fuzz.zig` requires the gate's 4,096 seeds to reach each of the 64 lengths. Another requires
most pointer mazes to aim past offset 255. An eighth strategy gives every seed another message,
so the whole lookup set ran again, as the paragraph on the runs below says. Six rows are in no
set and name the codec's fuzz gate as what catches them under `test-wire`: FZ1 to FZ5 and DL1.
Each was planted again by hand in the changed tree, and each still fails the gate, at seeds
0x51c, 0x5a, 0x1e, 0x309, 0x15b and 0xf6.

The gate's check ran `matches` alone over a question that parsed, and the long-name test of
`question.zig` held `matches_lowercase` at five lengths. The check now echoes the question with
the letters of its name small, and requires `matches_lowercase` to take the echo, at every
length the gate writes. QO23 refuses the echo of a name of 250 octets, a length the long-name
test does not ask. The gate fails under it at seed 0x120, and with the new check taken out again
no test of `test-wire` fails.

Two sums stay as they are. `deadline_ns` in `src/resolver/lookup_policy.zig` adds a wait of 30
seconds at most to `now_ns`, and `insert` in `src/cache/cache.zig` adds a TTL, 136 years at most,
to it. Neither saturates. Each overflows only with a clock that close to the end of a `u64` of
nanoseconds, 584 years, which no response, name or file can set.

These tests reach a limit no test reached, and no check changed for them:

- In `question.zig`, the most-labels test: a question of 127 labels, the most 255 octets hold,
  written, read back and matched.
- In `record.zig`, the real-records test: a walk over 65 records reads `records_max` of them.
- In `servers.zig`, the saturation test: 257 failures count 255.
- In `lookup_cookie_test.zig`, the longest-cookie test: a server cookie of 32 octets is learned
  and sent back.
- In `lookup_config_test.zig`, the payload test: a query advertises 512 and 65535 octets.
- In `lookup_walk_test.zig`, the largest-walk test: 8 servers by 5 passes by 7 candidates under
  a 30-second wait, 280 tries.

Three of those tests are the first to catch a break of the line they reach: the saturation
test, the longest-cookie test and the payload test. The review broke each line at 8074c20 and
ran `test-wire`, `test-resolver`, `test-cache`, `test-cocuyo` and `test-io` there, and no test
failed. The three breaks are rows now: QO19, QO21 and QO22. In the changed tree each fails the
one test its row names, and `test-cache`, `test-cocuyo` and `test-io` still pass under each. The
codec's own largest-cookie test wrote 32 octets of server cookie and never read them back. It
reads them back now, so `test-wire`, the step of the module that owns the check, catches the
same break as QO20.

Each of QO1 to QO23 was broken by hand against the step its row names, to name the tests that
fail. QO1 and QO2 each fail the fuzz gate, by a panic. With the edits of QO3, which is both, and
of QO4 applied together, the gate holds: the long names are what make the gate catch the fault.
The lookup's harness in `src/resolver/fixtures.zig` had the same sum, a name's length and the
question's four fixed octets in a `u8`; without its type the two 255-octet tests panic in the
harness. A test of `lookup_case_test.zig` summed a name's length and one in the same octet, with
`example.com` alone: it has its type now, and no test, since no name it is given reaches it.

QO1 to QO7 and QO19 to QO23 are in `tools/mutations/lookup.zon`, and QO8 to QO18, the engine's,
the plain session's and the twin's, in `tools/mutations/engine.zon`. Once the last of them was
written, `zig build mutations -- lookup` ran the whole set, after running each check once with
nothing mutated: 202 mutations, each against the step it names, and caught each.
`zig build mutations -- engine` ran the twenty rows of its set that `test-io`,
`test-cocuyo_quic` and `test-sim` catch: QO8 to QO18, and ET12, ET13, SQ3, SQ4, TR4, CE4, CE18,
CE20 and CE21. It caught each. The engine's other rows did not run again: the walks catch them,
or `test-cocuyo_doh` does, whose files this change does not touch. The review ran the 28 rows of
`test-cocuyo_doh` in a copy of the tree, before QO17 to QO23 were written, and caught each.
Twenty-three new mutations, twenty-three `CAUGHT`; the 190 others of the lookup set run again,
190 `CAUGHT`; nine of the engine set run again, nine `CAUGHT`.

The tests the table names: in `src/wire/question.zig`, the long-name test (names of 241, 242,
243, 244 and 255 octets under `matches` and `matches_lowercase`, each against another name of
its length) and the most-labels test; in `src/wire/fuzz.zig`, the fuzz gate, the every-length
test and the maze test; in `lookup_case_test.zig`, the two 255-octet tests (a name of 255 octets
asked mixed, in lowercase and as held, and over a stream after a truncated answer and under
`use_tcp`); in `lookup_order.zig`, the largest-delay test; in `io_sim_test.zig`, the 255-octet
test, over UDP and over a stream; in `io_request_test.zig`, the DoQ 255-octet test; in
`io_tcp_test.zig`, the prefix test (prefixes of 65533, 65534 and 65535), the whole-frame test (a
frame filled by hand with a message of 65535 octets) and the tiny-frame test (a message of 64
octets taken by a connection of 64, and one of 65 not); in `io_tls_test.zig`, the record-prefix
test; in `io_request_failure_test.zig`, the DoQ buffer test; in `io_quic_plain.zig`, the ALPN
test, the message-length test, the second-Finished test and the second-hello test (a server
whose flight is at its longest, 281 of a level's 512 octets); in `edns.zig`, the largest-cookie
test; and in the twin, the record-length test of `sim_tls.zig`, the item-length test of
`sim_quic.zig` and the record-prefix scenario of `sim_scenarios_test.zig`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| QO1 | the offset of a question's type is summed in the octet a name's length is held in | RFC 1035 §2.3.4, §7 check 5 | the long-name and most-labels tests and the fuzz gate, each by a panic, `test-wire` | CAUGHT |
| QO2 | the offset of a question's class is summed in the octet a name's length is held in | RFC 1035 §2.3.4, §7 check 5 | the long-name and most-labels tests and the fuzz gate, each by a panic, `test-wire` | CAUGHT |
| QO3 | both offsets of a question are summed in that octet, under a lookup | RFC 1035 §2.3.4, §7 check 5 | the two 255-octet tests of `lookup_case_test.zig`, by a panic, `test-resolver` | CAUGHT |
| QO4 | the fuzz generator writes an ordinary question where a long one goes | §13, a question of a long name in the gate | the every-length test, `test-wire` | CAUGHT |
| QO5 | the fuzz generator's long names stop at 241 octets | §13, names of 242 to 255 octets in the gate | the every-length test, `test-wire` | CAUGHT |
| QO6 | a pointer of a maze keeps the low octet of its target alone, so none aims past offset 255 | RFC 1035 §4.1.4, §13 pointers at every offset | the maze test, `test-wire` | CAUGHT |
| QO7 | the failover delay and the instant of the failure are summed without saturating | §19 step 12, a delay of any `u64` | the largest-delay test, by a panic, `test-resolver` | CAUGHT |
| QO8 | both offsets of a question are summed in the octet a name's length is held in, under the engine | RFC 1035 §2.3.4, §7 check 5 | the 255-octet test of `io_sim_test.zig` and the DoQ 255-octet test, by a panic, `test-io` | CAUGHT |
| QO9 | a stream's length prefix and its own two octets are summed in the sixteen bits the prefix reads as | RFC 1035 §4.2.2 | the prefix, whole-frame and record-prefix tests, by a panic, `test-io`; since 2026-10-13 also the test of a record after a partial message at its longest (What a survey of the named limits found) | CAUGHT |
| QO10 | a connection's frame holds `tcp_message_bytes`, with no room for the prefix beside the longest message | §19 step 13, the buffer a stream assembles into | the whole-frame and tiny-frame tests, `test-io`; since 2026-10-13 the whole-frame test and the test of a frame over TLS of empty messages (What a survey of the named limits found) | CAUGHT |
| QO11 | the DoQ answer buffer holds `tcp_message_bytes`, with no room for the prefix beside the longest message | RFC 9250 §4.2, §24 request rule 5 | the DoQ buffer test, `test-io` | CAUGHT |
| QO12 | the plain session sums an ALPN length and its own octet in the octet the length reads as | the plain session's hello, an ALPN token after its length | the ALPN test, by a panic, `test-cocuyo_quic` | CAUGHT |
| QO13 | the plain session sums a handshake message's length and its frame in the 24 bits the length reads as | RFC 9846 §4, a message's framing | the message-length test, by a panic, `test-cocuyo_quic` | CAUGHT |
| QO14 | the twin sums a record's length and its header in the sixteen bits the length reads as | RFC 9846 §5.1, a record's header | the record-length test, by a panic, `test-sim` | CAUGHT |
| QO15 | the twin sums a QUIC item's length and its header in the sixteen bits the length reads as | the twin's items | the item-length test, by a panic, `test-sim` | CAUGHT |
| QO16 | the twin's TLS server sums a query's length prefix and its own two octets in sixteen bits | RFC 1035 §4.2.2 | the record-prefix scenario, by a panic, `test-sim` | CAUGHT |
| QO17 | a client of the plain session takes a second Finished, and owes another of its own | RFC 9846 §4, a message out of its order | the second-Finished test, `test-cocuyo_quic` | CAUGHT |
| QO18 | a server of the plain session takes a second ClientHello, and owes another flight | RFC 9846 §4, a message out of its order | the second-hello test, by a panic, `test-cocuyo_quic` | CAUGHT |
| QO19 | a server's failures are counted without saturating | §19 step 12, a count that stops at the most its octet holds | the saturation test, by a panic, `test-resolver` | CAUGHT |
| QO20 | a COOKIE option as long as the longest server cookie makes it is refused | RFC 7873 §4, a server cookie of 8 to 32 octets | the largest-cookie test of `edns.zig`, `test-wire` | CAUGHT |
| QO21 | a COOKIE option as long as the longest server cookie makes it is refused, under a lookup | RFC 7873 §4, a server cookie of 8 to 32 octets | the longest-cookie test of `lookup_cookie_test.zig`, `test-resolver` | CAUGHT |
| QO22 | a query advertises the default payload size whatever the configuration says | RFC 6891 §6.2.3, the payload size a configuration names | the payload test, `test-resolver` | CAUGHT |
| QO23 | a lowercase echo of a question whose name is 250 octets long is not taken for one | §7, a server that changes the case, at every length the gate writes | the fuzz gate, `test-wire` | CAUGHT |

## Names compared a word at a time

2026-10-10. `wire_equal` in `src/core/name.zig`, which `Name.equal` and the hosts table compare
names with, now compares eight octets at a time. It reads each word whole and folds it with
`Name.fold_word`, the fold the cache's hash already uses, which folds each octet as the octet
fold does. The last word ends at the name's last octet, so it overlaps the word before it when the
length is not a multiple of eight. A name shorter than eight octets goes to `octets_equal`, the
compare of one octet at a time that `wire_equal` was before. It stays as the reference the new
compare is held to. No result changes: two names are equal when they have the same length and the
same octets, with `A` to `Z` folded to `a` to `z` (RFC 1035 §2.3.3, RFC 4343 §3). Every caller
gets the same answer: the record owner compare of `collect`, the cache's key compare, the
assertion in `Lookup.cased_name`, and the hosts table. Neither model changed, since neither
compares names. The word's compare carries no inline attribute, as design §11 asks: LLVM inlines
it into `wire_equal` on its own.

Two proofs came before the mutations. The first is a first-difference harness, kept out of the
tree. It runs the new compare, the reference, the base's `wire_equal` and an oracle of its own,
which lowers each octet with `std.ascii.toLower`, and prints the first input on which any of them
differs. It found none over 4,697,734,090 inputs:

- every pair of octet values at every position of every length from 0 to 255, the other octets
  from two fillers, one with every letter in the other case and one the same: 4,278,190,080
  inputs, each through the new compare and the reference;
- every string over eight pairs of octets at every length from 0 to 9, and over four pairs from 0
  to 12, in both orders: 351,522,620;
- seeded random pairs of names in wire form at every length to 255, with letters in the other
  case, up to four octets replaced, and one pair in sixteen of two lengths: 63,750,000;
- every pair of lengths from 0 to 255: 65,536;
- pairs of `Name`s through `Name.equal`, the new and the base's, with other octets past their
  length: 4,000,000;
- the benchmark's names and others, the root and a name of 255 octets among them, each against
  itself in the other case and with each octet set to every value: 205,854.

Built over a copy of `name.zig` under NW1, NW3, NW6 and NW7 in turn, it printed a first
difference each time. The second proof is three tests of `name.zig`. The one-octet-change test
lays a run of twenty-one octets from either side of the fold's edges against the same run in the
other case, at every length from 0 to 255. It changes each octet in three ways, the case bit, the
high bit and the low bit, and requires both compares to give what `std.ascii.toLower` says of the
two octets. The length test requires a run and a longer run that starts with it to differ, in
either order, for a run shorter than a word and one longer. The RFC 4343 case test requires the
reference to refuse two lengths.

A review of the same day asked for four things. Three are in:

- `wire_equal` checks the lengths itself, and no row broke that check. NW11 does, and the length
  test is the one that sees it.
- The compare of two words cites its rule where it compares: RFC 1035 §2.3.3, as RFC 4343 §3
  clarifies it.
- The assertion after the loop restated the loop's condition. A second one says the loop stopped
  before the name's end. NW4 and NW12 fail it.

The fourth was a loss, and no code answers it. On aarch64 LLVM no longer inlines the compare into
`Cache.find`. `find` calls `Name.equal`, keeps its walk in registers a call preserves, and saves
six pairs of them on entry where it saved two. A miss that stops at the first key entry runs 39
instructions in `find` where it ran 27, by the listing, though it compares no name. On x86-64
`find` saves the same six registers in both builds. In the review's binary the filter's row for
that miss, on a young index, lost past its noise in every job.

Most of that loss was where the code sat, and what is left is under the floor:

- The review's binary and this tree's run such a miss on the same instructions, addresses masked:
  the harness's sampling loop, the case, `get`, `hash_of` and `find`. The second assertion is
  two instructions in `Name.equal` and two in the program's `main`, neither of which that miss
  runs. They moved `find` by 8 octets and the four others by 16.
- The review's shape was built again on this base and timed in one job with the base and with
  this tree's binary. It lost on that row past its noise, and this tree's did not.
- With those five functions aligned to 64 octets in the base and in the change, the row stayed
  inside the floor in two jobs.
- In five paired jobs of five alternated runs, the base built in the main tree and the change in
  this one, each with a cache of its own, no row loses past its noise (docs/performance.md, the
  admission rule).

So a later change that moves those functions can move that row again, by more than the frame
costs. Three shapes were built to take the frame off that miss, and none is in:

- The compare inlined into `find` with `@call(.always_inline, ...)` at both levels. Design §11
  rules out an inline attribute without a new table, and `find` still saves four pairs.
- `find` confirming its first candidate before its loop. LLVM kept the six pairs at the entry.
- A `get` that reads the first key entry before it calls `find`, so that such a miss never enters
  `find`. By the listing that miss runs 19 instructions fewer than the base's. Its row was slower
  than the base's in three jobs, with those functions aligned or not, and the cause was not
  found.

None of the filter's numbers is recorded here: the judge decides a speed.

Each of NW1 to NW12 was broken by hand against core's tests, in a copy of `src/core`, to name the
tests that fail. NW4 and NW5 fail an assertion in the first test that compares two names, and
the panic ends the run there. With the two assertions taken out, each fails the one-octet-change
test, so the tests see the wrong result too. NW12 changes no result, since the word it adds is
compared again as the last word: with the assertions out no test fails, and the assertion alone
holds it. Then `zig build mutations -- lookup` ran the whole set, 214 rows, each against the step
it names, after running each check once with nothing mutated, and caught every one. No row of any
set edits a line this change replaced, so none was written again. Twelve mutations, twelve
`CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| NW1 | a word is compared unfolded | RFC 1035 §2.3.3, RFC 4343 §3, the word's fold | the RFC 4343 case, `fold_case` and one-octet-change tests | CAUGHT |
| NW2 | only the first name's word is folded | RFC 1035 §2.3.3, RFC 4343 §3, the word's fold | the RFC 4343 case, `fold_case` and one-octet-change tests | CAUGHT |
| NW3 | the last word is not compared | the last word | the RFC 4343 case and one-octet-change tests | CAUGHT |
| NW4 | the loop steps over every second word | the word loop | the assertion that the loop stopped before the name's end, by a panic in the RFC 4343 case test | CAUGHT |
| NW5 | the loop stops a word early | the word loop | the assertion that the last word starts where the loop stopped or before, by a panic in the RFC 4343 case test | CAUGHT |
| NW6 | the last word stops one octet short of the end | the last word | the one-octet-change test | CAUGHT |
| NW7 | a name shorter than a word is compared exactly | RFC 1035 §2.3.3, RFC 4343 §3, a short name | the one-octet-change test and the hosts table's alias test | CAUGHT |
| NW8 | a name of seven octets takes the word path | the bound of a short name | the one-octet-change test, by a panic at the subtraction that finds the last word | CAUGHT |
| NW9 | the reference compares the octets exactly | RFC 1035 §2.3.3, RFC 4343 §3, the reference | the one-octet-change test and the hosts table's alias test | CAUGHT |
| NW10 | the reference ignores the lengths | the reference's length check | the RFC 4343 case test, by a panic at the loop over two lengths | CAUGHT |
| NW11 | the word compare ignores the lengths | the word compare's length check | the length test; the hosts table's alias test, by a panic at a word read past a name's end | CAUGHT |
| NW12 | the loop compares the last word too | the word loop, one word and no more past the last word's start | the assertion that the loop stopped before the name's end, by a panic in the one-octet-change test | CAUGHT |

## Check 5 read in place

2026-10-11. The owner ruled on 2026-10-09 that check 5 reads the echoed question in place, against
the case the transaction's seed gives the name the lookup holds, so that a reply builds no cased
copy of the name (design §7, A server that changes the case; §16 decision 5). Two rulings of that
day carry it. New public declarations in `wire` are allowed, since `wire` is public through
`src/cocuyo.zig`. And the check in `Lookup.cased_name` that the cased name is the held name in
another case moves from every reply to the build of the query: while a lookup waits, the held
name, the case seed and `query_mixed` are what the build had, so a rebuild per reply re-ran a
deterministic function the build had checked. Design §7 and §16 decision 5 changed first. Neither
model changed: the Lean model leaves the case out, and a reply that differs in case alone is an
unmatched reply there; the engine's TLA+ model has no letter case. `zig build spec-lean` and the
replays of `zig build test` agree.

What the code does now:

- `wire.name.is_mix_of`, in `src/wire/name_case.zig`, split from `name.zig` by the file-length
  rule, reads an echo against the mixer's first draw octet by octet. The mixer and the compare
  share one bit stream, `Draw`. The mixer walks the labels, and that walk is the reference; the
  compare walks the bytes, which meets the letters in the same order because no length octet is a
  letter. When the first draw left every letter small, the compare builds the name with
  `mix_case` and compares that.
- `wire.question.matches_mixed` is check 5 over it. `src/resolver/lookup_response_case.zig`,
  split from `lookup_response.zig`, holds check 5's compare and the mark.
- The question compare reads the type and the class before the name, in each of its three forms:
  exact, lowercase and mixed. It sums their offsets in `usize`, as the fix above left them (Sums
  at the most their operands reach). Read first, those sums are made for every reply that
  reaches check 5 and is long enough, whether or not its name matches.
- `apply` takes no name: past check 5 the name is read for its length alone. An assertion in
  `apply` holds the question inside the message, and a test each of `response.zig` and
  `response_opt.zig` holds the sections to the name's length.
- The codec's fuzz target holds `matches_mixed` to `matches` over the name `mix_case` builds, on
  every message whose question parses, the questions of 192 to 255 octets among them.

The change removed the `old` text of S4 and S6 of the state machine, DH13, DH14, TT8, WN1, WN2,
DT4, CM3, CM5, CM11, CM12, CM19, CM22 and QO2, and moved CM1, CM2, CM4, CM8, CM20 and CM21 into
the files split off, so each was written again to apply. CM7's edit still applied to
`cased_name`, but no reply reads `cased_name` any more, so CM7 was moved to check 5's own branch.
CM10's edit still applied, but with the type read first for every compare it turned off the
mixed compare's type check as well, so it was narrowed to the lowercase compare. CP1 to CP17 are
new. Each of those forty rows was broken by hand against `test-wire` and against
`test-resolver`, to name the tests that fail. So were QO1, QO3 and QO23, whose text the change
left alone: each still fails the tests its row names.

The sums have rows here beside those of the fix above. QO1 to QO3 take the type off the sums,
and the tests of that fix catch each under `matches` and `matches_lowercase`. CP14 is QO3's edit
against `test-wire`. CP15 and CP16 make the sums in the octet for the mixed compare alone, which
no test of that fix calls: the long `matches_mixed` test and the fuzz gate catch CP15, and the
three 255-octet tests of a lookup catch CP16, each by a panic. CP17 is to the mixed compare what
QO23 is to the lowercase one: it refuses the question a mixed query sent when its name is 250
octets long, a length no test asks. The fuzz gate fails under it at seed 0x120, and with the
target's mixed check taken out again no test of `test-wire` or `test-resolver` fails.

Part of the suite cannot see some of these rows, and the table names what does. CP2 and CP3
break a shortcut whose work the reference redoes, one of the method's masks: `is_mix_of` answers
the same under each, so no test of a lookup can see them, and the test of the first draw's
reading, which says what the loop took, catches each. CP5 changes the bit
stream the mixer and the compare share, so the two still agree, and only the tests that pin the
stream catch it. CP12 and CP13 break no check, and each shows only that an assertion runs, by a
panic. CP12's, in `apply`, is new. With that assertion taken out, the message CP12 cuts still
stops 100 tests of `test-resolver` some other way, 92 by a failure and 8 by a panic, so CP12
shows the assertion runs, not that it is needed. CP13's is the assertion `case_change` made
before the change, that the lowercase echo is not the name sent, moved into `mark`. And the fuzz
gate does not reach the path CP1 and CP7 break, another of the method's masks: for none of its
seeds does the first draw leave every letter of the question's name small. It caught both before
the fix above gave every seed another message. The later-draw tests and the boundary-octets test
catch each, whatever the gate's seeds write.

The tests the table names: in `src/wire/name_case.zig`, the redraw, one-letter and letterless
tests, the takes-the-name test, the later-draw test (later draws and the fallback, for one, two
and three letters), the first-draw-reading test, and the boundary-octets test (every one- and
two-octet label of fourteen octets at the edges of the letters and of the case bit, each octet
echoed in seven forms, under sixteen seeds); in `src/wire/question.zig`, the `matches_mixed` and
lowercase tests, the long `matches_mixed` test (names of 241, 242, 243, 244 and 255 octets, and
one of 127 labels, each as the seed mixes it and in six ways it must be refused), and the
long-name and most-labels tests of the fix above; the fuzz gate of `src/wire/fuzz.zig`; in
`lookup_case_echo_test.zig`, split from `lookup_case_test.zig` by the file-length rule, the
later-draw test (each name sent from the second, third and fourth draw and from the fallback,
for one, two and three letters), the type-or-class test and the every-letter test (a name of 255
octets, the echo refused with each of its 250 letters in the other case, and with another type
or class); and in `lookup_case_test.zig`, the two 255-octet tests of the fix above, beside the
tests the rows of A server that changes the case name.

Then `zig build mutations -- lookup` ran the whole set, after running each check once with
nothing mutated: 219 mutations, each against the step it names, and caught each. Seventeen new
mutations, seventeen `CAUGHT`; twenty-three written again or moved, twenty-three `CAUGHT`; the
other 179 run again, 179 `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CP1 | a name whose first draw left every letter small is read against that draw, not the name the mixer drew again | §7 check 5, for a name the mixer drew again | the later-draw test, and two tests each of `address_lookup_test.zig` and `lookup_negative_test.zig`, `test-resolver`; the later-draw, first-draw-reading and boundary-octets tests, `test-wire` | CAUGHT |
| CP2 | a letter that differs in more than its case is read as the same letter in another case | RFC 1035 §2.3.3, RFC 4343 §3, §7 check 5 | the first-draw-reading test, `test-wire` | CAUGHT |
| CP3 | a length octet, a digit or the root that differs by the case bit is read as a letter in another case | §7 check 5, the name's own octets | the first-draw-reading test, `test-wire` | CAUGHT |
| CP4 | an echo in another case than the draw gave is read as the name sent | RFC 5452 §9.1, §7 check 5 | nine tests, the folded-case, lowercasing and every-letter tests among them, `test-resolver`; the takes-the-name, first-draw-reading and boundary-octets tests, both `matches_mixed` tests, the fuzz gate and the fuzz target's two verdict tests, `test-wire` | CAUGHT |
| CP5 | the first letter takes its bit from the seed itself, not from the word after it | §7 Entropy, each draw from the next word | the redraw, later-draw and first-draw-reading tests, `test-wire` | CAUGHT |
| CP6 | a draw that cased letters counts as one that found none, so a draw that leaves every letter small stands | §7 Entropy, a capital in every mixed name | the redraw, one-letter, later-draw and first-draw-reading tests, `test-wire`; the later-draw test, `test-resolver` | CAUGHT |
| CP7 | a name the mixer drew again is compared in lowercase, its first draw's case | §7 check 5, for a name the mixer drew again | the later-draw test, and two tests each of `address_lookup_test.zig` and `lookup_negative_test.zig`, `test-resolver`; the later-draw and boundary-octets tests, `test-wire` | CAUGHT |
| CP8 | check 5 for a query that mixed takes the question echoed in lowercase | RFC 5452 §9.1, §7 check 5, decision 10 | both `matches_mixed` tests, the fuzz gate and the fuzz target's two verdict tests, `test-wire`; eight tests, the later-draw, folded-case and lowercasing tests among them, `test-resolver` | CAUGHT |
| CP9 | check 5 for a query that mixed ignores the type | §7 check 5, the type compares exactly | both `matches_mixed` tests, `test-wire`; the type-or-class and every-letter tests, `test-resolver` | CAUGHT |
| CP10 | check 5 for a query that mixed ignores the class | §7 check 5, class IN | the `matches_mixed` test, `test-wire`; the type-or-class and every-letter tests, `test-resolver` | CAUGHT |
| CP11 | a reply to a query asked in lowercase is compared with the name as held | §7, a marked server is asked in lowercase | the capitals test, `test-resolver` | CAUGHT |
| CP12 | a response is applied cut at its header, short of the question check 5 read | §7, past check 5 the name is read for its length | the assertion in `apply`, by a panic under 123 tests, `test-resolver` | CAUGHT |
| CP13 | the name a mark asserts the lowercase echo is not is built in lowercase | §7 Entropy, a capital in every mixed name | the assertion in `mark`, by a panic under eleven tests, the lowercasing and later-draw tests among them, `test-resolver` | CAUGHT |
| CP14 | the offsets of a question's type and class, read before its name, are summed in the octet a name's length is held in | RFC 1035 §2.3.4, §7 check 5 | the long-name and most-labels tests, the long `matches_mixed` test and the fuzz gate, each by a panic, `test-wire`; the three 255-octet tests of a lookup, each by a panic, `test-resolver` | CAUGHT |
| CP15 | those offsets are summed in that octet for a query that mixed the case alone | RFC 1035 §2.3.4, §7 check 5 | the long `matches_mixed` test and the fuzz gate, each by a panic, `test-wire` | CAUGHT |
| CP16 | those offsets are summed in that octet for a query that mixed the case alone, under a lookup | RFC 1035 §2.3.4, §7 check 5 | the every-letter test and the two 255-octet tests of `lookup_case_test.zig`, each by a panic, `test-resolver` | CAUGHT |
| CP17 | check 5 for a query that mixed refuses the echo of a question whose name is 250 octets long | §7 check 5, at every length the gate writes | the fuzz gate, `test-wire` | CAUGHT |
| S4 | the question section is not compared, written again for check 5 read in place | RFC 5452 §9.1 | thirteen tests of `lookup_case_test.zig` and `lookup_case_echo_test.zig`, the nobody-asked and type-or-class tests among them, `test-resolver` | CAUGHT |
| S6 | a response is read whatever the state, written again for `apply` without a name | §5 | the after-settled test of `lookup_response.zig` and the shared-id test of `table.zig`, by a panic, `test-resolver` | CAUGHT |
| DH13 | NXDOMAIN's negative TTL keeps its `Age`, written again for the name held | RFC 8484 §5.1, RFC 2308 §5 | the kept-record test, `test-resolver` | CAUGHT |
| DH14 | NODATA's negative TTL keeps its `Age`, written again for the name held | RFC 8484 §5.1, RFC 2308 §5 | the kept-record test, `test-resolver` | CAUGHT |
| TT8 | a negative's TTL is not bounded by the chain, written again for the name held | RFC 1035 §3.2.1, RFC 2308 §5 | the negative chain test, `test-resolver` | CAUGHT |
| WN1 | NXDOMAIN replaces the walk's negative TTL rather than keeping the smaller, written again for the name held | §5 search list policy, RFC 2308 §5 | the all-negative walk test, `test-resolver` | CAUGHT |
| WN2 | NODATA replaces the walk's negative TTL rather than keeping the smaller, written again for the name held | §5 search list policy, RFC 2308 §5 | the all-negative walk test, `test-resolver` | CAUGHT |
| DT4 | a response takes a sample before §7's checks, so an unmatched one does too, written again for `on_response` without a name | §5, §16 decision 10 | eleven tests, the memory-hit, third-sample, ignored-response and TLS tests among them, `test-resolver` | CAUGHT |
| CM1 | the mark is never made, moved to `lookup_response_case.zig` | §7, the mark | seven tests, the lowercasing, check-6, later-draw and 255-octet tests among them, `test-resolver` | CAUGHT |
| CM2 | a response in another case marks its server though the query did not mix the case, moved to `lookup_response_case.zig` | §7, only a query that mixed | the unmixed-query test, `test-resolver` | CAUGHT |
| CM3 | the mark does not compare the question with the one asked in lowercase, so another question marks, written again for the name held | RFC 1035 §2.3.3, RFC 4343 §3, §7 the mark | the more-than-case, other-way, later-draw and every-letter tests, `test-resolver` | CAUGHT |
| CM4 | the mark skips check 6, so a wrong or a missing cookie marks, moved to `lookup_response_case.zig` | RFC 7873 §5.3, §7 check 6 | the check-6 and owed-cookie tests, `test-resolver` | CAUGHT |
| CM5 | a malformed OPT record is read as none, and marks, written again for the name held | RFC 7873 §5.2.2, §7 check 6 | the check-6 test, `test-resolver` | CAUGHT |
| CM7 | check 5 compares with the server's mark at the response, not with what the query sent, moved to check 5's branch | §7, the query's record | the later-draw test and the 255-octet test of `lookup_case_test.zig`, `test-resolver` | CAUGHT |
| CM8 | the mark lands on the first server, not the one that answered, moved to `lookup_response_case.zig` | §7, that server alone | the other-server test, `test-resolver` | CAUGHT |
| CM10 | the lowercase compare ignores the type, narrowed to the lowercase compare now that every compare reads the type first | §7, the type compares exactly | the lowercase test, `test-wire`; the more-than-case test, `test-resolver` | CAUGHT |
| CM11 | the lowercase compare ignores the class, written again for the class read first | §7, the class compares exactly | the lowercase test, `test-wire` | CAUGHT |
| CM12 | check 5 takes the question echoed in lowercase, so the response that marks is the answer too, written again for check 5 read in place | RFC 5452 §9.1, §7 check 5, decision 10 | nine tests, the folded-case, lowercasing and later-draw tests among them, `test-resolver` | CAUGHT |
| CM19 | a letter drawn small counts as a capital, so a draw that leaves every letter small stands, written again for `Draw` | §7 Entropy, a capital in every mixed name | the redraw, one-letter, later-draw and first-draw-reading tests, `test-wire`; the later-draw test, `test-resolver` | CAUGHT |
| CM20 | a draw is repeated from the word the first started from, so it leaves every letter small again, moved to `name_case.zig` | §7 Entropy, each draw from the next word | the redraw test, `test-wire` | CAUGHT |
| CM21 | the first letter is not made a capital once every draw left the name small, moved to `name_case.zig` | `case_draws_max` | the one-letter and later-draw tests, `test-wire`; the later-draw test, `test-resolver` | CAUGHT |
| CM22 | a name without a letter is drawn again as one left small, written again for `Draw` | §7 Entropy | the letterless, takes-the-name and boundary-octets tests, `test-wire`, by a panic at the `unreachable` past the last draw | CAUGHT |
| QO2 | the offset of a question's class is summed in the octet a name's length is held in, written again for the class read first | RFC 1035 §2.3.4, §7 check 5 | the long-name and most-labels tests, the long `matches_mixed` test and the fuzz gate, each by a panic, `test-wire` | CAUGHT |

## The engine's cache over memory the caller hands it

2026-10-11. The owner ruled that the caller hands the engine its cache memory at init, as the
library's `Cache.init` takes it, so that the size can come from a configuration file, and that
the cache's TTL cap is a `Config` field, 3,600 s by default (design §16 decision 37). Until then
`Options.cache_slots` sized two arrays inside the engine when its type was built. So no number
read at run time reached the size, an engine could not run without a cache, and the cap was the
constant of an hour.

`init` and `reinit` now take a `?cocuyo.cache.Slices`, the slots and the key index, or null.
The engine builds its `Cache` over them, keyed by the seed of the call and capped at the
configuration's `cache_ttl_seconds_max`, and an engine handed null gives its table no `Memory`.
`reinit` takes the memory it holds, other memory, or none. The library's `cache` module gained
what a caller sizes that memory with: `Slices`, `Storage`, `keys_for` and `slot_count_valid`
(`src/cache/cache_storage.zig`). `Config` gained `cache_ttl_seconds_max`, whose default is
`core`'s `cache_ttl_seconds_max_default`, and `cache.constants.ttl_seconds_max_default` is that
constant under its older name. `Cache.init` keeps its signature, and the cache's eviction, its
probe bound and what it refuses to keep are as they were.

The design changed first: §3, §4, §10, §12, §18 (Sizing the memory), §19 step 13 (The cache's
memory), §20, §24, §16 decision 37 and §17 questions 29 to 33. No model changed. The Lean models
are of one lookup and of the `getaddrinfo` walks, and the TLA+ model of the engine leaves the
cache out, as spec/README.md says: a search of `spec/lean/` and `spec/tla/` for a cache, a
recall, a remember or a `reinit` finds none, and the two lines there that say memory are about
buffers lent to the loop. The replay's engine is handed two slots, the size it had as an
option, and no start of a walk asks a name twice. `zig build spec-lean` and the replays of
`zig build test` agree.

Each of CZ1 to CZ28 was broken by hand against the step its row names, to name the tests that
fail. Then `zig build mutations -- lookup` ran CZ1 to CZ14, CZ25, CZ27 and CZ28, and
`zig build mutations -- engine` ran CZ15 to CZ24 and CZ26, each after running its checks once
with nothing mutated, and caught each. Twenty-eight new mutations, twenty-eight `CAUGHT`.

A review the same day broke two checks that no test caught, and each was a test missing:

- CZ25. `Slices.valid` took more slots than the most. CZ9 takes its bound on the slots away
  whole, which the shape test catches at no slots, and nothing asked it of 16385. The
  most-slots test does, over slices cut longer than the memory under them: `valid` reads the
  two lengths and nothing else, and no cache is built over those slices.
- CZ26. Design §19 step 13 rule 5 says the memory an engine held is the caller's once a
  `reinit` handed other memory or none returns, whatever it returns. That held only because
  `reinit` builds its table and its cache before it opens its sockets, and no test ran a
  `reinit` that fails. The failed-reinit test does. The twin refuses the open, and the cache
  must be over the memory that call handed in, under its seed, then over none when the call
  hands none. The rule now says so of the new memory too: a failed `reinit` has taken it.

CZ24 breaks the README and was in no set at first. Its check fails where the package the
README's code is written into does not compile, and the tool read the nested compiler's line
as a mutation whose text no longer applies. `readme-check` now quotes what the nested build
prints, each line set in from the margin, and the tool takes a compiler's line for this tree's
own only from a line's first column. CZ27 and CZ28 break those two against the tools' tests,
and CZ24 is in the engine's set.

Breaking the checks changed four tests before the rows stood:

- CZ3 was one edit at first, and did not compile: `keys_for` asserts the bound it computes, and
  `Storage` evaluates it when the caller compiles. The row breaks the check and the assertion
  together, as a bound is both (CLAUDE.md non-negotiable 6). The shape test sliced six keys
  from a `Storage` of three slots, which under the mutation holds four, a compile error of the
  test's own. It now slices arrays of its own.
- CZ8 was caught by a panic alone, the assertion in `slices`. The shape test now holds two
  slots and four keys valid, the case where the least index is exactly the bound.
- CZ17 was caught by the off test alone. The no-memory test read the cache of an engine whose
  memory had held nothing. It now starts an engine with a cache, closes it, and starts it again
  with none, so a cache left behind shows.
- The run-time test of `cache_storage.zig` read its slot count from a function, which the
  magic-numbers rule refused for its literal. The count is a variable of the test.

Four checks are in no row, as Z10 and T11 are not: the assertion of `assert_cache_memory` in
`io/io_lifecycle.zig`, which `init` and `reinit` call, the two in `keys_for`,
`assert_valid`'s floor of one second under the cap, weakened, and the compile error `Storage`
gives a count outside the bounds. `Cache.init` asserts the same of the slices and of the cap,
and `keys_for` refuses the same count when `Storage` evaluates it, so a test that reached one
of them would halt or not compile, and no behaviour changes without it. `Storage(0)` and
`Storage(16385)` were compiled by hand: each stops at the error that names the bounds, and
`Storage(1)` and `Storage(16384)` compile. `assert_cache_memory` asserted a second thing, a key
index of `keys_for` entries at least, which `valid` already says, and the review took it out.
Z9, `reinit` keeps the answers the old servers gave, is CZ22 now: the cache is emptied by
being built again over the memory `reinit` is handed, and the reinit test of
`io_lifecycle_test.zig` still catches it.

Rows of the engine's set run again, since the rigs and the replay's world now hand the engine
its cache memory, each `CAUGHT` as before:

- The thirteen that `test-io` and `test-cocuyo_quic` catch: ET12, ET13, SQ3, SQ4, TR4, CE4,
  CE18, CE20, CE21 and QO8 to QO11.
- The twenty-eight that `test-cocuyo_doh` catches, DC1 to DC28, whose world holds the memory of
  its engine's cache.
- The fifty-four the committed short walks catch, by those walks.

The twenty-two rows the picked walks catch did not run again: each needs TLC's full run. The
picked walks replay in agreement in the gate with nothing mutated, and no file their edits
touch changed but `io/io.zig`, where E3's lines stand as they were.

The review's changes touched files that older rows edit, so those ran again by the tool, each
`CAUGHT` as before: QO11 in the engine's set, and DH1, QU1, QU2, DT28 and TA6 to TA8 in the
lookup's.

The tests the table names. In `src/cache/cache_storage.zig`: the least-index test (1, 2, 3,
1024 and 16384 slots take 2, 4, 8, 2048 and 32768 keys, each a power of two, at least two a
slot, and the least such), the bounds test (0 and 16385 slots refused, 1, 1024 and 16384
taken), the shape test, the most-slots test (16384 slots under their least index valid, and
16385 under an index long enough for them not), the storage test, the one-slot test and the
run-time test (a count of three, in a variable, over part of a memory of eight). In
`src/cache/cache_ttl_test.zig`, the default-cap test. In `src/core/config.zig`, the cap test
(an hour by default, and caps of 1, 300 and the most a `u32` holds valid). In
`src/config/resolv_conf.zig`, the options test. In `io/io_lifecycle_cache_test.zig`: the hit
test (memory handed over, a repeated question answered with nothing sent, and the cache over
that memory under that seed), the no-memory test, the two-slot test (a count read at run time,
and the third name evicts one), the least-memory test (one slot and two keys), the same-memory
test, the other-memory test (the old memory written over and found as written), the
failed-reinit test (the open refused, the cache over the memory that call handed in, the old
memory written over and found as written after the next `reinit`, then a second failure
handed none), the off test (none, then memory again), the default-cap test (a TTL of 7,200 s
kept an hour), the set-cap test (caps of 60 and 86,400 s) and the reinit-cap test (600 s, then
30). A lookup counts as sent when its slot's buffer is lent to the loop as `start` returns, and
as answered from the cache when its result is taken before the loop turns. In
`tools/mutations_check.zig`, the quoted-error test, and in `tools/readme_check.zig`, the
quotation test.

The same day the owner answered design §17 question 30: follow the RFC. A cap is at most seven
days, the named `cache_ttl_seconds_max`: "Values SHOULD be capped on the order of days to weeks,
with a recommended cap of 604,800 seconds (7 days)" (RFC 8767 §4). `cache.ttl_seconds_max_valid`
says whether a cap is one a cache takes, and CZ29 and CZ30 break its two bounds; the cap test of
`cache_ttl_test.zig` sees both. `Cache.init` and `Config.assert_valid` assert the same bound and
have no row, as the assertions of Z10 and T11 have none: taking an assertion away changes
nothing a test can see.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CZ1 | `slot_count_valid` takes a cache of no slots | §18, a slot count of 1 to `cache_slots_max` | the bounds and shape tests, `test-cache` | CAUGHT |
| CZ2 | `slot_count_valid` takes one slot more than the most | §18, a slot count of 1 to `cache_slots_max` | the bounds and most-slots tests, `test-cache` | CAUGHT |
| CZ3 | `keys_for` gives one key a slot, and its own assertion asks no more | §18, `cache_keys_per_slot_min` entries a slot | the least-index, most-slots, storage, one-slot and run-time tests; twenty-three tests that build a cache, by `Cache.init`'s assertion, `test-cache` | CAUGHT |
| CZ4 | `keys_for` does not round up to a power of two | §18, a key index of a power of two | the least-index, storage and run-time tests; four tests of the probe and the sweep, by a panic, `test-cache` | CAUGHT |
| CZ5 | `keys_for` gives twice the least key index | §18, the least index a slot count takes | the least-index, storage and one-slot tests, `test-cache` | CAUGHT |
| CZ6 | `Slices.valid` takes a key index that is no power of two | §18, what `Cache.init` asserts | the shape test, `test-cache` | CAUGHT |
| CZ7 | `Slices.valid` takes a key index of fewer than two entries a slot | §18, what `Cache.init` asserts | the shape test, `test-cache` | CAUGHT |
| CZ8 | `Slices.valid` refuses the least key index | §18, the least index is enough | the shape and most-slots tests; the one-slot test, by the assertion in `slices`, `test-cache` | CAUGHT |
| CZ9 | `Slices.valid` asks nothing of the slot count | §18, a slot count of 1 to `cache_slots_max` | the shape and most-slots tests, `test-cache` | CAUGHT |
| CZ10 | the cache module's default cap is not the configuration's | §12, one constant for the two | the default-cap test of `cache_ttl_test.zig`, `test-cache` | CAUGHT |
| CZ11 | a configuration's default cap is not the named hour | §4, 3,600 s by default | the cap test of `config.zig`, `test-core` | CAUGHT |
| CZ12 | `assert_valid` refuses a cap of one second | §4, a cap of at least 1 | the cap test of `config.zig`, by a panic, `test-core` | CAUGHT |
| CZ13 | a parsed configuration's cap is not the default | §10, no line of a `resolv.conf` sets the cap | the options test of `resolv_conf.zig`, `test-config` | CAUGHT |
| CZ14 | the consumer fixture starts its resolver without its cache memory, as before the ruling | §24, what a consumer writes | `consumer-check`: the dependent package does not build | CAUGHT |
| CZ15 | an engine handed cache memory puts no cache under its table | §19 step 13, the cache's memory, rule 2 | ten of the eleven tests of `io_lifecycle_cache_test.zig`, all but the no-memory test; the second-start test of `io_sim_test.zig` and the reinit test of `io_lifecycle_test.zig`, each by a panic, `test-io` | CAUGHT |
| CZ16 | an engine handed no cache memory is refused | rule 3, null is an engine with no cache | the no-memory, failed-reinit and off tests, each by a panic, `test-io` | CAUGHT |
| CZ17 | an engine handed no cache memory keeps the cache its memory held | rule 3, no cache | the no-memory, failed-reinit and off tests, `test-io` | CAUGHT |
| CZ18 | the engine caps its cache at the constant of an hour, whatever the configuration says | rule 8, the configuration's cap | the set-cap and reinit-cap tests, `test-io` | CAUGHT |
| CZ19 | the engine's cache has no cap | rule 8, the configuration's cap | the default-cap, set-cap and reinit-cap tests, `test-io` | CAUGHT |
| CZ20 | the engine keys its cache by a constant, not by the seed it is given | rule 2, keyed by the seed of the call | the hit, same-memory and failed-reinit tests, `test-io` | CAUGHT |
| CZ21 | the engine builds its cache over the first slot alone | rule 2, a cache over the memory handed in | the hit and two-slot tests, `test-io` | CAUGHT |
| CZ22 | `reinit` keeps the cache it had, whatever memory it is handed | rule 4, `reinit` takes the memory again | the same-memory, other-memory, failed-reinit, off and reinit-cap tests, and the reinit test of `io_lifecycle_test.zig`, `test-io` | CAUGHT |
| CZ23 | `reinit` builds its cache over the memory the engine held, when it held some | rules 4 and 5, the old memory is never touched again | the other-memory, failed-reinit and off tests, `test-io` | CAUGHT |
| CZ24 | the README's engine block starts the engine without its cache memory, as before the ruling | the README's code compiles | `readme-check`: the package does not build, since `init` expects five arguments and finds four | CAUGHT |
| CZ25 | `Slices.valid` takes more slots than the most, where it refuses none | §18, a slot count of 1 to `cache_slots_max` | the most-slots test, `test-cache` | CAUGHT |
| CZ26 | `reinit` opens its sockets before it builds its table and its cache, so a `reinit` that fails keeps the cache it had | rule 5, the old memory is the caller's whatever `reinit` returns, and a failed `reinit` has taken the new | the failed-reinit test, `test-io` | CAUGHT |
| CZ27 | the mutation tool reads a compile error a check quotes as this tree's own | a nested build's compile error is what its check caught | the quoted-error test of `mutations_check.zig`, `test-tools` | CAUGHT |
| CZ28 | `readme-check` prints the nested build's output at the margin, as it did | the nested build's output is quoted, set in from the margin | the quotation test of `readme_check.zig`, `test-tools` | CAUGHT |
| CZ29 | a cache takes a cap of zero | §18, a cap of 1 second to `cache_ttl_seconds_max` | the cap test of `cache_ttl_test.zig`, `test-cache` | CAUGHT |
| CZ30 | a cache takes a cap past seven days | §18, a cap of 1 second to `cache_ttl_seconds_max`, the cap RFC 8767 §4 recommends | the cap test of `cache_ttl_test.zig`, `test-cache` | CAUGHT |

## cocuyo_quic's session with no default

2026-10-11. The owner ruled that `cocuyo_quic.Options.Session` has no default and must be set
(design §16 decision 38). Until then it defaulted to `Plain`, the wrapper of the plain session
of `io/io_quic_plain.zig`, since 8b9fa5b of 2026-09-25, in v0.2.0 to v0.5.0. The gate runs
colibri's QUIC over that session (decision 29), which encrypts nothing and authenticates
nobody. A consumer that left the option unset ran it, and the build never said so. What the
run did depended on who answered (design §24, the session a connection names):

- A server that speaks DoQ opened nothing in the session's packets: "Initial packets apply the
  packet protection process" (RFC 9001 §5.2), and the session's apply none. No handshake
  ended, no query left, and every lookup failed. The run said so.
- A peer that sends the session's made-up messages completed the handshake on `doq`. Such a
  peer is cocuyo's own test server, or an attacker who answers in the server's place. Each
  query went to it in the clear and its answers were taken, and the run said nothing.

`SECURITY.md` lists `cocuyo_quic` in scope. The session's own faults, two sums and a message
taken twice, were fixed in 1765131 (Sums at the most their operands reach, above). This change
is about the default alone.

`Options.Session` is now a field with no default value. A consumer that names no session does
not compile: the compiler stops where the options are written, with `missing struct field:
Session`. `plain`, `Plain` and `server` stay exported under the names they had, for tests.
Their comments, design §24 and the README say that they encrypt nothing, authenticate nobody,
and are never for a network. The change breaks `cocuyo_quic`'s public API, as the owner asked,
and changes nothing else of it.

The design changed first: §24 (the request interface, colibri under the request interface, the
session a connection names, the checks, and step 4), §16 decision 38, with the two alternatives
it beat, and §17 question 34. No model changed. The Lean models are of one lookup and of the
`getaddrinfo` walks. The engine's TLA+ model takes a request connection's handshake as it ends
or fails and never says which type runs it, and the replay drives the twin's `sim.quic`: a
search of `spec/` and `tools/spec_replay/` for `cocuyo_quic` finds nothing.
`zig build spec-lean` and the replays of `zig build test` agree.

Two users in the tree relied on the default, and each now writes its session:

- The module's own tests, in `io/io_quic.zig`, write `.Session = Plain`.
- The engine's tests over colibri on the twin, in `io/io_quic_test.zig`, write
  `.Session = cocuyo_quic.Plain`.

`examples/doq_rotor.zig` named chapulin's session already. Nothing else names a connection of
`cocuyo_quic`: a search of `bench/`, `test/consumer/`, `tools/`, the other examples and the
README's blocks finds none. `zig build examples`, `consumer-check`, `readme-check`,
`bench-cares` and `test-cares` each ran after the change and passed. `zig build examples`
installs four examples and not the DoQ one, which `zig build test` builds.

The check is the no-default test of `io/io_quic.zig`. It reads the fields of `Options` when it
compiles, and requires two things of `Session`: that it carries no default value, and that its
type is `type`. Three mutations break it:

- QS1 puts the default back, as the line stood before the ruling.
- QS2 makes the field a `?type` that defaults to null, and has a connection that reads null run
  the plain session. That is the old default by another spelling.
- QS3 makes the field a `?type` with no default, and has a connection that reads null run the
  plain session. A consumer must then write the field, and `.Session = null` gets it no
  protection.

Each was broken by hand against `zig build test-cocuyo_quic`, to read what fails: QS1 and QS2
at the test's first expectation, QS3 at its second, eight of the module's nine tests passing
each time. Then `zig build mutations -- engine` ran the three, after running the step once with
nothing mutated, and caught each. Three new mutations, three `CAUGHT`.

That a consumer which names no session does not compile is the compiler's rule, and no check
of cocuyo's, so it has no row: the tool reads a compile error of this tree's own as a mutation
whose text no longer applies. It was shown by hand, twice. With `.Session = Plain` taken out of
the module's tests, `zig build test-cocuyo_quic` stops where `Pair` writes its options, in
`io/io_quic.zig`, with `error: missing struct field: Session`. With
`.Session = cocuyo_quic.Plain` taken out of the engine's tests, `zig build test-io` stops where
`io/io_quic_test.zig` writes its options, with the same words.

Rows of the engine's set ran again by the tool, since the two rigs now name their session and
the comments of `io/io_quic_plain.zig`, `io/io_quic_server.zig` and the README changed, each
`CAUGHT` as before:

- The five older rows that `test-cocuyo_quic` catches: TR4, QO12, QO13, QO17 and QO18.
- The twenty-two that `test-io` catches: ET12, ET13, SQ3, SQ4, CE4, CE18, CE20, CE21, QO8 to
  QO11, CZ15 to CZ23 and CZ26.
- CZ24, which `readme-check` catches.

The other 109 rows of the engine's set did not run again, since no file their edits touch
changed:

- The fifty-four the short walks catch and the twenty-two the picked walks catch. The replay
  names no `cocuyo_quic`.
- The twenty-eight that `test-cocuyo_doh` catches, DC1 to DC28.
- The three that `test-sim` catches, QO14 to QO16.
- The two that `spec-engine` catches, RF5 and FR13.

A review the same day found the first account of the old default wrong. It said the handshake
ended and the answers came, whoever answered. That holds against a peer that sends the plain
session's messages, and not against a server that speaks DoQ. The two cases at the head of this
section, decision 38 and design §24 now say so. Both are read from the code and the RFCs, and
the gate's tests run the second against the test server. The first was then run by hand, with
two tests written for the run and taken out after it:

- One, in `io/io_quic.zig`, printed the first datagram of the module's test client. It is
  1,200 octets. Its first octet is 0xc0, a long header's with no header protection over it,
  and its CRYPTO frame carries the made-up hello and its `doq` as they are.
- The other, in `io/io_doh_channel_quic_test.zig`, handed that datagram to colibri's server
  over chapulin's QUIC, the one `cocuyo_doh`'s tests answer with. The server owed it nothing,
  then or ten seconds on. Handed the first datagram of a client over chapulin's QUIC, from the
  same address, the same server owed 48 octets at once.

That server selects `h3` and not `doq`, which it never came to read. No public resolver was
sent the datagram. No peer was written to play the attacker: the test server sends the
messages one would.

The review asked how a consumer reaches the session it must name, since the build registers no
module for it. The README and design §24 now say what the module is made of, and design §17
question 34 asks the owner whether the build should register one. No check of the gate builds
such a consumer, since `test/consumer/` binds no colibri, so a package outside the tree was
built by hand. It depends on cocuyo by path, and on colibri and rotor at the pins of
`build.zig.zon`. Its build binds `cocuyo_quic`'s `quic` import to colibri's, and makes the
session's module from `cocuyo.path("io/io_chapulin_quic.zig")` with the imports `build/doq.zig`
gives it. What it showed:

- With the two lines design §24 gives, it built, and its program started a lookup whose first
  datagram, 1,200 octets, reached a socket on the loopback.
- With `.Session` left out of the same options, it stopped where its program writes them, with
  `error: missing struct field: Session`.

The review's changes touched two files that rows edit, so those rows ran again by the tool,
each `CAUGHT` as before: QS1 to QS3, for the comments of `io/io_quic.zig`, and CZ24, for the
README. TR4, QO12, QO13, QO17 and QO18 ran with them.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| QS1 | `Options.Session` defaults to `Plain`, as before the ruling | design §16 decision 38, the options carry no default session | the no-default test, at its first expectation, `test-cocuyo_quic` | CAUGHT |
| QS2 | `Options.Session` is a `?type` that defaults to null, and a connection with none runs the plain session | decision 38, no default under any spelling | the no-default test, at its first expectation, `test-cocuyo_quic` | CAUGHT |
| QS3 | `Options.Session` is a `?type` with no default, and a connection handed null runs the plain session | decision 38, the options hold no value that means no session | the no-default test, at its second expectation, `test-cocuyo_quic` | CAUGHT |

## The context a session starts from

2026-10-11. The owner ruled that the engine holds no default context: "No default context. An
engine asked to open a DoT, DoQ or DoH session whose context was never set stops with an
assertion, since forgetting it is a programmer error. Tests name their test contexts on
purpose" (design §16 decision 39). A context is what every session of one encrypted transport
starts from, and a consumer hands the engine one with `use_tls`, `use_quic` or `use_doh`. Until
then `init` set all three to defaults, and nothing checked that a consumer replaced them. A
default held values for tests: no anchor, a wall clock of zero, and a stream seeded with zeros
for DoQ and DoH and left undefined for DoT.

What the engine does now (design §24, the context a session starts from):

- It holds each context as an optional, null from `init` until its `use_` call.
  `io/io_context.zig` is the one file that reads the three, and it hands a session its context
  after an assertion that one was set.
- `has_context` says whether the transport the engine's configuration speaks has its context.
  A configuration of plain DNS needs none.
- `start` asserts `has_context`. A lookup against a DoT, DoQ or DoH configuration whose
  context was never set stops the program there.
- The four context types that carried defaults carry none: the DoT session's and the DoQ
  session's over chapulin, `cocuyo_quic`'s connection's and `cocuyo_doh`'s.

The change breaks the engine's public API, as the owner asked. A consumer that skipped a `use_`
call stops at its first lookup, and one that wrote a context with a field left out does not
compile. It adds one name, `has_context` (design §17 question 35), and changes nothing else of
the API.

The design changed first: §21 (the ruling of 2026-09-23 on the seed and the clock, the session
interface and the checks), §24 (the request interface, DoH over colibri's client, the context a
session starts from, and the checks), §16 decision 39 with the two alternatives it beat, and
§17 question 35. No model changed. The engine's TLA+ model starts a handshake and says how it
ends, and never what it started from, and the Lean models are of one lookup and of the
`getaddrinfo` walks: a search of `spec/` for a context, an anchor or a `use_` call finds none.
`zig build spec-lean` and the replays of `zig build test` agree.

What the calls did before, as read from the code:

- **The order a consumer follows.** `examples/dot_rotor.zig`, `examples/doq_rotor.zig` and
  `examples/doh_rotor.zig` each call their `use_` function on the line after `init`, before
  any lookup. So the assertion is in `start`, and `init` holds none.
- **`init`.** It set the three contexts to their defaults. It now sets them to none, so an
  engine closed and started again in the same memory is handed its contexts again, each built
  from a new draw of its seed.
- **`reinit`.** It reset no context. It drops the tickets of all three transports, which were
  the old servers', and it neither reads nor writes a context. That stands. A context set
  before a `reinit` still counts after it, its stream goes on from where it was, and one never
  set is still missing.
- **The `use_` functions.** Each takes its context by value and the engine keeps the copy, which
  its sessions draw from. The consumer's own copy still holds its stream as it was built, so a
  context handed again from that copy, or built again from the same 32 octets, starts the
  stream where the first one started. The engine cannot see that, and the design, the doc
  comments and the README state it as the consumer's rule (§24, rules 4 and 5).

Every user in the tree, and what each needed:

- The engine's tests on the twin. The rigs of `io_tls_test.zig`, `io_request_test.zig`,
  `io_request_failure_test.zig` and `io_channel_test.zig` call `use_test_contexts` after
  `init`, a helper of `io_sim_test.zig` that names the empty context of each of the twin's
  types an engine speaks. `io_channel_link_test.zig` starts through `io_channel_test.zig`.
- The engine's tests over colibri on the twin, `io_quic_test.zig`, name a `test_context`: the
  plain session's, and a stream of connection IDs seeded with zeros.
- The sessions' tests, in `io_chapulin.zig` and `io_chapulin_quic_test.zig`, built each context
  with `init` already. They now build it through a `test_context` of their own.
- `cocuyo_quic`'s tests, in `io_quic.zig`, held a context of defaults. They name a
  `test_context`.
- `cocuyo_doh`'s tests build theirs with `identity.test_context`, over the test identity. Each
  of the two fixtures holds it as its field's default, from where the fixture is built, and
  none is left `undefined` for a later statement to fill. The engine's test over it wrote the
  engine's field, and now calls `use_doh`.
- The replay's world, `tools/spec_replay/engine_world.zig`, names the twin's context for the
  transport a walk configures.
- The three examples above called their `use_` function already, and each gained a comment.
  The other examples, `test/consumer/`, `bench/` and the README's blocks speak plain DNS and
  name no context: a search of them for `.tls =`, `.quic =` and `.doh =` in an engine's
  options finds none. `zig build examples`, `consumer-check`, `readme-check`, `bench-cares` and
  `test-cares` each ran after the change and passed.

The checks are tests. Six are in `io/io_context_test.zig`, on an engine that speaks all three
of the twin's types:

- The DoT test, the DoQ test and the DoH test. Each starts an engine over a configuration of
  its transport and requires three things of `has_context`: no before any call, no still once
  the other two transports have their contexts, and yes after its own `use_` call. Then a
  lookup is started and answered, which passes `start`'s assertion and hands the session its
  context.
- The plain test. A configuration of plain DNS has what it needs with no context set, and its
  lookup is answered.
- The reinit test. It walks one engine from DoT to DoQ, back to DoT, to DoQ, to DoH, to DoT
  and to DoH. A transport never named is still missing after the `reinit` that reaches it, and
  each one named is still there when a later `reinit` comes back to it. For each of the three
  a lookup is then started and answered over the context a `reinit` kept, so a session takes a
  kept context.
- The init test. For each transport, an engine with all three contexts set is closed and
  started again in the same memory, and has none.

Four more are the no-default tests, one for each context type: in `io/io_chapulin.zig`,
`io/io_chapulin_quic_test.zig`, `io/io_quic.zig` and `io/io_doh_channel_start.zig`. Each reads
the type's fields when it compiles and requires that none carries a default value, as the
no-default test of `Options.Session` does (QS1 to QS3, above). Each default the four types
lost has a row, TC17 to TC30: the stream, the anchors, the wall clock and its instant of the
three contexts that `init` builds, and the two fields of `cocuyo_quic`'s.

Each of TC1 to TC30 was broken by hand against the step its row names, to read which tests
fail. Then `zig build mutations -- engine` ran the thirty, after running each of the five
steps once with nothing mutated, and caught each. Thirty new mutations, thirty `CAUGHT`.

Two things have no row:

- **The assertions.** `start` asserts the predicate, and the three readers of
  `io/io_context.zig` each assert that the configuration speaks their transport and that its
  context is set. Taking an assertion away changes nothing a test can see, as with Z10 and
  T11. That `start` stops the program was shown by hand, three times, with
  `use_test_contexts` taken out of one rig each time and `zig build test-io` run. Without it
  in the rig of `io_tls_test.zig`, seven tests stop; in `io_request_test.zig`, sixteen; in
  `io_channel_test.zig`, fifteen. Each stops at the assertion in `start`, and the other tests
  pass.
- **That a context with a field left out does not compile.** It is the compiler's rule, and
  the tool reads a compile error of this tree's own as a mutation whose text no longer
  applies. It was shown by hand in the three examples. With `.stream` taken out of the context
  `examples/doq_rotor.zig` writes, `zig build example-doq-rotor` stops with `missing struct
  field: stream`. With `use_tls(.{})` and `use_doh(.{})` in place of the two `init` calls, the
  DoT and DoH examples each stop with `missing struct field: anchors`.

The readers cannot be weakened into reading a default: no context type has one left, so a
reader that met null has no value to hand over.

The rows are named `TC`, as two older sets of rows are: the TCP request connections' and the
text parsers' fuzz target's. In the engine's set these are the only rows of that name.

The engine's whole set then ran again by the tool, after the last edit to the code: 170 rows,
in three runs of `zig build mutations -- engine` one after another, none interrupted. The rigs
and the replay's world now name their contexts, and seven files that older rows edit changed,
with the README: `io/io.zig`, `io/io_tls.zig`, `io/io_lifecycle.zig`,
`io/io_request_connection.zig`, `io/io_channel.zig`, `io/io_quic.zig` and
`io/io_doh_channel_start.zig`. Each of the 140 older rows is `CAUGHT` as before:

- The twenty-two that `test-io` catches: ET12, ET13, SQ3, SQ4, CE4, CE18, CE20, CE21, QO8 to
  QO11, CZ15 to CZ23 and CZ26.
- The eight that `test-cocuyo_quic` catches: TR4, QO12, QO13, QO17, QO18 and QS1 to QS3.
- The twenty-eight that `test-cocuyo_doh` catches, DC1 to DC28.
- CZ24, which `readme-check` catches.
- QO14 to QO16, which `test-sim` catches.
- RF5 and FR13, which `spec-engine` catches.
- The fifty-four the committed short walks catch, by those walks.
- The twenty-two the picked walks catch. TLC wrote the full run, 2,000 walks of 201 states for
  each configuration, and it replays in agreement with nothing mutated. The short walks catch
  six of the rows and miss sixteen. The full run first catches those at walks 4, 8, 13, 2002,
  4020, 4212, 8046, 12011, 13182, 16008, 16068, 16478 and 17842, which are the thirteen the
  committed picks hold, so no walk is picked anew.

The three examples each resolved `example.com` against a public resolver the same day, by
hand, with the context each one builds: `example-dot-rotor` through Cloudflare's 1.1.1.1,
known as `cloudflare-dns.com`; `example-doq-rotor` through AdGuard's 94.140.14.14, known as
`dns.adguard-dns.com`; and `example-doh-rotor` through Cloudflare's template, which came up on
HTTP/3. Each was answered after a full handshake.

Two reviews read the change the same day, before any of it was committed. What they changed,
which the paragraphs above already describe as it stands:

- Design §21's ruling of 2026-09-23 said the engine takes the seed at `init`, and the wall
  clock at `init` and at `reinit`. No code did, and the bullet now says where both arrive: in
  the context `use_tls` takes.
- The doc comments of `init` and of `reinit` say what each does to the contexts, where only
  `use_tls`'s did.
- A context handed again is built from a new draw. Design §16 decision 39 and §24 rules 4 and
  5, the README and the doc comments of the three `use_` functions say so.
- The README says DoQ's context takes a second draw, for the stream of its connection IDs.
- `cocuyo_doh`'s two fixtures left their context `undefined` until `create` built it, and a
  test that opened a pair without `create` had to build it by hand. Each fixture now holds a
  test's context as its field's default.
- The reinit test asked the predicate and started no lookup after the `reinit` calls that came
  back to DoQ and to DoH. It starts one after each, as above.
- The DoQ session's context and `cocuyo_doh`'s each had a row for the stream alone. TC25 to
  TC30 are the rows for the anchors, the wall clock and its instant of each.
- Twenty-seven older rows had not run again: the twenty-two of the picked walks, QO14 to QO16,
  RF5 and FR13. The whole set ran, as above.
- `has_context` is public before the owner has answered design §17 question 35. The question
  now says what goes if the answer is no: the method and what names it, with `start` and the
  tests asking `held` of `io/io_context.zig`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TC1 | an engine over DoT is taken as having its context when none was set | design §24, the context a session starts from, rule 2 | the DoT test, at its first expectation, and the init test, `test-io` | CAUGHT |
| TC2 | an engine over DoQ is taken as having its context when none was set | rule 2 | the DoQ test, at its first expectation, the reinit test and the init test, `test-io` | CAUGHT |
| TC3 | an engine over DoH is taken as having its context when none was set | rule 2 | the DoH test, at its first expectation, the reinit test and the init test, `test-io` | CAUGHT |
| TC4 | a configuration of plain DNS is asked for the TLS context | rule 2, plain DNS needs none | the plain test; forty-eight tests that start a lookup over plain DNS, by the assertion in `start`, `test-io` | CAUGHT |
| TC5 | the context of any transport counts for a DoT configuration | rule 2, one context is read | the DoT test, at its second expectation, `test-io` | CAUGHT |
| TC6 | the context of any transport counts for a DoQ configuration | rule 2, one context is read | the DoQ test, at its second expectation, and the reinit test, `test-io` | CAUGHT |
| TC7 | the context of any transport counts for a DoH configuration | rule 2, one context is read | the DoH test, at its second expectation, and the reinit test, `test-io` | CAUGHT |
| TC8 | `use_tls` sets no context | rule 1, a context is held once its call has run | the DoT test, at its third expectation, and the init test; the reinit test and the eight tests of `io_tls_test.zig` that start a lookup, by the assertion in `start`, `test-io` | CAUGHT |
| TC9 | `use_quic` sets no context | rule 1 | the DoQ test and the init test; the reinit test and twenty-nine tests of `io_request_test.zig`, `io_request_failure_test.zig` and `io_quic_test.zig`, by the assertion in `start`, `test-io` | CAUGHT |
| TC10 | `use_doh` sets no context | rule 1 | the DoH test and the init test; the reinit test and sixteen tests of `io_channel_test.zig` and `io_channel_link_test.zig`, by the assertion in `start`, `test-io` | CAUGHT |
| TC11 | `init` keeps the TLS context its memory held | rule 4, `init` leaves none | the init test, `test-io` | CAUGHT |
| TC12 | `init` keeps the QUIC context its memory held | rule 4 | the init test, `test-io` | CAUGHT |
| TC13 | `init` keeps the DoH context its memory held | rule 4 | the init test, `test-io` | CAUGHT |
| TC14 | `reinit` forgets the TLS context | rule 5, `reinit` keeps the contexts | the reinit test, `test-io` | CAUGHT |
| TC15 | `reinit` forgets the QUIC context | rule 5 | the reinit test, `test-io` | CAUGHT |
| TC16 | `reinit` forgets the DoH context | rule 5 | the reinit test, `test-io` | CAUGHT |
| TC17 | the DoT session's context leaves its stream undefined by default, as before the ruling | rule 6, no context type carries a default | the no-default test of `io_chapulin.zig`, `test-chapulin` | CAUGHT |
| TC18 | the DoT session's context has no anchors by default, as before the ruling | rule 6 | the no-default test of `io_chapulin.zig`, `test-chapulin` | CAUGHT |
| TC19 | the DoT session's context has a wall clock of zero by default, as before the ruling | rule 6 | the no-default test of `io_chapulin.zig`, `test-chapulin` | CAUGHT |
| TC20 | the DoT session's context pins its wall clock to instant zero by default, as before the ruling | rule 6 | the no-default test of `io_chapulin.zig`, `test-chapulin` | CAUGHT |
| TC21 | the DoQ session's context seeds its stream with zeros by default, as before the ruling | rule 6 | the no-default test of `io_chapulin_quic_test.zig`, `test-chapulin-quic` | CAUGHT |
| TC22 | a `cocuyo_quic` connection's context seeds its stream with zeros by default, as before the ruling | rule 6 | the no-default test of `io_quic.zig`, `test-cocuyo_quic` | CAUGHT |
| TC23 | a `cocuyo_quic` connection's context holds its session's defaults by default, as before the ruling | rule 6 | the no-default test of `io_quic.zig`, `test-cocuyo_quic` | CAUGHT |
| TC24 | `cocuyo_doh`'s context seeds its stream with zeros by default, as before the ruling | rule 6 | the no-default test of `io_doh_channel_start.zig`, `test-cocuyo_doh` | CAUGHT |
| TC25 | the DoQ session's context has no anchors by default, as before the ruling | rule 6 | the no-default test of `io_chapulin_quic_test.zig`, `test-chapulin-quic` | CAUGHT |
| TC26 | the DoQ session's context has a wall clock of zero by default, as before the ruling | rule 6 | the no-default test of `io_chapulin_quic_test.zig`, `test-chapulin-quic` | CAUGHT |
| TC27 | the DoQ session's context pins its wall clock to instant zero by default, as before the ruling | rule 6 | the no-default test of `io_chapulin_quic_test.zig`, `test-chapulin-quic` | CAUGHT |
| TC28 | `cocuyo_doh`'s context has no anchors by default, as before the ruling | rule 6 | the no-default test of `io_doh_channel_start.zig`, `test-cocuyo_doh` | CAUGHT |
| TC29 | `cocuyo_doh`'s context has a wall clock of zero by default, as before the ruling | rule 6 | the no-default test of `io_doh_channel_start.zig`, `test-cocuyo_doh` | CAUGHT |
| TC30 | `cocuyo_doh`'s context pins its wall clock to instant zero by default, as before the ruling | rule 6 | the no-default test of `io_doh_channel_start.zig`, `test-cocuyo_doh` | CAUGHT |

## A type on every integer constant

2026-10-13. The owner ruled on the cause of the faults of 2026-10-10 (Sums at the most their
operands reach): "Type header_bytes, tcp_prefix_bytes and the two fixed-size constants as usize,
so a sum with a narrow value widens instead of overflowing." This change extends the ruling to
every integer constant of the constants files of `src/` and `io/`. The extension is this
change's own reading of the ruling, and the owner can overrule it (design §16 decision 40, §17
question 36).

The design changed first: §5, §12, §16 decision 40, and §17 questions 36 and 37. No model
changed. No transition of §5 and no rule of §19 steps 13 and 14 reads the type of a constant.
`zig build spec-lean` and the replays of `zig build test` agree.

What the change does:

- Each integer constant of the ten constants files has the type of what it names. Of the 349,
  225 are a `usize`, 45 a `u16`, 36 a `u64`, 20 a `u8`, 13 a `u6`, 5 a `u4` and 5 a `u32`. A
  probe compiled before and after printed the same value for each, so no named limit changed.
- Four sites stopped compiling, and each was changed. Two shifts of a `u8` constant by
  `octet_bits`, in the comptime checks of `src/wire/constants.zig` and in the twin's
  `write_answer`, now shift a `u16`. `fill_quad` in `src/core/address_text.zig` narrows its
  sum with `@intCast`, under its check and a new assertion that the sum is at most
  `address_v6_groups`. The twin's `prefix_bytes` narrows its sum after the assertion that held
  it already.
- Thirteen sites now compute in a `usize`, and none changes a value at the named limits. Each
  combines a narrow value with one of the constants `tls_record_header_bytes`,
  `bits_per_octet`, `groups_per_quad`, `record_fixed_bytes`, `pointer_bytes`,
  `opt_option_fixed_bytes`, `cookie_client_bytes` and `fuzz_question_name_bytes_min`. The
  survey of the change compared the LLVM IR of 23 test units before and after to find them.
- The engine's comptime checks of its index shifts add in `comptime_int`, and subtract nothing.
  With `u6` shifts, the check of the receive's room subtracted in a `u6`. A shift past
  `kind_shift` then stopped the build with an overflow, and not with the check's message.
- `Resolver.loop_operations` has its type written, `u32`, as it was. The `usize` of
  `servers_max` in its sum would have made it a `usize`.
- The lint rule `typed-constants`, in `tools/lint/typed_constants.zig`, reads the syntax of
  each constants file of `src/` and `io/`. It reports a constant whose type is `comptime_int`,
  and a constant with no type whose value is integer-shaped. Design §16 decision 40 lists the
  shapes it reads and the shapes it does not read. It is cocuyo's own rule, and
  `tools/lint/main.zig` registers it after the eleven of pepegrillo. The canary tree holds a
  constants file with one such constant. Over the tree as it was before the change, the rule
  reports 332 constants: the 343 with no type, less the 11 aliases.
- A test in each of the ten constants files reads the types. It fails on a public constant
  that is a `comptime_int`, and it names the constant. So it catches an alias or a call that
  gives a `comptime_int`, which the lint rule cannot read. The tests of each module run it, and
  the count of each rose by one.

The locals of type `usize` that 1765131 wrote stay, with their comments. Six are now redundant,
since the constant of their sum is a `usize`: `start` in `src/wire/question.zig`, `length` in
`deliver` of `io/io_tcp.zig`, `name_bytes` in `src/resolver/fixtures.zig`, `message_len` in
`src/sim/sim_loop_perform.zig`, and `length` in `src/sim/sim_tls.zig` and in
`src/sim/sim_quic.zig`. Three are not. `alpn_len` and `body_len` in `io/io_quic_plain.zig` are
summed with a literal and with `frame_bytes`, a constant of that file with no type. `type_low`
in `src/resolver/lookup_case_test.zig` is summed with a literal.

So nine older rows stopped catching their fault: eight of the section of 2026-10-10, and CP14 of
Check 5 read in place. Each put back a sum with the constant, and the constant now widens the
sum. `zig build mutations` ran QO1 to QO3, QO8, QO9 and QO14 to QO16 against the typed tree,
before the rows changed. Each was `NOT CAUGHT`. QO12 and QO13 were `CAUGHT` in the same run:
the constant of their sums is in no constants file. The run of the whole lookup set found CP14
`NOT CAUGHT` the same way. CP15 and CP16 write the octet's type themselves, and stayed `CAUGHT`.
Each of the nine rows now also takes the type off its constant. That is `header_bytes` for QO1
to QO3, QO8 and CP14, `tcp_prefix_bytes` for QO9 and QO16, and the twin's
`tls_record_header_bytes` and `quic_item_header_bytes` for QO14 and QO15. The tests still catch
the fault when the type and the local are both gone. The lint catches the first half alone
(TY18), and so does the test of the constants file (TY27 to TY36). QO14 and QO15 take the type
off a constant of the twin's constants file, and their step, `test-sim`, runs the test of that
file. So each of the two rows also turns that test off, and the twin's overflow tests are then
what catches it. DT29's text changed, since the constant it edits has its type written now.

A type on a constant makes no sum narrower than it was. A sum of two types has the wider of the
two, and a `comptime_int` took the type of the runtime value.

The sums of two narrow runtime values that the survey of the change found, and how each is
held inside its type. The rule cannot see these: no constant is in them.

- `users` of a DoH channel's slot (`io/io_channel.zig`) and of a DoQ connection
  (`io/io_request_connection.zig`) sums two counts in a `u16`. They are the requests that wait
  and those on the channel or on a stream. A request is in one of the two at most, and the
  engine holds `lookups` of them. A new assertion in each says the sum is at most `lookups`,
  so it fits its type.
- The ring of results (`io/io_results.zig`) and the ring of a TCP connection
  (`io/io_tcp_queue_ring.zig`) each sum two positions in a `u16`: a head and a count, or a head
  and a position. Each is below the ring's capacity. An engine makes that capacity `lookups`,
  and two more for the TCP ring. New assertions say each operand is below the capacity, and
  the capacity is at most `lookup_slots_max`, or that and `tls_records_entries_max`. So the
  sum is at most 2046, or 2050. `init` holds `lookups` to `lookup_slots_max` already.
- The records a TLS connection seals, `io/io_tls.zig`. `take_out` subtracts the head of its
  buffer from the tail, and a new assertion says the head is not past the tail. It adds what
  the session made to the tail. A new assertion says the session made no more than the room it
  was given. So the sum is inside the buffer of `tls_records_out_bytes`. `pending` adds what
  was sent of the head entry to the head of the buffer. The assertion after it holds the sum
  below the entry's end, inside the same buffer.
- What a send moved, `io/io_tcp_queue.zig` and `io/io_channel_link.zig`, in a `u16`. Each is
  held by the assertion before it. A send moves no more than what is left. So the sum is at
  most the length of the head entry, or of what the channel made.
- The twin's delivery, `src/sim/sim_buffers.zig`: a prefix and a payload in a `u32`, in an
  assertion. A new assertion says the payload is at most `transfer_bytes_max`, 2^30, as the
  prefix is below it, so the sum fits.
- The twin's `prefix_bytes`, `src/sim/sim_types.zig`: two reserves of a caller's options, in a
  `u32`, with no bound before the sum. The typed constant at the head of the sum now makes it a
  `usize`, and the assertion under it holds the sum below `transfer_bytes_max`.
- The decimal octet of `parse_octet`, `src/core/address_text.zig`, in a `u16`: three digits at
  most, so 999 at most. A new case of the malformed-quad test parses `1.2.3.999`, the largest
  value the sum reaches, and the octet is refused. TY19 holds the sum in nine bits, which hold
  511 at most, and that case catches it.
- Two reach their limit in a test already, and nothing changed. The 255-octet tests hold a
  name at its limit. The test of `fe80::1` and `fe80::2` finds a common prefix of 64 bits.
- These are held by their own code, and nothing changed. The groups on the two sides of a
  `::` sum to 16 at most in a `u8`, since a side holds eight groups at most
  (`src/core/address_text.zig`). The test of `1:2:3:4:5:6:7::8` sums them to 8, where the
  address is refused. The kinds of a server, three flags of one bit each, sum to 3 at most
  (`src/core/config.zig`). The records an answer keeps are asserted at most `rdata_bytes_max`
  before each is kept (`src/wire/response_take.zig`). So an offset and a length sum to that at
  most (`src/wire/response_answers.zig`). The sealed ends and the sealed count are asserted
  before each subtraction (`io/io_tcp_queue_ring.zig`, `io/io_tcp_queue.zig`). So is the
  payload of a twin's buffer (`src/sim/sim_types.zig`). Two differences and a shift are in
  tests alone, in `src/cache/cache_ttl_test.zig` and `src/cache/cache_keys.zig`.
- Three sums meet a constant of a narrow type, the value of a protocol field, and each stays
  inside that type. The twin's server octet is 53 and an index asserted below `servers_max`
  (`src/sim/sim_network.zig`). A hexadecimal digit's value is 15 at most
  (`src/core/address_text.zig`). The test of the source-port hint subtracts
  `port_ephemeral_min` from a port asserted at or above it (`src/resolver/entropy.zig`).
- Four shifts by a constant drop high bits with no check, and the width of each operand holds
  it. The plain QUIC session shifts a packet number of four octets at most into a `u32`.
  `src/core/address_text.zig` shifts a quad's octet and a group's digit into a `u16`.
  `src/resolver/lookup_response.zig` shifts the extended RCODE, twelve bits, into a `u16`.

Taking an assertion away changes nothing a test can see, as with Z10 and T11, so the new
assertions have no rows. Each ran under the gate's tests, which pass.

Two checks have no row in a set. The engine's comptime checks of its index shifts stop the
build. The tool reads a compile error of this tree's own as a mutation whose text no longer
applies. Each was shown by hand, by a probe that compiled `io/constants.zig` with one shift
changed:

- `receive_generation_shift` of 9 stops the build with "a receive's user_data has no room for a
  thirty-two-bit generation", and so does 41. With the subtraction in a `u6`, 41 stopped it with
  "overflow of integer type 'u6' with value '-1'".
- `quic_incarnation_shift` of 9 stops the build with "a QUIC connection's user_data has no room
  for a thirty-two-bit incarnation", and so does 40. With the sum in a `u6`, 40 stopped it with
  "overflow of integer type 'u6' with value '72'".

The runs, after the last edit to the code, each after running its checks once with nothing
mutated:

- The first run of the whole lookup set, before the review, ran 268 rows. 266 were `CAUGHT`.
  CP14 was `NOT CAUGHT`, as above, before its row took the type off `header_bytes`. CZ28 "did
  not compile": its step failed, but the output quoted a line of the test's source, which
  holds a message in the compiler's form, and the tool read that line as the compiler's. The
  same row on the tree before this change, at 07faffc, did not compile either.
- `zig build mutations -- lookup` then ran the whole set again, after the review's changes:
  281 rows, each `CAUGHT`. CP14, CZ28 and the thirty-one TY rows of the set are among them.
  So the tool's reading of CZ28 is not stable, though its step fails each time. The table of
  2026-10-11 records it `CAUGHT`.
- `zig build mutations -- engine` ran the whole set, 170 rows, before the review, over the full
  run TLC wrote on 2026-10-11, since the model has not changed. Each was `CAUGHT`: 94 by a
  build step, QO8, QO9 and QO14 to QO16 among them, 54 by the short walks and 22 by the
  picked walks. The full run first catches those 22 at the thirteen walks the committed picks
  hold, so no walk is picked anew.
- `zig build mutations -- engine` then ran the rows that the review's changes touched, over the
  same full run: QO8, QO9 and QO16, whose constant is in `src/core/constants.zig`, QO14 and
  QO15, which turn off the twin's test now, and TY32 to TY36. Each
  of the ten was `CAUGHT` by its build step.

Thirty-six new mutations, thirty-six `CAUGHT`. Ten older rows changed, the nine above and DT29,
and each is `CAUGHT`. The review's changes to the rule moved the text that TY7, TY10 and TY15
edit, so each of the three edits the new text.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TY1 | the rule takes an integer literal for no integer | design §16 decision 40, a literal has no type | the literal and container fixtures, `test-tools` | CAUGHT |
| TY2 | the rule takes a character literal for no integer | a character is an integer | the literal fixture, `test-tools` | CAUGHT |
| TY3 | the rule reads no negation | a negated literal has no type | the literal fixture, `test-tools` | CAUGHT |
| TY4 | the rule reads nothing inside parentheses | a grouped literal has no type | the literal fixture, `test-tools` | CAUGHT |
| TY5 | the rule reads no arithmetic, bitwise or shift operator | a sum of constants has no type | the literal fixture, `test-tools` | CAUGHT |
| TY6 | the rule reads no wrapping or saturating operator | a sum of constants has no type | the literal fixture, `test-tools` | CAUGHT |
| TY7 | the rule reads no builtin | `@bitSizeOf` gives a `comptime_int` | the literal fixture, `test-tools` | CAUGHT |
| TY8 | the rule reads no `maxInt` | `maxInt` gives a `comptime_int` | the literal fixture, `test-tools` | CAUGHT |
| TY9 | the rule reads no `if` | an `if` of literals has no type | the literal fixture, `test-tools` | CAUGHT |
| TY10 | the rule reports a constant whose type is written | a typed constant passes | the passing fixture, `test-tools` | CAUGHT |
| TY11 | the rule takes an alias for an integer | an alias has the type of what it names | the passing fixture, `test-tools` | CAUGHT |
| TY12 | the rule reads the constants of a function and of a block | the rule reads a container's members | the container fixture, `test-tools` | CAUGHT |
| TY13 | the rule reads no member of a container inside the file | the rule reads a container's members | the container fixture, `test-tools` | CAUGHT |
| TY14 | the rule's scope leaves `io/` out | the engine's constants carry a type | the scope test and the container fixture, `test-tools` | CAUGHT |
| TY15 | the rule reads every Zig file, and not the constants files alone | the rule reads the constants files | the scope test, `test-tools` | CAUGHT |
| TY16 | the rule is not registered | every rule checks the build | the registered-rules test, `test-tools` | CAUGHT |
| TY17 | the canary holds no integer constant with no type | the canary shows the rule is live | the canary run, `lint` | CAUGHT |
| TY18 | the header's length loses its type | the ruling of 2026-10-13 | the tree run, `lint` | CAUGHT |
| TY19 | the decimal octet is summed in nine bits, which hold 511 at most | the octet's sum fits its type | the malformed-quad test's case of `1.2.3.999`, `test-core` | CAUGHT |
| TY20 | the rule takes a written `comptime_int` for a type | a `comptime_int` is no type | the fixture of a switch, a block and `@abs`, `test-tools` | CAUGHT |
| TY21 | the rule reads the value of `@as`, and not its type | `@as(comptime_int, ...)` has no type | the fixture of a switch, a block and `@abs`, `test-tools` | CAUGHT |
| TY22 | the rule reads no `@abs` | `@abs` gives a `comptime_int` | the fixture of a switch, a block and `@abs`, `test-tools` | CAUGHT |
| TY23 | the rule reads no `switch` | a `switch` of literals has no type | the fixture of a switch, a block and `@abs`, `test-tools` | CAUGHT |
| TY24 | the rule reads no labeled block | a block that breaks with a sum has no type | the fixture of a switch, a block and `@abs`, `test-tools` | CAUGHT |
| TY25 | the rule reads no piece split from a constants file | the rule reads `constants_<piece>.zig` | the test of the split pieces, `test-tools` | CAUGHT |
| TY26 | the rule reads no file under a directory named `constants` | the rule reads `constants/<piece>.zig` | the test of the split pieces, `test-tools` | CAUGHT |
| TY27 | the header's length is a call that gives a `comptime_int`, which the lint rule does not read | the test reads the type | the test of `src/core/constants.zig`, `test-core` | CAUGHT |
| TY28 | the codec's pointer length loses its type | the test of the codec's constants | the test of `src/wire/constants.zig`, `test-wire` | CAUGHT |
| TY29 | the state machine's transactions for a server lose their type | the test of the state machine's constants | the test of `src/resolver/constants.zig`, `test-resolver` | CAUGHT |
| TY30 | the parser's line bound loses its type | the test of the parser's constants | the test of `src/config/constants.zig`, `test-config` | CAUGHT |
| TY31 | the cache's slot bound loses its type | the test of the cache's constants | the test of `src/cache/constants.zig`, `test-cache` | CAUGHT |
| TY32 | the twin's operation bound loses its type | the test of the twin's constants | the test of `src/sim/constants.zig`, `test-sim` | CAUGHT |
| TY33 | the engine's default lookups lose their type | the test of the engine's constants | the test of `io/constants.zig`, `test-io` | CAUGHT |
| TY34 | the length of a QUIC connection ID loses its type | the test of `cocuyo_quic`'s constants | the test of `io/io_quic_constants.zig`, `test-cocuyo_quic` | CAUGHT |
| TY35 | the bound of a DoH request loses its type | the test of `doh`'s constants | the test of `io/io_doh_constants.zig`, `test-doh` | CAUGHT |
| TY36 | the length of a TLS record's header loses its type, in the DoH channel | the test of `cocuyo_doh`'s constants | the test of `io/io_doh_channel_constants.zig`, `test-cocuyo_doh` | CAUGHT |

## What a survey of the named limits found

2026-10-13. A survey read each limit of the ten constants files, the check that uses it, and the
body of each test that touches it. It found five faults, four in the engine's streams and one in
the codec. It also found two smaller faults of form. Each fault was shown on the twin before this
change. The design changed first:

- §7 and §8, the length of a name;
- §12, the limits;
- §16 decision 41;
- §17 questions 37 and 38;
- §19 step 13, the stream's rule 11;
- §21, TLS rules 5 and 7;
- §24, the limits of `cocuyo_doh`.

No model changed. The engine model holds no frame and counts no octets. It applies a message at
the receive that brings it, so the code now does what the model does.

The faults:

- A TLS connection's record buffer held one record at its longest, 16,645 octets, and no more.
  `take` in `io/io_tls.zig` added a chunk to the partial record. It failed the connection when
  the sum passed the buffer, before it handed a whole record to the session. So a sound
  connection failed when a chunk ended a full AES-GCM record and held 240 octets or more of the
  next. Since 21918bf, of 2026-09-24, in v0.2.0 to v0.6.0.
- A connection's frame had the same fault in `take_chunk` of `io/io_tcp.zig`. A chunk that ended
  a message of L octets and held h octets of the next failed the connection when L + h passed
  `tcp_message_bytes`. Since 886a4e8, of 2026-09-22, in v0.1.0 to v0.6.0.
- The session opens a record into the frame after the partial message. The frame had no room for
  a record after a partial message at its longest. So over DoT a full AES-GCM record found no room
  after a partial message of more than 49,136 octets, and colibri refused it. Since 21918bf.
- `deliver` and `take` stopped after 32 messages or records, `tcp_messages_per_chunk_max` and
  `tls_records_per_chunk_max`. The rest waited for the next chunk. When none came, a lookup whose
  answer was among them waited until its deadline, and failed over. Since 886a4e8 and 21918bf.
- `wire.name.skip` counted labels and not octets. It took a name of up to 128 labels, 8,193
  octets, where RFC 1035 §2.3.4 allows 255. The record walk skips the owners it does not decode.
  So such a name passed unread in three places:
  - the owner of a record of a type the lookup does not want;
  - the owner of a record before the OPT record;
  - the names of an SOA, from which a negative answer takes its TTL.

  Since 23fd425, of 2026-09-21, in v0.1.0 to v0.6.0.

The two smaller faults: `cocuyo_doh` copied four sizes of the engine's and of `cocuyo_quic`'s,
with only a comment to tie them. And `ndots_limit` and `timeout_seconds_limit` were in the
parser's file, and not in a constants file (CLAUDE.md non-negotiable 5).

What the change does:

- Each buffer holds its longest item and what one take adds after a partial item.
  `tls_record_in_bytes` gains a chunk, 2,048 octets. The frame gains `tcp_frame_room_bytes`,
  2,048 octets, in the clear, and `tls_frame_room_bytes`, 16,640, over TLS. A comptime check in
  `io/constants.zig` ties each size to the limits it comes from.
- `take_chunk` and `take` take each chunk whole. Then the loop hands every whole item to the
  table or to the session, and moves the rest once. Each loop's bound is the most whole items its
  buffer holds: `tcp_messages_per_frame_max`, 41,088, and `tls_records_per_buffer_max`, 3,738. An
  assertion after each loop holds that no whole item is left. The check that refused a chunk is
  an assertion now. The checks are on what a server writes: the prefix and the record's header.
- A prefix that says more than `tcp_message_bytes` fails the connection when it arrives. In the
  clear the connection closes at once. Over TLS the session says `close_notify` first, and the
  connection closes once the alert has gone (TLS rule 5). Before, the frame filled until a chunk
  did not fit, or until the session refused a record.
- A record the session refuses puts the connection in its `closing` state. The rest of its chunk
  leaves the buffer unread. Before, the rest stayed in the buffer until the next chunk.
- The stream's messages moved from `io/io_tcp.zig` to `io/io_tcp_frame.zig` by the file-length
  rule. Their tests moved from `io/io_tcp_test.zig` to `io/io_tcp_frame_test.zig`.
- `skip` refuses a name whose labels, with a root after them, pass `name_bytes_max`. The error is
  `decode`'s, `NameTooLong`. `record.Iterator.next` and `Record.soa_negative_ttl` change with it.
  An assertion at the top of the loop holds that the labels leave room for a root.
- A test of `cocuyo_doh` holds each copied size to the size it copies. The build binds
  `cocuyo_quic` into the module's tests for it.
- `ndots_limit` and `timeout_seconds_limit` are in `src/config/constants.zig`, each with a type.
  The comptime check of the timeout moved with them.

The tests came first. At e4db956 with the new tests, `zig build test-io` had 9 of 135 tests fail.
`test-wire` had 2 of 181 fail, and `test-cocuyo_doh` 1 of 21, on the size of the stream. One test
came with the fix, for a path the fix opened: a prefix in a record that says more than the
connection assembles. At e4db956 the twin's session refused that record for want of room in the
frame. This was read from the code, and not run. The connection then closed through TLS rule 4,
after the session's alert.

A review of the change found four more points, and the change now meets each:

- Over TLS, a prefix that said too much closed the connection at once, with no `close_notify`.
  The peer is still there, and RFC 9846 §6.1 asks for the alert. The test of that path now asks
  for it, and `quit` in `io/io_tls.zig` stages it. Before `quit`, `zig build test-io` had 1 of 136
  tests fail. With `quit`, SB15 went uncaught: `take` reads on past a `closing` connection in any
  case. So the test has a second pass, where the loop refuses the alert's send. The connection
  then closes at once, and SB15 reads past the end of its emptied buffer.
- No test split a prefix between two chunks. A new test does. SB25 and SB26 break the two checks
  that wait for both octets of a prefix.
- No row broke the size of `cocuyo_doh`'s stream alone. SB24 does.
- The test of a frame over TLS of empty messages tests `deliver`. So it moved to
  `io/io_tcp_frame_test.zig`.

With the fix, `zig build test` has 1,000 tests pass of 1,000.

`zig build mutations` ran the twenty-eight rows below, each against its step, and each was
`CAUGHT`. It ran QO9 and QO10 again too, since their text moved: QO9 to `io/io_tcp_frame.zig`,
and QO10 to the frame's new size. It also ran ET14 to ET18 again. Their text did not change, but
`refuse` now also ends a connection that quits, and `take` reads on past a refused record. Each
older row was `CAUGHT`. The tests that catch each row were read from a run of each row by hand, in
a copy of the tree. Fourteen rows are caught by a panic, at least in part. The panic is an
assertion of this change, or a slice past its end in SB15, SB25 and SB26. SB19 and SB20 are also
caught by the codec's fuzz gate, through the assertion at the top of the skip's loop.

Twenty-eight new mutations, twenty-eight `CAUGHT`. Seven older rows ran again, QO9, QO10 and ET14
to ET18, and each is `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| SB1 | a TLS connection's record buffer holds one record at its longest, and no chunk past it | §21, TLS rule 7 | the back-to-back records test and the refused-record test, each by a panic, `test-io` | CAUGHT |
| SB2 | a frame in the clear holds the longest message and its prefix, and no chunk past them | §19 step 13, the stream's rule 11 | the one-chunk test, by a panic, and the whole-frame test, `test-io` | CAUGHT |
| SB3 | a frame over TLS holds a chunk past its partial message, and not a record's body | the stream's rule 11 | the test of a record after a partial message at its longest, by a panic, and the test of a frame over TLS of empty messages, `test-io` | CAUGHT |
| SB4 | a prefix that says more than the connection assembles is waited for, and does not fail it | the stream's rule 11 | the long-answer, tiny-frame and split-prefix tests, each by a panic, and the test of a long prefix over TLS, `test-io` | CAUGHT |
| SB5 | a prefix that says exactly `tcp_message_bytes` fails the connection | the stream's rule 11 | the one-chunk, tiny-frame, whole-frame, 65534-prefix and record-prefix tests, and the test of a record after a partial message at its longest, `test-io` | CAUGHT |
| SB6 | the partial message after the whole ones stays where it is, and does not move to the frame's head | the stream's rule 11 | the one-chunk test, and three tests of `io_tcp_test.zig` with two answers on a stream, `test-io` | CAUGHT |
| SB7 | the loop over the frame stops after 32 messages | the stream's rule 11 | the test of every whole message in a chunk, the whole-frame test and the test of a frame over TLS of empty messages, each by a panic, `test-io` | CAUGHT |
| SB8 | the loop over the frame stops after 32 messages, and nothing asserts that no whole message is left | the stream's rule 11 | the same three tests, `test-io` | CAUGHT |
| SB9 | the loop over the frame stops one message short of the most a frame holds | `tcp_messages_per_frame_max` | the test of a frame over TLS of empty messages, by a panic, `test-io` | CAUGHT |
| SB10 | the loop over the record buffer stops after 32 records | §21, TLS rule 7 | the test of every whole record in a chunk and the test of a buffer of empty records, each by a panic, `test-io` | CAUGHT |
| SB11 | the loop over the record buffer stops after 32 records, and nothing asserts that no whole record is left | TLS rule 7 | the same two tests, `test-io` | CAUGHT |
| SB12 | the loop over the record buffer stops one record short of the most the buffer holds | `tls_records_per_buffer_max` | the test of a buffer of empty records, by a panic, `test-io` | CAUGHT |
| SB13 | the partial record after the whole ones stays where it is, and does not move to the buffer's head | TLS rule 7 | the back-to-back records test and the test of flights before the handshake's end, `test-io` | CAUGHT |
| SB14 | a record the session refuses ends the loop, and the rest of its chunk stays in the buffer | TLS rules 4, 5 and 7 | the refused-record test, by a panic at the next chunk, `test-io` | CAUGHT |
| SB15 | a record whose message fails the connection is taken as heard, and the loop reads on | the stream's rule 11 over TLS | the test of a long prefix over TLS, in its pass where the loop refuses the alert's send, by a slice past its end, `test-io` | CAUGHT |
| SB16 | `cocuyo_doh`'s copy of the engine's chunk is not the engine's chunk | §24, New limits | the test of the copied sizes, `test-cocuyo_doh` | CAUGHT |
| SB17 | `cocuyo_doh`'s copy of the engine's datagram buffer is not the engine's buffer | §24, New limits | the test of the copied sizes, `test-cocuyo_doh` | CAUGHT |
| SB18 | `cocuyo_doh`'s copy of `cocuyo_quic`'s receive pool is not `cocuyo_quic`'s | §24, New limits | the test of the copied sizes, `test-cocuyo_doh` | CAUGHT |
| SB19 | the record walk's skip counts labels and not octets | RFC 1035 §2.3.4, §3.1 | the two skip tests and the fuzz gate, each by a panic, `test-wire` | CAUGHT |
| SB20 | the record walk's skip counts no root after the labels | RFC 1035 §3.1 | the two skip tests and the fuzz gate, each by a panic, `test-wire` | CAUGHT |
| SB21 | the record walk's skip refuses a name of 255 octets | RFC 1035 §2.3.4 | the two skip tests, `test-wire` | CAUGHT |
| SB22 | `ndots:` is clamped at the cap of `timeout:` | `resolv.conf(5)` | the clamp test, `test-config` | CAUGHT |
| SB23 | the cap of `ndots:` loses its type in the constants file | §16 decision 40 | the type test of `src/config/constants.zig`, `test-config` | CAUGHT |
| SB24 | `cocuyo_doh`'s stream holds a record at its longest, and no chunk past it | §24, New limits | the test of the copied sizes, `test-cocuyo_doh` | CAUGHT |
| SB25 | the check of a prefix's length reads it before both its octets have come | the stream's rule 11 | the split-prefix test, and the whole-frame test and the test of a frame over TLS of empty messages, each by a slice past its end, `test-io` | CAUGHT |
| SB26 | the length of a whole message is read from a prefix before both its octets have come | the stream's rule 11 | the whole-frame test and the test of a frame over TLS of empty messages, each by a slice past its end, `test-io` | CAUGHT |
| SB27 | a prefix too long over TLS closes the connection at once, its `close_notify` unsaid | §21, TLS rule 5; RFC 9846 §6.1 | the test of a long prefix over TLS, `test-io` | CAUGHT |
| SB28 | a connection that quits stages no `close_notify`, and closes at once | TLS rule 5; RFC 9846 §6.1 | the test of a long prefix over TLS, `test-io` | CAUGHT |

## Tests at the named limits

2026-10-13. A survey of that day listed each named limit that no test reached at its value. The
survey is not in the repository, so this section names each limit in words. This change adds a
test at each limit on that list. Each test is at the limit, and one past it when one past exists.
Each test is in the file that holds the check. The tests of an engine check are in the test file
of its part, as before. No check changed, and no limit changed. The codec's fuzz target has two
more strategies, and a check of the OPT record.

This change read each claim of the survey again against 356eeb7, which fixed the faults of the
section above:

- The survey named `tcp_messages_per_chunk_max` and `tls_records_per_chunk_max`. 356eeb7 removed
  both. `tcp_messages_per_frame_max` and `tls_records_per_buffer_max` replace them, and the tests
  of SB9 and SB12 reach those.
- The back-to-back records test of 356eeb7 takes a whole record of 16,640 octets, the most that
  `tls_record_body_bytes_max` allows. It fills the record buffer too (SB1).
- `labels_max` in `skip` is out of reach. Since 356eeb7, `skip` counts octets. A name of 128 labels
  and a root has more than 255 octets, so the octet check refuses it first. The skip tests of
  356eeb7 reach the octet bound (SB19 to SB21).
- `doh_stream_bytes` changed in 356eeb7, to a record at its longest and one chunk. The new test
  fills that size.
- A test reaches `hosts_names_bytes_max` already, as the survey says.
- One octet past `tls_records_out_bytes` fails each server, and not the first server alone, as the
  survey says. The session asks for its room each time that a connection opens, and the buffer
  has less room than that for each server.

Left out:

- A table at `lookup_slots_max`. The bench test holds it, as the survey says.
- A cache at `slots_max`. Its slots take 49 MB.
- An answer of 65,535 octets through colibri, and a QUIC datagram of 1,500 octets. Their cost is
  moderate, and their value is low.
- `sweep_steps_max`. The survey gives it for information only.

One past does not exist for these limits:

- `name_text_bytes_max`: no name gives more than 1,004 octets of text, 16 under the bound.
- `pointer_offset_mask`: fourteen bits name no offset past 16,383.
- A TTL of 0xFFFFFFFF, `Slot.generation` and the engine's counters: each value fills its type. A
  TTL of 0xFFFFFFFF is the largest, and each counter's test is at its wrap.
- `spki_pins_max` over QUIC: five pins are not a valid configuration, and the QUIC session asserts
  that. Over TCP the session gives the pins to chapulin, and chapulin refuses five.
- `values_bytes` of `cocuyo_doh`: one past is colibri's check. The test of 283 octets reached it
  before, and the new test of 257 octets reaches it too.
- `tls_records_entries_max`: one past is a third entry of records. The join rule prevents it, and
  LM53 breaks that rule.
- The twin's `sockets_max`, `datagrams_pending_max` and `connections_max`: one past each array is
  not a slot.
- `drive_polls_per_lookup_max`: no run gives one lookup more than 49 polls in one drive, as the
  next part shows.

### The wrap of the engine's counters

The wrap tests of the TCP connection, the QUIC connection, the channel link and the timer start
each counter at 0xFFFFFFFE. So a real connection, link or timer runs at 0xFFFFFFFF, and the next
one wraps the counter to zero. Before, each test started at 0xFFFFFFFF. The first connection
wrapped the counter before any event carried it, and the test made the event at 0xFFFFFFFF itself.

The test of the receive's generation now requires its second lookup to end before its deadline,
with no failure against the server. Before, a receive that did not find its socket lost the
answer. The lookup then asked again, and the test passed all the same.

So LM38 is caught on the path of each event now. The receive test fails, and the TCP, QUIC and
link tests stop at the assertion in `user_data`. The timer's index has no bits above the
thirty-two of its generation, so LM38 cannot reach it.

### The drive's bound

`drive_polls_per_lookup_max` is 81: two polls for each server and pass, and one more. A new test
in `io_sim_servers_test.zig` finds the most polls that one drive gives one lookup. Eight
servers each have a connection that is up, and the loop refuses each send:

- The first try at a server costs two polls: one for the connection, and one for the send.
- The refused send fails the connection.
- Each later try at that server costs one poll, because no slot is free for a new connection.

So the drive gives the lookup 8 × 2 + 8 × 4 + 1 = 49 polls, and the lookup ends in that drive. A
bound of 48 leaves the lookup on the ready list, and the test fails (LM67). With a bound of 49 or
more, every test passes. A drive with output added by hand printed 49 polls of 81 for this case.
That 49 is the most comes from a read of the drive, and not from a measurement of each case. So
32 polls of the bound are slack. Whether to lower it to 49 is a question for the owner, because it
changes a named limit (CLAUDE.md, Ask before; docs/design.md §17 question 39).

### A datagram at the room of a buffer

The engine's datagram group has buffers of `buffer_bytes`, 2,048 octets. After rotor's prefix of
192 octets, a datagram has 1,856. The twin carries 1,232 octets at most, so two new tests write
the completion of a receive themselves. They write it into a buffer of the group, as the kernel
does (`io_sim_datagram_test.zig`):

- A datagram of 1,856 octets is read whole, and answers its lookup. A group of buffers of 1,536
  octets fails this test (LM68).
- A datagram of 1,857 octets keeps 1,856, and the kernel marks it as truncated. The engine reads no
  such mark. It gives the cut octets to the table, as the datagram's rule 3 says: "whatever its
  length". The cut OPT record fails check 6, so the lookup ignores the message and waits.

The second test holds what the engine does today. A question for the owner: must the engine drop
a cut datagram, or take it as truncated and ask again over TCP? The query advertises a payload of
1,232 octets. RFC 6891 §6.2.3 calls that "the largest UDP payload" that the requestor can take. A
server that sends more gets its answer cut, and today its lookup waits out its try.

### The DoH request's bound

The test at `doh_request_bytes_max` now writes the longest GET:

- Its path is 1,536 octets, with a `dns` value of 512 octets.
- Its authority is a name of 253 octets and a port.
- Its query has 384 octets, which base64url writes in 512 (RFC 4648 §5).

colibri sends the GET over HTTP/2, and the server answers it. This change did not try HTTP/3 at
that length.

The comment of the constant and §24 give the bound to the HEADERS frame of the GET. That frame has
317 octets of colibri's fields, 259 for the authority and 960 for the path. The code gives the
bound to the path alone: `fits`, and the path buffer of an exchange. So the check takes a path of
1,536 octets, where the comment allows 960. The test holds what the code does. The owner decides
whether the comment or the check is correct.

### The codec's fuzz target

The target moved to `src/wire/fuzz/`, because it has four files now (CLAUDE.md, Layout). The text
target is in `src/config/fuzz/` already. CLAUDE.md still names `src/wire/fuzz.zig` under Commands,
and only the owner edits CLAUDE.md.

The generator has two more strategies, ten in all, and the 4,096 seeds of the gate spread over
them:

- `lengths_at_most` writes a response whose one record holds a length field at its most:
  - an rdlength, an EDNS option's length or an SVCB parameter's length of 0xFFFF or 0xFFFE, which
    runs past what holds it;
  - a TXT string, a CAA tag or an alpn-id of 255 octets, or a name of labels of 63 octets, in a
    record that is whole or has one octet changed;
  - a COOKIE option of 8, 16, 40 or 41 octets, the last option of its OPT record. Its data ends at
    the end of the rdata, and a Padding option comes before it half the time.
- `long_message` writes a message of up to 65,535 octets, the longest half the time. A copy of the
  question's name is at offset 16,383 in the rdata of the first answer. That offset is the
  farthest that a pointer names. The last answer ends the message, and its owner is a pointer to
  that name.

The check reads the OPT record's options as a lookup reads them. Each option's data must be inside
the rdata, and a COOKIE must have a length that RFC 7873 §4 allows. The COOKIE options of the
lengths strategy make the gate run both of these checks. Before, the gate read no option whole, and
it read no COOKIE. The gate now catches LM65, a COOKIE of 41 octets read as the long form.

A test of `fuzz.zig` pins what the readers meet in the seeds of the gate. Each value must reach the
reader that shares it, and must give what a lookup gets from it:

| Field | Value | What its reader does | Messages |
| --- | --- | --- | --- |
| rdlength | 0xFFFF, 0xFFFE | the record walk refuses it | 24, 25 |
| an option's length | 0xFFFF, 0xFFFE | `response_opt.find` finds the OPT, and the option walk and `find_cookie` refuse it | 30, 28 |
| an SVCB parameter's length | 0xFFFF, 0xFFFE | after the copy, the parameter walk refuses it | 26, 31 |
| a TXT string | 255 | `Txt.strings` reads it whole | 32 |
| a CAA tag | 255 | `Caa.parse` reads it whole | 25 |
| an alpn-id | 255 | the parameter walk reads and checks it | 18 |
| a label | 63 | the name decoder reads it | 19 |
| a COOKIE | 8, 16, 40, 41 | `find_cookie` gives a server cookie of 0, 8 or 32 octets, and refuses 41 | 11, 15, 14, 18 |

The test requires each sixteen-bit length to be refused in each message. It counts a one-octet
field only in a record written whole, and requires its reader to read it in each one. The table
gives those counts. A record with one octet changed can read or not, so the test does not count
it. The test reads what each reader returns, and not only what the generator wrote. So a value
that no reader finds fails it (LM63). Another test pins that the seeds reach a message of 65,535
octets, 193 times. The walk reads its last answer through the pointer to offset 16,383.

`strategy_of` gives the strategy of a seed, from the first word of its stream. A test that reads
one strategy skips the other seeds with it, and so builds no long message that it does not read.
A test pins that `strategy_of` agrees with `generate` (LM66). `zig build fuzz -- --seed` prints the
field at its most and its offset now.

A message is 64 KiB now. `generate` sets the first 1,232 octets of it to zero for each seed, and
not all of it. The long strategy draws its noise eight octets to a word of the stream. These are
the times on an Apple M1 Pro with macOS 26.6.2, before (356eeb7) and after. The host had a load
average of about 45. So the table also gives the instructions retired, which `/usr/bin/time -l`
reports, and which the load does not change.

| Command | Before | After |
| --- | --- | --- |
| `zig build fuzz-gate -- 4096`, median of 11 runs | 251 ms | 257 ms |
| the gate's program, 4,096 seeds, median of 11 runs | 25 ms, 95 M instructions | 37 ms, 131 M instructions |
| the gate's program, 65,536 seeds, median of 11 runs | 427 ms, 1.24 G instructions | 800 ms, 1.86 G instructions |
| `zig build fuzz-gate -- --text 4096`, median of 11 runs | 242 ms | 240 ms |
| the `test-wire` program in Debug, median of 7 runs | 213 ms, 2.28 G instructions | 199 ms, 2.11 G instructions |

The gate stays within twice its earlier time, so the long strategy stays in. The `test-wire`
program takes less than before, because its pins skip the seeds of the other strategies.

The gate catches seven rows of this section on its own: LM3, LM4, LM5, LM20, LM21, LM26 and LM65.
Each ran in a copy of the tree, with the gate as the one test compiled. The gate failed under each,
by a panic for the first five. Under the generator of 356eeb7, it failed under LM3 alone of the
first five. The rows of earlier sections that name the gate still fail it alone: QO1, QO2, QO23,
CP8, CP14, CP15, CP17, SB19 and SB20.

### What the tests found

One probable fault, which this change does not fix. `doh.template.expand` in
`io/io_doh_template.zig` keeps the first octet of its output for a slash. A template whose path
starts with a slash gets 1,535 octets of the 1,536 of the path buffer. So `start` refuses such a
template when its GET path at its longest has exactly 1,536 octets. §24 refuses only a GET longer
than `doh_request_bytes_max`. The test that shows it is not in the tree. It starts a channel on the
path `/`, 1,018 octets of `p`, then `{?dns}`. The test at the limit in the tree uses a path that
starts with `?`.

docs/design.md §17 asks the owner questions 39 to 45. Six come from this change: the slack of
`drive_polls_per_lookup_max`, a datagram longer than the room of a buffer, the bound of a DoH
request, the slash above, `cocuyo.wire.fuzz` in the public API and the path in CLAUDE.md. The
seventh comes from the survey: `Options.lookups` over `lookup_slots_max` compiles, then stops at
an assertion in `init`. This change does not touch it.

### The rows

`zig build mutations` ran the 68 rows below, each against its step. The Test column names the tests
that catch each row. A run by hand of each row, in the tree or in a copy of it, found them. A test
at a limit catches a row that moves the bound by one. It also catches a row that sums a length in a
narrower type, the fault of "Sums at the most their operands reach". Some rows are caught by older
tests too, and the table names those.

Sixty-eight new mutations, sixty-eight `CAUGHT`.

| # | Limit | Test | Mutation | Status |
| --- | --- | --- | --- | --- |
| LM1 | `message_bytes_max`, 65,535, at check 1 of §7 | the test of messages of 65,535 and 65,536 octets in `lookup_response.zig`, by a panic in the name codec, `test-resolver` | check 1 is gone | CAUGHT |
| LM2 | the same, at the limit | the same test, `test-resolver` | check 1 ignores a message of 65,535 octets | CAUGHT |
| LM3 | an rdlength of 0xFFFF and 0xFFFE | the rdlength test of `record.zig` and the fuzz gate, each by a panic, `test-wire` | the record walk sums the rdata's offset and the rdlength in sixteen bits | CAUGHT |
| LM4 | an EDNS option's length of 0xFFFF and 0xFFFE | the option-length test of `rdata_opt.zig`, the COOKIE test of `edns.zig` and the fuzz gate, each by a panic, `test-wire` | an option's offset and its length are summed in sixteen bits | CAUGHT |
| LM5 | an SVCB parameter's length of 0xFFFF and 0xFFFE | the parameter-length test of `rdata_svcb.zig` and the fuzz gate, each by a panic, `test-wire` | a parameter's offset and its length are summed in sixteen bits | CAUGHT |
| LM6 | `name_text_bytes_max`, 1,020, and the longest text, 1,004 | the longest-text test of `name_text.zig`, by a panic, `test-core` | the text buffer is 1,003 octets, and the comptime check that pins it is gone | CAUGHT |
| LM7 | `hosts_lines_max`, 4,096 | the test of the line at the bound in `hosts.zig`, `test-config` | the hosts file is read one line past its bound | CAUGHT |
| LM8 | the same | the same test, `test-config` | the hosts file is read one line short of its bound | CAUGHT |
| LM9 | `options_max`, 16 | the test of the option at the bound in `resolv_conf.zig`, by a panic, `test-config` | an options line is read one token past its bound | CAUGHT |
| LM10 | the same | the same test, `test-config` | an options line is read one token short of its bound | CAUGHT |
| LM11 | `lines_max`, 256 | the test of the line at the bound in `resolv_conf.zig`, `test-config` | `resolv.conf` is read one line short of its bound | CAUGHT |
| LM12 | the same | the same test and the older test of 267 lines, each by a panic, `test-config` | `resolv.conf` is read one line past its bound | CAUGHT |
| LM13 | `ptr_names_max`, 1 | the PTR test of `response_take.zig`, by a panic, `test-wire` | a PTR answer keeps a name past the one its list holds | CAUGHT |
| LM14 | `rdata_bytes_max`, 2,048, filled | the test of records that fill the rdata buffer in `response_take.zig`, `test-wire` | a copy that fills the buffer to its last octet is refused | CAUGHT |
| LM15 | a TTL of 0xFFFFFFFF through the cache | the largest-TTL test of `cache_ttl_test.zig` and four older tests of that file, each by a panic, `test-cache` | the cache keeps a TTL over its cap | CAUGHT |
| LM16 | `Slot.generation` at 0xFFFF | the wrap test of `table_slots.zig`, by a panic, `test-resolver` | a slot's generation does not wrap at the release | CAUGHT |
| LM17 | `cookie_option_long_bytes_min`, 16 | the test of a server cookie of 8 octets in `edns.zig`, `test-wire` | a COOKIE option of 16 octets is refused | CAUGHT |
| LM18 | the same, under a lookup | the test of a server cookie of 8 octets in `lookup_cookie_test.zig`, `test-resolver` | a COOKIE option of 16 octets is refused | CAUGHT |
| LM19 | `pointer_offset_mask`, a pointer to 16,383 | the farthest-pointer test of `name.zig` and the long-message test of `fuzz.zig`, `test-wire` | a pointer keeps thirteen bits of its offset | CAUGHT |
| LM20 | `character_string_bytes_max`, 255 | the 255-octet string test of `rdata_string.zig` and the fuzz gate, each by a panic, `test-wire` | a string's length and its own octet are summed in the octet the length reads as | CAUGHT |
| LM21 | a CAA tag of 255 octets | the 255-octet tag test of `rdata_caa.zig` and the fuzz gate, each by a panic, `test-wire` | a tag's length and the octets before it are summed in the octet the length reads as | CAUGHT |
| LM22 | `port_ephemeral_max`, 65,535, in the lookup | the test of the range's ends in `entropy.zig`, `test-resolver` | the lookup's port span leaves out its last port | CAUGHT |
| LM23 | `address_v4_octet_digits_max`, 3 | the test of octets of four and five digits in `address_text.zig`, by a panic, `test-core` | an octet of a dotted quad is summed whatever its digits | CAUGHT |
| LM24 | each length field at its most | the test of what the readers meet in `fuzz.zig`, `test-wire` | the lengths strategy writes no length field at its most | CAUGHT |
| LM25 | 0xFFFE of a sixteen-bit length | the same test, `test-wire` | a sixteen-bit length is written at 0xFFFF or 0xFFFD, and never at 0xFFFE | CAUGHT |
| LM26 | a label of 63 octets | the same test and the fuzz gate, `test-wire` | a label of the lengths strategy says 62 octets | CAUGHT |
| LM27 | a message of 65,535 octets | the long-message test of `fuzz.zig`, `test-wire` | a long message is one octet short of the longest, at most | CAUGHT |
| LM28 | a pointer to offset 16,383 in a long message | the same test, `test-wire` | the last answer of a long message is owned by a pointer to offset 16,382 | CAUGHT |
| LM29 | `tls_records_out_bytes`, 4,096 | the test of sessions that ask for all of the records buffer, and for more, in `io_tls_failing_test.zig`, `test-io` | the records buffer refuses a session that asks for all of it | CAUGHT |
| LM30 | the same | the same test, `test-io` | the records buffer takes a session that asks for more than it holds | CAUGHT |
| LM31 | `port_ephemeral_max`, 65,535, in the engine | the test of the range's ends in `io_udp.zig`, `test-io` | the engine's port span leaves out its last port | CAUGHT |
| LM32 | a TCP connection's incarnation at its wrap | the incarnation test of `io_tcp_test.zig`, by a panic, `test-io` | the incarnation does not wrap | CAUGHT |
| LM33 | a receive's generation at its wrap | the test of the generation and the epoch in `io_lifecycle_test.zig`, by a panic, `test-io` | the generation does not wrap | CAUGHT |
| LM34 | a socket's epoch at its wrap | the same test, by a panic, `test-io` | the epoch does not wrap | CAUGHT |
| LM35 | a QUIC connection's incarnation at its wrap | the incarnation test of `io_request_test.zig`, by a panic, `test-io` | the incarnation does not wrap | CAUGHT |
| LM36 | a channel link's incarnation at its wrap | the incarnation test of `io_channel_link_test.zig`, by a panic, `test-io` | the incarnation does not wrap | CAUGHT |
| LM37 | the timer's generation at its wrap | the test of a replaced timer in `io_sim_test.zig`, by a panic, `test-io` | the generation does not wrap | CAUGHT |
| LM38 | `index_mask`: the largest counter above the last slot | the wrap tests of `io_lifecycle_test.zig`, `io_tcp_test.zig`, `io_request_test.zig` and `io_channel_link_test.zig`, the last three by a panic, `test-io` | the index of a `user_data` loses its top bit | CAUGHT |
| LM39 | `spki_pins_max`, 4, through chapulin | the four-pin test of `io_chapulin.zig`, `test-chapulin` | the pins a configuration may name pass chapulin's bound | CAUGHT |
| LM40 | the same, over QUIC | the four-pin test of `io_chapulin_quic_test.zig`, `test-chapulin-quic` | the pins a configuration may name pass chapulin's bound | CAUGHT |
| LM41 | `quic_connection_events_max`, 16 | the test of a flood of tickets in `io_request_test.zig`, `test-io` | one read of a connection takes one event more than its bound | CAUGHT |
| LM42 | the same | the same test, `test-io` | one read of a connection takes one event fewer than its bound | CAUGHT |
| LM43 | `channel_events_max`, 16 | the test of a flood of tickets in `io_channel_test.zig`, `test-io` | one read of a channel takes one event more than its bound | CAUGHT |
| LM44 | the same | the same test, `test-io` | one read of a channel takes one event fewer than its bound | CAUGHT |
| LM45 | `status_success_last`, 299 | the test of statuses 299 and 300 in `io_doh_channel_test.zig`, `test-cocuyo_doh` | a status of 299 is no answer | CAUGHT |
| LM46 | the same | the same test, `test-cocuyo_doh` | a status of 300 is an answer | CAUGHT |
| LM47 | `values_bytes`, 256 | the test of values that fill the buffer in `io_doh_channel_test.zig`, `test-cocuyo_doh` | the values buffer of an exchange is one octet short | CAUGHT |
| LM48 | `datagram_bytes`, 2,048 | the test of a datagram and stream octets that fill what the type keeps, in `io_doh_channel_test.zig`, `test-cocuyo_doh` | a datagram that fills what the channel keeps is dropped | CAUGHT |
| LM49 | `stream_bytes`, a record and a chunk | the same test, `test-cocuyo_doh` | stream octets that fill what the channel keeps overrun it | CAUGHT |
| LM50 | `doh_request_bytes_max`, 1,536 | the test of a template that fills the path buffer, and its longest GET, in `io_doh_channel_test.zig`, `test-cocuyo_doh` | the start check expands a template into one octet less than the buffer | CAUGHT |
| LM51 | the same | the same test, `test-cocuyo_doh` | the start check expands a template into one octet more than the buffer | CAUGHT |
| LM52 | `tls_records_entries_max`, 2 | the queue test of `io_tls_failing_test.zig`, by a panic, `test-io` | a connection's queue holds one entry fewer than a query for each lookup and two of records | CAUGHT |
| LM53 | the same | the same test, by a panic, `test-io` | records made behind an entry of records that has not started do not join it | CAUGHT |
| LM54 | `servers_max`, 8, in the engine | the test of eight servers over UDP in `io_sim_servers_test.zig`, `test-io` | the server index of a receive keeps two bits | CAUGHT |
| LM55 | `sockets_max`, 64, of the twin | the socket test of `sim_network.zig`, `test-sim` | the twin opens one socket fewer than its bound | CAUGHT |
| LM56 | `datagrams_pending_max`, 256, of the twin | the datagram test of `sim_network.zig`, `test-sim` | the twin holds one datagram fewer than its bound | CAUGHT |
| LM57 | `connections_max`, 16, of the twin | the test of connections and QUIC peers in `sim_network.zig`, `test-sim` | the twin opens one connection fewer than its bound | CAUGHT |
| LM58 | the same, for QUIC peers | the same test, `test-sim` | the twin opens one QUIC peer fewer than its bound | CAUGHT |
| LM59 | `stream_bytes_max`, 16,384, of the twin | the stream test of `sim_network.zig`, `test-sim` | a stream of the twin refuses octets that fill it | CAUGHT |
| LM60 | `servers_max`, 8, in the engine | the tests of eight servers over UDP and over TCP in `io_sim_servers_test.zig`, each by a panic, `test-io` | the engine keeps a UDP socket for seven servers | CAUGHT |
| LM61 | the same, over TLS | the test of eight servers over TLS in `io_sim_servers_test.zig`, by a panic, `test-io` | the engine keeps a TLS ticket for seven servers | CAUGHT |
| LM62 | a CAA tag that ends at the last octet of the rdata | the 255-octet tag test and the older test of a flag, a tag and a value in `rdata_caa.zig`, `test-wire` | a tag that ends at the last octet of the rdata is refused | CAUGHT |
| LM63 | the readers of the lengths strategy | the test of what the readers meet in `fuzz.zig`, `test-wire` | the header of the lengths strategy counts no OPT record | CAUGHT |
| LM64 | a COOKIE one octet past the longest, in the fuzz target | the same test, `test-wire` | a COOKIE of 41 octets is never written | CAUGHT |
| LM65 | `cookie_option_long_bytes_max`, 40 | the COOKIE test of `edns.zig`, the fuzz gate, and the test of what the readers meet in `fuzz.zig`, `test-wire` | a COOKIE option of 41 octets is read as the long form | CAUGHT |
| LM66 | the strategy of a seed | the test of `strategy_of` in `fuzz_generate.zig`, the test of each type in `fuzz_generate_records.zig`, by a panic, and four tests of `fuzz.zig` that read one strategy, `test-wire` | `strategy_of` draws from the seed after the one that `generate` reads | CAUGHT |
| LM67 | `drive_polls_per_lookup_max`, 81, at the most a run reaches, 49 | the test of one drive through each try at eight servers in `io_sim_servers_test.zig`, `test-io` | one drive polls a lookup 48 times at most | CAUGHT |
| LM68 | `buffer_bytes`, 2,048, of the datagram group | the test of a datagram that fills a buffer of the group in `io_sim_datagram_test.zig`, `test-io` | the buffers of the datagram group are 1,536 octets | CAUGHT |

## The skip follows each pointer

2026-10-14. `wire.name.skip` ended a name at its first pointer, and did not follow the pointer
(c4milo/cocuyo#46). From 356eeb7 it refused a name whose labels before the pointer passed 255
octets. A name of short labels and a pointer to a long name passed it, but the whole name passed
255 octets. A pointer forward, a pointer loop and a pointer past the end of the message passed it
too. `decode` refuses each of these names. The record walk skips each owner that it does not
decode, so such an owner passed each walk that decodes nothing at that place. The owner ruled on
2026-10-14: close the issue. The design changed first:

- §7, Parsing;
- §8, Name decoding and Record walking;
- §11, the notes on the record walk;
- §13, the fuzz target;
- §16 decision 42.

No model changed. The Lean models and the engine model hold no octets of a message.

What the change does:

- `skip` and `decode` share one walk in `src/wire/name.zig`. `decode` gives the walk a `Name`,
  which copies each label. `skip` gives it a `Measure`, which counts the octets of each label and
  copies nothing. A `Measure` refuses a label where `Name.append_label` refuses it. That is where
  the label, its length octet and a root after them pass 255 octets (RFC 1035 §2.3.4, §3.1).
- So `skip` follows each pointer (§4.1.4), and `compression_hops_max` bounds its hops, as in
  `decode`. It still returns the octet after the first pointer.
- `copy_label` is now `label_at`. It returns the octets of a label, and the walk gives them to a
  `Name` or a `Measure`. A `Measure` copies nothing, so the old name was not true for `skip`.
- The fuzz target compares `skip` with `decode` at each offset where it aims both: the same end,
  or the same error. Before, it compared them only where `decode` took the name. It also decodes
  each owner that the record walk passes.
- The long-question strategy writes the first answer's owner as labels and a pointer to the
  question's name, 255 octets whole or 256. Before, no strategy wrote such a name on purpose. Over
  the gate's 4096 seeds, noise held 2,415 names longer than 255 octets that the old `skip` took.
  The record walk passed none of them as an owner. A test pins that the gate's seeds reach an
  owner of each length.

The change also found an error in §8 and in the comment at the top of `src/wire/name.zig`. Both
said that the strictly-backwards rule alone makes a loop impossible. A pointer can point back at
labels that lead to the same pointer, and each hop of that loop points backwards. The hop bound
ends such a loop at the seventeenth pointer. The length of the name ends it first when its labels
are long. A test holds each of the two cases. The rule did not change.

The tests came first. At 05567b7 with the new tests, `zig build test-wire` had 14 of 208 tests
fail:

- eight tests of `src/wire/name.zig`:
  - a name through its pointer, and a name through every hop;
  - a pointer at itself, a pointer forward, and a pointer past the end of the message;
  - a loop that the hop bound ends, and a loop that the length ends;
  - a chain longer than the hop bound, which now runs `skip` too.
- four tests of the walks that skip an owner. Each holds an owner of labels and a pointer, 255
  octets whole and 256. They are `Record.soa_negative_ttl` in `record.zig`, `response.collect` and
  `response.negative_ttl_seconds` in `response.zig`, and `response_opt.find` in
  `response_opt.zig`. At 05567b7 each took the owner of 256 octets.
- the fuzz gate, at seed 0, where `skip` and `decode` disagreed on a name;
- the test of the long question's owner in `fuzz.zig`, which `skip` took at 256 octets.

Each of those failures came from a run, and each test shows its own failure. One new test passed
at 05567b7: the test of a pointer whose second octet is past the end. The old `skip` had a check
of its own for that octet. So that test is a guard of the check that `read_pointer` now makes for
both walks. With the change, `zig build test` has 1,062 tests pass of 1,062. `zig build fuzz-gate
-- 4096` and `zig build fuzz-gate`, 1,048,576 seeds, each held.

`zig build mutations -- lookup` ran W5, NS1 to NS6 and SB19 to SB21, each against `test-wire`,
and each was `CAUGHT`. Each row also ran by hand, in a copy of the tree with a cache of its own.
Those runs name the tests that catch each row. A panic stops the test binary. So for a row that
panics, the table names the first test that the panic stops.

- W5 held the old contract, that `skip` ends at a pointer. It is written again to break the new
  contract the way the old code did: `skip` reads the pointer's two octets, ends the name, and
  returns. The 14 tests that failed at 05567b7 catch it, and no other test.
- SB19 to SB21 broke the length check of the old `skip`. That check is now the check of
  `Measure`, so their text moved there. Each still breaks the one check that it broke before.
  SB19 and SB20 are caught by a panic of the assertion after the check. SB21 is caught with no
  panic, by eleven tests. One of them is the test of a response that echoes a name of 255 octets,
  since its owner is a pointer to that name.
- NS3 removes the strictly-backwards rule. The tests of a pointer at itself and of the loops do
  not catch it. The hop bound then refuses each of them with the same error. The tests of a pointer
  forward catch it, in `decode` and in `skip`. The test of a pointer past the end catches it too.
  The walk then goes to an offset past the end, and fails with `MalformedMessage`.
- NS4 is the row of the pointer's second octet past the end of the message. Before, `skip` had a
  check of its own for it. Now `read_pointer` makes the check for both walks.
- NS6 removes the bound of `label_at`, which W4 of Step 2 broke as the bound of `copy_label`. No
  row of `lookup.zon` held that bound until now. The walk then reads past the end of the message,
  and the slice of the label panics.

Seven new or rewritten rows, seven `CAUGHT`. The text of NS1 changed with `label_at`, and the row
was run again. Three older rows ran again with their text moved, SB19 to SB21, and each is
`CAUGHT`.

`zig build mutations -- lookup` then ran the whole set, 326 rows, after the last edit to the code.
Each of the 326 was `CAUGHT`, CZ28 too. On 2026-10-13, and in the first whole run of this change,
the tool said that CZ28 "did not compile". The cache of the tree was cleared before this run, to
keep space on the disk. The change does not touch `tools/readme_check.zig`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| W5 | `skip` ends at a pointer and does not follow it, as before 2026-10-14 | §16 decision 42 | the 14 tests that failed at 05567b7, `test-wire` | CAUGHT |
| NS1 | `skip` follows each pointer, and counts no label after the first hop | RFC 1035 §3.1, §4.1.4 | the tests of a name through its pointer, of every hop and of the loop through a label of 63; the tests of the SOA's MNAME, of `collect`, of the negative TTL and of `find`; the fuzz gate and the test of the long question's owner, `test-wire` | CAUGHT |
| NS2 | the walk of `decode` and `skip` allows a seventeenth hop | `compression_hops_max` | the test of a chain longer than the hop bound, by a panic, `test-wire` | CAUGHT |
| NS3 | a pointer may point at itself, forwards, or past the end of the message | strictly backwards, RFC 1035 §4.1.4 | the forwards-pointer test of `decode`, and the tests of `skip` with a pointer forward and a pointer past the end, `test-wire` | CAUGHT |
| NS4 | a pointer whose second octet is past the end of the message is read | `read_pointer`'s bound | the truncated-pointer test of `decode`, by a panic, `test-wire` | CAUGHT |
| NS5 | a name ends after its last pointer, and not after its first | the end of a name, RFC 1035 §4.1.4 | the test of as many pointers as the hop bound allows, the test of every hop and the fuzz gate, `test-wire` | CAUGHT |
| NS6 | a label may run past the end of the message, in the walk of `decode` and `skip` | `label_at`'s bound | the test of a label past the end of the message, by a panic, `test-wire` | CAUGHT |

## The owner's answers of 2026-10-14

2026-10-14. The owner answered questions 39 to 44 of docs/design.md §17, which the section "Tests
at the named limits" asked. §17 records each answer in the form of the other answers:

- 39: `drive_polls_per_lookup_max` stays at 81, with its slack. No change.
- 40: a datagram that the buffer cut moves its lookup to TCP once checks 1 to 5 of §7 pass. This
  changes behaviour, and §16 decision 43 records it. Since the review below, check 6 runs too, on
  a message with no COOKIE option.
- 41: the bound of a DoH request is on the path, 1,536 octets, as the code had it. The comment of
  `doh_request_bytes_max` and §24 changed, and the code did not.
- 42: a template's path that starts with a slash now gets the whole buffer.
- 43: an engine of more lookups than `lookup_slots_max` does not compile.
- 44: `cocuyo.wire.fuzz` stays public. No change.

Question 45 is still open. CLAUDE.md still names `src/wire/fuzz.zig`, and only the owner edits it.
The review of the change asked questions 46 and 47 (The review, below).

### A datagram that the buffer cut

The design changed first:

- §4: `Lookup.on_datagram_cut` and `Resolver.on_datagram_cut`, the public API that the rule needs.
- §5: a row of the table, and the cut datagram's exception to the rule that an accepted response
  takes a sample.
- §7: the section "A datagram that the buffer cut", and the last rule of Parsing.
- §16: decision 43, and an amendment to decision 10.
- §17: questions 46 and 47.
- §19 step 13: the datagram's rule 6, rule 3's pointer to it, and "Checked on 2026-10-14".

Then the models. The Lean model of `Lookup` holds the rule already. Its TC=1 moves a lookup that
waits over UDP to `tcpNeeded` on the same server, and records no failure. A cut datagram that
passes the checks of a cut datagram is that reply, and each other cut datagram is its unmatched
reply. No transition changed, and the comment of TC=1 now says so. The replay checks it
(spec/README.md, The replay).

The engine model held no truncated UDP answer: spec/README.md said "every query over UDP with no
answer truncated". A message's replies were an answer, NXDOMAIN, SERVFAIL and an unmatched
message. Rule 6 is a new rule of §19 step 13, so the model changed before the code. `Truncates`
gives a datagram two replies more, TC set and a cut datagram, and each sends its lookup to TCP. TC
set counts as the server's success, as in the code, and a cut datagram counts nothing. Three
configurations set it:

- `Engine_truncated_1_1_bound_4_1`: TLC finds that each check holds in its 426,197 states.
  spec/README.md says what the configuration reaches.
- `trace/Trace_udp_truncated_1_1`: the replay's walks of the rule.
- `mutants/OA34`: a draining socket kept open while its lookup waits on a stream.

`Truncates` is an operator that is false, so each other configuration reaches what it reached
before. TLC ran the configurations and the mutants that CI runs on each push, after the review's
changes:

- Each configuration holds, with the states that spec/README.md gives it:
  - the channel: 1,672,552;
  - requests: 22,688, 217,540 and 2,897,539;
  - TCP: 18,625, 561,813 and 2,438,035;
  - TLS: 252,573;
  - UDP: 25,385 and 70,400;
  - truncated: 426,197.
- Each of the 33 mutants is violated, as its header expects.

The configurations that CI checks once a day did not run. They set no `Truncates` either.

Then the code, each change with its failing test first:

- The 1,857-octet test of `io/io_sim_datagram_test.zig` held the old behaviour: the lookup ignored
  the cut datagram and waited. Now it requires the new rule. The cut answer comes from the server
  that the query went to, and that server answers over TCP from then on. Run before the code, the
  test failed at its first new check: "expected .connecting_tcp, found .awaiting_udp". With the
  code, the lookup asks over TCP, and its answer comes on a connection to that server.
- A new test of the same file hands the same cut answer from the other server. Check 3 refuses it,
  and the lookup waits, as before. It passed before the code too, so it guards rule 2 of the new
  section of §7.
- `src/resolver/lookup_response_cut.zig` holds the cut path and its tests: each check of 1 to 6,
  the server's state left as it was, and the states and the configurations that ignore a cut
  datagram. `table.zig` has a test of `Resolver.on_datagram_cut`.

The two entry points of the table share one loop, `offer_datagram`, which takes the lookup's
function at compile time. So `on_datagram` gives the same machine code as before.

### The review of 2026-10-14

A review read the change before its commit. It found three things to fix and twelve to consider.
Each change below came with its failing test first, where it changed what the code does.

Check 6 was not on the cut path. RFC 7873 §5.3 says that a response without the COOKIE option
that the client expects "MUST be discarded". A lookup that expected a cookie took a cut datagram
with none, and ignored an answer with TC set and no OPT record. So a forger who matched the id,
the port and the question could move that lookup with a cut datagram alone. The fix runs check 6
on the cut path, on a message with no COOKIE option: the cut took the OPT record. Two new tests of
`lookup_response_cut.zig` failed before it, each with "expected .ignored, found .accepted":

- a lookup whose query carried the server's cookie;
- a lookup whose fresh cookie went out before the server gave a cookie.

No replay reached rule 6. The engine model held the rule, but no walk had `Truncates` set, and
the lookup replay handed no cut datagram to the code. Now both replays do:

- `tools/spec_replay/replay_cut.zig` hands a cut datagram to the lookup at each `reply_truncated`
  line where the lookup waits over UDP, and at each `reply_unmatched` line elsewhere. The lookup
  must answer and move as the line's reply does. `zig build spec-lean` checks 354,997 cut
  datagrams that way over the whole transcript, and the gate checks 605 over the slice.
  No line of either transcript changed.
- The engine replay has a reply `cut`: the answer, grown by a Padding option to one octet past the
  room, cut to the room, with the kernel's mark. `trace/Trace_udp_truncated_1_1` is the
  replay's `Trace_udp_1_1` with `Truncates` set. Its name sorts last, so its walks come last, and
  no pick moves. TLC wrote the walks of the other twelve configurations as before, octet for octet.
  The short walks gained ten walks, and the full run 2,000, 5,226,000 events in all. The engine
  agrees with the model on each.
- The short walks catch OA28, the engine that reads no mark, in walk 123. They miss OA29 and OA33.
  The full run catches both first in walk 24001, the first walk of the new configuration, so it is
  the fourteenth pick of `build/spec.zig`.

The public API changed without the owner's word on its shape: `Lookup.on_datagram_cut` and
`Resolver.on_datagram_cut`. The answer to question 40 ruled on the behaviour. No change here can
give the owner's word, so §17 question 46 asks for it, and the commit waits for the answer.

What the review asked to consider, and what changed:

- §7 and decision 10 said that an attacker cannot race the retry. That is false in three cases:
  an engine of no TCP connection, one whose connection slots are all in use, and a server that
  refuses TCP. In each, the lookup asks the next server over UDP. §7, decision 10 and Parsing now say so,
  and say that a forged TC answer did the same before. A new twin test shows the engine of no TCP
  connection.
- A cut datagram whose question is itself cut had no test. A new test hands each length from the
  header to the question's end less one, and requires each to be ignored. The question's end is
  taken. OA27 breaks the check of the length, and the test catches it by the assertion after it.
- Check 1's upper bound on the cut path had no test. A new test hands 65,536 octets, which check 1
  refuses, and 65,535, which it takes. OA26 keeps the parse and drops the bound.
- The twin reached two cases of rule 6. Three new tests of `io_sim_datagram_test.zig` reach three
  more: an engine of no TCP connection, a draining socket and `ignore_truncation`. The 1,857-octet
  test now also hands a copy of the cut datagram once the lookup is on its way to a stream, which
  the lookup ignores.
- No TLA mutant showed that the new configuration can catch a broken rule. OA34 keeps a draining
  socket open while its lookup waits on a stream. TLC finds the check "rotated" broken within
  1,000 distinct states. Without `Truncates` the same mutant holds in 70,400 states.
- `examples/udp_rotor.zig` handed each datagram to `on_response`. It now reads rotor's mark, and
  hands a cut datagram to `on_datagram_cut`. `examples/udp_blocking.zig` does the same with the
  `trunc` flag of `std.Io`. No test runs the examples, so no row breaks them.
- The cut path quoted RFC 1035 §4.2.1 mid-sentence. It now cites RFC 7766 §5 alone, as the
  permission to ask over TCP, and says that no RFC states the rule.
- Decision 43 did not weigh RFC 6891 §6.2.3. It now does, and §17 question 47 asks the owner
  whether the engine refuses a `Config.udp_payload_bytes` above its room.
- §24's request rule 3 said that a DoH request slot holds a HEADERS frame. It holds the message,
  and the exchange holds the path. The rule and "The GET" now say so.
- The test of a slash path only started the channel. It now sends the longest GET on that path,
  and requires colibri's server to answer it.
- Some new sentences ran past 25 words, and a line of spec/README.md past 100 columns. They are
  shorter now.
- `takes_cut` and `matches` held no assertion. Each now asserts what the state of the lookup must
  be, and `matches` asserts the header's length after check 1. With them, OA6 is caught by a crash
  where the DoH test once failed an expectation.

### What CI's instruction check will do

`bench/count.zig` was built for x86-64 Linux at the baseline CPU, ReleaseSafe, at 1008e9a and with
the change, after the review. That is the program that CI counts under cachegrind. The disassembly
of the two programs is the same, instruction for instruction and immediate for immediate, once
the addresses are left out. No case of `bench/count.zig` reaches the cut path, the engine or the
DoH template. So CI's instruction check will likely find each of the fourteen counts of
`bench/instructions.zon`, and pass. Nobody counted them under cachegrind.

### The DoH template's slash

The tests came first:

- `io/io_doh_template.zig`: a path that starts with a slash expands into a buffer of its own
  length. A path that starts with `?` needs one octet more, for the slash before it. Before the
  fix, `/q?dns=X` did not fit in eight octets.
- `io/io_doh_channel_test.zig`: a channel starts on the path of question 42: `/`, 1,018 octets of
  `p`, then `{?dns}`. With a `dns` value of 512 octets that path has 1,536 octets. Before the fix,
  `start` returned `error.Failed` at its check of the path. Since the review the test also sends
  the longest GET on that path, and colibri's server answers it. One octet more is still refused.

The fix gives the expansion the whole buffer. The first octet that `Out.put` writes decides: when
it is `?`, a slash goes before it. Each other expansion keeps the buffer for itself.

### The bound of a DoH request

The comment of `doh_request_bytes_max` and §24 now give the bound to the path alone. No code
changed, so no row is new. LM50 and LM51 still break the check of the path, and the test at the
limit catches each. The new test of question 42 catches each too.

### `Options.lookups`

`io.Resolver` checks `Options.lookups` when it compiles. An engine of 1 to `lookup_slots_max`
lookups compiles. An engine of any other count stops with an error that names the bound. The tool
reads a compile error of this tree's own as a mutation whose text no longer applies. So the check
has no row, as the comptime checks of the index shifts have none. It was shown by hand, in a copy
of the tree with a cache of its own. Each probe ran `zig build test-io` with a `comptime` block
that sizes an engine:

- 1,025 lookups: `error: an engine holds 1 to 1024 lookups, lookup_slots_max, and these Options
  name 1025`.
- 0 lookups: the same error, which names 0. `Resolver.init` asserted both bounds before, when the
  engine ran.
- 1,024 lookups: it compiles, and the 153 tests pass.
- 1,025 lookups with the check taken out: it compiles, and the 153 tests pass. The engine stops
  at the assertion of `init` when it runs, as question 43 said.

### What ran

With the change, `zig build test` has 1,084 tests pass of 1,084. The change adds these tests:
nine in `lookup_response_cut.zig`, four in `io_sim_datagram_test.zig`, two in `replay_cut.zig`,
and one each in `table.zig`, `io_doh_template.zig` and `io_doh_channel_test.zig`. The replay's
tests run under two roots, so the gate counts those of `replay_cut.zig` twice. `zig build lint`
passes, with each function at a complexity of 15 or less. `zig build spec-lean` passes: 2,680,563
events and 354,997 cut datagrams agree with the model, and 66,565 events of the walks. Steps that
the gate does not run were run too:

- `zig build examples` builds its four programs.
- `zig build test-cares` has 37 tests pass of 37.
- `zig build spec-engine` has TLC write the short walks and the full run again, finds the
  committed walks the same, and replays 5,226,000 events over 26,000 walks.
- `zig build tla` holds the eleven configurations that CI checks on each push, and finds each of
  the 33 mutants violated.

### The rows

Each row ran by hand, in a copy of the tree with a cache of its own, against the check that it
names. Those runs name the tests that catch each row. Then `zig build mutations -- engine` ran the
35 rows of the section, OA1 to OA36 but OA34, after it ran each of their checks once with
nothing mutated. `--walks` named the full run that TLC wrote for this change, so TLC did not write
it again. The run found each row `CAUGHT`, and left the tree as it was:

- OA28 in walk 123 of the short walks.
- OA29 and OA33 in walk 24001 of the full run, and in walk 14 of the picked walks, which is that
  walk.
- OA32 in the lookup's replay and in walk 123 of the short walks, both under `test-tools`.
- Each other row in the step that it names.

OA34 is a mutant of the model, which `zig build tla` checks. OA15's edit follows the cut path's
check 5, which the review moved to an `if`. The cache of the tree and old caches of the scratch
directory were cleared before the run, to keep 20 GB free on the disk.

Thirty-six mutations, thirty-six `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| OA1 | the engine reads no mark, and hands a cut datagram over as whole | the datagram's rule 6 | three tests of `io_sim_datagram_test.zig`: a datagram one octet longer than the room, a draining socket and an engine of no TCP connection, `test-io` | CAUGHT |
| OA2 | the engine hands each datagram over as cut | the datagram's rule 6 | fourteen tests of `test-io`, seven by a crash: among them a datagram that fills a buffer in `io_sim_datagram_test.zig`, a name of 255 octets in `io_sim_test.zig`, a refused connection in `io_tcp_test.zig`, and a port that cannot be replaced in `io_lifecycle_test.zig` | CAUGHT |
| OA3 | a lookup reads a cut datagram as a whole message | `Lookup.on_datagram_cut` | the test of a cut answer that passes the checks of a cut datagram in `lookup_response_cut.zig`, and the cut test of `table.zig`, `test-resolver` | CAUGHT |
| OA4 | the table hands a cut datagram to its lookups as a whole message | `Resolver.on_datagram_cut` | the cut test of `table.zig`, `test-resolver` | CAUGHT |
| OA5 | a lookup reads a cut datagram in each state | rule 1 of §7, A datagram that the buffer cut | the test of `ignore_truncation`, a stream and an end in `lookup_response_cut.zig`, by a crash, `test-resolver` | CAUGHT |
| OA6 | a lookup over DoH or DoQ reads a cut datagram | rule 1 | the DoH test of `lookup_response_cut.zig`, by a crash, `test-resolver` | CAUGHT |
| OA7 | a lookup under `ignore_truncation` reads a cut datagram | rule 1 | the test of `ignore_truncation`, a stream and an end, `test-resolver` | CAUGHT |
| OA8 | check 1 is gone from the cut path | check 1 of §7 | the test of checks 1, 2 and 3 in `lookup_response_cut.zig`, by a panic, `test-resolver` | CAUGHT |
| OA9 | check 2 is gone from the cut path | check 2 | the same test, `test-resolver` | CAUGHT |
| OA10 | check 3 of the cut path compares the port alone | check 3, RFC 5452 §4.4, §4.5 | the same test, `test-resolver` | CAUGHT |
| OA11 | check 3 of the cut path compares the address alone | check 3, RFC 5452 §4.5 | the same test, `test-resolver` | CAUGHT |
| OA12 | check 4 of the cut path takes a query | check 4 | the test of checks 4 and 5 in `lookup_response_cut.zig`, `test-resolver` | CAUGHT |
| OA13 | check 4 of the cut path takes any opcode | check 4 | the same test, `test-resolver` | CAUGHT |
| OA14 | check 5 of the cut path takes any count of questions | check 5 | the same test, `test-resolver` | CAUGHT |
| OA15 | check 5 of the cut path takes any question | check 5, RFC 5452 §9.1 | the same test, `test-resolver` | CAUGHT |
| OA16 | a cut datagram is a latency sample of its server | rule 5 | the test of a cut answer that passes the checks of a cut datagram, `test-resolver` | CAUGHT |
| OA17 | a cut datagram counts as its server's success | rule 5 | the same test, `test-resolver` | CAUGHT |
| OA18 | a cut datagram with no cookie starts its server's silence | rule 5 | the same test, `test-resolver` | CAUGHT |
| OA19 | a cut datagram moves its lookup to the next server | rule 4, RFC 7766 §5 | the same test, and the cut test of `table.zig`, `test-resolver` | CAUGHT |
| OA20 | a template's expansion has one octet less than the buffer, whatever its first octet | §24, the path; §17 question 42 | the two tests at `doh_request_bytes_max` in `io_doh_channel_test.zig`, `test-cocuyo_doh` | CAUGHT |
| OA21 | the same, against the template's own tests | the same | the test of a path that starts with a slash in `io_doh_template.zig`, `test-doh` | CAUGHT |
| OA22 | no slash goes before a path that starts with `?` | RFC 9114 §4.3.1 | the test of each operator and the test of a path that starts with a slash in `io_doh_template.zig`, `test-doh` | CAUGHT |
| OA23 | a slash goes before each path, one that starts with a slash too | RFC 9114 §4.3.1 | five tests of `io_doh_template.zig`: RFC 8484's example, each operator, the literals, the refused templates and a path that starts with a slash, `test-doh` | CAUGHT |
| OA24 | check 6 is gone from the cut path | check 6, RFC 7873 §5.3 | the two cookie tests of `lookup_response_cut.zig`, `test-resolver` | CAUGHT |
| OA25 | check 6 of the cut path expects a cookie only when the query carried the pair | check 6, RFC 7873 §5.3 | the test of a fresh cookie whose server gave one since, `test-resolver` | CAUGHT |
| OA26 | check 1 of the cut path takes a message longer than a message can be | check 1 | the test of 65,535 and 65,536 octets in `lookup_response_cut.zig`, `test-resolver` | CAUGHT |
| OA27 | check 5 compares a question that the message does not hold whole | check 5's length, in `src/wire/question.zig` | the test of a cut datagram that ends inside its question, by the assertion after the check, `test-resolver` | CAUGHT |
| OA28 | the engine reads no mark, against the short walks | the datagram's rule 6 | the short walks, walk 123 | CAUGHT |
| OA29 | a cut datagram counts as its server's success, against the walks | rule 5 | the picked walks, walk 24001 of the full run | CAUGHT |
| OA30 | a lookup reads a cut datagram in each state, against the lookup's replay | rule 1 | the replay of the committed slice, and the test of `replay_cut.zig` that holds a stream, each by a crash, `test-tools` | CAUGHT |
| OA31 | a lookup over DoH or DoQ reads a cut datagram, against the lookup's replay | rule 1 | the replay of the committed slice, by a crash, `test-tools` | CAUGHT |
| OA32 | a cut datagram moves its lookup to the next server, against the replays | rule 4 | the replay of the committed slice, the test of `replay_cut.zig` that holds a stream, and the engine's short and picked walks, `test-tools` | CAUGHT |
| OA33 | a draining socket stays open while its lookup waits on a stream | the datagram's rules 4 and 6 | the picked walks, walk 24001 of the full run | CAUGHT |
| OA34 | the model's draining socket stays open while its lookup waits on a stream | the same, in the engine model | TLC's check "rotated" on `mutants/OA34`, `zig build tla` | CAUGHT |
| OA35 | the same as OA33, against the engine's tests | the datagram's rules 4 and 6 | the test of a draining socket in `io_sim_datagram_test.zig`, `test-io` | CAUGHT |
| OA36 | a lookup under `ignore_truncation` reads a cut datagram, against the engine's tests | rule 1 | the test of `ignore_truncation` in `io_sim_datagram_test.zig`, `test-io` | CAUGHT |

## A payload that the engine cannot receive

2026-10-14. The owner answered question 47 of docs/design.md §17. The engine's `init` and `reinit`
now refuse a `Config.udp_payload_bytes` that passes what a buffer of the datagram group holds.
Each returns `error.UdpPayloadTooLarge`, and the call changes nothing. §16 decision 44 records the
rule. §17 questions 48 to 50 asked the owner about three choices that the rule left to the build.
The owner kept each one as built, the same day.

### Where a payload size comes from

- `Config.udp_payload_bytes` holds it. Its default is 1,232 octets, `udp_payload_bytes_default`.
  `assert_valid` takes 512 to 65,535.
- No line of a `resolv.conf` sets it, and no option of `RES_OPTIONS` does. The option parser
  reads `edns0` as no option (`src/config/resolv_conf_options.zig`). No server holds a size of
  its own.
- So only the caller's code sets it. Such a caller can read the size from a file of its own.

A buffer of the datagram group is `buffer_bytes`, 2,048 octets. rotor puts a prefix of 192 octets
before each payload, under the options of the group. So a buffer holds 1,856 octets of a
datagram. `udp_payload_bytes_max` in `io/constants.zig` names that room. It is what rotor's
`payload_capacity` gives for `buffer_bytes` under `group_options`. `io_udp.zig` provides the
group under the same `group_options`, so a change of the buffer or of the options changes the
limit too.

The tree's rules argue for an assertion. `assert_valid` asserts each rule of a configuration,
since the caller builds it. But the owner ruled an error, and no rule of CLAUDE.md forbids one, so
the code follows the owner. An assertion in `reset_tables` stands after the check (decision 44).

### The design

The design changed first:

- §4: a comment on `udp_payload_bytes` in the sketch of `Config`.
- §7, A datagram that the buffer cut: only a forger or a broken server sends such a datagram now.
- §16: decision 44, and the end of decision 43. Decision 37 now says a `reinit` that fails at its
  sockets.
- §17: the answer to question 47, and questions 48 to 50 with their answers. Question 33 now
  asks about a `reinit` that fails at its sockets.
- §19 step 13: the datagram's rule 7, `InitError` in the sketch, rule 5 of the cache's memory,
  and a row of New limits.
- §24: the section "What `init` and `reinit` return", and the memory after a refused `reinit`.

Neither model changes. The Lean models hold no size of a payload. The TLA+ model of the engine
starts from an engine that `init` built, and holds no `reinit` and no octets.

Rule 5 of the cache's memory gives a `reinit` that fails at its sockets the new configuration and
the new memory. A refused `reinit` is not like it. The check comes before the call changes
anything, so the engine keeps the old configuration and the old memory. The memory of the call is
the caller's again at once. Until this rule, the old memory was the caller's whatever `reinit`
returned, so §17 question 49 asked the owner about the change. The owner accepted it.

### The tests and the code

The tests came first, in `io/io_lifecycle_test.zig`. Run before the code, each failed at its
first new check: "expected error.UdpPayloadTooLarge, found void".

- The test of `init`. One octet past the room, `init` returns the error. The engine's memory,
  marked before the call, is as it was. The loop holds no group, and the twin holds no open
  socket. At the room, `init` starts the engine. The room is what a buffer of the loop's group
  holds under the options that the engine gave it. A query advertises the room, and its answer
  comes.
- The test of `reinit`. The first server cuts each answer over UDP, so the lookup asks it again
  over a stream. The stream stays up and idle beside the socket. One octet past the room,
  `reinit` returns the error. The engine keeps its configuration and its cache over the memory
  that it held, with its seed and its answer. Each field of the socket is as it was, and its
  receive is one of them. The stream is still up, with the same socket, receive and opening. The
  twin holds as many open sockets as before. The memory of the call, marked before it, is as it
  was. At the room, `reinit` takes the configuration, and a query advertises the room.

Then the code:

- `io/constants.zig`: `group_options` and `udp_payload_bytes_max`. The comptime check that a
  buffer holds the default payload reads the limit. It no longer adds rotor's prefix of 192 by
  hand.
- `io/io_udp.zig`: the datagram group gets `constants.group_options`. Its comptime check that a
  buffer holds the default payload is gone, since the check of `io/constants.zig` says the same.
- `io/io_lifecycle.zig`: `check_payload`, which `init` and `reinit` call before they change
  anything, and the assertion of `reset_tables`.
- `io/io.zig`: `UdpPayloadTooLarge` in `InitError`, and the doc comments of `init` and `reinit`.

README.md and the doc comment of `Config.udp_payload_bytes` say what the engine refuses.

### The review

A review found two gaps in the first test of `reinit`:

- It read three fields of the socket: `open`, the descriptor and the generation of its receive.
  `Sockets.cancel` changes none of them. It sets the receive alone to none.
- Its rig held no stream. A check after the streams closed changed nothing that the test read.

Three rows showed the gaps. Against the first test, each was `NOT CAUGHT`:

- PL11: `reinit` cancels the receives of its sockets before the check.
- PL12: `reinit` closes its streams before the check, and its sockets after it.
- PL13: `reinit` cancels the operations of its streams before the check.

The test now holds a stream, and compares each field of the socket. Against it, each of the three
is `CAUGHT`. The engine's map from a lookup to its stream holds nothing for an idle stream:
`release` clears the entry of a lookup that ends. So the test reads the connection itself.

The review also found that the comptime check of `io_udp.zig` said again what the check of
`io/constants.zig` says. That check is gone. In its place, a run of the tool tried a check that
requires the room of the group to equal the limit. The run had a fourteenth row. The check made PL7
and PL8 stop the build. The tool reads a compile error of this tree's own as an edit that no longer
applies, so it found both rows `NOT CAUGHT`. The test of `init` already ties the group to the
limit, and it catches both rows. So no comptime check took the place of the old one, and the
fourteenth row went with it.

### The users

No example, test, replay or benchmark gives the engine a size above the room:

- The examples over the engine, `test/consumer/embed.zig`, `bench/end_to_end/rotor_loop.zig` and
  `tools/spec_replay/engine_world.zig` keep the default, 1,232 octets. So do the README's blocks.
- `src/resolver/lookup_config_test.zig` advertises 65,535 octets, but to the library alone, whose
  caller holds its own buffer.
- None of them names an error of `InitError`. Each calls `init` with `try`, so the new error
  changes none of them.

### What ran

With the change, `zig build test` has 1,086 tests pass of 1,086. The change adds the two tests
of `io_lifecycle_test.zig`. `zig build lint` passes, with each function at a complexity of 15 or
less. `zig build spec-lean` passes: 2,680,563 events and 354,997 cut datagrams agree with the
model, and 66,565 events of the walks. These steps ran too:

- `zig build examples` builds its four programs.
- `zig build test-cares` has 37 tests pass of 37. The engine of `bench/end_to_end/` keeps the
  default size.

`zig build spec-engine` and `zig build tla` did not run. Neither model changed, and no walk
reaches `init` with a size other than the default.

### The rows

Each row ran by hand, in a copy of the tree with a cache of its own. Those runs name the tests
that catch each row. Then `zig build mutations -- engine PL1 ... PL13` ran the thirteen rows,
after it ran `zig build test-io` once with nothing mutated. The run found each row `CAUGHT`, and
left the tree as it was.

Thirteen mutations, thirteen `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| PL1 | `init` has no check of the payload | the datagram's rule 7 | the test of `init` in `io_lifecycle_test.zig`, by the assertion of `reset_tables`, `test-io` | CAUGHT |
| PL2 | `reinit` has no check of the payload | rule 7 | the test of `reinit` in `io_lifecycle_test.zig`, by the assertion of `reset_tables`, `test-io` | CAUGHT |
| PL3 | `init` has no check of the payload, and `reset_tables` no assertion of it | rule 7, RFC 6891 §6.2.3 | the test of `init`: "expected error.UdpPayloadTooLarge, found void", `test-io` | CAUGHT |
| PL4 | `reinit` has no check of the payload, and `reset_tables` no assertion of it | rule 7, RFC 6891 §6.2.3 | the test of `reinit`: "expected error.UdpPayloadTooLarge, found void", `test-io` | CAUGHT |
| PL5 | the check takes one octet past the room | rule 7 | the tests of `init` and `reinit`, each by the assertion of `reset_tables`, `test-io` | CAUGHT |
| PL6 | the check refuses the room | rule 7 | the tests of `init` and `reinit`, each at the room, `test-io` | CAUGHT |
| PL7 | the limit is the whole buffer, rotor's prefix with it | `udp_payload_bytes_max` | the test of `init`: "expected 2048, found 1856", `test-io` | CAUGHT |
| PL8 | the datagram group is provided under options other than the limit's | `group_options` | the test of `init`, and the test of a datagram that fills a buffer in `io_sim_datagram_test.zig`, each "expected 1856, found 1792", `test-io` | CAUGHT |
| PL9 | `init` checks the payload after it writes the engine | rule 7: the call changes nothing | the test of `init`, at the engine's memory, `test-io` | CAUGHT |
| PL10 | `reinit` checks the payload after it closes its connections and its sockets | rule 7: the call changes nothing | the test of `reinit`, at its socket, `test-io` | CAUGHT |
| PL11 | `reinit` cancels the receives of its sockets before the check | rule 7: the call changes nothing | the test of `reinit`, at the receive of its socket, `test-io` | CAUGHT |
| PL12 | `reinit` closes its streams before the check, and its sockets after it | rule 7: the call changes nothing | the test of `reinit`, at its stream, which is no longer up, `test-io` | CAUGHT |
| PL13 | `reinit` cancels the operations of its streams before the check | rule 7: the call changes nothing | the test of `reinit`, at the receive of its stream, `test-io` | CAUGHT |

## The DoH channel's stream buffer

2026-10-17. c4milo/cocuyo#44 said that `cocuyo_doh` could end a sound TCP link. The type adds the
octets that it keeps and each new chunk. It ends the link when the sum passes `doh_stream_bytes`,
18,693 octets. The issue said that whole records could stay in the buffer when the next chunk
comes. It named two causes: records that colibri keeps for later, and records that the bound of
the engine's read leaves behind. No test showed it.

docs/design.md §16 decision 41 records the check. §17 questions 51 and 52 ask the owner about two
ways in which a sound stream still ends the link.

### What the code does

- The engine hands each chunk to the type, then reads the channel until it says nothing more
  (`take` in `io_channel_link.zig`, `hear` in `io_channel.zig`). A read takes at most an end for
  each request and `channel_events_max`, 16, of the channel's own.
- `next` hands colibri every octet that the type keeps. It goes on while colibri takes octets or
  says something. It ends when colibri takes nothing and says nothing (`io_doh_channel_read.zig`).
- In each pass, colibri v0.6.0 first reads the protocol from what it holds (`poll` in its
  `channel_events.zig`). Then it opens each whole record that its room holds, and reads the
  protocol again until an exchange ends (`read` and `open_records` in its `connection_tls.zig`).
- A record opens only into room for its body. The room is `plaintext_in_len`, 33,033 octets: a
  frame of HTTP/2 at its longest, 16,393 octets, and the body of a record at its longest, 16,640.

### The two causes

- The bound of the read: this cause cannot happen. Each request ends once, so a read hears one
  end for each at most. The rest is a ticket for each pass that opened one, the opens and closes
  of two links, and `closed`. colibri keeps the latest ticket alone (`collect_ticket`). The
  version that the channel speaks comes once, and `next` reads past it. A sound channel stays far
  under 16 of these.
- The room, over HTTP/2: this cause cannot happen. A pass starts with a partial frame at most,
  16,392 octets, so the first record of a pass fits. A later record of the same pass may not
  fit, because colibri opens records before it reads frames. That pass took octets, so `next`
  makes one more. It starts with a partial frame again, and the record fits.
- The room, over HTTP/1.1: this cause can happen. colibri's h11 reads a head or a trailer
  section only when it is whole, and keeps a partial one in its room. It accepts a head of up to
  32,768 octets, and a trailer section of up to 24,576. A record of 2^14 octets of plaintext has
  a body of 16,401 octets. When more than 16,632 octets of a head wait, the room is shorter.
  colibri then opens no more records, and the head never becomes whole.

### The probe

A test written for the check showed the hold over HTTP/1.1. The tree does not keep it, because it
requires the behaviour that §17 question 52 asks the owner to change. Its rig was the pair of
`io_doh_channel_test.zig`:

- colibri's server answered one request with a head of about 18,100 octets and 20,000 octets of
  content.
- The first record held 1,000 octets of plaintext, and the records after it were full.
- After the second record, colibri held 17,384 octets of the head. The third record did not fit.
- After the read, the third record stayed whole in the type's buffer. The next chunk passed
  `doh_stream_bytes`. The TCP link closed, and the exchange ended `closed`.

colibri's server does not let the rig choose its reason phrase, and writes no whitespace around a
value. So the probe's head held a field section larger than colibri's client accepts, 16,384
octets. The hold comes before the client reads the head, so the probe shows it all the same. A
sound head of that length has a long reason phrase, or whitespace around its values (RFC 9112 §4,
§5.1).

### Other states in which colibri opens no record

After a KeyUpdate that asks for a reply, colibri opens no record until its next `send` writes the
reply (`connection_tls.zig` and `record_provider.zig` of colibri). RFC 9846 §4.7.3 asks only for
the reply before the next Application Data record that colibri sends. The RFC does not ask for the
hold. The engine asks the channel for octets only when the link's send buffer is free (`send` in
`io_channel_link.zig`). The buffer is busy while a send is in flight, and while it holds octets not
yet sent.

Meanwhile each chunk after the KeyUpdate stays in the buffer. When more than 16,645 such octets
wait, the next full chunk ends the link. colibri's server sends no KeyUpdate of its own, so no test
shows it. §17 question 51 asks the owner.

In two more states colibri opens no record, and no exchange is left:

- After the connection stopped: it failed, or its last exchange ended after a shutdown. The
  octets stay until the link closes, or an overrun closes it sooner. After a shutdown, DATA can
  still come for a stream that the client cancelled (RFC 9113 §5.1).
- After the server's `close_notify`. The server sends no more messages after it, and data after
  it is ignored (RFC 9846 §6.1).

### The test

`io/io_doh_channel_read_test.zig` plays the engine, over the pair of `io_doh_channel_test.zig`.
Two requests are in flight. colibri's server answers each with a message of 2,000, 20,000 or
40,000 octets, over HTTP/2 and over HTTP/1.1. Call after call, it writes into rooms that follow
one of six lists:

- one room alone: 16,645, 2,049, 2,047 or 100 octets;
- two rooms of 16,406 octets, then one of 1,022 or 1,522 octets. A record in a room of 16,406
  octets holds 2^14 octets of plaintext and nothing after it.

Each chunk goes to the type, then a read as the engine's `hear` makes it, with the engine's bound.
The test requires:

- that no chunk ends the link;
- that no whole record stays in the buffer after a read;
- that no read reaches the engine's bound;
- that each answer comes whole.

The lists of two full rooms and a short one came after the review. Over HTTP/2, the first full
record holds the HEADERS frame of the first answer, and most of its first DATA frame. The second
full record ends that frame, and holds most of the next. The short record comes whole in the chunk
that ends the second. It finds no room beside the second, so it opens in a second pass of the
read.

Only the answers of 40,000 octets show it. Their second DATA frame has no END_STREAM, so no
exchange ends in the second full record. A first version alternated one full room with one short
room. No run of it made such a second pass, because the frames fell at other places.

The server of `io_doh_channel_server.zig` changed for the answers of 40,000 octets. colibri's
server takes a response's content only as its output and the stream's window allow (RFC 9113
§6.9). Now the rig's server keeps the rest of each answer, and writes more of it before each send.
It holds two such answers at once.

Over the 36 runs, 833 chunks came. After 224 of them the buffer held two whole records or more
before the read. The most that the buffer held with a chunk was 18,432 octets: a partial record of
16,384 and a chunk of 2,048. That passes a record at its longest, so the runs use the room that
decision 41 gives a chunk. The test passed on the code as it stood. The code did not change.

The rig of `io_doh_channel_test.zig` changed for it. The test reads through `Pair.note`, which
keeps what the channel said, and the pieces that it reads are public.

### What ran

With the change, `zig build test` has 1,087 tests pass of 1,087. The change adds the test of
`io_doh_channel_read_test.zig`. `zig build test-cocuyo_doh` has 27 tests pass of 27. `zig build
lint` passes, with each function at a complexity of 15 or less. `zig build example-doh-rotor`
builds its program, which asks for its arguments.

No code of the library or of the engine changed, so no count of `bench/count.zig` moves. Neither
model changes: the engine model holds no octets.

### The rows

Each row ran by hand first, with `zig build test-cocuyo_doh` in the tree. Then `zig build mutations
-- engine DS1 DS2 DS3 DS4` ran the four rows, after it ran `zig build test-cocuyo_doh` once with
nothing mutated. The run found each row `CAUGHT`, and left the tree as it was.

The review found that DS4 is not equivalent. It stops `next` after a pass that took octets and
said nothing. The first version of the test did not catch it, since none of its runs made such a
second pass. The lists of two full rooms and a short one catch it: "expected 0, found 1".

Four mutations, four `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| DS1 | the stream buffer holds a record at its longest, and no chunk past it | decision 41's room for a chunk | the new test, at a long partial record and a chunk; the test of the copied sizes: "expected 18693, found 16645", `test-cocuyo_doh` | CAUGHT |
| DS2 | the stream check counts against a record at its longest, and not the buffer | the room for a chunk | the new test; the test of stream octets of exactly what the type keeps: "expected 18693, found 0", `test-cocuyo_doh` | CAUGHT |
| DS3 | colibri is handed one chunk of the stream at most | no whole record stays after a read | the new test: "expected 0, found 1", `test-cocuyo_doh` | CAUGHT |
| DS4 | the read stops after a pass that took octets and said nothing | the second pass of a read over HTTP/2 | the new test, at two full records and a short one, over HTTP/2 with answers of 40,000 octets: "expected 0, found 1", `test-cocuyo_doh` | CAUGHT |

## The cause of a failure

2026-10-17. The owner ruled that a lookup that fails keeps the last cause a server gave, and that
the examples print it. On 2026-10-11 a run of the DoT live check failed once at Quad9 with
`AllServersFailed`, and nobody could say why. A dispatch started that run, 38168653502. Until
2026-10-18 this section named the daily check of 2026-10-12, but the run's record says otherwise.
The lookup kept the flag `had_server_failure` and no reason, and the example printed
`failure.err` alone.

docs/design.md §16 decision 45 records the rule, and §5 (The cause of a failure) says what each
error carries. §17 question 53 asks the owner about the name and the type of the field. Question
54 asks about a reason in `on_tcp_failed` and `on_request_failed`, which §16 decision 25 counted
against an alternative that it rejected. So the lookup reads the cause of a transport from its own
state, and no entry point changes.

### What the code did

Three places set the flag:

- `on_tcp_failed`, for a connection or a handshake that failed (`lookup.zig`);
- `on_request_failed`, for a DoH or DoQ request that ended without an answer
  (`lookup_request.zig`);
- `heard`, for SERVFAIL, REFUSED, NOTIMP and BADVERS, FORMERR without EDNS0, and a BADCOOKIE that
  advances the server (`lookup_response.zig`).

`next_server` read it when the passes ran out, and chose `AllServersFailed` over `Timeout`. The
engine calls `on_tcp_failed` at each failure of a connection:

- a connect refused or failed;
- no socket, no free connection slot, or an engine that keeps no TCP connection;
- a send or a receive that failed, and the peer's close;
- a TLS session that cannot start, seal or open, and a handshake that the session refuses.

It calls `on_request_failed` at these failures:

- each failure of a DoQ connection, and a stream that the server reset;
- each DoH exchange that ends with no DNS message.

Over TLS the engine tells a lookup that its connection is up only at the handshake's end (design
§21, TLS rule 1).

### The design and the models

- `Failure.cause: ?Cause`, where `Cause` is `union(enum) { rcode: wire.Rcode, connect, stream,
  request }`. `Failure` grows from 8 octets to 12, and a test pins it. `Action` stays at 64.
- The lookup's field `cause` replaces the flag. Each place that set the flag keeps a cause, and
  `next_server` reads whether there is one. `on_tcp_failed` keeps `connect` in `connecting_tcp`,
  and `stream` in `tcp_ready` and `awaiting_tcp`.
- `failure_of` asserts that `AllServersFailed` has a cause and `Timeout` has none.
- `AddressLookup` keeps each pending lookup's whole failure, and ends a walk on a hard failure
  with it. Until now it took the error from that lookup and the other fields from the last lookup
  that failed. It grows from 1,152 octets to 1,184, and design §9 says so. A `Lookup` stays at
  3,072 octets: the cause took three octets of the padding.
- The Lean model of the lookup holds `cause : Option Cause` in place of `serverFailed`. One
  definition, `keep`, gives a lookup the cause of a server failure, and `streamCause` reads the
  stage of a stream that failed. `LookupProofs/Cause.lean` proves `failure_cause`: a lookup that
  fails with `allServersFailed` holds a cause, and one that fails with `timeout` holds none.
- Each line of the lookup's transcript ends with the cause, and the replay compares it. A failed
  lookup's cause is read from its `Failure`. The full transcript grew from 2,680,454 transitions,
  173 deep, to 7,530,842, 183 deep, since states that differ in their cause alone are walked
  apart. The committed slice kept its 4,414 transitions, until the review below added to it.
- The engine model in TLA+ keeps its flag, and the engine's walks spell a lookup as before. Which
  cause a lookup holds changes no transition of the engine. The model of the walks holds no
  `Failure`, so it does not change.

### The tests, before the code

The tests came first, over a stub: the type, the field and a lookup that never set it. Each failed
as the list says, and each `err` that it checked passed.

- `lookup_failure.zig`, each rcode that fails a server: "expected .{ .rcode = .server_failure },
  found null".
- There, FORMERR without EDNS0: "expected .{ .rcode = .format_error }, found null".
- There, a connection that fails before it is up and after: "expected .{ .connect = void }, found
  null".
- There, the last server failure, with a silent server after it: "expected .{ .rcode = .refused },
  found null".
- There, a stream after an rcode and an rcode after a stream: "expected .{ .connect = void },
  found null".
- There, `NameNotFound` and `Canceled` after a server failure: "expected .{ .rcode =
  .server_failure }, found null".
- `lookup_cookie_test.zig`, BADCOOKIE over a stream after its retry, twice: "expected .{ .rcode =
  .bad_cookie }, found null".
- `lookup_request_test.zig`, every request failed: "expected .{ .request = void }, found null";
  BADCOOKIE over DoH or DoQ: "expected .{ .rcode = .bad_cookie }, found null".
- `address_lookup_walk.zig`, a walk that ends on a hard failure: "expected .{ .rcode =
  .server_failure }, found null".
- `name_lookup.zig`, a server that fails the reverse walk: "expected .{ .rcode = .server_failure },
  found null".
- `io_tcp_test.zig`, every server refused a connection: "expected .{ .connect = void }, found
  null"; a query send that fails, and a connection that fails mid-send: "expected .{ .stream = void
  }, found null". After the review the test of refused connections moved to
  `io_tcp_cause_test.zig`.
- `io_tls_failing_test.zig`, a session that fails at each server: "expected .{ .connect = void },
  found null".
- `io_request_failure_test.zig`, three tests over DoQ: "expected .{ .request = void }, found
  null".
- `io_channel_test.zig`, every DoH exchange failed: "expected .{ .request = void }, found null".

These passed over the stub, since null was all that it gave: a lookup that no server failed, a
retry, a server error under `check_response` off, and a negative that the memory recalls. Their
rows below are what shows each one.

### What the rows found

Each row ran once by hand first, with its step, and each file put back after it.

- The two tests of `io_tcp_test.zig` that break a stream expected `stream`. With the code, both
  found `connect`. The second server of that rig is down, and the twin refuses a connect to a
  server that is down. So the last failure is that refusal, and the last cause wins. The tests now
  expect `connect`. A new test resets the stream at each server once it is up, and expects
  `stream`.
- LC21 was not caught at first. The TLS test that every server refuses runs two passes. On the
  second pass a lookup finds no free connection slot, since the refused connection still closes
  after its alert. The engine then calls `on_tcp_failed` in `connecting_tcp`, which is `connect`
  whatever the handshake did. A new test runs one pass, and its last failure is the second
  server's own refusal: "expected .connect, found .stream". The test of two passes now checks
  the error alone, as it did before.
- LC22 and LC25 broke two proofs at first, because each proof named the cause that a SERVFAIL
  keeps. Neither proof failed for a reason of the behaviour. The model now keeps each cause
  through `keep`, and the proofs do not name it. Then LC22 meets the committed slice, and LC25
  only the full transcript: in the slice, one server and one pass end a lookup at its first server
  failure, so a first cause never meets a second.
- LC19 is caught by the engine's replay alone, for the same reason: the lookup's slice never shows
  a lookup that a server failed and that still runs.
- After the review the slice holds one server with two passes over DoH too. So since then the
  slice catches LC25 and LC19 as well (What the review found, below).

The rows of earlier sections whose edits named the flag were written again for the cause, with the
same intent: RF3, RF4, FR2, FR3, FR8 to FR12, CO30, DT38 and G1 in `lookup.zon`, A4 and A5 in
`address.zon`, and DM3, RF1, RF2, CO22 and CO23 in `lean.zon`. Each ran again below.

### What the review found

A review read the change on 2026-10-17. What it found, and what changed for it:

- `NameLookup` lost the cause at a negative end, and at a cancel after its lookup failed. Its
  `end_failed` built a `Failure` of zeros. In a copy of the tree the review gave the first server
  SERVFAIL and the second NXDOMAIN. `NameLookup` then ended `NameNotFound` with no cause, and
  `AddressLookup` with the SERVFAIL. `NameLookup` now keeps `last_failure` as `AddressLookup`
  does, and both ends put their error on its fields. So a negative end carries its lookup's
  negative TTL too (design §16 decision 45, §19 step 14).
- In `examples/answer_text.zig`, `report_failure` stood between the doc comment of `report` and
  `report`. Each function has its own comment again.
- Design §5, §17 question 54 and the README now name three more causes of `connect`. These are
  no socket, no free connection slot, and an engine that keeps no TCP connection. They are local,
  and no server took part. Over TLS a second pass can find no free slot while the connection of the
  first pass still closes. Its `connect` then replaces the cause that the server gave.
- No engine test checked the cause on three paths: an engine with no TCP connection, no free
  slot, and a query send that fails on a connection that is up. `io/io_tcp_cause_test.zig` has a
  test for each. The two tests of a cause in `io_tcp_test.zig` moved there too, by the
  file-length rule.
- The committed slice held no lookup that runs with a cause. So `zig build test` never replayed a
  cause that a later failure replaces. `configsGate` in `spec/lean/Main.lean` now adds one server
  with two passes over DoH. The slice grew by 2,282 transitions to 6,696, and the replay's test
  requires six configurations. Two passes over TCP held 10,094 transitions, and over DoH both
  `request` and three rcodes come, so DoH was the smaller choice.
- The interop check took `connect` or `request` over each transport. It now requires `connect`
  over DoT, and `request` over DoQ and DoH.
- Some new sentences were longer than 25 words, and one list was written as a sentence. They are
  split, or written as lists.
- The time of `zig build spec` here did not match the runs of the builder and of the review. The
  time below is measured over the final tree.

One finding stays as it was. `examples/udp_blocking.zig` and `examples/udp_rotor.zig` each have a
`report_failure` of their own, and do not import `answer_text.zig`. Each is one file by design,
"so the shape of the API is visible in one file". Each has its own `report` for that reason.

The change to `NameLookup` made LC17 an equivalent mutant. Its edit called `end_failed` with the
error, and `end_failed` now reads the failure that was just kept. So its edit now builds a
`Failure` of zeros, which is what `end_failed` built before.

### The tests, before the code, after the review

The two tests of `name_lookup.zig` came first, and each failed:

- a negative end after a server failure: "expected .{ .rcode = .server_failure }, found null";
- a cancel after the lookup failed: "expected .{ .rcode = .server_failure }, found null".

The three tests of `io_tcp_cause_test.zig` passed at once, since the engine took each path
already. LC32 to LC34 show what each one catches.

### What ran

These runs went over the final tree, after the review:

- `zig build mutations -- lookup` with LC1 to LC19, LC29 to LC31 and the twelve carried rows;
- `zig build mutations -- engine` with LC20, LC21 and LC32 to LC34;
- `zig build mutations -- address A4 A5`;
- `zig build mutations -- lean` with LC22 to LC28 and the five carried rows.

Each ran its steps once with nothing mutated first. Each found each row `CAUGHT`, and each left the
tree as it was. LC1 also breaks the two engine tests of a stream, in `test-io`: "expected .stream,
found .connect".

With the change, `zig build test` has 1,111 tests pass of 1,111. `zig build lint` passes, with
each function at a complexity of 15 or less. `zig build spec` passes. The lookup's replay agrees
over 7,530,951 events and 994,033 cut datagrams, the walks' over 66,565 events, and the engine's
over 5,226,000 events in 26,000 walks. Over the final tree it took 490 seconds, 8 minutes 10
seconds, on 2026-10-18, on an Apple M1 Pro. `zig build examples` builds each example.
`example-cleartext-rotor` over TCP to a closed port on the loopback prints
`example.com: AllServersFailed (connect)`. The live checks and the interop check need the network
or dnsproxy, and did not run.

### The instruction counts

No counted case of `bench/count.zig` ends in a failure, and an `Action` keeps its size. The x86-64
code of the library's hot paths did change. `zig build fill-check` compiles them ReleaseSafe to
assembly. It ran for HEAD and for the change, each in a copy of the tree with a cache of its own.
By the instructions that each function holds:

- `heard` went from 138 to 145, and `next_server` from 51 to 49.
- `Resolver.poll` went from 1,040 to 1,056, and `Resolver.on_datagram` from 934 to 919.
- `Resolver.on_tcp_failed` went from 67 to 81.
- `init_in_place` and the query's build kept their counts, and their code changed: the fields
  moved.

The cases `round-trip`, `match-accept`, `match-stray` and `match-wrong` run these functions, so
their counts can move. `query-build`, `query-build-tcp`, the three `parse` cases, `resolv-conf`
and the four cache cases run none of them, and should not move. A function's size is not what a
case takes, so the review counted the cases under cachegrind 3.22.0, for HEAD and for the change.
It ran in an arm64 Linux container, and not on the x86-64 of the baseline:

- `round-trip` went from 3,948 instructions to 3,970, 0.56% more;
- `match-wrong` went from 258 to 255, 1.2% fewer;
- the other twelve cases did not move.

Both moves are under the 2% floor of `tools/instructions.zig`, so the x86-64 counts of CI will
likely pass too. The changes after the review are in `NameLookup`, in tests and in comments, and
no counted case runs them. `bench/instructions.zon` did not change. CI's Linux job prints the
counts as they stand when they move.

### The rows

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| LC1 | the cause of a failed stream is the connect's in every state | `stream_cause` reads the state | the test of a connection that fails before it is up and after: "expected .stream, found .connect", `test-resolver` | CAUGHT |
| LC2 | the cause of a failed stream is the stream's in every state | `stream_cause` reads the state | the same test and two others: "expected .connect, found .stream", `test-resolver` | CAUGHT |
| LC3 | a failed request keeps the stream's cause | `on_request_failed` keeps `request` | the test of every request failed: "expected .request, found .stream", `test-resolver` | CAUGHT |
| LC4 | a response that fails its server keeps no cause | `heard` keeps the rcode | the BADCOOKIE tests over a stream: "expected .{ .rcode = .bad_cookie }, found null"; the test of each rcode: "expected error.AllServersFailed, found error.Timeout", `test-resolver` | CAUGHT |
| LC5 | each rcode that fails a server keeps SERVFAIL as its cause | `cause_of` keeps the rcode read | the test of each rcode: "expected .refused, found .server_failure"; the BADCOOKIE tests: "expected .bad_cookie, found .server_failure", `test-resolver` | CAUGHT |
| LC6 | FORMERR to a query with EDNS0, a retry, keeps a cause | a retry is no failure | the FORMERR test and the test of a retry: "expected null, found .{ .rcode = .format_error }", `test-resolver` | CAUGHT |
| LC7 | a first BADCOOKIE, a retry, keeps a cause | a retry is no failure | the test of a retry: "expected null, found .{ .rcode = .bad_cookie }"; the BADCOOKIE tests on the server's count: "expected 0, found 2", `test-resolver` | CAUGHT |
| LC8 | a server error taken as the answer under `check_response` off keeps a cause | the answer is no failure | the test under `check_response` off: "expected null, found .{ .rcode = .server_failure }", `test-resolver` | CAUGHT |
| LC9 | the next candidate clears the cause | nothing clears the cause | the test of an error but `AllServersFailed`: "expected .{ .rcode = .server_failure }, found null", `test-resolver` | CAUGHT |
| LC10 | a try that ran out clears the cause | silence clears no cause | the test of a silent server after a failure: "expected error.AllServersFailed, found error.Timeout", `test-resolver` | CAUGHT |
| LC11 | the first rcode stays the cause | the last cause wins | the test of the last server failure: "expected .refused, found .server_failure", `test-resolver` | CAUGHT |
| LC12 | the first cause stays, and a failed stream after it does not replace it | the last cause wins | the test of a stream after an rcode: "expected .connect, found .rcode", `test-resolver` | CAUGHT |
| LC13 | the failure reports no cause | `failure_of` copies the cause | each test of a cause, among them: "expected .{ .rcode = .server_failure }, found null", `test-resolver` | CAUGHT |
| LC14 | a failed send keeps a cause | a failed send is silence | the test of a lookup no server failed: "expected error.Timeout, found error.AllServersFailed", `test-resolver` | CAUGHT |
| LC15 | a lookup starts with a cause | `init` sets none | the timeout test of `lookup_poll.zig`: "expected error.Timeout, found error.AllServersFailed", and three more, `test-resolver` | CAUGHT |
| LC16 | a walk ends a hard failure with its error alone, on the fields of the last lookup that failed | the hard end hands on that lookup's failure | the walk's test trips the assertion of `end_failed_with`, that `AllServersFailed` has a cause: "reached unreachable code", `test-resolver` | CAUGHT |
| LC17 | the reverse walk ends a hard failure with its error alone, on zeros and no cause | `NameLookup` hands on the failure whole | the test of a server that fails the reverse walk trips the assertion of `end_failed_with`, that `AllServersFailed` has a cause: "reached unreachable code", `test-resolver` | CAUGHT |
| LC18 | the replay spells the cause FORMERR as SERVFAIL | the replay compares the cause | the replay of the committed slice, at line 107: the model's "failed all_servers_failed - formerr" against the lookup's "... - servfail"; the test of the spelling, `test-tools` | CAUGHT |
| LC19 | the replay's flag that a server failed ignores the cause | the flag is the cause's | the replay of the committed slice, at line 4,822: the model's `E-F- request` against the lookup's `E--- request`; the engine's replay of the committed walks, at line 7: the model's `E-F-` against the engine's `E---`, `test-tools` | CAUGHT |
| LC20 | a connect that failed tells its lookups the connection is up first | `connect` before `on_tcp_connected` | the test that every server refused a connection, and the two tests of `two_queued`: "expected .connect, found .stream", `test-io` | CAUGHT |
| LC21 | a TLS connection tells its lookups that it is up when its handshake starts | TLS rule 1 | the one-pass test of a refused handshake: "expected .connect, found .stream"; four other TLS tests, on a server's count of failures, `test-io` | CAUGHT |
| LC22 | the model keeps the cause FORMERR at SERVFAIL | the model's SERVFAIL | `cocuyo-spec check`: "lookup_gate.txt is not the slice the model writes", `spec-lean` | CAUGHT |
| LC23 | the model's cause of a failed stream is the connect's in every stage | `streamCause` | the same check, `spec-lean` | CAUGHT |
| LC24 | the model's failed request keeps the stream's cause | the model's failed request | the same check, `spec-lean` | CAUGHT |
| LC25 | the model keeps the first cause, and a later server failure does not replace it | `keep` | `cocuyo-spec check`: "lookup_gate.txt is not the slice the model writes", `spec-lean`. Before the review, the replay of the full transcript alone, at line 41,673 | CAUGHT |
| LC26 | the model forgets the cause at the end of its last pass | `failure_cause`, `refused_never_timeout` | the proofs: "Timeout.lean:38:4: unsolved goals", in `marked_advanceServer`, `spec-lean` | CAUGHT |
| LC27 | the model's walk writes no cause | the cause on each line | `cocuyo-spec check`: "lookup_gate.txt is not the slice the model writes", `spec-lean` | CAUGHT |
| LC28 | `failure_cause` proved by `sorry` | the axiom pins | "Axioms.lean:49:0: Docstring on `#guard_msgs` does not match generated message", `spec-lean` | CAUGHT |
| LC29 | the reverse walk keeps no failure of its lookup, so a negative end or a cancel ends on zeros | `NameLookup` keeps `last_failure` | both tests of `name_lookup.zig` after the review: "expected .{ .rcode = .server_failure }, found null", `test-resolver` | CAUGHT |
| LC30 | the reverse walk reads the cancel before it keeps the failure of its lookup | the failure is kept first | the test of a cancel after the lookup failed: "expected .{ .rcode = .server_failure }, found null", `test-resolver` | CAUGHT |
| LC31 | the first rcode stays the cause, as the replay of the committed slice sees it | the last cause wins | the replay of the committed slice, at line 4,906: the model's "failed all_servers_failed - servfail" against the lookup's "... - request", `test-tools` | CAUGHT |
| LC32 | an engine that keeps no TCP connection tells the lookup it is up before it fails it | `connect` with no TCP | the test of an engine with no TCP connection: "expected .connect, found .stream", `test-io` | CAUGHT |
| LC33 | a lookup that finds no free connection slot is told it is up before it is failed | `connect` with no slot | the test of no free slot: "expected .connect, found .stream", `test-io` | CAUGHT |
| LC34 | a stream send that moved nothing is reported as a failed send before the connection fails | a failed send on a stream is `stream` | the test of a query send that fails on a connection that is up: "expected error.AllServersFailed, found error.Timeout", `test-io` | CAUGHT |

The carried rows were each `CAUGHT` again, by the step they name: RF3, RF4, FR2, FR3, FR8 to FR12,
CO30 and DT38 by `test-resolver`, and G1 by `test-tools`; A4 and A5 by `test-resolver`; DM3, RF1,
RF2, CO22 and CO23 by `spec-lean`.

Thirty-four mutations, thirty-four `CAUGHT`.

## A pass that waits for a connection slot

2026-10-18. The owner ruled that the engine's defect of the section before is fixed now. Over TLS a
lookup's second pass could find no free connection slot, while the connection of its first pass
still closed after its alert. The engine then failed the pass at once with `connect`, and that
local failure replaced the cause that the server gave.

docs/design.md §19 step 13 holds the new rule, the stream's rule 12, and §16 decision 46 records it
with the alternatives that it beats. §21's TLS rule 6 says why a TLS lookup always has a slot to
wait for. The lookup model does not change. The engine model in TLA+ does.

### The sequence

Over TLS, with one server, one slot and two passes:

1. The first pass opens a connection, and the handshake starts.
2. The session refuses the server's handshake record. The lookup hears `on_tcp_failed` before it
   hears that the connection is up, so it keeps `connect`. It goes on to its second pass.
3. The connection seals its fatal alert and stays `closing` until the alert's send ends (TLS rules
   4 and 5). The loop holds the records buffer until then (TLS rule 3).
4. In the drive of the same event, the lookup asks for a stream. `find` passes over a connection
   that closes, and `free_slot` closes no TLS connection to make room (TLS rule 6). So `open`
   returned `SocketFailed`, and the engine called `on_tcp_failed` at once.
5. The lookup ended in `AllServersFailed` with `connect`. The server heard one alert, and its
   count of failures rose by two.

A record that the session refuses once the connection is up takes the same way, after `stream`. The
second pass then replaced `stream` with `connect`. A slot is free over TLS only when its
connection has closed. So the second pass found no slot when no other slot was free at that
moment, as with one server and one slot. With more slots another may be free, or may close too.

In the clear a connection that fails closes at once, and its slot is free unless the loop holds
it. So the TLS sequence cannot happen there. Another sequence can. A connect that outlasts its
lookup's wait holds its slot until its event (the stream's rule 10). With one slot, the lookup at
the next server found no free slot, and failed at once with `connect`. That next server was never
asked. `tcp_connections_default` is 1.

### The Quad9 failure of run 38168653502

The failed run is the `dot-live` workflow's run 38168653502, which a dispatch started at
19:35:14 UTC on 2026-10-11, at commit `db4395a`. No `dot-live` run on 2026-10-12 failed, and none
other failed from 2026-10-08 to 2026-10-18. Its log says, word for word:

- "FAILS the types beyond A through dns.quad9.net", and the AAAA answer of `cloudflare.com`;
- "cloudflare.com/MX: AllServersFailed".

The evidence, read from the log and from the tree at `db4395a`:

- `tools/dot_live/run.sh` hands `examples/dot_rotor.zig` one server at each run.
- The example's engine has `tcp_connections = servers_max`, 8 slots, and 4 lookups at once on one
  connection, with the default 2 passes.
- `free_slot` took any closed slot that the loop did not hold, as it does now.
- The typed turn took less than 0.87 seconds by the log's times, its build among them. The
  default wait is 2 seconds, so no try at the MX lookup ran out.

The inference: the sequence of this section cannot explain that failure. With one server, the
server has at most one connection that a lookup may join. A pass finds no free slot only when the
other slots are all closing or held by the loop. Each failed pass leaves one such slot, and the
four lookups share the next connection. Eight such slots are needed at once, and two passes make
two at most. So each of the
MX lookup's two passes ended at a failure of the server: an rcode, a handshake, or a stream.
The example printed no cause then, so which one is not known. A SERVFAIL for MX at both passes
fits the times, and so do two connections that Quad9 closed. Neither is evidence. The next
failure prints its cause.

### The design and the model

- A lookup that finds no free slot waits while a slot is pending, in `connecting_tcp` and on no
  connection. Its deadline bounds the wait.
- In the clear, when no slot is pending, the lookup closes a connection that no lookup is on while
  its connect is in flight. Then it waits for that slot. The review of the change asked for this
  (What the review found, below).
- The drive's end admits each lookup that waits, after the idle close.
- The engine keeps `tcp_waiting`, a flag for each lookup, and `tcp_waiters`, their count.
  `io/io_tcp_wait.zig` holds the wait, split from `io_tcp.zig` by the file-length rule.
- The model holds `waits` for each slot of the table. `Want` waits while a slot is pending, and
  `Admit` runs at the drive's end. Four checks hold the rule:
  - "waits connecting": a lookup that waits is in `connectingTcp`, on no connection;
  - "waits for no free slot": after a drive with nothing refused, a lookup waits only while no
    slot is free and its server has no connection to join. A slot is then pending, or in the
    clear each slot holds a lookup;
  - "told when up": no lookup in `connectingTcp` is on a connection that is up;
  - "slot waited for": no lookup is told its connection failed for want of a slot over TLS, or in
    the clear while a slot has no lookup on it. A refused socket or submission is not judged. The
    field `slotless` holds that, and it is never set in a model that keeps its rules.
- The trace writes a lookup that waits as `cw` in place of `c-`. So a walk with no wait is
  written as before.

`zig build tla` checked every configuration and mutant on 2026-10-18, the nightly ones among
them. Each configuration holds, and each mutant is violated, TS11 to TS13 and TS18 among them. The
configurations of UDP alone, of DoQ and of DoH hold the states that they held before. Those that
reach a stream hold more, since a lookup that failed there now waits. The first form is the rule
before the review:

| Configuration | Before | First form | Now |
| --- | --- | --- | --- |
| `Engine_tcp_1_1_bound_4_1` | 18,625 | 22,847 | 20,098 |
| `Engine_tcp_2_1_bound_4_1` | 561,813 | 914,106 | 690,360 |
| `Engine_tcp_2_2_bound_4_1` | 2,438,035 | 3,466,275 | 3,466,275 |
| `Engine_tls_1_2_bound_2_1` | 252,573 | 294,898 | 294,898 |
| `Engine_tls_1_2_bound_3_1` | 9,004,551 | 11,259,959 | 11,259,959 |
| `Engine_tls_2_2_bound_2_1` | 16,382,680 | 28,446,316 | 28,446,316 |
| `Engine_truncated_1_1_bound_4_1` | 426,197 | 451,556 | 427,125 |

### The tests, before the code

The two tests of the defect came first, and each failed on the code of 95ef1d0:

- `io_tls_failing_test.zig`, a second pass after a refused handshake, one server and one slot:
  "expected null, found .{ .connect = void }". The lookup ended in `AllServersFailed` at 2 ms of
  the twin's clock, under a wait of 25 seconds. Its server's failures were 2, and the connection
  was still `closing`.
- `io_tcp_test.zig`, the lookup at the next server after a connect that outlasted its wait:
  "expected null, found error.AllServersFailed". After the review a test of
  `io_tcp_wait_test.zig` replaces it.

The failing session of `io_tls_failing_test.zig` gained a failure point, `handshake`. There it
refuses the twin's `refused` step, and stages its fatal alert.

Three tests came with the code. Their rows below show what each catches:

- `io_tls_failing_test.zig`, a second pass that waits for a closed slot whose records the loop
  still holds: the peer resets the connection while the hello's send is in flight.
- `io_tcp_test.zig`, a lookup whose wait runs out at its deadline. It ends in `Timeout`, and the
  slot that frees later admits nobody. After the review the lookup closes that connect, so a test
  of a refused admission in `io_tcp_wait_test.zig` replaces it.
- `io_tcp_cause_test.zig`, a lookup that finds each slot held by a lookup. It fails at once with
  `connect`, as the stream's rule 1 says. This test replaces the one of a connect that outlasted
  its wait, which now waits, and it catches LC33.

### What the review found

The review of the change found one fault that had to be fixed, and ten more:

- §16 decision 46 rejected a choice for a false reason. It said that the close of an unused
  connection while its connect is in flight changes the stream's rule 10. Rule 10 forbids a new
  opening of the slot while that connect is in flight, and no cancel. The idle close cancels such a
  connect already.
- The rule's cost in the clear was real. The defaults are one slot, a wait of 2 seconds and an
  idle close at 10 seconds. With them, a connect that hangs held the slot past each wait. The
  lookup at the next server waited out each pass, never reached that server, and ended in `Timeout`.
- So the rule changed in the clear. When no slot is pending, the lookup closes the first connection
  that no lookup is on while its connect is in flight. Then it waits for that slot, which frees at
  the cancelled connect's event. The design changed first, then the model, then the code.
- No row broke the half of `want` that tells a want of a slot from a refused socket. TS16 does
  now, and a TLS test catches it.
- Nothing bounds how long a pending slot takes. A peer that stops reading holds a TLS connection in
  `closing`, and a lookup that waits for its slot waits until its deadline. Rule 12 says so now,
  and §17 question 55 asks the owner about a time bound. It needs a GitHub issue too.
- Over TLS a query's send also goes out from the connection's records buffer. Only a send of the
  session's own records marks that buffer as the loop's. A connection that fails during a query's
  send leaves its slot free while the loop may still read the buffer. A new opening can then
  write its hello there, which TLS rule 3 forbids. This was there before the change, and the change
  does not touch it. It needs a GitHub issue of its own.
- This section said that a configuration with as many slots as servers meets the defect at each
  refusal. The defect needs no other slot free at that moment. The text says so now.
- The heading named the Quad9 failure for 2026-10-12. The failed run was a dispatch on 2026-10-11.
  Decision 45 and the section before named the day wrong too. Each now says what the run's record
  says.
- Rule 12 said that a lookup waits while a slot is pending. In the clear it can wait while each slot
  holds a lookup. That happens when the slot that freed went to a lookup that asked in the drive's
  polls. Rule 12 and the doc comments say so now.
- Rule 12 said that no connection opens between two drives. `connect_again` opens one, for a TLS
  connection that waits to connect again. The rule now says why that changes nothing.
- A doc comment said that over TLS each server has a slot of its own. It now gives TLS rule 6's
  argument: each server has at most one connection that a lookup may join.
- The TLS test of a refused handshake did not count the server's failures. It now requires one
  failure while the second pass waits.
- §19 step 13 said that TLC checks twenty-five invariants. It checks forty-one.

### The tests, before the code, after the review

`io/io_tcp_wait_test.zig` holds the tests of the wait in the clear, split from `io_tcp_test.zig` by
the file-length rule. Its first test came before the code. A lookup's first server has a connect
that hangs, and its second server answers. On the first form of the rule it failed with "expected
null, found error.Timeout". It replaces both tests of the first form in `io_tcp_test.zig`.

These tests came with the code. Their rows below show what each catches:

- `io_tcp_wait_test.zig`, a lookup whose admission the loop refuses waits for the next drive, and
  that drive admits it.
- `io_tcp_wait_test.zig`, a lookup whose admission the loop refuses until its deadline moves on
  there, in `Timeout`, and a later lookup waits for nothing.
- `io_tcp_wait_test.zig`, a lookup at the next server leaves alone a connect that a lookup is on,
  and is told at once.
- `io_tcp_wait_test.zig`, a lookup that waits while a slot is pending leaves alone a connect that
  no lookup is on. Two slots, and the idle close makes the pending one.
- `io_tls_failing_test.zig`, a second pass whose connect the loop refuses is told at once, though a
  slot is pending.

On the first form the three tests of a refused admission and of a connect that a lookup is on
failed too. The last two passed: they keep what the first form did.

### What ran on the first form

These ran on the first form of the rule, before the review:

- The tests of the defect, then the code, then `zig build test-io`: each test passed.
- `zig build tla` over each configuration and mutant: each configuration held, and each mutant was
  violated, TS11 to TS13 among them.
- `zig build tla -- walks 1 10 41`, the short walks. Eleven of the 130 held a wait, and only they
  changed. Five were over TCP with one lookup, five over TCP with two lookups on one connection,
  and one over TLS.
- `zig build tla -- walks 1 2000 201`, the full run. It held 26,687 states in which a lookup waits,
  and its replay agreed with the engine over 5,226,000 events in 26,000 walks.
- `zig build mutations -- engine --walks` that full run, over the 80 rows that the walks catch. Each
  was `CAUGHT`, and the tool named sixteen walks to pick.
- `zig build mutations -- engine TS1 TS2 TS3 TS4 TS5 TS6 TS7 TS8 TS9 TS10 LC33`: each was `CAUGHT`.
  At the first run TS1 did not compile: its edit removed the line that waits, and left `err`
  unused. Its edit now turns the wait off in place.

### What ran after the review

- The test of a connect that hangs, then the code, then `zig build test-io`: 174 tests pass.
- `zig build tla` over the configurations in the clear and over the mutants of the rule:
  `Engine_tcp_1_1_bound_4_1` holds 20,098 states, `Engine_tcp_2_1_bound_4_1` 690,360,
  `Engine_tcp_2_2_bound_4_1` 3,466,275 and `Engine_truncated_1_1_bound_4_1` 427,125.
  `Engine_tls_1_2_bound_2_1` holds 294,898, as on the first form. TS11, TS12 and TS18 break "slot
  waited for", and TS13 breaks "waits for no free slot".
- `zig build tla -- walks 1 10 41`, the short walks. Ten of them changed, the five over TCP with one
  lookup and the five over TCP with two lookups that held a wait. The lookup there now closes the
  connect of its last try, where the first form left it in flight.
- `zig build tla -- walks 1 2000 201`, the full run, 880 MB. It holds 23,831 states in which a
  lookup waits.
- `zig build mutations -- engine --walks` that full run, over the 80 rows that the walks catch and
  23 rows of `test-io` whose edits read `io_tcp.zig`, `io_tcp_wait.zig` or `io_drive.zig`. Each of
  the 103 is `CAUGHT`. The replay of the full run with nothing mutated agrees with the engine. The
  short walks catch each row they caught before. For each row that they miss, the tool named the
  full run's first walk that catches it. These are walks 4, 8, 13, 2002, 4020, 4212, 8025, 8046,
  8241, 12004, 12011, 16008, 16068, 16478 and 24001. These fifteen are the picks now, in
  `engine_picks` of `build/spec.zig`.
- The same, over the 24 rows that the picked walks catch, against the new picks: each is `CAUGHT`.
- Each TS row of the code and LC33 ran by hand once, its step's output read, and each file put
  back. The texts in the rows below come from there.

Over the final tree:

- `zig build test`: 1,119 tests pass of 1,119, where 1,111 passed before the change.
- `zig build lint`: each function scores 15 or less.
- `zig build spec-engine`: the committed short walks and the fifteen picks are the ones TLC
  writes, and the full run agrees over 5,226,000 events in 26,000 walks. It took 9 minutes 17
  seconds on an Apple M1 Pro.
- `zig build tla`, the nightly configurations among them: 15 configurations hold, and 37 mutants
  are violated. It took 2 hours 30 minutes, while a TLC check of another project ran.
- `zig build examples` builds each example.
- The live checks and the interop check need the network or dnsproxy, and did not run.

### The instruction counts

`bench/count.zig` imports `cocuyo` and `wire` alone, and no counted case runs the engine. This
change touches no file under `src/`. So no count can move, and `bench/instructions.zon` did not
change.

### The rows

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TS1 | a lookup that finds no free slot is told at once, as the engine did until 2026-10-18 | the stream's rule 12 | seven tests: the test of a connect that hangs, "expected null, found error.AllServersFailed"; the test of a slot pending and a connect that no lookup is on, "expected 1, found 0"; both TLS tests of a wait, "expected 1, found 0"; three more of `io_tcp_wait_test.zig`, `test-io` | CAUGHT |
| TS2 | a connection that closes after its alert is not pending | `pending` reads a connection that closes | the TLS test of a refused handshake: "expected 1, found 0", `test-io` | CAUGHT |
| TS3 | a closed slot whose memory the loop holds is not pending | `pending` reads a closed slot that the loop holds | five tests of `io_tcp_wait_test.zig` trip an assertion of `make_pending`: "reached unreachable code"; the TLS test of a reset during the hello: "expected 1, found 0", `test-io` | CAUGHT |
| TS4 | in the clear, a lookup closes no connection that no lookup is on while its connect is in flight | `free_slot` makes a slot pending | four tests: the test of a connect that hangs, "expected null, found error.AllServersFailed"; the test of a connect that a lookup is on, the same; both tests of a refused admission, `test-io` | CAUGHT |
| TS5 | the drive's end admits no lookup that waits | `admit` in the drive | six tests: the test of a connect that hangs, "expected null, found error.Timeout"; the test of a refused admission that the next drive admits, "expected 0, found 1"; both TLS tests of a wait, "expected null, found .{ .connect = void }", `test-io` | CAUGHT |
| TS6 | a lookup that acts still waits for a slot | `follow` ends the wait | the test of a refused admission until the deadline trips an assertion of `admit`: "reached unreachable code", `test-io` | CAUGHT |
| TS7 | a lookup that the drive's end admits still waits | `admit` ends the wait | the test of a refused admission that the next drive admits, "expected 0, found 1"; both TLS tests of a wait trip an assertion of `admit`, "reached unreachable code", `test-io` | CAUGHT |
| TS8 | a lookup that begins to wait is not counted | `wait` counts the lookup | seven tests: five trip the assertion of `unwait` on the count, "reached unreachable code"; the test of a slot pending and the TLS test of a reset, "expected 1, found 0", `test-io` | CAUGHT |
| TS9 | a lookup waits while every slot holds a lookup | `pending` reads no slot that a lookup uses | five tests: the test of each slot held by a lookup, "expected error.AllServersFailed, found null"; the test of a connect that a lookup is on, "expected error.AllServersFailed, found error.Timeout", `test-io` | CAUGHT |
| TS10 | the replay writes a lookup that waits as one on no connection | the trace's `cw` | the short walks, at walk 41 | CAUGHT |
| TS11 | the model's engine finds no slot pending, as the engine did until 2026-10-18 | the model's `Pending` | TLC's check "slot waited for" on `mutants/TS11`, over TLS, `zig build tla` | CAUGHT |
| TS12 | the model's pending slot is only a connection that closes | the model's `Pending` | TLC's check "slot waited for" on `mutants/TS12`, over TCP, `zig build tla` | CAUGHT |
| TS13 | the model's drive admits no lookup that waits | the model's `Admit` | TLC's check "waits for no free slot" on `mutants/TS13`, over TCP, `zig build tla` | CAUGHT |
| TS14 | in the clear, a lookup closes a connection that no lookup is on while a slot is pending | `make_pending` waits for a pending slot | the test of a slot pending and a connect that no lookup is on: its check that the other connect is still in flight fails, `test-io` | CAUGHT |
| TS15 | in the clear, a lookup closes a connection that a lookup is on while its connect is in flight | `make_pending` passes over a slot with a lookup | the test of a connect that a lookup is on: "expected error.AllServersFailed, found null"; the test of each slot held by a lookup trips an assertion of `make_pending`, "reached unreachable code", `test-io` | CAUGHT |
| TS16 | a lookup whose socket or connect is refused waits while a slot is pending | `want` waits only for want of a slot | the TLS test of a refused connect while a slot is pending: "expected 0, found 1", `test-io` | CAUGHT |
| TS17 | a lookup that the drive's end cannot place stops its wait | `admit` keeps the wait | seven tests: the test of a connect that hangs, "expected null, found error.Timeout". The lookup leaves the wait at the end of the drive in which it began, `test-io` | CAUGHT |
| TS18 | the model's `FreeConn` closes no connect, as in the first form | the model's `FreeConn` in the clear | TLC's check "slot waited for" on `mutants/TS18`, over TCP, `zig build tla` | CAUGHT |

TS3's edit and TS4's row changed after the review. `pending` now reads a closed slot and its
borrow on one line, and the slot of an unused connect is no kind of pending slot. TS4 now breaks the
close that makes such a slot pending.

LC33 was written again, since its edit named the code of `want`. It tells a lookup that its
connection is up before it fails it, where no slot is free and none is pending. Three tests catch
it, the test of each slot held by a lookup among them: "expected .connect, found .stream",
`test-io`. `CAUGHT`.

The 80 rows that the walks catch ran again against the new walks, and each is `CAUGHT` (What ran
after the review, above).

Eighteen mutations, eighteen `CAUGHT`.

## A query's send lends the records buffer

2026-10-18. The review of the section before found a possible defect of the engine by a read of the
code alone. The owner ruled on the same day: prove it, and fix it if it is real. It is real, over
TLS alone. docs/design.md §16 decision 47 records the fix with the alternatives that it beats.
§21's TLS rule 3 holds the rule, and the stream's rule 12 names the slot that it makes pending. The
lookup model does not change. The engine model in TLA+ does.

### What the code did

The line numbers in this part are those of 7b12c41.

Over TLS each send of a connection reads the connection's records buffer, `tls.out`:

- A query's send. `submit_rest` names the query's table slot in its `user_data`, as `tcp_send`
  (`io/io_tcp_queue.zig:58-71`). `rest_of` hands the loop `tls.pending`, the query's sealed
  records in `tls.out` (`io_tcp_queue.zig:75-76`, `io/io_tls.zig:334-339`). The lookup's own send
  buffer is read only by `seal`, which gives the query to the session (`io_tls.zig:291-308`).
- A send of the session's own records. These are its handshake flights, the records that it makes
  of its own accord, the fatal alert of `refuse`, and a `close_notify`. Each is an entry
  `ring.records` of the queue, which `make_records` seals into `tls.out` (`io_tls.zig:270-288`).
  Its `user_data`, `tls_send`, names the connection slot and the opening.

The marks of a lent buffer:

- `send_in_flight` marks the lookup's own send buffer. `lend` sets it when the query joins the
  queue, and the send's event clears it (`io/io_send.zig:90-94`, `:119-122`).
- `records_in_flight` marked the records buffer. `submit_rest` set it only for an entry of the
  session's records (`io_tcp_queue.zig:70`). `on_records_event` cleared it, of whichever opening
  (`:122-123`).
- `connect_in_flight` marks the address of a connect, until the connect's event.
- `borrowed` read the last two (`io/io_tcp.zig:91-93`).

A failure while a send is in flight: `fail` tells each lookup on the connection, and calls `shut`
(`io_tcp.zig:359-382`). `shut` cancels the connection's one handle, a connect or a receive. A send
keeps no handle. `release_all` gives back the buffer of each query that waits, but not that of the
send in flight (`io_tcp_queue.zig:191-200`). `restart` resets each field but the opening's count,
the marks, the address, the frame, the queue's entries and the records' octets. So `sending`
became false, and `out_head` and `out_tail` became 0.

A slot was free when it was closed and `borrowed` was false (`free_slot`, `io_tcp.zig:205-218`).
The rule of 7b12c41 counts a slot as pending when its connection closes, or when it is closed and
`borrowed` is true (`io/io_tcp_wait.zig:19-25`).

The model at 7b12c41 held the same gap. `Borrowed` read a connect and a `sendRecords` of the slot
(`spec/tla/engine/EngineTable.tla:347-348`). A query's send is `Op("send", l)`, whose target is the
table slot, and it named no connection. "buffers lent" held one send for each lookup's buffer, and
"one send a stream" one send for each queue. No check read the records buffer of a closed slot.

Over plain TCP a query's send reads the lookup's own buffer (`rest_of`). `send_in_flight` keeps it
lent past the connection, and `release_all` keeps the one in flight. The event of a send whose
connection is gone gives it back (`on_send_event`). A new opening of the connection slot writes
no lookup's buffer. A next send of the same lookup is held in `held_buffers` until the buffer comes
back (`ask`, `io_send.zig:42-56`). So plain TCP holds the bound, and a new test shows it.

### The sequence

Over TLS, with one server and one slot:

1. The connection is up. A lookup's query is sealed into `tls.out` from offset 0, and its send is
   in flight. `records_in_flight` stays false.
2. The peer resets the connection before the send ends. `fail` shuts the connection, and the slot
   is closed with `borrowed` false.
3. The lookup hears `on_tcp_failed`, and its second pass asks for a stream in the drive of the same
   event. `free_slot` takes the slot, and `connect` opens it again.
4. At the connect's event, `begin` starts the new session. `make_records` calls `take_out`, which
   writes the hello into `tls.out` from offset 0.
5. The query's send event comes later. Until then the loop may read the octets that it was lent.

The test of the twin holds the send's event back, and reads the octets that the send was lent.
Before the fix their first five changed:

- lent: `17 03 03 00 82`, the header of an application data record of 130 octets;
- read after the hello: `16 03 03 00 01`, the header of a handshake record of 1 octet, then `00`.

So from step 4 the loop reads the hello's record, and then 129 octets of the query's record. A peer
that reads them takes the first five of those octets for the header of the next record. The twin's
send takes its octets when it is submitted, so no wrong octet reached the twin's server. rotor's
contract lets the loop read them until the send's final event (rotor decision 5, rule 3).

### The design and the model

- Each send from the records buffer marks the slot, a query's send and a send of the session's own
  records. `records_send` replaces `records_in_flight`, and names the send: the query's table slot,
  or `ring.records`. `submit_rest` sets it over TLS, and only the send's final event clears it.
- A query's send keeps its `user_data`. Its event finds the slot that it read by the mark, after
  its connection closed too (`records_back` in `io_tcp_queue.zig`).
- `borrowed` reads the mark, so a closed slot whose buffer a query's send reads is not free. It is
  pending, and a lookup that finds no free slot waits for it (the stream's rule 12).
- `take_out` asserts that the buffer is not lent to a send of another opening before it writes
  (`writable` in `io_tls.zig`, named `lent_to_head` until the review). `submit_rest` asserts that
  no send reads the buffer when it starts one. `on_send_event` asserts that a send over TLS read
  its own connection's buffer. It also asserts that a slot whose connection closed during the send
  is still closed at the send's event.
- The connection does not grow: an optional `u16` takes the room of the flag and its padding. A
  connection is 67,960 octets in the clear and 106,600 over the twin's TLS, before and after.
- The model gives each operation `buffer`, the connection slot whose records buffer it reads.
  `Borrowed` reads it, and the check "records lent" holds the rule (spec/README.md). `mutants/TB5`
  puts back `Borrowed` as it was. TLC finds "records lent" broken at the seventh state of its
  counterexample.

No named limit and no entry point change. `Connection` is the engine's own type, and no consumer
reads its fields.

### The tests, before the code

The test of the defect came first, `io_tls_failing_test.zig`: a second pass waits for a closed slot
whose query's records the loop still holds. One server and one slot over TLS. The connection is up
with a query's send in flight, and the peer resets it. The test holds that send's event back, steps
the twin until the slot's connection handshakes again, and reads the octets that the send was lent.
On 7b12c41 it failed at that read, after 174 tests passed: "slices differ. first difference occurs
at index 0 (0x0)". Of the 135 octets, `17 03 03 00 82` had become `16 03 03 00 01`. With the fix
the slot stays closed and borrowed, and the lookup waits. The send's event gives the buffer back,
the drive's end admits the lookup, and the server answers it on a new connection.

One test came with the code, `io_tcp_test.zig`: a new opening in the slot of a connection that
failed mid-send writes none of that send's octets. In the clear the next server's connection takes
the slot at once. The first lookup's next query waits, held, until the send's event, and the
octets that the send was lent stay as they were. It shows the bound over plain TCP, and passes on
7b12c41 as after the fix. `step_holding`, which holds an event back, is shared by both tests.

### What ran on the first form

- The test of the defect on 7b12c41: it failed, as above. Then the model, then the code, then
  `zig build test-io`: 176 tests pass, the two new ones among them. The test of plain TCP passes
  on a copy of 7b12c41 too.
- `zig build tla` over each configuration and mutant, the nightly ones among them: 15
  configurations hold, and 38 mutants are violated, TB5 among them. It took 2 hours 29 minutes
  while other work ran. Three configurations over TLS changed their counts (spec/README.md):

  | Configuration | Before | Now |
  | --- | --- | --- |
  | `Engine_tls_1_2_bound_2_1` | 294,898 | 297,743 |
  | `Engine_tls_1_2_bound_3_1` | 11,259,959 | 11,165,668 |
  | `Engine_tls_2_2_bound_2_1` | 28,446,316 | 28,696,711 |

  Each other configuration holds the states that it held before.
- `zig build tla -- walks 1 10 41`, the short walks: none changed.
- `zig build tla -- walks 1 2000 201` with the fifteen picks, the full run, 880 MB. The picks did
  not change. 16 of its 26,000 walks changed, all over TLS. In each, a connection failed while its
  query's send was in flight. The model opened the same slot again there before, and now opens the
  other.
- `zig build spec-engine`: the committed short walks and picks are the ones that TLC writes. The
  full run agrees with the engine over 5,226,000 events in 26,000 walks.
- `zig build mutations -- engine --walks` that full run, over the six TB rows of the code and the
  80 rows that the walks catch. Each of the 86 is `CAUGHT`, in 41 minutes. The short walks catch
  each row that they caught before. For each row that they miss, the tool names the same walk as
  before, so the fifteen picks of `engine_picks` in `build/spec.zig` stay.
- ET9 and CR4 were written again, since their edits named `records_in_flight`. Each breaks its
  rule as before, and each is `CAUGHT` by the short walks.
- Each TB row of the code ran by hand once too, its step's output read, and each file put back.
  The texts in the rows below come from there.

On the first form, `zig build test` passed 1,121 tests of 1,121, where 1,119 passed before the
change. `zig build lint` and `zig build examples` passed too.

### What the review found

The review of the change found one fault that had to be fixed, and eight more:

- The model's check "records lent" read `buffer`, which only `SendFrom` writes, and TB5 replaces
  only `Borrowed`. A mutant that puts back the `Pump` of 7b12c41 held under TLC, over 294,898
  states, the count before the change. So the model did not require that a query's send lends the
  buffer. Now the check also requires that each operation names the buffer that it reads.
  `mutants/TB8` is that mutant, and TLC finds "records lent" broken at its sixth state.
- TLS rule 3 grew to eleven sentences, and two paragraphs of §16 decision 47 to seven and eight.
  The rule now lists its two kinds of send, and its history is in the decision alone. The two
  paragraphs are split.
- Three new lines of prose passed 100 columns. They are wrapped now.
- The stream's rule 12 names a query's send in its list, but did not cite decision 47. It does now.
- No committed walk drove the new path, so the replay of the gate never compared the model and the
  code there. TB9 breaks the engine as TB4 does, and the walks must catch it. The full run caught
  it first at walk 16271, which is the sixteenth pick now (spec/README.md).
- `lent_to_head` was true when no send read the buffer, so its name said the opposite of its doc.
  It is `writable` now. `take_out` also asserts that a write goes behind the records of the head's
  send. And it asserts that records move to the buffer's start only while no send reads them.
  TB12 found no test that made records while a send from inside the buffer was in flight, so a
  test does now.
- `records_back` had no assertion. It now asserts the slot that it is handed, and that one
  connection slot alone holds a lookup's mark. The review also asked for a guard that skips the
  scan in the clear. That guard is wrong. A `reinit` from TLS to the clear may come while a query's
  send is in flight. The guard would then leave that send's mark for ever, and the slot would never
  free. Decision 47 rejects the guard, and TB11 puts it in.
- No test covered a `reinit` while a query's send over TLS is in flight. A test does now, once to
  TLS and once to the clear, and TB10 breaks what it covers.
- Decision 47 did not say what bounds the wait. Nothing in the engine does. A send keeps no
  handle, so a send that stalls after its connection failed keeps its slot pending until the loop
  ends it. The decision says so now, beside §17 question 55.

### The tests after the review

- `io_tls_failing_test.zig`, a second pass opens the other slot while a query's send reads the
  first one's records. One server and two slots over TLS. The peer resets the first connection
  while a query's send is in flight, and the second pass connects in the other slot at once. Its
  query waits, held, until the send's event. It is the twin's form of walk 16271.
- `io_tls_failing_test.zig`, records the session makes while a send is in flight go behind it,
  and move none of it. It came after TB12 was `NOT CAUGHT`. The session makes records during a
  query's send, and again during the send of those records, which starts inside the buffer. The
  octets in flight stay where they were.
- `io_lifecycle_test.zig`, a reinit keeps a slot whose records a query's send reads until that
  send's event. The caller cancels each lookup and calls `reinit`, once to TLS and once to the
  clear. The slot stays closed and lent, and a new lookup waits for it. The send's event frees it.

Each test covers code that the change made right already, so none failed against the code. Two
faults of the tests themselves came out at their first run. A `reinit` needs the cancelled lookup
taken twice, and the second connection may still send its own records once it is up.

One check ran by hand, with TB14 applied. The test of the other slot was changed in place to wait
for the second connection's send, with its checks of the wait taken out. Then the first send's
event tripped the assertion of `records_back` that one slot lends to a lookup: "reached
unreachable code" at `io_tcp_queue.zig:138`. The test as committed catches TB14 before that, at
its check that the query waits. The file was put back.

### What ran after the review

- `zig build tla -- spec/tla/engine/mutants/TB8.cfg` on the check as it was: "expected violated,
  found holds", over 294,898 states. On the check with its second part, TB8 is violated after 771
  distinct states and TB5 after 1,869. `Engine_tls_1_2_bound_2_1` holds 297,743 states, as before
  the review. TLC by hand finds "records lent" broken at the sixth state of TB8 and at the seventh
  of TB5.
- `zig build tla -- walks 1 10 41` writes the octets of `engine_gate.txt`. `zig build tla -- walks
  1 2000 201` writes the full run of the first form, octet for octet by SHA-256. So the second
  part of the check changes no walk.
- `zig build mutations -- engine --walks` that full run, TB9 alone: `NOT CAUGHT`, as it must be.
  The short walks and the picks missed it, and the full run caught it at walk 16271. That walk
  joined `engine_picks` in `build/spec.zig`, and `engine_picks.txt` holds the sixteen walks.
- Each new TB row of the code ran by hand once, its step's output read, and each file put back.
  TB1 to TB4, TB6 and TB7 ran by hand again, since the new tests catch them too. The texts in the
  rows below come from there.
- `zig build mutations -- engine --walks` that full run, over the eleven TB rows of the code and
  the 81 rows that the walks catch, TB9 among them. Each of the 92 is `CAUGHT`, in 1 hour 16
  minutes while other work ran. The short walks catch each row that they caught before. For the
  rows that they miss, the tool names the sixteen picks, and the picks catch TB9 at walk 16271.
- `zig build spec-engine`: the committed short walks and the sixteen picks are the ones that TLC
  writes. The full run agrees with the engine over 5,226,000 events in 26,000 walks. It took 14
  minutes 41 seconds while other work ran.
- `zig build tla` over each configuration and mutant, the nightly ones among them: the 15
  configurations hold and the 39 mutants are violated, as each header expects. TB5 and TB8 are
  among the 39. The run took 5 hours 43 minutes, from 2026-10-19 to 2026-10-20.

Over the final tree:

- `zig build test`: 1,124 tests pass of 1,124, the three new ones among them.
- `zig build lint`: each function scores 15 or less.
- `zig build examples` builds each example.
- The live checks and the interop check need the network or dnsproxy, and did not run.

### The instruction counts

`bench/count.zig` imports `cocuyo` and `wire` alone, and no counted case runs the engine. This
change touches no file under `src/`. So no count can move, and `bench/instructions.zon` did not
change.

### The rows

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| TB1 | a query's send over TLS marks no records buffer, as until 2026-10-18 | `submit_rest` marks each send over TLS | 23 tests over TLS trip the assertion of `on_send_event` that a send read its own connection's buffer: "reached unreachable code"; three tests fail, the test of the defect among them, "slices differ", and the test of a reinit, "expected 0, found null", `test-io` | CAUGHT |
| TB2 | a query's send event leaves its records buffer lent | `records_back` clears the mark | 23 tests over TLS crash, 21 of them at the assertion of `take_out`: "reached unreachable code"; three tests fail, the test of the defect at its check that the mark is gone among them, `test-io` | CAUGHT |
| TB3 | a closed slot whose records a query's send reads is free, as until 2026-10-18 | `borrowed` reads the mark of a query's send | the test of the defect and the test of the other slot trip the assertion of `take_out` when the new opening writes its hello: "reached unreachable code"; the test of a reinit, "expected 1, found 0", `test-io` | CAUGHT |
| TB4 | as TB3, and no assertion guards the records buffer | the test reads the octets that the send was lent | three tests: the test of the defect, "slices differ. first difference occurs at index 0 (0x0)"; the test of the other slot, at its check that the second connection is up; the test of a reinit, "expected 1, found 0", `test-io` | CAUGHT |
| TB5 | the model's `Borrowed` reads no query's send, as until 2026-10-18 | the model's `Borrowed` | TLC's check "records lent" on `mutants/TB5`, over TLS, at the seventh state of its counterexample, `zig build tla` | CAUGHT |
| TB6 | a new opening forgets that a send reads the slot's records buffer | `restart` keeps the mark | six tests: the test of a reset slot, "expected 3, found null"; the test of a reinit, "expected 0, found null"; the test of the defect, "slices differ"; three more TLS tests of a slot that the loop holds, `test-io` | CAUGHT |
| TB7 | a closed slot whose records a query's send reads is not pending | `pending` reads the mark | the test of the defect and the test of a reinit: "expected 1, found 0", `test-io` | CAUGHT |
| TB8 | the model's `Pump` names no buffer for a query's send, as until 2026-10-18 | "records lent" requires that each operation names the buffer that it reads | TLC's check "records lent" on `mutants/TB8`, over TLS, at the sixth state of its counterexample, `zig build tla`. On the check before the review TLC found no error | CAUGHT |
| TB9 | as TB4, against the walks | the replay of a walk in which a connection fails during a query's send | the picked walks, at walk 16271 | CAUGHT |
| TB10 | a reinit writes each connection whole, its mark among it | `close_all` keeps the mark through `restart` | the test of a reinit: "expected 0, found null", `test-io` | CAUGHT |
| TB11 | a query's send event looks for its mark only over TLS, the guard that the review asked for | `records_back` reads each slot whatever the engine speaks | the test of a reinit, in the clear, at its check that the slot connects after the send's event, `test-io` | CAUGHT |
| TB12 | the records move to the buffer's start while a send reads them | `take_out` moves records only while no send is in flight | the test of records made during a send trips the new assertion of `take_out` before the move: "reached unreachable code", `test-io`. Before that test no test caught it | CAUGHT |
| TB13 | a sealed query leaves the buffer's tail in front of its records | `seal` moves `out_tail` behind the query | the test of records made during a send trips the new assertion of `take_out` that a write goes behind the head's records; 25 tests over TLS trip the assertion of `sent_through`: "reached unreachable code", `test-io` | CAUGHT |
| TB14 | a lookup's next query goes out while its send is in flight | `ask` holds the next send (the stream's rule 6) | three tests: the test of plain TCP and the test of the other slot, at their checks that the query waits; the test of `reinit` in the clear trips the assertion of `finish`, "reached unreachable code", `test-io` | CAUGHT |

TB4 removes both assertions that guard the buffer, the one of `take_out` and the one of
`submit_rest`. So it shows that the test of the defect reads the overwrite itself, and catches the
defect with no assertion. TB9 has the same edits, and shows that the replay of walk 16271 catches
it too.

The 80 rows that the walks catch ran again against the full run and the sixteen picks, beside
TB9, and each is `CAUGHT` (What ran after the review, above).

Fourteen mutations, fourteen `CAUGHT`.

## colibri v0.8.0

2026-10-20. The owner ruled that cocuyo moves its pin of colibri from v0.6.0 to v0.8.0. The move
does c4milo/cocuyo#47, and finishes c4milo/cocuyo#44. docs/design.md §16 decisions 29, 32, 33
and 41 record what changed, and §17 questions 51 and 52 are done. §17 question 56 asks the owner
what a session states of the CPU, and question 57 asks about the QUIC version a session names.

### What the move changed

- `build.zig.zon` pins colibri v0.8.0, at 7496cdc, by the hash that `zig fetch` wrote.
- `cocuyo_doh` hands colibri a `client.Request` and a `client.Response` in place of a
  `client.HttpExchange` (colibri's decision 124). It hands the channel one `client.Config`. The
  channel builds the TLS configuration of each transport, and draws QUIC's grease value and
  connection IDs (decision 120).
- Each root exports a type under its own name (decisions 115 and 121). So
  `client.channel.Address` is `client.Address`, and the channel's other types change the same way.
- Each TLS value takes `cpu`, which has no default. The DoT, DoQ and DoH sessions state nothing,
  so each hello offers TLS_CHACHA20_POLY1305_SHA256 alone. Before v0.8.0 colibri chose AES-GCM
  from the build target.
- colibri's suite names the QUIC version of each packet (decision 108). A client lists version 2
  first, and colibri's server switches it to version 2 (decision 111). The plain suite of
  `io/io_quic_plain.zig` refuses a switch to version 2, and colibri drops the packet that asks
  for it. No packet on the twin asks for one.
- A ticket names the QUIC version of its connection, and a session that resumes with it starts
  in that version. Since the review each connection of `cocuyo_quic` starts in the version its
  session names, `original_version`.
- colibri sends a GET again, once, on another connection, when its connection closes before any
  octet of the response (decision 124, ruling 3).
- The DoH test servers run on `server.Endpoint`, and route each GET through `server.router`
  (decisions 119, 121 and 122). c4milo/cocuyo#47 calls the router `server.routes`. colibri
  renamed it on 2026-10-14, before v0.8.0.
- `io/io_doh_channel_server_raw.zig` is a third test server. It writes its own octets over
  colibri's TLS record server.

No file under `src/` changed, and no file of the engine changed. In `cocuyo_quic` the plain suite
changed, one name in two files, and, after the review, the version a connection starts in.

### The two holds

- **A long head or trailer section over HTTP/1.1.** A test of `io_doh_channel_read_test.zig`
  sends heads of 20,000 and 32,768 octets. Its records leave 17,384 or 32,767 octets of a head in
  colibri before a full record. On v0.8.0 each exchange ends with its answer. The test also ran on
  a copy of the tree at 9d94399, with colibri v0.6.0. There it fails in `deliver`: "expected 0,
  found 1". A whole record stayed in the type's buffer after a read. Each of the two heads fails
  alone too. Since the review a second test sends a trailer section of 24,000 octets, and a
  second response after it. Its records leave 17,000 octets of the trailer section in colibri
  before a full record. That is the shape of the heads' cases, past the 16,632 octets that v0.6.0
  held beside a full record. This test did not run on v0.6.0: the disk had too little room for a
  second copy of the tree.
- **A KeyUpdate that asks for a reply.** No test of cocuyo's sends one. chapulin's record mode
  starts no KeyUpdate: colibri's `src/tls/record/record_provider.zig` answers
  `initiate_key_update` with `error.Unsupported`. So neither colibri's server nor its `tls` can
  send one. colibri's own tests show the fix over a provider that protects nothing:
  `connection_records_test.zig` of its client and of its server, at its commit 5368f5b. colibri
  still owes two replies at most, `tls.constants.key_update_replies_max`, and a third request
  fails the read (its `record_keylog_test.zig`). RFC 9846 §4.7.3 forbids a server that request.

### The rows of the files that the move changed

- DC9, DC13, DC23, LM45 and LM46 edited code that named `exchange`. Their edits now name
  `response`, and each applies once. The edit of DC23 keeps the assertion on the response, beside
  the new assertion on the request. No other row needed a new edit.
- 52 rows edit a file that the move changed: TR4, DC1 to DC28, QO12, QO13, QO17, QO18, TC17 to
  TC21, TC24 to TC30, and LM45 to LM51. DS1 to DS4 ran too, since their tests changed. DS1 edits
  `io_doh_channel_constants.zig`, which the move did not change. With the ten CB rows of the first
  form, that is 66.
- CZ24 edits `README.md`, whose prose the move changed. Its edit is a line of the README's Zig
  block, which did not change, and `readme-check` builds that block alone. So CZ24 did not run
  again, and its row stands.
- The first run, of DS1 to DS4 and the CB rows, found DS4 `NOT CAUGHT`. In colibri v0.8.0 the
  protocol reads what a record held before the next record opens. So one pass of the read opens
  each whole record of the stream, and no run of the test made a second pass.
- A pass that takes octets and says nothing still comes before more octets in one case. The type
  holds a datagram and the stream apart, and `next` hands colibri the datagram first. A new test
  of `io_doh_channel_read_test.zig` hands the type a datagram of zeros before each chunk. colibri
  takes it whole and says nothing of it, so the read must go on to the stream. The test catches
  DS4: "expected 0, found 5".

### What ran on the first form

- `zig build mutations -- engine` over the 66 rows ran after it ran each check once with nothing
  mutated. Each of the 66 is `CAUGHT`, in 27 minutes. The run was on a copy of the working tree,
  with a cache of its own in a scratchpad directory. The disk had less than 20 GB free, and that
  cache went after the run. The copy held the tree's code. After the run only comments changed.
- Each CB row and DS4 ran by hand once more on that copy, to read its step's output. The texts in
  the rows below come from there.
- `zig build test`: 1,130 tests pass of 1,130, six of them new.
- `zig build lint`, `consumer-check` and `examples` pass.

### What the review found

The review of the first form found four faults to fix, and eight to consider:

- A DoQ session that resumed with a ticket of QUIC version 2 stopped the program. colibri's
  `tls.quic.Client` started in the ticket's version, and colibri's connection started in version
  1, its default. The first send then failed chapulin's assertion that the two agree
  (`quic_suite.zig`, `protect`). The test of a ticket named version 1, so no test met it.
- A comment of `io_quic_plain.zig` cited RFC 9369, which `docs/rfcs/` does not hold. It also said
  that a refused switch keeps the connection in version 1. In colibri v0.8.0 a refused switch
  drops the packet, and the twin stays in version 1 because no server asks for a switch.
- Three comments cited RFC 9846 §4.1.2 for a ClientHello. In RFC 9846 the ClientHello is §4.2.2.
  Nine older comments of the same files used RFC 8446's numbers too: §4.6.1, §4.6.2 and §4.2.11.
  They now cite RFC 9846's §4.7.1, §4.7.2 and §4.3.11.
- The design named no resend of a GET (colibri's decision 124, ruling 3).
- The ones to consider:
  - colibri's least memory for a TCP transport (its decision 124, ruling 5);
  - the bound of two KeyUpdate replies, and the state in which h2 reads no more;
  - the 405 of the test servers, and the POST route of c4milo/cocuyo#47;
  - CZ24 and DS1 in the list above;
  - prose, and copies in the tests;
  - the QUIC hello of the DoH channel, and a long trailer section;
  - what the commit must not close.

### The tests, before the code, after the review

- `io/io_chapulin_quic_resume_test.zig` runs a server of colibri's QUIC over chapulin in memory,
  under the test identity. It selects `doq`, issues a ticket, and switches the client to version
  2. The client's first connection runs on version 2, and its ticket names version 2. The next
  connection resumes with that ticket. Before the fix its first send stopped the program:
  "reached unreachable code" at `quic_suite.zig:166`, in `test-chapulin-quic`.
- A test of `io/io_quic.zig` reads the Version field of a connection's first Initial, over
  `Plain` and over a session that names version 2. Before the fix the second was version 1:
  "expected 1798521807, found 1", in `test-cocuyo_quic`.
- A test of `io_doh_channel_start.zig` reads the suites of the hello that the QUIC link's TLS
  configuration writes: ChaCha20-Poly1305 alone.
- The test of the DoH channel over QUIC requires that its ticket names version 2.
- The trailer test of the holds, above.
- Assertions in `start` (`io_doh_channel_start.zig`) hold the type's sizes to colibri's
  `stream_output_len_min` and to its room, `plaintext_in_len`, at each start of a channel.

### What ran after the review

- `zig build test`: 1,134 tests pass of 1,134, four of them new. `zig build lint`, `fmt`,
  `consumer-check` and `examples` pass. `test-cocuyo_doh` has 32 tests pass of 32,
  `test-cocuyo_quic` 13 of 13, `test-chapulin` 11 of 11, and `test-chapulin-quic` 13 of 13.
- CB11 ran when the tests above failed, since the code before the fix is CB11's edit.
- On 2026-10-20 the owner's session deleted the main tree's build cache, 42 GB that a build
  makes again, and the disk then had 50 GB free. Then this command ran over the 30 rows: CB11 to
  CB15, the rows that edit a file the review changed, and DS1 to DS4.

```sh
zig build mutations -- engine CB11 CB12 CB13 CB14 CB15 QS1 QS2 QS3 TC21 TC22 TC23 TC25 TC26 \
    TC27 QO12 QO13 QO17 QO18 CB2 CB3 CB8 DS1 DS2 DS3 DS4 TY36 SB16 SB17 SB18 SB24
```

- 26 of the 30 rows were `CAUGHT`. SB24, DS1, CB14 and CB15 were `NOT CAUGHT`, because the build
  stopped at the review's checks at compile time. The tool reads a compile error as an edit that
  no longer applies. So the three checks moved into `assert_sizes`, which `start` calls first, as
  assertions that stay in the program. Run again, the four rows were each `CAUGHT` by
  `test-cocuyo_doh`, at the assertion in `start`.
- No file of the engine changed, so `zig build spec-engine` did not run, and neither model
  changes.
- The live checks and the interop check need the network or dnsproxy, and did not run.

### The instruction counts

`bench/count.zig` imports `cocuyo` and `wire` alone, and no counted case runs the engine. This
change touches no file under `src/`. So no count can move, and `bench/instructions.zon` did not
change.

### The rows

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| CB1 | the DoT session states the AES instructions and a data-independent timing | the session states nothing of the CPU (§17 question 56) | the test of the hello's suites: "expected 2, found 6", `test-chapulin` | CAUGHT |
| CB2 | the DoQ session states the AES instructions and a data-independent timing | as CB1, over QUIC | the test of the hello's suites: "expected 2, found 6", `test-chapulin-quic` | CAUGHT |
| CB3 | the DoH channel states the AES instructions and a data-independent timing | as CB1, at the channel | the test of the TCP hello's suites: "expected 2, found 6", `test-cocuyo_doh` | CAUGHT |
| CB4 | the DoH channel speaks no HTTP/2, so its TCP connection offers `http/1.1` alone | rule 18's versions | five tests, the test of HTTP/2 among them: "expected 2, found 1"; the test of a reset stream, "expected .reset, found .closed", `test-cocuyo_doh` | CAUGHT |
| CB5 | the DoH channel speaks no HTTP/3, so it opens no QUIC link | rule 18's versions | three tests fail, the test of HTTP/2 among them: "expected .quic, found .tcp"; two tests of the engine crash, `test-cocuyo_doh` | CAUGHT |
| CB6 | the test server's route table has no root, so a GET of the root gets 404 | the server's routes | the test of the longest GET of a template of a query alone: no answer, `test-cocuyo_doh` | CAUGHT |
| CB7 | a test server that is to select no protocol names its versions in ALPN | the server that selects no protocol | the two tests of HTTP/1.1 from a server that selects none: "expected 1, found 2", `test-cocuyo_doh` | CAUGHT |
| CB8 | the plain suite takes a switch to QUIC version 2 | the plain suite speaks version 1 alone | the test of the switch: "expected error.Refused, found void", `test-cocuyo_quic` | CAUGHT |
| CB9 | the assertion that a finished exchange's request is its slot's, inverted | the assertion | each test that finishes an exchange: "reached unreachable code", `test-cocuyo_doh` | CAUGHT |
| CB10 | the assertion that a new exchange's response has no outcome yet, inverted | the assertion | each test that makes a request: "reached unreachable code", `test-cocuyo_doh` | CAUGHT |
| CB11 | a DoQ connection starts in QUIC version 1, whatever version its session names | the connection starts in its session's version (§16 decision 29) | the test of the first Initial's version: "expected 1798521807, found 1", `test-cocuyo_quic`; the resumed DoQ session stops at chapulin's assertion, `test-chapulin-quic` | CAUGHT, by the tests that failed before the fix |
| CB12 | the DoQ session names QUIC version 1, whatever version its ticket names | as CB11, at the session | the resumed DoQ session, `test-chapulin-quic` | CAUGHT |
| CB13 | `Plain` names QUIC version 2, which its suite refuses | the gate's QUIC speaks version 1 alone | the test of the first Initial's version, `test-cocuyo_quic` | CAUGHT |
| CB14 | the DoH channel's output is one octet shorter than colibri's least output | the output holds what `send_stream` owes (colibri's decision 124, ruling 5) | the assertion in `start`, `test-cocuyo_doh` | CAUGHT |
| CB15 | a record's protection adds one octet more than RFC 9846 allows, past colibri's room | colibri's room holds the longest partial unit and one record | the assertion in `start`, `test-cocuyo_doh` | CAUGHT |

DS4 ran again with the new test, as the list above says. The 55 other rows of the files that the
move changed ran again on the first form, and each is `CAUGHT`.

Fifteen mutations, fifteen `CAUGHT`.
