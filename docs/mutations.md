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
since the baseline runs builds. Ten mutations: eight `CAUGHT`, EM4's line removed, and EM8 shown
by the run.

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
and `zig build lint`. FL3 is `NOT CAUGHT`, as dropping any other directory from the lint's list
is: a clean tree holds nothing for the dropped directory to find. Issue #12 asks for the check
that would catch it. Four mutations, three `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| FL0 | a model grows past 500 lines | the length limit | `zig build lint`, naming the file | CAUGHT |
| FL1 | the rule leaves `.lean` files unread | a model is bounded | the models' fixture test | CAUGHT |
| FL2 | the rule's scope leaves `spec/` out | a model is bounded | the models' fixture test | CAUGHT |
| FL3 | the lint walks no directory under `spec/` | a model is bounded | nothing: **the list of directories is checked by nothing, issue #12** | NOT CAUGHT |

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
so it needs two servers. Every new check is caught by one mutant at least. Eleven mutations,
eleven `CAUGHT`.

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

Design §24 step 5, 2026-09-25. `io/io_quic_template.zig` splits a DoH server's template into the
authority and the path's template, and expands the path with `dns`, the one variable defined.
Three checks were `NOT CAUGHT` at first. UT8 was a refusal of the `#` operator that nothing
needed: a character that is not an operator is read as a varname's, and `#` is none, so the
refusal was removed and UT8 became the operator table gaining `#`. UT18 and UT19 had no test, and
now each has one. Broken against `zig build test-cocuyo_quic`. Twenty mutations, twenty `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| UT1 | any scheme is taken | DoH is https alone (RFC 8484 §5) | the authority refusals | CAUGHT |
| UT2 | the scheme is compared by case | schemes are case-insensitive (RFC 3986 §3.1) | the case and port test | CAUGHT |
| UT3 | the host's characters are not checked | no userinfo (RFC 9114 §4.3.1), no IP literal | the authority refusals | CAUGHT |
| UT4 | an IPv4 address is taken as a host | the session checks a name (RFC 3986 §3.2.2) | the authority refusals | CAUGHT |
| UT5 | a port's characters are not checked | `port = *DIGIT` (RFC 3986 §3.2.3) | the authority refusals | CAUGHT |
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
