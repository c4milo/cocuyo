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
`zig build test-resolver`. Five mutations, five `CAUGHT`.

| # | Mutation | Check it breaks | Caught by | Status |
| --- | --- | --- | --- | --- |
| H1 | the hosts table is never consulted | `Config.lookups` | the table-first test | CAUGHT |
| H2 | the sources are tried in the order they are written | `Config.lookups` | the DNS-first test | CAUGHT |
| H3 | a failure ends the walk rather than trying the next source | §19 step 14 | the DNS-first test | CAUGHT |
| H4 | a cancel is answered by the next source | §19 step 14 | the cancel test | CAUGHT |
| H5 | the question is built for a name rather than an address | `Question.from_address` | the PTR question test | CAUGHT |

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

## The build's own mutation

`zig build lint` runs the rules twice: over the tree, which must be clean, and over a canary tree
written into the build cache that holds one violation of every rule, which must exit 1 and name
each rule on stdout. A clean tree cannot show that a rule is live — a run that dropped a rule
passes a tree that rule would have passed anyway. The canary is the mutation, and it is wired into
`build/lint.zig` rather than recorded here, because it runs on every build.

`zig build graph-check` is the same idea for the module graph: it compiles a fixture that imports
`config` from a module of the `resolver` shape and requires the compiler to reject it, with a
positive control importing `core` that must compile, so a failure means what it says.
