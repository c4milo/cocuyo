# Mutations

A test must fail when the code it covers is broken (CLAUDE.md non-negotiable 7). Every check lands
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

## Planned, steps 2 and 3

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
