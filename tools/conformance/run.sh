#!/usr/bin/env bash
# hickory-dns's DNSSEC conformance suite against cocuyo (docs/design.md §25 step 17,
# c4milo/cocuyo#59). It needs Docker, a Rust toolchain and the network: the suite, its crates and
# its images' packages are fetched.
#
#     tools/conformance/run.sh [forwarder | resolver | all]
#
# It fetches hickory-dns at the pinned commit and checks the commit's tree id, applies
# cocuyo.patch, which adds `cocuyo` to DNS_TEST_SUBJECT, builds tools/conformance/forward.zig for
# the Docker host's Linux, and runs the suite's tests of the role named, both by default.
#
# Each test must pass, or expected.txt must name it with the reason it fails. A test that the list
# names and that passes fails the run too, so the list stays true. A failure prints the test's
# name; its output is in the results file the run names.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
# hickory-dns's main of 2026-10-30, and the tree id of that commit.
commit=99ab3475c1defea1e6521ef158fa9087837dced9
tree=d3dc5cc83cf3ee89cb32bcdcea687a120a3b34b9

role=${1:-all}
case $role in
forwarder | resolver) filters="$role::" ;;
all) filters="forwarder:: resolver::" ;;
*)
    echo "usage: tools/conformance/run.sh [forwarder | resolver | all]" >&2
    exit 2
    ;;
esac

work=$(mktemp -d)
echo "conformance: working in $work"
mkdir "$work/hickory"
git -C "$work/hickory" init -q
git -C "$work/hickory" remote add origin https://github.com/hickory-dns/hickory-dns
git -C "$work/hickory" fetch -q --depth 1 origin "$commit"
git -C "$work/hickory" checkout -q FETCH_HEAD
got=$(git -C "$work/hickory" rev-parse 'HEAD^{tree}')
if [ "$got" != "$tree" ]; then
    echo "TREE of hickory-dns $commit is $got, not $tree" >&2
    exit 1
fi
git -C "$work/hickory" apply "$here/cocuyo.patch"

# The program runs in the suite's Linux containers, on the Docker host's own architecture.
case $(docker info --format '{{.Architecture}}') in
x86_64 | amd64) target=x86_64-linux-musl ;;
aarch64 | arm64) target=aarch64-linux-musl ;;
*)
    echo "conformance: no Linux target for this Docker host" >&2
    exit 1
    ;;
esac
(cd "$root" && zig build conformance-forward -Dtarget="$target" -Drelease --prefix "$work/out")

results="$work/results.txt"
# shellcheck disable=SC2086 # the filters are words of their own
(cd "$work/hickory/conformance" &&
    DNS_TEST_SUBJECT=cocuyo DNS_TEST_COCUYO_BINARY="$work/out/bin/conformance-forward" \
        cargo test -p conformance-tests -- --include-ignored $filters) >"$results" 2>&1 || true

passed=$(sed -n 's/^test \(.*\) \.\.\. ok$/\1/p' "$results")
failed=$(sed -n 's/^test \(.*\) \.\.\. FAILED$/\1/p' "$results")
if [ -z "$passed$failed" ]; then
    echo "conformance: no test ran; see $results" >&2
    exit 1
fi
# Each line of expected.txt is a test's name, then the reason it fails. `#` starts a comment.
expected=$(sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$here/expected.txt" | awk '{ print $1 }')
listed() {
    echo "$expected" | grep -qxF "$1"
}

broken=0
for name in $failed; do
    if ! listed "$name"; then
        echo "FAILS, and expected.txt does not name it: $name"
        broken=$((broken + 1))
    fi
done
for name in $passed; do
    if listed "$name"; then
        echo "PASSES, and expected.txt names it: $name"
        broken=$((broken + 1))
    fi
done
pass_count=$(echo "$passed" | grep -c . || true)
fail_count=$(echo "$failed" | grep -c . || true)
echo "conformance: $pass_count passed, $fail_count failed, and $broken not as expected.txt says;" \
    "results in $results"
[ "$broken" -eq 0 ]
