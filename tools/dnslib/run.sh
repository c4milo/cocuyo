#!/bin/sh
# The codec against dnslib's reading of responses real servers sent (tools/dnslib/check.zig,
# c4milo/cocuyo#22). CI's dnslib job runs this; it needs git and the network, once, for 91 KB.
#
#     tools/dnslib/run.sh
#
# It fetches dnslib's repository at the commit below into a directory of its own, requires the tree
# of dnslib/test to be the one below, and runs the check over that directory. The tree id is the
# hash of every file in it, so a fetch that brought anything else stops here. A new pin changes
# both lines, after the new responses have been read.
set -eu

repository=https://github.com/paulc/dnslib.git
commit=e266b75fab4464350346200638dbd08c254b5b01
tree=196e5d6d8ec1f763e980827ed44120a0fe87849d

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

git init --quiet "$work"
git -C "$work" fetch --quiet --depth 1 "$repository" "$commit"
fetched=$(git -C "$work" rev-parse FETCH_HEAD:dnslib/test)
if [ "$fetched" != "$tree" ]; then
    echo "dnslib/test at $commit is tree $fetched, not $tree" >&2
    exit 1
fi
git -C "$work" checkout --quiet FETCH_HEAD -- dnslib/test

cd "$root"
zig build dnslib-check -- "$work/dnslib/test"
