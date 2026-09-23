#!/bin/sh
# The order a resolver walks the search list in, observed on the wire (docs/design.md §5, §17
# question 7). glibc's and musl's getaddrinfo(3) in containers, c-ares's ares_getaddrinfo, and
# cocuyo's own examples/udp_blocking.zig are each asked the same names against a recorder that
# writes down every question and answers NXDOMAIN unless a case says otherwise.
#
#     tools/search_order/run.sh [cares-prefix]
#
# Needs docker with the ubuntu:24.04 and alpine:3.20 images, and c-ares under the prefix
# (Homebrew's by default). It is not part of the gate; what it showed is recorded in §5.
set -eu

cares=${1:-/opt/homebrew/opt/c-ares}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

case $(uname -m) in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64 | amd64) arch=x86_64 ;;
    *) echo "unknown machine $(uname -m)" >&2; exit 1 ;;
esac

zig build-exe -O ReleaseSafe -target "$arch-linux-musl" -femit-bin="$out/recorder" "$here/recorder.zig"
zig build-exe -O ReleaseSafe -target "$arch-linux-gnu.2.39" -lc -femit-bin="$out/probe-glibc" "$here/probe_libc.zig"
zig build-exe -O ReleaseSafe -target "$arch-linux-musl" -lc -femit-bin="$out/probe-musl" "$here/probe_libc.zig"
zig build-exe -O ReleaseSafe -femit-bin="$out/recorder-host" "$here/recorder.zig"
zig build-exe -O ReleaseSafe -lc -lcares -I"$cares/include" -L"$cares/lib" \
    -femit-bin="$out/probe-cares" "$here/probe_cares.zig"
(cd "$root" && zig build examples -Dtarget="$arch-linux-musl" -Drelease --prefix "$out/examples")

search="a.test b.test"
host_port=15353

# One library and one case in a container: its resolv.conf, the recorder on port 53, the probe.
in_container() { # image probe ndots name rules
    docker run --rm -v "$out:/probe:ro" "$1" sh -c "
        printf 'nameserver 127.0.0.1\nsearch $search\noptions ndots:$3 attempts:1 timeout:1\n' > /etc/resolv.conf
        /probe/recorder 53 $5 &
        sleep 1
        $2 $4 || true
        kill \$! 2>/dev/null || true
    " 2>&1
}

# c-ares on this machine, given the same server, search list and ndots as options.
c_ares() { # ndots name rules
    # shellcheck disable=SC2086
    "$out/recorder-host" "$host_port" $3 2>&1 &
    recorder=$!
    sleep 1
    # shellcheck disable=SC2086
    "$out/probe-cares" "$host_port" "$1" "$2" $search 2>&1 || true
    kill "$recorder" 2>/dev/null || true
    wait "$recorder" 2>/dev/null || true
}

run_case() { # title ndots name rules
    printf '\n== %s: %s, ndots %s, search %s\n' "$1" "$3" "$2" "$search"
    printf -- '-- glibc, ubuntu:24.04\n'
    in_container ubuntu:24.04 /probe/probe-glibc "$2" "$3" "$4"
    printf -- '-- musl, as zig links it\n'
    in_container alpine:3.20 /probe/probe-musl "$2" "$3" "$4"
    printf -- '-- c-ares\n'
    c_ares "$2" "$3" "$4"
    printf -- '-- cocuyo, examples/udp_blocking.zig\n'
    in_container alpine:3.20 /probe/examples/bin/udp-blocking "$2" "$3" "$4"
}

run_case "no dot" 1 host ""
run_case "fewer dots than ndots" 2 host.sub ""
run_case "as many dots as ndots" 1 host.sub ""
run_case "absolute" 1 host.sub. ""
run_case "NODATA on the first candidate" 1 host "nodata:host.a.test"
run_case "SERVFAIL on the first candidate" 1 host "servfail:host.a.test"
run_case "an answer on the second candidate" 1 host "answer:host.b.test"
