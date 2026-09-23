#!/bin/sh
# The rotor example resolves where io_uring is refused, over rotor's epoll fallback. CI runs this;
# it needs docker and the alpine:3.20 image. Offline: tools/search_order/recorder.zig answers the
# one name asked, inside the container, so no run depends on the network.
#
#     tools/epoll_check/run.sh
#
# Two runs, each of which must resolve. Under Docker's default seccomp profile, the realistic case,
# which refuses io_uring on current Docker. Under a profile that refuses every io_uring call
# outright, so the epoll path is taken whatever the default allows; before that run, a probe must
# see io_uring refused, or the run proves nothing.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

case $(uname -m) in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64 | amd64) arch=x86_64 ;;
    *) echo "unknown machine $(uname -m)" >&2; exit 1 ;;
esac

(cd "$root" && zig build examples -Dtarget="$arch-linux-musl" -Drelease --prefix "$out")
zig build-exe -O ReleaseSafe -target "$arch-linux-musl" -femit-bin="$out/recorder" \
    "$root/tools/search_order/recorder.zig"
zig build-exe -O ReleaseSafe -target "$arch-linux-musl" -femit-bin="$out/uring_probe" \
    "$here/uring_probe.zig"
printf '%s' '{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[{"names":["io_uring_setup","io_uring_enter","io_uring_register"],"action":"SCMP_ACT_ERRNO","errnoRet":1}]}' \
    > "$out/no-io-uring.json"

# The example asks the recorder for example.test and must print the one answer the recorder gives.
resolve() { # label [docker options...]
    label=$1
    shift
    log=$(docker run --rm "$@" -v "$out:/w:ro" alpine:3.20 sh -c '
        printf "nameserver 127.0.0.1\n" > /etc/resolv.conf
        /w/uring_probe
        /w/recorder 53 answer:example.test 2>/dev/null &
        sleep 1
        /w/bin/udp-rotor example.test
    ' 2>&1) || true
    printf '%s\n%s\n' "== $label" "$log"
    printf '%s' "$log" | grep -q "example.test A 192.0.2.1" || {
        echo "the rotor example did not resolve under $label" >&2
        return 1
    }
}

resolve "Docker's default seccomp profile"
resolve "a profile refusing io_uring" --security-opt "seccomp=$out/no-io-uring.json"
docker run --rm --security-opt "seccomp=$out/no-io-uring.json" -v "$out:/w:ro" alpine:3.20 \
    /w/uring_probe 2>&1 | grep -q "io_uring: refused"
echo "the rotor example resolved in both, and io_uring was refused in the second"
