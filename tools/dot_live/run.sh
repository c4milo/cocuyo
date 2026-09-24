#!/bin/sh
# DNS over TLS, live (docs/design.md §21 step 6): the engine over rotor with chapulin's session
# resolves through the public resolvers that serve DoT, and refuses what strict mode refuses. It
# needs a chapulin checkout with bin/chapulin-record.o (build/dot.zig says how to make it), the
# network, and macOS: each resolver's root comes from the system root store.
#
#     tools/dot_live/run.sh <chapulin checkout>
#
# Two names must resolve through each resolver, with the root its chain ends at: the first over a
# full handshake, the second once the first connection has closed idle, over a connection that
# spends the ticket the first one kept (§21, TLS rule 8). At least one resolver must resume. One
# that declines the ticket must be answered anyway, over a full handshake the engine opens again.
# Two lookups must fail, and fail rather than fall back: the right root with a name the certificate
# does not carry, and the right name with a root the chain does not end at (RFC 8310 §5).
set -eu

checkout=${1:?usage: tools/dot_live/run.sh <chapulin checkout>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
store=/System/Library/Keychains/SystemRootCertificates.keychain

# A root from the system store, by its common name, as DER.
root_der() {
    security find-certificate -a -c "$1" -p "$store" | openssl x509 -outform DER -out "$out/$2.der"
}
root_der "GTS Root R1" google
root_der "SSL.com Root Certification Authority ECC" cloudflare
root_der "DigiCert Global Root G3" quad9
root_der "ISRG Root X1" unrelated

lookup() {
    (cd "$root" && zig build -Dchapulin="$checkout" example-dot-rotor -- example.com,example.org "$@" 2>&1)
}

failures=0
resumed=0
for resolver in "8.8.8.8 dns.google google" "1.1.1.1 cloudflare-dns.com cloudflare" \
    "9.9.9.9 dns.quad9.net quad9"; do
    set -- $resolver
    if answer=$(lookup "$1" "$2" "$out/$3.der") && echo "$answer" | grep -q "example.com A" &&
        echo "$answer" | grep -q "example.org A"; then
        if echo "$answer" | grep -q "example.org: resumed handshake"; then
            echo "resolves through $2, and resumes"
            resumed=$((resumed + 1))
        else
            echo "resolves through $2, which declines the ticket: a full handshake again"
        fi
    else
        echo "FAILS through $2: $answer" >&2
        failures=$((failures + 1))
    fi
done
if [ "$resumed" -eq 0 ]; then
    echo "NO RESOLVER RESUMED" >&2
    failures=$((failures + 1))
fi

refuse() {
    if lookup "$@" >/dev/null; then
        echo "RESOLVED what strict mode refuses: $*" >&2
        failures=$((failures + 1))
    else
        echo "refuses $2 with $(basename "$3")"
    fi
}
refuse 8.8.8.8 dns.example "$out/google.der"
refuse 8.8.8.8 dns.google "$out/unrelated.der"

exit "$failures"
