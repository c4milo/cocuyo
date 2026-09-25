#!/bin/sh
# DNS over TLS, live (docs/design.md §21 step 6): the engine over rotor with chapulin's session
# resolves through the public resolvers that serve DoT, and refuses what strict mode refuses. It
# needs a chapulin checkout with bin/chapulin-tcp-nonblocking.o (build/dot.zig says how to make it), the
# network, and macOS: each resolver's root comes from the system root store.
#
#     tools/dot_live/run.sh <chapulin checkout>
#
# Two names must resolve through each resolver, with the root its chain ends at: the first over a
# full handshake, the second once the first connection has closed idle, over a connection that
# spends the ticket the first one kept (§21, TLS rule 8). At least one resolver must resume. One
# that declines the ticket must be answered anyway: chapulin finishes a declined ticket as a full
# handshake on the same connection. Two lookups must fail, and fail rather than fall back: the
# right root with a name the certificate does not carry, and the right name with a root the chain
# does not end at (RFC 8310 §5). Each must end in AllServersFailed, a refusal: one that ends in
# Timeout was not answered at all, which is the network and not strict mode (§16 decision 25).
# Cloudflare is then known by its leaf key alone.
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
        how=$(echo "$answer" | sed -n 's/^example\.org: handshake //p')
        case $how in
        resumed)
            echo "resolves through $2, and resumes"
            resumed=$((resumed + 1)) ;;
        "in full, its ticket declined")
            echo "resolves through $2, which declined the ticket: in full on the same connection" ;;
        *)
            echo "resolves through $2, but spends no ticket: $how $(echo "$answer" | grep "ticks" | tr '\n' ' ')" ;;
        esac
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
    if answer=$(lookup "$@"); then
        echo "RESOLVED what strict mode refuses: $*" >&2
        failures=$((failures + 1))
    elif echo "$answer" | grep -q "^example.com: AllServersFailed$"; then
        echo "refuses $2 with $(basename "$3")"
    else
        echo "DID NOT SEE a refusal of $2 with $(basename "$3"): $answer" >&2
        failures=$((failures + 1))
    fi
}
refuse 8.8.8.8 dns.example "$out/google.der"
refuse 8.8.8.8 dns.google "$out/unrelated.der"

# A server known by its key alone, RFC 8310 §6.3's "SPKI + IP": the pin of its leaf key, read
# from the chain it shows, with a backup pin that matches nothing here, the unrelated root's, as
# RFC 7858 §4.2 asks a pin set to carry. The pin of the key that issued the leaf is refused: under pins alone
# chapulin matches the leaf's key, and reads nothing else of the chain.
spki_pin() {
    openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64
}
shown() {
    openssl s_client -connect "$1:853" -servername "$2" -showcerts </dev/null 2>/dev/null |
        awk -v n="$3" '/BEGIN CERTIFICATE/ { i++ } i == n { print } /END CERTIFICATE/ && i == n { exit }'
}
backup=$(openssl x509 -in "$out/unrelated.der" -inform DER | spki_pin)
pinned() {
    address=$1 name=$2
    leaf=$(shown "$address" "$name" 1 | spki_pin)
    issuer=$(shown "$address" "$name" 2 | spki_pin)
    if answer=$(lookup "$address" "pin-sha256:$leaf,$backup") && echo "$answer" | grep -q "example.com A" &&
        echo "$answer" | grep -q "example.org A"; then
        echo "resolves through $address by its leaf key alone, $(echo "$answer" | sed -n 's/^example\.org: handshake //p')"
    else
        echo "FAILS through $address by its leaf key alone: $answer" >&2
        failures=$((failures + 1))
    fi
    for refused in "the backup pin:$backup" "its issuer's pin:$issuer"; do
        what=${refused%%:*} pin=${refused#*:}
        if answer=$(lookup "$address" "pin-sha256:$pin"); then
            echo "RESOLVED through $address by $what alone" >&2
            failures=$((failures + 1))
        elif echo "$answer" | grep -q "^example.com: AllServersFailed$"; then
            echo "refuses $address by $what alone"
        else
            echo "DID NOT SEE a refusal of $address by $what alone: $answer" >&2
            failures=$((failures + 1))
        fi
    done
}
pinned 1.1.1.1 cloudflare-dns.com

exit "$failures"
