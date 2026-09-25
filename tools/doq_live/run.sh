#!/bin/sh
# DNS over QUIC, live (docs/design.md §24 step 4): the engine over rotor, carrying each query on a
# stream of colibri's QUIC with chapulin's QUIC object as its TLS, resolves through the public
# resolvers that serve DoQ, and refuses what strict mode refuses. It needs a chapulin checkout with
# bin/chapulin-quic-nonblocking.o (build/doq.zig says how to make it), the network, and macOS:
# each resolver's root comes from the system root store.
#
#     tools/doq_live/run.sh <chapulin checkout>
#
# Two names must resolve through each resolver: the first over a full handshake, the second once
# the first connection has closed idle, over a connection that spends the ticket the first one
# kept (§24, request rule 10). Every resolver must resume. Two lookups must fail, and fail rather
# than fall back: the right root with a name the certificate does not carry, and the right name
# with a root the chain does not end at (RFC 9250 §5.1, RFC 8310 §5). Each must end in
# AllServersFailed, a refusal: one that ends in Timeout was not answered at all, which is the
# network and not strict mode (§16 decision 25). AdGuard is then known by its leaf key alone.
set -eu

checkout=${1:?usage: tools/doq_live/run.sh <chapulin checkout>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
store=/System/Library/Keychains/SystemRootCertificates.keychain

# A root from the system store, by its common name, as DER.
root_der() {
    security find-certificate -a -c "$1" -p "$store" | openssl x509 -outform DER -out "$out/$2.der"
}
root_der "USERTrust ECC Certification Authority" usertrust
root_der "ISRG Root X1" unrelated

lookup() {
    (cd "$root" && zig build -Dchapulin="$checkout" example-doq-rotor -- example.com,example.org "$@" 2>&1)
}

failures=0
for resolver in "94.140.14.14 dns.adguard-dns.com" "45.90.28.0 dns.nextdns.io"; do
    set -- $resolver
    if answer=$(lookup "$1" "$2" "$out/usertrust.der") && echo "$answer" | grep -q "example.com A" &&
        echo "$answer" | grep -q "example.org A"; then
        how=$(echo "$answer" | sed -n 's/^example\.org: handshake //p')
        if [ "$how" = resumed ]; then
            echo "resolves through $2 over DoQ, and resumes"
        else
            echo "RESOLVES through $2 over DoQ, but does not resume: $how" >&2
            failures=$((failures + 1))
        fi
    else
        echo "FAILS through $2: $answer" >&2
        failures=$((failures + 1))
    fi
done

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
refuse 94.140.14.14 dns.example "$out/usertrust.der"
refuse 94.140.14.14 dns.adguard-dns.com "$out/unrelated.der"

# A server known by its key alone, RFC 8310 §6.3's "SPKI + IP": the pin of its leaf key, read
# from the chain it shows over DoT on the same address, since no client here reads a QUIC
# server's, with a backup pin that matches nothing here, the unrelated root's, as RFC 7858 §4.2
# asks a pin set to carry. The pin of the key that issued the leaf is refused: under pins alone
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
pinned 94.140.14.14 dns.adguard-dns.com

exit "$failures"
