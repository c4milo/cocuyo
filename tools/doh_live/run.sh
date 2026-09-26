#!/bin/sh
# DoH over HTTP/3, live (docs/design.md §24 step 5): the engine over rotor, carrying each query as
# a GET on a stream of colibri's HTTP/3 with chapulin's QUIC object as its TLS, resolves through
# the public resolvers that serve DoH on HTTP/3, and refuses what HTTPS refuses. It needs a
# chapulin checkout with bin/chapulin-quic-nonblocking.o (build/doq.zig says how to make it), the
# network, and macOS: each resolver's root comes from the system root store.
#
#     tools/doh_live/run.sh <chapulin checkout>
#
# Two names must resolve through each resolver: the first over a full handshake, the second once
# the first connection has closed idle, over a connection that spends the ticket the first one
# kept (§24, request rule 10). A resolver that declines the ticket is answered anyway, as over DoT.
# Two lookups must fail, and fail rather than fall back: a template whose host the certificate does
# not carry, and the right template with a root the chain does not end at (RFC 9110 §4.3.4). Each
# must end in AllServersFailed, a refusal: one that ends in Timeout was not answered at all, which
# is the network and not the certificate check (§16 decision 25). Each resolver is also asked
# AAAA, MX, TXT and HTTPS at once, of a name that has each, and must answer each with records of
# that type.
set -eu

checkout=${1:?usage: tools/doh_live/run.sh <chapulin checkout>}
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
root_der "ISRG Root X1" unrelated

lookup_names() {
    names=$1
    shift
    (cd "$root" && zig build -Dchapulin="$checkout" example-doh-rotor -- "$names" "$@" 2>&1)
}
lookup() {
    lookup_names example.com,example.org "$@"
}

# The four types beside A (c4milo/cocuyo#20), asked at once of a name that has each: each must be
# answered, and every record written under a question must be of the type it asked for.
typed_turn=cloudflare.com/AAAA+cloudflare.com/MX+cloudflare.com/TXT+cloudflare.com/HTTPS
reads_types() {
    name=$1
    shift
    if ! answer=$(lookup_names "$typed_turn" "$@"); then
        echo "FAILS the types beyond A through $name: $answer" >&2
        failures=$((failures + 1))
        return
    fi
    counts=
    for kind in AAAA MX TXT HTTPS; do
        count=$(echo "$answer" | grep -c "^cloudflare\.com/$kind $kind " || true)
        stray=$(echo "$answer" | grep "^cloudflare\.com/$kind " | grep -vc "^cloudflare\.com/$kind $kind " || true)
        if [ "$count" -eq 0 ] || [ "$stray" -ne 0 ]; then
            echo "MISREADS $kind through $name: $count records of it, $stray of another type: $answer" >&2
            failures=$((failures + 1))
            return
        fi
        counts="$counts, $count $kind"
    done
    echo "reads AAAA, MX, TXT and HTTPS at once through $name${counts}"
}

failures=0
for resolver in "8.8.8.8 https://dns.google/dns-query{?dns} google" \
    "1.1.1.1 https://cloudflare-dns.com/dns-query{?dns} cloudflare"; do
    set -- $resolver
    if answer=$(lookup "$1" "$2" "$out/$3.der") && echo "$answer" | grep -q "example.com A" &&
        echo "$answer" | grep -q "example.org A"; then
        how=$(echo "$answer" | sed -n 's/^example\.org: handshake //p')
        case $how in
        resumed) echo "resolves through $2 over DoH on HTTP/3, and resumes" ;;
        "in full, its ticket declined")
            echo "resolves through $2 over DoH on HTTP/3, which declined the ticket: in full on the same connection" ;;
        *) echo "resolves through $2 over DoH on HTTP/3, but spends no ticket: $how" ;;
        esac
    else
        echo "FAILS through $2: $answer" >&2
        failures=$((failures + 1))
    fi
    reads_types "$2" "$1" "$2" "$out/$3.der"
done

refuse() {
    if answer=$(lookup "$@"); then
        echo "RESOLVED what HTTPS refuses: $*" >&2
        failures=$((failures + 1))
    elif echo "$answer" | grep -q "^example.com: AllServersFailed$"; then
        echo "refuses $2 with $(basename "$3")"
    else
        echo "DID NOT SEE a refusal of $2 with $(basename "$3"): $answer" >&2
        failures=$((failures + 1))
    fi
}
refuse 8.8.8.8 "https://dns.example/dns-query{?dns}" "$out/google.der"
refuse 8.8.8.8 "https://dns.google/dns-query{?dns}" "$out/unrelated.der"

exit "$failures"
