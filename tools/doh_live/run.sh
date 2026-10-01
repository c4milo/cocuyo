#!/bin/sh
# DoH, live (docs/design.md §24 steps 5 and 7b): the engine over rotor, carrying each query as a
# GET through colibri's channel (`cocuyo_doh`), with chapulin's TLS in colibri's `tls`, resolves
# through two public resolvers, on whichever version of HTTP the channel comes up on, and refuses
# what HTTPS refuses. It needs the network, and macOS: each resolver's roots come from the system
# root store. colibri is a dependency of the build, which fetches it the first time
# (build/doh.zig).
#
#     tools/doh_live/run.sh
#
# Two names must resolve through each resolver: the first over a full handshake, the second once
# the first connection has closed idle, over a connection that spends the ticket the first one
# kept (§24, rule 23). A resolver that declines the ticket is answered anyway, as over DoT. Each
# says the version of HTTP its second name came over.
# Two lookups must fail, and fail rather than fall back: a template whose host the certificate does
# not carry, and the right template with a root the chain does not end at (RFC 9110 §4.3.4). Each
# must end in AllServersFailed, a refusal: one that ends in Timeout was not answered at all, which
# is the network and not the certificate check (§16 decision 25). Each resolver is also asked
# AAAA, MX, TXT and HTTPS at once, of a name that has each, and must answer each with records of
# that type.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
store=/System/Library/Keychains/SystemRootCertificates.keychain

# A root from the system store, by its common name, as DER.
root_der() {
    security find-certificate -a -c "$1" -p "$store" | openssl x509 -outform DER -out "$out/$2.der"
}
# A root from the system store, as DER, by a common name several roots share and the unit name in
# its subject that tells it from the others.
root_der_unit() {
    security find-certificate -a -c "$1" -p "$store" |
        awk -v dir="$out" '/BEGIN CERTIFICATE/ { n++ } { print > (dir "/candidate-" n ".pem") }'
    for candidate in "$out"/candidate-*.pem; do
        if openssl x509 -in "$candidate" -noout -subject | grep -q "$2"; then
            openssl x509 -in "$candidate" -outform DER -out "$out/$3.der"
        fi
    done
    rm -f "$out"/candidate-*.pem
    test -s "$out/$3.der"
}
# Google holds certificates for dns.google from two issuers: WR2, issued by GTS Root R1, and WE2,
# which Google's repository serves issued by GlobalSign ECC Root CA - R4, a root of Google's own.
# Certificate Transparency held 21 of each on 2026-10-01, and which one a connection is shown
# depends on the frontend it reaches. With GTS Root R1 alone, a run that reached a WE2 frontend was
# refused, as HTTPS must refuse it: one run in seven until then, and two DoT runs in nine.
root_der "GTS Root R1" google
root_der_unit GlobalSign "GlobalSign ECC Root CA - R4" google-ecc-r4
root_der "SSL.com Root Certification Authority ECC" cloudflare
root_der "ISRG Root X1" unrelated

# The chain a server shows over TLS at this moment, issuer by issuer, which a failure reports beside
# its own: the next refusal then says which certificates it was shown.
chain() {
    openssl s_client -connect "$1" -servername "$2" -showcerts </dev/null 2>/dev/null |
        grep -E '^ *[0-9]+ s:|^ *i:' | tr -s ' ' | tr '\n' ' '
}
lookup_names() {
    names=$1
    shift
    (cd "$root" && zig build example-doh-rotor -- "$names" "$@" 2>&1)
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
for resolver in "8.8.8.8 https://dns.google/dns-query{?dns} google google-ecc-r4" \
    "1.1.1.1 https://cloudflare-dns.com/dns-query{?dns} cloudflare"; do
    # An address, a template, and the roots its host's chains end at.
    set -- $resolver
    address=$1 template=$2
    shift 2
    roots=
    for each in "$@"; do roots="$roots $out/$each.der"; done
    set -- "$address" "$template"
    if answer=$(lookup "$1" "$2" $roots) && echo "$answer" | grep -q "example.com A" &&
        echo "$answer" | grep -q "example.org A"; then
        how=$(echo "$answer" | sed -n 's/^example\.org: handshake //p')
        over=$(echo "$answer" | sed -n 's/^example\.org: over //p')
        case $how in
        resumed) echo "resolves through $2 over DoH on $over, and resumes" ;;
        "in full, its ticket declined")
            echo "resolves through $2 over DoH on $over, which declined the ticket: in full on the same connection" ;;
        *) echo "resolves through $2 over DoH on $over, but spends no ticket: $how" ;;
        esac
    else
        echo "FAILS through $2: $answer" >&2
        host=$(echo "$2" | sed 's|^https://\([^/]*\)/.*|\1|')
        echo "  $host shows: $(chain "$1:443" "$host")" >&2
        failures=$((failures + 1))
    fi
    reads_types "$2" "$1" "$2" $roots
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
