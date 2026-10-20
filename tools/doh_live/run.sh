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
# is the network and not the certificate check (§16 decision 25). Its cause must be the request's,
# as each failure over DoH is (§5, The cause of a failure). Each resolver is also asked
# AAAA, MX, TXT and HTTPS at once, of a name that has each, and must answer each with records of
# that type. Google, which shows one of two chains, is asked one name with each of its roots
# alone, and the run says which chain it met.
# Each resolver resolves its two names in two runs: first without the word `cpu`, then with it
# (docs/design.md §16 decision 48). Without the word each handshake must run ChaCha20-Poly1305.
# With it each must run AES-GCM on an arm64 host whose system reports the AES instructions, PMULL
# and FEAT_DIT, and ChaCha20-Poly1305 elsewhere. On an arm64 Mac whose sysctl does not report all
# three, each run with the word fails (tools/cpu_word/suite.sh).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
store=/System/Library/Keychains/SystemRootCertificates.keychain
. "$root/tools/cpu_word/suite.sh"
cpu_word_says

# A root from the system store, by its common name, as DER. A name the store does not hold stops
# the check here, by that name.
root_der() {
    security find-certificate -a -c "$1" -p "$store" |
        openssl x509 -outform DER -out "$out/$2.der" ||
        { echo "NO ROOT named $1 in $store" >&2; exit 1; }
}
# Google shows one of two chains for dns.google, by the frontend a connection reaches, each of three
# certificates, the leaf's key P-256 in both:
#   - dns.google, issued by WR2 (RSA 2048), which GTS Root R1 (RSA 4096) issued;
#   - dns.google, issued by WE2 (ECDSA P-256), which GTS Root R4 (ECDSA P-384) issued.
# The third certificate is the root's own name and key signed by GlobalSign Root CA (RSA 2048, with
# SHA-256), a cross-certificate that expires on 2028-01-28. chapulin looks for each certificate's
# issuer among its anchors before it reads the next certificate, so with the two GTS roots its
# walk ends at WR2 or WE2 and never reads the third: both chains verify, and will with the
# cross-certificate gone. GlobalSign Root CA alone verifies both too, but only while Google sends
# that certificate.
# Until 2026-10-11 the check handed in GTS Root R1 and GlobalSign ECC Root CA - R4, which issued
# neither chain, so a run that reached a WE2 frontend was refused, as HTTPS must refuse it:
# 4 scheduled runs of 11 since 2026-10-01, and 1 of 11 of the DoT check.
root_der "GTS Root R1" gts-root-r1
root_der "GTS Root R4" gts-root-r4
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
    (cd "$root" && zig build example-doh-rotor -- $word "$names" "$@" 2>&1)
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
for resolver in "8.8.8.8 https://dns.google/dns-query{?dns} gts-root-r1 gts-root-r4" \
    "1.1.1.1 https://cloudflare-dns.com/dns-query{?dns} cloudflare"; do
    # An address, a template, and the roots its host's chains end at.
    set -- $resolver
    address=$1 template=$2
    shift 2
    roots=
    for each in "$@"; do roots="$roots $out/$each.der"; done
    set -- "$address" "$template"
    for word in "" cpu; do
        with=$(cpu_word_named)
        if answer=$(lookup "$1" "$2" $roots) && echo "$answer" | grep -q "example.com A" &&
            echo "$answer" | grep -q "example.org A"; then
            how=$(echo "$answer" | sed -n 's/^example\.org: handshake //p')
            over=$(echo "$answer" | sed -n 's/^example\.org: over //p')
            if ! suite=$(cpu_word_check "$answer"); then
                echo "RESOLVES through $2 over DoH on $over$with, but $suite" >&2
                failures=$((failures + 1))
                continue
            fi
            case $how in
            resumed) echo "resolves through $2 over DoH on $over$with, over $suite, and resumes" ;;
            "in full, its ticket declined")
                echo "resolves through $2 over DoH on $over$with, over $suite, which declined the ticket: in full on the same connection" ;;
            *) echo "resolves through $2 over DoH on $over$with, over $suite, but spends no ticket: $how" ;;
            esac
        else
            echo "FAILS through $2$with: $answer" >&2
            host=$(echo "$2" | sed 's|^https://\([^/]*\)/.*|\1|')
            echo "  $host shows: $(chain "$1:443" "$host")" >&2
            failures=$((failures + 1))
        fi
    done
    word=
    reads_types "$2" "$1" "$2" $roots
done

# Which of its two chains Google showed this run, which a run that passes would not say otherwise:
# one name is asked with each root alone, and the root that answers alone is the one the chain
# ended at. It is a report and fails nothing, since two connections may reach two frontends.
ends_at() {
    address=$1 template=$2
    shift 2
    ended=
    for each in "$@"; do
        if lookup_names example.com "$address" "$template" "$out/$each.der" >/dev/null; then
            ended="$ended${ended:+ and }$each"
        fi
    done
    echo "$template showed a chain that ends at ${ended:-neither root alone}"
}
ends_at 8.8.8.8 "https://dns.google/dns-query{?dns}" gts-root-r1 gts-root-r4

# A lookup that must be refused: an address, a template, and the roots handed in.
refuse() {
    address=$1 template=$2
    shift 2
    with=
    for each in "$@"; do with="$with${with:+ and }$(basename "$each")"; done
    if answer=$(lookup "$address" "$template" "$@"); then
        echo "RESOLVED what HTTPS refuses: $template at $address with $with" >&2
        failures=$((failures + 1))
    elif echo "$answer" | grep -q "^example.com: AllServersFailed (request)$"; then
        echo "refuses $template with $with"
    else
        echo "DID NOT SEE a refusal of $template with $with: $answer" >&2
        failures=$((failures + 1))
    fi
}
refuse 8.8.8.8 "https://dns.example/dns-query{?dns}" "$out/gts-root-r1.der" "$out/gts-root-r4.der"
refuse 8.8.8.8 "https://dns.google/dns-query{?dns}" "$out/unrelated.der"

exit "$failures"
