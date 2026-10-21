#!/bin/sh
# DNS over TLS, live (docs/design.md §21 step 6): the engine over rotor with chapulin's session in
# colibri's `tls` resolves through the public resolvers that serve DoT, and refuses what strict mode
# refuses. It needs the network, and macOS: each resolver's roots come from the system root store.
# colibri is a dependency of the build, which fetches it the first time (build/dot.zig).
#
#     tools/dot_live/run.sh
#
# Two names must resolve through each resolver, with the roots its chains end at: the first over
# a full handshake, the second once the first connection has closed idle, over a connection that
# spends the ticket the first one kept (§21, TLS rule 8). At least one resolver must resume. One
# that declines the ticket must be answered anyway: chapulin finishes a declined ticket as a full
# handshake on the same connection. Two lookups must fail, and fail rather than fall back: the
# right roots with a name the certificate does not carry, and the right name with a root the chain
# does not end at (RFC 8310 §5). Each must end in AllServersFailed, a refusal: one that ends in
# Timeout was not answered at all, which is the network and not strict mode (§16 decision 25). Its
# cause must be the handshake's, from the one server the example names (§5, The cause of a
# failure).
# Cloudflare is then known by its leaf key alone. Each resolver is also asked AAAA, MX, TXT and
# HTTPS at once, of a name that has each, and must answer each with records of that type. Google,
# which shows one of two chains, is asked one name with each of its roots alone, and the run says
# which chain it met.
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
# neither chain, so a run that reached a WE2 frontend was refused, as strict mode must refuse it:
# 1 scheduled run of 11 since 2026-10-01, and 4 of 11 of the DoH check.
root_der "GTS Root R1" gts-root-r1
root_der "GTS Root R4" gts-root-r4
root_der "SSL.com Root Certification Authority ECC" cloudflare
root_der "DigiCert Global Root G3" quad9
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
    (cd "$root" && zig build example-dot-rotor -- $word "$names" "$@" 2>&1)
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
resumed=0
for resolver in "8.8.8.8 dns.google gts-root-r1 gts-root-r4" \
    "1.1.1.1 cloudflare-dns.com cloudflare" "9.9.9.9 dns.quad9.net quad9"; do
    # An address, a name, and the roots the name's chains end at.
    set -- $resolver
    address=$1 name=$2
    shift 2
    roots=
    for each in "$@"; do roots="$roots $out/$each.der"; done
    set -- "$address" "$name"
    for word in "" cpu; do
        with=$(cpu_word_named)
        if answer=$(lookup "$1" "$2" $roots) && echo "$answer" | grep -q "example.com A" &&
            echo "$answer" | grep -q "example.org A"; then
            how=$(echo "$answer" | sed -n 's/^example\.org: handshake //p')
            if ! over=$(cpu_word_check "$answer"); then
                echo "RESOLVES through $2$with, but $over" >&2
                failures=$((failures + 1))
                continue
            fi
            case $how in
            resumed)
                echo "resolves through $2$with over $over, and resumes"
                resumed=$((resumed + 1)) ;;
            "in full, its ticket declined")
                echo "resolves through $2$with over $over, which declined the ticket: in full on the same connection" ;;
            *)
                echo "resolves through $2$with over $over, but spends no ticket: $how $(echo "$answer" | grep "ticks" | tr '\n' ' ')" ;;
            esac
        else
            echo "FAILS through $2$with: $answer" >&2
            echo "  $2 shows: $(chain "$1:853" "$2")" >&2
            failures=$((failures + 1))
        fi
    done
    word=
    reads_types "$2" "$1" "$2" $roots
done
if [ "$resumed" -eq 0 ]; then
    echo "NO RESOLVER RESUMED" >&2
    failures=$((failures + 1))
fi

# Which of its two chains Google showed this run, which a run that passes would not say otherwise:
# one name is asked with each root alone, and the root that answers alone is the one the chain
# ended at. It is a report and fails nothing, since two connections may reach two frontends.
ends_at() {
    address=$1 name=$2
    shift 2
    ended=
    for each in "$@"; do
        if lookup_names example.com "$address" "$name" "$out/$each.der" >/dev/null; then
            ended="$ended${ended:+ and }$each"
        fi
    done
    echo "$name showed a chain that ends at ${ended:-neither root alone}"
}
ends_at 8.8.8.8 dns.google gts-root-r1 gts-root-r4

# A lookup that must be refused: an address, a name, and the roots handed in.
refuse() {
    address=$1 name=$2
    shift 2
    with=
    for each in "$@"; do with="$with${with:+ and }$(basename "$each")"; done
    if answer=$(lookup "$address" "$name" "$@"); then
        echo "RESOLVED what strict mode refuses: $name at $address with $with" >&2
        failures=$((failures + 1))
    elif echo "$answer" | grep -q "^example.com: AllServersFailed (handshake from server 0)$"; then
        echo "refuses $name with $with"
    else
        echo "DID NOT SEE a refusal of $name with $with: $answer" >&2
        failures=$((failures + 1))
    fi
}
refuse 8.8.8.8 dns.example "$out/gts-root-r1.der" "$out/gts-root-r4.der"
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
        elif echo "$answer" | grep -q "^example.com: AllServersFailed (handshake from server 0)$"; then
            echo "refuses $address by $what alone"
        else
            echo "DID NOT SEE a refusal of $address by $what alone: $answer" >&2
            failures=$((failures + 1))
        fi
    done
}
pinned 1.1.1.1 cloudflare-dns.com

exit "$failures"
