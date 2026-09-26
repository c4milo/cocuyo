#!/bin/sh
# Every transport the engine speaks, against an independent server on the loopback
# (c4milo/cocuyo#16, #20 and #21): the engine over rotor against AdGuard's dnsproxy, over plain DNS
# on UDP and on TCP, whose DNS is miekg/dns, over DoT, whose TLS is Go's, and over DoQ and DoH on
# HTTP/3, whose QUIC and HTTP/3 are quic-go's. The encrypted transports run over chapulin, and DoQ
# and DoH over colibri's QUIC and HTTP/3. It needs a chapulin checkout holding
# bin/chapulin-tcp-nonblocking.o and bin/chapulin-quic-nonblocking.o (build/dot.zig and
# build/doq.zig say how to make them), a dnsproxy binary, and openssl. It needs no network: the
# certificates are made here, dnsproxy answers addresses from a hosts file, and every other type
# from tools/interop/zone.zig, its upstream on the loopback.
#
#     tools/interop/run.sh <chapulin checkout> <dnsproxy>
#
# Over each transport, three names must resolve at once, and a fourth after them. Over UDP each
# query goes on a datagram of its own, and over TCP, DoT, DoQ and DoH each on the one connection
# (RFC 7766 §6.2.1.1, RFC 9250 §4.2, RFC 9114 §4.1). Over DoT, DoQ and DoH the fourth goes once
# that connection has closed idle, over a connection that resumes with its ticket (design §21, TLS
# rule 8; RFC 9250 §4.5). What the certificate check refuses must end in AllServersFailed: a name
# the leaf does not carry and a root the chain does not end at, over each encrypted transport, and
# a pin on the issuer's key over DoT and DoQ, where a server known by its leaf key alone, with a
# backup pin, must resolve. Over each transport, AAAA, MX, TXT and HTTPS records of one name must
# be read at once, each record as the zone wrote it, and then a CNAME to that name. Over plain DNS,
# dnsproxy's own log must show the queries came over the transport asked for, and not the other.
set -eu

checkout=${1:?usage: tools/interop/run.sh <chapulin checkout> <dnsproxy>}
dnsproxy=${2:?usage: tools/interop/run.sh <chapulin checkout> <dnsproxy>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
proxy=
zone=
trap 'for pid in $proxy $zone; do kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true; done; rm -rf "$out"' EXIT

# A CA of the check's own, and a leaf for interop.example under it (RFC 2606 §3), both P-256,
# and a second CA the chain does not end at.
authority() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
        -keyout "$out/$1.key" -out "$out/$1.pem" -subj "/CN=cocuyo interop $1" \
        -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    openssl x509 -in "$out/$1.pem" -outform DER -out "$out/$1.der"
}
authority ca
authority unrelated
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$out/leaf.key" \
    -out "$out/leaf.csr" -subj "/CN=interop.example" 2>/dev/null
printf 'subjectAltName=DNS:interop.example\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' >"$out/leaf.ext"
openssl x509 -req -in "$out/leaf.csr" -CA "$out/ca.pem" -CAkey "$out/ca.key" -CAcreateserial \
    -out "$out/leaf.pem" -days 2 -extfile "$out/leaf.ext" 2>/dev/null
cat "$out/leaf.pem" "$out/ca.pem" >"$out/chain.pem"
printf '192.0.2.1 example.com\n192.0.2.2 example.org\n192.0.2.3 example.net\n192.0.2.4 interop.example\n' >"$out/hosts"

# The zone answers every type the hosts file does not, as dnsproxy's upstream.
zone_port=8054
zig build-exe -O ReleaseSafe -femit-bin="$out/zone" "$here/zone.zig"
"$out/zone" "$zone_port" &
zone=$!

# Plain DNS on 8053, over UDP and over TCP, DoT and DoQ on 8853, over TCP and over UDP as DoT and
# DoQ share 853 (RFC 7858 §3.1, RFC 9250 §4.1.1), and DoH on HTTP/3 on 8443.
plain_port=8053
secure_port=8853
https_port=8443
"$dnsproxy" -l 127.0.0.1 -p "$plain_port" --tls-port "$secure_port" --quic-port "$secure_port" \
    --https-port "$https_port" --http3 --verbose -c "$out/chain.pem" -k "$out/leaf.key" \
    --hosts-file-enabled --hosts-files "$out/hosts" -u "127.0.0.1:$zone_port" >"$out/dnsproxy.log" 2>&1 &
proxy=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "dns-over-quic listener loop" "$out/dnsproxy.log" && grep -q "proto=tls" "$out/dnsproxy.log" && break
    sleep 1
done

lookup() {
    step=$1
    shift
    (cd "$root" && zig build -Dchapulin="$checkout" "$step" -- "$@" 2>&1)
}

failures=0
fail() {
    echo "$1" >&2
    failures=$((failures + 1))
}
at_once=example.com+example.org+example.net,interop.example
all_four() {
    echo "$1" | grep -q "^example.com A 192.0.2.1" && echo "$1" | grep -q "^example.org A 192.0.2.2" &&
        echo "$1" | grep -q "^example.net A 192.0.2.3" && echo "$1" | grep -q "^interop.example A 192.0.2.4"
}
answers() {
    what=$1
    shift
    if answer=$(lookup "$@") && all_four "$answer"; then
        echo "resolves $what, three names at once"
    else
        fail "FAILS $what: $answer"
    fi
}
resolves() {
    what=$1
    shift
    if answer=$(lookup "$@") && all_four "$answer"; then
        how=$(echo "$answer" | sed -n 's/^interop\.example: handshake //p')
        if [ "$how" = resumed ]; then
            echo "resolves $what, three names at once, and resumes"
        else
            fail "RESOLVES $what, but does not resume: $how"
        fi
    else
        fail "FAILS $what: $answer"
    fi
}
refuses() {
    what=$1
    shift
    if answer=$(lookup "$@"); then
        fail "RESOLVED what the certificate check refuses: $what"
    elif echo "$answer" | grep -q ": AllServersFailed$"; then
        echo "refuses $what"
    else
        fail "DID NOT SEE a refusal of $what: $answer"
    fi
}

# What the zone serves, as the examples write it (examples/answer_text.zig): every record the
# answers must hold, and nothing else under the two names.
typed=typed.example/AAAA+typed.example/MX+typed.example/TXT+typed.example/HTTPS,alias.typed.example
typed_lines='typed.example/AAAA AAAA 2001:db8:0:0:0:0:0:5
typed.example/AAAA AAAA 2001:db8:0:0:0:0:0:6
typed.example/MX MX 10 mail.typed.example.
typed.example/MX MX 20 backup.typed.example.
typed.example/TXT TXT "v=spf1 -all"
typed.example/TXT TXT "first" "second"
typed.example/HTTPS HTTPS 1 . alpn=h3,h2 port=8443
alias.typed.example canonical typed.example.
alias.typed.example A 192.0.2.5'
# dnsproxy logs, with --verbose, each datagram it takes and each TCP connection it accepts.
seen() {
    case $1 in
    udp) grep -c "handling new packet prefix=dnsproxy .*proto=udp" "$out/dnsproxy.log" || true ;;
    tcp) grep -c "handling new request prefix=dnsproxy proto=tcp " "$out/dnsproxy.log" || true ;;
    esac
}
# A check over plain DNS, which must bring dnsproxy queries over `transport` and none over `other`.
alone() {
    transport=$1 other=$2
    shift 2
    before=$(seen "$transport") before_other=$(seen "$other")
    "$@"
    if [ "$(seen "$transport")" -le "$before" ] || [ "$(seen "$other")" -ne "$before_other" ]; then
        fail "WENT OUT over another transport than $transport: $2"
    fi
}
reads_types() {
    what=$1
    shift
    if ! answer=$(lookup "$@"); then
        fail "FAILS the types beyond A $what: $answer"
        return
    fi
    missing=$(echo "$typed_lines" | while IFS= read -r line; do
        echo "$answer" | grep -qF "$line" || echo "$line"
    done)
    held=$(echo "$answer" | grep -c "^typed\.example/[A-Z]* \|^alias\.typed\.example ")
    if [ -z "$missing" ] && [ "$held" -eq "$(echo "$typed_lines" | wc -l)" ]; then
        echo "reads AAAA, MX, TXT and HTTPS at once, and a CNAME, $what"
    else
        fail "MISREADS the types beyond A $what: missing [$missing], $held lines: $answer"
    fi
}

plain="127.0.0.1:$plain_port"
secure="127.0.0.1:$secure_port"
template="https://interop.example:$https_port/dns-query{?dns}"
alone udp tcp answers "over UDP" example-cleartext-rotor "$at_once" "$plain" udp
alone tcp udp answers "over TCP" example-cleartext-rotor "$at_once" "$plain" tcp
resolves "over DoT" example-dot-rotor "$at_once" "$secure" interop.example "$out/ca.der"
resolves "over DoQ" example-doq-rotor "$at_once" "$secure" interop.example "$out/ca.der"
resolves "over DoH on HTTP/3" example-doh-rotor "$at_once" 127.0.0.1 "$template" "$out/ca.der"
alone udp tcp reads_types "over UDP" example-cleartext-rotor "$typed" "$plain" udp
alone tcp udp reads_types "over TCP" example-cleartext-rotor "$typed" "$plain" tcp
reads_types "over DoT" example-dot-rotor "$typed" "$secure" interop.example "$out/ca.der"
reads_types "over DoQ" example-doq-rotor "$typed" "$secure" interop.example "$out/ca.der"
reads_types "over DoH on HTTP/3" example-doh-rotor "$typed" 127.0.0.1 "$template" "$out/ca.der"
for transport in dot:DoT doq:DoQ; do
    example=example-${transport%%:*}-rotor label=${transport#*:}
    refuses "over $label a name the leaf does not carry" "$example" example.com "$secure" dns.example "$out/ca.der"
    refuses "over $label a root the chain does not end at" "$example" example.com "$secure" interop.example "$out/unrelated.der"
done
refuses "over DoH a host the leaf does not carry" example-doh-rotor example.com 127.0.0.1 "https://dns.example:$https_port/dns-query{?dns}" "$out/ca.der"
refuses "over DoH a root the chain does not end at" example-doh-rotor example.com 127.0.0.1 "$template" "$out/unrelated.der"

# RFC 8310 §6.3's "SPKI + IP": the leaf's key and a backup pin, the unrelated CA's (RFC 7858
# §4.2), with no name and no root. A pin on the issuer's key alone is refused.
spki_pin() {
    openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64
}
leaf=$(spki_pin "$out/leaf.pem")
issuer=$(spki_pin "$out/ca.pem")
backup=$(spki_pin "$out/unrelated.pem")
for transport in dot:DoT doq:DoQ; do
    example=example-${transport%%:*}-rotor label=${transport#*:}
    resolves "over $label by the leaf's key alone" "$example" "$at_once" "$secure" "pin-sha256:$leaf,$backup"
    refuses "over $label a pin on the issuer's key alone" "$example" example.com "$secure" "pin-sha256:$issuer"
done

exit "$failures"
