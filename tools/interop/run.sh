#!/bin/sh
# DoQ and DoH on HTTP/3 against an independent server, on the loopback (c4milo/cocuyo#16): the
# engine over rotor, colibri's QUIC and HTTP/3 and chapulin's QUIC object, against AdGuard's
# dnsproxy, whose QUIC and HTTP/3 are quic-go's. It needs a chapulin checkout with
# bin/chapulin-quic-nonblocking.o (build/doq.zig says how to make it), a dnsproxy binary, and
# openssl. It needs no network: the certificates are made here, and dnsproxy answers from a hosts
# file.
#
#     tools/interop/run.sh <chapulin checkout> <dnsproxy>
#
# Over each transport, three names must resolve at once, each on a stream of its own on one
# connection (RFC 9250 §4.2, RFC 9114 §4.1), and a fourth once that connection has closed idle,
# over a connection that resumes with its ticket (RFC 9250 §4.5). What the certificate check
# refuses must end in AllServersFailed: a name the leaf does not carry, a root the chain does not
# end at, and a pin on the issuer's key. A server known by its leaf key alone, with a backup pin,
# must resolve.
set -eu

checkout=${1:?usage: tools/interop/run.sh <chapulin checkout> <dnsproxy>}
dnsproxy=${2:?usage: tools/interop/run.sh <chapulin checkout> <dnsproxy>}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=$(mktemp -d)
proxy=
trap 'if [ -n "$proxy" ]; then kill "$proxy" 2>/dev/null || true; fi; rm -rf "$out"' EXIT

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

# DoQ on 8853 and DoH on HTTP/3 on 8443, from the hosts file alone: no plain listener, and an
# upstream that is never asked.
quic_port=8853
https_port=8443
"$dnsproxy" -l 127.0.0.1 -p 0 --quic-port "$quic_port" --https-port "$https_port" --http3 \
    -c "$out/chain.pem" -k "$out/leaf.key" --hosts-file-enabled --hosts-files "$out/hosts" \
    -u 127.0.0.1:9 >"$out/dnsproxy.log" 2>&1 &
proxy=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "dns-over-quic listener loop" "$out/dnsproxy.log" && break
    sleep 1
done

lookup() {
    step=$1
    shift
    (cd "$root" && zig build -Dchapulin="$checkout" "$step" -- "$@" 2>&1)
}

failures=0
at_once=example.com+example.org+example.net,interop.example
resolves() {
    what=$1
    shift
    if answer=$(lookup "$@") && echo "$answer" | grep -q "^example.com A 192.0.2.1" &&
        echo "$answer" | grep -q "^example.org A 192.0.2.2" && echo "$answer" | grep -q "^example.net A 192.0.2.3" &&
        echo "$answer" | grep -q "^interop.example A 192.0.2.4"; then
        how=$(echo "$answer" | sed -n 's/^interop\.example: handshake //p')
        if [ "$how" = resumed ]; then
            echo "resolves $what, three names at once, and resumes"
        else
            echo "RESOLVES $what, but does not resume: $how" >&2
            failures=$((failures + 1))
        fi
    else
        echo "FAILS $what: $answer" >&2
        failures=$((failures + 1))
    fi
}
refuses() {
    what=$1
    shift
    if answer=$(lookup "$@"); then
        echo "RESOLVED what the certificate check refuses: $what" >&2
        failures=$((failures + 1))
    elif echo "$answer" | grep -q ": AllServersFailed$"; then
        echo "refuses $what"
    else
        echo "DID NOT SEE a refusal of $what: $answer" >&2
        failures=$((failures + 1))
    fi
}

template="https://interop.example:$https_port/dns-query{?dns}"
resolves "over DoQ" example-doq-rotor "$at_once" "127.0.0.1:$quic_port" interop.example "$out/ca.der"
resolves "over DoH on HTTP/3" example-doh-rotor "$at_once" 127.0.0.1 "$template" "$out/ca.der"
refuses "over DoQ a name the leaf does not carry" example-doq-rotor example.com "127.0.0.1:$quic_port" dns.example "$out/ca.der"
refuses "over DoQ a root the chain does not end at" example-doq-rotor example.com "127.0.0.1:$quic_port" interop.example "$out/unrelated.der"
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
resolves "over DoQ by the leaf's key alone" example-doq-rotor "$at_once" "127.0.0.1:$quic_port" "pin-sha256:$leaf,$backup"
refuses "over DoQ a pin on the issuer's key alone" example-doq-rotor example.com "127.0.0.1:$quic_port" "pin-sha256:$issuer"

exit "$failures"
