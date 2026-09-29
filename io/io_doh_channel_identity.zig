//! The TLS identity `cocuyo_doh`'s tests run colibri's server under (docs/design.md §24, DoH over
//! colibri's client, the owner's ruling of 2026-09-28): a CA and a leaf for `dns.example`, both on
//! P-256, valid from 2026-01-01 to 2126-01-01, so a test's clock may sit anywhere in that century.
//! It was made once with OpenSSL 3.6.4, and is kept in `testdata/`. Its key is a test's, and names
//! no server anyone runs.
//!
//!     openssl ecparam -name prime256v1 -genkey -noout -out ca.key
//!     openssl req -x509 -new -key ca.key -sha256 -not_before 20260101000000Z \
//!         -not_after 21260101000000Z -subj "/CN=cocuyo test CA" \
//!         -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" \
//!         -out ca.pem
//!     openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
//!     openssl req -new -key leaf.key -subj "/CN=dns.example" -out leaf.csr
//!     printf 'subjectAltName=DNS:dns.example\nbasicConstraints=critical,CA:FALSE\n'\
//!     'keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' > leaf.ext
//!     openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 \
//!         -not_before 20260101000000Z -not_after 21260101000000Z -extfile leaf.ext -out leaf.pem
//!     openssl x509 -in ca.pem -outform DER -out identity.ca.der
//!     openssl x509 -in leaf.pem -outform DER -out identity.leaf.der
//!     openssl x509 -in ca.pem -pubkey -noout | openssl pkey -pubin -outform DER -out identity.spki
//!
//! `identity.name` is the CA's subject Name, the whole DER TLV the certificate carries after its
//! validity. `identity.priv` is the leaf's private scalar, the 32 octets of the one OCTET STRING in
//! `openssl ec -in leaf.key -outform DER`. `identity.pub` is the leaf's point X||Y, the last 64
//! octets of `openssl ec -in leaf.key -pubout -outform DER`, after the 0x04 that marks it
//! uncompressed.
const tls = @import("tls");

/// The leaf, then nothing: the server's chain (RFC 9846 §4.5.1).
pub const chain = [_][]const u8{@embedFile("testdata/identity.leaf.der")};
pub const public_key: *const [tls.constants.p256_public_key_len]u8 = @embedFile("testdata/identity.pub");
pub const private_key: *const [tls.constants.p256_private_key_len]u8 = @embedFile("testdata/identity.priv");

/// The root a client trusts: the CA's subject Name and SubjectPublicKeyInfo.
pub const anchor: tls.Anchor = .{
    .subject = @embedFile("testdata/identity.name"),
    .spki = @embedFile("testdata/identity.spki"),
};

/// The name the leaf carries (RFC 9110 §4.3.4).
pub const server_name = "dns.example";

/// An instant inside the identity's validity, 2026-06-01T00:00:00Z, for a test's wall clock.
pub const unix_seconds: u64 = 1_780_272_000;
