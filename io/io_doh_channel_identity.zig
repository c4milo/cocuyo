//! The TLS identity `cocuyo_doh`'s tests run colibri's server under (docs/design.md §24, DoH over
//! colibri's client, the owner's ruling of 2026-09-28): a CA and a leaf for `dns.example`, both on
//! P-256, valid from 2026-01-01 to 2126-01-01, so a test's clock may sit anywhere in that century.
//! It was made once with OpenSSL 3.6.4, and is kept in `testdata/`. Its key is a test's, and names
//! no server anyone runs. `test_context` builds the context a test's channel starts from under it.
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
const std = @import("std");
const tls = @import("colibri").tls;
const start_module = @import("io_doh_channel_start.zig");

/// The leaf, then nothing: the server's chain (RFC 9846 §4.5.1).
pub const chain = [_][]const u8{@embedFile("testdata/identity.leaf.der")};
pub const public_key: *const [tls.constants.protocol.p256_public_key_len]u8 = @embedFile("testdata/identity.pub");
pub const private_key: *const [tls.constants.protocol.p256_private_key_len]u8 = @embedFile("testdata/identity.priv");
/// The leaf's key as a server holds it: the scheme, then the scalar and the point, each at the
/// start of its room (colibri's `tls.Key`).
pub const key: tls.Key = p256_key: {
    var filled: tls.Key = .{ .scheme = .ecdsa_secp256r1_sha256 };
    @memcpy(filled.private_key[0..private_key.len], private_key);
    @memcpy(filled.public_key[0..public_key.len], public_key);
    break :p256_key filled;
};
/// The identity a server holds: the chain and its key.
pub const identities = [_]tls.Identity{.{ .chain = &chain, .key = &key }};

/// The root a client trusts: the CA's subject Name and SubjectPublicKeyInfo.
pub const anchor: tls.Anchor = .{
    .subject = @embedFile("testdata/identity.name"),
    .spki = @embedFile("testdata/identity.spki"),
};

/// The name the leaf carries (RFC 9110 §4.3.4).
pub const server_name = "dns.example";

/// An instant inside the identity's validity, 2026-06-01T00:00:00Z, for a test's wall clock.
pub const unix_seconds: u64 = 1_780_272_000;

/// The roots a test's context trusts: the identity's CA alone.
pub const anchors = [_]tls.Anchor{anchor};

/// What the tests state of the CPU, and the streams their contexts draw from
/// (`io_crypto_test_support.zig`). With no instruction, a hello offers TLS_CHACHA20_POLY1305_SHA256
/// alone (docs/design.md §16 decision 48). The test servers state no instruction either.
pub const support = @import("io_crypto_test_support.zig");

/// A channel's context for a test over the identity. Its anchors are the identity's CA, and its
/// wall clock is `unix_seconds` at `now_ns`. It draws from `source`, which a seed repeated seeds,
/// so each run draws what the last drew, and which outlives the channel. It states no instruction.
/// Never for a network, whose source is a CSPRNG's.
pub fn test_context(source: *std.Random.ChaCha, now_ns: u64) start_module.Context {
    return test_context_with(.nothing, source, now_ns).?;
}

/// As `test_context`, with the CPU that `case` names. Null where this host cannot state it.
pub fn test_context_with(case: support.Case, source: *std.Random.ChaCha, now_ns: u64) ?start_module.Context {
    const crypto = support.crypto(case, source) orelse return null;
    return .init(&anchors, crypto, .{ .unix_seconds = unix_seconds, .monotonic_ns = now_ns });
}
