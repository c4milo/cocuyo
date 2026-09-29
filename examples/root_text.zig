//! A root certificate, read from an engine example's argument, as the trust anchor chapulin checks a
//! chain against: its subject Name and its SubjectPublicKeyInfo, each a whole DER TLV, which is what
//! colibri's anchor carries (its values.zig), as chapulin's does (its webpki_cfg.h). The walk reads
//! the certificate's fields in order: the version, the serial, the signature, the issuer, the
//! validity, the subject, the key.
const std = @import("std");

/// The anchor of the DER certificate `der`, as `Anchor`, a struct of `subject` and `spki`.
pub fn anchor_of(comptime Anchor: type, der: []const u8) !Anchor {
    const certificate = try tlv(der);
    var fields = (try tlv(certificate.contents)).contents;
    var field = try tlv(fields);
    // The version is the one field with a context tag, [0], and it is optional.
    if (field.tag == 0xa0) {
        fields = fields[field.whole.len..];
        field = try tlv(fields);
    }
    // The serial, the signature, the issuer and the validity come before the subject.
    for (0..4) |_| {
        fields = fields[field.whole.len..];
        field = try tlv(fields);
    }
    const subject = field.whole;
    fields = fields[field.whole.len..];
    const key = (try tlv(fields)).whole;
    return .{ .subject = subject, .spki = key };
}

const Tlv = struct { tag: u8, whole: []const u8, contents: []const u8 };

/// One DER TLV at the start of `bytes`, with a length of one, two or three octets (X.690 §8.1.3).
fn tlv(bytes: []const u8) !Tlv {
    if (bytes.len < 2) return error.BadCertificate;
    const first = bytes[1];
    var header: usize = 2;
    var length: usize = first;
    if (first & 0x80 != 0) {
        const octets = first & 0x7f;
        if (octets == 0 or octets > 3 or bytes.len < 2 + octets) return error.BadCertificate;
        length = 0;
        for (bytes[2..][0..octets]) |octet| length = (length << 8) | octet;
        header += octets;
    }
    if (bytes.len < header + length) return error.BadCertificate;
    return .{ .tag = bytes[0], .whole = bytes[0 .. header + length], .contents = bytes[header..][0..length] };
}
