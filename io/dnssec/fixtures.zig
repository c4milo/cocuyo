//! The examples RFC 5702, RFC 6605 and RFC 8080 print, and the octets of the records they sign,
//! for the tests of `cocuyo_dnssec` (`io_dnssec_test.zig`). Exempt from the magic-numbers rule by
//! name, like every corpus, and test-only.
const std = @import("std");
const validation = @import("validation");

/// The octets of a Base64 text, as the RFCs print keys and signatures.
pub fn base64(comptime text: []const u8) [std.base64.standard.Decoder.calcSizeForSlice(text) catch unreachable]u8 {
    @setEvalBranchQuota(100_000);
    var octets: [std.base64.standard.Decoder.calcSizeForSlice(text) catch unreachable]u8 = undefined;
    std.base64.standard.Decoder.decode(&octets, text) catch unreachable;
    return octets;
}

pub fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var octets: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&octets, text) catch unreachable;
    return octets;
}

/// A DNSKEY's rdata: flags, protocol 3, the algorithm, and the key.
pub fn dnskey(comptime flags: u16, comptime algorithm: u8, comptime key: []const u8) [4 + key.len]u8 {
    return [_]u8{ flags >> 8, flags & 0xff, 3, algorithm } ++ key[0..key.len].*;
}

/// An RRSIG's rdata: the fields RFC 4034 §3.1 lists, the signer, then the signature.
pub fn rrsig(
    comptime covered: u16,
    comptime algorithm: u8,
    comptime labels: u8,
    comptime expiration: u32,
    comptime inception: u32,
    comptime key_tag: u16,
    comptime signer: []const u8,
    comptime signature: []const u8,
) [18 + signer.len + signature.len]u8 {
    var out: [18 + signer.len + signature.len]u8 = undefined;
    std.mem.writeInt(u16, out[0..2], covered, .big);
    out[2] = algorithm;
    out[3] = labels;
    std.mem.writeInt(u32, out[4..8], 3600, .big);
    std.mem.writeInt(u32, out[8..12], expiration, .big);
    std.mem.writeInt(u32, out[12..16], inception, .big);
    std.mem.writeInt(u16, out[16..18], key_tag, .big);
    @memcpy(out[18..][0..signer.len], signer);
    @memcpy(out[18 + signer.len ..], signature);
    return out;
}

/// The Public Key field of a DNSKEY's rdata: what follows flags, protocol and algorithm.
pub fn public_key(rdata: []const u8) []const u8 {
    return rdata[4..];
}

/// The algorithm number of Ed25519 (RFC 8080 §5).
pub const ed25519: u8 = 15;

pub const example_net = "\x07example\x03net\x00";

/// RFC 8080 §6.1's signed data, built as RFC 4034 §3.1.8.1 has it: the RRSIG's rdata before its
/// signature, then the MX record. The example's RRSIG text leaves out the Algorithm field, 15,
/// and signs over Labels 3, where `example.com` has 2. cocuyo's signed data refuses a Labels
/// field past the owner's labels (RFC 4035 §5.3.1), so this one is built here.
pub fn ed25519_data(comptime key_tag: u16, out: []u8) []const u8 {
    const head = rrsig(15, 15, 3, 1440021600, 1438207200, key_tag, "\x07example\x03com\x00", "");
    const record = "\x07example\x03com\x00".* ++ [_]u8{ 0, 15, 0, 1, 0, 0, 0x0e, 0x10, 0, 20 } ++
        [_]u8{ 0, 10 } ++ "\x04mail\x07example\x03com\x00".*;
    @memcpy(out[0..head.len], &head);
    @memcpy(out[head.len..][0..record.len], &record);
    return out[0 .. head.len + record.len];
}

/// The base32hex of RFC 4648 §7 that RFC 5155 prints its hashes in, lowercase.
pub fn base32hex(hash: *const validation.nsec3.Hash) [32]u8 {
    const alphabet = "0123456789abcdefghijklmnopqrstuv";
    var out: [32]u8 = undefined;
    var accumulated: u16 = 0;
    var held: u4 = 0;
    var at: usize = 0;
    for (hash) |octet| {
        accumulated = (accumulated << 8) | octet;
        held += 8;
        while (held >= 5) {
            held -= 5;
            out[at] = alphabet[(accumulated >> held) & 0x1f];
            at += 1;
        }
    }
    return out;
}

/// RFC 6605 §6.1's answer as one message: the question, the A record and its RRSIG.
pub fn p256_message(out: []u8, signature: []const u8) []const u8 {
    const fields = rrsig(1, 13, 3, 1284026679, 1281607479, 55648, example_net, "");
    return a_message(out, .{ 192, 0, 2, 1 }, &fields, signature);
}

/// An answer to `www.example.net A` as one message, as RFC 5702 §6 and RFC 6605 §6 print it: the
/// question, the A record of `address`, and the RRSIG of `fields` and `signature` over it.
pub fn a_message(out: []u8, address: [4]u8, fields: []const u8, signature: []const u8) []const u8 {
    const owner = "\x03www\x07example\x03net\x00";
    const head = [_]u8{ 0, 0, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0 };
    var writer: std.Io.Writer = .fixed(out);
    writer.writeAll(&head) catch unreachable;
    writer.writeAll(owner ++ [_]u8{ 0, 1, 0, 1 }) catch unreachable;
    writer.writeAll(owner ++ [_]u8{ 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4 } ++ address) catch unreachable;
    writer.writeAll(owner ++ [_]u8{ 0, 46, 0, 1, 0, 0, 0x0e, 0x10 }) catch unreachable;
    writer.writeInt(u16, @intCast(fields.len + signature.len), .big) catch unreachable;
    writer.writeAll(fields) catch unreachable;
    writer.writeAll(signature) catch unreachable;
    return writer.buffered();
}
