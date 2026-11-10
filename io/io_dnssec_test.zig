//! Tests of `cocuyo_dnssec` over chapulin, against the examples the RFCs print (docs/design.md §25
//! step 10): the DS digests of RFC 4034 §5.4, RFC 4509 §2.3, RFC 6605 §6 and RFC 8080 §6.1, the
//! signatures of RFC 5702 §6, RFC 6605 §6 and RFC 8080 §6.1, and the NSEC3 hashes of RFC 5155
//! Appendix A. Each signature is checked over the data `validation.canonical.signed_data`
//! builds, where the RFC's RRSIG allows, and refused with one signed octet changed.
const std = @import("std");
const cocuyo = @import("cocuyo");
const core = @import("core");
const wire = @import("wire");
const validation = @import("validation");
const Name = cocuyo.Name;
const Chapulin = @import("cocuyo_dnssec").Chapulin;
const fixtures = @import("dnssec/fixtures.zig");
const base64 = fixtures.base64;
const hex = fixtures.hex;
const dnskey = fixtures.dnskey;
const rrsig = fixtures.rrsig;
const example_net = fixtures.example_net;
const ed25519_data = fixtures.ed25519_data;
const base32hex = fixtures.base32hex;
const p256_message = fixtures.p256_message;

const testing = std.testing;

/// What a DS digest of `digest_type` over the DNSKEY `rdata` of `owner` is.
fn digest_of(chapulin: *Chapulin, owner: []const u8, rdata: []const u8, digest_type: u8, out: *[validation.constants.digest_bytes]u8) []const u8 {
    const verifier = chapulin.verifier();
    const hash = verifier.digest_begin(verifier.context, digest_type);
    validation.ds_input(&(Name.parse(owner) catch unreachable), rdata, hash);
    return out[0..verifier.digest_end(verifier.context, out)];
}

test "the algorithms and digest types chapulin checks, and none of RSA/SHA-1" {
    var chapulin: Chapulin = .{};
    const verifier = chapulin.verifier();
    for ([_]u8{ 8, 10, 13, 14, 15 }) |algorithm| try testing.expect(verifier.checks(verifier.context, algorithm));
    // RFC 9905 §2, as §17 question 22 answers it, and Ed448, which no library here holds.
    for ([_]u8{ 1, 3, 5, 6, 7, 12, 16, 253 }) |algorithm| try testing.expect(!verifier.checks(verifier.context, algorithm));
    for ([_]u8{ 1, 2, 4 }) |digest_type| try testing.expect(verifier.digests(verifier.context, digest_type));
    for ([_]u8{ 0, 3, 5 }) |digest_type| try testing.expect(!verifier.digests(verifier.context, digest_type));
}

test "the DS digests of RFC 4034 §5.4 and RFC 4509 §2.3" {
    var chapulin: Chapulin = .{};
    var bytes: [wire.rdata.fixtures.dnskey_example_bytes]u8 = undefined;
    const key = wire.rdata.fixtures.dnskey_example(&bytes);
    var out: [validation.constants.digest_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, &wire.rdata.fixtures.ds_example_digest, digest_of(&chapulin, "dskey.example.com", key, 1, &out));
    const sha256 = hex("D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A");
    try testing.expectEqualSlices(u8, &sha256, digest_of(&chapulin, "dskey.example.com", key, 2, &out));
}

/// Whether `rrsig_rdata` verifies under `key`, the DNSKEY's rdata, over the A record `address`
/// at `owner`, through cocuyo's signed data.
fn verifies(chapulin: *Chapulin, rrsig_rdata: []const u8, owner: []const u8, address: []const u8, key: []const u8) !bool {
    const verifier = chapulin.verifier();
    const sig = try wire.rdata.Rrsig.parse(rrsig_rdata);
    const hash = verifier.check_begin(verifier.context, sig.algorithm, fixtures.public_key(key), sig.signature) orelse return false;
    const records = validation.canonical.Written{ .records = &.{address} };
    try validation.canonical.signed_data(rrsig_rdata, &try Name.parse(owner), .a, core.constants.class_internet, records, hash);
    return verifier.check_end(verifier.context, fixtures.public_key(key), sig.signature);
}

test "RFC 6605 §6.1 and §6.2: the ECDSA keys' DS digests and signatures" {
    var chapulin: Chapulin = .{};
    const p256 = dnskey(257, 13, &base64("GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="));
    const p384 = dnskey(257, 14, &base64("xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"));
    try testing.expectEqual(@as(u16, 55648), validation.key_tag(&p256));
    try testing.expectEqual(@as(u16, 10771), validation.key_tag(&p384));
    var out: [validation.constants.digest_bytes]u8 = undefined;
    try testing.expectEqualSlices(u8, &hex("b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17"), digest_of(&chapulin, "example.net", &p256, 2, &out));
    try testing.expectEqualSlices(u8, &hex("72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6"), digest_of(&chapulin, "example.net", &p384, 4, &out));
    const address = [_]u8{ 192, 0, 2, 1 };
    const sig256 = rrsig(1, 13, 3, 1284026679, 1281607479, 55648, example_net, &base64("qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="));
    const sig384 = rrsig(1, 14, 3, 1284027625, 1281608425, 10771, example_net, &base64("/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"));
    try testing.expect(try verifies(&chapulin, &sig256, "www.example.net", &address, &p256));
    try testing.expect(try verifies(&chapulin, &sig384, "www.example.net", &address, &p384));
    // One signed octet changed, the address, and the signature fails.
    const other = [_]u8{ 192, 0, 2, 2 };
    try testing.expect(!try verifies(&chapulin, &sig256, "www.example.net", &other, &p256));
    try testing.expect(!try verifies(&chapulin, &sig384, "www.example.net", &other, &p384));
    // The P-256 signature under the P-384 key's form is refused before it is checked.
    var wrong = sig256;
    wrong[2] = 14;
    try testing.expect(!try verifies(&chapulin, &wrong, "www.example.net", &address, &p384));
}

test "RFC 5702 §6: the RSA/SHA-256 and RSA/SHA-512 signatures" {
    var chapulin: Chapulin = .{};
    const rsa256 = dnskey(256, 8, &base64("AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk="));
    const rsa512 = dnskey(256, 10, &base64("AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"));
    try testing.expectEqual(@as(u16, 9033), validation.key_tag(&rsa256));
    try testing.expectEqual(@as(u16, 3740), validation.key_tag(&rsa512));
    const address = [_]u8{ 192, 0, 2, 91 };
    const sig256 = rrsig(1, 8, 3, 1893456000, 946684800, 9033, example_net, &base64("kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg=="));
    const sig512 = rrsig(1, 10, 3, 1893456000, 946684800, 3740, example_net, &base64("tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw="));
    // RFC 5702 §6.1's key is 512 bits, which RFC 5702 §2 allows for algorithm 8 and chapulin
    // admits; §25 asked it to admit 1024 at least. §6.2's is 1024 bits.
    try testing.expect(try verifies(&chapulin, &sig256, "www.example.net", &address, &rsa256));
    try testing.expect(try verifies(&chapulin, &sig512, "www.example.net", &address, &rsa512));
    const other = [_]u8{ 192, 0, 2, 92 };
    try testing.expect(!try verifies(&chapulin, &sig256, "www.example.net", &other, &rsa256));
    try testing.expect(!try verifies(&chapulin, &sig512, "www.example.net", &other, &rsa512));
}

fn ed25519_verifies(chapulin: *Chapulin, data: []const u8, key: []const u8, signature: []const u8) bool {
    const verifier = chapulin.verifier();
    const hash = verifier.check_begin(verifier.context, fixtures.ed25519, fixtures.public_key(key), signature) orelse return false;
    hash.feed(data);
    return verifier.check_end(verifier.context, fixtures.public_key(key), signature);
}

test "RFC 8080 §6.1: the two Ed25519 keys' DS digests and signatures" {
    var chapulin: Chapulin = .{};
    const keys = [_][4 + 32]u8{
        dnskey(257, 15, &base64("l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=")),
        dnskey(257, 15, &base64("zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=")),
    };
    const tags = [_]u16{ 3613, 35217 };
    const digests = [_][32]u8{
        hex("3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b"),
        hex("401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c"),
    };
    const signatures = [_][64]u8{
        base64("Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkjH5GaMWeG96GUVZu6ECKOQmemHDg=="),
        base64("5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3SzfcRawOle9bodhC+oip9ayUGjY9T/rL4rN3bOuESGDA=="),
    };
    var out: [validation.constants.digest_bytes]u8 = undefined;
    var buffer: [256]u8 = undefined;
    inline for (0..2) |index| {
        try testing.expectEqual(tags[index], validation.key_tag(&keys[index]));
        try testing.expectEqualSlices(u8, &digests[index], digest_of(&chapulin, "example.com", &keys[index], 2, &out));
        const data = ed25519_data(tags[index], &buffer);
        try testing.expect(ed25519_verifies(&chapulin, data, &keys[index], &signatures[index]));
        buffer[data.len - 1] +%= 1;
        try testing.expect(!ed25519_verifies(&chapulin, data, &keys[index], &signatures[index]));
    }
    // A signature shorter than Ed25519's 64 octets is of a form the algorithm refuses.
    try testing.expect(!ed25519_verifies(&chapulin, "data", &keys[0], signatures[0][0..63]));
}

test "RFC 5155 Appendix A: the hashed owner names, under salt aabbccdd and 12 iterations" {
    var chapulin: Chapulin = .{};
    const hasher = chapulin.hasher();
    const salt = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd };
    for ([_][2][]const u8{
        .{ "example", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom" },
        .{ "a.example", "35mthgpgcu1qg68fab165klnsnk3dpvl" },
        .{ "ai.example", "gjeqe526plbf1g8mklp59enfd789njgi" },
        .{ "ns1.example", "2t7b4g4vsa5smi47k61mv5bv1a22bojr" },
        .{ "*.w.example", "r53bq7cc2uvmubfu5ocmm6pers9tk9en" },
        .{ "xx.example", "t644ebqk9bibcna874givr6joj62mlhv" },
    }) |entry| {
        var hash: validation.nsec3.Hash = undefined;
        hasher.compute(hasher.context, (try Name.parse(entry[0])).wire(), &salt, 12, &hash);
        try testing.expectEqualStrings(entry[1], &base32hex(&hash));
    }
}

test "a whole message validates over chapulin: RFC 6605 §6.1's answer, under its key" {
    var chapulin: Chapulin = .{};
    const key = dnskey(257, 13, &base64("GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="));
    const zone = try Name.parse("example.net");
    const anchors = [_]validation.store.Anchor{.{ .zone = zone, .kind = .dnskey, .rdata = &key }};
    var entries: [2]validation.store.Entry = undefined;
    var store = validation.store.Store.init(&entries, &anchors);
    // 2010-08-20, inside the signature's dates.
    store.set_clock(.{ .unix_seconds = 1282262400, .monotonic_ns = 0 });
    try testing.expect(store.put(&zone, .keys, &.{&key}, std.math.maxInt(u64)));
    var scratch: validation.scratch.Scratch = .{};
    const validator: validation.validate.Validator = .{ .store = &store, .verifier = chapulin.verifier(), .hasher = chapulin.hasher(), .scratch = &scratch };
    var signature = base64("qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==");
    var buffer: [512]u8 = undefined;
    const asked = try Name.parse("www.example.net");
    const secure = validator.validate(&asked, .a, p256_message(&buffer, &signature), 0);
    try testing.expectEqual(validation.validate.Ending.answer, secure.secure.ending);
    signature[0] +%= 1;
    try testing.expect(validator.validate(&asked, .a, p256_message(&buffer, &signature), 0) == .bogus);
}
