//! What one validation costs, by algorithm (docs/design.md §25 step 15, §11; §17 question 103):
//! the five algorithms colibri's verifier checks, 8, 10, 13, 14 and 15.
//!
//!     zig build bench-dnssec
//!
//! Two kinds of case:
//!
//! - A signature check alone: cocuyo's signed data of one RRset fed to chapulin, and the check.
//! - A whole message validated: the answer to `www.example.net A` read, its RRset and RRSIG found,
//!   the key taken from a store that holds it, and the check. The gap between the two rows is the
//!   DNS half of the cost, which is cocuyo's own.
//!
//! The keys and signatures are the ones the RFCs print: RFC 5702 §6 for algorithms 8 and 10,
//! RFC 6605 §6 for 13 and 14, RFC 8080 §6.1 for 15. RFC 5702's keys are 512 and 1,024 bits, far
//! smaller than the 2,048 bits a signed zone uses, so the RSA rows understate an RSA check. The
//! validator passes over a key under 1,024 bits (§25, New limits), so algorithm 8's key has the
//! check alone. RFC
//! 8080's example signs an MX set with a Labels field past its owner's labels, which cocuyo
//! refuses (RFC 4035 §5.3.1). So algorithm 15 has the check alone, over that example's signed data.
//!
//! Built ReleaseSafe, with colibri ReleaseSafe too, whatever `-Drelease` says. It needs colibri,
//! so it is a step of its own and not a part of `zig build bench`.
const std = @import("std");
const harness = @import("harness.zig");
const cocuyo = @import("cocuyo");
const core = @import("core");
const wire = @import("wire");
const validation = @import("validation");
const Chapulin = @import("cocuyo_dnssec").Chapulin;
const fixtures = @import("dnssec_fixtures");
const memset = @import("memset.zig");
const Name = cocuyo.Name;

// On Linux under Zig 0.16 the program's `memset` is `bench/memset.zig`'s, which says why.
comptime {
    if (memset.needed) @export(&memset.memset, .{ .name = "memset" });
}

/// One algorithm's example: the key, the RRSIG's fields, the signature, the address it signs and
/// the instant inside its dates.
const Example = struct {
    key: []const u8,
    fields: []const u8,
    signature: []const u8,
    address: [4]u8,
    unix_seconds: u64,
};

const rsa_sha256_key = fixtures.dnskey(256, 8, &fixtures.base64("AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8PkxUdp6p/DlUmObdk="));
const rsa_sha512_key = fixtures.dnskey(256, 10, &fixtures.base64("AwEAAdHoNTOW+et86KuJOWRDp1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFDxj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8gpMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL"));
const p256_key = fixtures.dnskey(257, 13, &fixtures.base64("GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="));
const p384_key = fixtures.dnskey(257, 14, &fixtures.base64("xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"));
const ed25519_key = fixtures.dnskey(257, 15, &fixtures.base64("l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="));
const ed25519_signature = fixtures.base64("Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkjH5GaMWeG96GUVZu6ECKOQmemHDg==");
const ed25519_tag = 3613;

const examples = struct {
    // RFC 5702 §6.1 and §6.2: inside 2000-01-01 to 2030-01-01.
    const rsa_sha256: Example = .{
        .key = &rsa_sha256_key,
        .fields = &fixtures.rrsig(1, 8, 3, 1893456000, 946684800, 9033, fixtures.example_net, ""),
        .signature = &fixtures.base64("kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEacFYK/lPtPiVYP4bwg=="),
        .address = .{ 192, 0, 2, 91 },
        .unix_seconds = 1262304000,
    };
    const rsa_sha512: Example = .{
        .key = &rsa_sha512_key,
        .fields = &fixtures.rrsig(1, 10, 3, 1893456000, 946684800, 3740, fixtures.example_net, ""),
        .signature = &fixtures.base64("tsb4wnjRUDnB1BUi+t6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRaeUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOLDiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw="),
        .address = .{ 192, 0, 2, 91 },
        .unix_seconds = 1262304000,
    };
    // RFC 6605 §6.1 and §6.2: 2010-08-20.
    const p256: Example = .{
        .key = &p256_key,
        .fields = &fixtures.rrsig(1, 13, 3, 1284026679, 1281607479, 55648, fixtures.example_net, ""),
        .signature = &fixtures.base64("qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="),
        .address = .{ 192, 0, 2, 1 },
        .unix_seconds = 1282262400,
    };
    const p384: Example = .{
        .key = &p384_key,
        .fields = &fixtures.rrsig(1, 14, 3, 1284027625, 1281608425, 10771, fixtures.example_net, ""),
        .signature = &fixtures.base64("/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuzWTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"),
        .address = .{ 192, 0, 2, 1 },
        .unix_seconds = 1282262400,
    };
};

/// What every case reads, set at its setup: the verifier, a store that holds the example's key,
/// the scratch, and the message or the signed data. Copied into `var`s, so the optimizer cannot
/// fold a check away (`bench/harness.zig`).
var chapulin: Chapulin = .{};
var entries: [2]validation.store.Entry = undefined;
var anchors: [1]validation.store.Anchor = undefined;
var store: validation.store.Store = undefined;
var scratch: validation.scratch.Scratch = .{};
var message_buffer: [1024]u8 = undefined;
var message: []const u8 = &.{};
var rrsig_buffer: [512]u8 = undefined;
var rrsig_rdata: []const u8 = &.{};
var key: []const u8 = &.{};
var address: [4]u8 = undefined;
var data_buffer: [256]u8 = undefined;
var data: []const u8 = &.{};

fn zone() Name {
    return Name.from_text("example.net") catch unreachable;
}

fn asked() Name {
    return Name.from_text("www.example.net") catch unreachable;
}

/// Sets up one example: the message, the RRSIG's rdata, and a store that holds the key. A key
/// the validator passes over, as RFC 5702 §6.1's 512 bits are, is not validated.
fn set(example: *const Example, validates: bool) void {
    key = example.key;
    address = example.address;
    message = fixtures.a_message(&message_buffer, example.address, example.fields, example.signature);
    @memcpy(rrsig_buffer[0..example.fields.len], example.fields);
    @memcpy(rrsig_buffer[example.fields.len..][0..example.signature.len], example.signature);
    rrsig_rdata = rrsig_buffer[0 .. example.fields.len + example.signature.len];
    anchors = .{.{ .zone = zone(), .kind = .dnskey, .rdata = example.key }};
    store = validation.store.Store.init(&entries, &anchors);
    store.set_clock(.{ .unix_seconds = example.unix_seconds, .now_ns = 0 });
    const held = store.put(&zone(), .keys, &.{example.key}, std.math.maxInt(u64));
    std.debug.assert(held);
    // Each case is checked once, here, so a row never measures a check that fails.
    std.debug.assert(check());
    if (validates) std.debug.assert(validate() == .secure);
}

/// cocuyo's signed data of the one A record, fed to chapulin, and the check.
fn check() bool {
    const verifier = chapulin.verifier();
    const sig = wire.rdata.Rrsig.parse(rrsig_rdata) catch unreachable;
    const public_key = fixtures.public_key(key);
    const hash = verifier.check_begin(verifier.context, sig.algorithm, public_key, sig.signature) orelse return false;
    const records = validation.canonical.Written{ .records = &.{&address} };
    validation.canonical.signed_data(rrsig_rdata, &asked(), .a, core.constants.class_internet, records, hash) catch return false;
    return verifier.check_end(verifier.context, public_key, sig.signature);
}

fn validate() validation.validate.Validation {
    const validator: validation.validate.Validator = .{ .store = &store, .verifier = chapulin.verifier(), .hasher = chapulin.hasher(), .scratch = &scratch };
    return validator.validate(&asked(), .a, message, 0);
}

fn run_check() void {
    std.mem.doNotOptimizeAway(check());
}

fn run_validate() void {
    std.mem.doNotOptimizeAway(validate());
}

/// RFC 8080 §6.1's signed data, fed to chapulin as it is, and the check.
fn check_ed25519() bool {
    const verifier = chapulin.verifier();
    const public_key = fixtures.public_key(key);
    const hash = verifier.check_begin(verifier.context, fixtures.ed25519, public_key, &ed25519_signature) orelse return false;
    hash.feed(data);
    return verifier.check_end(verifier.context, public_key, &ed25519_signature);
}

fn run_ed25519() void {
    std.mem.doNotOptimizeAway(check_ed25519());
}

fn set_ed25519() void {
    key = &ed25519_key;
    data = fixtures.ed25519_data(ed25519_tag, &data_buffer);
    std.debug.assert(check_ed25519());
}

fn set_rsa_sha256() void {
    set(&examples.rsa_sha256, false);
}

fn set_rsa_sha512() void {
    set(&examples.rsa_sha512, true);
}

fn set_p256() void {
    set(&examples.p256, true);
}

fn set_p384() void {
    set(&examples.p384, true);
}

/// The iterations make one sample last milliseconds on the machine of §11's rows.
const cases = [_]harness.Case{
    .{ .name = "check, RSA/SHA-256 (8), 512-bit key, RFC 5702", .iterations = 2000, .run = &run_check, .setup = &set_rsa_sha256 },
    .{ .name = "check, RSA/SHA-512 (10), 1024-bit key, RFC 5702", .iterations = 1000, .run = &run_check, .setup = &set_rsa_sha512 },
    .{ .name = "validate one A, RSA/SHA-512 (10), 1024-bit key", .iterations = 1000, .run = &run_validate, .setup = &set_rsa_sha512 },
    .{ .name = "check, ECDSA P-256 (13), RFC 6605", .iterations = 200, .run = &run_check, .setup = &set_p256 },
    .{ .name = "validate one A, ECDSA P-256 (13)", .iterations = 200, .run = &run_validate, .setup = &set_p256 },
    .{ .name = "check, ECDSA P-384 (14), RFC 6605", .iterations = 100, .run = &run_check, .setup = &set_p384 },
    .{ .name = "validate one A, ECDSA P-384 (14)", .iterations = 100, .run = &run_validate, .setup = &set_p384 },
    .{ .name = "check, Ed25519 (15), RFC 8080", .iterations = 500, .run = &run_ed25519, .setup = &set_ed25519 },
};

pub fn main() void {
    harness.run("cocuyo DNSSEC bench", &cases);
}
