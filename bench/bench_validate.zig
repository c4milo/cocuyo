//! cocuyo's half of a validation (docs/design.md §25 step 15, §17 question 111): one answer read,
//! its RRset and RRSIG found, the key taken from a store that holds it, and the signed data fed to
//! a verifier. The verifier is the tests' (`dnssec.fixtures.Sums`), which does no cryptography, so
//! the case counts cocuyo's own code and no change in chapulin moves it. `zig build bench-dnssec`
//! measures the whole of it over chapulin.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const validation = @import("validation");
const fixtures = validation.fixtures;
const Case = @import("harness.zig").Case;
const iterations = @import("bench_cases.zig").iterations;
const Name = cocuyo.Name;

/// The zone's key: the Zone Key flag, protocol 3, algorithm 5, which the tests' verifier takes,
/// and eight octets of public key.
const key = [_]u8{ 0x01, 0x00, 3, 5, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
/// Inside the RRSIG's default dates, 2004-04-09 to 2004-05-09: 2004-04-20.
const unix_seconds = 1082419200;

var sums: fixtures.Sums = .{};
var hashes: fixtures.Hashes = .{};
var entries: [2]validation.store.Entry = undefined;
var anchors: [1]validation.store.Anchor = undefined;
var store: validation.store.Store = undefined;
var scratch: validation.scratch.Scratch = .{};
var builder: fixtures.Builder = undefined;
var message: []const u8 = &.{};
var asked: Name = undefined;

fn setup() void {
    const zone = Name.from_text("example") catch unreachable;
    asked = Name.from_text("www.example") catch unreachable;
    anchors = .{.{ .zone = zone, .kind = .dnskey, .rdata = &key }};
    store = validation.store.Store.init(&entries, &anchors);
    store.set_clock(.{ .unix_seconds = unix_seconds, .monotonic_ns = 0 });
    const held = store.put(&zone, .keys, &.{&key}, std.math.maxInt(u64));
    assert(held);
    builder = fixtures.Builder.init("www.example", .a, 0);
    builder.rrset("www.example", .a, &.{&.{ 192, 0, 2, 1 }}, .{ .key_tag = validation.key_tag(&key), .public_key = key[4..] });
    message = builder.message();
    // Checked once here, so the row never measures a validation that fails.
    assert(validate() == .secure);
}

fn validate() validation.validate.Validation {
    const validator: validation.validate.Validator = .{ .store = &store, .verifier = sums.verifier(), .hasher = hashes.hasher(), .scratch = &scratch };
    return validator.validate(&asked, .a, message, 0);
}

fn run() void {
    std.mem.doNotOptimizeAway(validate());
}

pub const all = [_]Case{
    .{ .name = "validate one A, the tests' verifier (cocuyo's half)", .iterations = iterations, .run = &run, .setup = &setup },
};
