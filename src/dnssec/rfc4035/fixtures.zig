//! RFC 4035 Appendix A's zone and the responses of its Appendix B, signed for the tests'
//! verifier (docs/design.md §25 step 9). Each response holds the RFC's answer and authority
//! sections, record for record, with the RFC's RRSIG fields and a signature of `fixtures.Sums`.
//! The additional sections are left out, since the validator never reads them (§25 item 1). Exempt
//! from the magic-numbers rule by name, like every corpus, and test-only.
const std = @import("std");
const core = @import("core");
const fixtures = @import("../fixtures.zig");
const Builder = fixtures.Builder;
const map = fixtures.map;
const Name = core.Name;
const store_module = @import("../dnssec_store.zig");
const validating = @import("../dnssec_validate.zig");
const Scratch = @import("../dnssec_scratch.zig").Scratch;

/// The instant the tests read the zone at: 2004-04-20, inside its signatures' dates.
pub const now_seconds: u64 = 1082419200;

/// A store that holds `example`'s keys under its anchor, and the tests' cryptography.
pub const Setup = struct {
    entries: [4]store_module.Entry = undefined,
    anchors: [1]store_module.Anchor = undefined,
    store: store_module.Store = undefined,
    sums: fixtures.Sums = .{},
    hashes: fixtures.Hashes = .{},
    scratch: Scratch = .{},

    pub fn init(self: *Setup) void {
        self.anchors = .{.{ .zone = Name.from_text("example") catch unreachable, .kind = .dnskey, .rdata = &ksk }};
        self.store = store_module.Store.init(&self.entries, &self.anchors);
        self.store.set_clock(.{ .unix_seconds = now_seconds, .monotonic_ns = 0 });
        const held = self.store.put(&(Name.from_text("example") catch unreachable), .keys, &.{ &zsk, &ksk }, std.math.maxInt(u64));
        std.debug.assert(held);
    }

    pub fn validate(self: *Setup, asked: []const u8, kind: core.Kind, bytes: []const u8) validating.Validation {
        const validator: validating.Validator = .{ .store = &self.store, .verifier = self.sums.verifier(), .hasher = self.hashes.hasher(), .scratch = &self.scratch };
        return validator.validate(&(Name.from_text(asked) catch unreachable), kind, bytes, 0);
    }
};

/// The zone's two keys: flags, protocol 3, algorithm 5, then the key. The first has the tag
/// 38519 and signs the zone's data; the second, with the SEP flag, has the tag 9465 and signs
/// the DNSKEY set.
pub const zsk = key(256, "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBVrZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61ek8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFovBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZIySFNsgEYvh0z2542lzMKR4Dh8uZffQ==");
pub const ksk = key(257, "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXlLnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZsyCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzPRLMlGybr51bOV/1se0ODacj3DomyB4QB5gKTYot/K9alk5/j8vfd4jWCWD+E1Sze0Q==");

fn key(comptime flags: u16, comptime text: []const u8) [4 + 130]u8 {
    @setEvalBranchQuota(10_000);
    var out: [4 + 130]u8 = undefined;
    out[0..4].* = .{ @intCast(flags >> 8), @intCast(flags & 0xff), 3, 5 };
    std.base64.standard.Decoder.decode(out[4..], text) catch unreachable;
    return out;
}

/// A key with the zone key's tag and another public key: one high octet up by one, and the next
/// high octet down by one, keep the sum of 16-bit groups (RFC 4034 Appendix B).
pub const zsk_twin = twin: {
    var bytes = zsk;
    bytes[4] +%= 1;
    bytes[6] -%= 1;
    break :twin bytes;
};

/// A key of `algorithm`, above 5, with the zone key's tag: the algorithm octet moves up by some
/// count, and a later low octet, 0xd5, moves down by the same count.
pub fn zsk_of_algorithm(comptime algorithm: u8) [zsk.len]u8 {
    var bytes = zsk;
    const step = algorithm - bytes[3];
    bytes[3] = algorithm;
    bytes[7] -= step;
    return bytes;
}

/// The zone's signature on its data, and on its DNSKEY set.
pub const by_zone: fixtures.Signing = .{ .public_key = zsk[4..] };
pub const by_key_signing: fixtures.Signing = .{ .key_tag = 9465, .public_key = ksk[4..] };
/// A signature under the wrong key: the key-signing key's, with the zone key's tag.
pub const by_wrong_key: fixtures.Signing = .{ .public_key = ksk[4..] };

const ns1 = "\x03ns1\x07example\x00";
const ns2 = "\x03ns2\x07example\x00";
/// An address of the zone's, for an A record of a test's own.
pub const address = [_]u8{ 192, 0, 2, 1 };

pub const mx_xx = "\x00\x01\x02xx\x07example\x00";
const mx_ai = "\x00\x01\x02ai\x07example\x00";
pub const soa = ns1 ++ "\x04bugs\x01x\x01w\x07example\x00" ++
    [_]u8{ 0x40, 0x76, 0xfb, 0x31, 0, 0, 0x0e, 0x10, 0, 0, 0x01, 0x2c, 0, 0x36, 0xee, 0x80, 0, 0, 0x0e, 0x10 };

/// NSEC rdata: the next name, then the type bit map.
const nsec_b = ns1 ++ fixtures.ns;
const nsec_apex = "\x01a\x07example\x00" ++ fixtures.apex;
const nsec_ns1 = ns2 ++ fixtures.address;
const nsec_x_y_w = "\x02xx\x07example\x00" ++ fixtures.mail;
const nsec_wildcard = "\x01x\x01w\x07example\x00" ++ fixtures.mail;

/// The DS of `a.example`: key 57855, algorithm 5, SHA-1, as Appendix A prints it.
const ds_a = [_]u8{ 0xe1, 0xff, 5, 1 } ++ [_]u8{
    0xb6, 0xdc, 0xd4, 0x85, 0x71, 0x9a, 0xdc, 0xa1, 0x8e, 0x5f,
    0x3d, 0x48, 0xa2, 0x33, 0x16, 0x27, 0xfd, 0xd3, 0x63, 0x6b,
};

fn apex_ns(builder: *Builder) void {
    builder.rrset("example", .ns, &.{ ns1, ns2 }, by_zone);
}

pub fn apex_soa(builder: *Builder) void {
    builder.rrset("example", .soa, &.{soa}, by_zone);
}

/// The zone's DNSKEY set, signed by both keys, as a response to `example DNSKEY`.
pub fn keys() Builder {
    var builder = Builder.init("example", .dnskey, 0);
    builder.record("example", .dnskey, 3600, &zsk);
    builder.record("example", .dnskey, 3600, &ksk);
    builder.rrsig("example", .dnskey, &.{ &zsk, &ksk }, by_key_signing);
    builder.rrsig("example", .dnskey, &.{ &zsk, &ksk }, by_zone);
    return builder;
}

/// B.1: an answer, `x.w.example MX`.
pub fn answer() Builder {
    var builder = Builder.init("x.w.example", .mx, 0);
    builder.rrset("x.w.example", .mx, &.{mx_xx}, by_zone);
    builder.authority();
    apex_ns(&builder);
    return builder;
}

/// B.2: a name error, `ml.example A`.
pub fn name_error() Builder {
    var builder = Builder.init("ml.example", .a, 3);
    builder.authority();
    apex_soa(&builder);
    builder.rrset("b.example", .nsec, &.{nsec_b}, by_zone);
    builder.rrset("example", .nsec, &.{nsec_apex}, by_zone);
    return builder;
}

/// B.3: no data, `ns1.example MX`.
pub fn no_data() Builder {
    var builder = Builder.init("ns1.example", .mx, 0);
    builder.authority();
    apex_soa(&builder);
    builder.rrset("ns1.example", .nsec, &.{nsec_ns1}, by_zone);
    return builder;
}

/// B.4: a referral to the signed zone `a.example`, for `mc.a.example MX`.
pub fn referral_signed() Builder {
    var builder = Builder.init("mc.a.example", .mx, 0);
    builder.authority();
    builder.record("a.example", .ns, 3600, "\x03ns1\x01a\x07example\x00");
    builder.record("a.example", .ns, 3600, "\x03ns2\x01a\x07example\x00");
    builder.rrset("a.example", .ds, &.{&ds_a}, by_zone);
    return builder;
}

/// B.5: a referral to the unsigned zone `b.example`, for `mc.b.example MX`.
pub fn referral_unsigned() Builder {
    var builder = Builder.init("mc.b.example", .mx, 0);
    builder.authority();
    builder.record("b.example", .ns, 3600, "\x03ns1\x01b\x07example\x00");
    builder.record("b.example", .ns, 3600, "\x03ns2\x01b\x07example\x00");
    builder.rrset("b.example", .nsec, &.{nsec_b}, by_zone);
    return builder;
}

/// B.6: a wildcard expansion, `a.z.w.example MX`.
pub fn wildcard() Builder {
    var builder = Builder.init("a.z.w.example", .mx, 0);
    var expanded = by_zone;
    expanded.labels = 2;
    builder.rrset("a.z.w.example", .mx, &.{mx_ai}, expanded);
    builder.authority();
    apex_ns(&builder);
    builder.rrset("x.y.w.example", .nsec, &.{nsec_x_y_w}, by_zone);
    return builder;
}

/// B.7: wildcard no data, `a.z.w.example AAAA`.
pub fn wildcard_no_data() Builder {
    var builder = Builder.init("a.z.w.example", .aaaa, 0);
    builder.authority();
    apex_soa(&builder);
    builder.rrset("x.y.w.example", .nsec, &.{nsec_x_y_w}, by_zone);
    builder.rrset("*.w.example", .nsec, &.{nsec_wildcard}, by_zone);
    return builder;
}

/// B.8: no data for a DS asked of the child, `example DS`.
pub fn ds_at_child() Builder {
    var builder = Builder.init("example", .ds, 0);
    builder.authority();
    apex_soa(&builder);
    builder.rrset("example", .nsec, &.{nsec_apex}, by_zone);
    return builder;
}

/// The answers a walk reads (docs/design.md §25 step 12). `a.example` is a signed child, with
/// `example`'s two keys as its own and a DS of SHA-256 for its key-signing key.
pub fn child_ds() [12]u8 {
    return fixtures.ds_of(&(Name.from_text("a.example") catch unreachable), &ksk, 5, 2);
}

/// A response to `a.example DS`: the set `ds` holds, signed by `example`.
pub fn ds_answer(ds: []const u8) Builder {
    var builder = Builder.init("a.example", .ds, 0);
    builder.rrset("a.example", .ds, &.{ds}, by_zone);
    return builder;
}

/// A response to `a.example DNSKEY`: the child's keys, signed by both under its own name.
pub fn child_keys() Builder {
    var builder = Builder.init("a.example", .dnskey, 0);
    var by_child_key = by_key_signing;
    by_child_key.signer = "a.example";
    builder.rrset("a.example", .dnskey, &.{ &zsk, &ksk }, by_child_key);
    return builder;
}

/// A response to `name DS` that proves no DS at `name` with the NSEC at `owner`, and the apex SOA.
pub fn ds_denied(name: []const u8, owner: []const u8, nsec: []const u8) Builder {
    var builder = Builder.init(name, .ds, 0);
    builder.authority();
    apex_soa(&builder);
    builder.rrset(owner, .nsec, &.{nsec}, by_zone);
    return builder;
}

/// NSEC rdata of the zone's chain that the walk's denials read.
pub const nsec_at_b = nsec_b;
pub const nsec_at_apex = nsec_apex;
pub const nsec_at_ns1 = nsec_ns1;
pub const nsec_at_ns2 = "\x01*\x01w\x07example\x00" ++ fixtures.address;
pub const nsec_at_x_w = "\x01x\x01y\x01w\x07example\x00" ++ fixtures.mail;

comptime {
    if (soa.len != ns1.len + "\x04bugs\x01x\x01w\x07example\x00".len + 20) @compileError("not an SOA");
}
