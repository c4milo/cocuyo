//! RFC 5155 Appendix A's NSEC3 records and the responses of its Appendix B, signed for the tests'
//! verifier (docs/design.md §25 step 9). The RFC's zone signs with algorithm 7 under keys of its
//! own; these responses are signed by RFC 4035 Appendix A's zone key instead, which the tests'
//! store holds for `example`, since the tests' verifier reads no key's arithmetic. Every record of
//! the example has Opt-Out set, so each response is built with the flags a test asks for. The
//! additional sections are left out, since the validator never reads them. Exempt from the
//! magic-numbers rule by name, like every corpus, and test-only.
const std = @import("std");
const fixtures = @import("../fixtures.zig");
const zone = @import("../rfc4035/fixtures.zig");
const Builder = fixtures.Builder;

/// NSEC3 rdata: SHA-1, `flags`, `iterations`, the salt "aabbccdd", the next hash `next` in
/// base32hex, then the type bit map.
pub fn nsec3(comptime next: []const u8, comptime types: []const u8, flags: u8, iterations: u16) [30 + types.len]u8 {
    var rdata: [30 + types.len]u8 = undefined;
    rdata[0..5].* = .{ 1, flags, @intCast(iterations >> 8), @intCast(iterations & 0xff), 4 };
    rdata[5..9].* = .{ 0xaa, 0xbb, 0xcc, 0xdd };
    rdata[9] = 20;
    rdata[10..30].* = comptime decoded(next);
    @memcpy(rdata[30..], types);
    return rdata;
}

fn decoded(comptime text: []const u8) [20]u8 {
    @setEvalBranchQuota(10_000);
    var out: [20]u8 = undefined;
    std.debug.assert(@import("../dnssec_base32.zig").decode(text, &out).? == out.len);
    return out;
}

/// What a test builds the responses with: the flags of every NSEC3 record, and the iterations.
pub const Options = struct { flags: u8 = 1, iterations: u16 = 12 };

fn record(builder: *Builder, comptime owner: []const u8, comptime next: []const u8, comptime types: []const u8, options: Options) void {
    const rdata = nsec3(next, types, options.flags, options.iterations);
    builder.rrset(owner ++ ".example", .nsec3, &.{&rdata}, zone.by_zone);
}

const apex = "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
const ns1 = "2t7b4g4vsa5smi47k61mv5bv1a22bojr";
const x_w = "b4um86eghhds6nea196smvmlo4ors995";
const c = "35mthgpgcu1qg68fab165klnsnk3dpvl";
const y_w = "ji6neoaepv8b5o6k4ev33abha8ht9fgc";
const w = "k8udemvp1j2f7eg6jebps17vp3n8i58h";
const z_w_cover = "q04jkcevqvmu85r014c7dkba38o0ji5r";
const wildcard_w = "r53bq7cc2uvmubfu5ocmm6pers9tk9en";

/// B.1: a name error, `a.c.x.w.example A`.
pub fn name_error(options: Options) Builder {
    var builder = Builder.init("a.c.x.w.example", .a, 3);
    builder.authority();
    zone.apex_soa(&builder);
    record(&builder, apex, ns1, &fixtures.apex3, options);
    record(&builder, x_w, "gjeqe526plbf1g8mklp59enfd789njgi", &fixtures.mail3, options);
    record(&builder, c, x_w, &fixtures.secure_cut3, options);
    return builder;
}

/// B.2: no data, `ns1.example MX`.
pub fn no_data(options: Options) Builder {
    var builder = Builder.init("ns1.example", .mx, 0);
    builder.authority();
    zone.apex_soa(&builder);
    record(&builder, ns1, "2vptu5timamqttgl4luu9kg21e0aor3s", &fixtures.address3, options);
    return builder;
}

/// B.2.1: no data at an empty non-terminal, `y.w.example A`.
pub fn empty_non_terminal(options: Options) Builder {
    var builder = Builder.init("y.w.example", .a, 0);
    builder.authority();
    zone.apex_soa(&builder);
    record(&builder, y_w, w, &.{}, options);
    return builder;
}

/// B.3: a referral to the Opt-Out unsigned zone `c.example`, for `mc.c.example MX`.
pub fn referral(options: Options) Builder {
    var builder = Builder.init("mc.c.example", .mx, 0);
    builder.authority();
    builder.record("c.example", .ns, 3600, "\x03ns1\x01c\x07example\x00");
    builder.record("c.example", .ns, 3600, "\x03ns2\x01c\x07example\x00");
    record(&builder, c, x_w, &fixtures.secure_cut3, options);
    record(&builder, apex, ns1, &fixtures.apex3, options);
    return builder;
}

/// B.4: a wildcard expansion, `a.z.w.example MX`.
pub fn wildcard(options: Options) Builder {
    var builder = Builder.init("a.z.w.example", .mx, 0);
    var expanded = zone.by_zone;
    expanded.labels = 2;
    builder.rrset("a.z.w.example", .mx, &.{"\x00\x01\x02ai\x07example\x00"}, expanded);
    builder.authority();
    builder.rrset("example", .ns, &.{ "\x03ns1\x07example\x00", "\x03ns2\x07example\x00" }, zone.by_zone);
    record(&builder, z_w_cover, wildcard_w, &fixtures.address3, options);
    return builder;
}

/// B.5: wildcard no data, `a.z.w.example AAAA`.
pub fn wildcard_no_data(options: Options) Builder {
    var builder = Builder.init("a.z.w.example", .aaaa, 0);
    builder.authority();
    zone.apex_soa(&builder);
    record(&builder, w, "kohar7mbb8dc2ce8a9qvl8hon4k53uhi", &.{}, options);
    record(&builder, z_w_cover, wildcard_w, &fixtures.address3, options);
    record(&builder, wildcard_w, "t644ebqk9bibcna874givr6joj62mlhv", &fixtures.mail3, options);
    return builder;
}

/// B.6: no data for a DS asked of the child, `example DS`.
pub fn ds_at_child(options: Options) Builder {
    var builder = Builder.init("example", .ds, 0);
    builder.authority();
    zone.apex_soa(&builder);
    record(&builder, apex, ns1, &fixtures.apex3, options);
    return builder;
}
