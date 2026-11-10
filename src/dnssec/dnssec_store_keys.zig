//! A zone's DNSKEY set enters the store: a zone key in it matches an anchor or a held DS set,
//! and that key's signature over the set verifies (docs/design.md §25, walk rule 4, and step 9).
//! Split from `dnssec_store.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Kind = core.Kind;
const Name = core.Name;
const dnssec = @import("dnssec.zig");
const Verifier = dnssec.Verifier;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const rrset = @import("dnssec_rrset.zig");
const Scratch = @import("dnssec_scratch.zig").Scratch;
const message_reader = @import("dnssec_message.zig");
const store_module = @import("dnssec_store.zig");
const Store = store_module.Store;

pub const Admission = enum {
    /// The set is validated, and the store holds it.
    admitted,
    /// No anchor or DS names an algorithm and a digest type the verifier supports, so the zone is
    /// read as unsigned, and the store holds it as an insecure delegation (§25 item 5).
    insecure,
    /// No key matched, or none of those that matched verified the set.
    bogus,
    /// Neither an anchor nor a held DS set speaks for the zone yet.
    ds_wanted,
};

/// What a DNSKEY may match: an anchor's DS or DNSKEY rdata, or a record of a held DS set.
const Basis = struct {
    kind: Kind,
    rdata: []const u8,

    /// Whether it names an algorithm the verifier checks, and for a DS a digest type it computes.
    fn usable(self: *const Basis, verifier: Verifier) bool {
        if (self.kind == .dnskey) {
            const key = wire.rdata.Dnskey.parse(self.rdata) catch return false;
            return verifier.checks(verifier.context, key.algorithm);
        }
        const ds = wire.rdata.Ds.parse(self.rdata) catch return false;
        return usable_ds(verifier, &ds);
    }

    /// Whether the DNSKEY `rdata` of `zone`, read as `key`, is this anchor's DNSKEY, or has this
    /// DS record's tag, algorithm and digest (RFC 4034 §5.2). `sha256` passes a SHA-1 DS over.
    fn names(self: *const Basis, verifier: Verifier, zone: *const Name, rdata: []const u8, key: *const wire.rdata.Dnskey, sha256: bool) bool {
        if (self.kind == .dnskey) return std.mem.eql(u8, self.rdata, rdata);
        const ds = wire.rdata.Ds.parse(self.rdata) catch return false;
        if (ds.key_tag != dnssec.key_tag(rdata) or ds.algorithm != key.algorithm) return false;
        if (!usable_ds(verifier, &ds)) return false;
        if (sha256 and ds.digest_type == constants.digest_sha1) return false;
        return digest_matches(verifier, zone, rdata, &ds);
    }
};

pub const Bases = struct {
    items: [limits.anchors_max + limits.zone_keys_max]Basis = undefined,
    len: usize = 0,
    /// Set when a DS of SHA-256 the verifier computes is among them: "Validator implementations
    /// SHOULD ignore DS RRs containing SHA-1 digests if DS RRs with SHA-256 digests are present in
    /// the DS RRset" (RFC 4509 §3).
    sha256: bool = false,

    fn slice(self: *const Bases) []const Basis {
        return self.items[0..self.len];
    }
};

/// Reads `bytes`, a response to `zone DNSKEY`, and admits its DNSKEY set to `store` when it is
/// valid (RFC 4035 §5.2). It verifies under the matched keys alone, `zone` its only signer.
/// `scratch` is the key store's, which the admission writes and keeps nothing in.
pub fn admit(store: *Store, verifier: Verifier, scratch: *Scratch, zone: *const Name, bytes: []const u8, now_ns: u64) Error!Admission {
    const bases = gather(&scratch.bases, store, verifier, zone, now_ns);
    if (bases.len == 0) return .ds_wanted;
    const message = &scratch.message;
    if (!try message.read(bytes, zone)) return .bogus;
    const set = try message.rrset(.answer, .dnskey, zone);
    if (set.count() > limits.zone_keys_max) return .bogus;
    if (!supported(bases, verifier)) {
        const expires_ns = now_ns + @as(u64, set.ttl_seconds()) * constants.ns_per_second;
        return if (store.put(zone, .insecure, &.{}, expires_ns)) .insecure else .bogus;
    }
    const matched = matched_keys(&scratch.matched, bases, verifier, zone, &set);
    if (matched.len() == 0) return .bogus;
    var budget: rrset.Budget = .{};
    const only: Only = .{ .zone = zone, .keys = matched };
    const check: rrset.Check = .{
        .message = message,
        .signers = .{ .context = &only, .keys = Only.held },
        .verifier = verifier,
        .now_seconds = store.now_seconds(now_ns),
        .budget = &budget,
        .buffers = &scratch.buffers,
    };
    const valid = switch (try rrset.verify(check, &set, zone, .answer)) {
        .valid => |valid| valid,
        else => return .bogus,
    };
    return if (keep(&scratch.kept, store, zone, &set, valid.ttl_seconds, now_ns)) .admitted else .bogus;
}

/// The keys of `set` that match a basis, listed in `out`.
fn matched_keys(out: *[limits.zone_keys_max][]const u8, bases: *const Bases, verifier: Verifier, zone: *const Name, set: *const message_reader.Rrset) rrset.Keys {
    assert(set.count() <= limits.zone_keys_max);
    var count: usize = 0;
    for (0..set.count()) |index| {
        const rdata = set.record(index).rdata;
        if (!matches(bases, verifier, zone, rdata)) continue;
        out[count] = rdata;
        count += 1;
    }
    return .{ .list = out[0..count] };
}

/// Keeps every record of `set` as the zone's keys for `ttl_seconds`.
fn keep(records: []([]const u8), store: *Store, zone: *const Name, set: *const message_reader.Rrset, ttl_seconds: u32, now_ns: u64) bool {
    assert(set.count() <= records.len);
    for (0..set.count()) |index| records[index] = set.record(index).rdata;
    const expires_ns = now_ns + @as(u64, ttl_seconds) * constants.ns_per_second;
    return store.put(zone, .keys, records[0..set.count()], expires_ns);
}

/// The one signer an admission reads: the zone, under the keys that matched.
const Only = struct {
    zone: *const Name,
    keys: rrset.Keys,

    fn held(context: *const anyopaque, signer: *const Name) rrset.Held {
        const self: *const Only = @ptrCast(@alignCast(context));
        return if (signer.equal(self.zone)) .{ .keys = self.keys } else .outside;
    }
};

/// The anchors for exactly `zone`, then the records of the DS set the store holds for it.
fn gather(bases: *Bases, store: *const Store, verifier: Verifier, zone: *const Name, now_ns: u64) *const Bases {
    bases.len = 0;
    bases.sha256 = false;
    for (store.anchors) |*anchor| {
        if (!anchor.zone.equal(zone)) continue;
        bases.items[bases.len] = .{ .kind = anchor.kind, .rdata = anchor.rdata };
        bases.len += 1;
    }
    if (store.find(zone, now_ns)) |entry| if (entry.known == .ds) {
        for (0..entry.len) |index| {
            bases.items[bases.len] = .{ .kind = .ds, .rdata = entry.record(index) };
            bases.len += 1;
        }
    };
    assert(bases.len <= bases.items.len);
    for (bases.slice()) |basis| {
        const ds = wire.rdata.Ds.parse(basis.rdata) catch continue;
        if (basis.kind == .ds and ds.digest_type == constants.digest_sha256 and usable_ds(verifier, &ds)) bases.sha256 = true;
    }
    return bases;
}

/// Whether one basis names an algorithm the verifier checks, and for a DS a digest type it
/// computes. With none, the zone is unsigned for this validator (RFC 4035 §5.2, RFC 6840 §5.2).
fn supported(bases: *const Bases, verifier: Verifier) bool {
    for (bases.slice()) |*basis| if (basis.usable(verifier)) return true;
    return false;
}

fn usable_ds(verifier: Verifier, ds: *const wire.rdata.Ds) bool {
    return verifier.checks(verifier.context, ds.algorithm) and verifier.digests(verifier.context, ds.digest_type);
}

/// Whether the DNSKEY `rdata` of `zone` matches a basis. The check of the set refuses a key
/// without the Zone Key flag or of a protocol other than 3 (`rrset.verify`).
fn matches(bases: *const Bases, verifier: Verifier, zone: *const Name, rdata: []const u8) bool {
    const key = wire.rdata.Dnskey.parse(rdata) catch return false;
    for (bases.slice()) |*basis| if (basis.names(verifier, zone, rdata, &key, bases.sha256)) return true;
    return false;
}

fn digest_matches(verifier: Verifier, zone: *const Name, rdata: []const u8, ds: *const wire.rdata.Ds) bool {
    const hash = verifier.digest_begin(verifier.context, ds.digest_type);
    dnssec.ds_input(zone, rdata, hash);
    var digest: [constants.digest_bytes]u8 = undefined;
    const length = verifier.digest_end(verifier.context, &digest);
    assert(length <= digest.len);
    return std.mem.eql(u8, digest[0..length], ds.digest);
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const zone_fixtures = @import("rfc4035/fixtures.zig");

/// RFC 4035 Appendix A's dates hold this instant: 2004-04-20.
const now_seconds: u64 = 1082419200;

/// A store of two entries holds a zone's DS set and then its keys, or an insecure delegation.
const entries_count: usize = 2;
const Entries = [entries_count]store_module.Entry;

fn example() Name {
    return Name.from_text("example") catch unreachable;
}

/// Admits `bytes` to a store whose anchors are `anchors`, and whose DS set for `example` is `ds`.
fn admitted(anchors: []const store_module.Anchor, ds: []const []const u8, bytes: []const u8, entries: *Entries) !struct { Admission, Store } {
    var store = Store.init(entries, anchors);
    store.set_clock(.{ .unix_seconds = now_seconds, .monotonic_ns = 0 });
    if (ds.len > 0) try testing.expect(store.put(&example(), .ds, ds, std.math.maxInt(u64)));
    var sums: fixtures.Sums = .{};
    var scratch: Scratch = .{};
    const result = try admit(&store, sums.verifier(), &scratch, &example(), bytes, 0);
    return .{ result, store };
}

fn admission(anchors: []const store_module.Anchor, ds: []const []const u8, bytes: []const u8) !Admission {
    var entries: Entries = undefined;
    return (try admitted(anchors, ds, bytes, &entries))[0];
}

test "the zone's DNSKEY set enters under a DNSKEY anchor, kept for its TTL" {
    var builder = zone_fixtures.keys();
    var entries: Entries = undefined;
    const anchors = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &zone_fixtures.ksk }};
    const result, const store = try admitted(&anchors, &.{}, builder.message(), &entries);
    try testing.expectEqual(Admission.admitted, result);
    const entry = store.find(&example(), 0).?;
    try testing.expectEqual(store_module.Known.keys, entry.known);
    try testing.expectEqual(@as(u8, 2), entry.len);
    try testing.expectEqual(3600 * constants.ns_per_second, entry.expires_ns);
}

test "the set enters under a DS anchor, or a held DS set, and waits for a DS without either" {
    var builder = zone_fixtures.keys();
    const ds = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 2);
    const anchors = [_]store_module.Anchor{.{ .zone = example(), .kind = .ds, .rdata = &ds }};
    try testing.expectEqual(Admission.admitted, try admission(&anchors, &.{}, builder.message()));
    try testing.expectEqual(Admission.admitted, try admission(&.{}, &.{&ds}, builder.message()));
    try testing.expectEqual(Admission.ds_wanted, try admission(&.{}, &.{}, builder.message()));
    // An anchor for another zone speaks for nothing here.
    const elsewhere = [_]store_module.Anchor{.{ .zone = Name.from_text("org") catch unreachable, .kind = .ds, .rdata = &ds }};
    try testing.expectEqual(Admission.ds_wanted, try admission(&elsewhere, &.{}, builder.message()));
}

test "a DS of an algorithm or a digest the verifier lacks makes the zone insecure" {
    var builder = zone_fixtures.keys();
    for ([_]fixtures.DsRdata{ fixtures.ds_of(&example(), &zone_fixtures.ksk, 15, 2), fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 4) }) |ds| {
        var entries: Entries = undefined;
        const result, const store = try admitted(&.{}, &.{&ds}, builder.message(), &entries);
        try testing.expectEqual(Admission.insecure, result);
        try testing.expectEqual(store_module.Known.insecure, store.find(&example(), 0).?.known);
    }
}

test "a DS set that names Ed448 alone is insecure, and one that names it beside a checked algorithm is not" {
    // Algorithm 16 is Ed448, which no verifier checks (§25). The zone's keys are of algorithm 5,
    // which the tests' verifier checks as the real one checks 13.
    var builder = zone_fixtures.keys();
    const ed448 = fixtures.ds_of(&example(), &zone_fixtures.ksk, 16, 2);
    const checked = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 2);
    try testing.expectEqual(Admission.insecure, try admission(&.{}, &.{&ed448}, builder.message()));
    // "a validator accepts any single valid path" (RFC 6840 §5.11).
    try testing.expectEqual(Admission.admitted, try admission(&.{}, &.{ &ed448, &checked }, builder.message()));
    try testing.expectEqual(Admission.admitted, try admission(&.{}, &.{ &checked, &ed448 }, builder.message()));
}

test "a SHA-1 DS is passed over beside a SHA-256 one" {
    // RFC 4509 §3: the SHA-1 digest matches, and the SHA-256 one does not.
    var builder = zone_fixtures.keys();
    const sha1 = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 1);
    var sha256 = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 2);
    sha256[11] +%= 1;
    try testing.expectEqual(Admission.admitted, try admission(&.{}, &.{&sha1}, builder.message()));
    try testing.expectEqual(Admission.bogus, try admission(&.{}, &.{ &sha1, &sha256 }, builder.message()));
}

test "a set the matched key did not sign, or that holds no matched key, is bogus" {
    var builder = Builder.init("example", .dnskey, 0);
    builder.rrset("example", .dnskey, &.{ &zone_fixtures.zsk, &zone_fixtures.ksk }, zone_fixtures.by_zone);
    const anchors = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &zone_fixtures.ksk }};
    try testing.expectEqual(Admission.bogus, try admission(&anchors, &.{}, builder.message()));
    var keys = zone_fixtures.keys();
    const other = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &zone_fixtures.zsk_twin }};
    try testing.expectEqual(Admission.bogus, try admission(&other, &.{}, keys.message()));
    // A matched key without the Zone Key flag is no match.
    var not_zone = zone_fixtures.ksk;
    not_zone[0] = 0;
    var unflagged = Builder.init("example", .dnskey, 0);
    var signing = zone_fixtures.by_key_signing;
    signing.key_tag = dnssec.key_tag(&not_zone);
    unflagged.rrset("example", .dnskey, &.{&not_zone}, signing);
    const flagless = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &not_zone }};
    try testing.expectEqual(Admission.bogus, try admission(&flagless, &.{}, unflagged.message()));
}

const Builder = fixtures.Builder;

test "any changed octet of the DNSKEY set or of its RRSIGs keeps it out" {
    var builder = zone_fixtures.keys();
    const bytes = builder.message();
    const anchors = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &zone_fixtures.ksk }};
    var message: message_reader.Message = undefined;
    _ = try message.read(bytes, &example());
    for (message.records[0..message.count]) |record| {
        const ttl_at = record.end - record.rdata.len - 6;
        for (record.owner_offset..record.end) |at| {
            if (at >= ttl_at and at < ttl_at + 4) continue;
            var changed: [4096]u8 = undefined;
            @memcpy(changed[0..bytes.len], bytes);
            changed[at] +%= 1;
            const result = admission(&anchors, &.{}, changed[0..bytes.len]) catch continue;
            // The zone key's RRSIG is the one change that does not count: the matched key signs.
            if (result == .admitted) try testing.expect(at > message.records[2].end);
        }
    }
}

fn ds_anchor(ds: []const u8) [1]store_module.Anchor {
    return .{.{ .zone = example(), .kind = .ds, .rdata = ds }};
}

test "a DS is matched by its tag and algorithm before its digest is computed" {
    var builder = zone_fixtures.keys();
    const ds = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 2);
    var entries: Entries = undefined;
    var store = Store.init(&entries, &ds_anchor(&ds));
    store.set_clock(.{ .unix_seconds = now_seconds, .monotonic_ns = 0 });
    var sums: fixtures.Sums = .{};
    var scratch: Scratch = .{};
    try testing.expectEqual(Admission.admitted, try admit(&store, sums.verifier(), &scratch, &example(), builder.message(), 0));
    try testing.expectEqual(@as(usize, 1), sums.digested);
    // The key's digest under a DS of another algorithm matches nothing.
    const other = fixtures.ds_of(&example(), &zone_fixtures.ksk, 8, 2);
    try testing.expectEqual(Admission.bogus, try admission(&ds_anchor(&other), &.{}, builder.message()));
}

test "a DS whose digest is wrong, or of a type not computed, matches nothing" {
    var builder = zone_fixtures.keys();
    var wrong = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 2);
    wrong[11] +%= 1;
    try testing.expectEqual(Admission.bogus, try admission(&.{}, &.{&wrong}, builder.message()));
    // The digest of type 4 would match; a DS of a key the set lacks keeps the zone signed.
    const uncomputed = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 4);
    const absent = fixtures.ds_of(&example(), &zone_fixtures.zsk_twin, 5, 2);
    try testing.expectEqual(Admission.bogus, try admission(&.{}, &.{ &uncomputed, &absent }, builder.message()));
}

test "a DNSKEY anchor of an algorithm the verifier lacks makes the zone insecure" {
    var builder = zone_fixtures.keys();
    const key = zone_fixtures.zsk_of_algorithm(15);
    const anchors = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &key }};
    try testing.expectEqual(Admission.insecure, try admission(&anchors, &.{}, builder.message()));
}

test "no DNSKEY set, too many keys, too many octets, or a signer above the zone is bogus" {
    const anchors = [_]store_module.Anchor{.{ .zone = example(), .kind = .dnskey, .rdata = &zone_fixtures.ksk }};
    var empty = Builder.init("example", .dnskey, 0);
    try testing.expectEqual(Admission.bogus, try admission(&anchors, &.{}, empty.message()));
    var filler: [limits.zone_keys_max][4 + 300]u8 = undefined;
    var records: [limits.zone_keys_max + 1][]const u8 = undefined;
    for (&filler, 0..) |*key, index| {
        key.* = @splat(@intCast(index));
        records[index] = key;
    }
    records[limits.zone_keys_max] = &zone_fixtures.ksk;
    // Every key but the anchor's, and the anchor's: one key too many.
    var many = Builder.init("example", .dnskey, 0);
    many.rrset("example", .dnskey, &records, zone_fixtures.by_key_signing);
    try testing.expectEqual(Admission.bogus, try admission(&anchors, &.{}, many.message()));
    // Fewer keys, and more octets than an entry holds.
    var big = Builder.init("example", .dnskey, 0);
    big.rrset("example", .dnskey, records[limits.zone_keys_max - 7 ..], zone_fixtures.by_key_signing);
    try testing.expectEqual(Admission.bogus, try admission(&anchors, &.{}, big.message()));
    var above = Builder.init("example", .dnskey, 0);
    var signing = zone_fixtures.by_key_signing;
    signing.signer = ".";
    above.rrset("example", .dnskey, &.{&zone_fixtures.ksk}, signing);
    try testing.expectEqual(Admission.bogus, try admission(&anchors, &.{}, above.message()));
}

test "a key set the store holds is no DS set to match a new one against" {
    var builder = zone_fixtures.keys();
    var entries: Entries = undefined;
    var store = Store.init(&entries, &.{});
    store.set_clock(.{ .unix_seconds = now_seconds, .monotonic_ns = 0 });
    const ds = fixtures.ds_of(&example(), &zone_fixtures.ksk, 5, 2);
    try testing.expect(store.put(&example(), .keys, &.{&ds}, std.math.maxInt(u64)));
    var sums: fixtures.Sums = .{};
    var scratch: Scratch = .{};
    try testing.expectEqual(Admission.ds_wanted, try admit(&store, sums.verifier(), &scratch, &example(), builder.message(), 0));
}
