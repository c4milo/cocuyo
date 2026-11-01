//! What NSEC3 records prove of a name and a type: no data, a name error, a wildcard answer with no
//! closer match, or an unsigned delegation (RFC 5155 §8, RFC 6840 §4, RFC 9276 §3.2, RFC 9824 §4).
//! The records come here verified, and the hashes come from the caller's `Hasher`, so nothing here
//! computes SHA-1 (docs/design.md §25, step 8).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Kind = core.Kind;
const Name = core.Name;
const canonical = core.canonical;
const constants = @import("constants.zig");
const Proof = @import("dnssec_nsec3_proof.zig").Proof;
pub const Record = @import("dnssec_nsec3_proof.zig").Record;
pub const Hasher = @import("dnssec_nsec3_proof.zig").Hasher;
pub const Hash = @import("dnssec_nsec3_proof.zig").Hash;

/// What a set of NSEC3 records proves of a name and a type. `insecure` is a proof the validator
/// may not call secure: an iteration count past `limits.nsec3_iterations_max` (RFC 9276 §3.2), or
/// a closest encloser proof whose next closer span has Opt-Out set. "names that would be covered by
/// the Opt-Out NSEC3 RR may or may not exist as insecure delegations" (RFC 5155 §9.2).
pub const Denial = enum { none, no_data, name_error, insecure };

/// What a proof of a wildcard answer, or of an unsigned delegation, came to.
pub const Holds = enum { no, yes, insecure };

/// What `records` prove of `kind` at `name`, with the hashes `hasher` computes.
pub fn deny(name: *const Name, kind: Kind, records: []const Record, hasher: Hasher) Denial {
    var proof = Proof.of(name, records, hasher) orelse return .none;
    if (proof.costly()) return .insecure;
    const hashed = proof.hash(name) orelse return .none;
    if (proof.matching(&hashed)) |record| return matched(record, name, kind);
    return unmatched(&proof, name, kind, &hashed);
}

/// What the records prove of `kind` at `name`, which no record matches: a closest encloser proof,
/// then the wildcard at the encloser, matched or covered (RFC 5155 §8.4, §8.6, §8.7).
fn unmatched(proof: *Proof, name: *const Name, kind: Kind, hashed: *const Hash) Denial {
    const encloser = proof.closest_encloser(name, hashed) orelse return .none;
    const insecure = encloser.next_closer.opt_out();
    // "the NSEC3 RR that covers the 'next closer' name has the Opt-Out bit set" (RFC 5155 §8.6).
    if (kind == .ds) return if (insecure) .insecure else .none;
    const wildcard = wildcard_at(name, encloser.labels) orelse return .none;
    const wildcard_hash = proof.hash(&wildcard) orelse return .none;
    var proved: Denial = .name_error;
    if (proof.matching(&wildcard_hash)) |record| {
        // "the bits corresponding to both QTYPE and CNAME MUST NOT be set" (RFC 5155 §8.7).
        if (!absent(record, kind)) return .none;
        proved = .no_data;
    } else if (proof.covering(&wildcard_hash) == null) {
        // "an NSEC3 RR that covers the wildcard at the closest encloser" (RFC 5155 §8.4).
        return .none;
    }
    return if (insecure) .insecure else proved;
}

/// Whether `records` prove that an answer a wildcard produced had no closer match: a record covers
/// the "next closer" name, one label longer than the wildcard's encloser, the rightmost `labels`
/// labels of `name`, which the answer's RRSIG counts (RFC 5155 §8.8).
pub fn wildcard_answer(name: *const Name, labels: u8, records: []const Record, hasher: Hasher) Holds {
    assert(labels < name.label_count());
    var proof = Proof.of(name, records, hasher) orelse return .no;
    if (proof.costly()) return .insecure;
    const next_closer = canonical.ancestor(name, labels + 1);
    const hashed = proof.hash(&next_closer) orelse return .no;
    return if (proof.covering(&hashed) != null) .yes else .no;
}

/// Whether `records` prove that the delegation at `name` is not signed (RFC 5155 §8.9). A record
/// at the name must set NS and clear DS and SOA; with none, a closest provable encloser proof must
/// rest on a span with Opt-Out set, which leaves the delegation `insecure`.
pub fn unsigned_delegation(name: *const Name, records: []const Record, hasher: Hasher) Holds {
    var proof = Proof.of(name, records, hasher) orelse return .no;
    if (proof.costly()) return .insecure;
    const hashed = proof.hash(name) orelse return .no;
    if (proof.matching(&hashed)) |record| {
        const types = record.nsec3.types;
        return if (types.has(.ns) and !types.has(.ds) and !types.has(.soa)) .yes else .no;
    }
    const encloser = proof.closest_encloser(name, &hashed) orelse return .no;
    return if (encloser.next_closer.opt_out()) .insecure else .no;
}

/// What a record that matches `name` proves of `kind` (RFC 5155 §8.5, §8.6). NXNAME says the name
/// does not exist (RFC 9824 §4).
fn matched(record: *const Record, name: *const Name, kind: Kind) Denial {
    const types = record.nsec3.types;
    if (types.nxname()) return .name_error;
    if (kind == .ds) {
        // A set SOA bit is the child's apex, which says nothing of the parent's DS (RFC 4035
        // Appendix C.8, as RFC 5155 §8.9 reads the same bit).
        return if (types.has(.soa) or !absent(record, kind)) .none else .no_data;
    }
    // An ancestor delegation "MUST NOT be used to assume nonexistence of any RRs below that zone
    // cut, which include all RRs at that (original) owner name other than DS RRs" (RFC 6840 §4.1).
    const cut = types.has(.ns) and !types.has(.soa) and record.signer.label_count() < name.label_count();
    if (cut or kind == .any) return .none;
    return if (absent(record, kind)) .no_data else .none;
}

/// Whether the record's map clears both `kind` and CNAME (RFC 5155 §8.5, RFC 6840 §4.3).
fn absent(record: *const Record, kind: Kind) bool {
    const types = record.nsec3.types;
    return !types.has(kind) and !types.has(.cname);
}

/// The wildcard at the closest encloser of `name`: "*." and its rightmost `labels` labels (RFC
/// 5155 §8.4). Null when it would not fit in a name.
fn wildcard_at(name: *const Name, labels: u8) ?Name {
    assert(labels < name.label_count());
    const encloser = canonical.ancestor(name, labels);
    var wildcard: Name = Name.empty;
    wildcard.append_label(constants.wildcard_label) catch unreachable;
    wildcard.terminate() catch unreachable;
    return wildcard.concat(&encloser) catch null;
}

// Tests.

const testing = std.testing;
const appendix_a = @import("fixtures.zig");
const record3 = appendix_a.record3;

test "RFC 5155 B.1: a.c.x.w.example does not exist, under the closest encloser x.w.example" {
    var table: appendix_a.Hashes = .{};
    const records = [_]Record{
        try record3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", &appendix_a.apex3, 1),
        try record3("b4um86eghhds6nea196smvmlo4ors995", "gjeqe526plbf1g8mklp59enfd789njgi", &appendix_a.mail3, 1),
        try record3("35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995", &appendix_a.secure_cut3, 1),
    };
    const asked = try Name.from_text("a.c.x.w.example");
    // The record that covers c.x.w.example has Opt-Out set, so the proof is not secure.
    try testing.expectEqual(Denial.insecure, deny(&asked, .a, &records, table.hasher()));
    var clear = records;
    for (&clear) |*each| each.nsec3.flags = 0;
    try testing.expectEqual(Denial.name_error, deny(&asked, .a, &clear, table.hasher()));
    // Without the record that covers *.x.w.example, a wildcard could have answered.
    try testing.expectEqual(Denial.none, deny(&asked, .a, clear[0..2], table.hasher()));
    // Without the record that matches x.w.example, no closest encloser is proved.
    try testing.expectEqual(Denial.none, deny(&asked, .a, &.{ clear[0], clear[2] }, table.hasher()));
}

test "RFC 5155 B.2 and B.2.1: ns1.example holds no MX, and the empty non-terminal y.w.example no A" {
    var table: appendix_a.Hashes = .{};
    const host = [_]Record{try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.address3, 1)};
    const ns1 = try Name.from_text("ns1.example");
    try testing.expectEqual(Denial.no_data, deny(&ns1, .mx, &host, table.hasher()));
    try testing.expectEqual(Denial.none, deny(&ns1, .a, &host, table.hasher()));
    try testing.expectEqual(Denial.none, deny(&ns1, .any, &host, table.hasher()));
    const empty = [_]Record{try record3("ji6neoaepv8b5o6k4ev33abha8ht9fgc", "k8udemvp1j2f7eg6jebps17vp3n8i58h", &.{}, 1)};
    try testing.expectEqual(Denial.no_data, deny(&try Name.from_text("y.w.example"), .a, &empty, table.hasher()));
    // RFC 6840 §4.3: the CNAME bit set denies every type.
    const alias = [_]Record{try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.alias3, 1)};
    try testing.expectEqual(Denial.none, deny(&ns1, .mx, &alias, table.hasher()));
}

test "RFC 5155 B.3: c.example is an unsigned delegation under an Opt-Out span" {
    var table: appendix_a.Hashes = .{};
    const records = [_]Record{
        try record3("35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995", &appendix_a.secure_cut3, 1),
        try record3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", &appendix_a.apex3, 1),
    };
    const cut = try Name.from_text("c.example");
    try testing.expectEqual(Holds.insecure, unsigned_delegation(&cut, &records, table.hasher()));
    try testing.expectEqual(Denial.insecure, deny(&cut, .ds, &records, table.hasher()));
    var clear = records;
    for (&clear) |*each| each.nsec3.flags = 0;
    try testing.expectEqual(Holds.no, unsigned_delegation(&cut, &clear, table.hasher()));
    try testing.expectEqual(Denial.none, deny(&cut, .ds, &clear, table.hasher()));
}

test "RFC 5155 B.4: a.z.w.example came from *.w.example, and z.w.example does not exist" {
    var table: appendix_a.Hashes = .{};
    const records = [_]Record{try record3("q04jkcevqvmu85r014c7dkba38o0ji5r", "r53bq7cc2uvmubfu5ocmm6pers9tk9en", &appendix_a.address3, 1)};
    const asked = try Name.from_text("a.z.w.example");
    try testing.expectEqual(Holds.yes, wildcard_answer(&asked, 2, &records, table.hasher()));
    // Labels 1 names a.z.w.example's next closer w.example, which the record does not cover.
    try testing.expectEqual(Holds.no, wildcard_answer(&asked, 1, &records, table.hasher()));
}

test "RFC 5155 B.5: a.z.w.example matches *.w.example, which holds no AAAA" {
    var table: appendix_a.Hashes = .{};
    const records = [_]Record{
        try record3("k8udemvp1j2f7eg6jebps17vp3n8i58h", "kohar7mbb8dc2ce8a9qvl8hon4k53uhi", &.{}, 1),
        try record3("q04jkcevqvmu85r014c7dkba38o0ji5r", "r53bq7cc2uvmubfu5ocmm6pers9tk9en", &appendix_a.address3, 1),
        try record3("r53bq7cc2uvmubfu5ocmm6pers9tk9en", "t644ebqk9bibcna874givr6joj62mlhv", &appendix_a.mail3, 1),
    };
    const asked = try Name.from_text("a.z.w.example");
    // The span that covers z.w.example has Opt-Out set, as every span of the example does.
    try testing.expectEqual(Denial.insecure, deny(&asked, .aaaa, &records, table.hasher()));
    var clear = records;
    for (&clear) |*each| each.nsec3.flags = 0;
    try testing.expectEqual(Denial.no_data, deny(&asked, .aaaa, &clear, table.hasher()));
    try testing.expectEqual(Denial.none, deny(&asked, .mx, &clear, table.hasher()));
    try testing.expectEqual(Denial.none, deny(&asked, .aaaa, clear[1..], table.hasher()));
}

test "RFC 5155 B.6: the child's apex record says nothing of a DS" {
    var table: appendix_a.Hashes = .{};
    const records = [_]Record{try record3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", &appendix_a.apex3, 1)};
    try testing.expectEqual(Denial.none, deny(&try Name.from_text("example"), .ds, &records, table.hasher()));
}

test "a compact denial's NXNAME says the name does not exist, and too many iterations is insecure" {
    // RFC 9824 §4: "In responses for nonexistent names, the Type Bit Maps field will contain only
    // the NXNAME Meta-TYPE".
    var table: appendix_a.Hashes = .{};
    const ns1 = try Name.from_text("ns1.example");
    var compact = try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2t7b4g4vsa5smi47k61mv5bv1a22bojs", &appendix_a.nxname3, 0);
    try testing.expectEqual(Denial.name_error, deny(&ns1, .aaaa, &.{compact}, table.hasher()));
    try testing.expectEqual(Denial.name_error, deny(&ns1, .ds, &.{compact}, table.hasher()));
    // RFC 9276 §3.2: past the limit the denial is insecure, before any hash is computed.
    compact.nsec3.iterations = @import("limits.zig").nsec3_iterations_max + 1;
    var costly_table: appendix_a.Hashes = .{};
    try testing.expectEqual(Denial.insecure, deny(&ns1, .aaaa, &.{compact}, costly_table.hasher()));
    try testing.expectEqual(@as(usize, 0), costly_table.computed);
}

test "an ancestor delegation's record denies no type at its owner but DS" {
    // RFC 6840 §4.1, over RFC 5155 Appendix A's a.example, which holds NS and DS.
    var table: appendix_a.Hashes = .{};
    const cut = [_]Record{try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.ns3, 0)};
    const ns1 = try Name.from_text("ns1.example");
    try testing.expectEqual(Denial.none, deny(&ns1, .a, &cut, table.hasher()));
    try testing.expectEqual(Denial.no_data, deny(&ns1, .ds, &cut, table.hasher()));
    try testing.expectEqual(Holds.yes, unsigned_delegation(&ns1, &cut, table.hasher()));
    // A DS bit set denies no DS, and makes the delegation signed.
    const signed = [_]Record{try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.secure_cut3, 0)};
    try testing.expectEqual(Denial.none, deny(&ns1, .ds, &signed, table.hasher()));
    try testing.expectEqual(Holds.no, unsigned_delegation(&ns1, &signed, table.hasher()));
}

test "a host and a zone's apex are no unsigned delegation" {
    // RFC 5155 §8.9: the NS bit set, and the DS and SOA bits clear.
    var table: appendix_a.Hashes = .{};
    const host = [_]Record{try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.address3, 0)};
    try testing.expectEqual(Holds.no, unsigned_delegation(&try Name.from_text("ns1.example"), &host, table.hasher()));
    const apex = [_]Record{try record3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", &appendix_a.apex3, 0)};
    try testing.expectEqual(Holds.no, unsigned_delegation(&try Name.from_text("example"), &apex, table.hasher()));
}

test "too many iterations make a wildcard answer and an unsigned delegation insecure" {
    var table: appendix_a.Hashes = .{};
    var costly = try record3("q04jkcevqvmu85r014c7dkba38o0ji5r", "r53bq7cc2uvmubfu5ocmm6pers9tk9en", &appendix_a.address3, 0);
    costly.nsec3.iterations = @import("limits.zig").nsec3_iterations_max + 1;
    const asked = try Name.from_text("a.z.w.example");
    try testing.expectEqual(Holds.insecure, wildcard_answer(&asked, 2, &.{costly}, table.hasher()));
    try testing.expectEqual(Holds.insecure, unsigned_delegation(&asked, &.{costly}, table.hasher()));
}

test "a match with no cover below it proves no closest encloser" {
    // RFC 5155 B.1 without the record that covers c.x.w.example: x.w.example matches, and
    // nothing shows that c.x.w.example does not exist.
    var table: appendix_a.Hashes = .{};
    const records = [_]Record{
        try record3("b4um86eghhds6nea196smvmlo4ors995", "gjeqe526plbf1g8mklp59enfd789njgi", &appendix_a.mail3, 0),
        try record3("35mthgpgcu1qg68fab165klnsnk3dpvl", "b4um86eghhds6nea196smvmlo4ors995", &appendix_a.secure_cut3, 0),
    };
    try testing.expectEqual(Denial.none, deny(&try Name.from_text("c.x.w.example"), .a, &records, table.hasher()));
}

test "a record of another zone takes no part in the proof" {
    // A record of the root's zone at ns1.example's hash, beside the apex record of example.
    var table: appendix_a.Hashes = .{};
    var root_zone = try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &.{}, 0);
    root_zone.owner = try Name.from_text("2t7b4g4vsa5smi47k61mv5bv1a22bojr");
    root_zone.signer = Name.root;
    const records = [_]Record{ try record3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", &appendix_a.apex3, 0), root_zone };
    try testing.expectEqual(Denial.none, deny(&try Name.from_text("ns1.example"), .a, &records, table.hasher()));
}
