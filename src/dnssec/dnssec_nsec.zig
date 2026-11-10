//! What NSEC records prove of a name and a type: that the type does not exist at the name, that
//! the name does not exist, that a wildcard answer had no closer match, or that a delegation is
//! not signed (RFC 4035 §5.4, as RFC 6840 §4 clarifies it, and RFC 9824 §3). The records come
//! here verified: their signatures are the validator's (docs/design.md §25, step 8).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Kind = core.Kind;
const Name = core.Name;
const canonical = core.canonical;
const constants = @import("constants.zig");

/// An NSEC record the validator verified, with what the RRSIG over it said.
pub const Record = struct {
    owner: Name,
    /// The RRSIG's signer: the apex of the zone the record is in.
    signer: Name,
    /// The RRSIG's Labels field.
    labels: u8,
    nsec: wire.rdata.Nsec,
};

/// What a set of NSEC records proves of a name and a type. The response code is not signed, so
/// the proof says which negative the answer is (RFC 9824 §8).
pub const Denial = enum { none, no_data, name_error };

/// What `records` prove of `kind` at `name`. A record matches the name, or covers it in canonical
/// order, and a name it covers needs the wildcard at its closest encloser denied too (RFC 4035
/// §5.4, §3.1.3.4).
pub fn deny(name: *const Name, kind: Kind, records: []const Record) Denial {
    assert(records.len <= core.limits.records_max);
    if (matching(name, records)) |record| return matched(record, kind);
    const covering = covering_record(name, records) orelse return .none;
    // An empty non-terminal exists: the record covers it, and the next name is below it (RFC
    // 4592 §2.2.2). It holds no type, and no wildcard answers for a name that exists.
    const next_labels = covering.nsec.next.label_count();
    if (next_labels > name.label_count() and under(&covering.nsec.next, name)) return .no_data;
    const wildcard = wildcard_at(name, closest_encloser(name, covering)) orelse return .none;
    if (matching(&wildcard, records)) |record| {
        // "no RRsets matching STYPE at the wildcard owner name" (RFC 4035 §3.1.3.4).
        return if (matched(record, kind) == .no_data) .no_data else .none;
    }
    if (covering_record(&wildcard, records) != null) return .name_error;
    return .none;
}

/// Whether `records` prove that an answer a wildcard produced had no closer match: one covers
/// `name`, and the closest encloser it shows is the wildcard's, the rightmost `labels` labels of
/// `name`, which the answer's RRSIG counts (RFC 4035 §5.3.4, §3.1.3.3).
pub fn wildcard_answer(name: *const Name, labels: u8, records: []const Record) bool {
    assert(labels < name.label_count());
    assert(records.len <= core.limits.records_max);
    for (records) |*record| {
        if (!usable(record, name) or !covers(record, name)) continue;
        if (closest_encloser(name, record) == labels) return true;
    }
    return false;
}

/// Whether `records` prove that the delegation at `name` is not signed: a record at the name with
/// the NS bit set and the DS and SOA bits clear (RFC 4035 §5.2, RFC 6840 §4.4). A set SOA bit is
/// the child's apex, which proves nothing of the parent's side.
pub fn unsigned_delegation(name: *const Name, records: []const Record) bool {
    assert(records.len <= core.limits.records_max);
    const record = matching(name, records) orelse return false;
    const types = record.nsec.types;
    return types.has(.ns) and !types.has(.ds) and !types.has(.soa);
}

/// What a record at the name proves of `kind`. NXNAME says the name does not exist (RFC 9824
/// §3.1). Otherwise the type's bit and the CNAME bit must both be clear (RFC 4035 §5.4, RFC 6840
/// §4.3).
fn matched(record: *const Record, kind: Kind) Denial {
    const types = record.nsec.types;
    if (types.nxname()) return .name_error;
    if (kind == .ds) {
        // The child's apex holds the SOA, and a DS lives on the parent's side (RFC 4035 Appendix
        // C.8).
        if (types.has(.soa)) return .none;
    } else if (delegation(record)) {
        // "MUST NOT be used to assume nonexistence of any RRs below that zone cut, which include
        // all RRs at that (original) owner name other than DS RRs" (RFC 6840 §4.1).
        return .none;
    }
    // The record proves that it and its RRSIG exist: "a validator MUST ignore the settings of
    // the NSEC and RRSIG bits" (RFC 4035 §5.4). So does ANY, which they answer.
    if (kind == .nsec or kind == .rrsig or kind == .any) return .none;
    if (types.has(kind) or types.has(.cname)) return .none;
    return .no_data;
}

/// The usable record whose owner is `name`.
fn matching(name: *const Name, records: []const Record) ?*const Record {
    for (records) |*record| {
        if (usable(record, name) and record.owner.equal(name)) return record;
    }
    return null;
}

/// The usable record that covers `name`, and may deny a name below its owner.
fn covering_record(name: *const Name, records: []const Record) ?*const Record {
    for (records) |*record| {
        if (usable(record, name) and covers(record, name)) return record;
    }
    return null;
}

/// Whether `record` may speak of `name`: the name is in its zone, and its owner is no wildcard
/// expansion. "The owner names of these NSEC and RRSIG RRs are not subject to wildcard name
/// expansion" (RFC 4035 §3.1.3.2), so an RRSIG whose Labels field counts fewer labels than the
/// owner holds, a leading "*" apart (RFC 4034 §3.1.3), was made over another name.
fn usable(record: *const Record, name: *const Name) bool {
    if (!under(name, &record.signer) or !under(&record.owner, &record.signer)) return false;
    const owner_labels = record.owner.label_count();
    const wildcard: u8 = if (is_wildcard(&record.owner)) 1 else 0;
    return record.labels == owner_labels - wildcard;
}

/// Whether `name` falls after the owner and before the next name in canonical order (RFC 4035
/// §5.4). The last record of a zone names the apex next, so its span wraps past the end. A
/// record may not deny a name below its owner when it marks a zone cut or a DNAME there (RFC
/// 6840 §4.1).
fn covers(record: *const Record, name: *const Name) bool {
    const after_owner = record.owner.canonical_order(name) == .lt;
    const before_next = name.canonical_order(&record.nsec.next) == .lt;
    const inside = if (record.owner.canonical_order(&record.nsec.next) == .lt)
        after_owner and before_next
    else
        after_owner or before_next;
    if (!inside) return false;
    if (!under(name, &record.owner)) return true;
    return !delegation(record) and !record.nsec.types.has(.dname);
}

/// An "ancestor delegation" record: the NS bit set, the SOA bit clear, and a signer shorter than
/// the owner (RFC 6840 §4.1).
fn delegation(record: *const Record) bool {
    const types = record.nsec.types;
    if (!types.has(.ns) or types.has(.soa)) return false;
    return record.signer.label_count() < record.owner.label_count();
}

/// The labels of the closest encloser a covering record shows for `name`. Nothing exists between
/// the owner and the next name, and a name's descendants follow it in canonical order (RFC 4034
/// §6.1). So the deepest ancestor of `name` that exists is an ancestor of one of them, which is
/// the closest encloser (RFC 4592 §3.3.1). No RFC states this step: it follows from those two.
fn closest_encloser(name: *const Name, record: *const Record) u8 {
    const by_owner = canonical.shared_labels(name, &record.owner);
    const by_next = canonical.shared_labels(name, &record.nsec.next);
    const labels = @max(by_owner, by_next);
    assert(labels <= name.label_count());
    return labels;
}

/// The wildcard at the closest encloser of `name`: "*." and its rightmost `labels` labels (RFC
/// 4592 §3.3.1). Null when the name is the encloser itself, which a covering record never shows,
/// or when the wildcard would not fit in a name.
fn wildcard_at(name: *const Name, labels: u8) ?Name {
    if (labels >= name.label_count()) return null;
    const encloser = canonical.ancestor(name, labels);
    var wildcard: Name = Name.empty;
    wildcard.append_label(constants.wildcard_label) catch unreachable;
    wildcard.terminate() catch unreachable;
    return wildcard.concat(&encloser) catch null;
}

/// Whether `name` is `zone` or below it.
fn under(name: *const Name, zone: *const Name) bool {
    return canonical.shared_labels(name, zone) == zone.label_count();
}

fn is_wildcard(name: *const Name) bool {
    const label = constants.wildcard_label;
    return name.bytes[0] == label.len and std.mem.eql(u8, name.bytes[1..][0..label.len], label);
}

// Tests.

const testing = std.testing;
const appendix_a = @import("fixtures.zig");

test "RFC 4035 B.2: ml.example does not exist, and no wildcard at example answers for it" {
    const records = [_]Record{ try appendix_a.record("b.example", "ns1.example", &appendix_a.ns), try appendix_a.record("example", "a.example", &appendix_a.apex) };
    try testing.expectEqual(Denial.name_error, deny(&try Name.parse("ml.example"), .a, &records));
    // Without the record that covers *.example, a wildcard could have answered.
    try testing.expectEqual(Denial.none, deny(&try Name.parse("ml.example"), .a, records[0..1]));
}

test "RFC 4035 B.3: ns1.example holds no MX, and a type its map sets is not denied" {
    const records = [_]Record{try appendix_a.record("ns1.example", "ns2.example", &appendix_a.address)};
    const ns1 = try Name.parse("ns1.example");
    try testing.expectEqual(Denial.no_data, deny(&ns1, .mx, &records));
    try testing.expectEqual(Denial.none, deny(&ns1, .a, &records));
    try testing.expectEqual(Denial.none, deny(&ns1, .nsec, &records));
    try testing.expectEqual(Denial.none, deny(&ns1, .rrsig, &records));
    try testing.expectEqual(Denial.none, deny(&ns1, .any, &records));
}

test "a record with the CNAME bit set denies no type at its owner" {
    // RFC 6840 §4.3: a CNAME stripped from the answer would otherwise read as no data.
    const records = [_]Record{try appendix_a.record("ns1.example", "ns2.example", &appendix_a.alias)};
    try testing.expectEqual(Denial.none, deny(&try Name.parse("ns1.example"), .mx, &records));
}

test "RFC 4035 B.6: the record that covers a.z.w.example shows the wildcard's encloser w.example" {
    const records = [_]Record{try appendix_a.record("x.y.w.example", "xx.example", &appendix_a.mail)};
    const asked = try Name.parse("a.z.w.example");
    try testing.expect(wildcard_answer(&asked, 2, &records));
    // Labels 1 claims *.example, and the record shows w.example exists, a closer encloser.
    try testing.expect(!wildcard_answer(&asked, 1, &records));
    try testing.expect(!wildcard_answer(&asked, 2, &.{}));
}

test "RFC 4035 B.7: a.z.w.example matches *.w.example, which holds no AAAA" {
    const records = [_]Record{ try appendix_a.record("x.y.w.example", "xx.example", &appendix_a.mail), try appendix_a.record("*.w.example", "x.w.example", &appendix_a.mail) };
    const asked = try Name.parse("a.z.w.example");
    try testing.expectEqual(Denial.no_data, deny(&asked, .aaaa, &records));
    try testing.expectEqual(Denial.none, deny(&asked, .mx, &records));
    try testing.expectEqual(Denial.none, deny(&asked, .aaaa, records[0..1]));
}

test "RFC 4035 B.8: the child's apex record says nothing of a DS" {
    const records = [_]Record{try appendix_a.record("example", "a.example", &appendix_a.apex)};
    try testing.expectEqual(Denial.none, deny(&try Name.parse("example"), .ds, &records));
}

test "RFC 4035 B.5: b.example is an unsigned delegation, and its record denies nothing below it" {
    const records = [_]Record{try appendix_a.record("b.example", "ns1.example", &appendix_a.ns)};
    const cut = try Name.parse("b.example");
    try testing.expect(unsigned_delegation(&cut, &records));
    try testing.expectEqual(Denial.no_data, deny(&cut, .ds, &records));
    // RFC 6840 §4.1: neither a type at the cut but DS, nor a name below it.
    try testing.expectEqual(Denial.none, deny(&cut, .mx, &records));
    try testing.expectEqual(Denial.none, deny(&try Name.parse("mc.b.example"), .mx, &records));
    // a.example's record sets DS, and the apex's sets SOA: neither is an unsigned delegation.
    const signed = [_]Record{try appendix_a.record("a.example", "ai.example", &appendix_a.secure_cut)};
    try testing.expect(!unsigned_delegation(&try Name.parse("a.example"), &signed));
    const apex = [_]Record{try appendix_a.record("example", "a.example", &appendix_a.apex)};
    try testing.expect(!unsigned_delegation(&try Name.parse("example"), &apex));
    const host = [_]Record{try appendix_a.record("ns1.example", "ns2.example", &appendix_a.address)};
    try testing.expect(!unsigned_delegation(&try Name.parse("ns1.example"), &host));
}

test "an empty non-terminal holds no data, as w.example and y.w.example do in RFC 4035 Appendix A" {
    const records = [_]Record{ try appendix_a.record("ns2.example", "*.w.example", &appendix_a.address), try appendix_a.record("x.w.example", "x.y.w.example", &appendix_a.mail) };
    try testing.expectEqual(Denial.no_data, deny(&try Name.parse("w.example"), .a, &records));
    try testing.expectEqual(Denial.no_data, deny(&try Name.parse("y.w.example"), .mx, &records));
}

test "the zone's last record wraps to the apex and covers what sorts after it" {
    const records = [_]Record{ try appendix_a.record("xx.example", "example", &appendix_a.everything), try appendix_a.record("example", "a.example", &appendix_a.apex) };
    try testing.expectEqual(Denial.name_error, deny(&try Name.parse("zz.example"), .a, &records));
}

test "a record with the DNAME bit set denies no name below its owner" {
    // RFC 6840 §4.1. b.example covers mc.b.example in order, and a DNAME there redirects it.
    const records = [_]Record{ try appendix_a.record("b.example", "ns1.example", &appendix_a.redirect), try appendix_a.record("example", "a.example", &appendix_a.apex) };
    try testing.expectEqual(Denial.none, deny(&try Name.parse("mc.b.example"), .a, &records));
}

test "a record signed as a wildcard expansion, or outside the zone asked, proves nothing" {
    var expanded = try appendix_a.record("ns1.example", "ns2.example", &appendix_a.address);
    expanded.labels = 1;
    try testing.expectEqual(Denial.none, deny(&try Name.parse("ns1.example"), .mx, &.{expanded}));
    var other_zone = try appendix_a.record("ns1.example", "ns2.example", &appendix_a.address);
    other_zone.signer = try Name.parse("other");
    try testing.expectEqual(Denial.none, deny(&try Name.parse("ns1.example"), .mx, &.{other_zone}));
    // The zone is example, and the name asked is under another, which the last record's span
    // would wrap over.
    const records = [_]Record{try appendix_a.record("xx.example", "example", &appendix_a.everything)};
    try testing.expectEqual(Denial.none, deny(&try Name.parse("www.other"), .a, &records));
}

test "a compact denial's NXNAME says the name does not exist, under NOERROR" {
    // RFC 9824 §3.1: "a.example.com. 300 IN NSEC \000.a.example.com. RRSIG NSEC NXNAME".
    var record = try appendix_a.record("a.example", "a.example", &appendix_a.compact);
    record.nsec.next = try appendix_a.epsilon("a.example");
    try testing.expectEqual(Denial.name_error, deny(&try Name.parse("a.example"), .aaaa, &.{record}));
    // The same record without NXNAME is an empty non-terminal (§3.2).
    var empty = record;
    empty.nsec.types = try wire.rdata.TypeBitmaps.parse(&appendix_a.nothing);
    try testing.expectEqual(Denial.no_data, deny(&try Name.parse("a.example"), .aaaa, &.{empty}));
}

test "a record whose owner is outside its signer's zone covers nothing" {
    // "other" sorts after every name under example, so its span would wrap over ml.example.
    var outside = try appendix_a.record("other", "zz.example", &appendix_a.address);
    outside.signer = try Name.parse("example");
    const records = [_]Record{ outside, try appendix_a.record("example", "a.example", &appendix_a.apex) };
    try testing.expectEqual(Denial.none, deny(&try Name.parse("ml.example"), .a, &records));
}

test "a record at its signer's own name is no delegation, with the SOA bit clear or not" {
    // RFC 6840 §4.1 asks for "a signer field that is shorter than the owner name".
    const records = [_]Record{try appendix_a.record("example", "a.example", &appendix_a.ns)};
    try testing.expectEqual(Denial.no_data, deny(&try Name.parse("example"), .mx, &records));
}

test "the closest encloser is the deeper of what the owner and the next name show" {
    // a.y.w.example falls between x.w.example and x.y.w.example: its closest encloser is the
    // empty non-terminal y.w.example, which the next name shows, and *.y.w.example is covered.
    const records = [_]Record{ try appendix_a.record("x.w.example", "x.y.w.example", &appendix_a.mail), try appendix_a.record("*.w.example", "x.w.example", &appendix_a.mail) };
    try testing.expectEqual(Denial.name_error, deny(&try Name.parse("a.y.w.example"), .a, &records));
    // a.x.w.example falls in the same span, and its closest encloser x.w.example is the owner.
    try testing.expectEqual(Denial.name_error, deny(&try Name.parse("a.x.w.example"), .a, &records));
}
