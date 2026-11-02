//! The twin's signed server (docs/design.md §25 step 14). It answers from the tree of
//! `signed/fixtures.zig` as a recursive server does that passes the records on, and signs each
//! RRset for the tests' verifier of `dnssec.fixtures`. A script names one zone, and a fault and a
//! phase of a key replacement for that zone alone.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const dnssec = @import("dnssec");
const Kind = core.Kind;
const Name = core.Name;
const Builder = dnssec.fixtures.Builder;
const Signing = dnssec.fixtures.Signing;
const tree = @import("signed/fixtures.zig");
pub const Zone = tree.Zone;

/// What the script's zone does wrong.
pub const Fault = enum {
    none,
    /// The last octet of the first record of each RRset but the DNSKEY set changes after the
    /// signature is made. A lie in the DNSKEY set would fail at the DS digest, before a signature
    /// is read.
    lies,
    /// Each signature expired an hour before `now_seconds`.
    expired,
    /// The RRSIG records are taken out.
    stripped,
    /// The RRSIG records of the answer are taken out, but those of a DNSKEY or a DS set. So a walk
    /// proves the name exists in a signed zone, and its data is bogus (§25 walk rule 8).
    stripped_answer,
};

/// Where the script's zone is in the replacement of its key, key 0 by key 1.
pub const Phase = enum {
    /// The DNSKEY set holds key 0, and key 0 signs.
    first,
    /// The set holds both keys, and key 0 signs: key 1 is published before it signs.
    both,
    /// The set holds both keys, and key 1 signs.
    both_second,
    /// The set holds key 1, and key 1 signs.
    second,

    fn published(self: Phase) []const u1 {
        return switch (self) {
            .first => &.{0},
            .both, .both_second => &.{ 0, 1 },
            .second => &.{1},
        };
    }

    fn signing(self: Phase) u1 {
        return switch (self) {
            .first, .both => 0,
            .both_second, .second => 1,
        };
    }
};

pub const Behaviour = struct {
    /// Answers from the signed tree, and not with the address the name derives.
    on: bool = false,
    /// The zone that `fault` and `phase` apply to. Every other zone signs with key 0 and lies
    /// about nothing.
    zone: Zone = .signed,
    fault: Fault = .none,
    phase: Phase = .first,
};

/// The instant the signatures are made for, at which a test pins the key store's time of day.
pub const now_seconds = tree.now_seconds;
pub const ttl_seconds = tree.ttl_seconds;
pub const zones = tree.zones;
pub const key = tree.key;
pub const address_signed_v4 = tree.address_signed_v4;
pub const address_signed_v6 = tree.address_signed_v6;
pub const address_plain_v4 = tree.address_plain_v4;

/// The DS a key store takes as the root's trust anchor (RFC 4035 §4.4): the root's key 0.
pub fn root_anchor() dnssec.fixtures.DsRdata {
    return dnssec.fixtures.ds_of(&Name.root, key(.root, 0), tree.algorithm, tree.digest_type);
}

/// Writes the reply to `name` of `kind_code`, with the query's `id`, into `out`: the header, the
/// question as asked, the answer and the authority section, or null for a type the twin does not
/// know, which gets no answer. The caller writes the OPT record and its count. `dnssec_ok` is the
/// query's DO bit.
pub fn respond(behaviour: *const Behaviour, id: u16, name: *const Name, kind_code: u16, dnssec_ok: bool, out: []u8) ?usize {
    assert(behaviour.on);
    const kind = Kind.from_code(kind_code) orelse return null;
    const zone = authoritative(name, kind);
    var reply: Reply = .{
        .behaviour = behaviour,
        .zone = zone,
        .dnssec_ok = dnssec_ok,
        .builder = Builder.init_name(name, kind, 0),
    };
    reply.answer(name, kind);
    return written(&reply.builder, id, out);
}

/// NXDOMAIN (RFC 1035 §4.1.1).
const rcode_name_error: u4 = 3;
/// Where the rcode sits in the header's second flags octet.
const flags_rcode_at: usize = 3;

/// Copies the builder's message into `out`, with the query's id and a recursive server's flags:
/// QR, RD and RA, AA clear, and the builder's rcode.
fn written(builder: *const Builder, id: u16, out: []u8) usize {
    var copy = builder.*;
    const message = copy.message();
    assert(message.len <= out.len);
    @memcpy(out[0..message.len], message);
    const rcode: u16 = message[flags_rcode_at] & wire.constants.rcode_mask;
    const flags = wire.constants.flag_response | wire.constants.flag_recursion_desired |
        wire.constants.flag_recursion_available | rcode;
    wire.integer.write_u16(out, 0, id);
    wire.integer.write_u16(out, wire.constants.u16_bytes, flags);
    return message.len;
}

/// The zone that answers for `name`: the deepest one it lies in, but its parent for the DS set
/// at a zone's apex, which lives on the parent's side of the cut (RFC 4034 §5).
fn authoritative(name: *const Name, kind: Kind) Zone {
    var best: Zone = .root;
    var best_labels: u8 = 0;
    for (zones, 0..) |info, index| {
        const apex = named(info.apex);
        if (!under(name, &apex)) continue;
        if (kind == .ds and name.equal(&apex) and info.parent != null) continue;
        if (apex.label_count() < best_labels) continue;
        best = @enumFromInt(index);
        best_labels = apex.label_count();
    }
    return best;
}

fn under(name: *const Name, zone: *const Name) bool {
    return core.canonical.shared_labels(name, zone) == zone.label_count();
}

fn named(text: []const u8) Name {
    return Name.from_text(text) catch unreachable;
}

/// One reply under construction.
const Reply = struct {
    behaviour: *const Behaviour,
    zone: Zone,
    dnssec_ok: bool,
    builder: Builder,

    fn info(self: *const Reply) *const tree.Info {
        return &zones[@intFromEnum(self.zone)];
    }

    fn answer(self: *Reply, name: *const Name, kind: Kind) void {
        const node = self.find(name) orelse return self.name_error(name);
        if (kind == .dnskey and node.apex and self.info().signed) return self.key_set(name, self.zone);
        if (kind == .ds and node.delegates != null) return self.ds_set(name, node.delegates.?);
        if (node.set(kind)) |set| return self.put(name, set.kind, set.records);
        self.no_data(node);
    }

    fn find(self: *const Reply, name: *const Name) ?*const tree.Node {
        for (self.info().nodes) |*node| if (named(node.owner).equal(name)) return node;
        return null;
    }

    fn key_set(self: *Reply, owner: *const Name, zone: Zone) void {
        var records: [tree.published_max][]const u8 = undefined;
        const published = self.phase_of(zone).published();
        for (published, 0..) |generation, index| records[index] = key(zone, generation);
        self.put(owner, .dnskey, records[0..published.len]);
    }

    /// The DS set at a signed delegation: one DS for each key the child publishes.
    fn ds_set(self: *Reply, owner: *const Name, child: Zone) void {
        var digests: [tree.published_max]dnssec.fixtures.DsRdata = undefined;
        var records: [tree.published_max][]const u8 = undefined;
        const published = self.phase_of(child).published();
        const apex = named(zones[@intFromEnum(child)].apex);
        for (published, 0..) |generation, index| {
            digests[index] = dnssec.fixtures.ds_of(&apex, key(child, generation), tree.algorithm, tree.digest_type);
            records[index] = &digests[index];
        }
        self.put(owner, .ds, records[0..published.len]);
    }

    /// NODATA: the zone's SOA and the NSEC at the name, which says the type is not there (RFC
    /// 4035 §3.1.3.1).
    fn no_data(self: *Reply, node: *const tree.Node) void {
        self.builder.authority();
        self.soa();
        self.nsec(node);
    }

    /// NXDOMAIN: the zone's SOA, the NSEC that covers the name and the one that covers the
    /// wildcard at its closest encloser (RFC 4035 §3.1.3.2).
    fn name_error(self: *Reply, name: *const Name) void {
        self.builder.bytes[flags_rcode_at] = rcode_name_error;
        self.builder.authority();
        self.soa();
        const name_covering = self.covering(name);
        self.nsec(name_covering);
        var wildcard_text: [core.limits.name_text_bytes_max]u8 = undefined;
        const closest = self.encloser(name);
        const text = std.fmt.bufPrint(&wildcard_text, "*.{s}", .{closest.owner}) catch unreachable;
        // The root's wildcard is `*` alone.
        const wildcard = if (named(closest.owner).label_count() == 0) named("*") else named(text);
        const wildcard_covering = self.covering(&wildcard);
        if (wildcard_covering != name_covering) self.nsec(wildcard_covering);
    }

    /// The last name before `name` in canonical order, whose NSEC covers it.
    fn covering(self: *const Reply, name: *const Name) *const tree.Node {
        const nodes = self.info().nodes;
        var last = &nodes[0];
        for (nodes) |*node| {
            if (named(node.owner).canonical_order(name) == .lt) last = node;
        }
        return last;
    }

    /// The deepest name the zone holds above `name`.
    fn encloser(self: *const Reply, name: *const Name) *const tree.Node {
        const nodes = self.info().nodes;
        var deepest = &nodes[0];
        for (nodes) |*node| {
            const owner = named(node.owner);
            if (under(name, &owner) and owner.label_count() > named(deepest.owner).label_count()) deepest = node;
        }
        return deepest;
    }

    fn soa(self: *Reply) void {
        const apex = &self.info().nodes[0];
        assert(apex.apex);
        const set = apex.set(.soa).?;
        self.put(&named(apex.owner), .soa, set.records);
    }

    fn nsec(self: *Reply, node: *const tree.Node) void {
        if (!self.dnssec_ok or !self.info().signed) return;
        self.put(&named(node.owner), .nsec, &.{node.nsec});
    }

    /// The RRset `records` of `kind` at `owner`, then its RRSIG when the query asked for one and
    /// the zone signs.
    fn put(self: *Reply, owner: *const Name, kind: Kind, records: []const []const u8) void {
        assert(records.len >= 1);
        const faulty = self.zone == self.behaviour.zone;
        var forged: [tree.rdata_bytes_max]u8 = undefined;
        for (records, 0..) |rdata, index| {
            assert(rdata.len >= 1 and rdata.len <= forged.len);
            if (index == 0 and faulty and self.behaviour.fault == .lies and kind != .dnskey) {
                @memcpy(forged[0..rdata.len], rdata);
                forged[rdata.len - 1] ^= 1;
                self.builder.record_wire(owner.wire(), kind, ttl_seconds, forged[0..rdata.len]);
            } else {
                self.builder.record_wire(owner.wire(), kind, ttl_seconds, rdata);
            }
        }
        if (!self.dnssec_ok or !self.info().signed) return;
        if (faulty and self.behaviour.fault == .stripped) return;
        const answered = self.builder.section == 0 and kind != .dnskey and kind != .ds;
        if (faulty and self.behaviour.fault == .stripped_answer and answered) return;
        self.builder.rrsig_name(owner, kind, records, self.signing());
    }

    fn phase_of(self: *const Reply, zone: Zone) Phase {
        return if (zone == self.behaviour.zone) self.behaviour.phase else .first;
    }

    /// The RRSIG fields of this zone's signature: its signing key, and its dates.
    fn signing(self: *const Reply) Signing {
        const signing_key = key(self.zone, self.phase_of(self.zone).signing());
        const expired = self.zone == self.behaviour.zone and self.behaviour.fault == .expired;
        return .{
            .ttl = ttl_seconds,
            .algorithm = tree.algorithm,
            .original_ttl = ttl_seconds,
            .expiration = if (expired) tree.expired_seconds else tree.expiration_seconds,
            .inception = tree.inception_seconds,
            .key_tag = dnssec.key_tag(signing_key),
            .signer = self.info().apex,
            .public_key = signing_key[tree.public_key_at..],
        };
    }
};
