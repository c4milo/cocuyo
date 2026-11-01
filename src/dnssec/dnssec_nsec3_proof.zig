//! The parts of an NSEC3 proof: which records count, the hashes, a match, a cover and the closest
//! encloser proof (RFC 5155 §8.1 to §8.3). Split from `dnssec_nsec3.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const canonical = core.canonical;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const base32 = @import("dnssec_base32.zig");

/// One SHA-1 hash of a name (RFC 5155 §5).
pub const Hash = [constants.nsec3_hash_bytes]u8;

/// An NSEC3 record the validator verified, with the signer of the RRSIG over it.
pub const Record = struct {
    owner: Name,
    signer: Name,
    nsec3: wire.rdata.Nsec3,

    pub fn opt_out(self: *const Record) bool {
        return self.nsec3.opt_out();
    }
};

/// Where the hashes come from: a SHA-1 over chapulin, or a test's table.
pub const Hasher = struct {
    context: *anyopaque,
    /// Writes IH(salt, name, iterations) into `out`, with SHA-1 (RFC 5155 §5). `name` is in
    /// canonical form: whole, and in lowercase.
    compute: *const fn (context: *anyopaque, name: []const u8, salt: []const u8, iterations: u16, out: *Hash) void,
};

/// The closest encloser of a name, by its labels, and the record that covers the next closer name.
pub const Encloser = struct { labels: u8, next_closer: *const Record };

/// One proof over the records of one zone, with the parameters they share, and a count of the
/// hashes it computed.
pub const Proof = struct {
    records: []const Record,
    hasher: Hasher,
    zone: *const Name,
    salt: []const u8,
    iterations: u16,
    hashes: usize,

    /// A proof over the records that may speak of `name`. Null when none may, or when two of them
    /// differ in salt or iterations: a validator "MAY treat a response as bogus" then (RFC 5155
    /// §8.2).
    pub fn of(name: *const Name, records: []const Record, hasher: Hasher) ?Proof {
        assert(records.len <= core.limits.records_max);
        const first = for (records) |*record| {
            if (usable(record, name)) break record;
        } else return null;
        for (records) |*record| {
            if (!usable(record, name) or !record.signer.equal(&first.signer)) continue;
            if (record.nsec3.iterations != first.nsec3.iterations) return null;
            if (!std.mem.eql(u8, record.nsec3.salt, first.nsec3.salt)) return null;
        }
        return .{
            .records = records,
            .hasher = hasher,
            .zone = &first.signer,
            .salt = first.nsec3.salt,
            .iterations = first.nsec3.iterations,
            .hashes = 0,
        };
    }

    /// Whether the iterations pass what a validator computes before it reads the proof as
    /// insecure (RFC 9276 §3.2). Each record's signature has verified by now, as §3.2 asks.
    pub fn costly(self: *const Proof) bool {
        return self.iterations > limits.nsec3_iterations_max;
    }

    /// The hash of `name`, in canonical form (RFC 5155 §5). Null past the work one proof may do
    /// (RFC 4035 §5.4: "the resolver MUST bound the work").
    pub fn hash(self: *Proof, name: *const Name) ?Hash {
        if (self.hashes == limits.nsec3_hashes_per_message_max) return null;
        assert(self.hashes < limits.nsec3_hashes_per_message_max);
        self.hashes += 1;
        var lowered = name.*;
        lowered.fold_case();
        var out: Hash = undefined;
        self.hasher.compute(self.hasher.context, lowered.wire(), self.salt, self.iterations, &out);
        return out;
    }

    /// The record whose owner is the hash: "the owner name of the NSEC3 RR is the same as the
    /// hashed owner name of that name" (RFC 5155 §1.3).
    pub fn matching(self: *const Proof, hashed: *const Hash) ?*const Record {
        for (self.records) |*record| {
            if (!self.counts(record)) continue;
            const owner = owner_hash(record) orelse continue;
            if (std.mem.eql(u8, &owner, hashed)) return record;
        }
        return null;
    }

    /// The record whose span holds the hash, strictly, in hash order (RFC 5155 §1.3). The last
    /// record names the first next, so its span wraps past the end (§3.1.7).
    pub fn covering(self: *const Proof, hashed: *const Hash) ?*const Record {
        for (self.records) |*record| {
            if (!self.counts(record)) continue;
            const owner = owner_hash(record) orelse continue;
            const next = record.nsec3.next_hashed;
            const after_owner = std.mem.order(u8, &owner, hashed) == .lt;
            const before_next = std.mem.order(u8, hashed, next) == .lt;
            const wraps = std.mem.order(u8, &owner, next) != .lt;
            if (if (wraps) after_owner or before_next else after_owner and before_next) return record;
        }
        return null;
    }

    /// The closest encloser proof of `name`, whose hash is `hashed` (RFC 5155 §8.3): the longest
    /// ancestor a record matches, whose child toward `name` a record covers.
    pub fn closest_encloser(self: *Proof, name: *const Name, hashed: *const Hash) ?Encloser {
        const floor = self.zone.label_count();
        var labels = name.label_count();
        assert(labels >= floor);
        var current = hashed.*;
        var covered: ?*const Record = null;
        // Bounded: one pass for each label from `name` up to the zone's apex.
        for (0..labels - floor + 1) |_| {
            if (self.matching(&current)) |record| {
                // "If there is a matching NSEC3 RR in the response, but the flag is not set, then
                // the response is bogus" (RFC 5155 §8.3).
                const next_closer = covered orelse return null;
                // "The DNAME type bit must not be set and the NS type bit may only be set if the
                // SOA type bit is set" (§8.3).
                const types = record.nsec3.types;
                if (types.has(.dname) or (types.has(.ns) and !types.has(.soa))) return null;
                return .{ .labels = labels, .next_closer = next_closer };
            }
            covered = self.covering(&current);
            if (labels == floor) break;
            labels -= 1;
            current = self.hash(&canonical.ancestor(name, labels)) orelse return null;
        }
        return null;
    }

    fn counts(self: *const Proof, record: *const Record) bool {
        return record.signer.equal(self.zone) and usable(record, self.zone);
    }
};

/// Whether `record` may speak of `name`. A record of an unknown hash, or with flags other than 0
/// and 1, is ignored (RFC 5155 §8.1, §8.2). Its owner must be a hash "prepended as a single label
/// to the zone name" of its signer (§8.3), and `name` must be in that zone.
fn usable(record: *const Record, name: *const Name) bool {
    const nsec3 = record.nsec3;
    if (nsec3.hash_algorithm != constants.nsec3_hash_sha1) return false;
    if (nsec3.flags & ~wire.constants.nsec3_flag_opt_out != 0) return false;
    if (nsec3.next_hashed.len != constants.nsec3_hash_bytes) return false;
    if (owner_hash(record) == null) return false;
    const owner_labels = record.owner.label_count();
    const signer_labels = record.signer.label_count();
    if (owner_labels != signer_labels + 1) return false;
    if (canonical.shared_labels(&record.owner, &record.signer) != signer_labels) return false;
    return canonical.shared_labels(name, &record.signer) == signer_labels;
}

/// The hash the owner's first label holds in base32hex (RFC 5155 §3.3). Null when the label is no
/// hash of `constants.nsec3_hash_bytes` octets.
fn owner_hash(record: *const Record) ?Hash {
    const length = record.owner.bytes[0];
    if (length == 0) return null;
    const label = record.owner.bytes[1..][0..length];
    var out: Hash = undefined;
    const written = base32.decode(label, &out) orelse return null;
    if (written != out.len) return null;
    return out;
}

// Tests.

const testing = std.testing;
const appendix_a = @import("fixtures.zig");
const record3 = appendix_a.record3;

test "a record of another hash, with unknown flags, or not one label below its signer is ignored" {
    var table: appendix_a.Hashes = .{};
    const name = try Name.from_text("ns1.example");
    const good = try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.address3, 1);
    try testing.expect(Proof.of(&name, &.{good}, table.hasher()) != null);
    var other_hash = good;
    other_hash.nsec3.hash_algorithm = 2;
    var other_flags = good;
    other_flags.nsec3.flags = 2;
    var deeper = good;
    deeper.signer = try Name.from_text("w.example");
    var short_next = good;
    short_next.nsec3.next_hashed = good.nsec3.next_hashed[1..];
    var not_hash = good;
    not_hash.owner = try Name.from_text("ns1.example");
    var two_below = good;
    two_below.owner = try Name.from_text("2t7b4g4vsa5smi47k61mv5bv1a22bojr.w.example");
    var other_zone = good;
    other_zone.owner = try Name.from_text("2t7b4g4vsa5smi47k61mv5bv1a22bojr.other");
    for ([_]Record{ other_hash, other_flags, deeper, two_below, short_next, not_hash, other_zone }) |bad| {
        try testing.expectEqual(@as(?Proof, null), Proof.of(&name, &.{bad}, table.hasher()));
    }
    // A name outside the signer's zone.
    try testing.expectEqual(@as(?Proof, null), Proof.of(&try Name.from_text("ns1.other"), &.{good}, table.hasher()));
}

test "records that differ in salt or iterations make no proof, and past the limit one is costly" {
    var table: appendix_a.Hashes = .{};
    const name = try Name.from_text("ns1.example");
    const good = try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.address3, 1);
    var salted = good;
    salted.nsec3.salt = good.nsec3.salt[1..];
    try testing.expectEqual(@as(?Proof, null), Proof.of(&name, &.{ good, salted }, table.hasher()));
    var iterated = good;
    iterated.nsec3.iterations = 13;
    try testing.expectEqual(@as(?Proof, null), Proof.of(&name, &.{ good, iterated }, table.hasher()));
    iterated.nsec3.iterations = limits.nsec3_iterations_max;
    try testing.expect(!(Proof.of(&name, &.{iterated}, table.hasher()).?).costly());
    iterated.nsec3.iterations = limits.nsec3_iterations_max + 1;
    try testing.expect((Proof.of(&name, &.{iterated}, table.hasher()).?).costly());
}

test "a proof hashes no more names than its limit, and hashes each in lowercase" {
    var table: appendix_a.Hashes = .{};
    const good = try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.address3, 1);
    const name = try Name.from_text("NS1.Example");
    var proof = Proof.of(&name, &.{good}, table.hasher()).?;
    const hashed = proof.hash(&name).?;
    try testing.expect(proof.matching(&hashed) != null);
    for (1..limits.nsec3_hashes_per_message_max) |_| _ = proof.hash(&name).?;
    try testing.expectEqual(@as(?Hash, null), proof.hash(&name));
}

test "a span covers what lies strictly inside it, and the last one wraps past the end" {
    var table: appendix_a.Hashes = .{};
    const name = try Name.from_text("example");
    const last = try record3("t644ebqk9bibcna874givr6joj62mlhv", "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", &appendix_a.mail3, 0);
    const proof = Proof.of(&name, &.{last}, table.hasher()).?;
    const low: Hash = @splat(0);
    const high: Hash = @splat(0xff);
    try testing.expect(proof.covering(&low) != null and proof.covering(&high) != null);
    const owner = owner_hash(&last).?;
    try testing.expect(proof.covering(&owner) == null);
    const inner = try record3("2t7b4g4vsa5smi47k61mv5bv1a22bojr", "2vptu5timamqttgl4luu9kg21e0aor3s", &appendix_a.address3, 0);
    const inside = Proof.of(&name, &.{inner}, table.hasher()).?;
    try testing.expect(inside.covering(&low) == null and inside.covering(&high) == null);
    try testing.expect(inside.covering(&owner_hash(&inner).?) == null);
}

test "a closest encloser whose record marks a cut or a DNAME proves nothing" {
    // RFC 5155 B.1's encloser x.w.example, with NS and no SOA, then with DNAME.
    var table: appendix_a.Hashes = .{};
    const name = try Name.from_text("c.x.w.example");
    var records = [_]Record{
        try record3("b4um86eghhds6nea196smvmlo4ors995", "gjeqe526plbf1g8mklp59enfd789njgi", &appendix_a.mail3, 0),
        try record3("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom", "2t7b4g4vsa5smi47k61mv5bv1a22bojr", &appendix_a.apex3, 0),
    };
    var proof = Proof.of(&name, &records, table.hasher()).?;
    const hashed = proof.hash(&name).?;
    try testing.expectEqual(@as(u8, 3), proof.closest_encloser(&name, &hashed).?.labels);
    for ([_][]const u8{ &appendix_a.ns3, &appendix_a.redirect3 }) |types| {
        records[0].nsec3.types = try wire.rdata.TypeBitmaps.parse(types);
        var marked = Proof.of(&name, &records, table.hasher()).?;
        try testing.expectEqual(@as(?Encloser, null), marked.closest_encloser(&name, &hashed));
    }
}
