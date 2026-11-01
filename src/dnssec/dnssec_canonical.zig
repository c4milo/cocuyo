//! The canonical form of a record's rdata, the canonical order of an RRset, and the data an RRSIG
//! signs (RFC 4034 §6.2, §6.3, RFC 4035 §5.3.2, as RFC 6840 §5.1 corrects §6.2). Split from
//! `dnssec.zig` by the file-length rule. Nothing here verifies: the octets go to the caller's
//! `Hash` (docs/design.md §25, step 7).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Kind = core.Kind;
const Name = core.Name;
const Hash = @import("dnssec.zig").Hash;
const constants = @import("constants.zig");
const Segment = wire.rdata.layout.Segment;

/// Where the names sit in the rdata of a type whose names are lowercased: the types of RFC 4034
/// §6.2's list that cocuyo names, but NSEC, which RFC 6840 §5.1 takes out. Null for every other
/// type, whose canonical rdata is its rdata as it came: "no downcasing of embedded domain names
/// takes place" (RFC 3597 §7).
fn lowered(kind: Kind) ?[]const Segment {
    return switch (kind) {
        .ns, .cname, .soa, .ptr, .mx, .sig, .naptr, .srv => wire.rdata.layout.of(kind.code()),
        // Their names are never compressed, so the collector copies them as they came, and the
        // layout says nothing of them (RFC 4034 §3.1.7, RFC 6672 §2.5).
        .rrsig => &rrsig_layout,
        .dname => &dname_layout,
        else => null,
    };
}

const rrsig_layout = [_]Segment{ .{ .fixed = wire.constants.sig_fixed_bytes }, .name, .rest };
const dname_layout = [_]Segment{.name};

/// Writes the canonical form of `stored`, rdata of `kind` as the collector keeps it, its names
/// written in full, into `out`, and returns its length. A name it lowercases must hold as labels.
pub fn rdata(kind: Kind, stored: []const u8, out: []u8) Error!usize {
    assert(out.len >= stored.len);
    @memcpy(out[0..stored.len], stored);
    try lower(kind, out[0..stored.len]);
    return stored.len;
}

/// Whether the canonical form of `kind`'s rdata differs from the rdata as it came, its names in
/// full: whether `lower` changes anything.
pub fn lowers(kind: Kind) bool {
    return lowered(kind) != null;
}

/// Lowercases, in place, the names of `bytes`, rdata of `kind` with its names written in full.
pub fn lower(kind: Kind, bytes: []u8) Error!void {
    const layout = lowered(kind) orelse return;
    var at: usize = 0;
    for (layout) |segment| {
        switch (segment) {
            .fixed => |count| {
                if (bytes.len - at < count) return Error.MalformedMessage;
                at += count;
            },
            .name => at = try lower_name(bytes, at),
            .character_string => {
                if (at == bytes.len or bytes.len - at - 1 < bytes[at]) return Error.MalformedMessage;
                at += 1 + @as(usize, bytes[at]);
            },
            .rest => break,
        }
    }
    assert(at <= bytes.len);
}

/// Lowercases the letters of the name at `at` in `bytes`, and returns the offset after it.
fn lower_name(bytes: []u8, at: usize) Error!usize {
    var name: Name = Name.empty;
    const after = try wire.rdata.name.read(bytes, at, &name);
    for (bytes[at..after]) |*octet| octet.* = std.ascii.toLower(octet.*);
    return after;
}

/// The room the canonical rdata of one record is written in, when its names are written out in
/// full or lowered.
pub const Scratch = [constants.canonical_rdata_bytes]u8;

/// An RRset given as the canonical rdata of each record (`rdata`), for a caller that holds them.
pub const Written = struct {
    records: []const []const u8,

    pub fn count(self: Written) usize {
        return self.records.len;
    }

    pub fn canonical(self: Written, index: usize, scratch: *Scratch) Error![]const u8 {
        _ = scratch;
        return self.records[index];
    }
};

/// What an RRSIG signs, fed to `hash`: its rdata without the signature, its signer in lowercase,
/// then each record of the RRset in canonical form and order (RFC 4035 §5.3.2). `owner` is the
/// RRset's, `kind` its type and `class` its class. `records` gives the canonical rdata of each
/// record by index, as `Written` does, written into a `Scratch` when it has to be. A record that
/// repeats another is fed once: an RRset with duplicates is "a protocol error", and a validator
/// that takes it "MUST remove all but one" (RFC 4034 §6.3).
pub fn signed_data(
    rrsig_rdata: []const u8,
    owner: *const Name,
    kind: Kind,
    class: u16,
    records: anytype,
    hash: Hash,
) Error!void {
    const count = records.count();
    assert(count >= 1 and count <= core.limits.records_max);
    const sig = try wire.rdata.Rrsig.parse(rrsig_rdata);
    var head: [wire.constants.sig_fixed_bytes + core.limits.name_bytes_max]u8 = undefined;
    const head_bytes = rrsig_rdata.len - sig.signature.len;
    assert(head_bytes <= head.len);
    @memcpy(head[0..head_bytes], rrsig_rdata[0..head_bytes]);
    _ = try lower_name(head[0..head_bytes], wire.constants.sig_fixed_bytes);
    hash.feed(head[0..head_bytes]);
    const name = try signed_owner(owner, sig.labels);
    var fixed: [constants.record_fixed_bytes]u8 = undefined;
    std.mem.writeInt(u16, fixed[0..constants.record_class_offset], kind.code(), .big);
    std.mem.writeInt(u16, fixed[constants.record_class_offset..constants.record_ttl_offset], class, .big);
    std.mem.writeInt(u32, fixed[constants.record_ttl_offset..constants.record_length_offset], sig.original_ttl, .big);
    var last_buffer: Scratch = undefined;
    var best_buffer: Scratch = undefined;
    var candidate_buffer: Scratch = undefined;
    var order: Order = .{ .last = &last_buffer, .best = &best_buffer, .candidate = &candidate_buffer };
    var last: ?[]const u8 = null;
    // In canonical order, each record once: the smallest of those after the last one fed.
    for (0..count) |_| {
        const next = try order.smallest_after(records, last) orelse break;
        hash.feed(name.wire());
        std.mem.writeInt(u16, fixed[constants.record_length_offset..constants.record_fixed_bytes], @intCast(next.len), .big);
        hash.feed(&fixed);
        hash.feed(next);
        last = next;
        std.mem.swap(*Scratch, &order.last, &order.best);
    }
}

/// The three records a selection in canonical order holds at once, each in a `Scratch` of its own:
/// the last one fed, the best one yet, and the one being read.
const Order = struct {
    last: *Scratch,
    best: *Scratch,
    candidate: *Scratch,

    /// The record of `records` that sorts first after `after`, in canonical order: the rdata as a
    /// left-justified octet sequence, "in which the absence of an octet sorts before a zero octet"
    /// (RFC 4034 §6.3). Null when none sorts after it. The result is in `best`.
    fn smallest_after(self: *Order, records: anytype, after: ?[]const u8) Error!?[]const u8 {
        var best: ?[]const u8 = null;
        for (0..records.count()) |index| {
            const candidate = try records.canonical(index, self.candidate);
            if (after) |floor| if (std.mem.order(u8, candidate, floor) != .gt) continue;
            if (best) |held| if (std.mem.order(u8, candidate, held) != .lt) continue;
            best = candidate;
            std.mem.swap(*Scratch, &self.best, &self.candidate);
        }
        return best;
    }
};

/// The owner a signature covers, in lowercase: the owner itself when the RRSIG's Labels field
/// counts its labels, and "*." and the rightmost of them when it counts fewer, which is how a
/// wildcard expansion is signed (RFC 4035 §5.3.2). More labels than the owner has is invalid
/// (RFC 4035 §5.3.1).
fn signed_owner(owner: *const Name, labels: u8) Error!Name {
    const count = owner.label_count();
    if (labels > count) return Error.MalformedMessage;
    var lowered_owner = owner.*;
    lowered_owner.fold_case();
    if (labels == count) return lowered_owner;
    var at: usize = 0;
    // Bounded: the owner holds `count` labels, and `count - labels` of them are skipped.
    for (0..count - labels) |_| at += 1 + @as(usize, lowered_owner.bytes[at]);
    var name: Name = Name.empty;
    try name.append_label(constants.wildcard_label);
    const rest = lowered_owner.bytes[at..lowered_owner.len];
    @memcpy(name.bytes[name.len..][0..rest.len], rest);
    name.len += @intCast(rest.len);
    assert(name.label_count() == labels + 1);
    return name;
}

// Tests.

const testing = std.testing;

const fixtures = @import("fixtures.zig");
const Recorded = fixtures.Recorded;
const rrsig_a = fixtures.rrsig_a;

test "the signed data is the RRSIG's head with its signer lowered, then each record in canonical order" {
    // RFC 4035 §5.3.2: RRSIG_RDATA | RR(1) | RR(2), the RRs sorted (RFC 4034 §6.3).
    // An owner of two labels, as the RRSIG's Labels field counts, in the case it came in.
    const owner = try Name.from_text("EXAMPLE.com");
    const high = [_]u8{ 192, 0, 2, 2 };
    const low = [_]u8{ 192, 0, 2, 1 };
    var recorded: Recorded = .{};
    try signed_data(&rrsig_a, &owner, .a, core.constants.class_internet, Written{ .records = &.{ &high, &low, &high } }, recorded.hash());
    const head = rrsig_a[0..wire.constants.sig_fixed_bytes] ++ "\x07example\x03com\x00".*;
    const rr_fixed = [_]u8{ 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04 };
    const owner_wire = "\x07example\x03com\x00".*;
    const expected = head ++ owner_wire ++ rr_fixed ++ low ++ owner_wire ++ rr_fixed ++ high;
    // The duplicate of `high` is fed once.
    try testing.expectEqualSlices(u8, expected, recorded.slice());
}

test "a wildcard expansion is signed under its wildcard, and too many labels is malformed" {
    // RFC 4035 §5.3.2: Labels 2 under a three-label owner signs `*.example.com`.
    const expanded = try Name.from_text("a.b.example.com");
    var recorded: Recorded = .{};
    try signed_data(&rrsig_a, &expanded, .a, core.constants.class_internet, Written{ .records = &.{&[_]u8{ 192, 0, 2, 1 }} }, recorded.hash());
    const owner_at = wire.constants.sig_fixed_bytes + "\x07example\x03com\x00".len;
    try testing.expectEqualSlices(u8, "\x01*\x07example\x03com\x00", recorded.slice()[owner_at..][0.."\x01*\x07example\x03com\x00".len]);
    const short = try Name.from_text("com");
    try testing.expectError(Error.MalformedMessage, signed_data(&rrsig_a, &short, .a, core.constants.class_internet, Written{ .records = &.{&[_]u8{ 192, 0, 2, 1 }} }, recorded.hash()));
}

test "an MX's exchange and an RRSIG's signer are lowered, and an NSEC's next name keeps its case" {
    // RFC 4034 §6.2 item 3, as RFC 6840 §5.1 corrects it, and RFC 3597 §7 for SVCB.
    var out: [64]u8 = undefined;
    const mx = [_]u8{ 0x00, 0x0a } ++ "\x04Mail\x07Example\x00".*;
    const mx_len = try rdata(.mx, &mx, &out);
    try testing.expectEqualSlices(u8, &([_]u8{ 0x00, 0x0a } ++ "\x04mail\x07example\x00".*), out[0..mx_len]);
    const nsec = "\x04Host\x07Example\x00".* ++ [_]u8{ 0x00, 0x01, 0x40 };
    const nsec_len = try rdata(.nsec, &nsec, &out);
    try testing.expectEqualSlices(u8, &nsec, out[0..nsec_len]);
    const svcb = [_]u8{ 0x00, 0x01 } ++ "\x03Svc\x00".*;
    const svcb_len = try rdata(.svcb, &svcb, &out);
    try testing.expectEqualSlices(u8, &svcb, out[0..svcb_len]);
    const rrsig_len = try rdata(.rrsig, &rrsig_a, &out);
    try testing.expectEqualSlices(u8, "\x07example\x03com\x00", out[wire.constants.sig_fixed_bytes..][0.."\x07example\x03com\x00".len]);
    try testing.expectEqual(rrsig_a.len, rrsig_len);
}

test "a name to lower that is a pointer, or that runs past the rdata, is malformed" {
    var out: [16]u8 = undefined;
    try testing.expectError(Error.MalformedName, rdata(.cname, &.{ 0xc0, 0x0c }, &out));
    try testing.expectError(Error.MalformedMessage, rdata(.cname, "\x04mai".*[0..], &out));
    try testing.expectError(Error.MalformedMessage, rdata(.mx, &.{0x00}, &out));
}
