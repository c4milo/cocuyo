//! Reading a response's answer section: following the CNAME chain, collecting the records that
//! answer the question, and dropping the ones that do not.
//!
//! Two rules govern what is collected.
//!
//! A record counts only if its owner name is the name the chain has reached. A response may carry
//! records nobody asked about, and an attacker who can get a response accepted will put the
//! records it wants in it, so "accepting only in-domain records" is a named countermeasure
//! (RFC 5452 §6). Here that is the owner-name comparison, and nothing else lets a record in.
//!
//! A CNAME moves the chain rather than answering it (RFC 1034 §3.6.2). The chain is bounded by
//! `cname_hops_max` across messages as well as inside one, and each pass over the answer section
//! is bounded by the record walk, so the whole collection is bounded whatever the message says.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const Name = core.Name;
const Kind = core.Kind;
const Address = core.Address;
const header_codec = @import("header.zig");
const record_codec = @import("record.zig");

/// What a response turned out to be.
pub const Outcome = enum {
    /// Records of the type asked for, owned by the chain's end, were collected.
    answered,
    /// The chain ends in a CNAME with no record of the type asked for. The lookup asks again for
    /// `Collected.canonical`.
    chain_incomplete,
    /// The name exists and carries no record of this type: NODATA.
    no_data,
};

/// What was collected. The addresses and the names share storage, because one question asks for
/// one type and no response can fill both (docs/design.md §9).
pub const Collected = struct {
    /// The end of the CNAME chain: the name the collected records belong to.
    canonical: Name,
    answers: Answers,
    count: u8,
    /// The smallest TTL over every record used, which is what a cache above cocuyo would honour.
    ttl_seconds: u32,
    /// Whether the chain moved: a CNAME was followed.
    aliased: bool,
    /// Whether records were dropped for want of room, here or in the record walk.
    truncated: bool,

    pub const Answers = union {
        addresses: [core.constants.addresses_max]Address,
        names: [core.constants.ptr_names_max]Name,
    };

    /// An empty collection for a question. The union's active field is chosen by the type asked
    /// for and both are zeroed, so nothing here is ever read uninitialised.
    pub fn init(kind: Kind, question: *const Name) Collected {
        assert(kind.queryable());
        return .{
            .canonical = question.*,
            .answers = switch (kind) {
                .ptr => .{ .names = @splat(Name.root) },
                else => .{ .addresses = @splat(.{ .family = .ipv4, .octets = @splat(0) }) },
            },
            .count = 0,
            .ttl_seconds = 0,
            .aliased = false,
            .truncated = false,
        };
    }

    /// The addresses collected for an A or AAAA question.
    pub fn addresses(self: *const Collected) []const Address {
        assert(self.count <= core.constants.addresses_max);
        return self.answers.addresses[0..self.count];
    }

    /// The names collected for a PTR question.
    pub fn names(self: *const Collected) []const Name {
        assert(self.count <= core.constants.ptr_names_max);
        return self.answers.names[0..self.count];
    }
};

/// Collects what `message` answers about `question`, of type `kind`, into `out`.
///
/// `hops_before` is how many CNAMEs this lookup has already followed in earlier messages, so the
/// bound holds across a chain that spans several responses. The loop's own condition is the bound:
/// a pass that follows an alias raises the hop count, and the `ChainTooLong` after the loop is
/// what a chain that runs out of hops ends in.
pub fn collect(
    message: []const u8,
    question: *const Name,
    kind: Kind,
    hops_before: u8,
    out: *Collected,
) Error!Outcome {
    assert(kind.queryable());
    const header = try header_codec.parse(message);
    if (header.qdcount != 1) return Error.MalformedMessage;
    out.* = Collected.init(kind, question);
    const answer_offset = core.constants.header_bytes + question.len +
        core.constants.question_fixed_bytes;
    if (answer_offset > message.len) return Error.MalformedMessage;

    var hops: u8 = hops_before;
    while (hops <= core.constants.cname_hops_max) {
        const pass = try one_pass(message, header.ancount, kind, out, answer_offset);
        if (pass.collected) return .answered;
        // Nothing for this name. If the chain moved to get here, the lookup asks again for
        // where it moved to; if it never moved, the name simply has no record of this type.
        const target = pass.alias orelse
            return if (out.aliased) .chain_incomplete else .no_data;
        out.canonical = target;
        out.aliased = true;
        hops += 1;
    }
    assert(hops > core.constants.cname_hops_max);
    return Error.ChainTooLong;
}

/// What one pass over the answer section found for the chain's current name.
const Pass = struct {
    collected: bool = false,
    alias: ?Name = null,
};

/// The part a record can play for the question being asked.
const Role = enum { wanted, alias, other };

fn role_of(record: *const record_codec.Record, kind: Kind) Role {
    if (record.is_kind(kind)) return .wanted;
    if (record.is_kind(.cname)) return .alias;
    return .other;
}

fn one_pass(
    message: []const u8,
    ancount: u16,
    kind: Kind,
    out: *Collected,
    answer_offset: usize,
) Error!Pass {
    var pass: Pass = .{};
    var walk = record_codec.Iterator.init(message, answer_offset, ancount);
    while (try walk.next()) |record| {
        const role = role_of(&record, kind);
        if (role == .other) continue;
        // The owner name is decoded only now, for a record whose type could matter.
        var owner: Name = Name.empty;
        try record.owner_name(message, &owner);
        if (!owner.equal(&out.canonical)) continue;
        switch (role) {
            .wanted => pass.collected = try take(message, &record, kind, out) or pass.collected,
            // The first CNAME for this name wins; a second one for the same name is the
            // "no other data" rule of RFC 1034 §3.6.2 being broken, and is ignored.
            .alias => if (pass.alias == null) {
                var target: Name = Name.empty;
                try record.rdata_name(message, &target);
                pass.alias = target;
                note_ttl(record.ttl_seconds, out);
            },
            .other => unreachable,
        }
    }
    if (walk.truncated) out.truncated = true;
    return pass;
}

/// Stores one wanted record. Returns whether it was stored: a record that does not fit sets
/// `truncated` rather than failing, because the addresses already collected are still answers.
fn take(
    message: []const u8,
    record: *const record_codec.Record,
    kind: Kind,
    out: *Collected,
) Error!bool {
    const room: u8 = if (kind == .ptr)
        core.constants.ptr_names_max
    else
        core.constants.addresses_max;
    if (out.count == room) {
        out.truncated = true;
        return false;
    }
    assert(out.count < room);
    if (kind == .ptr) {
        try record.rdata_name(message, &out.answers.names[out.count]);
    } else {
        out.answers.addresses[out.count] = try record.address();
    }
    out.count += 1;
    note_ttl(record.ttl_seconds, out);
    return true;
}

/// The smallest TTL over the records used. Zero means nothing has been noted yet, and a record
/// with a TTL of zero is one nothing may cache, so it stays the smallest.
fn note_ttl(ttl_seconds: u32, out: *Collected) void {
    if (out.ttl_seconds == 0 or ttl_seconds < out.ttl_seconds) out.ttl_seconds = ttl_seconds;
    assert(out.ttl_seconds <= ttl_seconds or ttl_seconds == 0);
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

fn collect_from(message: []const u8, kind: Kind, out: *Collected) !Outcome {
    const question = try Name.from_text("example.com");
    return collect(message, &question, kind, 0, out);
}

test "an A record owned by the question is collected" {
    var collected: Collected = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_a, .a, &collected));
    try testing.expectEqual(@as(u8, 1), collected.count);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[0].slice());
    try testing.expectEqual(@as(u32, 300), collected.ttl_seconds);
    try testing.expect(!collected.aliased);
    try testing.expect(!collected.truncated);
}

test "two A records for one name are both collected" {
    var collected: Collected = undefined;
    const outcome = try collect_from(&fixtures.answer_a_twice, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expectEqual(@as(u8, 2), collected.count);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, collected.addresses()[1].slice());
}

test "a record of another type is not an answer" {
    var collected: Collected = undefined;
    const outcome = try collect_from(&fixtures.answer_aaaa, .a, &collected);
    try testing.expectEqual(Outcome.no_data, outcome);
    try testing.expectEqual(@as(u8, 0), collected.count);
}

test "a CNAME and its target's A record answer in one message" {
    var collected: Collected = undefined;
    const outcome = try collect_from(&fixtures.answer_cname_then_a, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expect(collected.aliased);
    try testing.expect(collected.canonical.equal(&try Name.from_text("host.example.net")));
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, collected.addresses()[0].slice());
    // The smallest TTL over the records used: the CNAME's 60, not the address's 300.
    try testing.expectEqual(@as(u32, 60), collected.ttl_seconds);
}

test "a CNAME with no target record asks the caller to query again" {
    var collected: Collected = undefined;
    const outcome = try collect_from(&fixtures.answer_cname_only, .a, &collected);
    try testing.expectEqual(Outcome.chain_incomplete, outcome);
    try testing.expectEqual(@as(u8, 0), collected.count);
    try testing.expect(collected.canonical.equal(&try Name.from_text("host.example.net")));
}

test "an A record for a name nobody asked about is dropped" {
    var collected: Collected = undefined;
    const outcome = try collect_from(&fixtures.answer_injected, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    // The injected record is first in the section and holds 192.0.2.9. Only the asked-about
    // record is collected (RFC 5452 §6).
    try testing.expectEqual(@as(u8, 1), collected.count);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[0].slice());
}

test "a response with no answers at all is NODATA" {
    var collected: Collected = undefined;
    try testing.expectEqual(Outcome.no_data, try collect_from(&fixtures.answer_no_data, .a, &collected));
}

test "a chain already at the hop bound is refused rather than followed" {
    var collected: Collected = undefined;
    const question = try Name.from_text("example.com");
    try testing.expectError(Error.ChainTooLong, collect(
        &fixtures.answer_cname_only,
        &question,
        .a,
        core.constants.cname_hops_max,
        &collected,
    ));
}

test "a malformed record in the section fails the whole collection" {
    var collected: Collected = undefined;
    try testing.expectError(
        Error.TruncatedMessage,
        collect_from(&fixtures.answer_long_rdlength, .a, &collected),
    );
    try testing.expectError(
        Error.MalformedMessage,
        collect_from(&fixtures.answer_lying_count, .a, &collected),
    );
}

test "a response whose question count is not one is malformed" {
    var chaos = fixtures.answer_a;
    chaos[5] = 2; // qdcount 2
    var collected: Collected = undefined;
    try testing.expectError(Error.MalformedMessage, collect_from(&chaos, .a, &collected));
}

test "more records than there is room for are truncated, not dropped silently" {
    var collected: Collected = undefined;
    const outcome = try collect_from(&fixtures.answer_a_seventeen, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expectEqual(@as(u8, core.constants.addresses_max), collected.count);
    try testing.expect(collected.truncated);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[15].slice());
}
