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
const response_take = @import("response_take.zig");
const response_answers = @import("response_answers.zig");

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

/// What was collected, and the records kept of the types that are neither addresses nor PTR
/// names: `response_answers.zig`.
pub const Answers = response_answers.Answers;
pub const Records = response_answers.Records;
pub const Kept = response_answers.Kept;

/// Collects what `message` answers about `question`, of type `kind`, into `out`.
///
/// `hops_before` is how many CNAMEs this lookup has already followed in earlier messages, so the
/// bound holds across a chain that spans several responses. The loop's own condition is the bound:
/// a pass that follows an alias raises the hop count, and the `ChainTooLong` after the loop is
/// what a chain that runs out of hops ends in.
pub fn collect(
    message: []const u8,
    chain: *Name,
    kind: Kind,
    hops_before: u8,
    out: *Answers,
) Error!Outcome {
    assert(kind.queryable());
    assert(chain.len >= 1);
    const start = try sections(message, chain);
    out.reset(kind);
    out.hops_used = hops_before;

    var hops: u8 = hops_before;
    while (hops <= core.constants.cname_hops_max) {
        const pass = try one_pass(message, start.header.ancount, kind, out, start.answer_offset, chain);
        if (pass.collected) return .answered;
        // Nothing for this name. If the chain moved to get here, the lookup asks again for
        // where it moved to; if it never moved, the name simply has no record of this type.
        const target = pass.alias orelse
            return if (out.aliased) .chain_incomplete else .no_data;
        chain.* = target;
        out.aliased = true;
        hops += 1;
        out.hops_used = hops;
    }
    assert(hops > core.constants.cname_hops_max);
    return Error.ChainTooLong;
}

/// The TTL a negative answer is cached for: the MINIMUM of the first SOA in the authority section,
/// capped by that record's TTL (RFC 2308 §5), or zero when the message carries no SOA, which is a
/// message that cannot be cached negatively (RFC 2308 §5, last paragraph). The CNAMEs a chain took
/// in the answer section on its way to the negative bound it as well: the negative is cached under
/// the name asked, which reaches it through them (RFC 1035 §3.2.1).
///
/// The authority section starts where the answer section ends, so the answer records are stepped
/// over on the way, their TTLs read and nothing else. `question` is the name the message echoes,
/// which fixes where the sections start (§7 check 5).
pub fn negative_ttl_seconds(message: []const u8, question: *const Name) Error!u32 {
    assert(question.len >= 1);
    const start = try sections(message, question);
    var answers = record_codec.Iterator.init(message, start.answer_offset, start.header.ancount);
    var authority_offset: usize = start.answer_offset;
    var chain_ttl_seconds: u32 = std.math.maxInt(u32);
    while (try answers.next()) |record| {
        authority_offset = record.end;
        chain_ttl_seconds = @min(chain_ttl_seconds, record.ttl_seconds);
    }
    var authority = record_codec.Iterator.init(message, authority_offset, start.header.nscount);
    while (try authority.next()) |record| {
        if (record.is_kind(.soa)) return @min(try record.soa_negative_ttl(message), chain_ttl_seconds);
    }
    return 0;
}

/// Where the answer section starts: after the header and the one question the message echoes.
/// The sum is taken in a usize: a maximal name overflows the octet its length is held in.
pub fn section_start(question: *const Name) usize {
    const name_len: usize = question.len;
    assert(name_len <= core.constants.name_bytes_max);
    return core.constants.header_bytes + name_len + core.constants.question_fixed_bytes;
}

/// A message's header, and where its answer section starts.
const Sections = struct { header: header_codec.Header, answer_offset: usize };

/// The start every walk past the question shares. A message that echoes other than one question,
/// or that ends inside the one it echoes, is malformed.
fn sections(message: []const u8, question: *const Name) Error!Sections {
    assert(question.len >= 1);
    const header = try header_codec.parse(message);
    if (header.qdcount != 1) return Error.MalformedMessage;
    // The question's own name fixes where the answer section starts, and the response was already
    // checked to carry that question byte for byte (docs/design.md §7 check 5).
    const answer_offset = section_start(question);
    if (answer_offset > message.len) return Error.MalformedMessage;
    assert(answer_offset > core.constants.header_bytes);
    return .{ .header = header, .answer_offset = answer_offset };
}

/// What one pass over the answer section found for the chain's current name.
const Pass = struct {
    collected: bool = false,
    alias: ?Name = null,
};

/// The part a record can play for the question being asked.
const Role = enum { wanted, alias, other };

fn role_of(record: *const record_codec.Record, kind: Kind) Role {
    // An ANY question wants every record the name owns, a CNAME among them, and follows nothing
    // (RFC 1034 §3.6.2, RFC 8482 §4.1).
    if (kind == .any) return if (record.class == core.constants.class_internet) .wanted else .other;
    if (record.is_kind(kind)) return .wanted;
    // A CNAME moves every other question along the chain (RFC 1034 §3.6.2); a CNAME question
    // took it as wanted above.
    if (record.is_kind(.cname)) return .alias;
    return .other;
}

fn one_pass(
    message: []const u8,
    ancount: u16,
    kind: Kind,
    out: *Answers,
    answer_offset: usize,
    chain: *const Name,
) Error!Pass {
    var pass: Pass = .{};
    var walk = record_codec.Iterator.init(message, answer_offset, ancount);
    while (try walk.next()) |record| {
        const role = role_of(&record, kind);
        if (role == .other) continue;
        // The owner name is decoded only now, for a record whose type could matter.
        var owner: Name = Name.empty;
        try record.owner_name(message, &owner);
        if (!owner.equal(chain)) continue;
        switch (role) {
            .wanted => pass.collected = try response_take.take(message, &record, kind, out) or pass.collected,
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

/// The smallest TTL over the records used. A record with a TTL of zero is one nothing may cache
/// (RFC 1035 §3.2.1), so it stays the smallest whatever comes after it.
pub fn note_ttl(ttl_seconds: u32, out: *Answers) void {
    out.ttl_seconds = @min(out.ttl_seconds, ttl_seconds);
    assert(out.ttl_seconds <= ttl_seconds);
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test {
    _ = response_answers;
}

/// The chain the tests walk, left holding the canonical name when a CNAME was followed.
threadlocal var test_chain: Name = Name.empty;

fn collect_from(message: []const u8, kind: Kind, out: *Answers) !Outcome {
    test_chain = try Name.from_text("example.com");
    return collect(message, &test_chain, kind, 0, out);
}

test "an A record owned by the question is collected" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.answered, try collect_from(&fixtures.answer_a, .a, &collected));
    try testing.expectEqual(@as(u8, 1), collected.count);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[0].slice());
    try testing.expectEqual(@as(u32, 300), collected.ttl_seconds);
    try testing.expect(!collected.aliased);
    try testing.expect(!collected.truncated);
}

test "two A records for one name are both collected" {
    var collected: Answers = undefined;
    const outcome = try collect_from(&fixtures.answer_a_twice, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expectEqual(@as(u8, 2), collected.count);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 2 }, collected.addresses()[1].slice());
}

test "a record of another type is not an answer" {
    var collected: Answers = undefined;
    const outcome = try collect_from(&fixtures.answer_aaaa, .a, &collected);
    try testing.expectEqual(Outcome.no_data, outcome);
    try testing.expectEqual(@as(u8, 0), collected.count);
}

test "a CNAME and its target's A record answer in one message" {
    var collected: Answers = undefined;
    const outcome = try collect_from(&fixtures.answer_cname_then_a, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expect(collected.aliased);
    try testing.expect(test_chain.equal(&try Name.from_text("host.example.net")));
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, collected.addresses()[0].slice());
    // The smallest TTL over the records used: the CNAME's 60, not the address's 300.
    try testing.expectEqual(@as(u32, 60), collected.ttl_seconds);
}

test "a CNAME with no target record asks the caller to query again" {
    var collected: Answers = undefined;
    const outcome = try collect_from(&fixtures.answer_cname_only, .a, &collected);
    try testing.expectEqual(Outcome.chain_incomplete, outcome);
    try testing.expectEqual(@as(u8, 0), collected.count);
    try testing.expect(test_chain.equal(&try Name.from_text("host.example.net")));
}

test "an A record for a name nobody asked about is dropped" {
    var collected: Answers = undefined;
    const outcome = try collect_from(&fixtures.answer_injected, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    // The injected record is first in the section and holds 192.0.2.9. Only the asked-about
    // record is collected (RFC 5452 §6).
    try testing.expectEqual(@as(u8, 1), collected.count);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[0].slice());
}

test "a response with no answers at all is NODATA" {
    var collected: Answers = undefined;
    try testing.expectEqual(Outcome.no_data, try collect_from(&fixtures.answer_no_data, .a, &collected));
}

test "a chain already at the hop bound is refused rather than followed" {
    var collected: Answers = undefined;
    const question = try Name.from_text("example.com");
    test_chain = question;
    try testing.expectError(Error.ChainTooLong, collect(
        &fixtures.answer_cname_only,
        &test_chain,
        .a,
        core.constants.cname_hops_max,
        &collected,
    ));
}

test "a malformed record in the section fails the whole collection" {
    var collected: Answers = undefined;
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
    var collected: Answers = undefined;
    try testing.expectError(Error.MalformedMessage, collect_from(&chaos, .a, &collected));
}

test "more records than there is room for are truncated, not dropped silently" {
    var collected: Answers = undefined;
    const outcome = try collect_from(&fixtures.answer_a_seventeen, .a, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expectEqual(@as(u8, core.constants.addresses_max), collected.count);
    try testing.expect(collected.truncated);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[15].slice());
}

test "the hop count follows the chain across messages" {
    var collected: Answers = undefined;
    _ = try collect_from(&fixtures.answer_cname_then_a, .a, &collected);
    try testing.expectEqual(@as(u8, 1), collected.hops_used);

    test_chain = try Name.from_text("example.com");
    const outcome = try collect(&fixtures.answer_cname_only, &test_chain, .a, 3, &collected);
    try testing.expectEqual(Outcome.chain_incomplete, outcome);
    try testing.expectEqual(@as(u8, 4), collected.hops_used);
}

test "a negative answer's TTL is the SOA minimum, and zero with no SOA, which is not cached" {
    const question = try Name.from_text("example.com");
    try testing.expectEqual(@as(u32, 60), try negative_ttl_seconds(&fixtures.answer_name_error_soa, &question));
    try testing.expectEqual(@as(u32, 60), try negative_ttl_seconds(&fixtures.answer_no_data_soa, &question));
    try testing.expectEqual(@as(u32, 30), try negative_ttl_seconds(&fixtures.answer_no_data_soa_short, &question));
    try testing.expectEqual(@as(u32, 0), try negative_ttl_seconds(&fixtures.answer_name_error, &question));
    try testing.expectEqual(@as(u32, 0), try negative_ttl_seconds(&fixtures.answer_no_data, &question));
    // The walk steps over the answers to the authority section, and a message whose only
    // records are answers has no SOA to find.
    try testing.expectEqual(@as(u32, 60), try negative_ttl_seconds(&fixtures.answer_a_with_soa, &question));
    try testing.expectEqual(@as(u32, 0), try negative_ttl_seconds(&fixtures.answer_a_twice, &question));
}

test "a response echoing a maximal name parses, and its offsets do not overflow an octet" {
    var collected: Answers = undefined;
    test_chain = try Name.from_text("a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61);
    try testing.expectEqual(core.constants.name_bytes_max, test_chain.len);
    const outcome = try collect(&fixtures.answer_a_long_name, &test_chain, .a, 0, &collected);
    try testing.expectEqual(Outcome.answered, outcome);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, collected.addresses()[0].slice());
    try testing.expectEqual(@as(u32, 0), try negative_ttl_seconds(&fixtures.answer_a_long_name, &test_chain));
}

test {
    _ = response_take;
}
