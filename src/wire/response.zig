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

/// What was collected. The addresses, the PTR names and the kept records share storage, because
/// one question asks for one type and no response can fill more than one of them
/// (docs/design.md §9 and §19 step 9).
///
/// The chain's name is not here: it is the caller's, passed to `collect` by pointer and left
/// holding the canonical name. A lookup already holds the name it is asking about, so keeping a
/// second copy here would cost 256 octets per lookup slot to say the same thing twice.
pub const Answers = struct {
    items: Items,
    count: u8,
    /// The smallest TTL over every record used, which is what a cache above cocuyo would honour.
    ttl_seconds: u32,
    /// Whether the chain moved: a CNAME was followed.
    aliased: bool,
    /// How many CNAMEs were followed, counting the ones followed before this message, so a lookup
    /// carries the bound across a chain that spans several responses.
    hops_used: u8,
    /// Whether records were dropped for want of room, here or in the record walk.
    truncated: bool,

    pub const Items = union {
        addresses: [core.constants.addresses_max]Address,
        names: [core.constants.ptr_names_max]Name,
        records: Records,
    };

    /// An empty collection for a question. The union's active field is chosen by the type asked
    /// for and each is zeroed, so nothing here is ever read uninitialised.
    pub fn init(kind: Kind) Answers {
        assert(kind.queryable());
        return .{
            .items = switch (kind.storage()) {
                .names => .{ .names = @splat(Name.root) },
                .addresses => .{ .addresses = @splat(.{ .family = .ipv4, .octets = @splat(0) }) },
                .rdata => .{ .records = Records.empty },
            },
            .count = 0,
            .ttl_seconds = 0,
            .aliased = false,
            .hops_used = 0,
            .truncated = false,
        };
    }

    /// Empties `self` for a question of `kind`, touching only the storage that kind uses. The
    /// rdata buffer is not cleared: nothing reads past `used`, which `Records.at` asserts, and
    /// clearing two kilooctets on every response is what §11 measured at 25 ns a parse.
    pub fn reset(self: *Answers, kind: Kind) void {
        assert(kind.queryable());
        // Assigning the union is what makes a member active in a safe build; writing a field of
        // an inactive member is a safety panic.
        switch (kind.storage()) {
            .names => self.items = .{ .names = @splat(Name.root) },
            .addresses => self.items = .{ .addresses = @splat(.{ .family = .ipv4, .octets = @splat(0) }) },
            .rdata => {
                self.items = .{ .records = undefined };
                self.items.records.used = 0;
            },
        }
        self.count = 0;
        self.ttl_seconds = 0;
        self.aliased = false;
        self.hops_used = 0;
        self.truncated = false;
        assert(self.count == 0);
    }

    /// Copies `src` into `dst` for a question of `kind`: the scalars and the storage in use, and
    /// nothing past `count` or `used`, so a cache put costs what the answer holds and not what
    /// the union can hold.
    pub fn assign(dst: *Answers, src: *const Answers, kind: Kind) void {
        assert(kind.queryable());
        dst.count = src.count;
        dst.ttl_seconds = src.ttl_seconds;
        dst.aliased = src.aliased;
        dst.hops_used = src.hops_used;
        dst.truncated = src.truncated;
        switch (kind.storage()) {
            .addresses => {
                dst.items = .{ .addresses = undefined };
                @memcpy(dst.items.addresses[0..src.count], src.items.addresses[0..src.count]);
            },
            .names => {
                dst.items = .{ .names = undefined };
                @memcpy(dst.items.names[0..src.count], src.items.names[0..src.count]);
            },
            .rdata => {
                const from = &src.items.records;
                assert(from.used <= core.constants.rdata_bytes_max);
                dst.items = .{ .records = undefined };
                const to = &dst.items.records;
                @memcpy(to.refs[0..src.count], from.refs[0..src.count]);
                @memcpy(to.bytes[0..from.used], from.bytes[0..from.used]);
                to.used = from.used;
            },
        }
    }

    /// The addresses collected for an A or AAAA question.
    pub fn addresses(self: *const Answers) []const Address {
        assert(self.count <= core.constants.addresses_max);
        return self.items.addresses[0..self.count];
    }

    /// The names collected for a PTR question.
    pub fn names(self: *const Answers) []const Name {
        assert(self.count <= core.constants.ptr_names_max);
        return self.items.names[0..self.count];
    }

    /// The records kept for a question of any other type, `count` of them.
    pub fn records(self: *const Answers) *const Records {
        assert(self.count <= core.constants.records_kept_max);
        return &self.items.records;
    }
};

/// The records of one type that are neither addresses nor PTR names: a reference each into a
/// buffer holding its rdata with every name written out in full (docs/design.md §19 step 9).
pub const Records = struct {
    refs: [core.constants.records_kept_max]Ref,
    bytes: [core.constants.rdata_bytes_max]u8,
    /// Octets of `bytes` in use.
    used: u16,

    pub const Ref = struct { kind_code: u16, ttl_seconds: u32, offset: u16, len: u16 };

    pub const empty: Records = .{
        .refs = @splat(.{ .kind_code = 0, .ttl_seconds = 0, .offset = 0, .len = 0 }),
        .bytes = @splat(0),
        .used = 0,
    };

    /// The record at `index`, which the owning `Answers.count` bounds.
    pub fn at(self: *const Records, index: usize) Kept {
        assert(index < core.constants.records_kept_max);
        const ref = self.refs[index];
        assert(ref.offset + ref.len <= self.used);
        return .{
            .kind_code = ref.kind_code,
            .ttl_seconds = ref.ttl_seconds,
            .rdata = self.bytes[ref.offset..][0..ref.len],
        };
    }
};

/// One kept record: its type as the octets said it, its TTL, and its rdata, self-contained, for
/// the typed views of `wire.rdata`.
pub const Kept = struct { kind_code: u16, ttl_seconds: u32, rdata: []const u8 };

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
    const header = try header_codec.parse(message);
    if (header.qdcount != 1) return Error.MalformedMessage;
    out.reset(kind);
    out.hops_used = hops_before;
    // The question's own name fixes where the answer section starts, and the response was already
    // checked to carry that question byte for byte (docs/design.md §7 check 5). The sum is taken
    // in a usize: a maximal name overflows the octet its length is held in.
    const answer_offset = section_start(chain);
    if (answer_offset > message.len) return Error.MalformedMessage;

    var hops: u8 = hops_before;
    while (hops <= core.constants.cname_hops_max) {
        const pass = try one_pass(message, header.ancount, kind, out, answer_offset, chain);
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
/// message that cannot be cached negatively (RFC 2308 §5, last paragraph).
///
/// The authority section starts where the answer section ends, so the answer records are skipped
/// on the way, never decoded. `question` is the name the message echoes, which fixes where the
/// sections start (§7 check 5).
pub fn negative_ttl_seconds(message: []const u8, question: *const Name) Error!u32 {
    assert(question.len >= 1);
    const header = try header_codec.parse(message);
    if (header.qdcount != 1) return Error.MalformedMessage;
    const answer_offset = section_start(question);
    if (answer_offset > message.len) return Error.MalformedMessage;
    var answers = record_codec.Iterator.init(message, answer_offset, header.ancount);
    var authority_offset: usize = answer_offset;
    while (try answers.next()) |record| authority_offset = record.end;
    var authority = record_codec.Iterator.init(message, authority_offset, header.nscount);
    while (try authority.next()) |record| {
        if (record.is_kind(.soa)) return record.soa_negative_ttl(message);
    }
    return 0;
}

/// Where the answer section starts: after the header and the one question the message echoes.
pub fn section_start(question: *const Name) usize {
    const name_len: usize = question.len;
    assert(name_len <= core.constants.name_bytes_max);
    return core.constants.header_bytes + name_len + core.constants.question_fixed_bytes;
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

/// The smallest TTL over the records used. Zero means nothing has been noted yet, and a record
/// with a TTL of zero is one nothing may cache, so it stays the smallest.
pub fn note_ttl(ttl_seconds: u32, out: *Answers) void {
    if (out.ttl_seconds == 0 or ttl_seconds < out.ttl_seconds) out.ttl_seconds = ttl_seconds;
    assert(out.ttl_seconds <= ttl_seconds or ttl_seconds == 0);
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

/// The chain the tests walk, left holding the canonical name when a CNAME was followed.
var test_chain: Name = Name.empty;

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

test "a negative answer's TTL is the SOA minimum, for NXDOMAIN and for NODATA alike" {
    const question = try Name.from_text("example.com");
    try testing.expectEqual(@as(u32, 60), try negative_ttl_seconds(&fixtures.answer_name_error_soa, &question));
    try testing.expectEqual(@as(u32, 60), try negative_ttl_seconds(&fixtures.answer_no_data_soa, &question));
    try testing.expectEqual(@as(u32, 30), try negative_ttl_seconds(&fixtures.answer_no_data_soa_short, &question));
}

test "a negative answer with no SOA has a TTL of zero, which is not cached" {
    const question = try Name.from_text("example.com");
    try testing.expectEqual(@as(u32, 0), try negative_ttl_seconds(&fixtures.answer_name_error, &question));
    try testing.expectEqual(@as(u32, 0), try negative_ttl_seconds(&fixtures.answer_no_data, &question));
}

test "the authority walk starts after the answers, not at the first record" {
    // A message with answers: the walk must step over them to reach the authority section, and
    // a message whose only records are answers has no SOA to find.
    const question = try Name.from_text("example.com");
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

test "the negative TTL walk steps over the answers to reach the SOA" {
    const question = try Name.from_text("example.com");
    try testing.expectEqual(@as(u32, 60), try negative_ttl_seconds(&fixtures.answer_a_with_soa, &question));
}

test {
    _ = response_take;
}
