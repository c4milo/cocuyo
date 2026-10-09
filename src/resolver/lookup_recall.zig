//! Ending a lookup from memory: the two ways a cache under the table answers a question before
//! any query is built (docs/design.md §20). `table_memory.zig` is the one caller, at a lookup's
//! first poll, and both leave the lookup in the end state a lookup that went out would reach.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Lookup = @import("lookup.zig").Lookup;

/// Whether `lookup` is where a lookup stands before its first query: ready to build it, or, when
/// every query goes over TCP (§19 step 11), waiting for its connection. The memory is asked only
/// there, at the first poll.
fn before_first_query(lookup: *const Lookup) bool {
    return lookup.state == .query_ready or lookup.state == .tcp_needed;
}

/// Ends `lookup` with answers the memory remembered. `ttl_seconds` is what is left of the
/// answers' own TTL, the life they were given, so the answer reports the life it has now. A
/// memory may report more than that TTL, and the answer then reports what it says.
///
/// `canonical` is the end of the CNAME chain that reached them, or null when none did. The
/// answer reports it as a lookup that went out reports its own, so the same question answers the
/// same whether the memory held it or not (§17 question 13).
pub fn answer(
    lookup: *Lookup,
    answers: *const wire.Answers,
    ttl_seconds: u32,
    canonical: ?*const Name,
) void {
    assert(before_first_query(lookup));
    assert(!lookup.flags.aliased);
    // Only the storage in use is copied, as a cache put does, not the whole union.
    lookup.answers.assign(answers, lookup.question.kind);
    // The TTLs of cached data "count down" (RFC 1035 §6.1.3): every TTL the answers hold, each
    // record's own included, loses the time they spent in the memory, which is the life they were
    // given less what is left of it. A memory that keeps answers past their own TTL says more is
    // left than that: no time spent is known then, nothing is lowered, and the answer reports
    // what the memory says.
    lookup.answers.age(lookup.question.kind, answers.ttl_seconds -| ttl_seconds);
    assert(lookup.answers.ttl_seconds == @min(answers.ttl_seconds, ttl_seconds));
    lookup.answers.ttl_seconds = ttl_seconds;
    if (canonical) |name| {
        lookup.current = name.*;
        lookup.flags.aliased = true;
    }
    lookup.state = .done;
    assert(lookup.is_settled());
}

/// Ends `lookup` with a negative the memory remembered: one of the two of RFC 2308 §5, with what
/// is left of its life.
pub fn failure(lookup: *Lookup, err: core.Error, ttl_seconds: u32) void {
    assert(before_first_query(lookup));
    assert(err == core.Error.NameNotFound or err == core.Error.NoData);
    lookup.negative_ttl_seconds = ttl_seconds;
    lookup.fail(err);
}

// Tests. The table's tests drive these through a memory; these pin what a recalled answer's
// TTLs are (c4milo/cocuyo#39).

const testing = std.testing;
const fixtures = @import("fixtures.zig");

/// Two records with TTLs of their own, so an answer that aged one and not the other would show.
const mx_count = 2;

/// Two MX records with TTLs of their own, as a lookup that went out collects them, and the
/// answers' TTL the smaller of the two.
fn two_mx(first_ttl_seconds: u32, second_ttl_seconds: u32) wire.Answers {
    const mx = wire.rdata.fixtures.mx;
    var answers = wire.Answers.init(.mx);
    const records = &answers.items.records;
    @memcpy(records.bytes[0..mx.len], &mx);
    @memcpy(records.bytes[mx.len..][0..mx.len], &mx);
    const code = core.Kind.mx.code();
    records.refs[0] = .{ .kind_code = code, .ttl_seconds = first_ttl_seconds, .offset = 0, .len = mx.len };
    records.refs[1] = .{ .kind_code = code, .ttl_seconds = second_ttl_seconds, .offset = mx.len, .len = mx.len };
    records.used = mx_count * mx.len;
    answers.count = mx_count;
    answers.ttl_seconds = @min(first_ttl_seconds, second_ttl_seconds);
    return answers;
}

test "a recalled answer's records each lose the time the answers spent in the memory" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_two } };
    try harness.start("example.com.", .mx, fixtures.seed);
    const answers = two_mx(300, 200);
    // Given 200 seconds and left with 150: fifty spent in the memory, which each record loses.
    answer(&harness.lookup, &answers, 150, null);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u32, 150), done.ttl_seconds);
    try testing.expectEqual(@as(u8, mx_count), done.record_count);
    try testing.expectEqual(@as(u32, 250), done.records.?.at(0).ttl_seconds);
    try testing.expectEqual(@as(u32, 150), done.records.?.at(1).ttl_seconds);
    try testing.expectEqualSlices(u8, answers.records().at(1).rdata, done.records.?.at(1).rdata);
}

test "a recalled answer with more left than it was given keeps every record's TTL" {
    // A memory that keeps answers past their TTL, with a floor of its own, reports more than the
    // answers hold. No time spent is known, so no record is lowered, and the answer reports what
    // the memory says, as every recalled answer did before c4milo/cocuyo#39.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_two } };
    try harness.start("example.com.", .mx, fixtures.seed);
    const answers = two_mx(300, 200);
    answer(&harness.lookup, &answers, 250, null);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u32, 250), done.ttl_seconds);
    try testing.expectEqual(@as(u32, 300), done.records.?.at(0).ttl_seconds);
    try testing.expectEqual(@as(u32, 200), done.records.?.at(1).ttl_seconds);
}

test "a recalled answer with its whole life left keeps every TTL it was given" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_two } };
    try harness.start("example.com.", .mx, fixtures.seed);
    const answers = two_mx(300, 200);
    answer(&harness.lookup, &answers, 200, null);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u32, 200), done.ttl_seconds);
    try testing.expectEqual(@as(u32, 300), done.records.?.at(0).ttl_seconds);
    try testing.expectEqual(@as(u32, 200), done.records.?.at(1).ttl_seconds);
}
