//! Ending a lookup from memory: the two ways a cache under the table answers a question before
//! any query is built (docs/design.md §20). `table_memory.zig` is the one caller, at a lookup's
//! first poll, and both leave the lookup in the end state a lookup that went out would reach.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Lookup = @import("lookup.zig").Lookup;
const security = @import("lookup_security.zig");

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
    status: core.Security,
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
    security.recalled(lookup, status);
}

/// Ends `lookup` with a negative the memory remembered: one of the two of RFC 2308 §5, with what
/// is left of its life.
pub fn failure(lookup: *Lookup, err: core.Error, ttl_seconds: u32, status: core.Security) void {
    assert(before_first_query(lookup));
    assert(err == core.Error.NameNotFound or err == core.Error.NoData);
    lookup.negative_ttl_seconds = ttl_seconds;
    lookup.fail(err);
    security.recalled(lookup, status);
}

/// Ends `lookup` with a resolution failure the memory remembered (RFC 9520 §3.2). The memory
/// keeps no cause, and no pass was made, so the failure has neither (docs/design.md §16
/// decision 61, §17 question 89).
pub fn failed(lookup: *Lookup, err: core.Error) void {
    assert(before_first_query(lookup));
    assert(err != core.Error.NameNotFound and err != core.Error.NoData);
    assert(lookup.round == 0);
    assert(lookup.cause.what == .none);
    lookup.fail(err);
}

// Tests. The table's tests drive these through a memory; these pin what a recalled answer's
// TTLs are (c4milo/cocuyo#39).

const testing = std.testing;
const fixtures = @import("fixtures.zig");

/// Two records with TTLs of their own, so an answer that aged one and not the other would show.
const mx_count: usize = 2;

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
    answer(&harness.lookup, &answers, 150, null, .unchecked);
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
    answer(&harness.lookup, &answers, 250, null, .unchecked);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u32, 250), done.ttl_seconds);
    try testing.expectEqual(@as(u32, 300), done.records.?.at(0).ttl_seconds);
    try testing.expectEqual(@as(u32, 200), done.records.?.at(1).ttl_seconds);
}

test "a recalled answer with its whole life left keeps every TTL it was given" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_two } };
    try harness.start("example.com.", .mx, fixtures.seed);
    const answers = two_mx(300, 200);
    answer(&harness.lookup, &answers, 200, null, .unchecked);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u32, 200), done.ttl_seconds);
    try testing.expectEqual(@as(u32, 300), done.records.?.at(0).ttl_seconds);
    try testing.expectEqual(@as(u32, 200), done.records.?.at(1).ttl_seconds);
}

test "a recalled end reports the status it was kept with, while the lookup relies on the AD bit" {
    // docs/design.md §25, Stage A rule 5: the memory keeps the status with the entry.
    const cached = fixtures.cached_a("192.0.2.1");
    for ([_]core.AuthenticatedData{ .always, .ignored }) |mode| {
        for ([_]core.Security{ .authenticated, .unchecked }) |status| {
            const expected: core.Security = if (mode == .always) status else .unchecked;
            var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one, .authenticated_data = mode } };
            try harness.start("example.com.", .a, fixtures.seed);
            answer(&harness.lookup, &cached, fixtures.cached_ttl_seconds, null, status);
            try testing.expectEqual(expected, harness.lookup.answer().security);
            try harness.start("example.com.", .a, fixtures.seed);
            failure(&harness.lookup, core.Error.NameNotFound, fixtures.cached_ttl_seconds, status);
            try testing.expectEqual(expected, harness.lookup.failure_of().security);
        }
    }
}
