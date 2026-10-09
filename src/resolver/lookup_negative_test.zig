//! Negative answers driven through the fake server: NXDOMAIN and NODATA moving the search walk
//! on, and the negative TTL a failure carries, or an answer reached past them (docs/design.md §5,
//! §18, RFC 2308). Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

test "NXDOMAIN moves to the next candidate, and the last one fails the lookup" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    try harness.start("example.com", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0].endpoint);
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("example.com.one.net")));
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0].endpoint);
    try testing.expectEqual(core.Error.NameNotFound, harness.poll().failed.err);
}

test "NOERROR with no record of this type is NODATA, and ends as NoData" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.no_data, servers[0].endpoint));
    try testing.expect(harness.lookup.flags.had_no_data);
    try testing.expectEqual(core.Error.NoData, harness.poll().failed.err);
}

test "a negative answer's SOA minimum reaches the failure, for NXDOMAIN and for NODATA" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error_soa, servers[0].endpoint);
    const failure = harness.poll().failed;
    try testing.expectEqual(core.Error.NameNotFound, failure.err);
    try testing.expectEqual(@as(u32, 60), failure.negative_ttl_seconds);

    var no_data: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try no_data.start("example.com.", .a, seed);
    _ = no_data.send();
    _ = no_data.respond(fixtures.no_data_soa, servers[0].endpoint);
    const nodata_failure = no_data.poll().failed;
    try testing.expectEqual(core.Error.NoData, nodata_failure.err);
    try testing.expectEqual(@as(u32, 60), nodata_failure.negative_ttl_seconds);
}

test "a negative answer is kept no longer than the alias that led to it, in its message or before" {
    // The alias's TTL is 20, the SOA's MINIMUM 60 (RFC 1035 §3.2.1, RFC 2308 §5).
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error_cname_soa, servers[0].endpoint);
    try testing.expectEqual(@as(u32, 20), harness.poll().failed.negative_ttl_seconds);
    const ends = [_]fixtures.Reply{ fixtures.name_error_soa, fixtures.no_data_soa };
    for (ends) |end| {
        try harness.start("example.com.", .a, seed);
        _ = harness.send();
        _ = harness.respond(fixtures.cname_short, servers[0].endpoint);
        _ = harness.send();
        _ = harness.respond(end, servers[0].endpoint);
        try testing.expectEqual(@as(u32, 20), harness.poll().failed.negative_ttl_seconds);
    }
}

test "a negative answer with no SOA, or a broken one, carries a TTL of zero" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0].endpoint);
    try testing.expectEqual(@as(u32, 0), harness.poll().failed.negative_ttl_seconds);

    var broken: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try broken.start("example.com.", .a, seed);
    _ = broken.send();
    _ = broken.respond(fixtures.name_error_soa_broken, servers[0].endpoint);
    const failure = broken.poll().failed;
    try testing.expectEqual(core.Error.NameNotFound, failure.err);
    try testing.expectEqual(@as(u32, 0), failure.negative_ttl_seconds);
}

test "a failure that is not a negative answer carries a TTL of zero" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .attempts = 1 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[0].endpoint);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[1].endpoint);
    const failure = harness.poll().failed;
    try testing.expectEqual(core.Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(u32, 0), failure.negative_ttl_seconds);
}

// The search walk's end, kept under the name as asked, is bounded by every negative on the way
// (docs/design.md §5, c4milo/cocuyo#38).

/// A negative kept briefly: under the SOA fixture's MINIMUM and the A record's TTL.
const short_ttl_seconds = 5;
/// The negative TTL `fixtures.record_soa` carries: its MINIMUM, under its own TTL of 300.
const soa_ttl_seconds = 60;
/// The TTL of `fixtures.record_a`.
const answer_ttl_seconds = 300;
/// The TTL of the alias in `fixtures.name_error_cname_soa`, under the SOA's MINIMUM.
const alias_ttl_seconds = 20;

/// `fixtures.record_soa` with a TTL of `short_ttl_seconds`, which caps the negative TTL it
/// carries there (RFC 2308 §5).
const record_soa_short = soa: {
    var record = fixtures.record_soa;
    // The owner is a compression pointer, then the type, the class and the TTL (RFC 1035 §4.1.3).
    const ttl_at = wire.constants.pointer_bytes + wire.constants.record_ttl_offset;
    wire.integer.write_u32(&record, ttl_at, short_ttl_seconds);
    break :soa record;
};
const name_error_short: fixtures.Reply = .{ .rcode = .name_error, .authority = &record_soa_short, .nscount = 1 };
const no_data_short: fixtures.Reply = .{ .authority = &record_soa_short, .nscount = 1 };

/// Walks `host` over the search list `one.net`: `host.one.net` is asked first and answered with
/// `first`, then `host` with `second`. Returns the end the lookup polls.
fn walk(harness: *fixtures.Harness, first: fixtures.Reply, second: fixtures.Reply) !lookup_module.Action {
    try harness.start("host", .a, seed);
    _ = harness.send();
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("host.one.net")));
    try testing.expectEqual(Verdict.accepted, harness.respond(first, servers[0].endpoint));
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("host")));
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(second, servers[0].endpoint));
    return harness.poll();
}

test "a walk whose every candidate is negative carries the smallest negative TTL, not the last" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    const both_alike = (try walk(&harness, fixtures.name_error_soa, fixtures.name_error_soa)).failed;
    try testing.expectEqual(@as(u32, soa_ttl_seconds), both_alike.negative_ttl_seconds);
    // The shorter first: `host.one.net` may exist once it runs out, so `host` may not stay
    // missing for the longer one.
    const shorter_first = (try walk(&harness, name_error_short, fixtures.name_error_soa)).failed;
    try testing.expectEqual(core.Error.NameNotFound, shorter_first.err);
    try testing.expectEqual(@as(u32, short_ttl_seconds), shorter_first.negative_ttl_seconds);
    const shorter_last = (try walk(&harness, fixtures.name_error_soa, name_error_short)).failed;
    try testing.expectEqual(@as(u32, short_ttl_seconds), shorter_last.negative_ttl_seconds);
    // A NODATA bounds the walk as an NXDOMAIN does, before one and after one.
    const no_data_first = (try walk(&harness, no_data_short, fixtures.name_error_soa)).failed;
    try testing.expectEqual(core.Error.NoData, no_data_first.err);
    try testing.expectEqual(@as(u32, short_ttl_seconds), no_data_first.negative_ttl_seconds);
    const no_data_last = (try walk(&harness, name_error_short, fixtures.no_data_soa)).failed;
    try testing.expectEqual(core.Error.NoData, no_data_last.err);
    try testing.expectEqual(@as(u32, short_ttl_seconds), no_data_last.negative_ttl_seconds);
}

test "an answer past negative candidates is kept no longer than the shortest of them" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    // `host.one.net` may exist once its negative runs out, and a new walk would stop there.
    const past_name_error = (try walk(&harness, name_error_short, fixtures.answer_a)).done;
    try testing.expectEqual(@as(u32, short_ttl_seconds), past_name_error.ttl_seconds);
    // The answers the lookup holds are what the table hands a memory (docs/design.md §20).
    try testing.expectEqual(@as(u32, short_ttl_seconds), harness.lookup.answers.ttl_seconds);
    const past_no_data = (try walk(&harness, no_data_short, fixtures.answer_a)).done;
    try testing.expectEqual(@as(u32, short_ttl_seconds), past_no_data.ttl_seconds);
    // The alias on the way to the first candidate's NXDOMAIN bounds its negative, and so the end.
    const past_alias = (try walk(&harness, fixtures.name_error_cname_soa, fixtures.answer_a)).done;
    try testing.expectEqual(@as(u32, alias_ttl_seconds), past_alias.ttl_seconds);

    // The first candidate answers: the walk moved past nothing, and the answer keeps its TTL.
    try harness.start("host", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(@as(u32, answer_ttl_seconds), harness.poll().done.ttl_seconds);
}

test "a negative with no SOA on the way makes the walk's end one no cache keeps" {
    // Its TTL is zero, which is not cached (RFC 2308 §5), and the end rests on it.
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    const past_name_error = (try walk(&harness, fixtures.name_error, fixtures.answer_a)).done;
    try testing.expectEqual(@as(u32, 0), past_name_error.ttl_seconds);
    const past_no_data = (try walk(&harness, fixtures.no_data, fixtures.answer_a)).done;
    try testing.expectEqual(@as(u32, 0), past_no_data.ttl_seconds);
    const failure = (try walk(&harness, fixtures.name_error, fixtures.name_error_soa)).failed;
    try testing.expectEqual(core.Error.NameNotFound, failure.err);
    try testing.expectEqual(@as(u32, 0), failure.negative_ttl_seconds);
}
