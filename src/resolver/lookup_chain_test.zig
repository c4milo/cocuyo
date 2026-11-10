//! The CNAME chain through the fake server (docs/design.md §5, CNAME policy): a chain within one
//! message, one across messages, a loop, and the case a chain's name comes back in. Split from
//! `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Name = core.Name;
const Verdict = @import("lookup.zig").Verdict;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

test "a CNAME with no target asks the same server about where the chain went" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_only, servers[0].endpoint);
    try testing.expect(harness.lookup.current.equal(&try Name.parse("host.example.net")));
    try testing.expectEqual(@as(u8, 1), harness.lookup.cname_hops);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    try testing.expect(harness.poll() == .send_udp);
}

test "a CNAME re-query draws a new transaction" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.transaction;
    _ = harness.respond(fixtures.cname_only, servers[0].endpoint);
    const after = harness.lookup.transaction;
    try testing.expect(before.id != after.id or before.case_seed != after.case_seed);
    try testing.expect(before.case_seed != after.case_seed);
}

test "a chain across messages is kept no longer than the alias an earlier message gave" {
    // RFC 1035 §3.2.1: the answer is cached under the name asked, and reaches its records through
    // the aliases. The first, TTL 20, bounds the second, TTL 60, and the A record's 300.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    for ([_]fixtures.Reply{ fixtures.cname_short, fixtures.cname_fresh, fixtures.answer_a }) |reply| {
        _ = harness.send();
        try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    }
    try testing.expectEqual(@as(u8, 2), harness.lookup.cname_hops);
    try testing.expectEqual(@as(u32, 20), harness.poll().done.ttl_seconds);
}

test "a chain resolved in one message answers with the canonical name" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_then_a, servers[0].endpoint);
    const action = harness.poll();
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, action.done.addresses[0].slice());
    try testing.expect(action.done.canonical_name.?.equal(&try Name.parse("host.example.net")));
    try testing.expectEqual(@as(u32, 60), action.done.ttl_seconds);
}

test "a CNAME chain that loops fails the lookup, with the name left where it was" {
    // The chain moves before the hop bound stops it, which is the one path where the collector
    // has to put the name back: a lookup must not end pointing halfway around a loop.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.current;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.cname_loop, servers[0].endpoint));
    try testing.expectEqualSlices(u8, before.wire(), harness.lookup.current.wire());
    try testing.expectEqual(@as(u8, 0), harness.lookup.cname_hops);
    try testing.expectEqual(core.Error.ChainTooLong, harness.poll().failed.err);
}

test "a chain one hop past the bound across messages fails the lookup" {
    // Each reply moves the chain one hop, to a name no earlier reply named, so no loop is in any
    // one message: the bound across messages is what stops it (§5, CNAME policy).
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    var hops: u8 = 0;
    while (hops < core.limits.cname_hops_max) : (hops += 1) {
        _ = harness.send();
        try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.cname_fresh, servers[0].endpoint));
        try testing.expectEqual(hops + 1, harness.lookup.cname_hops);
    }
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.cname_fresh, servers[0].endpoint));
    try testing.expectEqual(core.Error.ChainTooLong, harness.poll().failed.err);
}

test "a chain name compressed into the question comes back without cocuyo's own case" {
    // A server may answer a CNAME whose target shares a suffix with the question, and compress
    // that suffix to a pointer into the question it echoed. The question carries the case
    // DNS-0x20 randomised, so the target decodes wearing it. Over sixteen seeds at least one
    // randomisation puts a capital in that suffix, and none of them may reach the caller.
    const seed_count = 16;
    var lookup_seed: u64 = 0;
    while (lookup_seed < seed_count) : (lookup_seed += 1) {
        var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
        try harness.start("example.com.", .a, lookup_seed);
        _ = harness.send();
        _ = harness.respond(fixtures.cname_into_question, servers[0].endpoint);
        try testing.expectEqualSlices(
            u8,
            (try Name.parse("host.com")).wire(),
            harness.lookup.current.wire(),
        );
    }
}

// The links a chain keeps (docs/design.md §5, The chain a lookup keeps; §17 question 122).

test "an answer through a chain across messages hands back each link, and each target" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    for ([_]fixtures.Reply{ fixtures.cname_short, fixtures.cname_fresh, fixtures.answer_a }) |reply| {
        _ = harness.send();
        try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    }
    const done = harness.poll().done;
    const end = done.canonical_name.?;
    try testing.expect(end.equal(&try Name.parse("c.host.example.net")));
    try testing.expectEqual(@as(u8, 2), done.aliases.count);
    try testing.expectEqualSlices(u8, (try Name.parse("example.com")).wire(), done.aliases.at(0).owner);
    try testing.expectEqual(@as(u32, 20), done.aliases.at(0).ttl_seconds);
    try testing.expectEqualSlices(u8, (try Name.parse("host.example.net")).wire(), done.aliases.at(1).owner);
    try testing.expectEqual(@as(u32, 60), done.aliases.at(1).ttl_seconds);
    try testing.expectEqualSlices(u8, done.aliases.at(1).owner, done.aliases.target(0, end));
    try testing.expectEqualSlices(u8, end.wire(), done.aliases.target(1, end));
}

test "a no data after a CNAME reports the chain's end and its link" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    for ([_]fixtures.Reply{ fixtures.cname_short, fixtures.no_data_soa }) |reply| {
        _ = harness.send();
        try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    }
    const failed = harness.poll().failed;
    try testing.expectEqual(core.Error.NoData, failed.err);
    try testing.expect(failed.canonical_name.?.equal(&try Name.parse("host.example.net")));
    try testing.expectEqual(@as(u8, 1), failed.aliases.count);
    try testing.expectEqualSlices(u8, (try Name.parse("example.com")).wire(), failed.aliases.at(0).owner);
}

test "a name error whose message holds the CNAME reports the link it took" {
    // RFC 2308 §2.1: the CNAME and the NXDOMAIN of its target in one message.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.name_error_cname_soa, servers[0].endpoint));
    const failed = harness.poll().failed;
    try testing.expectEqual(core.Error.NameNotFound, failed.err);
    try testing.expect(failed.canonical_name.?.equal(&try Name.parse("host.example.net")));
    try testing.expectEqual(@as(u8, 1), failed.aliases.count);
}

test "a reply the lookup ignores leaves the links as they were" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_short, servers[0].endpoint);
    // A CNAME whose rdata length runs past the message: the walk fails, and the chain stays.
    var malformed = fixtures.record_cname_fresh;
    malformed[11] = 0x40;
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(.{ .records = &malformed, .ancount = 1 }, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.lookup.aliases.count);
    try testing.expectEqual(harness.lookup.cname_hops, harness.lookup.aliases.count);
}

test "the search walk's next candidate starts with no link" {
    const search = [_]Name{try Name.parse("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    try harness.start("example", .a, seed);
    // `example.one.net` moves the chain, then has no data; `example` answers with no chain.
    for ([_]fixtures.Reply{ fixtures.cname_short, fixtures.no_data_soa, fixtures.answer_a }) |reply| {
        _ = harness.send();
        try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    }
    const done = harness.poll().done;
    try testing.expectEqual(@as(?*const Name, null), done.canonical_name);
    try testing.expectEqual(@as(u8, 0), done.aliases.count);
}
