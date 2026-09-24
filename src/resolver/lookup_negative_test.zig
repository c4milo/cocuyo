//! The negative TTL a failure carries (docs/design.md §18, RFC 2308), driven through the fake
//! server. Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

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
