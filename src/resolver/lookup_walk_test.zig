//! The walk over the servers, the passes and the candidates, pinned on the lookup alone.
//! Split from `lookup.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Config = core.Config;
const Question = core.Question;
const Name = core.Name;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const State = lookup_module.State;
const Servers = @import("servers.zig").Servers;
const fixtures = @import("fixtures.zig");
const resolver_limits = @import("limits.zig");

const one_server = fixtures.servers_one;
const three_servers = fixtures.servers_three;

test "the servers are tried in turn, then the passes, then the lookup fails" {
    const config: Config = .{ .servers = &three_servers, .attempts = 2 };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("example.com.", .a), 1);
    const first_id = lookup.transaction.id;
    lookup.next_server(1);
    try testing.expectEqual(@as(u8, 1), lookup.server_index);
    try testing.expectEqual(@as(u8, 0), lookup.round);
    try testing.expect(lookup.transaction.id != first_id or lookup.transaction.case_seed != 0);
    lookup.next_server(2);
    lookup.next_server(3);
    try testing.expectEqual(@as(u8, 0), lookup.server_index);
    try testing.expectEqual(@as(u8, 1), lookup.round);
    lookup.next_server(4);
    lookup.next_server(5);
    lookup.next_server(6);
    try testing.expectEqual(State.failed, lookup.state);
    try testing.expectEqual(core.Error.Timeout, lookup.failure_of().err);
}

test "a lookup that saw a server failure fails with that rather than a timeout" {
    const config: Config = .{ .servers = &one_server, .attempts = 1 };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("example.com.", .a), 1);
    lookup.cause = .{ .server_index = 0, .what = .{ .rcode = .server_failure } };
    lookup.next_server(1);
    try testing.expectEqual(core.Error.AllServersFailed, lookup.failure_of().err);
    try testing.expectEqual(@as(?lookup_module.Cause, .{ .server_index = 0, .what = .{ .rcode = .server_failure } }), lookup.failure_of().cause);
}

test "the candidate walk ends in NameNotFound, or NoData when a name existed" {
    const search = [_]Name{try Name.from_text("one.net")};
    const config: Config = .{ .servers = &one_server, .search = &search, .ndots = 1 };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("host.example", .a), 1);
    try testing.expect(lookup.current.equal(&try Name.from_text("host.example")));
    lookup.next_candidate(1);
    try testing.expect(lookup.current.equal(&try Name.from_text("host.example.one.net")));
    lookup.next_candidate(2);
    try testing.expectEqual(core.Error.NameNotFound, lookup.failure_of().err);

    var second = Lookup.init(&config, &servers_config, try Question.from_text("host.example", .a), 1);
    second.flags.had_no_data = true;
    second.next_candidate(1);
    second.next_candidate(2);
    try testing.expectEqual(core.Error.NoData, second.failure_of().err);
}

test "the next candidate starts over at the first server, the first pass and with EDNS0" {
    // A name that timed out once on every server must not leave the next candidate fewer passes
    // (docs/design.md §5, search list policy), and a server that refused EDNS0 for one name is
    // offered it again for the next (RFC 6891 §6.2.2).
    const search = [_]Name{try Name.from_text("one.net")};
    const config: Config = .{ .servers = &three_servers, .search = &search, .ndots = 1, .attempts = 2 };
    var servers_config = Servers.init(&config, 1);
    var lookup = Lookup.init(&config, &servers_config, try Question.from_text("host.example", .a), 1);
    lookup.next_server(1);
    lookup.next_server(2);
    lookup.next_server(3);
    lookup.next_server(4);
    try testing.expectEqual(@as(u8, 1), lookup.round);
    lookup.flags.edns_enabled = false;
    lookup.next_candidate(5);
    try testing.expectEqual(State.query_ready, lookup.state);
    try testing.expectEqual(@as(u8, 0), lookup.server_index);
    try testing.expectEqual(@as(u8, 0), lookup.round);
    try testing.expect(lookup.flags.edns_enabled);
}

test "a lookup over the most servers, passes and candidates sends every try, and ends at the last" {
    // 8 servers by 5 passes by 7 candidates under the longest wait. Each server takes 3 queries
    // of a name, so 24 tries a candidate, the last of each answered NXDOMAIN (RFC 9520 §3.1;
    // docs/design.md §16 decision 58). Every counter of the walk but the pass reaches the most
    // it holds.
    var eight: [core.limits.servers_max]core.Server = undefined;
    for (&eight, 1..) |*server, last| {
        server.* = .{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, @intCast(last) }) } };
    }
    var search: [core.limits.search_max]Name = undefined;
    for (&search, 0..) |*name, index| name.* = try Name.from_text(&.{ 's', @intCast('0' + index), '.', 'e', 'x' });
    var harness: fixtures.Harness = .{ .config = .{
        .servers = &eight,
        .search = &search,
        .attempts = core.limits.attempts_max,
        .timeout_ns = core.limits.timeout_ns_max,
        .timeout_ns_max = core.limits.timeout_ns_max,
    } };
    try harness.start("host", .a, fixtures.seed);
    const tries = eight.len * resolver_limits.queries_per_transport_max;
    for (0..core.limits.candidates_max) |_| {
        for (1..tries) |_| {
            _ = harness.send();
            harness.now_ns = harness.lookup.deadline_ns - 1;
        }
        _ = harness.send();
        const verdict = harness.respond(fixtures.name_error, harness.lookup.server());
        try testing.expectEqual(lookup_module.Verdict.accepted, verdict);
    }
    try testing.expectEqual(core.Error.NameNotFound, harness.poll().failed.err);
    // One transaction a try, numbered from zero.
    try testing.expectEqual(tries * core.limits.candidates_max - 1, harness.lookup.transaction.number);
}
