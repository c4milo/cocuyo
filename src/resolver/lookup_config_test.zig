//! The configuration knobs of docs/design.md §19 step 11, each driven through the fake server:
//! every query over TCP, a truncated answer taken as it is, the RD bit, a server's error as
//! the answer, the first server alone, a TCP port of its own, the timeout cap, and no server.
//! Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Endpoint = core.Endpoint;
const fixtures = @import("fixtures.zig");
const lookup_module = @import("lookup.zig");
const State = lookup_module.State;
const Verdict = lookup_module.Verdict;
const policy = @import("lookup_policy.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

fn harness_for(config: Config) fixtures.Harness {
    return .{ .config = config };
}

/// Runs a lookup over TCP up to the point where the fake server may answer.
fn connect_and_send(harness: *fixtures.Harness) Endpoint {
    const action = harness.poll();
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    return action.connect_tcp;
}

test "use_tcp sends every query over TCP, the retries included" {
    var harness = harness_for(.{ .servers = &servers, .use_tcp = true });
    try harness.start("example.com.", .a, seed);
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    _ = connect_and_send(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.cname_only, servers[0].endpoint));
    // The re-query for the chain's target goes over TCP too.
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
}

test "ignore_truncation takes a truncated UDP answer as it is" {
    var harness = harness_for(.{ .servers = &servers, .ignore_truncation = true });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_truncated, servers[0].endpoint));
    try testing.expectEqual(@as(usize, 1), harness.poll().done.addresses.len);

    var asks_again = harness_for(.{ .servers = &servers });
    try asks_again.start("example.com.", .a, seed);
    _ = asks_again.send();
    try testing.expectEqual(Verdict.accepted, asks_again.respond(fixtures.answer_a_truncated, servers[0].endpoint));
    try testing.expectEqual(State.tcp_needed, asks_again.lookup.state);
}

test "recursion_desired off clears the RD bit of the query" {
    var harness = harness_for(.{ .servers = &servers, .recursion_desired = false });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const header = try wire.header.parse(harness.query[0..harness.query_bytes]);
    try testing.expectEqual(@as(u16, 0), header.flags & wire.constants.flag_recursion_desired);
}

test "check_response off ends the lookup with the server's error rather than moving on" {
    var harness = harness_for(.{ .servers = &servers, .check_response = false });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[0].endpoint));
    const failure = harness.poll().failed;
    try testing.expectEqual(core.Error.ServerFailure, failure.err);
    try testing.expectEqual(@as(u8, 0), failure.server_index);
}

test "primary asks the first server alone" {
    var harness = harness_for(.{ .servers = &servers, .primary = true, .attempts = 1 });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[0].endpoint));
    const failure = harness.poll().failed;
    try testing.expectEqual(core.Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(u8, 0), failure.server_index);
}

test "a server's own TCP port is where the connection goes, and where its answer must come from" {
    const ported = [_]core.Server{
        .{ .endpoint = servers[0].endpoint, .tcp_port = fixtures.port_other },
        servers[1],
    };
    var harness = harness_for(.{ .servers = &ported, .use_tcp = true });
    try harness.start("example.com.", .a, seed);
    const connected = connect_and_send(&harness);
    try testing.expectEqual(@as(u16, fixtures.port_other), connected.port);
    try testing.expect(connected.address.equal(&servers[0].endpoint.address));
    // From the UDP port it is not this server's answer; from the TCP port it is.
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, connected));
}

test "the timeout cap is the configuration's, not the constant's" {
    const capped: Config = .{ .servers = &servers, .timeout_ns = 4_000_000_000, .timeout_ns_max = 5_000_000_000 };
    try testing.expectEqual(@as(u64, 4_000_000_000), policy.deadline_ns(&capped, 0, 0));
    try testing.expectEqual(@as(u64, 5_000_000_000), policy.deadline_ns(&capped, 1, 0));
    const open: Config = .{ .servers = &servers, .timeout_ns = 4_000_000_000 };
    try testing.expectEqual(@as(u64, 8_000_000_000), policy.deadline_ns(&open, 1, 0));
}

test "a configuration with no server fails every lookup at once" {
    var harness = harness_for(.{ .servers = &.{} });
    try harness.start("example.com.", .a, seed);
    try testing.expectEqual(State.failed, harness.lookup.state);
    try testing.expectEqual(core.Error.NoServers, harness.poll().failed.err);
}
