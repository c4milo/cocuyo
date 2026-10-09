//! The tests of BADCOOKIE (RFC 7873 §5.3; docs/design.md §5, §19 step 10), through the fake
//! server: `on_bad_cookie` in `lookup_response.zig`, split from it by the file-length rule. The
//! other cookie tests are in `lookup_cookie.zig`, whose helpers these read.
const std = @import("std");
const testing = std.testing;
const fixtures = @import("fixtures.zig");
const cookie_tests = @import("lookup_cookie.zig");
const Verdict = @import("lookup.zig").Verdict;
const State = @import("lookup.zig").State;

const servers = fixtures.servers_two;
const seed = fixtures.seed;
const sent_cookie = cookie_tests.sent_cookie;
const sent_client = cookie_tests.sent_client;
const truncated_client_only = cookie_tests.truncated_client_only;

test "BADCOOKIE is retried once with the fresh cookie, then over TCP, then the next server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = try sent_client(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    try testing.expectEqual(State.query_ready, harness.lookup.state);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    _ = harness.send();
    const retry = (try sent_cookie(&harness)).?;
    try testing.expectEqualSlices(u8, &fixtures.server_cookie_fresh, retry.server);
    try testing.expectEqualSlices(u8, &first, retry.client);

    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    // Over UDP each BADCOOKIE has somewhere left to go, and is the server up (§19 step 12).
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(0));
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    // The server had its retry over UDP, so a BADCOOKIE over TCP is the server failing it.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expect(!harness.lookup.flags.cookie_retried);
    // Over TCP it is the server failing the lookup, which counts against it.
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try testing.expect(harness.lookup.flags.had_server_failure);
}

/// Connects the harness's lookup, which must want a stream, and sends its query over it.
fn send_on_stream(harness: *fixtures.Harness) !void {
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
}

test "under use_tcp a BADCOOKIE is retried once on the stream with the fresh cookie, then the next server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .use_tcp = true } };
    try harness.start("example.com.", .a, seed);
    try send_on_stream(&harness);
    const number = harness.lookup.transaction.number;
    harness.servers.record_failure(0, 0);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    // "The client SHOULD retry the request using the new Server Cookie" (RFC 7873 §5.3): the
    // same server, a new transaction, and no failure counted, since the retry is left.
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(0));
    try testing.expect(!harness.lookup.flags.had_server_failure);
    try send_on_stream(&harness);
    try testing.expectEqual(number + 1, harness.lookup.transaction.number);
    try testing.expectEqualSlices(u8, &fixtures.server_cookie_fresh, (try sent_cookie(&harness)).?.server);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try testing.expect(harness.lookup.flags.had_server_failure);
}

test "a BADCOOKIE over the TCP a truncated answer led to is retried on the stream, not over UDP" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(truncated_client_only, servers[0].endpoint));
    try send_on_stream(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    try testing.expect(harness.lookup.flags.cookie_retried);
    try send_on_stream(&harness);
    try testing.expectEqualSlices(u8, &fixtures.server_cookie_fresh, (try sent_cookie(&harness)).?.server);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expect(harness.poll() == .done);
}
