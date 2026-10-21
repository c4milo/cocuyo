//! The tests of BADCOOKIE (RFC 7873 §5.3; docs/design.md §5, §19 step 10), through the fake
//! server: `on_bad_cookie` in `lookup_response.zig`, split from it by the file-length rule. The
//! other cookie tests are in `lookup_cookie.zig`, whose helpers these read.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const fixtures = @import("fixtures.zig");
const cookie_tests = @import("lookup_cookie.zig");
const Verdict = @import("lookup.zig").Verdict;
const State = @import("lookup.zig").State;
const Cause = @import("lookup.zig").Cause;

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
    // Over TCP the server fails the lookup: that counts against it, and its rcode is the cause.
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try testing.expectEqual(@as(?Cause, .{ .server_index = 0, .what = .{ .rcode = .bad_cookie } }), harness.lookup.cause.get());
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
    try testing.expectEqual(@as(?Cause, null), harness.lookup.cause.get());
    try send_on_stream(&harness);
    try testing.expectEqual(number + 1, harness.lookup.transaction.number);
    try testing.expectEqualSlices(u8, &fixtures.server_cookie_fresh, (try sent_cookie(&harness)).?.server);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try testing.expectEqual(@as(?Cause, .{ .server_index = 0, .what = .{ .rcode = .bad_cookie } }), harness.lookup.cause.get());
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

test "a server cookie of 32 octets, the longest, is learned and goes out in the next query" {
    // The option is then 4, 8 and 32 octets (RFC 7873 §4): the most its length sums to.
    const longest: [core.constants.cookie_server_bytes_max]u8 = @splat(0x5c);
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.cname_only_cookie;
    reply.server_cookie = &longest;
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    // The CNAME had no target, so the lookup asks the same server again: with the pair now.
    _ = harness.send();
    const cookie = (try sent_cookie(&harness)).?;
    try testing.expectEqualSlices(u8, &longest, cookie.server);
    var answer = fixtures.answer_a_cookie;
    answer.server_cookie = &longest;
    try testing.expectEqual(Verdict.accepted, harness.respond(answer, servers[0].endpoint));
}

test "a server cookie of 8 octets, the shortest, is learned and goes out in the next query" {
    // The option is then 16 octets, the shortest long form (RFC 7873 §4).
    const shortest: [core.constants.cookie_server_bytes_min]u8 = @splat(0x5c);
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.cname_only_cookie;
    reply.server_cookie = &shortest;
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    _ = harness.send();
    try testing.expectEqualSlices(u8, &shortest, (try sent_cookie(&harness)).?.server);
}
