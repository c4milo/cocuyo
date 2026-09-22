//! DNS cookies through the fake server (docs/design.md §19 step 10, RFC 7873): what a query
//! carries, what a response must carry back, what is learned, and what BADCOOKIE does. Split
//! from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const fixtures = @import("fixtures.zig");
const Verdict = @import("lookup.zig").Verdict;
const State = @import("lookup.zig").State;

const servers = fixtures.servers_two;
const seed = fixtures.seed;

fn harness_for() fixtures.Harness {
    return .{ .config = .{ .servers = &servers } };
}

/// The COOKIE option of the query the harness last sent, or null when it carried none.
fn query_cookie(harness: *const fixtures.Harness) !?wire.CookieView {
    const body = harness.query[harness.query_body_offset..harness.query_bytes];
    const cased = harness.lookup.cased_name();
    const opt = (try wire.response_opt.find(body, &cased)) orelse return null;
    return try wire.edns.find_cookie(opt.rdata);
}

test "the first query carries the client cookie alone, and a lookup without EDNS carries none" {
    var harness = harness_for();
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const cookie = (try query_cookie(&harness)).?;
    try testing.expectEqualSlices(u8, &harness.servers.state(0).cookie_client, cookie.client);
    try testing.expectEqual(@as(usize, 0), cookie.server.len);

    var plain = harness_for();
    try plain.start("example.com.", .a, seed);
    plain.lookup.flags.edns_enabled = false;
    _ = plain.send();
    try testing.expectEqual(@as(?wire.CookieView, null), try query_cookie(&plain));
    // A cookie in the answer to a query that sent none is not learned: the server was asked
    // without EDNS, and the next lookup must not expect a cookie it never sent.
    try testing.expectEqual(Verdict.accepted, plain.respond(fixtures.answer_a_cookie, servers[0]));
    try testing.expect(!plain.servers.expecting(0));
}

test "a response echoing the cookie is accepted, its server cookie learned, and the next query carries it" {
    var harness = harness_for();
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expect(!harness.servers.expecting(0));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.cname_only_cookie, servers[0]));
    try testing.expect(harness.servers.expecting(0));
    // The CNAME had no target, so the lookup asks the same server again: with the cookie now.
    _ = harness.send();
    const cookie = (try query_cookie(&harness)).?;
    try testing.expectEqualSlices(u8, &fixtures.server_cookie, cookie.server);
}

test "a wrong client cookie, or a malformed option, is ignored and teaches nothing" {
    var harness = harness_for();
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a_cookie_wrong, servers[0]));
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a_cookie_malformed, servers[0]));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expect(!harness.servers.expecting(0));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0]));
}

test "no cookie is accepted before one is learned, and ignored after" {
    var harness = harness_for();
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_opt_only, servers[0]));

    var learned = harness_for();
    try learned.start("example.com.", .a, seed);
    _ = learned.send();
    try testing.expectEqual(Verdict.accepted, learned.respond(fixtures.cname_only_cookie, servers[0]));
    _ = learned.send();
    try testing.expectEqual(Verdict.ignored, learned.respond(fixtures.answer_a, servers[0]));
    try testing.expectEqual(Verdict.ignored, learned.respond(fixtures.answer_a_opt_only, servers[0]));
    try testing.expectEqual(Verdict.accepted, learned.respond(fixtures.answer_a_cookie, servers[0]));
}

test "BADCOOKIE is retried once with the fresh cookie, then over TCP, then the next server" {
    var harness = harness_for();
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0]));
    try testing.expectEqual(State.query_ready, harness.lookup.state);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    _ = harness.send();
    try testing.expectEqualSlices(u8, &fixtures.server_cookie_fresh, (try query_cookie(&harness)).?.server);

    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0]));
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, servers[0]));
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expect(!harness.lookup.flags.cookie_retried);
}
