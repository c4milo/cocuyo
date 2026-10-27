//! The bound on the queries one server gets for one name over one transport (RFC 9520 §3.1;
//! docs/design.md §5, §16 decision 58), pinned on the lookup alone. Split from `lookup_bound.zig`
//! by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Config = core.Config;
const Name = core.Name;
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const Cause = lookup_module.Cause;
const fixtures = @import("fixtures.zig");
const Harness = fixtures.Harness;
const limits = @import("limits.zig");

const seed = fixtures.seed;
const one_server = fixtures.servers_one;
const two_servers = fixtures.servers_two;

/// A FORMERR that echoes the client cookie and carries the fresh server cookie, so that check 6
/// takes it after a query that carried that cookie.
const format_error_cookie: fixtures.Reply = .{ .rcode = .format_error, .cookie = .echo, .server_cookie = &fixtures.server_cookie_fresh };
/// TC=1 that echoes the client cookie and carries the fresh server cookie.
const truncated_cookie: fixtures.Reply = .{ .truncated = true, .cookie = .echo, .server_cookie = &fixtures.server_cookie_fresh };

/// Lets the wait of the try in flight run out, and returns what the poll at its deadline asks.
fn run_out(harness: *Harness) lookup_module.Action {
    harness.now_ns = harness.lookup.deadline_ns - 1;
    return harness.poll();
}

/// Sends the query over UDP, and lets its wait run out.
fn send_and_run_out(harness: *Harness) lookup_module.Action {
    _ = harness.send();
    return run_out(harness);
}

/// Sends the query over UDP to the current server, and hands the lookup that server's `reply`.
fn ask(harness: *Harness, reply: fixtures.Reply) !void {
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, harness.lookup.server()));
}

/// Connects the lookup, which must want a stream, and sends its query over it.
fn send_on_stream(harness: *Harness) !void {
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
}

fn expect_failure(action: lookup_module.Action, err: core.Error, cause: ?Cause) !void {
    try testing.expectEqual(err, action.failed.err);
    try testing.expectEqual(cause, action.failed.cause);
}

test "one server under five passes gets three queries of a name, and the lookup then ends" {
    // `attempts:5` is accepted, and the bound holds the rule (RFC 9520 §3.1).
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = core.limits.attempts_max } };
    try harness.start("example.com.", .a, seed);
    var queries: usize = 0;
    var action = harness.poll();
    while (action == .send_udp) : (queries += 1) {
        try testing.expect(queries < core.limits.attempts_max);
        action = send_and_run_out(&harness);
    }
    try testing.expectEqual(limits.queries_per_transport_max, queries);
    try expect_failure(action, core.Error.Timeout, null);
    try testing.expectEqual(@as(u8, core.limits.attempts_max), harness.lookup.failure_of().attempts_made);
}

test "under use_tcp one server under five passes gets three queries of a name on a stream" {
    var harness: Harness = .{ .config = .{ .servers = &one_server, .use_tcp = true, .attempts = core.limits.attempts_max } };
    try harness.start("example.com.", .a, seed);
    var queries: usize = 0;
    var action = harness.poll();
    while (action == .connect_tcp) : (queries += 1) {
        try testing.expect(queries < core.limits.attempts_max);
        harness.lookup.on_tcp_connected(harness.now_ns);
        _ = harness.send_over_tcp();
        action = run_out(&harness);
    }
    try testing.expectEqual(limits.queries_per_transport_max, queries);
    try expect_failure(action, core.Error.Timeout, null);
}

test "under the default two passes, a server that had three queries in the first is passed over" {
    // The query, the retry with the fresh server cookie (RFC 7873 §5.3) and the retry without
    // EDNS0 (RFC 6891 §6.2.2) spend the server's three in the first pass.
    var harness: Harness = .{ .config = .{ .servers = &one_server } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.bad_cookie_fresh);
    try ask(&harness, format_error_cookie);
    try testing.expect(!harness.lookup.flags.edns_enabled);
    // Neither reply failed the server, so the end is a timeout.
    try expect_failure(send_and_run_out(&harness), core.Error.Timeout, null);
    try testing.expectEqual(@as(u8, 2), harness.lookup.failure_of().attempts_made);
}

test "a server with no query left is passed over, and the walk goes on to the next and the next pass" {
    var harness: Harness = .{ .config = .{ .servers = &two_servers, .attempts = 3, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.bad_cookie_fresh);
    try ask(&harness, format_error_cookie);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    // The first pass is on the second server, and the second pass passes over the first.
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expectEqual(@as(u8, 1), harness.lookup.round);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expectEqual(@as(u8, 2), harness.lookup.round);
    try expect_failure(send_and_run_out(&harness), core.Error.Timeout, null);
}

test "a FORMERR whose retry the bound forbids fails the server with its rcode" {
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = 3 } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try ask(&harness, fixtures.format_error);
    const cause: Cause = .{ .server_index = 0, .what = .{ .rcode = .format_error } };
    try expect_failure(harness.poll(), core.Error.AllServersFailed, cause);
    // Two tries that ran out, and the FORMERR, each count against the server (§19 step 12).
    try testing.expectEqual(@as(u8, 3), harness.servers.failures(0));
}

test "a BADCOOKIE whose retry over UDP the bound forbids fails the server with its rcode" {
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = 3 } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try ask(&harness, fixtures.bad_cookie_fresh);
    const cause: Cause = .{ .server_index = 0, .what = .{ .rcode = .bad_cookie } };
    try expect_failure(harness.poll(), core.Error.AllServersFailed, cause);
}

test "a BADCOOKIE whose retry on a stream the bound forbids fails the server with its rcode" {
    var harness: Harness = .{ .config = .{ .servers = &one_server, .use_tcp = true, .attempts = 3 } };
    try harness.start("example.com.", .a, seed);
    try send_on_stream(&harness);
    try testing.expect(run_out(&harness) == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expect(run_out(&harness) == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, harness.lookup.server()));
    const cause: Cause = .{ .server_index = 0, .what = .{ .rcode = .bad_cookie } };
    try expect_failure(harness.poll(), core.Error.AllServersFailed, cause);
}

/// Spends three queries on a stream and two over UDP, over two passes of one server: TC=1, then
/// the retry on the stream after BADCOOKIE (RFC 7873 §5.3), then TC=1 again.
fn spend_stream(harness: *Harness) !void {
    try harness.start("example.com.", .a, seed);
    try ask(harness, truncated_cookie);
    try send_on_stream(harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, harness.lookup.server()));
    try send_on_stream(harness);
    try testing.expect(run_out(harness) == .send_udp);
    try ask(harness, truncated_cookie);
    try send_on_stream(harness);
    try testing.expect(run_out(harness) == .send_udp);
    _ = harness.send();
}

test "TC=1 from a server with no query left on a stream moves the lookup on, and keeps no cause" {
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = 3 } };
    try spend_stream(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(truncated_cookie, harness.lookup.server()));
    try expect_failure(harness.poll(), core.Error.Timeout, null);
}

test "a cut datagram from a server with no query left on a stream moves the lookup on" {
    // The third query on the stream answers FORMERR, so the retry without EDNS0 goes over UDP
    // with no COOKIE option, and check 6 takes a cut datagram for it (§7).
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = 3 } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, truncated_cookie);
    try send_on_stream(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, harness.lookup.server()));
    try send_on_stream(&harness);
    try testing.expect(run_out(&harness) == .send_udp);
    try ask(&harness, truncated_cookie);
    try send_on_stream(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(format_error_cookie, harness.lookup.server()));
    _ = harness.send();
    try testing.expect(!harness.lookup.flags.edns_enabled);
    const whole = harness.build(fixtures.answer_a);
    harness.now_ns += 1;
    const verdict = harness.lookup.on_datagram_cut(whole[0 .. whole.len - 1], harness.lookup.server(), harness.now_ns);
    try testing.expectEqual(Verdict.accepted, verdict);
    try expect_failure(harness.poll(), core.Error.Timeout, null);
}

test "the next search candidate is another query, and each server has three queries for it" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: Harness = .{ .config = .{ .servers = &one_server, .search = &search, .ndots = 1, .attempts = 3 } };
    try harness.start("host.example", .a, seed);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try ask(&harness, fixtures.name_error);
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("host.example.one.net")));
    for (0..limits.queries_per_transport_max - 1) |_| try testing.expect(send_and_run_out(&harness) == .send_udp);
    try expect_failure(send_and_run_out(&harness), core.Error.Timeout, null);
}

test "a CNAME's target is another query, and the server that answered has three queries for it" {
    // The target keeps the passes the name left, so five passes leave it three (§5, CNAME policy).
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = core.limits.attempts_max } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try ask(&harness, fixtures.cname_fresh);
    for (0..limits.queries_per_transport_max - 1) |_| try testing.expect(send_and_run_out(&harness) == .send_udp);
    try testing.expectEqual(@as(u8, core.limits.attempts_max - 1), harness.lookup.round);
    try ask(&harness, fixtures.answer_a);
    try testing.expect(harness.poll() == .done);
}

test "a send that failed is no query, and the server keeps the three it has" {
    var harness: Harness = .{ .config = .{ .servers = &one_server, .attempts = core.limits.attempts_max } };
    try harness.start("example.com.", .a, seed);
    for (0..core.limits.attempts_max - limits.queries_per_transport_max) |_| {
        try testing.expect(harness.poll() == .send_udp);
        harness.lookup.on_send_failed(harness.now_ns);
    }
    for (0..limits.queries_per_transport_max - 1) |_| try testing.expect(send_and_run_out(&harness) == .send_udp);
    try expect_failure(send_and_run_out(&harness), core.Error.Timeout, null);
}

test "a second BADCOOKIE over UDP when the datagrams are spent goes on a stream, and keeps no cause" {
    // The retry after the second BADCOOKIE goes over TCP (RFC 7873 §5.3), so the bound reads the
    // stream's count, not the spent datagram's (RFC 9520 §3.1).
    var harness: Harness = .{ .config = .{ .servers = &one_server } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(send_and_run_out(&harness) == .send_udp);
    try ask(&harness, fixtures.bad_cookie_fresh);
    try ask(&harness, fixtures.bad_cookie_fresh);
    try testing.expect(harness.lookup.cause.what == .none);
    try send_on_stream(&harness);
    try expect_failure(run_out(&harness), core.Error.Timeout, null);
}

test "a second BADCOOKIE over UDP when the stream is spent fails the server with its rcode" {
    // Two passes of TC=1, then BADCOOKIE on the stream and its retry there (RFC 7873 §5.3), spend
    // the stream. FORMERR on the third then sends the retry without EDNS0 over UDP (RFC 6891
    // §6.2.2), and BADCOOKIE to it wants a stream that has no query left (RFC 9520 §3.1).
    var harness: Harness = .{ .config = .{ .servers = &one_server } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, truncated_cookie);
    try send_on_stream(&harness);
    try testing.expect(run_out(&harness) == .send_udp);
    try ask(&harness, truncated_cookie);
    try send_on_stream(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.bad_cookie_fresh, harness.lookup.server()));
    try send_on_stream(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(format_error_cookie, harness.lookup.server()));
    try testing.expect(harness.lookup.flags.cookie_retried and !harness.lookup.flags.edns_enabled);
    try ask(&harness, .{ .rcode = .bad_cookie });
    const cause: Cause = .{ .server_index = 0, .what = .{ .rcode = .bad_cookie } };
    try expect_failure(harness.poll(), core.Error.AllServersFailed, cause);
}
