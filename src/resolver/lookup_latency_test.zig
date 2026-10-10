//! A server's wait from its measured latency, through the lookup (docs/design.md §5, retry and
//! timeout policy): which responses are samples, on each transport, and the waits the samples
//! give. The windows themselves are `servers_latency.zig`'s to test; this is the lookup's half,
//! where a sample is taken (`lookup_response.zig`) and where a deadline is armed
//! (`lookup_poll.zig`).
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const State = lookup_module.State;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

/// A millisecond and a second, in nanoseconds.
const millisecond = 1_000_000;
const second = 1_000_000_000;

/// Starts a lookup on `harness`, sends its query over UDP, answers it `latency_ns` later from the
/// first server, and returns the wait the send armed.
fn answered_after(harness: *fixtures.Harness, latency_ns: u64) !u64 {
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const wait = harness.lookup.deadline_ns - harness.now_ns;
    // `respond` moves the clock one nanosecond itself.
    harness.now_ns += latency_ns - 1;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expect(harness.poll() == .done);
    return wait;
}

test "a server waits the configured wait until its third sample, then five times its average" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try testing.expectEqual(@as(u64, 2 * second), try answered_after(&harness, 100 * millisecond));
    try testing.expectEqual(@as(u64, 2 * second), try answered_after(&harness, 200 * millisecond));
    try testing.expectEqual(@as(u64, 2 * second), try answered_after(&harness, 300 * millisecond));
    try testing.expectEqual(@as(u64, 3), harness.servers.samples(0));
    // An average of 200 ms, five times over.
    try testing.expectEqual(@as(u64, 1 * second), try answered_after(&harness, 200 * millisecond));
    // A lookup the first server leaves unanswered moves to the second, which has no sample, and
    // waits the configured wait there rather than the first server's.
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(@as(u64, 1 * second), harness.lookup.deadline_ns - harness.now_ns);
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(@as(u64, 0), harness.servers.samples(1));
    try testing.expectEqual(@as(u64, 2 * second), harness.lookup.deadline_ns - harness.now_ns);
}

test "a measured server's wait doubles per pass, up to the cap" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one, .attempts = 3 } };
    for (0..3) |_| _ = try answered_after(&harness, 300 * millisecond);
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(@as(u64, 1_500 * millisecond), harness.lookup.deadline_ns - harness.now_ns);
    // The wait runs out: the next pass at the same server waits twice as long.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u8, 1), harness.lookup.round);
    try testing.expectEqual(@as(u64, 3 * second), harness.lookup.deadline_ns - harness.now_ns);
    // And the pass after that would wait six seconds, past the five-second cap.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u64, 5 * second), harness.lookup.deadline_ns - harness.now_ns);
}

test "a response the lookup ignores takes no sample, matched or not" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    // Another transaction's id fails §7's checks; a malformed answer section passes them and is
    // ignored all the same (§16 decision 10).
    var stray = fixtures.answer_a;
    stray.id = harness.lookup.transaction.id ^ 1;
    try testing.expectEqual(Verdict.ignored, harness.respond(stray, servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.long_rdlength, servers[0].endpoint));
    try testing.expectEqual(@as(u64, 0), harness.servers.samples(0));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(@as(u64, 1), harness.servers.samples(0));
}

test "an answer is measured from its own transaction's send, not an earlier one's" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first_id = harness.lookup.transaction.id;
    // The first server is silent; the query goes again, to the second, as a new transaction.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    const sent_ns = harness.now_ns;
    // The first transaction's answer, late, is no answer to the second.
    var late = fixtures.answer_a;
    late.id = first_id;
    try testing.expectEqual(Verdict.ignored, harness.respond(late, servers[0].endpoint));
    harness.now_ns += 30 * millisecond;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[1].endpoint));
    try testing.expectEqual(@as(u64, 0), harness.servers.samples(0));
    try testing.expectEqual(@as(u64, 1), harness.servers.samples(1));
    try testing.expectEqual(harness.now_ns - sent_ns, harness.servers.state(1).latency.windows[0].sum_ns);
}

test "a truncated answer and the TCP answer after it are a sample each, TCP's from its own send" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    harness.now_ns += 20 * millisecond;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expect(harness.poll() == .connect_tcp);
    // The connection takes 50 ms, which no sample counts.
    harness.now_ns += 50 * millisecond;
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    harness.now_ns += 10 * millisecond;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expect(harness.poll() == .done);
    try testing.expectEqual(@as(u64, 2), harness.servers.samples(0));
    // Each sample is the time to its answer, plus the nanosecond `respond` moves the clock.
    try testing.expectEqual(@as(u64, 30 * millisecond + 2), harness.servers.state(0).latency.windows[0].sum_ns);
}

test "an answer over TLS is a sample, measured once the connection is up" {
    const tls: core.Tls = .{ .name = try core.Name.from_text("dns.example.") };
    const encrypted = [_]core.Server{
        .{ .endpoint = servers[0].endpoint, .tls = tls },
        .{ .endpoint = servers[1].endpoint, .tls = tls },
    };
    var harness: fixtures.Harness = .{ .config = .{ .servers = &encrypted } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.now_ns += 80 * millisecond;
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    harness.now_ns += 15 * millisecond;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, encrypted[0].tcp_endpoint()));
    try testing.expectEqual(@as(u64, 1), harness.servers.samples(0));
    try testing.expectEqual(@as(u64, 15 * millisecond + 1), harness.servers.state(0).latency.windows[0].sum_ns);
}

test "an answer to a DoH or DoQ request is a sample, and a failed request is none" {
    const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    const quic: core.Tls = .{ .name = try core.Name.from_text("dns.example.") };
    const over_https = [_]core.Server{ .{ .endpoint = servers[0].endpoint, .https = https }, .{ .endpoint = servers[1].endpoint, .https = https } };
    const over_quic = [_]core.Server{ .{ .endpoint = servers[0].endpoint, .quic = quic }, .{ .endpoint = servers[1].endpoint, .quic = quic } };
    for ([_][]const core.Server{ &over_https, &over_quic }) |list| {
        var harness: fixtures.Harness = .{ .config = .{ .servers = list, .failover_retry_chance = 0 } };
        try harness.start("example.com.", .a, seed);
        // The first request fails: the server failed it, and no answer came to measure.
        try send_request(&harness);
        harness.lookup.on_request_failed(harness.lookup.transaction.number, harness.now_ns);
        try testing.expectEqual(@as(u64, 0), harness.servers.samples(0));
        // The second, to the next server, is answered 40 ms after it went.
        try send_request(&harness);
        harness.now_ns += 40 * millisecond;
        try testing.expectEqual(Verdict.accepted, answer_request(&harness));
        try testing.expectEqual(@as(u64, 1), harness.servers.samples(1));
        try testing.expectEqual(@as(u64, 40 * millisecond + 1), harness.servers.state(1).latency.windows[0].sum_ns);
    }
}

/// Polls, requires a request, remembers its message and tells the lookup it went out. A DoQ
/// message starts after its length prefix (RFC 9250 §4.2).
fn send_request(harness: *fixtures.Harness) !void {
    const action = harness.poll();
    try testing.expect(action == .send_request);
    harness.query_bytes = action.send_request.message_bytes.len;
    harness.query_body_offset = if (harness.config.uses_quic()) core.constants.tcp_prefix_bytes else 0;
    harness.lookup.on_sent(harness.now_ns);
}

/// Answers the current transaction with one A record and the ID of 0 its query carried.
fn answer_request(harness: *fixtures.Harness) Verdict {
    var reply = fixtures.answer_a;
    reply.id = 0;
    const message = harness.build(reply);
    harness.now_ns += 1;
    return harness.lookup.on_request_answer(harness.lookup.transaction.number, message, 0, harness.now_ns);
}

test "a send that failed takes no sample" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(harness.poll() == .send_udp);
    harness.lookup.on_send_failed(harness.now_ns);
    try testing.expectEqual(State.query_ready, harness.lookup.state);
    try testing.expectEqual(@as(u64, 0), harness.servers.samples(0));
}
