//! A server's wait from its measured latency, through the lookup (docs/design.md §5, retry and
//! timeout policy): which responses and which tries that ran out are samples, on each transport,
//! and the waits the samples give. The windows themselves are `servers_latency.zig`'s to test;
//! this is the lookup's half, where a sample is taken (`lookup_response.zig` for a response,
//! `lookup_poll.zig` for a try that ran out) and where a deadline is armed (`lookup_poll.zig`).
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const State = lookup_module.State;
const fixtures = @import("fixtures.zig");
const constants = @import("constants.zig");

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
    var harness: fixtures.Harness = .{ .config = .{
        .servers = &fixtures.servers_one,
        .attempts = 3,
        .timeout_ns_max = core.constants.timeout_ns_max,
    } };
    for (0..3) |_| _ = try answered_after(&harness, 300 * millisecond);
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(@as(u64, 1_500 * millisecond), harness.lookup.deadline_ns - harness.now_ns);
    // The wait runs out, a sample of 1.5 seconds that makes the average 600 ms: the next pass at
    // the same server waits five times that, doubled.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u8, 1), harness.lookup.round);
    try testing.expectEqual(@as(u64, 6 * second), harness.lookup.deadline_ns - harness.now_ns);
    // That runs out too, a sample of 6 seconds that makes the average 1.68 seconds: the pass after
    // it would wait 8.4 seconds doubled twice, 33.6, past the 30-second cap.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(core.constants.timeout_ns_max, harness.lookup.deadline_ns - harness.now_ns);
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
    // The first server's silent try is one sample as long as its wait, and the late answer adds
    // none.
    try expect_samples(&harness, 0, 1, 2 * second);
    try expect_samples(&harness, 1, 1, harness.now_ns - sent_ns);
}

/// Requires server `slot` to hold `count` samples since the table was built, and the minute's
/// window, which holds every sample of a test this short, to sum to `sum_ns`.
fn expect_samples(harness: *const fixtures.Harness, slot: usize, count: u64, sum_ns: u64) !void {
    try testing.expectEqual(count, harness.servers.samples(slot));
    try testing.expectEqual(sum_ns, harness.servers.state(slot).latency.windows[0].sum_ns);
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

test "a try that ran out is one sample as long as its wait, on its own server, a later pass's doubled" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    // The first server is silent, and the poll that finds its deadline passed comes 7 ms late: the
    // sample is the wait, from the send to the deadline, and not the time to that poll.
    harness.now_ns = harness.lookup.deadline_ns + 7 * millisecond - 1;
    _ = harness.send();
    try expect_samples(&harness, 0, 1, 2 * second);
    try expect_samples(&harness, 1, 0, 0);
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    // The second server is silent too. The first, on the second pass, waits the configured
    // 2 seconds doubled, since 1 sample is too few to read, and its sample is the 4 seconds.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try expect_samples(&harness, 1, 1, 2 * second);
    try testing.expectEqual(@as(u8, 1), harness.lookup.round);
    try testing.expectEqual(@as(u64, 4 * second), harness.lookup.deadline_ns - harness.now_ns);
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try expect_samples(&harness, 0, 2, 6 * second);
    // The last try runs out, and the lookup with it.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    try testing.expectEqual(core.Error.Timeout, harness.poll().failed.err);
    try expect_samples(&harness, 1, 2, 6 * second);
}

test "a try over TLS that ran out is a sample, and a connect that ran out is none" {
    const tls: core.Tls = .{ .name = try core.Name.from_text("dns.example.") };
    const encrypted = [_]core.Server{
        .{ .endpoint = servers[0].endpoint, .tls = tls },
        .{ .endpoint = servers[1].endpoint, .tls = tls },
    };
    var harness: fixtures.Harness = .{ .config = .{ .servers = &encrypted, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    // The connection to the first server never comes up. No query went out, so the server counts
    // a failure and no sample.
    try testing.expect(harness.poll() == .connect_tcp);
    harness.now_ns = harness.lookup.deadline_ns - 1;
    try testing.expect(harness.poll() == .connect_tcp);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try expect_samples(&harness, 0, 0, 0);
    // The second's comes up, and the query sent on it waits out its 2 seconds: one sample.
    harness.now_ns += 80 * millisecond;
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    harness.now_ns = harness.lookup.deadline_ns - 1;
    try testing.expect(harness.poll() == .connect_tcp);
    try expect_samples(&harness, 1, 1, 2 * second);
}

test "a DoH or DoQ request that ran out is a sample as long as its wait" {
    const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    const quic: core.Tls = .{ .name = try core.Name.from_text("dns.example.") };
    const over_https = [_]core.Server{.{ .endpoint = servers[0].endpoint, .https = https }};
    const over_quic = [_]core.Server{.{ .endpoint = servers[0].endpoint, .quic = quic }};
    for ([_][]const core.Server{ &over_https, &over_quic }) |list| {
        var harness: fixtures.Harness = .{ .config = .{ .servers = list } };
        try harness.start("example.com.", .a, seed);
        try send_request(&harness);
        harness.now_ns = harness.lookup.deadline_ns - 1;
        try testing.expect(harness.poll() == .send_request);
        try expect_samples(&harness, 0, 1, 2 * second);
    }
}

test "a connection that failed and a lookup cancelled take no sample" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    // A truncated answer is a sample. The connection it asks for comes up and fails after the
    // query went out on it: the server refused the lookup, and no wait for an answer was measured.
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    harness.now_ns += 40 * millisecond;
    harness.lookup.on_tcp_failed(harness.now_ns);
    try testing.expectEqual(@as(u64, 1), harness.servers.samples(0));
    // The query to the second server goes out, and the lookup is cancelled while it waits. Its
    // deadline passes with nothing to measure.
    _ = harness.send();
    harness.lookup.cancel();
    harness.now_ns = harness.lookup.deadline_ns;
    try testing.expectEqual(core.Error.Canceled, harness.poll().failed.err);
    try testing.expectEqual(@as(u64, 0), harness.servers.samples(1));
}

/// A server that has slowed past the floor's wait: it answers each query 600 ms after it went.
const slowed_ns = 600_000_000;
/// A server that never answers.
const never_ns = std.math.maxInt(u64);

/// How one lookup of `run_lookup` went.
const Run = struct {
    answered: bool,
    /// The tries it took to be answered, or every try it had.
    tries: usize,
    /// The wait its first try armed.
    first_wait_ns: u64,
};

/// Runs one lookup over UDP on `harness`, whose servers each answer a query `latency_ns` after it
/// went out. A try whose wait is no longer than that runs out first. The answer that comes after
/// it answers a transaction the lookup has left, so this does not deliver it.
fn run_lookup(harness: *fixtures.Harness, latency_ns: u64) !Run {
    try harness.start("example.com.", .a, seed);
    const tries_max = @as(usize, harness.config.attempts) * harness.config.servers.len;
    var run: Run = .{ .answered = false, .tries = tries_max, .first_wait_ns = 0 };
    for (0..tries_max) |index| {
        _ = harness.send();
        const wait = harness.lookup.deadline_ns - harness.now_ns;
        if (index == 0) run.first_wait_ns = wait;
        if (wait > latency_ns) {
            harness.now_ns += latency_ns - 1;
            try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, harness.lookup.server()));
            try testing.expect(harness.poll() == .done);
            run.answered = true;
            run.tries = index + 1;
            return run;
        }
        harness.now_ns = harness.lookup.deadline_ns - 1;
    }
    try testing.expectEqual(core.Error.Timeout, harness.poll().failed.err);
    return run;
}

test "a server that slows from 50 ms to 600 ms, past its wait, answers the first lookup after" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    // A record of 3 answers in 50 ms: a wait of 250 ms, the floor.
    for (0..3) |_| try testing.expect((try run_lookup(&harness, 50 * millisecond)).answered);
    // The first try runs out at 250 ms, a sample that makes the average 100 ms, so the second
    // pass waits 500 ms doubled, 1 second, and the answer comes in it. The average is then
    // 200 ms, and the next lookup waits 1 second from its first try.
    const first = try run_lookup(&harness, slowed_ns);
    try testing.expectEqual(Run{ .answered = true, .tries = 2, .first_wait_ns = 250 * millisecond }, first);
    const next = try run_lookup(&harness, slowed_ns);
    try testing.expectEqual(Run{ .answered = true, .tries = 1, .first_wait_ns = 1 * second }, next);
    try testing.expectEqual(@as(u64, 6), harness.servers.samples(0));
}

test "against a record of 100 answers in 50 ms, two lookups at 600 ms time out, and no more" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    for (0..100) |_| try testing.expect((try run_lookup(&harness, 50 * millisecond)).answered);
    // Each silent try moves an average of 100 samples less than one of 3. The first two lookups
    // end in `Timeout`, and from the third on every one is answered: on its second try until the
    // tenth, and on its first from the eleventh, whose first wait has passed 600 ms.
    for (1..15) |number| {
        const run = try run_lookup(&harness, slowed_ns);
        try testing.expectEqual(number >= 3, run.answered);
        try testing.expectEqual(@as(usize, if (number >= 11) 1 else 2), run.tries);
        try testing.expectEqual(number >= 11, run.first_wait_ns > slowed_ns);
    }
}

test "a server that never answers has its wait rise from the floor to the cap, and stay there" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    for (0..3) |_| try testing.expect((try run_lookup(&harness, 50 * millisecond)).answered);
    // Every lookup ends in `Timeout`. Its first try waits 250 ms, then 1.4 seconds, then the
    // 5-second cap, and stays there: no sample is longer than the cap, and five times an average
    // of a second or more is the cap. Past a minute the minute's window starts again, and the
    // fifteen minutes' holds the record.
    const waits = [_]u64{ 250 * millisecond, 1_400 * millisecond };
    for (0..12) |index| {
        const run = try run_lookup(&harness, never_ns);
        try testing.expect(!run.answered);
        const wait = if (index < waits.len) waits[index] else harness.config.timeout_ns_max;
        try testing.expectEqual(wait, run.first_wait_ns);
    }
    try testing.expectEqual(@as(u64, 3 + 12 * 2), harness.servers.samples(0));
    try testing.expect(harness.now_ns > constants.latency_window_minute_ns);
}

test "a datagram lost on a fast path raises its server's wait from the floor" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    // Three answers in 20 ms: five times their average is under the floor, so the wait is 250 ms.
    for (0..3) |_| try testing.expect((try run_lookup(&harness, 20 * millisecond)).answered);
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(@as(u64, 250 * millisecond), harness.lookup.deadline_ns - harness.now_ns);
    // The query is lost, a sample of 250 ms that makes the average 77.5 ms: the second pass waits
    // five times that, 387.5 ms, doubled.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u64, 775 * millisecond), harness.lookup.deadline_ns - harness.now_ns);
}

test "a record no minute of tries outweighs holds a slowed server back until its minute restarts" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    // A thousand answers in 1 ms. A minute of tries that run out at 600 ms adds about 160 samples
    // of 250 ms to 520 ms, which leaves the average under 60 ms, where the second pass's wait,
    // doubled, would reach 600 ms.
    for (0..1000) |_| try testing.expect((try run_lookup(&harness, 1 * millisecond)).answered);
    const record = harness.servers.state(0).latency.windows[0];
    // So the first 80 lookups at 600 ms end in `Timeout`. The minute's window starts again at the
    // 79th's second try, a minute after the record's first answer, and the 80th's two tries
    // bring it to 3 samples.
    for (0..80) |_| try testing.expect(!(try run_lookup(&harness, slowed_ns)).answered);
    const minute = harness.servers.state(0).latency.windows[0];
    try testing.expect(minute.start_ns >= record.start_ns + constants.latency_window_minute_ns);
    try testing.expectEqual(@as(u64, 3), minute.count);
    // From then on every lookup is answered. While the minute's window holds 3 samples the wait
    // reads only those and what came after, each 250 ms or more, so it is over a second and the
    // first try is answered. When that window starts again a minute later, the wait reads the
    // fifteen minutes' until it holds 3 again, and that window still holds the record: one
    // lookup's first try runs out there, and its second is answered.
    var second_tries: usize = 0;
    for (0..120) |_| {
        const run = try run_lookup(&harness, slowed_ns);
        try testing.expect(run.answered);
        second_tries += run.tries - 1;
    }
    try testing.expectEqual(@as(usize, 1), second_tries);
}
