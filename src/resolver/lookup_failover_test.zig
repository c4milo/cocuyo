//! Failover through the fake server (docs/design.md §19 step 12): what a timeout, a failed send
//! and a failed connection do to the shared table, what an answer does, and what the next
//! lookup on the same table sees. Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const fixtures = @import("fixtures.zig");
const Verdict = @import("lookup.zig").Verdict;

const servers = fixtures.servers_two;
const seed = fixtures.seed;

test "a server that timed out is asked last by the next lookup on the same table" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    harness.now_ns += harness.config.timeout_ns;
    const moved = harness.poll();
    try testing.expect(moved.send_udp.server.equal(&servers[1].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    // The order holds for the lookup: another poll does not recompute it around the failure,
    // so server 1's answer is still this lookup's.
    harness.lookup.on_sent(harness.now_ns);
    try testing.expect(harness.poll() == .wait);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[1].endpoint));

    try harness.start("other.example.", .a, seed + 1);
    const first = harness.send();
    try testing.expect(first.send_udp.server.equal(&servers[1].endpoint));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[1].endpoint));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(1));
}

test "an answer of any kind resets a server's failures" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    harness.servers.record_failure(0, 0);
    _ = harness.send();
    // Server 0 failed before, so this lookup started at server 1; its SERVFAIL is still an
    // answer, and server 1 stays at zero while the lookup moves to server 0.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[1].endpoint));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(1));
    const next = harness.send();
    try testing.expect(next.send_udp.server.equal(&servers[0].endpoint));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(0));
}

test "a failed send and a failed connection are failures of the server they were for" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.poll();
    harness.lookup.on_send_failed(harness.now_ns);
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(1));

    var over_tcp: fixtures.Harness = .{ .config = .{ .servers = &servers, .use_tcp = true, .failover_retry_chance = 0 } };
    try over_tcp.start("example.com.", .a, seed);
    _ = over_tcp.poll();
    over_tcp.lookup.on_tcp_failed(over_tcp.now_ns);
    try testing.expectEqual(@as(u8, 1), over_tcp.servers.failures(0));
}

test "a lookup a server refused ends in AllServersFailed, and one none answered in Timeout" {
    // A refused connection is the server failing the lookup, as SERVFAIL is; silence is not
    // (docs/design.md §16 decision 25).
    const config: core.Config = .{ .servers = &servers, .use_tcp = true, .attempts = 1, .failover_retry_chance = 0 };
    var refused: fixtures.Harness = .{ .config = config };
    try refused.start("example.com.", .a, seed);
    try testing.expect(refused.poll() == .connect_tcp);
    refused.lookup.on_tcp_failed(refused.now_ns);
    try testing.expect(refused.poll() == .connect_tcp);
    refused.now_ns += config.timeout_ns;
    try testing.expectEqual(core.Error.AllServersFailed, refused.poll().failed.err);

    var silent: fixtures.Harness = .{ .config = config };
    try silent.start("example.com.", .a, seed);
    try testing.expect(silent.poll() == .connect_tcp);
    silent.now_ns += config.timeout_ns;
    try testing.expect(silent.poll() == .connect_tcp);
    silent.now_ns += config.timeout_ns;
    try testing.expectEqual(core.Error.Timeout, silent.poll().failed.err);
}

test "the failure a lookup reports names the configured server it was on" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .check_response = false, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    harness.servers.record_failure(0, 0);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[1].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.poll().failed.server_index);
}

test "a server that answered FORMERR loses EDNS0 for itself, and the next server has it back" {
    // That a server does not speak EDNS0 is a fact about that server (RFC 6891 §6.2.2): the next
    // one is asked with the OPT record, cookie and all.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.format_error, harness.lookup.server()));
    const retried = harness.send();
    try testing.expectEqual(@as(u16, 0), (try wire.header.parse(retried.send_udp.message_bytes)).arcount);
    harness.now_ns += harness.config.timeout_ns;
    const moved = harness.poll();
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expectEqual(@as(u16, 1), (try wire.header.parse(moved.send_udp.message_bytes)).arcount);
}
