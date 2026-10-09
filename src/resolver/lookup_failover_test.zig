//! Failover through the fake server (docs/design.md §19 step 12): what a timeout, a failed send
//! and a failed connection do to the shared table, what each kind of answer does, what a response
//! the lookup ignores does not, and what the next lookup on the same table sees. Split from
//! `lookup_response.zig` by the file-length rule.
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

test "SERVFAIL counts against the server that sent it, and an answer resets the count" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    harness.servers.record_failure(0, 0);
    _ = harness.send();
    // Server 0 failed before, so this lookup started at server 1. Its SERVFAIL is a failure of
    // server 1 at the instant it came, as a timeout is, and the lookup moves to server 0.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[1].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(1));
    try testing.expectEqual(harness.now_ns, harness.servers.state(1).failed_at_ns);
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    const next = harness.send();
    try testing.expect(next.send_udp.server.equal(&servers[0].endpoint));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(0));
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(1));
}

test "a server that answered SERVFAIL is asked last by the next lookup on the same table" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[0].endpoint));
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[1].endpoint));

    try harness.start("other.example.", .a, seed + 1);
    const first = harness.send();
    try testing.expect(first.send_udp.server.equal(&servers[1].endpoint));
}

/// Server 0's count after `reply`, the first answer of a lookup under `config`, when the count
/// stood at one. The order was computed at the send, so the failure leaves server 0 first.
fn count_after(config: core.Config, edns: bool, reply: fixtures.Reply) !u8 {
    var harness: fixtures.Harness = .{ .config = config };
    try harness.start("example.com.", .a, seed);
    harness.lookup.flags.edns_enabled = edns;
    _ = harness.send();
    harness.servers.record_failure(0, 0);
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    if (harness.servers.failures(0) > 1) try testing.expectEqual(harness.now_ns, harness.servers.state(0).failed_at_ns);
    return harness.servers.failures(0);
}

test "an answer that marks the server's failure counts against it, at the instant it came" {
    const config: core.Config = .{ .servers = &servers };
    const bad_vers: fixtures.Reply = .{ .rcode = .bad_vers };
    const failing = [_]fixtures.Reply{ fixtures.server_failure, .{ .rcode = .refused }, .{ .rcode = .not_implemented }, bad_vers };
    for (failing) |reply| try testing.expectEqual(@as(u8, 2), try count_after(config, true, reply));
    // FORMERR from a server asked without EDNS0: the fallback of RFC 6891 §6.2.2 is spent.
    try testing.expectEqual(@as(u8, 2), try count_after(config, false, fixtures.format_error));
}

test "any other answer the lookup accepts resets the count" {
    const config: core.Config = .{ .servers = &servers };
    const reset = [_]fixtures.Reply{
        fixtures.answer_a,   fixtures.no_data,      fixtures.name_error,
        fixtures.truncated,  fixtures.format_error, fixtures.bad_cookie_fresh,
        fixtures.cname_only, fixtures.cname_loop,
    };
    for (reset) |reply| try testing.expectEqual(@as(u8, 0), try count_after(config, true, reply));
    // With `check_response` off, the server's error is the caller's answer (§19 step 11).
    const unchecked: core.Config = .{ .servers = &servers, .check_response = false };
    try testing.expectEqual(@as(u8, 0), try count_after(unchecked, true, fixtures.server_failure));
}

/// An rcode no code of `wire.Rcode` names.
const rcode_unknown = 6;

test "a response the lookup ignores changes nothing of its server's, its cookie included" {
    comptime std.debug.assert(wire.Rcode.from_bits(rcode_unknown) == null);
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    harness.servers.record_failure(0, 0);
    // An address three octets long, in a message whose every length is sound: the answer
    // section is malformed (§16 decision 10).
    const short_address: fixtures.Reply = .{ .records = &fixtures.record_short_a, .ancount = 1, .cookie = .echo, .server_cookie = &fixtures.server_cookie };
    try testing.expectEqual(Verdict.ignored, harness.respond(short_address, servers[0].endpoint));
    const unknown = harness.build(fixtures.answer_a_cookie);
    var header = try wire.header.parse(unknown);
    header.flags |= rcode_unknown;
    wire.header.write(&header, &harness.reply_buffer);
    harness.now_ns += 1;
    try testing.expectEqual(Verdict.ignored, harness.lookup.on_response(unknown, servers[0].endpoint, harness.now_ns));
    try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
    try testing.expect(!harness.servers.expecting(0));
    // The same answer with an rcode cocuyo knows is believed, and teaches both.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(0));
    try testing.expect(harness.servers.expecting(0));
}

test "SERVFAIL moves to the next server and is what the lookup fails with" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .attempts = 1 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[0].endpoint);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[1].endpoint);
    try testing.expectEqual(core.Error.AllServersFailed, harness.poll().failed.err);
}

test "FORMERR asks the same server again without EDNS0, and only once" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.format_error, servers[0].endpoint);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    try testing.expect(!harness.lookup.flags.edns_enabled);
    const action = harness.send();
    const header = try wire.header.parse(action.send_udp.message_bytes);
    try testing.expectEqual(@as(u16, 0), header.arcount);
    _ = harness.respond(fixtures.format_error, servers[0].endpoint);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
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
