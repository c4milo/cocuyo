//! Tests of `on_response` (`lookup_response.zig`). Split from it by the file-length rule.
const std = @import("std");
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const Endpoint = core.Endpoint;

// Tests. The fake server of fixtures.zig echoes whatever the lookup asked, so these run with
// DNS-0x20 on, which is what a caller gets by default.

const testing = std.testing;
const Address = core.Address;
const Name = core.Name;
const Kind = core.Kind;
const Question = core.Question;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

test "a response that matches is accepted and answers the lookup" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    const action = harness.poll();
    try testing.expectEqual(@as(usize, 1), action.done.addresses.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, action.done.addresses[0].slice());
    try testing.expectEqual(@as(u32, 300), action.done.ttl_seconds);
    try testing.expectEqual(@as(?*const Name, null), action.done.canonical_name);
    try testing.expect(!action.done.truncated);
}

test "a response with the wrong id is ignored and the wait stands" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.id = harness.lookup.transaction.id ^ 0xffff;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0].endpoint));
    try testing.expect(harness.poll() == .wait);
}

test "a response from another server, or another port, is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, servers[1].endpoint));
    const wrong_port: Endpoint = .{ .address = servers[0].endpoint.address, .port = fixtures.port_other };
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, wrong_port));
    try testing.expect(harness.poll() == .wait);
}

test "a truncated response sends the lookup to TCP" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expect(harness.poll() == .connect_tcp);
}

test "a record for a name nobody asked about is not part of the answer" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.injected, servers[0].endpoint);
    const action = harness.poll();
    try testing.expectEqual(@as(usize, 1), action.done.addresses.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, action.done.addresses[0].slice());
}

test "a malformed answer section is ignored and leaves the name alone" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.current;
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.long_rdlength, servers[0].endpoint));
    try testing.expectEqualSlices(u8, before.wire(), harness.lookup.current.wire());
    try testing.expect(harness.poll() == .wait);
}

test "an address of the wrong length is ignored, though every length in the message is sound" {
    // The scan for the OPT record walks the sections by their lengths and lets this through; the
    // answer's collection refuses it, and a malformed answer is ignored (§16 decision 10).
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.current;
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.short_address, servers[0].endpoint));
    try testing.expectEqualSlices(u8, before.wire(), harness.lookup.current.wire());
    try testing.expect(harness.poll() == .wait);
}

test "a response arriving after the lookup settled is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expect(harness.poll() == .done);
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, servers[0].endpoint));
}

test "a flood of unmatched datagrams neither extends nor shortens the wait" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const deadline = harness.lookup.deadline_ns;
    var reply = fixtures.answer_a;
    var sent: u16 = 0;
    while (sent < 64) : (sent += 1) {
        reply.id = harness.lookup.transaction.id ^ (sent + 1);
        try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0].endpoint));
        try testing.expectEqual(deadline, harness.lookup.deadline_ns);
    }
    try testing.expectEqual(deadline, harness.poll().wait);
}

test "a truncated response over TCP is read, marked truncated, and not a reason to connect again" {
    // A stream's limit is 65535 octets (RFC 9250 §4.6), so there is no larger channel to ask over.
    // A lookup that obeyed the bit would connect again and again to the same server.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.truncated, servers[0].endpoint);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expectEqual(lookup_module.State.awaiting_tcp, harness.lookup.state);

    var reply = fixtures.truncated;
    reply.records = fixtures.answer_a.records;
    reply.ancount = fixtures.answer_a.ancount;
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    // The answer is read rather than the bit obeyed, so the lookup finishes here. Records may be
    // missing from it all the same, so it is marked, and no cache keeps it (RFC 1035 §7.4).
    try testing.expect(harness.poll().done.truncated);
}

test "a message of 65535 octets is read, and one of 65536 is ignored at check 1" {
    // The longest message a length prefix describes (RFC 1035 §4.2.2). The answer sits at the
    // front, and the codec reads nothing after the last record the counts name.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var message: [core.limits.message_bytes_max + 1]u8 = @splat(0);
    const reply = harness.build(fixtures.answer_a);
    @memcpy(message[0..reply.len], reply);
    try testing.expectEqual(Verdict.ignored, harness.lookup.on_response(&message, servers[0].endpoint, harness.now_ns));
    try testing.expect(harness.poll() == .wait);
    const longest = message[0..core.limits.message_bytes_max];
    try testing.expectEqual(Verdict.accepted, harness.lookup.on_response(longest, servers[0].endpoint, harness.now_ns));
    try testing.expect(harness.poll() == .done);
}
