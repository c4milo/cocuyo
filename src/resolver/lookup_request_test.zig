//! A lookup over DoH and over DoQ through the fake server (docs/design.md §22, §23): the query's
//! shape, the answer by transaction, DoH's `Age`, the request that failed, and a stream's reading
//! of TC and BADCOOKIE. Split from `lookup_request.zig` so the fixtures stay out of it.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const Action = lookup_module.Action;
const Verdict = lookup_module.Verdict;
const fixtures = @import("fixtures.zig");

const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
const servers = [_]core.Server{
    .{ .endpoint = fixtures.servers_two[0].endpoint, .https = https },
    .{ .endpoint = fixtures.servers_two[1].endpoint, .https = https },
};
const quic: core.Tls = .{ .name = core.Name.from_text("dns.example.") catch unreachable };
const servers_quic = [_]core.Server{
    .{ .endpoint = fixtures.servers_two[0].endpoint, .quic = quic },
    .{ .endpoint = fixtures.servers_two[1].endpoint, .quic = quic },
};
/// Both kinds of request, for what they do alike.
const both = [_][]const core.Server{ &servers, &servers_quic };
const seed = fixtures.seed;

/// A harness over the two DoH servers, its lookup started for `text`.
fn start(harness: *fixtures.Harness, text: []const u8, kind: core.Kind, lookup_seed: u64) !void {
    try start_over(harness, &servers, text, kind, lookup_seed);
}

/// A harness over `list`, its lookup started for `text`.
fn start_over(harness: *fixtures.Harness, list: []const core.Server, text: []const u8, kind: core.Kind, lookup_seed: u64) !void {
    harness.* = .{ .config = .{ .servers = list } };
    try harness.start(text, kind, lookup_seed);
}

/// Polls, requires a request, remembers its message and tells the lookup it went out. A DoQ
/// message starts after its length prefix (RFC 9250 §4.2).
fn send(harness: *fixtures.Harness) !Action {
    const action = harness.poll();
    try testing.expect(action == .send_request);
    harness.query_bytes = action.send_request.message_bytes.len;
    harness.query_body_offset = if (harness.config.uses_quic()) core.constants.tcp_prefix_bytes else 0;
    harness.lookup.on_sent(harness.now_ns);
    return action;
}

/// Hands `reply` to the lookup as the answer to `transaction`, its id the 0 the query carried.
fn answer(harness: *fixtures.Harness, reply: fixtures.Reply, transaction: u16, age_seconds: u32) Verdict {
    var echoed = reply;
    echoed.id = 0;
    const message = harness.build(echoed);
    harness.now_ns += 1;
    return harness.lookup.on_request_answer(transaction, message, age_seconds, harness.now_ns);
}

test "a query over DoH or DoQ has ID 0, the name as given and no cookie, and is padded to 128" {
    for (both) |list| {
        var harness: fixtures.Harness = undefined;
        try start_over(&harness, list, "Example.COM.", .a, seed);
        const action = try send(&harness);
        const bytes = action.send_request.message_bytes;
        const message = bytes[harness.query_body_offset..];
        // Over DoQ, "a 2-octet length field followed by the message" (RFC 9250 §4.2).
        if (harness.query_body_offset > 0) try testing.expectEqual(message.len, wire.message_len(bytes));
        try testing.expectEqual(@as(u16, 0), (try wire.header.parse(message)).id);
        try testing.expectEqual(@as(u8, 0), action.send_request.server_index);
        try testing.expectEqual(harness.lookup.transaction.number, action.send_request.transaction);
        try expect_shape(&harness, message);
        // Another lookup, from another seed, asks the same question in the same octets, which is
        // what lets an HTTP cache share the answer.
        var other: fixtures.Harness = undefined;
        try start_over(&other, list, "Example.COM.", .a, seed + 1);
        try testing.expectEqualSlices(u8, bytes, (try send(&other)).send_request.message_bytes);
    }
}

/// The name as given, no cookie, and a message padded to a whole block (RFC 8467 §4.1).
fn expect_shape(harness: *const fixtures.Harness, message: []const u8) !void {
    const asked = harness.lookup.current;
    try testing.expectEqualSlices(u8, asked.wire(), message[core.constants.header_bytes..][0..asked.len]);
    const opt = (try wire.response_opt.find(message, &asked)).?;
    try testing.expectEqual(@as(?wire.CookieView, null), try wire.edns.find_cookie(opt.rdata));
    try testing.expectEqual(@as(usize, 0), message.len % core.constants.padding_block_bytes);
}

test "an answer to a transaction the lookup has left is ignored; one to its own is taken" {
    for (both) |list| {
        var harness: fixtures.Harness = undefined;
        try start_over(&harness, list, "example.com.", .a, seed);
        const first = (try send(&harness)).send_request.transaction;
        // The deadline moves the lookup to the second server and a new transaction.
        harness.now_ns = harness.lookup.deadline_ns - 1;
        const second = (try send(&harness)).send_request;
        try testing.expectEqual(@as(u8, 1), second.server_index);
        try testing.expect(second.transaction != first);
        try testing.expectEqual(Verdict.ignored, answer(&harness, fixtures.answer_a, first, 0));
        try testing.expect(harness.poll() == .wait);
        try testing.expectEqual(Verdict.accepted, answer(&harness, fixtures.answer_a, second.transaction, 0));
        try testing.expectEqual(@as(usize, 1), harness.poll().done.addresses.len);
    }
}

test "a datagram is no answer to a lookup over DoH or DoQ, whatever it carries" {
    for (both) |list| {
        var harness: fixtures.Harness = undefined;
        try start_over(&harness, list, "example.com.", .a, seed);
        _ = try send(&harness);
        try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, list[0].endpoint));
        try testing.expect(harness.poll() == .wait);
    }
}

test "an Age of 250 turns a TTL of 600 into 350, and an Age past the TTL into 0" {
    const reply = fixtures.answer_a_600;
    const cases = [_][2]u32{ .{ 250, 350 }, .{ 700, 0 }, .{ 0, 600 } };
    for (cases) |case| {
        var harness: fixtures.Harness = undefined;
        try start(&harness, "example.com.", .a, seed);
        const transaction = (try send(&harness)).send_request.transaction;
        try testing.expectEqual(Verdict.accepted, answer(&harness, reply, transaction, case[0]));
        try testing.expectEqual(case[1], harness.poll().done.ttl_seconds);
    }
}

test "the Age lowers a kept record's TTL, and a negative answer's" {
    var harness: fixtures.Harness = undefined;
    try start(&harness, "example.com.", .mx, seed);
    var transaction = (try send(&harness)).send_request.transaction;
    _ = answer(&harness, fixtures.answer_mx, transaction, 100);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u32, 200), done.ttl_seconds);
    try testing.expectEqual(@as(u32, 200), done.records.?.at(0).ttl_seconds);

    try start(&harness, "example.com.", .a, seed);
    transaction = (try send(&harness)).send_request.transaction;
    _ = answer(&harness, fixtures.name_error_soa, transaction, 25);
    try testing.expectEqual(@as(u32, 35), harness.poll().failed.negative_ttl_seconds);
    try start(&harness, "example.com.", .a, seed);
    transaction = (try send(&harness)).send_request.transaction;
    _ = answer(&harness, fixtures.no_data_soa, transaction, 25);
    try testing.expectEqual(@as(u32, 35), harness.poll().failed.negative_ttl_seconds);
}

test "each message of a chain over DoH loses its own Age before the chain bounds the answer" {
    // The alias, 20 aged 5, is 15; the A record, 600 aged 100, is 500. Aging the bounded answer
    // instead would take the 15 to 0.
    var harness: fixtures.Harness = undefined;
    try start(&harness, "example.com.", .a, seed);
    var transaction = (try send(&harness)).send_request.transaction;
    try testing.expectEqual(Verdict.accepted, answer(&harness, fixtures.cname_short, transaction, 5));
    transaction = (try send(&harness)).send_request.transaction;
    try testing.expectEqual(Verdict.accepted, answer(&harness, fixtures.answer_a_600, transaction, 100));
    try testing.expectEqual(@as(u32, 15), harness.poll().done.ttl_seconds);
}

test "a request that failed moves the lookup to the next server and counts one failure" {
    for (both) |list| {
        var harness: fixtures.Harness = undefined;
        try start_over(&harness, list, "example.com.", .a, seed);
        const transaction = (try send(&harness)).send_request.transaction;
        // A failure for a transaction the lookup is not on is nobody's.
        harness.lookup.on_request_failed(transaction +% 1, harness.now_ns);
        try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
        harness.lookup.on_request_failed(transaction, harness.now_ns);
        try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
        try testing.expectEqual(@as(u8, 1), harness.servers.failures(0));
        try testing.expectEqual(@as(u8, 1), (try send(&harness)).send_request.server_index);
    }
}

test "over DoH or DoQ a truncated answer is read as it stands, and BADCOOKIE fails the server" {
    const bad_cookie: fixtures.Reply = .{ .rcode = .bad_cookie, .cookie = .opt_only };
    for (both) |list| {
        var harness: fixtures.Harness = undefined;
        try start_over(&harness, list, "example.com.", .a, seed);
        var transaction = (try send(&harness)).send_request.transaction;
        try testing.expectEqual(Verdict.accepted, answer(&harness, fixtures.answer_a_truncated, transaction, 0));
        try testing.expectEqual(@as(usize, 1), harness.poll().done.addresses.len);

        try start_over(&harness, list, "example.com.", .a, seed);
        transaction = (try send(&harness)).send_request.transaction;
        try testing.expectEqual(Verdict.accepted, answer(&harness, bad_cookie, transaction, 0));
        try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
        try testing.expect(harness.lookup.flags.had_server_failure);
    }
}
