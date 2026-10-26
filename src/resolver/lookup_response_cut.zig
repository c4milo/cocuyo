//! `on_datagram_cut`: a datagram longer than the caller's buffer, which arrives cut (docs/design.md
//! §7, A datagram that the buffer cut; §16 decision 43). No RFC states this rule. The kernel keeps
//! the octets that fit, marks the datagram as truncated, and rotor gives the mark as
//! `Received.flags.truncated`. The rule is the owner's ruling of 2026-10-14 on §17 question 40.
//!
//! The header and the question come first in a message, so checks 1 to 5 of §7 read them as they
//! read any datagram. The OPT record is in the last section, and the cut took the end. So check 6
//! reads the datagram as a message with no COOKIE option, as it reads an answer with TC set and no
//! OPT record. A cut datagram that passes these checks sends its lookup to TCP, as such an answer
//! does. It tells the server's state nothing. Each other cut datagram is ignored, and the wait
//! stands (§16 decision 10).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Endpoint = core.Endpoint;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Verdict = lookup_module.Verdict;
const response = @import("lookup_response.zig");
const casing = @import("lookup_response_case.zig");
const cookies = @import("lookup_cookie.zig");

pub fn on_datagram_cut(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
    self.see(now_ns);
    if (!takes_cut(self)) return .ignored;
    if (!matches(self, message, from)) return .ignored;
    assert(self.state == .awaiting_udp);
    // The same server, over TCP. RFC 7766 §5 lets a stub ask over TCP "depending on local
    // operational reasons", and a buffer too short for the answer is one. No sample, no success
    // and no cookie: check 6 did not read a whole message.
    self.state = .tcp_needed;
    return .accepted;
}

/// Whether the lookup reads a cut datagram at all: it waits over UDP, and the caller has not asked
/// to read a truncated answer in place of TCP.
fn takes_cut(self: *const Lookup) bool {
    if (self.state != .awaiting_udp) return false;
    // A lookup that waits over UDP sent its query, and has a deadline.
    assert(self.is_waiting());
    assert(self.sent_at_ns <= self.now_ns_seen);
    // Over DoH or DoQ an answer comes by its transaction, and never as a datagram
    // (docs/design.md §22, §23).
    if (self.config.sends_requests()) return false;
    // `ignore_truncation` reads a truncated answer as it is, and the cut left no whole message.
    return !self.config.ignore_truncation;
}

/// The checks of a cut datagram (§7): checks 1 to 5 in the order `lookup_response.zig` runs them,
/// on the octets the cut left, then check 6 on a message with no COOKIE option.
fn matches(self: *const Lookup, message: []const u8, from: Endpoint) bool {
    assert(self.state == .awaiting_udp);
    assert(!self.config.sends_requests());
    // 1. A message too short to hold a header, or longer than a message can be.
    const header = response.header_of(message) orelse return false;
    assert(message.len >= core.constants.header_bytes);
    // 2. The transaction id.
    if (header.id != self.transaction.id) return false;
    // 3. The source: this server, on this port (RFC 5452 §4.4, §4.5).
    if (!self.server().equal(&from)) return false;
    // 4. A response to a standard query.
    if (!header.is_response()) return false;
    if (header.opcode() != wire.constants.opcode_query) return false;
    // 5. One question, byte-identical to the one asked, case included (RFC 5452 §9.1). An echo in
    //    lowercase marks no server: the mark needs check 6 on a whole message (§7).
    if (header.qdcount != 1) return false;
    if (!casing.echoes_question(self, message)) return false;
    // 6. The cut took the OPT record, so the message has no COOKIE option to read. "If the client
    //    is expecting the response to contain a COOKIE option and it is missing, the response MUST
    //    be discarded" (RFC 7873 §5.3).
    return cookies.accepted(self, null);
}

// Tests. The fake server of fixtures.zig writes the whole answer, and each test cuts its end.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const State = lookup_module.State;
const CookieForm = @import("servers.zig").CookieForm;

const servers = fixtures.servers_two;
const seed = fixtures.seed;
/// STATUS, an opcode that is not QUERY (RFC 1035 §4.1.1). Test-only.
const opcode_status: u16 = 2;

/// A lookup of `example.com.` whose query went out over UDP to its first server.
fn sent(harness: *fixtures.Harness) !void {
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
}

/// `reply` as the fake server writes it, less its last octet: what a buffer one octet short keeps.
fn cut_reply(harness: *fixtures.Harness, reply: fixtures.Reply) []const u8 {
    const whole = harness.build(reply);
    return whole[0 .. whole.len - 1];
}

fn hand(harness: *fixtures.Harness, message: []const u8, from: Endpoint) Verdict {
    harness.now_ns += 1;
    return harness.lookup.on_datagram_cut(message, from, harness.now_ns);
}

test "a cut answer that passes the checks of a cut datagram sends its lookup to TCP, and tells its server nothing" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    const slot = harness.lookup.server_slot();
    // A failure before, which a success would clear. The query carried a fresh client cookie,
    // which an answer without one would silence.
    harness.servers.record_failure(slot, harness.now_ns);
    const before = harness.servers.state(slot).*;
    const message = cut_reply(&harness, fixtures.answer_a_cookie);
    try testing.expectEqual(Verdict.accepted, hand(&harness, message, servers[0].endpoint));
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    try testing.expectEqual(before, harness.servers.state(slot).*);
    const action = harness.poll();
    try testing.expect(action == .connect_tcp);
    try testing.expect(action.connect_tcp.equal(&servers[0].tcp_endpoint()));
}

test "a cut datagram that fails check 1, 2 or 3 is ignored, and the wait stands" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    const message = cut_reply(&harness, fixtures.answer_a);
    // 1: less than a header.
    try testing.expectEqual(Verdict.ignored, hand(&harness, message[0 .. core.constants.header_bytes - 1], servers[0].endpoint));
    // 2: another transaction's id.
    var other = fixtures.answer_a;
    other.id = harness.lookup.transaction.id ^ 0xffff;
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, other), servers[0].endpoint));
    // 3: another server, and the right server on another port.
    const message_again = cut_reply(&harness, fixtures.answer_a);
    try testing.expectEqual(Verdict.ignored, hand(&harness, message_again, servers[1].endpoint));
    const wrong_port: Endpoint = .{ .address = servers[0].endpoint.address, .port = fixtures.port_other };
    try testing.expectEqual(Verdict.ignored, hand(&harness, message_again, wrong_port));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expect(harness.poll() == .wait);
}

test "a cut datagram that fails check 4 or 5 is ignored, and marks no server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    const slot = harness.lookup.server_slot();
    var buffer: [core.constants.udp_payload_bytes_default]u8 = undefined;
    const message = cut_reply(&harness, fixtures.answer_a);
    const copy = buffer[0..message.len];
    const flags_at = wire.constants.header_flags_offset;
    const flags = wire.integer.read_u16(message, flags_at);
    // 4: a query, then a response of another opcode.
    @memcpy(copy, message);
    wire.integer.write_u16(copy, flags_at, flags & ~wire.constants.flag_response);
    try testing.expectEqual(Verdict.ignored, hand(&harness, copy, servers[0].endpoint));
    wire.integer.write_u16(copy, flags_at, flags | opcode_status << wire.constants.opcode_shift);
    try testing.expectEqual(Verdict.ignored, hand(&harness, copy, servers[0].endpoint));
    // 5: two questions, another name, and the name asked in lowercase.
    @memcpy(copy, message);
    wire.integer.write_u16(copy, wire.constants.header_qdcount_offset, 2);
    try testing.expectEqual(Verdict.ignored, hand(&harness, copy, servers[0].endpoint));
    var other_name = fixtures.answer_a;
    other_name.other_name = true;
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, other_name), servers[0].endpoint));
    var folded = fixtures.answer_a_cookie;
    folded.fold_case = true;
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, folded), servers[0].endpoint));
    try testing.expect(!harness.servers.changes_case(slot));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
}

test "a cut answer is ignored under ignore_truncation, on a stream, and once the lookup has ended" {
    var ignoring: fixtures.Harness = .{ .config = .{ .servers = &servers, .ignore_truncation = true } };
    try sent(&ignoring);
    try testing.expectEqual(Verdict.ignored, hand(&ignoring, cut_reply(&ignoring, fixtures.answer_a), servers[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, ignoring.lookup.state);
    // On a stream: a truncated answer sent the lookup there, and its query went out.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expectEqual(State.awaiting_tcp, harness.lookup.state);
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, fixtures.answer_a), servers[0].endpoint));
    try testing.expectEqual(State.awaiting_tcp, harness.lookup.state);
    // Ended: the whole answer came over the stream.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(State.done, harness.lookup.state);
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, fixtures.answer_a), servers[0].endpoint));
}

test "a lookup that expects a COOKIE option ignores a cut datagram, as it ignores a TC answer with none" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    // The server gives a cookie of its own, so the next query carries the pair (RFC 7873 §5.1).
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expectEqual(CookieForm.paired, harness.lookup.cookie_form);
    // The cut took the OPT record, with any COOKIE option in it, and a lookup that expects one
    // discards the response (RFC 7873 §5.3). An answer with TC set and no OPT record is the same.
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, fixtures.answer_a), servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, fixtures.answer_a_cookie), servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expect(harness.poll() == .wait);
}

test "a fresh cookie whose server has given one since expects it, and a cut datagram is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    try testing.expectEqual(CookieForm.fresh, harness.lookup.cookie_form);
    // Another lookup's answer taught the server's state a cookie after this query went out.
    const slot = harness.lookup.server_slot();
    const other_client: [core.constants.cookie_client_bytes]u8 = @splat(0x0c);
    harness.servers.learn(slot, &other_client, &fixtures.server_cookie);
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, fixtures.answer_a), servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
}

test "a cut datagram that ends inside its question is ignored, and one that holds it whole is taken" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    const message = cut_reply(&harness, fixtures.answer_a);
    const question_end = wire.response.section_start(&harness.lookup.current);
    try testing.expect(question_end < message.len);
    // Check 5 compares the octets that came, and a question that the cut reached fails it.
    for (core.constants.header_bytes..question_end) |length| {
        try testing.expectEqual(Verdict.ignored, hand(&harness, message[0..length], servers[0].endpoint));
    }
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(Verdict.accepted, hand(&harness, message[0..question_end], servers[0].endpoint));
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
}

test "a cut datagram of 65535 octets is taken, and one of 65536 is ignored at check 1" {
    // No kernel cuts a datagram to more than a message can be, but check 1 holds for each caller.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try sent(&harness);
    var message: [core.limits.message_bytes_max + 1]u8 = @splat(0);
    const reply = harness.build(fixtures.answer_a);
    @memcpy(message[0..reply.len], reply);
    try testing.expectEqual(Verdict.ignored, hand(&harness, &message, servers[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(Verdict.accepted, hand(&harness, message[0..core.limits.message_bytes_max], servers[0].endpoint));
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
}

/// One server that speaks DoH, at the first test server's address. Test-only.
const servers_https = [_]core.Server{
    .{ .endpoint = servers[0].endpoint, .https = .{ .template = "https://dns.example/dns-query{?dns}" } },
};

test "a cut datagram is ignored over DoH, where no answer comes as a datagram" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers_https } };
    try harness.start("example.com.", .a, seed);
    const action = harness.poll();
    try testing.expect(action == .send_request);
    harness.query_bytes = action.send_request.message_bytes.len;
    harness.lookup.on_sent(harness.now_ns);
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    // Its id, its source and its question are the request's: only the transport refuses it.
    var reply = fixtures.answer_a;
    reply.id = harness.lookup.transaction.id;
    try testing.expectEqual(Verdict.ignored, hand(&harness, cut_reply(&harness, reply), servers_https[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
}
