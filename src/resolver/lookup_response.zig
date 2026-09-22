//! `on_response`: the checks a datagram must pass before it is believed, and what a believed
//! response does to the lookup (docs/design.md §7 and §5).
//!
//! The checks run cheapest-and-most-decisive first: the length, then the transaction id, then the
//! source endpoint, then the header's shape, then the question section byte for byte with its
//! case. The answer section is walked only after all of them pass. The security order and the fast
//! order are the same order.
//!
//! Anything that fails a check is `ignored`, in any state, and the wait stands. A late datagram
//! for a settled lookup is normal for a caller with one socket, so it is an operational event and
//! not a programmer error. A datagram that passes every check and then turns out to hold a
//! malformed answer section is also ignored: the deadline moves the lookup on, which is what an
//! off-path attacker must not be able to do for it (§16 decision 10).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Endpoint = core.Endpoint;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Verdict = lookup_module.Verdict;
const policy = @import("lookup_policy.zig");

pub fn on_response(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
    self.see(now_ns);
    const header = accepted_header(self, message, from) orelse return .ignored;
    assert(!self.is_settled());
    return apply(self, message, header, now_ns);
}

/// Every check of §7, in order. Returns the header when the message is ours, and null when it is
/// not, without touching the lookup.
fn accepted_header(self: *const Lookup, message: []const u8, from: Endpoint) ?wire.Header {
    if (self.state != .awaiting_udp and self.state != .awaiting_tcp) return null;
    // 1. A message too short to hold a header, or longer than a message can be.
    if (message.len > core.constants.message_bytes_max) return null;
    const header = wire.header.parse(message) catch return null;
    // 2. The transaction id: sixteen bits, and the most selective check there is.
    if (header.id != self.transaction.id) return null;
    // 3. The source: this server, on this port. An answer from the right host on the wrong port is
    //    not an answer to our query (RFC 5452 §4.4, §4.5).
    const server = self.server();
    if (!server.equal(&from)) return null;
    // 4. A response to a standard query, not a query and not another opcode.
    if (!header.is_response()) return null;
    if (header.opcode() != wire.constants.opcode_query) return null;
    // 5. One question, byte-identical to the one asked, case included: DNS-0x20 lives here
    //    (RFC 5452 §9.1, §9.2).
    if (header.qdcount != 1) return null;
    const cased = self.cased_name();
    if (!wire.question.matches(message, &cased, self.question.kind)) return null;
    return header;
}

fn apply(self: *Lookup, message: []const u8, header: wire.Header, now_ns: u64) Verdict {
    // Truncation over UDP sends this server's answer to TCP. Over TCP it means nothing: a stream
    // has no size limit to overflow (RFC 7766 §5), so the bit is ignored there.
    if (header.truncated() and self.state == .awaiting_udp) {
        self.state = .tcp_needed;
        return .accepted;
    }
    const rcode = header.rcode() catch return .ignored;
    switch (policy.rcode_action(rcode, self.flags.edns_enabled)) {
        .collect => return collect(self, message, now_ns),
        .next_candidate => self.next_candidate(now_ns),
        .next_server => {
            self.flags.had_server_failure = true;
            self.next_server(now_ns);
        },
        .retry_without_edns => {
            // The same server, asked again without the OPT record (RFC 6891 §6.2.2).
            self.flags.edns_enabled = false;
            self.restart(now_ns);
        },
    }
    return .accepted;
}

fn collect(self: *Lookup, message: []const u8, now_ns: u64) Verdict {
    // The chain walk moves `current`, so it is restored when the walk fails: a lookup must not be
    // left pointing at half a chain by a message it then ignores.
    const before = self.current;
    const outcome = wire.response.collect(
        message,
        &self.current,
        self.question.kind,
        self.cname_hops,
        &self.answers,
    ) catch {
        self.current = before;
        return .ignored;
    };
    // A name the chain moved to came off the wire, and a server that compressed it to a pointer
    // into the question it echoed handed back cocuyo's own case randomisation. That case is noise
    // cocuyo made, not the server's spelling, so it is folded away before anyone reads it.
    if (self.flags.mix_case and self.answers.aliased) self.current.fold_case();
    switch (outcome) {
        .answered => {
            self.flags.aliased = self.answers.aliased or self.flags.aliased;
            self.cname_hops = self.answers.hops_used;
            self.state = .done;
        },
        .chain_incomplete => {
            self.flags.aliased = true;
            self.cname_hops = self.answers.hops_used;
            // The server just answered, so it is the healthy one: ask it about where the chain
            // went, with a new transaction.
            self.restart(now_ns);
        },
        .no_data => {
            self.current = before;
            self.flags.had_no_data = true;
            self.next_candidate(now_ns);
        },
    }
    return .accepted;
}

// Tests. The fake server of fixtures.zig echoes whatever the lookup asked, so these run with
// DNS-0x20 on, which is what a caller gets by default.

const testing = std.testing;
const Config = core.Config;
const Address = core.Address;
const Name = core.Name;
const Kind = core.Kind;
const Question = core.Question;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

fn harness_for(config: Config) !fixtures.Harness {
    return .{ .config = config };
}

test "a response that matches is accepted and answers the lookup" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0]));
    const action = harness.poll();
    try testing.expectEqual(@as(usize, 1), action.done.addresses.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, action.done.addresses[0].slice());
    try testing.expectEqual(@as(u32, 300), action.done.ttl_seconds);
    try testing.expectEqual(@as(?*const Name, null), action.done.canonical_name);
    try testing.expect(!action.done.truncated);
}

test "a response with the wrong id is ignored and the wait stands" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.id = harness.lookup.transaction.id ^ 0xffff;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0]));
    try testing.expect(harness.poll() == .wait);
}

test "a response from another server, or another port, is ignored" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, servers[1]));
    const wrong_port: Endpoint = .{ .address = servers[0].address, .port = fixtures.port_other };
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, wrong_port));
    try testing.expect(harness.poll() == .wait);
}

test "a response echoing the question with its case folded is ignored" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.fold_case = true;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0]));
    try testing.expect(harness.poll() == .wait);

    // The same reply is accepted when the caller turned 0x20 off, which shows the fold is the
    // only thing the check refused.
    var without = try harness_for(.{ .servers = &servers, .mix_case = false });
    try without.start("example.com.", .a, seed);
    _ = without.send();
    try testing.expectEqual(Verdict.accepted, without.respond(reply, servers[0]));
}

test "a response to a question nobody asked is ignored" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.other_name = true;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0]));
}

test "a truncated response sends the lookup to TCP" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, servers[0]));
    try testing.expect(harness.poll() == .connect_tcp);
}

test "NXDOMAIN moves to the next candidate, and the last one fails the lookup" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness = try harness_for(.{ .servers = &servers, .search = &search, .ndots = 1 });
    try harness.start("example.com", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0]);
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("example.com.one.net")));
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0]);
    try testing.expectEqual(core.Error.NameNotFound, harness.poll().failed.err);
}

test "NOERROR with no record of this type is NODATA, and ends as NoData" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.no_data, servers[0]));
    try testing.expect(harness.lookup.flags.had_no_data);
    try testing.expectEqual(core.Error.NoData, harness.poll().failed.err);
}

test "SERVFAIL moves to the next server and is what the lookup fails with" {
    var harness = try harness_for(.{ .servers = &servers, .attempts = 1 });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[0]);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[1]);
    try testing.expectEqual(core.Error.AllServersFailed, harness.poll().failed.err);
}

test "FORMERR asks the same server again without EDNS0, and only once" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.format_error, servers[0]);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    try testing.expect(!harness.lookup.flags.edns_enabled);
    const action = harness.send();
    const header = try wire.header.parse(action.send_udp.message_bytes);
    try testing.expectEqual(@as(u16, 0), header.arcount);
    _ = harness.respond(fixtures.format_error, servers[0]);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
}

test "a CNAME with no target asks the same server about where the chain went" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_only, servers[0]);
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("host.example.net")));
    try testing.expectEqual(@as(u8, 1), harness.lookup.cname_hops);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    try testing.expect(harness.poll() == .send_udp);
}

test "a CNAME re-query draws a new transaction" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.transaction;
    _ = harness.respond(fixtures.cname_only, servers[0]);
    const after = harness.lookup.transaction;
    try testing.expect(before.id != after.id or before.case_seed != after.case_seed);
    try testing.expect(before.case_seed != after.case_seed);
}

test "a chain resolved in one message answers with the canonical name" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_then_a, servers[0]);
    const action = harness.poll();
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 3 }, action.done.addresses[0].slice());
    try testing.expect(action.done.canonical_name.?.equal(&try Name.from_text("host.example.net")));
    try testing.expectEqual(@as(u32, 60), action.done.ttl_seconds);
}

test "a record for a name nobody asked about is not part of the answer" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.injected, servers[0]);
    const action = harness.poll();
    try testing.expectEqual(@as(usize, 1), action.done.addresses.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, action.done.addresses[0].slice());
}

test "a malformed answer section is ignored and leaves the name alone" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.current;
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.long_rdlength, servers[0]));
    try testing.expectEqualSlices(u8, before.wire(), harness.lookup.current.wire());
    try testing.expect(harness.poll() == .wait);
}

test "a response arriving after the lookup settled is ignored" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0]);
    try testing.expect(harness.poll() == .done);
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, servers[0]));
}

test "a flood of unmatched datagrams neither extends nor shortens the wait" {
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const deadline = harness.lookup.deadline_ns;
    var reply = fixtures.answer_a;
    var sent: u16 = 0;
    while (sent < 64) : (sent += 1) {
        reply.id = harness.lookup.transaction.id ^ (sent + 1);
        try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0]));
        try testing.expectEqual(deadline, harness.lookup.deadline_ns);
    }
    try testing.expectEqual(deadline, harness.poll().wait);
}

test "a truncated response over TCP is not a reason to connect again" {
    // RFC 7766 §5: a stream has no size limit to overflow, so TC over TCP means nothing. A lookup
    // that took it seriously would connect again and again to the same server.
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.truncated, servers[0]);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expectEqual(lookup_module.State.awaiting_tcp, harness.lookup.state);

    var reply = fixtures.truncated;
    reply.records = fixtures.answer_a.records;
    reply.ancount = fixtures.answer_a.ancount;
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0]));
    // The answer is read rather than the bit obeyed, so the lookup finishes here.
    try testing.expect(harness.poll() == .done);
}

test "a CNAME chain that loops is ignored, and the name is left where it was" {
    // The chain moves before the hop bound stops it, which is the one path where the collector
    // has to put the name back: a lookup left pointing halfway around a loop would ask the next
    // server about a name the caller never mentioned.
    var harness = try harness_for(.{ .servers = &servers });
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const before = harness.lookup.current;
    const deadline = harness.lookup.deadline_ns;
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.cname_loop, servers[0]));
    try testing.expectEqualSlices(u8, before.wire(), harness.lookup.current.wire());
    try testing.expectEqual(@as(u8, 0), harness.lookup.cname_hops);
    try testing.expectEqual(deadline, harness.lookup.deadline_ns);
    try testing.expect(harness.poll() == .wait);
}

test "a chain name compressed into the question comes back without cocuyo's own case" {
    // A server may answer a CNAME whose target shares a suffix with the question, and compress
    // that suffix to a pointer into the question it echoed. The question carries the case
    // DNS-0x20 randomised, so the target decodes wearing it. Over sixteen seeds at least one
    // randomisation puts a capital in that suffix, and none of them may reach the caller.
    const seed_count = 16;
    var lookup_seed: u64 = 0;
    while (lookup_seed < seed_count) : (lookup_seed += 1) {
        var harness = try harness_for(.{ .servers = &servers });
        try harness.start("example.com.", .a, lookup_seed);
        _ = harness.send();
        _ = harness.respond(fixtures.cname_into_question, servers[0]);
        try testing.expectEqualSlices(
            u8,
            (try Name.from_text("host.com")).wire(),
            harness.lookup.current.wire(),
        );
    }
}
