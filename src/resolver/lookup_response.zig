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
    const cased = self.cased_name();
    const accepted = accepted_header(self, message, from, &cased) orelse return .ignored;
    assert(!self.is_settled());
    return apply(self, message, accepted, &cased, now_ns);
}

/// What the checks of §7 let through: the header, and what the OPT record said when there was
/// one.
pub const Accepted = struct {
    header: wire.Header,
    /// The COOKIE option the OPT carried; null for no OPT, or an OPT with no cookie.
    cookie: ?wire.CookieView,
    /// The rcode's eight high bits, from the OPT record's TTL (RFC 6891 §6.1.3).
    extended_rcode_high: u8,
    /// How long an HTTP cache held a DoH answer, which every TTL loses (RFC 8484 §5.1).
    age_seconds: u32 = 0,
};

/// Every check of §7, in order. Returns what was read when the message is ours, and null when it
/// is not, without touching the lookup.
fn accepted_header(
    self: *const Lookup,
    message: []const u8,
    from: Endpoint,
    cased: *const core.Name,
) ?Accepted {
    if (self.state != .awaiting_udp and self.state != .awaiting_tcp) return null;
    // Over DoH an answer comes by its transaction, and never as a datagram (docs/design.md §22).
    if (self.config.uses_https()) return null;
    const header = header_of(message) orelse return null;
    // 2. The transaction id: sixteen bits, and the most selective check there is.
    if (header.id != self.transaction.id) return null;
    // 3. The source: this server, on this port. An answer from the right host on the wrong port is
    //    not an answer to our query (RFC 5452 §4.4, §4.5).
    const server = if (self.state == .awaiting_tcp) self.server_tcp() else self.server();
    if (!server.equal(&from)) return null;
    return accepted_shape(self, message, header, cased);
}

/// 1. A message too short to hold a header, or longer than a message can be.
pub fn header_of(message: []const u8) ?wire.Header {
    if (message.len > core.constants.message_bytes_max) return null;
    return wire.header.parse(message) catch null;
}

/// Checks 4 to 6 of §7, which an answer over DoH passes as well (docs/design.md §22).
pub fn accepted_shape(
    self: *const Lookup,
    message: []const u8,
    header: wire.Header,
    cased: *const core.Name,
) ?Accepted {
    // 4. A response to a standard query, not a query and not another opcode.
    if (!header.is_response()) return null;
    if (header.opcode() != wire.constants.opcode_query) return null;
    // 5. One question, byte-identical to the one asked, case included: DNS-0x20 lives here
    //    (RFC 5452 §9.1, §9.2).
    if (header.qdcount != 1) return null;
    if (!wire.question.matches(message, cased, self.question.kind)) return null;
    // 6. The cookie (RFC 7873 §5.3): the client cookie must be the one this lookup sent, and a
    //    server that has given a server cookie before must give one again.
    const opt = opt_of(message, cased) orelse return null;
    if (!cookie_accepted(self, opt.cookie)) return null;
    return .{ .header = header, .cookie = opt.cookie, .extended_rcode_high = opt.extended_rcode_high };
}

const OptFields = struct { cookie: ?wire.CookieView, extended_rcode_high: u8 };

/// The OPT record's fields; the defaults when the message carries no OPT; null when it is
/// malformed: a version cocuyo does not speak (RFC 6891 §6.1.3), an owner that is not the root
/// (§6.1.2), or a COOKIE option of a length neither form allows (RFC 7873 §5.2.2).
fn opt_of(message: []const u8, cased: *const core.Name) ?OptFields {
    const record = (wire.response_opt.find(message, cased) catch return null) orelse
        return .{ .cookie = null, .extended_rcode_high = 0 };
    const opt = wire.edns.parse(record.class, record.ttl_seconds) catch return null;
    const cookie = wire.edns.find_cookie(record.rdata) catch return null;
    return .{ .cookie = cookie, .extended_rcode_high = opt.extended_rcode_high };
}

/// A wrong client cookie is a discard, and so is a missing option once this server has given a
/// server cookie (RFC 7873 §5.3). Before that, a response with no cookie is a server without
/// them, and it stands. A lookup that sent no OPT record expects nothing back.
fn cookie_accepted(self: *const Lookup, cookie: ?wire.CookieView) bool {
    if (!self.carries_cookie()) return true;
    const mine = self.servers.state(self.server_slot());
    if (cookie) |view| return std.mem.eql(u8, view.client, &mine.cookie_client);
    return !self.servers.expecting(self.server_slot());
}

/// Caches the server cookie a response carried, even an error response (RFC 7873 §5.3). The
/// client cookie beside it was checked already.
fn learn_cookie(self: *Lookup, cookie: ?wire.CookieView) void {
    if (!self.carries_cookie()) return;
    const view = cookie orelse return;
    if (view.server.len == 0) return;
    self.servers.learn(self.server_slot(), view.server);
    assert(self.servers.expecting(self.server_slot()));
}

pub fn apply(
    self: *Lookup,
    message: []const u8,
    accepted: Accepted,
    cased: *const core.Name,
    now_ns: u64,
) Verdict {
    const header = accepted.header;
    // An answer of any kind is the server being up (§19 step 12), and its cookie is learned
    // whatever its rcode (RFC 7873 §5.3).
    self.servers.record_success(self.server_slot());
    learn_cookie(self, accepted.cookie);
    // Truncation over UDP sends this server's answer to TCP. Over TCP it means nothing: a stream
    // has no size limit to overflow (RFC 7766 §5), so the bit is ignored there.
    if (header.truncated() and !over_stream(self) and !self.config.ignore_truncation) {
        self.state = .tcp_needed;
        return .accepted;
    }
    const bits = (@as(u16, accepted.extended_rcode_high) << wire.constants.extended_rcode_low_bits) |
        header.rcode_bits();
    const rcode = wire.Rcode.from_bits(bits) orelse return .ignored;
    switch (policy.rcode_action(rcode, self.flags.edns_enabled, self.config.check_response)) {
        .collect => return collect(self, message, accepted, cased, now_ns),
        .next_candidate => {
            // NXDOMAIN. The SOA in the authority section says how long a cache may remember it
            // (RFC 2308 §5); a message with no SOA, or a malformed one, says nothing, and nothing
            // is zero, which is not cached.
            self.negative_ttl_seconds = negative_ttl(message, cased) -| accepted.age_seconds;
            self.next_candidate(now_ns);
        },
        .next_server => {
            self.flags.had_server_failure = true;
            self.next_server(now_ns);
        },
        .retry_without_edns => {
            // The same server, asked again without the OPT record (RFC 6891 §6.2.2).
            self.flags.edns_enabled = false;
            self.restart(now_ns);
        },
        .retry_with_cookie => on_bad_cookie(self, now_ns),
        // The caller asked for the server's answer whatever it is (§19 step 11).
        .fail => self.fail(policy.error_of(rcode)),
    }
    return .accepted;
}

/// BADCOOKIE (RFC 7873 §5.3): once more with the server cookie just learned, then over TCP, and
/// a server that answers BADCOOKIE over TCP as well is one that will not answer at all.
fn on_bad_cookie(self: *Lookup, now_ns: u64) void {
    if (over_stream(self)) {
        self.flags.had_server_failure = true;
        self.next_server(now_ns);
    } else if (self.flags.cookie_retried) {
        self.state = .tcp_needed;
    } else {
        self.flags.cookie_retried = true;
        self.restart(now_ns);
    }
    assert(self.state != .awaiting_udp);
}

/// Whether the answer is read as one over a stream: it came over TCP, or over DoH, where there is
/// nowhere else to ask (docs/design.md §22).
fn over_stream(self: *const Lookup) bool {
    return self.state == .awaiting_tcp or self.config.uses_https();
}

/// The negative TTL a message carries, or zero. A malformed authority section is not a reason
/// to refuse a message whose rcode was already acted on; it is a reason not to cache it.
fn negative_ttl(message: []const u8, cased: *const core.Name) u32 {
    return wire.response.negative_ttl_seconds(message, cased) catch 0;
}

fn collect(
    self: *Lookup,
    message: []const u8,
    accepted: Accepted,
    cased: *const core.Name,
    now_ns: u64,
) Verdict {
    // The chain walk moves `current`, so it is restored when the walk fails: a lookup must not be
    // left pointing at half a chain by a message it then ignores.
    const before = self.current;
    const outcome = wire.response.collect(
        message,
        &self.current,
        self.question.kind,
        self.cname_hops,
        &self.answers,
    ) catch |err| {
        self.current = before;
        // A chain past `cname_hops_max`, a loop above all, is the server's answer and not a
        // malformed one: it passed every check of §7. Alias loops are an error passed back to
        // the client (RFC 1034 §3.6.2, §5.2.2), and §5 names it.
        if (err == error.ChainTooLong) {
            self.fail(core.Error.ChainTooLong);
            return .accepted;
        }
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
            // "DoH clients MUST account for the Age response header field's value" (RFC 8484
            // §5.1).
            self.answers.age(self.question.kind, accepted.age_seconds);
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
            // NODATA takes the SOA minimum too (RFC 2308 §2.2), which is where this differs from
            // c-ares (docs/design.md §18).
            self.negative_ttl_seconds = negative_ttl(message, cased) -| accepted.age_seconds;
            self.next_candidate(now_ns);
        },
    }
    return .accepted;
}

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

test "a response echoing the question with its case folded is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.fold_case = true;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0].endpoint));
    try testing.expect(harness.poll() == .wait);

    // The same reply is accepted when the caller turned 0x20 off, which shows the fold is the
    // only thing the check refused.
    var without: fixtures.Harness = .{ .config = .{ .servers = &servers, .mix_case = false } };
    try without.start("example.com.", .a, seed);
    _ = without.send();
    try testing.expectEqual(Verdict.accepted, without.respond(reply, servers[0].endpoint));
}

test "a response to a question nobody asked is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.other_name = true;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0].endpoint));
}

test "a truncated response sends the lookup to TCP" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, servers[0].endpoint));
    try testing.expect(harness.poll() == .connect_tcp);
}

test "NXDOMAIN moves to the next candidate, and the last one fails the lookup" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    try harness.start("example.com", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0].endpoint);
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("example.com.one.net")));
    _ = harness.send();
    _ = harness.respond(fixtures.name_error, servers[0].endpoint);
    try testing.expectEqual(core.Error.NameNotFound, harness.poll().failed.err);
}

test "NOERROR with no record of this type is NODATA, and ends as NoData" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.no_data, servers[0].endpoint));
    try testing.expect(harness.lookup.flags.had_no_data);
    try testing.expectEqual(core.Error.NoData, harness.poll().failed.err);
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

test "a truncated response over TCP is not a reason to connect again" {
    // RFC 7766 §5: a stream has no size limit to overflow, so TC over TCP means nothing. A lookup
    // that took it seriously would connect again and again to the same server.
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
    // The answer is read rather than the bit obeyed, so the lookup finishes here.
    try testing.expect(harness.poll() == .done);
}
