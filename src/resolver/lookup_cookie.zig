//! One lookup's DNS cookies (RFC 7873, RFC 9018; docs/design.md §19 step 10): the COOKIE option
//! a query carries, check 6 of §7 on the response, and what an accepted response teaches the
//! server's state. Split from `lookup_poll.zig` and `lookup_response.zig` by the file-length
//! rule. Its tests drive it through the fake server; those of BADCOOKIE, which is
//! `lookup_response.zig`'s, are in `lookup_cookie_test.zig`.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const Lookup = @import("lookup.zig").Lookup;
const CookieForm = @import("servers.zig").CookieForm;

/// The COOKIE option the query being built carries, or null for none, recorded in the lookup so
/// the response is checked against what went out. `stream` says the query goes over TCP, where
/// a transaction that went over UDP first needs another fresh cookie.
pub fn query_cookie(self: *Lookup, now_ns: u64, stream: bool) ?wire.Cookie {
    const slot = self.server_slot();
    // The cookie rides in the OPT record, so a query without one carries none (RFC 7873 §4), and
    // a query over DoH or DoQ carries none (docs/design.md §22, §23).
    const form: CookieForm = if (self.carries_cookie()) self.servers.cookie_form(slot, now_ns) else .none;
    self.cookie_form = form;
    switch (form) {
        .none => return null,
        .paired => {
            // "it uses the longer cookie form" once it has the server's cookie (RFC 7873 §5.1).
            const pair = self.servers.cookie(slot);
            self.cookie_client = pair.client;
            assert(pair.server_len > 0);
            return pair;
        },
        .fresh => {
            // "a client MUST NOT send a previously sent Client Cookie to a server in the absence
            // of an associated Server Cookie" (RFC 9018 §8.1): the transaction's own draw.
            const endpoint = if (stream) self.server_tcp() else self.server();
            self.cookie_client = self.servers.fresh_cookie(self.transaction.cookie_seed, &endpoint, stream);
            assert(!self.servers.expecting(slot));
            return .{ .client = self.cookie_client, .server = @splat(0), .server_len = 0 };
        },
    }
}

/// Check 6 of §7: the response's COOKIE option against the one the query carried, whatever
/// another lookup taught the server since. A query that carried none expects none back.
pub fn accepted(self: *const Lookup, cookie: ?wire.CookieView) bool {
    if (self.cookie_form == .none) return true;
    // "MUST discard the response if it contains ... an incorrect Client Cookie value"
    // (RFC 7873 §5.3).
    if (cookie) |view| return std.mem.eql(u8, view.client, &self.cookie_client);
    // "If the client is expecting the response to contain a COOKIE option and it is missing, the
    // response MUST be discarded" (RFC 7873 §5.3): it is when the query carried the server's
    // pair, or the server has given a server cookie since.
    return self.cookie_form == .fresh and !self.servers.expecting(self.server_slot());
}

/// What a response that passed the checks of §7 teaches the server's state: its server cookie,
/// with the client cookie that drew it, whatever the lookup then makes of the response. Called
/// before the rcode or the answer section is read, so a response the lookup then ignores teaches
/// it too (docs/design.md §19 steps 10 and 12). A query that carried none teaches nothing: there
/// is no client cookie to check the response's against.
pub fn learn(self: *Lookup, cookie: ?wire.CookieView) void {
    assert(!self.is_settled());
    assert(accepted(self, cookie));
    if (self.cookie_form == .none) return;
    const view = cookie orelse return;
    // A client cookie alone, with no server cookie beside it, teaches nothing.
    if (view.server.len == 0) return;
    const slot = self.server_slot();
    // "If the COOKIE option Client Cookie is correct, the client caches the Server Cookie
    // provided, even if the response is an error response (RCODE non-zero)" (RFC 7873 §5.3),
    // with the client cookie that drew it (RFC 9018 §3).
    self.servers.learn(slot, &self.cookie_client, view.server);
    assert(self.servers.expecting(slot));
}

/// What an answer the lookup takes says by carrying no COOKIE option, when its query carried a
/// fresh client cookie: the server does not support cookies. Called before the lookup moves on.
/// A response the lookup ignores is taken as never received, and says nothing of the kind
/// (docs/design.md §19 steps 10 and 12).
pub fn silence_if_missing(self: *Lookup, cookie: ?wire.CookieView, now_ns: u64) void {
    assert(!self.is_settled());
    assert(accepted(self, cookie));
    if (cookie != null or self.cookie_form != .fresh) return;
    // "When a server does not support DNS Cookies, the client MUST NOT send the same Client
    // Cookie to that same server again" (RFC 9018 §3): none for a while.
    const slot = self.server_slot();
    self.servers.silence(slot, now_ns);
    assert(self.servers.cookie_form(slot, now_ns) == .none);
}

// Tests, through the fake server of `fixtures.zig`. The BADCOOKIE tests of
// `lookup_cookie_test.zig` read the helpers marked `pub`.

const testing = std.testing;
const core = @import("core");
const fixtures = @import("fixtures.zig");
const constants = @import("constants.zig");
const Verdict = @import("lookup.zig").Verdict;
const State = @import("lookup.zig").State;

const servers = fixtures.servers_two;
const seed = fixtures.seed;

/// The COOKIE option of the query the harness last sent, or null when it carried none.
pub fn sent_cookie(harness: *const fixtures.Harness) !?wire.CookieView {
    const body = harness.query[harness.query_body_offset..harness.query_bytes];
    const cased = harness.lookup.cased_name();
    const opt = (try wire.response_opt.find(body, &cased)) orelse return null;
    return try wire.edns.find_cookie(opt.rdata);
}

/// The client cookie of the query the harness last sent, which must carry one.
pub fn sent_client(harness: *const fixtures.Harness) ![core.constants.cookie_client_bytes]u8 {
    const cookie = (try sent_cookie(harness)).?;
    return cookie.client.*;
}

/// Replies that echo the client cookie alone, the short form, with no server cookie beside it: a
/// server that has cookies and gave none this time.
const cname_client_only: fixtures.Reply = .{ .records = &fixtures.record_cname, .ancount = 1, .cookie = .echo };
pub const truncated_client_only: fixtures.Reply = .{ .truncated = true, .cookie = .echo };

test "the first query carries a fresh client cookie alone, and a lookup without EDNS carries none" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const cookie = (try sent_cookie(&harness)).?;
    // The transaction's own draw, mixed with the server's address and port (RFC 9018 §3).
    const fresh = harness.servers.fresh_cookie(harness.lookup.transaction.cookie_seed, &servers[0].endpoint, false);
    try testing.expectEqualSlices(u8, &fresh, cookie.client);
    try testing.expectEqual(@as(usize, 0), cookie.server.len);
    try testing.expectEqual(CookieForm.fresh, harness.lookup.cookie_form);

    var plain: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try plain.start("example.com.", .a, seed);
    plain.lookup.flags.edns_enabled = false;
    _ = plain.send();
    try testing.expectEqual(@as(?wire.CookieView, null), try sent_cookie(&plain));
    // A cookie in the answer to a query that sent none is not learned: the server was asked
    // without EDNS, and the next lookup must not expect a cookie it never sent.
    try testing.expectEqual(Verdict.accepted, plain.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expect(!plain.servers.expecting(0));
}

test "until a server cookie comes, each transaction and each transport carries a cookie of its own" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = try sent_client(&harness);
    // A CNAME with no target, echoing the client cookie alone: a new transaction asks again.
    try testing.expectEqual(Verdict.accepted, harness.respond(cname_client_only, servers[0].endpoint));
    _ = harness.send();
    const second = try sent_client(&harness);
    try testing.expect(!std.mem.eql(u8, &first, &second));
    try testing.expectEqual(@as(usize, 0), (try sent_cookie(&harness)).?.server.len);
    // TC=1 sends the same transaction to TCP, where it must not carry the cookie it carried over
    // UDP in the absence of a server cookie (RFC 9018 §8.1).
    const id = harness.lookup.transaction.id;
    try testing.expectEqual(Verdict.accepted, harness.respond(truncated_client_only, servers[0].endpoint));
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expectEqual(id, harness.lookup.transaction.id);
    const over_tcp = try sent_client(&harness);
    try testing.expect(!std.mem.eql(u8, &second, &over_tcp));
    try testing.expect(!std.mem.eql(u8, &first, &over_tcp));
}

test "a server cookie is kept with the client cookie that drew it, and the next query carries the pair" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = try sent_client(&harness);
    try testing.expect(!harness.servers.expecting(0));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.cname_only_cookie, servers[0].endpoint));
    try testing.expect(harness.servers.expecting(0));
    // The CNAME had no target, so the lookup asks the same server again: with the pair now.
    _ = harness.send();
    const cookie = (try sent_cookie(&harness)).?;
    try testing.expectEqualSlices(u8, &fixtures.server_cookie, cookie.server);
    try testing.expectEqualSlices(u8, &first, cookie.client);
    try testing.expectEqual(CookieForm.paired, harness.lookup.cookie_form);
    // A later answer with the pair's client cookie updates the server cookie (RFC 7873 §5.3).
    var refreshed = fixtures.answer_a_cookie;
    refreshed.server_cookie = &fixtures.server_cookie_fresh;
    try testing.expectEqual(Verdict.accepted, harness.respond(refreshed, servers[0].endpoint));
    const pair = harness.servers.cookie(0);
    try testing.expectEqualSlices(u8, &fixtures.server_cookie_fresh, pair.server[0..pair.server_len]);
    try testing.expectEqualSlices(u8, &first, &pair.client);
    // Another lookup carries the pair, and records the client cookie it carried for check 6.
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expectEqualSlices(u8, &first, &(try sent_client(&harness)));
    try testing.expectEqualSlices(u8, &first, &harness.lookup.cookie_client);
}

test "a response is checked against the cookie its own query carried, whatever the server learned since" {
    // The name's case is left alone, so either lookup's answer echoes the question the last
    // query sent.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .mix_case = false } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = harness.lookup;
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expect(!std.mem.eql(u8, &first.cookie_client, &harness.lookup.cookie_client));
    // The second lookup's answer pairs its client cookie with a server cookie.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expectEqualSlices(u8, &harness.lookup.cookie_client, &harness.servers.state(0).cookie_client);
    // The first lookup's answer must echo the first lookup's own cookie, and stands when it does.
    // Without the option it is a discard now: the server has given a cookie (RFC 7873 §5.3).
    harness.lookup = first;
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expectEqualSlices(u8, &first.cookie_client, &harness.servers.state(0).cookie_client);
}

test "a wrong client cookie, or a malformed option, is ignored and teaches nothing" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a_cookie_wrong, servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.answer_a_cookie_malformed, servers[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expect(!harness.servers.expecting(0));
    try testing.expectEqual(@as(u64, 0), harness.servers.state(0).cookie_silent_until_ns);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
}

test "no cookie is accepted before one is learned, and ignored after" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_opt_only, servers[0].endpoint));

    var learned: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try learned.start("example.com.", .a, seed);
    _ = learned.send();
    try testing.expectEqual(Verdict.accepted, learned.respond(fixtures.cname_only_cookie, servers[0].endpoint));
    _ = learned.send();
    try testing.expectEqual(Verdict.ignored, learned.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, learned.respond(fixtures.answer_a_opt_only, servers[0].endpoint));
    try testing.expectEqual(Verdict.accepted, learned.respond(fixtures.answer_a_cookie, servers[0].endpoint));
}

test "a server that answers a client cookie without one is sent none for five minutes, then a fresh one" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = try sent_client(&harness);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_opt_only, servers[0].endpoint));
    const answered_ns = harness.now_ns;
    try testing.expectEqual(answered_ns + constants.cookie_silence_ns, harness.servers.state(0).cookie_silent_until_ns);
    // The next lookup asks with EDNS0 and no COOKIE option, and expects none back.
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expectEqual(@as(u16, 1), (try wire.header.parse(harness.query[0..harness.query_bytes])).arcount);
    try testing.expectEqual(@as(?wire.CookieView, null), try sent_cookie(&harness));
    try testing.expectEqual(CookieForm.none, harness.lookup.cookie_form);
    // A cookie in its answer teaches nothing: no client cookie went out to check it against.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expect(!harness.servers.expecting(0));
    // Nor does an answer without one move the silence's end: no client cookie went unanswered.
    try harness.start("example.com.", .a, seed + 3);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_opt_only, servers[0].endpoint));
    try testing.expectEqual(answered_ns + constants.cookie_silence_ns, harness.servers.state(0).cookie_silent_until_ns);
    // Once the silence is over, a fresh client cookie, never the one that went unanswered.
    harness.now_ns = answered_ns + constants.cookie_silence_ns - 1;
    try harness.start("example.com.", .a, seed + 2);
    _ = harness.send();
    const after = try sent_client(&harness);
    try testing.expect(!std.mem.eql(u8, &first, &after));
}

test "a server cookie learned through the silence ends it" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .mix_case = false } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = harness.lookup;
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, servers[0].endpoint));
    try testing.expect(harness.servers.state(0).cookie_silent_until_ns > harness.now_ns);
    // The first lookup's query went before the silence, and its answer brings a server cookie.
    harness.lookup = first;
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_cookie, servers[0].endpoint));
    try testing.expectEqual(CookieForm.paired, harness.servers.cookie_form(0, harness.now_ns));
    // The next lookup carries the pair, inside the silence the server's earlier answer began.
    try harness.start("example.com.", .a, seed + 2);
    _ = harness.send();
    try testing.expectEqualSlices(u8, &fixtures.server_cookie, (try sent_cookie(&harness)).?.server);
}

/// An rcode no code of `wire.Rcode` names: a response that carries it is ignored
/// (docs/design.md §19 step 12).
const rcode_unknown = 6;

/// Hands the lookup `reply`, a NOERROR one, with its rcode replaced by one cocuyo does not know.
fn respond_unknown(harness: *fixtures.Harness, reply: fixtures.Reply) !Verdict {
    comptime assert(wire.Rcode.from_bits(rcode_unknown) == null);
    assert(reply.rcode == .no_error);
    const message = harness.build(reply);
    var header = try wire.header.parse(message);
    header.flags |= rcode_unknown;
    wire.header.write(&header, &harness.reply_buffer);
    harness.now_ns += 1;
    return harness.lookup.on_response(message, servers[0].endpoint, harness.now_ns);
}

/// An A record three octets long, in a message whose every length is sound, with the client
/// cookie echoed and a server cookie: a malformed answer section (§16 decision 10).
const short_address_cookie: fixtures.Reply = .{
    .records = &fixtures.record_short_a,
    .ancount = 1,
    .cookie = .echo,
    .server_cookie = &fixtures.server_cookie,
};

test "a response the lookup then ignores teaches its server cookie all the same" {
    // "If the COOKIE option Client Cookie is correct, the client caches the Server Cookie
    // provided, even if the response is an error response" (RFC 7873 §5.3): once the checks of
    // §7 pass, before the rest is read. A malformed answer section first.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const first = try sent_client(&harness);
    try testing.expectEqual(Verdict.ignored, harness.respond(short_address_cookie, servers[0].endpoint));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expect(harness.servers.expecting(0));
    const pair = harness.servers.cookie(0);
    try testing.expectEqualSlices(u8, &fixtures.server_cookie, pair.server[0..pair.server_len]);
    try testing.expectEqualSlices(u8, &first, &pair.client);
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expectEqualSlices(u8, &fixtures.server_cookie, (try sent_cookie(&harness)).?.server);

    // Then an rcode cocuyo does not know.
    var unknown: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try unknown.start("example.com.", .a, seed);
    _ = unknown.send();
    try testing.expectEqual(Verdict.ignored, try respond_unknown(&unknown, fixtures.answer_a_cookie));
    try testing.expectEqual(State.awaiting_udp, unknown.lookup.state);
    try testing.expect(unknown.servers.expecting(0));
}

test "a response without a COOKIE option that the lookup then ignores starts no silence" {
    // The silence needs an answer the lookup took; one it ignores is taken as never received
    // (docs/design.md §19 steps 10 and 12).
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(fixtures.short_address, servers[0].endpoint));
    try testing.expectEqual(Verdict.ignored, try respond_unknown(&harness, fixtures.answer_a_opt_only));
    try testing.expectEqual(@as(u64, 0), harness.servers.state(0).cookie_silent_until_ns);
    try testing.expectEqual(CookieForm.fresh, harness.servers.cookie_form(0, harness.now_ns));
    // The same answer with an rcode cocuyo knows is taken, and starts it.
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a_opt_only, servers[0].endpoint));
    try testing.expectEqual(CookieForm.none, harness.servers.cookie_form(0, harness.now_ns));
}
