//! Check 5 of §7 through the fake server: the question, DNS-0x20, and its fallback for a server
//! that lowercases the name (docs/design.md §7, A server that changes the case): which response
//! marks its server, that the wait stands, and that a marked server is asked in lowercase while
//! every other keeps 0x20. The mark is `lookup_response.zig`'s and the choice to mix
//! `lookup_poll.zig`'s. Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Question = core.Question;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Verdict = lookup_module.Verdict;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;
/// The one server of the tests that need the retry to come back to the same server.
const only = fixtures.servers_one[0].endpoint;

/// A case seed whose first draw leaves every letter of `example.com` small: the ten low bits of
/// the word after it are set. `wire.name.mix_case` draws such a name again, so it goes out with a
/// capital all the same.
const all_small_seed = 2277;
const example_letters_mask = 0x3ff;

/// The CNAME of `fixtures.record_cname`, its target spelled `HOST.EXAMPLE.NET` as a server could
/// pass it on.
fn cname_capitals() [fixtures.record_cname.len]u8 {
    var record = fixtures.record_cname;
    const rdata_at = wire.constants.pointer_bytes + core.constants.record_fixed_bytes;
    for (record[rdata_at..]) |*byte| byte.* = std.ascii.toUpper(byte.*);
    return record;
}

/// A reply that echoes the question with every letter lowercased: what a server that lowercases
/// the name sends.
const folded: fixtures.Reply = blk: {
    var reply = fixtures.answer_a;
    reply.fold_case = true;
    break :blk reply;
};

/// The name the query the harness last sent carries, as it went out.
fn sent_name(harness: *const fixtures.Harness) []const u8 {
    const at = harness.query_body_offset + core.constants.header_bytes;
    return harness.query[at..][0..harness.lookup.current.len];
}

/// Whether the query the harness last sent mixed the case, read from its octets: the name differs
/// from the one held, which is lowercase in these tests, so only mixing can make it differ.
fn sent_mixed(harness: *const fixtures.Harness) bool {
    return !std.mem.eql(u8, sent_name(harness), harness.lookup.current.wire());
}

test "a response to a question nobody asked is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var reply = fixtures.answer_a;
    reply.other_name = true;
    try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0].endpoint));
}

test "a response echoing the question with its case folded is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, servers[0].endpoint));
    try testing.expect(harness.poll() == .wait);

    // The same reply is accepted when the caller turned 0x20 off, which shows the fold is the
    // only thing the check refused.
    var without: fixtures.Harness = .{ .config = .{ .servers = &servers, .mix_case = false } };
    try without.start("example.com.", .a, seed);
    _ = without.send();
    try testing.expectEqual(Verdict.accepted, without.respond(folded, servers[0].endpoint));
}

test "a server that lowercases is marked by its reply, the wait stands, and it is asked so" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expect(harness.lookup.flags.query_mixed and sent_mixed(&harness));
    const deadline = harness.lookup.deadline_ns;
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, only));
    try testing.expect(harness.servers.changes_case(0));
    // The reply failed check 5, so it does not cut the wait short (§16 decision 10).
    try testing.expectEqual(deadline, harness.lookup.deadline_ns);
    try testing.expectEqual(deadline, harness.poll().wait);

    // The retry after the deadline goes to the same server in lowercase, and its reply is taken.
    harness.now_ns = deadline - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u8, 1), harness.lookup.round);
    try testing.expect(!harness.lookup.flags.query_mixed and !sent_mixed(&harness));
    try testing.expectEqual(Verdict.accepted, harness.respond(folded, only));
    try testing.expect(harness.poll() == .done);

    // So is a new lookup's first query, on the same table.
    try harness.start("example.com.", .a, seed + 1);
    _ = harness.send();
    try testing.expect(!harness.lookup.flags.query_mixed and !sent_mixed(&harness));
    try testing.expectEqual(Verdict.accepted, harness.respond(folded, only));
    try testing.expect(harness.poll() == .done);
}

test "a server that lowercases loses 0x20 alone, and each server is marked by its own reply" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, servers[0].endpoint));
    try testing.expect(harness.servers.changes_case(0) and !harness.servers.changes_case(1));
    // The wait runs out and the lookup moves to the second server, which keeps 0x20.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expect(harness.lookup.flags.query_mixed and sent_mixed(&harness));
    // Until it too echoes the name in another case.
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, servers[1].endpoint));
    try testing.expect(harness.servers.changes_case(1));
}

/// Hands the lookup `folded` with one octet of its question section set to `octet`.
fn respond_altered(harness: *fixtures.Harness, offset: usize, octet: u8) Verdict {
    const message = harness.build(folded);
    harness.reply_buffer[core.constants.header_bytes + offset] = octet;
    harness.now_ns += 1;
    return harness.lookup.on_response(message, servers[0].endpoint, harness.now_ns);
}

test "a reply whose question differs in more than its case marks nothing" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var other = folded;
    other.other_name = true;
    try testing.expectEqual(Verdict.ignored, harness.respond(other, servers[0].endpoint));
    // "fxample.com": a letter that is not the same letter in another case.
    try testing.expectEqual(Verdict.ignored, respond_altered(&harness, 1, 'f'));
    // The name in another case, and the type AAAA: the type's low octet follows the name.
    const type_low = harness.lookup.current.len + 1;
    const aaaa: u8 = @intCast(core.Kind.aaaa.code());
    try testing.expectEqual(Verdict.ignored, respond_altered(&harness, type_low, aaaa));
    try testing.expect(!harness.servers.changes_case(0));
    // The same reply unaltered marks, which shows each alteration is what refused the mark.
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, servers[0].endpoint));
    try testing.expect(harness.servers.changes_case(0));
}

test "an echo of another lookup's mixed query marks nothing, nor does one in capitals" {
    // Two lookups of one name to one server whose transactions drew one id: the reply to the first
    // reaches the second, in the first's case. The first's draw left every letter small, and it
    // went out with a capital all the same, so its echo is never the lowercase that marks.
    var first: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try first.start("example.com.", .a, seed);
    first.lookup.transaction.case_seed = all_small_seed;
    const first_word = core.mix.next(all_small_seed);
    try testing.expectEqual(@as(u64, example_letters_mask), first_word & example_letters_mask);
    _ = first.send();
    try testing.expect(sent_mixed(&first));
    var second: fixtures.Harness = .{ .config = first.config };
    const question = try Question.from_text("example.com.", .a);
    second.lookup = Lookup.init(&second.config, &first.servers, question, seed + 1);
    _ = second.send();
    second.lookup.transaction.id = first.lookup.transaction.id;
    try testing.expect(!std.mem.eql(u8, sent_name(&first), sent_name(&second)));
    const echo = first.build(fixtures.answer_a);
    second.now_ns += 1;
    try testing.expectEqual(Verdict.ignored, second.lookup.on_response(echo, only, second.now_ns));
    try testing.expect(!first.servers.changes_case(0));
    // The name in capitals: a server could send it, and so could a mix that drew every letter so.
    const upper = second.build(fixtures.answer_a);
    for (second.reply_buffer[core.constants.header_bytes..][0..sent_name(&second).len]) |*byte| {
        byte.* = std.ascii.toUpper(byte.*);
    }
    second.now_ns += 1;
    try testing.expectEqual(Verdict.ignored, second.lookup.on_response(upper, only, second.now_ns));
    try testing.expect(!first.servers.changes_case(0));
    // Each lookup takes its own echo, and the lowercase one still marks.
    try testing.expectEqual(Verdict.accepted, first.respond(fixtures.answer_a, only));
    try testing.expectEqual(Verdict.ignored, second.respond(folded, only));
    try testing.expect(first.servers.changes_case(0));
}

test "a late echo of a lookup's own earlier query marks nothing, though the retry drew its id" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    var late: [core.constants.udp_payload_bytes_default]u8 = undefined;
    const late_bytes = harness.build(fixtures.answer_a).len;
    @memcpy(late[0..late_bytes], harness.reply_buffer[0..late_bytes]);
    const first_id = harness.lookup.transaction.id;
    var first_name: [core.constants.name_bytes_max]u8 = undefined;
    @memcpy(first_name[0..harness.lookup.current.len], sent_name(&harness));
    // The wait runs out, and the retry to the same server draws the id the first query carried.
    harness.now_ns = harness.lookup.deadline_ns - 1;
    _ = harness.send();
    harness.lookup.transaction.id = first_id;
    const first_sent = first_name[0..harness.lookup.current.len];
    try testing.expect(!std.mem.eql(u8, first_sent, sent_name(&harness)));
    harness.now_ns += 1;
    const verdict = harness.lookup.on_response(late[0..late_bytes], only, harness.now_ns);
    try testing.expectEqual(Verdict.ignored, verdict);
    try testing.expect(!harness.servers.changes_case(0));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, only));
}

test "a reply in another case that check 6 refuses marks nothing" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    // Another client cookie, and a COOKIE option of a length neither form allows (RFC 7873 §5.3,
    // §5.2.2).
    for ([_]fixtures.CookieReply{ .wrong, .malformed }) |cookie| {
        var reply = folded;
        reply.cookie = cookie;
        try testing.expectEqual(Verdict.ignored, harness.respond(reply, servers[0].endpoint));
        try testing.expect(!harness.servers.changes_case(0));
    }
    // The client cookie the query carried, echoed: the same reply marks.
    var echoed = folded;
    echoed.cookie = .echo;
    try testing.expectEqual(Verdict.ignored, harness.respond(echoed, servers[0].endpoint));
    try testing.expect(harness.servers.changes_case(0));
}

test "a reply in another case without the cookie its server owes marks nothing" {
    // The server gave a server cookie, so the query carries the pair, and a response without a
    // COOKIE option "MUST be discarded" (RFC 7873 §5.3).
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    const client: [core.constants.cookie_client_bytes]u8 = @splat(7);
    harness.servers.learn(0, &client, &fixtures.server_cookie);
    _ = harness.send();
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, servers[0].endpoint));
    try testing.expect(!harness.servers.changes_case(0));
}

test "a reply in another case to a query that did not mix marks nothing" {
    // 0x20 off, and a name the caller wrote with capitals: the reply differs from what was sent
    // in its case alone, and it says nothing about 0x20, which the query did not use.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .mix_case = false } };
    try harness.start("Example.COM.", .a, seed);
    _ = harness.send();
    try testing.expect(!harness.lookup.flags.query_mixed);
    try testing.expectEqualSlices(u8, harness.lookup.current.wire(), sent_name(&harness));
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, servers[0].endpoint));
    try testing.expect(!harness.servers.changes_case(0));
}

test "a mark made while another lookup's mixed query is in flight changes nothing for that query" {
    var first: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try first.start("example.com.", .a, seed);
    _ = first.send();
    // A second lookup on the same table sends its own mixed query before the mark.
    var second: fixtures.Harness = .{ .config = first.config };
    const question = try Question.from_text("example.com.", .a);
    second.lookup = Lookup.init(&second.config, &first.servers, question, seed + 1);
    _ = second.send();
    try testing.expect(second.lookup.flags.query_mixed and sent_mixed(&second));

    try testing.expectEqual(Verdict.ignored, first.respond(folded, only));
    try testing.expect(first.servers.changes_case(0));
    // The second query went out mixed, and its reply is compared with what it carried.
    try testing.expectEqual(Verdict.ignored, second.respond(folded, only));
    try testing.expect(second.poll() == .wait);
    try testing.expectEqual(Verdict.accepted, second.respond(fixtures.answer_a, only));
}

test "a server that lowercases is asked for a name written with capitals in lowercase" {
    // With 0x20 on, the caller's spelling never goes on the wire: a mix replaces it, and so does
    // the lowercase a marked server is asked in, whose echo then matches what was sent.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("Example.COM.", .a, seed);
    harness.servers.record_case_change(0);
    _ = harness.send();
    try testing.expect(!harness.lookup.flags.query_mixed);
    const lowered = try Name.from_text("example.com");
    try testing.expectEqualSlices(u8, lowered.wire(), sent_name(&harness));
    try testing.expectEqual(Verdict.accepted, harness.respond(folded, servers[0].endpoint));
}

test "a chain name a server spelled with capitals is folded, though the query went in lowercase" {
    // A forwarder that lowercases the question can pass a CNAME's target on as written upstream.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    harness.servers.record_case_change(0);
    _ = harness.send();
    const record = cname_capitals();
    const reply: fixtures.Reply = .{ .records = &record, .ancount = 1, .fold_case = true };
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, servers[0].endpoint));
    const target = try Name.from_text("host.example.net");
    try testing.expectEqualSlices(u8, target.wire(), harness.lookup.current.wire());
    // The chain goes on at the same server, in lowercase, and its lowercase echo is taken.
    _ = harness.send();
    try testing.expectEqualSlices(u8, target.wire(), sent_name(&harness));
    try testing.expectEqual(Verdict.accepted, harness.respond(folded, servers[0].endpoint));
    try testing.expect(harness.poll() == .done);
}
