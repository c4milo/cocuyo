//! Check 5 of §7 read in place, through the fake server: a mixed query's echo is held to the case
//! the transaction's seed gives the name the lookup holds, without the name the query sent built
//! again (docs/design.md §7, A server that changes the case). The names here are the ones the
//! compare treats apart: a name whose first draw left every letter small, which went out from a
//! later draw or with its first letter a capital, and the longest name, whose letters take their
//! bits from four words. The compare is `lookup_response_case.zig`'s. Split from
//! `lookup_case_test.zig` by the file-length rule, whose helpers it shares.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const fixtures = @import("fixtures.zig");
const case_test = @import("lookup_case_test.zig");

const seed = fixtures.seed;
/// The one server of these tests, so that a retry comes back to it.
const only = fixtures.servers_one[0].endpoint;
const folded = case_test.folded;
const sent_name = case_test.sent_name;
const sent_mixed = case_test.sent_mixed;

/// Names of one, two and three letters, in that order.
const short_names = [_][]const u8{ "a.", "a1.b.", "x-y.2.z." };

/// How many of the draws after `case_seed` leave small the letters `mask` gives a bit, counted
/// from the first and up to `case_draws_max`: draw k reads the low bits of the k-th word.
fn small_draws(case_seed: u64, mask: u64) usize {
    var word = case_seed;
    for (0..wire.constants.case_draws_max) |draws| {
        word = core.mix.next(word);
        if (word & mask != mask) return draws;
    }
    return wire.constants.case_draws_max;
}

/// The case seeds searched: three letters stay small at every draw with chance 2^-12.
const case_seeds_max = 65536;

/// The first case seed whose draws leave small, `draws` times in a row from the first, the
/// letters `mask` gives a bit: the name goes out from the draw after those, or, when every draw
/// left it small, with its first letter a capital.
fn seed_drawing_small(mask: u64, draws: usize) u64 {
    var case_seed: u64 = 0;
    while (case_seed < case_seeds_max) : (case_seed += 1) {
        if (small_draws(case_seed, mask) == draws) return case_seed;
    }
    unreachable;
}

/// Answers the query last sent with its echo, one octet of its question flipped by the case bit.
fn respond_flipped(harness: *fixtures.Harness, at: usize) Verdict {
    const message = harness.build(fixtures.answer_a);
    harness.reply_buffer[core.constants.header_bytes + at] ^= core.constants.ascii_case_bit;
    harness.now_ns += 1;
    return harness.lookup.on_response(message, only, harness.now_ns);
}

/// Sends `text` with `case_seed`, whose first draw leaves every letter small, and requires the
/// reply path to take the name as sent: every other case ignored and marking nothing, the
/// lowercase echo, which is the first draw's case, ignored and marking, and the echo taken.
fn expect_matched_as_sent(text: []const u8, case_seed: u64) !void {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try harness.start(text, .a, seed);
    harness.lookup.transaction.case_seed = case_seed;
    _ = harness.send();
    try testing.expect(harness.lookup.flags.query_mixed and sent_mixed(&harness));
    const held = harness.lookup.current.wire();
    for (sent_name(&harness), held, 0..) |octet, held_octet, at| {
        // A capital made small, unless that leaves the whole name in lowercase.
        if (octet == held_octet) continue;
        var echo: [core.constants.name_bytes_max]u8 = undefined;
        @memcpy(echo[0..held.len], sent_name(&harness));
        echo[at] = held_octet;
        if (std.mem.eql(u8, echo[0..held.len], held)) continue;
        try testing.expectEqual(Verdict.ignored, respond_flipped(&harness, at));
    }
    try testing.expect(!harness.servers.changes_case(0));
    try testing.expectEqual(Verdict.ignored, harness.respond(folded, only));
    try testing.expect(harness.servers.changes_case(0));
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, only));
    try testing.expect(harness.poll() == .done);
}

test "a name sent from a later draw, or the fallback, is matched as sent, for one to three letters" {
    // The first draw leaves the name small with chance 2^-L, and then check 5 compares the name
    // `mix_case` built: from the second, third or fourth draw, or with its first letter a capital.
    for (short_names, 1..) |text, letters| {
        const mask = (@as(u64, 1) << @intCast(letters)) - 1;
        for (1..wire.constants.case_draws_max + 1) |draws| {
            try expect_matched_as_sent(text, seed_drawing_small(mask, draws));
        }
    }
}

test "the name as it went out, with another type or another class, is ignored" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expect(harness.lookup.flags.query_mixed);
    // The low octets of the type and of the class, after the name: type 33, and class 33.
    const type_low = @as(usize, harness.lookup.current.len) + 1;
    for ([_]usize{ type_low, type_low + wire.constants.u16_bytes }) |at| {
        try testing.expectEqual(Verdict.ignored, respond_flipped(&harness, at));
    }
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, only));
}

/// The whole words of the seed's stream the longest name's letters use up before the last one
/// they draw from: 250 letters, 64 to a word.
const words_before_last = 3;

test "a name of 255 octets is held to the case of every letter, read in place" {
    // Its type and class lie past octet 255 of the message, and the compare reads them before
    // the name. Its letters take their bits from more than three words after the seed, and the
    // echo with any one of them in the other case is ignored and marks nothing.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &fixtures.servers_one } };
    try harness.start(case_test.longest_text, .a, seed);
    _ = harness.send();
    try testing.expect(harness.lookup.flags.query_mixed and sent_mixed(&harness));
    var letters: usize = 0;
    for (harness.lookup.current.wire(), 0..) |octet, at| {
        if (!std.ascii.isAlphabetic(octet)) continue;
        try testing.expectEqual(Verdict.ignored, respond_flipped(&harness, at));
        letters += 1;
    }
    try testing.expect(letters > words_before_last * core.mix.word_bits);
    try testing.expect(!harness.servers.changes_case(0));
    // The type and the class, where they lie, with the name as it went out.
    const type_low = @as(usize, harness.lookup.current.len) + 1;
    for ([_]usize{ type_low, type_low + wire.constants.u16_bytes }) |at| {
        try testing.expectEqual(Verdict.ignored, respond_flipped(&harness, at));
    }
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.answer_a, only));
    try testing.expect(harness.poll() == .done);
}
