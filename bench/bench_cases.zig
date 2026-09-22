//! The cases `bench/bench.zig` measures: the three operations docs/design.md §11 estimated, and
//! the neighbours a reader needs to make sense of them.
//!
//! Every input lives in a `var` filled at setup, never in a comptime constant the optimizer could
//! fold the operation over, and every case's state is this file's own, because a case is a plain
//! function pointer with no context to carry it. Where a case has to restore state the operation
//! consumed, the restore has a row of its own or the case is written so that nothing needs
//! restoring; a row never hides a copy it did not name.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const wire = @import("wire");
const fixtures = wire.fixtures;
const table_keys = cocuyo.resolver.table_keys;
const Case = @import("harness.zig").Case;
const Name = cocuyo.Name;
const Lookup = cocuyo.Lookup;

const doNotOptimizeAway = std.mem.doNotOptimizeAway;

/// Iterations per sample, the same for every case, and for the comparison bench. The bound that matters is the clock's step
/// against the sample's length: at 200,000 iterations the cheapest case, an empty call at under
/// 2 ns, makes a sample of a third of a millisecond, and the clock steps at 42 ns on this machine,
/// which is under 0.03% of it. The dearest case makes a sample of about 120 ms.
pub const iterations = 200_000;

/// The table sizes the datagram match is measured at, to show the probe does not grow with them.
const table_small = 1;
const table_medium = 64;
const table_large = cocuyo.constants.lookup_slots_max;

/// The keys the largest table needs: at least two per slot, a power of two.
const keys_large = table_large * 2;

/// The seed every lookup here is started from. A fixed one, so two runs measure the same ids and
/// the same case patterns.
const seed = 0x5eed_5eed;

/// Where the search for an id nobody holds starts. The id used is the first from here upwards
/// that no lookup in the table drew, found by walking the key table at setup.
const stray_id_first = 0xfeed;

/// One reply for each lookup of the largest table, so a case can aim at a different slot every
/// iteration. Sixty-four octets hold a header, a `l1023.example.` question and one A record.
const rotating_reply_bytes = 64;

pub const all = [_]Case{
    .{ .name = "harness overhead (empty call)", .iterations = iterations, .run = &noop },
    .{ .name = "query build, example.com, EDNS0", .iterations = iterations, .run = &run_query_build, .setup = &setup_queries },
    .{ .name = "query build, 255-octet name, TCP", .iterations = iterations, .run = &run_query_build_max, .setup = &setup_queries },
    .{ .name = "name decode, two labels", .iterations = iterations, .run = &run_name_decode_labels, .setup = &setup_messages },
    .{ .name = "name decode, through a pointer", .iterations = iterations, .run = &run_name_decode_pointer, .setup = &setup_messages },
    .{ .name = "response parse, one A", .iterations = iterations, .run = &run_parse_one, .setup = &setup_messages },
    .{ .name = "response parse, CNAME then A (+ 256-octet restore)", .iterations = iterations, .run = &run_parse_cname, .setup = &setup_messages },
    .{ .name = "response parse, 16 A of 17", .iterations = iterations, .run = &run_parse_sixteen, .setup = &setup_messages },
    .{ .name = "datagram match, stray id, 1 in flight", .iterations = iterations, .run = &run_match_stray, .setup = &setup_table_small },
    .{ .name = "datagram match, stray id, 1024 in flight", .iterations = iterations, .run = &run_match_stray, .setup = &setup_table_large },
    .{ .name = "datagram match, wrong question, 1 in flight", .iterations = iterations, .run = &run_match_wrong, .setup = &setup_table_small },
    .{ .name = "datagram match, wrong question, 64 in flight", .iterations = iterations, .run = &run_match_wrong, .setup = &setup_table_medium },
    .{ .name = "datagram match, wrong question, 1024 in flight", .iterations = iterations, .run = &run_match_wrong, .setup = &setup_table_large },
    .{ .name = "datagram match, wrong question, rotating over 1024 slots", .iterations = iterations, .run = &run_match_rotating, .setup = &setup_rotation },
    .{ .name = "slot restore (3048-octet copy)", .iterations = iterations, .run = &run_slot_restore, .setup = &setup_table_large },
    .{ .name = "datagram match, accepted, 1024 in flight (+ slot restore)", .iterations = iterations, .run = &run_match_accept, .setup = &setup_table_large },
    .{ .name = "lookup round trip: init in place, poll, on_sent, on_response", .iterations = iterations, .run = &run_round_trip, .setup = &setup_round_trip },
    .{ .name = "resolv.conf parse, three lines", .iterations = iterations, .run = &run_resolv_conf, .setup = &setup_resolv_conf },
};

fn noop() void {}

// Query build.

var query: wire.Query = undefined;
var query_max: wire.Query = undefined;
var query_out: [cocuyo.constants.query_bytes_max]u8 = undefined;

pub fn setup_queries() void {
    query = .{ .id = fixtures.id, .name = Name.from_text("example.com") catch unreachable, .kind = .a };
    const long = "a" ** 63 ++ "." ++ "b" ** 63 ++ "." ++ "c" ** 63 ++ "." ++ "d" ** 61;
    query_max = .{ .id = fixtures.id, .name = Name.from_text(long) catch unreachable, .kind = .a, .tcp = true };
    assert(query_max.name.len == cocuyo.constants.name_bytes_max);
}

pub fn run_query_build() void {
    doNotOptimizeAway(wire.query.write(&query, &query_out));
    doNotOptimizeAway(&query_out);
}

fn run_query_build_max() void {
    doNotOptimizeAway(wire.query.write(&query_max, &query_out));
    doNotOptimizeAway(&query_out);
}

// Name decode and response parse, over the corpus copied into runtime buffers.

var message_one: [fixtures.answer_a.len]u8 = undefined;
var message_cname: [fixtures.answer_cname_then_a.len]u8 = undefined;
var message_sixteen: [fixtures.answer_a_seventeen.len]u8 = undefined;
var decoded: Name = undefined;
var chain: Name = undefined;
var answers: wire.Answers = undefined;
var question_name: Name = undefined;

pub fn setup_messages() void {
    message_one = fixtures.answer_a;
    message_cname = fixtures.answer_cname_then_a;
    message_sixteen = fixtures.answer_a_seventeen;
    question_name = Name.from_text("example.com") catch unreachable;
    chain = question_name;
}

fn run_name_decode_labels() void {
    const end = wire.name.decode(&message_one, cocuyo.constants.header_bytes, &decoded) catch unreachable;
    doNotOptimizeAway(end);
    doNotOptimizeAway(&decoded);
}

/// The first record's owner is the pointer `0xc00c` at the question's name (RFC 1035 §4.1.4).
fn run_name_decode_pointer() void {
    const end = wire.name.decode(&message_one, fixtures.answer_offset, &decoded) catch unreachable;
    doNotOptimizeAway(end);
    doNotOptimizeAway(&decoded);
}

fn parse(message: []const u8) void {
    const outcome = wire.response.collect(message, &chain, .a, 0, &answers) catch unreachable;
    doNotOptimizeAway(outcome);
    doNotOptimizeAway(&answers);
}

/// The chain does not move here, so nothing is restored between iterations.
pub fn run_parse_one() void {
    parse(&message_one);
}

/// The chain moves to `host.example.net`, so each iteration first puts the question back: a
/// 256-octet copy the row's name says it carries.
pub fn run_parse_cname() void {
    chain = question_name;
    parse(&message_cname);
}

pub fn run_parse_sixteen() void {
    parse(&message_sixteen);
}

// Datagram match: a table with N lookups in flight and one datagram aimed at it.

const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = cocuyo.Address.from_v4(.{ 192, 0, 2, 53 }) } }};
var config: cocuyo.Config = .{ .servers = &servers };
var slots: [table_large]cocuyo.Slot = undefined;
var keys: [keys_large]cocuyo.MatchKey = undefined;
var handles: [table_large]cocuyo.Handle = undefined;
var resolver: cocuyo.Resolver = undefined;
var first: cocuyo.Handle = undefined;
var saved_slot: cocuyo.Slot = undefined;
var stray_id: u16 = 0;
var reply_accept: [cocuyo.constants.udp_payload_bytes_default]u8 = undefined;
var reply_accept_len: usize = 0;
var reply_wrong: [cocuyo.constants.udp_payload_bytes_default]u8 = undefined;
var reply_wrong_len: usize = 0;
var reply_stray: [cocuyo.constants.udp_payload_bytes_default]u8 = undefined;
var reply_stray_len: usize = 0;
var send_out: [cocuyo.constants.query_bytes_max]u8 = undefined;
var other_name: Name = undefined;
var now_ns: u64 = 1;

fn setup_table_small() void {
    setup_table(table_small);
}

fn setup_table_medium() void {
    setup_table(table_medium);
}

fn setup_table_large() void {
    setup_table(table_large);
}

/// A table with `count` lookups sent and waiting, every one a different name, and three datagrams
/// aimed at one of them: one it accepts, one with its id and another name, one with an id nobody
/// holds. The target is a lookup whose id no other lookup shares, and the stray id is one the key
/// table was walked for, so each row measures the path its name says and not a collision.
fn setup_table(count: usize) void {
    assert(count >= 1);
    assert(count <= table_large);
    resolver = cocuyo.Resolver.init(slots[0..count], keys[0 .. count * 2], &config, seed);
    var started: usize = 0;
    while (started < count) : (started += 1) {
        handles[started] = resolver.start(question_for(started)) catch unreachable;
        const event = resolver.poll(now_ns, &send_out).?;
        assert(event.action == .send_udp);
        resolver.on_sent(event.handle, now_ns);
    }
    first = unique_handle(count);
    stray_id = unheld_id();
    const armed = resolver.lookup_of(first);
    saved_slot = slots[first.index];
    const cased = armed.cased_name();
    other_name = Name.from_text("other.example") catch unreachable;
    reply_accept_len = build_reply(&reply_accept, armed.transaction.id, &cased);
    reply_wrong_len = build_reply(&reply_wrong, armed.transaction.id, &other_name);
    reply_stray_len = build_reply(&reply_stray, stray_id, &cased);
}

/// The first lookup whose id is held by no other: the one the key table offers alone.
fn unique_handle(count: usize) cocuyo.Handle {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const id = resolver.lookup_of(handles[index]).transaction.id;
        var walk = table_keys.Candidates.init(resolver.keys, id);
        const only = walk.next() == handles[index].index and walk.next() == null;
        if (only) return handles[index];
    }
    // Every lookup shares its id with another: impossible below a few thousand in flight, and a
    // benchmark that could not find a unique one would be measuring collisions.
    unreachable;
}

/// An id the key table offers nobody for.
fn unheld_id() u16 {
    var candidate: u32 = stray_id_first;
    while (candidate <= std.math.maxInt(u16)) : (candidate += 1) {
        var walk = table_keys.Candidates.init(resolver.keys, @intCast(candidate));
        if (walk.next() == null) return @intCast(candidate);
    }
    unreachable;
}

/// `index` as a name of its own: `l<index>.example.`, so no two lookups share a question.
fn question_for(index: usize) cocuyo.Question {
    var text: [32]u8 = undefined;
    const written = std.fmt.bufPrint(&text, "l{d}.example.", .{index}) catch unreachable;
    return cocuyo.Question.from_text(written, .a) catch unreachable;
}

/// A response with `id`, echoing `name` as its question, and one A record whose owner points at
/// that question. What a server sends, minus the network.
fn build_reply(out: []u8, id: u16, name: *const Name) usize {
    const header: wire.Header = .{
        .id = id,
        .flags = wire.constants.flag_response | wire.constants.flag_recursion_desired,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };
    wire.header.write(&header, out);
    var offset: usize = cocuyo.constants.header_bytes;
    offset += wire.question.write(name, .a, out[offset..]);
    const record = fixtures.answer_a[fixtures.answer_offset..];
    @memcpy(out[offset..][0..record.len], record);
    return offset + record.len;
}

fn run_match_stray() void {
    now_ns += 1;
    doNotOptimizeAway(resolver.on_datagram(reply_stray[0..reply_stray_len], servers[0].endpoint, now_ns));
}

fn run_match_wrong() void {
    now_ns += 1;
    doNotOptimizeAway(resolver.on_datagram(reply_wrong[0..reply_wrong_len], servers[0].endpoint, now_ns));
}

/// The cost of putting the slot back, which the accepted case pays on every iteration because an
/// accepted datagram settles the lookup. Subtract this row from that one.
fn run_slot_restore() void {
    slots[first.index] = saved_slot;
    doNotOptimizeAway(&slots[first.index]);
}

fn run_match_accept() void {
    slots[first.index] = saved_slot;
    now_ns += 1;
    doNotOptimizeAway(resolver.on_datagram(reply_accept[0..reply_accept_len], servers[0].endpoint, now_ns));
}

// The same match, with the cache cold: a different slot and a different reply on every iteration.

var rotating_replies: [table_large][rotating_reply_bytes]u8 = undefined;
var rotating_lengths: [table_large]u8 = undefined;
var rotation: usize = 0;

/// The large table, and a wrong-question reply for every lookup in it. The rows above aim every
/// iteration at one slot, which is in the first-level cache from the second iteration on; this
/// one walks all 1024, whose 864 KiB do not fit a 128 KiB first-level cache, so each match reads
/// its slot from the level below. Ids may collide among 1024 draws, and when one does the key
/// walk offers both candidates and the row includes that at its real rate.
fn setup_rotation() void {
    setup_table(table_large);
    for (handles[0..table_large], 0..) |handle, index| {
        const armed = resolver.lookup_of(handle);
        const length = build_reply(&rotating_replies[index], armed.transaction.id, &other_name);
        assert(length <= rotating_reply_bytes);
        rotating_lengths[index] = @intCast(length);
    }
    rotation = 0;
}

fn run_match_rotating() void {
    rotation += 1;
    if (rotation == table_large) rotation = 0;
    now_ns += 1;
    const reply = rotating_replies[rotation][0..rotating_lengths[rotation]];
    doNotOptimizeAway(resolver.on_datagram(reply, servers[0].endpoint, now_ns));
}

// One whole lookup, minus the network: made, its query built, the send heard, the answer read.

var round_question: cocuyo.Question = undefined;
var lookup: Lookup = undefined;
var round_reply: [cocuyo.constants.udp_payload_bytes_default]u8 = undefined;
var round_reply_len: usize = 0;
var round_out: [cocuyo.constants.query_bytes_max]u8 = undefined;
var round_servers: cocuyo.Servers = undefined;

/// `init` from the same seed draws the same transaction every time, so one reply built at setup
/// answers every iteration.
fn setup_round_trip() void {
    round_question = cocuyo.Question.from_text("example.com.", .a) catch unreachable;
    round_servers = cocuyo.Servers.init(&config, seed);
    const initial = Lookup.init(&config, &round_servers, round_question, seed);
    const cased = initial.cased_name();
    round_reply_len = build_reply(&round_reply, initial.transaction.id, &cased);
}

fn run_round_trip() void {
    lookup.init_in_place(&config, &round_servers, round_question, seed);
    now_ns += 1;
    doNotOptimizeAway(lookup.poll(now_ns, &round_out));
    lookup.on_sent(now_ns);
    doNotOptimizeAway(lookup.on_response(round_reply[0..round_reply_len], servers[0].endpoint, now_ns));
    assert(lookup.state == .done);
}

// The configuration file, which a process parses once.

var storage: cocuyo.resolv_conf.Storage = .{};
const resolv_conf_text =
    \\nameserver 192.0.2.53
    \\search example.com corp.example
    \\options ndots:2 timeout:3 attempts:2
    \\
;
var resolv_conf_bytes: [resolv_conf_text.len]u8 = undefined;

fn setup_resolv_conf() void {
    resolv_conf_bytes = resolv_conf_text.*;
}

fn run_resolv_conf() void {
    const parsed = cocuyo.resolv_conf.parse(&resolv_conf_bytes, &storage);
    doNotOptimizeAway(parsed.servers.len);
    doNotOptimizeAway(&storage);
}

// Tests. Each case must do what its name says before its number means anything: not only that a
// datagram was refused, but that it was refused at the check the row is named for.

const testing = std.testing;

/// Gives a lookup the transaction id a case wants, key table and all. The table re-keys a lookup
/// when an entry point moves it (docs/design.md §11), and a case that writes the id itself has
/// moved nothing, so it does that work here.
fn rekey_by_hand(handle: cocuyo.Handle, id: u16) void {
    const slot = &resolver.slots.items[handle.index];
    table_keys.remove(resolver.keys, slot.keyed_id, handle.index);
    table_keys.insert(resolver.keys, id, handle.index);
    slot.keyed_id = id;
    slot.lookup.transaction.id = id;
}

fn expect_three_verdicts(count: usize) !void {
    setup_messages();
    setup_table(count);
    const armed = resolver.lookup_of(first);
    const cased = armed.cased_name();
    // The wrong-question reply passes every check up to the question compare, and fails there.
    const header = try wire.header.parse(reply_wrong[0..reply_wrong_len]);
    try testing.expectEqual(armed.transaction.id, header.id);
    try testing.expect(armed.server().equal(&servers[0].endpoint));
    try testing.expect(!wire.question.matches(reply_wrong[0..reply_wrong_len], &cased, .a));
    try testing.expect(wire.question.matches(reply_accept[0..reply_accept_len], &cased, .a));
    // The stray id is offered to nobody, and the target's id to the target alone.
    var stray_walk = table_keys.Candidates.init(resolver.keys, stray_id);
    try testing.expectEqual(@as(?u16, null), stray_walk.next());
    var own_walk = table_keys.Candidates.init(resolver.keys, armed.transaction.id);
    try testing.expectEqual(@as(?u16, first.index), own_walk.next());
    try testing.expectEqual(@as(?u16, null), own_walk.next());

    try testing.expectEqual(cocuyo.Verdict.ignored, resolver.on_datagram(reply_stray[0..reply_stray_len], servers[0].endpoint, now_ns + 1));
    try testing.expectEqual(cocuyo.Verdict.ignored, resolver.on_datagram(reply_wrong[0..reply_wrong_len], servers[0].endpoint, now_ns + 2));
    try testing.expectEqual(cocuyo.Verdict.accepted, resolver.on_datagram(reply_accept[0..reply_accept_len], servers[0].endpoint, now_ns + 3));
    try testing.expect(resolver.lookup_of(first).state == .done);
}

test "the three datagrams are refused or accepted at the checks their rows name, at every size" {
    try expect_three_verdicts(table_small);
    try expect_three_verdicts(table_medium);
    try expect_three_verdicts(table_large);
}

test "the rotating case refuses every reply and settles nothing" {
    setup_messages();
    setup_rotation();
    var turn: usize = 0;
    while (turn < table_large) : (turn += 1) run_match_rotating();
    try testing.expectEqual(@as(usize, table_large), resolver.in_flight());
    for (handles[0..table_large]) |handle| {
        try testing.expect(resolver.lookup_of(handle).state == .awaiting_udp);
    }
}

test "the round trip ends in an answer with the fixture's address" {
    setup_round_trip();
    run_round_trip();
    const answer = lookup.answer();
    try testing.expectEqual(@as(usize, 1), answer.addresses.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, answer.addresses[0].slice());
}

test "every parse case collects what its message holds" {
    // The harness runs a case's setup before its samples, and the two rows that never move the
    // chain rely on that: `collect` finds the answer section from the chain name's length, so a
    // chain the CNAME case left at `host.example.net` would start the sixteen-record walk five
    // octets in. The test restores the way the harness does.
    setup_messages();
    run_parse_one();
    try testing.expectEqual(@as(u8, 1), answers.count);
    try testing.expect(chain.equal(&question_name));

    setup_messages();
    run_parse_cname();
    try testing.expectEqual(@as(u8, 1), answers.count);
    try testing.expect(answers.aliased);
    try testing.expect(!chain.equal(&question_name));
    // Twice, because the case restores the chain itself: without that, every sample after the
    // first would parse a chain already moved and the row would quietly measure NODATA.
    run_parse_cname();
    try testing.expectEqual(@as(u8, 1), answers.count);
    try testing.expect(answers.aliased);

    setup_messages();
    run_parse_sixteen();
    try testing.expectEqual(@as(u8, cocuyo.constants.addresses_max), answers.count);
    try testing.expect(answers.truncated);
    try testing.expect(chain.equal(&question_name));
}

test "the configuration parse reads a runtime copy of the text" {
    setup_resolv_conf();
    run_resolv_conf();
    const parsed = cocuyo.resolv_conf.parse(&resolv_conf_bytes, &storage);
    try testing.expectEqual(@as(usize, 1), parsed.servers.len);
    try testing.expectEqual(@as(usize, 2), parsed.search.len);
    try testing.expectEqual(@as(u8, 2), parsed.ndots);
}

test "the stray id is walked for, past an id a lookup holds" {
    // For the fixed seed no lookup holds `stray_id_first`, so the guard's call site cannot be told
    // from a bare assignment. Force the collision and the walk is the only way to a stray id.
    setup_messages();
    setup_table(table_medium);
    rekey_by_hand(handles[3], stray_id_first);
    const found = unheld_id();
    try testing.expect(found != stray_id_first);
    var walk = table_keys.Candidates.init(resolver.keys, found);
    try testing.expectEqual(@as(?u16, null), walk.next());
}

test "the target is the lookup whose id no other holds, past ones that collide" {
    setup_messages();
    setup_table(table_medium);
    rekey_by_hand(handles[0], resolver.lookup_of(handles[1]).transaction.id);
    const target = unique_handle(table_medium);
    try testing.expect(target.index != handles[0].index);
    try testing.expect(target.index != handles[1].index);
    var walk = table_keys.Candidates.init(resolver.keys, resolver.lookup_of(target).transaction.id);
    try testing.expectEqual(@as(?u16, target.index), walk.next());
    try testing.expectEqual(@as(?u16, null), walk.next());
}
