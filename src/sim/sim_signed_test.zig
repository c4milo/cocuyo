//! A validating table over the twin's signed server (docs/design.md §25 step 14): whole chains
//! from the root's anchor, a server that lies, signatures that expired or were taken out, and a
//! key that is replaced. Each test counts the questions a lookup costs, against the walk's rules.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const resolver = @import("resolver");
const dnssec = @import("dnssec");
const Kind = core.Kind;
const Question = core.Question;
const server = @import("sim_server.zig");
const signed = @import("sim_signed.zig");
const limits = @import("limits.zig");
const fixtures = @import("fixtures.zig");
const KeyStore = dnssec.keys.KeyStore;

/// The table's slots: the lookup a test starts, and the walk's lookup in the slot kept for it.
const slot_count: usize = 4;
const key_count: usize = resolver.Resolver.keys_for(slot_count);
/// The store's entries: the three signed zones, and the delegation that is not.
const entries_count: usize = 4;
/// More polls than any lookup here takes: seven questions, each sent and answered.
const polls_max: usize = 64;
/// The table's seed: any value, since each test counts questions and not ids.
const table_seed: u64 = 0x5eed;

const servers = [_]core.Server{.{ .endpoint = .{ .address = core.Address.from_v4(fixtures.server_octets) } }};

/// What a lookup over the twin ended with, and the questions it cost the table, the walks' among
/// them.
const End = struct { action: resolver.Action, questions: usize };

/// A table that validates under a key store anchored at the root's DS, over one signed server.
/// Started in place: the table and the store name the arrays beside them.
const Rig = struct {
    config: core.Config = .{ .servers = &servers },
    slots: [slot_count]resolver.Slot = @splat(.{}),
    keys: [key_count]resolver.MatchKey = @splat(.{}),
    table: resolver.Resolver = undefined,
    entries: [entries_count]KeyStore.Entry = undefined,
    anchor_rdata: dnssec.fixtures.DsRdata = signed.root_anchor(),
    anchors: [1]dnssec.keys.Anchor = undefined,
    sums: dnssec.fixtures.Sums = .{},
    hashes: dnssec.fixtures.Hashes = .{},
    store: KeyStore = undefined,
    script: server.Script = .{ .signed = .{ .on = true } },
    out: [core.limits.query_bytes_max]u8 = undefined,
    reply: [limits.datagram_bytes_max]u8 = undefined,
    now_ns: u64 = 0,
    draw: u64 = 0,
    handle: ?resolver.Handle = null,
    /// The questions a walk has counted once it is joined, where a test sets them, or null.
    walk_questions: ?u8 = null,

    fn open(self: *Rig) void {
        self.anchors = .{.{ .zone = core.Name.root, .kind = .ds, .rdata = &self.anchor_rdata }};
        self.table = resolver.Resolver.init(&self.slots, &self.keys, &self.config, table_seed);
        self.store.init(&self.entries, &self.anchors, self.sums.verifier(), self.hashes.hasher(), .{ .unix_seconds = signed.now_seconds, .monotonic_ns = 0 });
        self.table.use_trust(signed.trust(&self.store));
    }

    /// Resolves `text` of `kind` to its end. The caller frees the lookup with `release`.
    fn resolve(self: *Rig, text: []const u8, kind: Kind) !End {
        const handle = try self.table.start(&try Question.parse(text, kind));
        self.handle = handle;
        var questions: usize = 0;
        for (0..polls_max) |_| {
            self.now_ns += 1;
            const event = self.table.poll(self.now_ns, &self.out) orelse return error.Stalled;
            switch (event.action) {
                .send_udp => |send| {
                    questions += 1;
                    self.answer(event.handle, send.message_bytes, false);
                },
                .connect_tcp => self.table.on_tcp_connected(event.handle, self.now_ns),
                .send_tcp => |send| {
                    questions += 1;
                    self.answer(event.handle, send.message_bytes[core.constants.tcp_prefix_bytes..], true);
                },
                .done, .failed => {
                    // A walk's lookup ends inside the table, and never here.
                    try testing.expectEqual(handle, event.handle);
                    return .{ .action = event.action, .questions = questions };
                },
                // The driver frees a walk's lookup that ended (docs/design.md §17 question 100).
                .walked => self.table.release(event.handle),
                .wait, .send_request => return error.Unexpected,
            }
        }
        return error.Stalled;
    }

    fn release(self: *Rig) void {
        self.table.release(self.handle.?);
        self.handle = null;
    }

    fn answer(self: *Rig, handle: resolver.Handle, query: []const u8, over_tcp: bool) void {
        self.table.on_sent(handle, self.now_ns);
        self.draw += 1;
        const reply = server.respond(&self.script, &fixtures.server_address, query, over_tcp, self.draw, &self.reply).?;
        self.now_ns += 1;
        _ = self.table.on_datagram(self.reply[0..reply.len], servers[0].endpoint, self.now_ns);
        const questions = self.walk_questions orelse return;
        for (&self.store.walker.walks) |*walk| {
            if (walk.phase != .free and walk.questions == 0) walk.questions = questions;
        }
    }
};

fn expect_answer(end: End, security: core.Security, questions: usize) !void {
    try testing.expect(end.action == .done);
    try testing.expectEqual(security, end.action.done.security);
    try testing.expectEqual(questions, end.questions);
}

fn expect_failure(end: End, err: core.Error, security: core.Security, questions: usize) !void {
    try testing.expect(end.action == .failed);
    try testing.expectEqual(err, end.action.failed.err);
    try testing.expectEqual(security, end.action.failed.security);
    try testing.expectEqual(questions, end.questions);
}

test "a name in a signed zone is secure, from the root's anchor down, and a second costs one question" {
    var rig: Rig = .{};
    rig.open();
    // The question, the root's DNSKEY set, the DS and DNSKEY sets of `example` and of
    // `signed.example`, and the question again: seven (Stage B: where the keys come from).
    const first = try rig.resolve("www.signed.example.", .a);
    try expect_answer(first, .secure, 7);
    try testing.expect(first.action.done.addresses[0].equal(&core.Address.from_v4(signed.address_signed_v4)));
    rig.release();
    try expect_answer(try rig.resolve("www.signed.example.", .aaaa), .secure, 1);
    rig.release();
}

test "a name under a delegation with no DS is insecure, and the walk ends at the delegation" {
    var rig: Rig = .{};
    rig.open();
    // The question, the root's DNSKEY set, `example`'s DS and DNSKEY sets, the DS question that
    // proves `plain.example` unsigned, and the question again.
    const end = try rig.resolve("www.plain.example.", .a);
    try expect_answer(end, .insecure, 6);
    try testing.expect(end.action.done.addresses[0].equal(&core.Address.from_v4(signed.address_plain_v4)));
    rig.release();
}

test "a name the signed zone does not hold, and a type it does not hold, are secure negatives" {
    var rig: Rig = .{};
    rig.open();
    // The NXDOMAIN is signed by `signed.example`, so its keys cost the walk's five questions.
    try expect_failure(try rig.resolve("nope.signed.example.", .a), core.Error.NameNotFound, .secure, 7);
    rig.release();
    try expect_failure(try rig.resolve("www.signed.example.", .mx), core.Error.NoData, .secure, 1);
    rig.release();
    try expect_failure(try rig.resolve("zzz.example.", .a), core.Error.NameNotFound, .secure, 1);
    rig.release();
}

test "a server that lies, signs with expired signatures, or strips them, gives Bogus" {
    const cases = [_]struct { zone: signed.Zone, fault: signed.Fault, questions: usize }{
        // The question, the walk's five, then UDP and TCP on each of the two passes: a bogus
        // answer over UDP asks the same server over TCP (§25, what the lookup does with it).
        .{ .zone = .signed, .fault = .lies, .questions = 10 },
        // The walk fails at the zone's DNSKEY set, its fifth question, and the lookup with it.
        .{ .zone = .signed, .fault = .expired, .questions = 6 },
        .{ .zone = .signed, .fault = .stripped, .questions = 6 },
        // The walk's five, then the DS question for the name, whose NSEC proves it is no
        // delegation: the data sits unsigned inside a signed zone (walk rule 8).
        .{ .zone = .signed, .fault = .stripped_answer, .questions = 7 },
        // A fault above the zone ends the walk where it reads that zone.
        .{ .zone = .example, .fault = .lies, .questions = 5 },
        .{ .zone = .root, .fault = .expired, .questions = 2 },
        .{ .zone = .example, .fault = .stripped, .questions = 4 },
    };
    for (cases) |case| {
        var rig: Rig = .{};
        rig.script.signed.zone = case.zone;
        rig.script.signed.fault = case.fault;
        rig.open();
        try expect_failure(try rig.resolve("www.signed.example.", .a), core.Error.Bogus, .unchecked, case.questions);
        rig.release();
    }
}

test "a walk past chain_questions_max fails the lookup that waits for it as Bogus" {
    var rig: Rig = .{};
    // The walk counts one question less than its bound as it is joined (§25 walk rule 10).
    rig.walk_questions = dnssec.limits.chain_questions_max - 1;
    rig.open();
    // The question, then the root's DNSKEY set, the walk's last question in its bound. The
    // answer to `example DS` is one past it.
    try expect_failure(try rig.resolve("www.signed.example.", .a), core.Error.Bogus, .unchecked, 3);
    rig.release();
}

test "a key published before it signs replaces the old one with no new walk" {
    var rig: Rig = .{};
    rig.script.signed.phase = .both;
    rig.open();
    try expect_answer(try rig.resolve("www.signed.example.", .a), .secure, 7);
    rig.release();
    rig.script.signed.phase = .both_second;
    try expect_answer(try rig.resolve("www.signed.example.", .aaaa), .secure, 1);
    rig.release();
}

test "a store that meets a zone while its new key signs takes the key by the DS that names it" {
    var rig: Rig = .{};
    rig.script.signed.phase = .both_second;
    rig.open();
    try expect_answer(try rig.resolve("www.signed.example.", .a), .secure, 7);
    rig.release();
}

test "a key replaced before it was published is Bogus until the old set expires" {
    var rig: Rig = .{};
    rig.open();
    try expect_answer(try rig.resolve("www.signed.example.", .a), .secure, 7);
    rig.release();
    rig.script.signed.phase = .second;
    // The question, then the DS question for the name twice. The store's old key verifies the
    // NSEC in neither answer, so the walk starts again once from the keys it holds, and fails.
    try expect_failure(try rig.resolve("www.signed.example.", .aaaa), core.Error.Bogus, .unchecked, 3);
    rig.release();
    // Past the old DNSKEY set's TTL the store holds nothing, and the walk starts again at the root.
    rig.now_ns += (signed.ttl_seconds + 1) * @import("constants.zig").ns_per_s;
    try expect_answer(try rig.resolve("www.signed.example.", .aaaa), .secure, 7);
    rig.release();
}

test "a query without the DO bit gets no RRSIG and no NSEC" {
    var script: server.Script = .{ .signed = .{ .on = true } };
    script.cookies = false;
    var query_out: [core.limits.query_bytes_max]u8 = undefined;
    var query: @import("wire").Query = .{ .id = fixtures.server_query_id, .name = try core.Name.parse("www.signed.example"), .kind = .a };
    const plain = query_out[0..@import("wire").query.write(&query, &query_out)];
    var reply: [limits.datagram_bytes_max]u8 = undefined;
    const answer = server.respond(&script, &fixtures.server_address, plain, false, 1, &reply).?;
    const header = try @import("wire").header.parse(reply[0..answer.len]);
    try testing.expectEqual(@as(u16, 1), header.ancount);
    try testing.expectEqual(fixtures.server_query_id, header.id);
}
