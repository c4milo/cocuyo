//! Tests of the validating lookup (`lookup_validate.zig`), through the fake server of
//! `fixtures.zig` and a validator that hands out the verdicts a test scripts (docs/design.md §25,
//! step 11).
const std = @import("std");
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Kind = core.Kind;
const Validation = core.Validation;
const lookup_module = @import("lookup.zig");
const State = lookup_module.State;
const Validator = lookup_module.Validator;
const limits = @import("limits.zig");
const fixtures = @import("fixtures.zig");

const testing = std.testing;
const servers = fixtures.servers_two;
const seed = fixtures.seed;

/// A validator that answers each message with the next verdict of `verdicts`, the last one over
/// and over, and counts what it was asked.
const Scripted = struct {
    verdicts: []const Validation,
    asked: usize = 0,
    validator: Validator = undefined,

    fn bind(self: *Scripted) *const Validator {
        self.validator = .{ .context = self, .validate = validate };
        return &self.validator;
    }

    fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation {
        _ = asked;
        _ = kind;
        _ = message;
        _ = now_ns;
        const self: *Scripted = @ptrCast(@alignCast(context));
        defer self.asked += 1;
        return self.verdicts[@min(self.asked, self.verdicts.len - 1)];
    }
};

fn secure(ending: core.validation.Ending, ttl_seconds: u32) Validation {
    return .{ .secure = .{ .ending = ending, .ttl_seconds = ttl_seconds } };
}

const bogus: Validation = .{ .bogus = .signature };
const keys_wanted: Validation = .{ .keys_wanted = Name.root };

/// A harness whose lookup asks `example.com A` under `scripted`.
fn started(harness: *fixtures.Harness, scripted: *Scripted, kind: Kind) !void {
    try start_validating(harness, scripted, "example.com.", kind);
}

/// Starts `text` of `kind` on a harness whose servers validate with `scripted`.
fn start_validating(harness: *fixtures.Harness, scripted: *Scripted, text: []const u8, kind: Kind) !void {
    harness.servers = .init(&harness.config, seed);
    harness.servers_ready = true;
    harness.servers.validate_with(&harness.config, scripted.bind());
    try harness.start(text, kind, seed);
}

test "a validating query sets DO and CD, and never AD" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .authenticated_data = .always } };
    var scripted: Scripted = .{ .verdicts = &.{secure(.answer, 300)} };
    try started(&harness, &scripted, .a);
    const query = harness.send().send_udp.message_bytes;
    const header = try wire.header.parse(query);
    try testing.expect(header.checking_disabled());
    try testing.expect(!header.authentic_data());
    const opt = (try wire.response_opt.find(query, &harness.lookup.current)).?;
    try testing.expect((try wire.edns.parse(opt.class, opt.ttl_seconds)).dnssec_ok());
}

test "a secure answer ends secure, kept no longer than its signatures allow" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{secure(.answer, 60)} };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    const done = harness.poll().done;
    try testing.expectEqual(core.Security.secure, done.security);
    try testing.expectEqual(@as(u32, 60), done.ttl_seconds);
    try testing.expectEqual(@as(usize, 1), scripted.asked);
}

test "an insecure message ends insecure, and an RRSIG question unchecked" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{.insecure} };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(core.Security.insecure, harness.poll().done.security);
    var rrsig: Scripted = .{ .verdicts = &.{secure(.answer, 60)} };
    try started(&harness, &rrsig, .rrsig);
    _ = harness.send();
    _ = harness.respond(fixtures.no_data, servers[0].endpoint);
    try testing.expectEqual(core.Security.unchecked, harness.poll().failed.security);
    try testing.expectEqual(@as(usize, 0), rrsig.asked);
}

test "a validating lookup reads neither AD nor DO in a response" {
    // RFC 4035 §4.9.3: a validating stub SHOULD NOT examine AD. RFC 6840 §5.6: a resolver MUST
    // ignore DO in a response. So the validator's verdict decides, even where Stage A relies on AD.
    for ([_]struct { verdict: Validation, signed: bool, security: core.Security }{
        .{ .verdict = .insecure, .signed = true, .security = .insecure },
        .{ .verdict = secure(.answer, 60), .signed = false, .security = .secure },
    }) |case| {
        var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .authenticated_data = .always } };
        var scripted: Scripted = .{ .verdicts = &.{case.verdict} };
        try started(&harness, &scripted, .a);
        _ = harness.send();
        var reply = fixtures.answer_a;
        reply.authentic_data = case.signed;
        reply.dnssec_ok = case.signed;
        reply.cookie = .opt_only;
        const message = harness.build(reply);
        const opt = (try wire.response_opt.find(message, &harness.lookup.current)).?;
        try testing.expectEqual(case.signed, (try wire.edns.parse(opt.class, opt.ttl_seconds)).dnssec_ok());
        _ = harness.respond(reply, servers[0].endpoint);
        try testing.expectEqual(case.security, harness.poll().done.security);
    }
}

test "a bogus answer over UDP is asked again over TCP, and one there moves to the next server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{bogus} };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
    try testing.expect(harness.lookup.cause.what == .none);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expect(harness.lookup.cause.what == .bogus);
}

test "a lookup whose passes run out after a bogus answer ends Bogus" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = servers[0..1], .attempts = 1, .use_tcp = true } };
    var scripted: Scripted = .{ .verdicts = &.{bogus} };
    try started(&harness, &scripted, .a);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    const failed = harness.poll().failed;
    try testing.expectEqual(core.Error.Bogus, failed.err);
    try testing.expect(failed.cause.?.what == .bogus);
}

test "keys wanted wait with no deadline, and the keys ask the same server again" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{ keys_wanted, secure(.answer, 300) } };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(State.awaiting_keys, harness.lookup.state);
    try testing.expect(!harness.lookup.is_waiting());
    try testing.expectEqual(std.math.maxInt(u64), harness.poll().wait);
    harness.lookup.on_keys_ready(harness.now_ns);
    try testing.expectEqual(State.query_ready, harness.lookup.state);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(core.Security.secure, harness.poll().done.security);
}

test "past key_asks_max waits for one name, keys wanted read as bogus" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{keys_wanted} };
    try started(&harness, &scripted, .a);
    for (0..limits.key_asks_max) |_| {
        _ = harness.send();
        _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
        try testing.expectEqual(State.awaiting_keys, harness.lookup.state);
        harness.lookup.on_keys_ready(harness.now_ns);
    }
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
    try testing.expectEqual(State.tcp_needed, harness.lookup.state);
}

test "a walk that fails ends the lookup with its failure" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    for ([_]struct { walked: core.validation.Walked, err: core.Error }{
        .{ .walked = .bogus, .err = core.Error.Bogus },
        .{ .walked = .failed, .err = core.Error.AllServersFailed },
        .{ .walked = .timeout, .err = core.Error.Timeout },
    }) |case| {
        var scripted: Scripted = .{ .verdicts = &.{keys_wanted} };
        try started(&harness, &scripted, .a);
        _ = harness.send();
        _ = harness.respond(fixtures.answer_a, servers[0].endpoint);
        harness.lookup.on_keys_failed(case.walked, harness.now_ns);
        const failed = harness.poll().failed;
        try testing.expectEqual(case.err, failed.err);
        // A walk whose servers failed keeps that as the cause.
        if (case.walked == .failed) try testing.expect(failed.cause.?.what == .keys);
    }
}

test "a walk's unanswered question ends AllServersFailed after a server failed the lookup" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{keys_wanted} };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.server_failure, servers[0].endpoint);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[1].endpoint);
    harness.lookup.on_keys_failed(.timeout, harness.now_ns);
    try testing.expectEqual(core.Error.AllServersFailed, harness.poll().failed.err);
}

test "the proof decides the negative, whatever the rcode says" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = servers[0..1] } };
    // Compact denial: NOERROR, and a proof that the name does not exist (RFC 9824 §3.1).
    var compact: Scripted = .{ .verdicts = &.{secure(.name_error, 30)} };
    try started(&harness, &compact, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.no_data_soa, servers[0].endpoint);
    const name_error = harness.poll().failed;
    try testing.expectEqual(core.Error.NameNotFound, name_error.err);
    try testing.expectEqual(core.Security.secure, name_error.security);
    try testing.expectEqual(@as(u32, 30), name_error.negative_ttl_seconds);
    var nodata: Scripted = .{ .verdicts = &.{secure(.no_data, 300)} };
    try started(&harness, &nodata, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.name_error_soa, servers[0].endpoint);
    try testing.expectEqual(core.Error.NoData, harness.poll().failed.err);
}

test "records of another shape than the proof's are bogus" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    for ([_]struct { verdict: Validation, reply: fixtures.Reply }{
        .{ .verdict = secure(.answer, 300), .reply = fixtures.name_error_soa },
        .{ .verdict = secure(.alias, 300), .reply = fixtures.answer_a },
        .{ .verdict = secure(.answer, 300), .reply = fixtures.cname_only },
    }) |case| {
        var scripted: Scripted = .{ .verdicts = &.{case.verdict} };
        try started(&harness, &scripted, .a);
        _ = harness.send();
        _ = harness.respond(case.reply, servers[0].endpoint);
        try testing.expectEqual(State.tcp_needed, harness.lookup.state);
        try testing.expect(harness.lookup.current.equal(&try Name.from_text("example.com.")));
    }
}

test "a secure chain whose end the message does not say asks the end's name" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{ secure(.alias, 40), secure(.answer, 300) } };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_only, servers[0].endpoint);
    try testing.expectEqual(State.query_ready, harness.lookup.state);
    try testing.expectEqual(@as(u32, 40), harness.lookup.chain_ttl_seconds);
}

test "FORMERR to a validating query fails the server and leaves EDNS0 on" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{secure(.answer, 300)} };
    try started(&harness, &scripted, .a);
    _ = harness.send();
    _ = harness.respond(fixtures.format_error, servers[0].endpoint);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
    try testing.expect(harness.lookup.flags.edns_enabled);
    try testing.expectEqual(wire.Rcode.format_error, harness.lookup.cause.what.rcode);
    try testing.expectEqual(@as(usize, 0), scripted.asked);
}

/// Sends, hears keys wanted over `reply`, and hands the lookup its keys.
fn wait_and_ready_with(harness: *fixtures.Harness, reply: fixtures.Reply) !void {
    _ = harness.send();
    _ = harness.respond(reply, servers[0].endpoint);
    try testing.expectEqual(State.awaiting_keys, harness.lookup.state);
    harness.lookup.on_keys_ready(harness.now_ns);
}

fn wait_and_ready(harness: *fixtures.Harness) !void {
    return wait_and_ready_with(harness, fixtures.answer_a);
}

/// An answer with the server cookie a BADCOOKIE handed out, which check 6 asks of the server
/// from then on (RFC 7873 §5.3).
const answer_fresh_cookie: fixtures.Reply = .{
    .records = &fixtures.record_a,
    .ancount = 1,
    .cookie = .echo,
    .server_cookie = &fixtures.server_cookie_fresh,
};

test "keys that come when the server has had its three queries move to the next server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{keys_wanted} };
    try started(&harness, &scripted, .a);
    // A first BADCOOKIE asks the same server again over UDP: the second query (RFC 7873 §5.3).
    _ = harness.send();
    _ = harness.respond(fixtures.bad_cookie_fresh, servers[0].endpoint);
    try wait_and_ready_with(&harness, answer_fresh_cookie);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
    // The third query, and its keys: the server has none left over UDP (RFC 9520 §3.1).
    try wait_and_ready_with(&harness, answer_fresh_cookie);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_index);
}

test "a new name, a CNAME's target or the next candidate, waits for keys afresh" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    var scripted: Scripted = .{ .verdicts = &.{ keys_wanted, keys_wanted, secure(.alias, 300), keys_wanted } };
    try started(&harness, &scripted, .a);
    try wait_and_ready(&harness);
    try wait_and_ready(&harness);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_only, servers[0].endpoint);
    try testing.expectEqual(@as(u8, 0), harness.lookup.conjunctions.key_asks);
    try wait_and_ready(&harness);
    const search = [_]Name{try Name.from_text("one.net")};
    var walking: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    var proofs: Scripted = .{ .verdicts = &.{ keys_wanted, keys_wanted, secure(.name_error, 300), keys_wanted } };
    try start_validating(&walking, &proofs, "host.example", .a);
    try wait_and_ready(&walking);
    try wait_and_ready(&walking);
    _ = walking.send();
    _ = walking.respond(fixtures.name_error_soa, servers[0].endpoint);
    try testing.expect(walking.lookup.current.equal(&try Name.from_text("host.example.one.net")));
    try testing.expectEqual(@as(u8, 0), walking.lookup.conjunctions.key_asks);
    try wait_and_ready(&walking);
}
