//! Tests of the tries a lookup keeps open (`lookup_earlier.zig`, `lookup_tries.zig`;
//! docs/design.md §5, Tries kept open; §16 decision 66), through the fake server of `fixtures.zig`.
//! Split from `lookup_earlier.zig` by the file-length rule.
const std = @import("std");
const core = @import("core");
const Name = core.Name;
const Kind = core.Kind;
const Validation = core.Validation;
const lookup_module = @import("lookup.zig");
const State = lookup_module.State;
const Verdict = lookup_module.Verdict;
const Validator = lookup_module.Validator;
const fixtures = @import("fixtures.zig");
const table_module = @import("table.zig");

const testing = std.testing;
const seed = fixtures.seed;
const two = fixtures.servers_two;
const three = fixtures.servers_three;

/// A reply to the query last sent, kept to hand over after the lookup has moved on.
const Late = struct {
    bytes: [core.constants.udp_payload_bytes_default]u8 = undefined,
    len: usize = 0,

    fn of(harness: *fixtures.Harness, reply: fixtures.Reply) Late {
        var late: Late = .{};
        const built = harness.build(reply);
        @memcpy(late.bytes[0..built.len], built);
        late.len = built.len;
        return late;
    }

    fn message(self: *const Late) []const u8 {
        return self.bytes[0..self.len];
    }

    /// The reply less its last octet: what a buffer one octet short keeps.
    fn cut(self: *const Late) []const u8 {
        return self.bytes[0 .. self.len - 1];
    }
};

/// Lets the current try's wait run out, and polls.
fn run_out(harness: *fixtures.Harness) lookup_module.Action {
    harness.now_ns = harness.lookup.deadline_ns - 1;
    return harness.poll();
}

/// Sends to the first server and keeps that try's `reply`, then lets the wait run out and sends
/// to the second server.
fn moved_on(harness: *fixtures.Harness, reply: fixtures.Reply) !Late {
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const late = Late.of(harness, reply);
    try testing.expect(run_out(harness) == .send_udp);
    harness.lookup.on_sent(harness.now_ns);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(@as(u8, 1), harness.lookup.tries.count);
    return late;
}

fn hand(harness: *fixtures.Harness, late: *const Late, from: usize) Verdict {
    harness.now_ns += 1;
    return harness.lookup.on_response(late.message(), harness.config.servers[from].endpoint, harness.now_ns);
}

test "a late answer to a try whose deadline passed ends the lookup, a sample from that try's own send" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    const late = try moved_on(&harness, fixtures.answer_a);
    const first_sent = harness.lookup.tries.items[0].sent_at_ns;
    const before = harness.servers.state(0).latency.windows[4];
    try testing.expectEqual(Verdict.accepted, hand(&harness, &late, 0));
    try testing.expectEqual(State.done, harness.lookup.state);
    const after = harness.servers.state(0).latency.windows[4];
    try testing.expectEqual(before.count + 1, after.count);
    try testing.expectEqual(harness.now_ns - first_sent, after.sum_ns - before.sum_ns);
}

test "SERVFAIL to an earlier try closes that try alone, and names its server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    const late = try moved_on(&harness, fixtures.server_failure);
    const current_id = harness.lookup.transaction.id;
    try testing.expectEqual(Verdict.accepted, hand(&harness, &late, 0));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(current_id, harness.lookup.transaction.id);
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
    try testing.expectEqual(@as(u8, 0), harness.lookup.cause.server_index);
    // The try is closed, so the same reply again is no lookup's.
    try testing.expectEqual(Verdict.ignored, hand(&harness, &late, 0));
}

test "TC=1 to an earlier try over UDP closes that try alone, and sends nobody to TCP" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    const late = try moved_on(&harness, fixtures.truncated);
    try testing.expectEqual(Verdict.accepted, hand(&harness, &late, 0));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
}

test "a cut datagram for an earlier try over UDP closes that try alone" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    const late = try moved_on(&harness, fixtures.answer_a);
    harness.now_ns += 1;
    try testing.expectEqual(Verdict.accepted, harness.lookup.on_datagram_cut(late.cut(), two[0].endpoint, harness.now_ns));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
    try testing.expectEqual(Verdict.ignored, hand(&harness, &late, 0));
}

test "a CNAME to an earlier try asks the target on the server the lookup is on, and closes every try" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &three } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    const alias = Late.of(&harness, fixtures.cname_only);
    try testing.expect(run_out(&harness) == .send_udp);
    harness.lookup.on_sent(harness.now_ns);
    const stale = Late.of(&harness, fixtures.answer_a);
    try testing.expect(run_out(&harness) == .send_udp);
    harness.lookup.on_sent(harness.now_ns);
    try testing.expectEqual(@as(u8, 2), harness.lookup.server_slot());
    try testing.expectEqual(Verdict.accepted, hand(&harness, &alias, 0));
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
    try testing.expectEqual(@as(u8, 1), harness.lookup.cname_hops);
    // The answer for the name asked before is an answer to another question now.
    try testing.expectEqual(Verdict.ignored, hand(&harness, &stale, 1));
    const action = harness.poll();
    try testing.expect(action.send_udp.server.equal(&three[2].endpoint));
}

test "a failed connection of an earlier stream try closes it, so a later pass connects again" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two, .use_tcp = true } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expect(run_out(&harness) == .connect_tcp);
    try testing.expectEqual(@as(?usize, 0), harness.lookup.tries.stream_at(0));
    harness.now_ns += 1;
    harness.lookup.on_tcp_failed(0, .closed, harness.now_ns);
    try testing.expectEqual(@as(?usize, null), harness.lookup.tries.stream_at(0));
    try testing.expectEqual(@as(u8, 0), harness.lookup.cause.server_index);
    try testing.expectEqual(State.connecting_tcp, harness.lookup.state);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    // The second pass reaches the first server with no try open there.
    try testing.expect(run_out(&harness) == .connect_tcp);
}

test "a later pass over a stream waits on the open try of that server, and sends nothing" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two, .use_tcp = true } };
    try harness.start("example.com.", .a, seed);
    try testing.expect(harness.poll() == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    const first_id = harness.lookup.transaction.id;
    try testing.expect(run_out(&harness) == .connect_tcp);
    harness.lookup.on_tcp_connected(harness.now_ns);
    _ = harness.send_over_tcp();
    try testing.expect(run_out(&harness) == .wait);
    try testing.expectEqual(State.awaiting_tcp, harness.lookup.state);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_slot());
    try testing.expectEqual(first_id, harness.lookup.transaction.id);
    try testing.expectEqual(@as(usize, 1), harness.lookup.sends.count(0, .stream));
}

test "a failed connection on the server the lookup is on closes the earlier stream tries there too" {
    // TC=1 on each pass sends the first server's query to TCP, so a stream try of the first pass is
    // open there when the second pass is on its stream.
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    try harness.start("example.com.", .a, seed);
    for (0..2) |pass| {
        _ = harness.send();
        try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.truncated, two[0].endpoint));
        try testing.expect(harness.poll() == .connect_tcp);
        harness.lookup.on_tcp_connected(harness.now_ns);
        _ = harness.send_over_tcp();
        if (pass == 0) {
            try testing.expect(run_out(&harness) == .send_udp);
            harness.lookup.on_sent(harness.now_ns);
            try testing.expect(run_out(&harness) == .send_udp);
            harness.now_ns -= 1;
        }
    }
    try testing.expect(harness.lookup.tries.stream_at(0) != null);
    harness.now_ns += 1;
    harness.lookup.on_tcp_failed(0, .closed, harness.now_ns);
    try testing.expectEqual(@as(?usize, null), harness.lookup.tries.stream_at(0));
}

test "a failed request of an earlier try over DoH or DoQ closes it, and names its server" {
    const template: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    const https = [_]core.Server{
        .{ .endpoint = two[0].endpoint, .https = template },
        .{ .endpoint = two[1].endpoint, .https = template },
    };
    var harness: fixtures.Harness = .{ .config = .{ .servers = &https } };
    try harness.start("example.com.", .a, seed);
    const first = harness.poll().send_request.transaction;
    harness.lookup.on_sent(harness.now_ns);
    try testing.expect(run_out(&harness) == .send_request);
    harness.lookup.on_sent(harness.now_ns);
    harness.now_ns += 1;
    harness.lookup.on_request_failed(first, .reset, harness.now_ns);
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
    try testing.expectEqual(@as(u8, 0), harness.lookup.cause.server_index);
}

/// A validator that calls every message bogus.
const Bogus = struct {
    validator: Validator = undefined,

    fn bind(self: *Bogus) *const Validator {
        self.validator = .{ .context = self, .validate = validate };
        return &self.validator;
    }

    fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation {
        _ = .{ context, asked, kind, message, now_ns };
        return .{ .bogus = .signature };
    }
};

test "a bogus message of an earlier try closes that try alone, and names its server" {
    var bogus: Bogus = .{};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    harness.servers = .init(&harness.config, seed);
    harness.servers_ready = true;
    harness.servers.validate_with(&harness.config, bogus.bind());
    const late = try moved_on(&harness, fixtures.answer_a);
    try testing.expectEqual(Verdict.accepted, hand(&harness, &late, 0));
    try testing.expectEqual(State.awaiting_udp, harness.lookup.state);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
    try testing.expectEqual(@as(u8, 0), harness.lookup.cause.server_index);
}

test "the next search candidate closes every try, so an answer for the name before is ignored" {
    const search = [_]Name{try Name.from_text("test.")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two, .search = &search } };
    // One dot and `ndots` at one: the name as written first, then with the search domain.
    try harness.start("example.com", .a, seed);
    _ = harness.send();
    const stale = Late.of(&harness, fixtures.answer_a);
    try testing.expect(run_out(&harness) == .send_udp);
    harness.lookup.on_sent(harness.now_ns);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.name_error, two[1].endpoint));
    try testing.expectEqual(@as(u8, 1), harness.lookup.candidate_index);
    try testing.expectEqual(@as(u8, 0), harness.lookup.tries.count);
    try testing.expectEqual(Verdict.ignored, hand(&harness, &stale, 0));
}

/// A validator that wants keys for every message.
const Wanting = struct {
    validator: Validator = undefined,

    fn bind(self: *Wanting) *const Validator {
        self.validator = .{ .context = self, .validate = validate };
        return &self.validator;
    }

    fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation {
        _ = .{ context, asked, kind, message, now_ns };
        return .{ .keys_wanted = Name.root };
    }
};

test "an earlier try's message that wants keys waits on the current server, and keeps the current try open" {
    var wanting: Wanting = .{};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &two } };
    harness.servers = .init(&harness.config, seed);
    harness.servers_ready = true;
    harness.servers.validate_with(&harness.config, wanting.bind());
    const late = try moved_on(&harness, fixtures.answer_a);
    const current_id = harness.lookup.transaction.id;
    try testing.expectEqual(Verdict.accepted, hand(&harness, &late, 0));
    try testing.expectEqual(State.awaiting_keys, harness.lookup.state);
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    // The try the lookup waited on stays open, now as an earlier one (the model's `earlierChecked`).
    try testing.expectEqual(@as(u8, 1), harness.lookup.tries.count);
    try testing.expectEqual(current_id, harness.lookup.tries.items[0].id);
    try testing.expectEqual(@as(u8, 1), harness.lookup.tries.items[0].position);
}

test "a table hands a late answer to the lookup whose earlier try it answers" {
    var table: fixtures.Table = .{ .config = .{ .servers = &two } };
    table.open();
    const handle = try table.start("example.com.");
    _ = table.poll();
    table.resolver.on_sent(handle, table.now_ns);
    const lookup = table.resolver.lookup_of(handle);
    var late: [core.constants.udp_payload_bytes_default]u8 = undefined;
    const built = table.build(lookup, fixtures.answer_a);
    @memcpy(late[0..built.len], built);
    table.now_ns = lookup.deadline_ns;
    _ = table.poll();
    table.resolver.on_sent(handle, table.now_ns);
    try testing.expectEqual(@as(u8, 1), lookup.tries.count);
    table.now_ns += 1;
    try testing.expectEqual(Verdict.accepted, table.resolver.on_datagram(late[0..built.len], two[0].endpoint, table.now_ns));
    try testing.expectEqual(State.done, lookup.state);
    table.resolver.release(handle);
}

comptime {
    _ = table_module;
}
