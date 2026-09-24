//! `poll`: what the caller should do next (docs/design.md §5).
//!
//! One entry point reads the clock's value, so the timeout lives here rather than in a timer: a
//! poll at or past the deadline is what makes the wait expire. The caller may poll as often as it
//! likes, and a poll that changes nothing returns the same `wait` it returned before.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Action = lookup_module.Action;
const policy = @import("lookup_policy.zig");
const lookup_order = @import("lookup_order.zig");

pub fn poll(self: *Lookup, now_ns: u64, out: []u8) Action {
    self.see(now_ns);
    assert(out.len >= core.constants.query_bytes_max);
    // The first poll is the first instant a lookup has, and the server order needs one.
    if (!self.flags.ordered and !self.is_settled()) lookup_order.order_servers(self, now_ns);
    if (expired(self, now_ns)) {
        self.servers.record_failure(self.server_slot(), now_ns);
        self.next_server(now_ns);
    }
    return switch (self.state) {
        .query_ready => if (self.config.exchanges()) send_exchange(self, out) else send_udp(self, out),
        .tcp_needed => connect_tcp(self, now_ns),
        .tcp_ready => send_tcp(self, out),
        .awaiting_udp, .awaiting_tcp, .connecting_tcp => .{ .wait = self.deadline_ns },
        .done => .{ .done = self.answer() },
        .failed => .{ .failed = self.failure_of() },
    };
}

/// Whether the wait is over. Only a state that is waiting can expire, so a lookup nobody polls
/// for an hour does not lose its answer.
fn expired(self: *const Lookup, now_ns: u64) bool {
    return self.is_waiting() and now_ns >= self.deadline_ns;
}

fn send_udp(self: *Lookup, out: []u8) Action {
    assert(self.state == .query_ready);
    const message_bytes = build(self, false, out);
    assert(message_bytes.len <= core.constants.query_bytes_max);
    return .{ .send_udp = .{
        .server = self.server(),
        .local_port_hint = self.transaction.port_hint,
        .message_bytes = message_bytes,
    } };
}

/// One exchange: an HTTP request carrying the message a datagram would, or a QUIC stream carrying
/// it after the length prefix every DoQ message has (RFC 9250 §4.2; docs/design.md §22, §23).
fn send_exchange(self: *Lookup, out: []u8) Action {
    assert(self.state == .query_ready);
    const prefixed = self.config.uses_quic();
    const message_bytes = build(self, prefixed, out);
    assert(prefixed or message_bytes.len <= core.constants.query_bytes_max - core.constants.tcp_prefix_bytes);
    return .{ .send_exchange = .{
        .server_index = self.server_slot(),
        .message_bytes = message_bytes,
        .transaction = self.transaction.number,
    } };
}

fn connect_tcp(self: *Lookup, now_ns: u64) Action {
    assert(self.state == .tcp_needed);
    self.state = .connecting_tcp;
    self.deadline_ns = policy.deadline_ns(self.config, self.round, now_ns);
    assert(self.deadline_ns > now_ns);
    return .{ .connect_tcp = self.server_tcp() };
}

fn send_tcp(self: *Lookup, out: []u8) Action {
    assert(self.state == .tcp_ready);
    const message_bytes = build(self, true, out);
    assert(message_bytes.len > core.constants.tcp_prefix_bytes);
    return .{ .send_tcp = .{ .message_bytes = message_bytes } };
}

/// Builds the query into the caller's buffer. Everything that varies is state, so the same lookup
/// in the same state builds the same octets every time (docs/design.md §16 decision 3).
fn build(self: *const Lookup, tcp: bool, out: []u8) []const u8 {
    const query: wire.Query = .{
        // A DoH client "SHOULD use a DNS ID of 0 in every DNS request" (RFC 8484 §4.1), so an
        // HTTP cache can share the answer, and over DoQ "the DNS Message ID MUST be set to 0"
        // (RFC 9250 §4.2.1; docs/design.md §22, §23).
        .id = if (self.config.exchanges()) 0 else self.transaction.id,
        .name = self.cased_name(),
        .kind = self.question.kind,
        .payload_bytes = if (self.flags.edns_enabled) self.config.udp_payload_bytes else null,
        .tcp = tcp,
        .cookie = if (self.carries_cookie()) self.servers.cookie(self.server_slot()) else null,
        .recursion_desired = self.config.recursion_desired,
        // A query to a TLS, HTTPS or QUIC server goes encrypted, and padding is for that alone
        // (RFC 7830 §6, RFC 9250 §5.4, docs/design.md §21 to §23).
        .padded = self.config.encrypted(),
    };
    const written = wire.query.write(&query, out);
    assert(written >= core.constants.header_bytes);
    return out[0..written];
}

// Tests.

const testing = std.testing;
const Config = core.Config;
const Endpoint = core.Endpoint;
const Address = core.Address;
const Name = core.Name;
const Question = core.Question;

const fixtures = @import("fixtures.zig");
const Servers = @import("servers.zig").Servers;
const servers = fixtures.servers_two;

/// A buffer of the size every caller must provide.
const Buffer = [core.constants.query_bytes_max]u8;

/// The per-server state of the lookup under test. One at a time is enough here.
var test_servers: Servers = undefined;

fn lookup_for(config: *const Config, text: []const u8) !Lookup {
    test_servers = Servers.init(config, fixtures.seed);
    return Lookup.init(config, &test_servers, try Question.from_text(text, .a), fixtures.seed);
}

test "the first poll asks for a UDP send to the first server" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    const action = lookup.poll(0, &out);
    try testing.expectEqual(servers[0].endpoint.address.octets, action.send_udp.server.address.octets);
    try testing.expect(action.send_udp.local_port_hint >= core.constants.port_ephemeral_min);
    const header = try wire.header.parse(action.send_udp.message_bytes);
    try testing.expectEqual(lookup.transaction.id, header.id);
    try testing.expect(header.recursion_desired());
    try testing.expectEqual(@as(u16, 1), header.arcount); // the OPT record
}

test "polling twice before sending builds the same octets" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var first: Buffer = @splat(0);
    var second: Buffer = @splat(0xff);
    const one = lookup.poll(0, &first);
    const two = lookup.poll(0, &second);
    try testing.expectEqualSlices(u8, one.send_udp.message_bytes, two.send_udp.message_bytes);
}

test "after sending, a poll waits until the deadline" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    _ = lookup.poll(0, &out);
    lookup.on_sent(0);
    const action = lookup.poll(1, &out);
    try testing.expectEqual(config.timeout_ns, action.wait);
    try testing.expectEqual(lookup_module.State.awaiting_udp, lookup.state);
}

test "a poll at the deadline moves to the next server with a new transaction" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    _ = lookup.poll(0, &out);
    lookup.on_sent(0);
    const first_id = lookup.transaction.id;
    const action = lookup.poll(config.timeout_ns, &out);
    try testing.expectEqual(servers[1].endpoint.address.octets, action.send_udp.server.address.octets);
    try testing.expect(lookup.transaction.id != first_id or lookup.transaction.case_seed != 0);
    try testing.expectEqual(@as(u8, 1), lookup.server_index);
}

test "every server and every pass is tried before the lookup times out" {
    const config: Config = .{ .servers = &servers, .attempts = 2 };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    var now: u64 = 0;
    var sends: usize = 0;
    while (sends < config.servers.len * config.attempts) : (sends += 1) {
        const action = lookup.poll(now, &out);
        try testing.expect(action == .send_udp);
        lookup.on_sent(now);
        now = lookup.deadline_ns;
    }
    const last = lookup.poll(now, &out);
    try testing.expectEqual(core.Error.Timeout, last.failed.err);
}

test "a send that failed costs the server its turn" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    _ = lookup.poll(0, &out);
    lookup.on_send_failed(0);
    try testing.expectEqual(@as(u8, 1), lookup.server_index);
    try testing.expectEqual(lookup_module.State.query_ready, lookup.state);
}

test "the TCP path connects, sends with a length prefix, then waits" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    _ = lookup.poll(0, &out);
    lookup.on_sent(0);
    lookup.state = .tcp_needed; // what a truncated response sets

    const connect = lookup.poll(1, &out);
    try testing.expectEqual(servers[0].endpoint.address.octets, connect.connect_tcp.address.octets);
    try testing.expectEqual(lookup_module.State.connecting_tcp, lookup.state);

    lookup.on_tcp_connected(2);
    const send = lookup.poll(2, &out);
    const prefixed = send.send_tcp.message_bytes;
    try testing.expectEqual(
        prefixed.len - core.constants.tcp_prefix_bytes,
        wire.message_len(prefixed),
    );
    lookup.on_sent(2);
    try testing.expectEqual(lookup_module.State.awaiting_tcp, lookup.state);
    try testing.expect(lookup.poll(3, &out) == .wait);
}

test "a connection that failed costs the server its turn" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    lookup.state = .tcp_needed;
    _ = lookup.poll(0, &out);
    lookup.on_tcp_failed(1);
    try testing.expectEqual(@as(u8, 1), lookup.server_index);
    try testing.expectEqual(lookup_module.State.query_ready, lookup.state);
}

test "a settled lookup keeps returning the same action" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    var out: Buffer = @splat(0);
    lookup.cancel();
    try testing.expectEqual(core.Error.Canceled, lookup.poll(0, &out).failed.err);
    try testing.expectEqual(core.Error.Canceled, lookup.poll(1000, &out).failed.err);
}

test "a query without EDNS0 carries no OPT record" {
    const config: Config = .{ .servers = &servers };
    var lookup = try lookup_for(&config, "example.com.");
    lookup.flags.edns_enabled = false;
    var out: Buffer = @splat(0);
    const action = lookup.poll(0, &out);
    const header = try wire.header.parse(action.send_udp.message_bytes);
    try testing.expectEqual(@as(u16, 0), header.arcount);
}
