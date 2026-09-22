//! One lookup's state machine (docs/design.md §5). It owns no socket, no clock and no allocator:
//! `poll` says what to do next, the caller does it and says what happened, and `now_ns` arrives as
//! a parameter every time.
//!
//! The eight states and every transition are the table in §5. The rules that are not obvious from
//! the code:
//!
//! - A response never changes what the caller does next. `on_response` returns `accepted` or
//!   `ignored` and the caller polls afterwards either way, so a stray datagram costs one parse.
//! - An unmatched datagram does not disturb the wait. Cutting the wait short on a malformed reply
//!   would hand an off-path attacker a cheap way to force a retry it can race (§16 decision 10).
//! - The name is held uncased and the case is applied when a query is built and again when a
//!   response is checked, both from `transaction.case_seed`. One name is stored rather than two.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Endpoint = core.Endpoint;
const Address = core.Address;
const Name = core.Name;
const Kind = core.Kind;
const Question = core.Question;
const entropy_module = @import("entropy.zig");
const policy = @import("lookup_policy.zig");
const poll_module = @import("lookup_poll.zig");
const response_module = @import("lookup_response.zig");

pub const State = enum {
    /// A query is ready to be sent to the current server over UDP.
    query_ready,
    /// The query was sent; the wait is on.
    awaiting_udp,
    /// The answer was truncated: this server must be asked again over TCP (RFC 7766 §5).
    tcp_needed,
    /// The caller was told to connect; the connection is not up yet.
    connecting_tcp,
    /// The connection is up and the query is ready to be sent over it.
    tcp_ready,
    /// The query was sent over TCP; the wait is on.
    awaiting_tcp,
    done,
    failed,
};

/// What the caller should do next.
pub const Action = union(enum) {
    /// Send these bytes to this server over UDP. `local_port_hint` is a port in the Dynamic range
    /// the caller may bind; a caller that reuses one socket keeps the id and case entropy and
    /// loses the port entropy (docs/design.md §7).
    send_udp: struct { server: Endpoint, local_port_hint: u16, message_bytes: []const u8 },
    /// Open a TCP connection to this server, then call `on_tcp_connected` or `on_tcp_failed`.
    connect_tcp: Endpoint,
    /// Write these bytes to the connection. The two-octet length prefix is included
    /// (RFC 7766 §8). Then read two octets, call `wire.message_len`, read that many, and hand
    /// them to `on_response`.
    send_tcp: struct { message_bytes: []const u8 },
    /// Nothing to do until this instant, in the caller's own monotonic nanoseconds.
    wait: u64,
    done: Answer,
    failed: Failure,
};

/// Whether a datagram belonged to this lookup. Either way the caller polls afterwards.
pub const Verdict = enum { accepted, ignored };

pub const Answer = struct {
    kind: Kind,
    /// Slices into the lookup. Valid until the next call on it.
    addresses: []const Address,
    names: []const Name,
    /// The end of the CNAME chain, when one was followed.
    canonical_name: ?*const Name,
    /// The smallest TTL over the records used, for a cache above cocuyo.
    ttl_seconds: u32,
    /// Whether the response held more records than the lookup has room for.
    truncated: bool,
};

pub const Failure = struct {
    err: core.Error,
    server_index: u8,
    attempts_made: u8,
};

/// The flags one lookup carries, packed into an octet so the hot block stays inside a cache line.
pub const Flags = packed struct(u8) {
    /// Whether the query carries an OPT record. Cleared for one server that answers FORMERR.
    edns_enabled: bool,
    /// Whether the qname's case is randomised (RFC 5452 §9.2).
    mix_case: bool,
    /// Whether any candidate answered NOERROR with no record of this type.
    had_no_data: bool,
    /// Whether any server answered SERVFAIL, REFUSED or NOTIMP.
    had_server_failure: bool,
    /// Whether a CNAME was followed, which makes the current name the canonical one.
    aliased: bool,
    unused: u3 = 0,
};

pub const Lookup = struct {
    // The fields `poll`, the timer and the response check read. They are declared together, but
    // Zig orders a struct's fields as it likes, and it does reorder these: the measurement in the
    // test at the bottom of this file found `state` well past the names. What keeps the
    // demultiplexer cheap is the side table of §11, not this declaration order.
    state: State,
    flags: Flags,
    server_index: u8,
    round: u8,
    candidate_index: u8,
    cname_hops: u8,
    transaction: entropy_module.Transaction,
    deadline_ns: u64,
    /// The last instant the caller passed in, so a clock going backwards is caught.
    now_ns_seen: u64,
    entropy: entropy_module.Entropy,
    failure: core.Error,
    config: *const Config,

    // The names and the records: the bulk of a slot.
    question: Question,
    /// The name being asked about now: a search candidate, or where the CNAME chain has reached.
    /// Held uncased; the case is applied on the way out and checked on the way back.
    current: Name,
    answers: wire.Answers,

    pub fn init(config: *const Config, question: Question, seed: u64) Lookup {
        config.assert_valid();
        assert(question.kind.queryable());
        var lookup: Lookup = .{
            .state = .query_ready,
            .flags = .{
                .edns_enabled = true,
                .mix_case = config.mix_case,
                .had_no_data = false,
                .had_server_failure = false,
                .aliased = false,
            },
            .server_index = 0,
            .round = 0,
            .candidate_index = 0,
            .cname_hops = 0,
            .transaction = undefined,
            .deadline_ns = 0,
            .now_ns_seen = 0,
            .entropy = entropy_module.Entropy.init(seed),
            .failure = core.Error.Timeout,
            .config = config,
            .question = question,
            .current = question.name,
            .answers = wire.Answers.init(question.kind),
        };
        lookup.transaction = lookup.entropy.transaction();
        if (config.rotate) {
            lookup.server_index = lookup.entropy.server_start(config.servers.len);
        }
        lookup.take_candidate(lookup.candidate_index);
        assert(lookup.state == .query_ready or lookup.state == .failed);
        return lookup;
    }

    pub fn poll(self: *Lookup, now_ns: u64, out: []u8) Action {
        return poll_module.poll(self, now_ns, out);
    }

    pub fn on_response(
        self: *Lookup,
        message: []const u8,
        from: Endpoint,
        now_ns: u64,
    ) Verdict {
        return response_module.on_response(self, message, from, now_ns);
    }

    /// The caller sent what `poll` asked for.
    pub fn on_sent(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .query_ready or self.state == .tcp_ready);
        self.state = switch (self.state) {
            .query_ready => .awaiting_udp,
            .tcp_ready => .awaiting_tcp,
            else => unreachable,
        };
        self.deadline_ns = policy.deadline_ns(self.config, self.round, now_ns);
        assert(self.deadline_ns > now_ns);
    }

    /// The send failed. The server is no better than one that did not answer.
    pub fn on_send_failed(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .query_ready or self.state == .tcp_ready);
        self.next_server(now_ns);
    }

    pub fn on_tcp_connected(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .connecting_tcp);
        self.state = .tcp_ready;
        self.deadline_ns = policy.deadline_ns(self.config, self.round, now_ns);
    }

    pub fn on_tcp_failed(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .connecting_tcp or self.state == .tcp_ready or
            self.state == .awaiting_tcp);
        self.next_server(now_ns);
    }

    /// Gives up on the lookup. A response that arrives afterwards is ignored like any other.
    pub fn cancel(self: *Lookup) void {
        assert(self.state != .done);
        self.fail(core.Error.Canceled);
        assert(self.state == .failed);
    }

    pub fn is_settled(self: *const Lookup) bool {
        return self.state == .done or self.state == .failed;
    }

    /// Whether the lookup is waiting for an instant to arrive, which is what a table's timer is
    /// armed for.
    pub fn is_waiting(self: *const Lookup) bool {
        return switch (self.state) {
            .awaiting_udp, .awaiting_tcp, .connecting_tcp => true,
            .query_ready, .tcp_needed, .tcp_ready, .done, .failed => false,
        };
    }

    /// The current server: the one a query goes to and the only one a response may come from.
    pub fn server(self: *const Lookup) Endpoint {
        assert(self.server_index < self.config.servers.len);
        return self.config.servers[self.server_index];
    }

    /// The name as it goes on the wire: the current name with its case set from this
    /// transaction's seed.
    pub fn cased_name(self: *const Lookup) Name {
        var name = self.current;
        if (self.flags.mix_case) wire.name.mix_case(&name, self.transaction.case_seed);
        assert(name.equal(&self.current));
        return name;
    }

    /// Records the instant, and asserts the caller's clock never goes backwards.
    pub fn see(self: *Lookup, now_ns: u64) void {
        assert(now_ns >= self.now_ns_seen);
        self.now_ns_seen = now_ns;
    }

    /// Moves to the next server, then to the next pass, then gives up.
    pub fn next_server(self: *Lookup, now_ns: u64) void {
        assert(!self.is_settled());
        self.server_index += 1;
        if (self.server_index == self.config.servers.len) {
            self.server_index = 0;
            self.round += 1;
        }
        if (self.round == self.config.attempts) {
            self.fail(if (self.flags.had_server_failure)
                core.Error.AllServersFailed
            else
                core.Error.Timeout);
            return;
        }
        assert(self.round < self.config.attempts);
        self.restart(now_ns);
    }

    /// Moves to the next candidate of the search walk, then gives up.
    pub fn next_candidate(self: *Lookup, now_ns: u64) void {
        assert(!self.is_settled());
        self.server_index = 0;
        self.round = 0;
        self.cname_hops = 0;
        self.flags.aliased = false;
        self.take_candidate(self.candidate_index + 1);
        if (self.state == .query_ready) self.restart(now_ns);
    }

    /// Starts a new transaction for the current name on the current server: a fresh id, port hint
    /// and case pattern, which is what a re-query must have (docs/design.md §7).
    pub fn restart(self: *Lookup, now_ns: u64) void {
        assert(!self.is_settled());
        self.transaction = self.entropy.transaction();
        self.state = .query_ready;
        self.deadline_ns = now_ns;
    }

    /// Takes the candidate at `index`, skipping any that cannot be encoded, and fails when the
    /// walk is over.
    pub fn take_candidate(self: *Lookup, index: u8) void {
        var at = index;
        while (at <= core.constants.candidates_max) {
            switch (policy.candidate(self.config, &self.question, at)) {
                .name => |name| {
                    self.candidate_index = at;
                    self.current = name;
                    self.state = .query_ready;
                    self.flags.aliased = false;
                    return;
                },
                .skip => at += 1,
                .exhausted => {
                    self.candidate_index = at;
                    self.fail(if (self.flags.had_no_data)
                        core.Error.NoData
                    else
                        core.Error.NameNotFound);
                    return;
                },
            }
        }
        assert(at > core.constants.candidates_max);
        self.fail(core.Error.NameTooLong);
    }

    pub fn fail(self: *Lookup, err: core.Error) void {
        self.failure = err;
        self.state = .failed;
        assert(self.is_settled());
    }

    /// What `.done` and `.failed` carry.
    pub fn answer(self: *const Lookup) Answer {
        assert(self.state == .done);
        return .{
            .kind = self.question.kind,
            .addresses = if (self.question.kind == .ptr) &.{} else self.answers.addresses(),
            .names = if (self.question.kind == .ptr) self.answers.names() else &.{},
            .canonical_name = if (self.flags.aliased) &self.current else null,
            .ttl_seconds = self.answers.ttl_seconds,
            .truncated = self.answers.truncated,
        };
    }

    pub fn failure_of(self: *const Lookup) Failure {
        assert(self.state == .failed);
        return .{
            .err = self.failure,
            .server_index = self.server_index,
            .attempts_made = self.round,
        };
    }
};

// Tests. The transitions are driven in lookup_poll.zig and lookup_response.zig; these pin what
// `init` sets up and what the advance rules do.

const testing = std.testing;

const fixtures = @import("fixtures.zig");
const one_server = fixtures.servers_one;
const three_servers = fixtures.servers_three;

test "a lookup starts ready to send its first query" {
    const config: Config = .{ .servers = &one_server };
    var lookup = Lookup.init(&config, try Question.from_text("example.com", .a), 1);
    try testing.expectEqual(State.query_ready, lookup.state);
    try testing.expect(lookup.current.equal(&try Name.from_text("example.com")));
    try testing.expect(lookup.flags.edns_enabled);
    try testing.expect(lookup.flags.mix_case);
    try testing.expectEqual(@as(u8, 0), lookup.server_index);
    try testing.expect(!lookup.is_settled());
}

test "the name on the wire is cased and the name held is not" {
    const config: Config = .{ .servers = &one_server };
    var lookup = Lookup.init(&config, try Question.from_text("example.com", .a), 1);
    const cased = lookup.cased_name();
    try testing.expect(cased.equal(&lookup.current));
    try testing.expect(!std.mem.eql(u8, cased.wire(), lookup.current.wire()));

    var without = Lookup.init(&.{ .servers = &one_server, .mix_case = false }, lookup.question, 1);
    try testing.expectEqualSlices(u8, without.current.wire(), without.cased_name().wire());
}

test "the servers are tried in turn, then the passes, then the lookup fails" {
    const config: Config = .{ .servers = &three_servers, .attempts = 2 };
    var lookup = Lookup.init(&config, try Question.from_text("example.com.", .a), 1);
    const first_id = lookup.transaction.id;
    lookup.next_server(1);
    try testing.expectEqual(@as(u8, 1), lookup.server_index);
    try testing.expectEqual(@as(u8, 0), lookup.round);
    try testing.expect(lookup.transaction.id != first_id or lookup.transaction.case_seed != 0);
    lookup.next_server(2);
    lookup.next_server(3);
    try testing.expectEqual(@as(u8, 0), lookup.server_index);
    try testing.expectEqual(@as(u8, 1), lookup.round);
    lookup.next_server(4);
    lookup.next_server(5);
    lookup.next_server(6);
    try testing.expectEqual(State.failed, lookup.state);
    try testing.expectEqual(core.Error.Timeout, lookup.failure_of().err);
}

test "a lookup that saw a server failure fails with that rather than a timeout" {
    const config: Config = .{ .servers = &one_server, .attempts = 1 };
    var lookup = Lookup.init(&config, try Question.from_text("example.com.", .a), 1);
    lookup.flags.had_server_failure = true;
    lookup.next_server(1);
    try testing.expectEqual(core.Error.AllServersFailed, lookup.failure_of().err);
}

test "the candidate walk ends in NameNotFound, or NoData when a name existed" {
    const search = [_]Name{try Name.from_text("one.net")};
    const config: Config = .{ .servers = &one_server, .search = &search, .ndots = 1 };
    var lookup = Lookup.init(&config, try Question.from_text("host.example", .a), 1);
    try testing.expect(lookup.current.equal(&try Name.from_text("host.example")));
    lookup.next_candidate(1);
    try testing.expect(lookup.current.equal(&try Name.from_text("host.example.one.net")));
    lookup.next_candidate(2);
    try testing.expectEqual(core.Error.NameNotFound, lookup.failure_of().err);

    var second = Lookup.init(&config, try Question.from_text("host.example", .a), 1);
    second.flags.had_no_data = true;
    second.next_candidate(1);
    second.next_candidate(2);
    try testing.expectEqual(core.Error.NoData, second.failure_of().err);
}

test "rotation starts somewhere in the list, and a lookup without it starts at the first" {
    const rotating: Config = .{ .servers = &three_servers, .rotate = true };
    const plain: Config = .{ .servers = &three_servers };
    var seen: [three_servers.len]bool = @splat(false);
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        const lookup = Lookup.init(&rotating, try Question.from_text("example.com.", .a), seed);
        seen[lookup.server_index] = true;
        const fixed = Lookup.init(&plain, try Question.from_text("example.com.", .a), seed);
        try testing.expectEqual(@as(u8, 0), fixed.server_index);
    }
    for (seen) |reached| try testing.expect(reached);
}

test "cancel settles a lookup without an answer" {
    const config: Config = .{ .servers = &one_server };
    var lookup = Lookup.init(&config, try Question.from_text("example.com.", .a), 1);
    lookup.cancel();
    try testing.expect(lookup.is_settled());
    try testing.expectEqual(core.Error.Canceled, lookup.failure_of().err);
}

test "the size of a lookup slot is pinned" {
    // docs/design.md §9 budgets the memory a caller provides, and a caller sizing a table needs
    // this number. It is measured, not computed: Zig chooses the field order, so a field added
    // here can cost more than its own width in padding.
    try testing.expectEqual(@as(usize, 856), @sizeOf(Lookup));
    try testing.expectEqual(@as(usize, 284), @sizeOf(wire.Answers));
    try testing.expectEqual(@as(usize, 16), @sizeOf(entropy_module.Transaction));
}
