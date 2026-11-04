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
//! - The name is held uncased. The case is applied when a query is built, and a response's echo
//!   is read against it in place, both from `transaction.case_seed`. One name is stored rather
//!   than two. Whether the query mixed the case at all is recorded when it is built, since a
//!   server that lowercases the name is asked in lowercase (§7), and another lookup can mark it
//!   in between.
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
const servers_module = @import("servers.zig");
const Servers = servers_module.Servers;

const policy = @import("lookup_policy.zig");
const poll_module = @import("lookup_poll.zig");
const init_module = @import("lookup_init.zig");
const response_module = @import("lookup_response.zig");
const cut_module = @import("lookup_response_cut.zig");
const request_module = @import("lookup_request.zig");
const security = @import("lookup_security.zig");
const failure_module = @import("lookup_failure.zig");
const bound = @import("lookup_bound.zig");
const validate_module = @import("lookup_validate.zig");
const tries_module = @import("lookup_tries.zig");
const earlier_module = @import("lookup_earlier.zig");
pub const Validator = validate_module.Validator;
pub const Try = tries_module.Try;

pub const State = enum {
    /// A query is ready to be sent to the current server over UDP, or over DoH or DoQ as one
    /// request (docs/design.md §22, §23).
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
    /// A validating lookup waits for the keys a message needs, which the table's walk fetches. It
    /// has no deadline (docs/design.md §25, step 11).
    awaiting_keys,
};

const types = @import("lookup_types.zig");
pub const Action = types.Action;
pub const Verdict = types.Verdict;
pub const Answer = types.Answer;
pub const Flags = types.Flags;

pub const Failure = failure_module.Failure;
pub const Cause = failure_module.Cause;
pub const Reason = failure_module.Reason;

pub const Lookup = struct {
    // The fields `poll`, the timer and the response check read. They are declared together, but
    // Zig orders a struct's fields as it likes, and it does reorder these: the measurement that
    // pinned a lookup's first size found `state` well past the names (docs/design.md §9). What
    // keeps the demultiplexer cheap is the side table of §11, not this declaration order.
    state: State,
    flags: Flags,
    /// Rule 3's conjunction (docs/design.md §25, Stage A), Stage B's, and the waits for keys of
    /// the current name (§25, step 11), in the one octet Stage A's took alone, so a lookup grows by
    /// nothing for Stage B (docs/performance.md).
    conjunctions: security.Conjunctions,
    /// Where the walk over the servers stands: a position in `order`, not a configured server.
    server_index: u8,
    round: u8,
    candidate_index: u8,
    cname_hops: u8,
    /// The configured servers in the order this lookup asks them: sorted by their failures,
    /// rotated among the equals, a retry promoted to the front (§19 step 12, `lookup_order.zig`).
    order: [core.limits.servers_max]u8,
    /// The queries sent for the current name to each position in `order`, over each transport,
    /// which RFC 9520 §3.1 bounds (docs/design.md §5; §16 decision 58).
    sends: bound.Sends,
    transaction: entropy_module.Transaction,
    deadline_ns: u64,
    /// When the current transaction's query went out: what a response accepted for it measures
    /// its server's latency from, and what a deadline that passes first measures the wait it used
    /// from (docs/design.md §5).
    sent_at_ns: u64,
    /// When the current try's wait began: its send, or the later pass that waits on it again over
    /// a stream (docs/design.md §5, Tries kept open). A try that runs out is a sample as long as
    /// that wait.
    waited_from_ns: u64,
    /// Whether the lookup reads a response to an earlier try: it closes that try alone where the
    /// current try's would move the lookup on (`lookup_earlier.zig`).
    hearing_earlier: bool,
    /// The last instant the caller passed in, so a clock going backwards is caught.
    now_ns_seen: u64,
    entropy: entropy_module.Entropy,
    failure: core.Error,
    /// The cause of the last server failure, which `Failure.cause` reports. It is `none` until a
    /// server fails the lookup, and nothing clears it after. `Cause` lists each way a server
    /// fails it: an rcode, or the reason a connection or a request failed. Whether there is one
    /// decides `AllServersFailed` against `Timeout` (docs/design.md §5).
    cause: failure_module.Held,
    /// The INFO-CODE of the last response the lookup took whose rcode was not NOERROR and that
    /// carried an extended error, which `Failure.extended_error` reports while
    /// `has_extended_error` says one came (§16 decision 64). Two fields and not a `?u16`, which
    /// takes four octets and would grow the lookup by eight: INFO-CODE 0 is a code (RFC 8914
    /// §4.1), so no value of its own can mean none.
    extended_error: u16,
    has_extended_error: bool,
    /// The smallest negative TTL of the candidates the search walk moved past: what
    /// `Failure.negative_ttl_seconds` reports, and what bounds `Answer.ttl_seconds`
    /// (docs/design.md §5). The largest TTL there is until a candidate answers NXDOMAIN or
    /// NODATA, so it bounds nothing before then.
    negative_ttl_seconds: u32,
    /// The smallest TTL of the CNAMEs earlier messages moved the chain through, while
    /// `cname_hops` is above zero: what the chain's end is reached through bounds it.
    chain_ttl_seconds: u32,
    config: *const Config,
    /// The per-server state shared with every other lookup of the caller: the cookies of
    /// RFC 7873 (docs/design.md §19 step 10).
    servers: *Servers,
    /// The COOKIE option the query last built carries, and its client cookie when it carries one:
    /// what check 6 compares a response with (docs/design.md §7), whatever another lookup taught
    /// the server since. "It is RECOMMENDED that a client keep the Client Cookie it is expecting in
    /// a reply until there is no longer an outstanding request associated with that Client
    /// Cookie" (RFC 7873 §7.1).
    cookie_form: servers_module.CookieForm,
    cookie_client: [core.constants.cookie_client_bytes]u8,

    // The names and the records: the bulk of a slot.
    question: Question,
    /// The name being asked about now: a search candidate, or where the CNAME chain has reached.
    /// Held uncased; the case is applied on the way out and checked on the way back.
    current: Name,
    answers: wire.Answers,
    /// The CNAME links the chain moved through to reach `current`, one for each of `cname_hops`
    /// (docs/design.md §5, The chain a lookup keeps).
    aliases: core.Aliases,
    /// The earlier tries of the current name still open (docs/design.md §5, Tries kept open).
    tries: tries_module.Tries,

    pub fn init(config: *const Config, servers: *Servers, question: Question, seed: u64) Lookup {
        var lookup: Lookup = undefined;
        lookup.init_in_place(config, servers, question, seed);
        return lookup;
    }

    /// `init` into memory the caller already owns, a slot of `Resolver` above all: the lookup is
    /// three kilooctets since §19 step 9, and a value built in a local and returned is copied
    /// into its destination, which §11 measured at forty nanoseconds a start.
    pub fn init_in_place(
        self: *Lookup,
        config: *const Config,
        servers: *Servers,
        question: Question,
        seed: u64,
    ) void {
        init_module.init_in_place(self, config, servers, question, seed);
    }

    pub fn poll(self: *Lookup, now_ns: u64, out: []u8) Action {
        return poll_module.poll(self, now_ns, out);
    }

    /// A datagram, or a message on a stream: the current try's response first, then one of an
    /// earlier try still open, the newest first (docs/design.md §5, Tries kept open).
    pub fn on_response(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
        return response_module.on_response(self, message, from, now_ns);
    }

    /// A datagram longer than the caller's buffer, which the kernel cut and marked. Over UDP, one
    /// that passes the checks of a cut datagram (§7) sends the lookup to TCP.
    pub fn on_datagram_cut(self: *Lookup, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
        if (cut_module.on_datagram_cut(self, message, from, now_ns) == .accepted) return .accepted;
        return earlier_module.on_datagram_cut(self, message, from, now_ns);
    }

    /// The caller sent what `poll` asked for.
    pub fn on_sent(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .query_ready or self.state == .tcp_ready);
        bound.count_sent(self);
        self.state = switch (self.state) {
            .query_ready => .awaiting_udp,
            .tcp_ready => .awaiting_tcp,
            else => unreachable,
        };
        // A try starts at its send, and no reply to it has marked its server yet (§16 decision 50).
        self.flags.reply_marked = false;
        self.sent_at_ns = now_ns;
        self.waited_from_ns = now_ns;
        poll_module.arm(self, now_ns);
    }

    /// The send failed. The server is no better than one that did not answer.
    pub fn on_send_failed(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .query_ready or self.state == .tcp_ready);
        self.servers.record_failure(self.server_slot(), now_ns);
        self.next_server(now_ns);
    }

    /// The answer to a request over DoH or DoQ, and its `Age` in seconds, zero over DoQ
    /// (docs/design.md §22, §23).
    pub fn on_request_answer(
        self: *Lookup,
        transaction: u16,
        message: []const u8,
        age_seconds: u32,
        now_ns: u64,
    ) Verdict {
        return request_module.on_request_answer(self, transaction, message, age_seconds, now_ns);
    }

    /// A request over DoH or DoQ ended without an answer, for `reason` (docs/design.md §22, §23).
    pub fn on_request_failed(self: *Lookup, transaction: u16, reason: Reason, now_ns: u64) void {
        request_module.on_request_failed(self, transaction, reason, now_ns);
    }

    pub fn on_tcp_connected(self: *Lookup, now_ns: u64) void {
        self.see(now_ns);
        assert(self.state == .connecting_tcp);
        self.state = .tcp_ready;
        poll_module.arm(self, now_ns);
    }

    /// The connection to the configured server `configured` failed, for `reason`: refused, reset, or
    /// its handshake failed. The server refused the lookup, which counts as SERVFAIL does
    /// (docs/design.md §16 decision 25). The reason is the cause, and it must fit the state (§5,
    /// The cause of a failure). It closes every try open on that connection. A lookup on another
    /// server keeps waiting there (§5, Tries kept open).
    pub fn on_tcp_failed(self: *Lookup, configured: u8, reason: Reason, now_ns: u64) void {
        self.see(now_ns);
        assert(configured < self.config.servers.len);
        if (self.is_settled()) return;
        if (!self.is_on_stream() or self.server_slot() != configured) {
            return earlier_module.on_connection_failed(self, configured, reason, now_ns);
        }
        assert(failure_module.fits_stream(self, reason));
        _ = earlier_module.close_streams_at(self, self.server_index);
        self.servers.record_failure(self.server_slot(), now_ns);
        failure_module.keep(self, .{ .reason = reason });
        self.next_server(now_ns);
    }

    /// The walk for the keys a message needed ended with them held, or with an insecure
    /// delegation: the lookup asks its question again.
    pub fn on_keys_ready(self: *Lookup, now_ns: u64) void {
        validate_module.on_keys_ready(self, now_ns);
    }

    /// The walk failed, and the lookup ends with its failure.
    pub fn on_keys_failed(self: *Lookup, walked: core.validation.Walked, now_ns: u64) void {
        validate_module.on_keys_failed(self, walked, now_ns);
    }

    /// Gives up on the lookup. A response that arrives afterwards is ignored like any other.
    pub fn cancel(self: *Lookup) void {
        assert(self.state != .done);
        self.fail(core.Error.Canceled);
        assert(self.state == .failed);
    }

    /// Whether the lookup is on a stream: waiting for a connection, ready to send on one, or
    /// waiting for its answer. What a caller holding one connection for several lookups asks
    /// before it tells a lookup the connection is up or gone (docs/design.md §19 step 13).
    pub fn is_on_stream(self: *const Lookup) bool {
        return switch (self.state) {
            .connecting_tcp, .tcp_ready, .awaiting_tcp => true,
            .query_ready, .awaiting_udp, .tcp_needed, .done, .failed => false,
            .awaiting_keys => false,
        };
    }

    pub fn is_settled(self: *const Lookup) bool {
        return self.state == .done or self.state == .failed;
    }

    /// Whether the lookup is waiting for an instant to arrive, which is what a table's timer is
    /// armed for. Since 2026-10-24 `tcp_ready` waits for the deadline that `on_tcp_connected`
    /// arms, and the query's send does not stop it (docs/design.md §5; §16 decision 52).
    pub fn is_waiting(self: *const Lookup) bool {
        return switch (self.state) {
            .awaiting_udp, .awaiting_tcp, .connecting_tcp, .tcp_ready => true,
            .query_ready, .tcp_needed, .done, .failed => false,
            // A wait for keys has no deadline: the table's walk ends it.
            .awaiting_keys => false,
        };
    }

    /// The current server: the one a query goes to and the only one a response may come from.
    pub fn server(self: *const Lookup) Endpoint {
        return self.config.servers[self.server_slot()].endpoint;
    }

    /// Where a TCP connection to the current server goes: its own port when it has one
    /// (docs/design.md §19 step 11).
    pub fn server_tcp(self: *const Lookup) Endpoint {
        return self.config.servers[self.server_slot()].tcp_endpoint();
    }

    /// The configured server the walk is on: what `Servers` and `Failure` are indexed by.
    pub fn server_slot(self: *const Lookup) u8 {
        assert(self.server_index < self.config.server_count());
        const slot = self.order[self.server_index];
        assert(slot < self.config.servers.len);
        return slot;
    }

    /// Whether the query may carry a COOKIE option: it rides in the OPT record, so there is none
    /// without it (RFC 7873 §4), and none over DoH or DoQ (docs/design.md §22, §23). Which one
    /// it carries is the server's state to say (`lookup_cookie.zig`).
    pub fn carries_cookie(self: *const Lookup) bool {
        return self.flags.edns_enabled and !self.config.sends_requests();
    }

    /// The name as the query last built carries it: the current name, with its case set from this
    /// transaction's seed when that query mixed it, in lowercase when 0x20 is on and that query's
    /// server lowercases the name, and as it is held otherwise. The query is built with it, and
    /// check 5 reads a response against the same three branches in place without building it
    /// (`lookup_response_case.zig`), so the check that it is `current` in another case runs at
    /// the build (§16 decision 5, the ruling of 2026-10-09).
    pub fn cased_name(self: *const Lookup) Name {
        var name = self.current;
        if (self.flags.query_mixed) {
            wire.name.mix_case(&name, self.transaction.case_seed);
        } else if (self.flags.mix_case) {
            // A server that answered a mixed name in lowercase is asked in lowercase (§7).
            name.fold_case();
        }
        assert(name.equal(&self.current));
        return name;
    }

    /// Whether a query built now mixes the case: the lookup may, and its server has not been
    /// marked as one that lowercases the name (docs/design.md §7).
    pub fn mixes_case(self: *const Lookup) bool {
        assert(self.flags.mix_case or !self.flags.query_mixed);
        return self.flags.mix_case and !self.servers.changes_case(self.server_slot());
    }

    /// Records the instant, and asserts the caller's clock never goes backwards.
    pub fn see(self: *Lookup, now_ns: u64) void {
        assert(now_ns >= self.now_ns_seen);
        self.now_ns_seen = now_ns;
    }

    /// Moves to the next server with a query left, then to the next pass, then gives up
    /// (`lookup_bound.zig`).
    pub fn next_server(self: *Lookup, now_ns: u64) void {
        bound.next_server(self, now_ns);
    }

    /// Moves to the next candidate of the search walk, then gives up.
    pub fn next_candidate(self: *Lookup, now_ns: u64) void {
        assert(!self.is_settled());
        self.flags.cookie_retried = false;
        self.flags.edns_enabled = true;
        self.server_index = 0;
        self.round = 0;
        // Another name, so another query, and no retry of the last (RFC 9520 §3.1).
        self.sends = .{};
        self.conjunctions.key_asks = 0;
        // A walk with no candidate left fails with the chain it had: the chain resets only when
        // another candidate is taken (docs/design.md §5, The chain a lookup keeps).
        self.take_candidate(self.candidate_index + 1);
        if (self.state == .query_ready) self.restart(now_ns);
    }

    /// Starts a new transaction for the current name on the current server: a fresh id, port hint
    /// and case pattern, which is what a re-query must have (docs/design.md §7).
    pub fn restart(self: *Lookup, now_ns: u64) void {
        assert(!self.is_settled());
        const number = self.transaction.number +% 1;
        self.transaction = self.entropy.transaction();
        self.transaction.number = number;
        // Every query on a stream when the configuration says so (§19 step 11) or its servers
        // speak TLS (§21): the connection comes first.
        self.state = if (self.config.streams_only()) .tcp_needed else .query_ready;
        self.deadline_ns = now_ns;
    }

    /// Takes the candidate at `index`, skipping any that cannot be encoded, and fails when the
    /// walk is over.
    pub fn take_candidate(self: *Lookup, index: u8) void {
        var at = index;
        while (at <= core.limits.candidates_max) {
            switch (policy.candidate(self.config, &self.question, at)) {
                .name => |name| {
                    self.candidate_index = at;
                    self.current = name;
                    self.state = .query_ready;
                    self.flags.aliased = false;
                    self.cname_hops = 0;
                    self.aliases.clear();
                    // Another name: an answer to a try of the last would answer another question.
                    self.tries.clear();
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
        assert(at > core.limits.candidates_max);
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
        const storage = self.question.kind.storage();
        return .{
            .kind = self.question.kind,
            .addresses = if (storage == .addresses) self.answers.addresses() else &.{},
            .names = if (storage == .names) self.answers.names() else &.{},
            .records = if (storage == .rdata) self.answers.records() else null,
            .record_count = if (storage == .rdata) self.answers.count else 0,
            .canonical_name = if (self.flags.aliased) &self.current else null,
            .aliases = &self.aliases,
            .ttl_seconds = self.answers.ttl_seconds,
            .truncated = self.answers.truncated,
            .security = security.of(self),
        };
    }

    pub fn failure_of(self: *const Lookup) Failure {
        return failure_module.failure_of(self);
    }

    /// The lookup as the earlier try at `index` left it: its id, server, case and cookie in the
    /// lookup's own fields. What a test or a replay builds that try's reply from.
    pub fn viewed_as(self: *const Lookup, index: usize) Lookup {
        assert(index < self.tries.count);
        var view = self.*;
        tries_module.load(&view, index);
        return view;
    }
};
