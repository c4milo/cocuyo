//! How a lookup ends in failure: the `Failure` it reports, and the cause of the last server failure
//! that it keeps (docs/design.md §5, The cause of a failure; §16 decision 45). Split from
//! `lookup.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const lookup_module = @import("lookup.zig");
const security = @import("lookup_security.zig");
const Lookup = lookup_module.Lookup;

pub const Failure = struct {
    err: core.Error,
    server_index: u8,
    /// The passes over the server list the lookup completed before it ended: `Config.attempts`
    /// when it ran out of them, as `Timeout` and `AllServersFailed` do, and zero when it ended in
    /// its first pass, as a name that does not exist usually does.
    attempts_made: u8,
    /// For `NameNotFound` and `NoData`, the TTL a cache may keep the negative answer for. Each
    /// negative response carries the SOA minimum it held (RFC 2308 §5), or zero when it held no
    /// SOA. A lookup that `Resolver.start` runs walks its search list itself, and reports the
    /// smallest of its candidates' negative TTLs, not the last one's alone: the end is kept under
    /// the name as asked, and it rests on every candidate's negative (docs/design.md §5).
    /// `AddressLookup` walks the search list with one absolute lookup per candidate, and its
    /// failure carries its last lookup's negative TTL alone, which the candidates before that one
    /// do not bound (docs/design.md §19 step 14). `NameLookup`'s failure carries its lookup's.
    /// Zero for every other failure, and zero is never cached (docs/design.md §18).
    negative_ttl_seconds: u32,
    /// The cause of the last server failure the lookup met, or null when no server failed it.
    /// `AllServersFailed` has one, unless the memory of docs/design.md §20 recalled it, and then
    /// `attempts_made` is zero (§17 question 89). `Timeout` never has one. Any other error has
    /// the last one, or null: a `NameNotFound` can carry the SERVFAIL of a server before the one
    /// that answered NXDOMAIN. A negative that the memory of docs/design.md §20 recalls has none.
    /// `AddressLookup` and `NameLookup` hand on the cause of the lookup whose end they report
    /// (docs/design.md §5, The cause of a failure).
    cause: ?Cause,
    /// For `NameNotFound` and `NoData`, whether the servers said they validated the denial, as
    /// `Answer.security` says of an answer (docs/design.md §25). `unchecked` for every other
    /// failure.
    security: core.Security,
};

/// What made a server fail a lookup, and that server. Each server failure replaces the cause the
/// lookup holds, and nothing clears it before the lookup ends (docs/design.md §5, The cause of a
/// failure; §16 decisions 45 and 51).
pub const Cause = struct {
    /// The server that gave the cause, an index into `Config.servers`, as `Failure.server_index`
    /// counts. That field names the server the lookup was on at its end, which after the last pass
    /// is the first of the order, so it does not name this one.
    server_index: u8,
    what: What,

    pub const What = union(enum) {
        /// The rcode of a response that failed the server, never NOERROR or NXDOMAIN. It is one
        /// of:
        ///
        /// - SERVFAIL, REFUSED, NOTIMP or BADVERS, while `Config.check_response` is on;
        /// - FORMERR to a query without EDNS0;
        /// - BADCOOKIE that advances the server: over a stream after its retry, or over DoH or DoQ.
        rcode: wire.Rcode,
        /// The reason that came with `on_tcp_failed` or `on_request_failed`.
        reason: Reason,
    };
};

/// Why a transport failed a lookup: what the caller passes `on_tcp_failed` and `on_request_failed`
/// (docs/design.md §5, The cause of a failure; §16 decision 51). Before `on_tcp_connected` a
/// stream's reason is `connect`, `handshake` or `local`, and after it the reason is `closed`. A
/// caller that cannot tell what failed passes `connect` before `on_tcp_connected`, `closed` after
/// it, and `closed` for a request.
pub const Reason = enum(u8) {
    /// The connect failed: refused, reset or unreachable, or the system gave up on it. Over DoH,
    /// each connection that the channel tried failed, and no server took part. Never over DoQ,
    /// which has no connect of its own.
    connect,
    /// The TLS handshake failed, or over DoQ the QUIC handshake: a certificate, a name or a pin
    /// that the check refused, an alert, a close before its end, or an ALPN other than `doq`. Over
    /// DoH, each connection that the channel tried failed after a server took part.
    handshake,
    /// No server took part: no socket, no free connection slot, no TCP at all, a session or a
    /// connection that could not start, or a submission that the loop refused before the
    /// connection was up.
    local,
    /// A connection that was up failed, or a send on it: the server closed or reset it, a send or
    /// a receive failed, or what the server sent broke the protocol. The one reason after
    /// `on_tcp_connected`.
    closed,
    /// Over DoH, a response that holds no DNS message: a status that is not 2xx (RFC 8484
    /// §4.2.1), content of another type or coding, or a response that colibri refused.
    status,
    /// Over DoH or DoQ, a stream that the server reset (RFC 9250 §4.3.2). Over DoH, also a request
    /// that the server processed none of, once a connection came up: a refused stream (RFC 9113
    /// §8.7), or a GOAWAY that left it unprocessed (§6.8).
    reset,
};

/// Whether `reason` may come with `on_tcp_failed` in the lookup's state: what failed before the
/// lookup was told the connection is up, and `closed` after. A handshake comes over TLS alone, and
/// an HTTP status or a reset stream never comes over a stream (docs/design.md §5, The cause of a
/// failure).
pub fn fits_stream(self: *const Lookup, reason: Reason) bool {
    assert(self.is_on_stream());
    return switch (reason) {
        .connect, .local => self.state == .connecting_tcp,
        .handshake => self.state == .connecting_tcp and self.config.uses_tls(),
        .closed => self.state != .connecting_tcp,
        .status, .reset => false,
    };
}

/// Whether `reason` may come with `on_request_failed`: `connect` and `status` over DoH alone, since
/// QUIC has no connect of its own and DoQ no HTTP status (docs/design.md §5, The cause of a
/// failure).
pub fn fits_request(self: *const Lookup, reason: Reason) bool {
    assert(self.config.sends_requests());
    return switch (reason) {
        .connect, .status => self.config.transport() == .https,
        .handshake, .local, .closed, .reset => true,
    };
}

/// The cause as a lookup holds it: three octets, where a `?Cause` takes four. So a `Lookup` stays
/// at 3,072 octets (docs/design.md §9; §16 decision 51). `none` holds until a server fails the
/// lookup, and `get` gives the `?Cause` that `Failure.cause` reports.
pub const Held = struct {
    server_index: u8,
    what: union(enum) { none, rcode: wire.Rcode, reason: Reason },

    pub const none: Held = .{ .server_index = 0, .what = .none };

    /// `what` from the server at `server_index`.
    pub fn of(server_index: u8, what: Cause.What) Held {
        return switch (what) {
            .rcode => |rcode| .{ .server_index = server_index, .what = .{ .rcode = rcode } },
            .reason => |reason| .{ .server_index = server_index, .what = .{ .reason = reason } },
        };
    }

    pub fn get(held: Held) ?Cause {
        // `none` names no server.
        assert(held.what != .none or held.server_index == 0);
        return switch (held.what) {
            .none => null,
            .rcode => |rcode| .{ .server_index = held.server_index, .what = .{ .rcode = rcode } },
            .reason => |reason| .{ .server_index = held.server_index, .what = .{ .reason = reason } },
        };
    }
};

/// Keeps `what` as the cause, from the server the lookup is on (docs/design.md §5, The cause of a
/// failure).
pub fn keep(self: *Lookup, what: Cause.What) void {
    assert(!self.is_settled());
    self.cause = Held.of(self.server_slot(), what);
    assert(self.cause.server_index < self.config.servers.len);
}

/// `Lookup.failure_of`: what `.failed` carries.
pub fn failure_of(self: *const Lookup) Failure {
    assert(self.state == .failed);
    // `AllServersFailed` rests on a server that failed the lookup, and `Timeout` on none. A cause
    // names a server of the configuration. A failure that the memory recalled made no pass and
    // has no cause (docs/design.md §17 question 89); one that went out ends after its last pass.
    const passes_end = self.failure == core.Error.AllServersFailed or self.failure == core.Error.Timeout;
    assert(!passes_end or self.round == 0 or self.round == self.config.attempts);
    assert(self.failure != core.Error.AllServersFailed or self.cause.what != .none or self.round == 0);
    assert(self.failure != core.Error.Timeout or self.cause.what == .none);
    assert(self.cause.server_index < self.config.servers.len or self.cause.what == .none);
    const negative = self.failure == core.Error.NameNotFound or self.failure == core.Error.NoData;
    return .{
        .err = self.failure,
        // A lookup with no server to have been on reports the first.
        .server_index = if (self.config.server_count() == 0) 0 else self.server_slot(),
        .attempts_made = self.round,
        .negative_ttl_seconds = if (negative) self.negative_ttl_seconds else 0,
        .cause = self.cause.get(),
        .security = if (negative) security.of(self) else .unchecked,
    };
}

// Tests. The fake server of fixtures.zig answers whatever the lookup asked (docs/design.md §5,
// The cause of a failure).

const testing = std.testing;
const Config = core.Config;
const Verdict = lookup_module.Verdict;
const Action = lookup_module.Action;
const fixtures = @import("fixtures.zig");
const recall = @import("lookup_recall.zig");
const Harness = fixtures.Harness;

const seed = fixtures.seed;
/// One server and one pass: each server failure ends the lookup.
const one_try: Config = .{ .servers = &fixtures.servers_one, .attempts = 1 };

/// Polls the lookup, which must have failed with `err`, and requires `cause` of its failure.
fn expect_failure(harness: *Harness, err: core.Error, cause: ?Cause) !void {
    const failure = harness.poll().failed;
    try testing.expectEqual(err, failure.err);
    try testing.expectEqual(cause, failure.cause);
}

/// Lets the wait of the try in flight run out, and returns what the poll at its deadline asks.
fn run_out(harness: *Harness) Action {
    harness.now_ns = harness.lookup.deadline_ns - 1;
    return harness.poll();
}

/// Sends the query over UDP and hands the current server's `reply` to the lookup.
fn ask(harness: *Harness, reply: fixtures.Reply) !void {
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(reply, harness.lookup.server()));
}

/// The cause `what` from the server at `server_index`.
fn from(server_index: u8, what: Cause.What) ?Cause {
    return .{ .server_index = server_index, .what = what };
}

test "each rcode that fails a server is the cause that AllServersFailed carries" {
    const rcodes = [_]wire.Rcode{ .server_failure, .refused, .not_implemented, .bad_vers };
    for (rcodes) |rcode| {
        var harness: Harness = .{ .config = one_try };
        try harness.start("example.com.", .a, seed);
        try ask(&harness, .{ .rcode = rcode });
        try expect_failure(&harness, core.Error.AllServersFailed, from(0, .{ .rcode = rcode }));
    }
}

test "FORMERR to a query without EDNS0 is the cause, and FORMERR to one with it is none" {
    var harness: Harness = .{ .config = one_try };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.format_error);
    // The same server, asked again without the OPT record: a retry, and no failure (RFC 6891
    // §6.2.2).
    try testing.expectEqual(@as(?Cause, null), harness.lookup.cause.get());
    try ask(&harness, fixtures.format_error);
    try expect_failure(&harness, core.Error.AllServersFailed, from(0, .{ .rcode = .format_error }));
}

/// A TLS server, for the one reason that a stream gives over TLS alone.
const servers_tls = [_]core.Server{.{ .endpoint = fixtures.servers_one[0].endpoint, .tls = .{ .name = core.Name.from_text("dns.example.") catch unreachable } }};

test "a connection that fails keeps the reason given: what failed before it is up, and closed after" {
    // A caller that owns its sockets passes the reason too (docs/design.md §5, The cause of a
    // failure). A handshake comes over TLS alone.
    const plain: Config = .{ .servers = &fixtures.servers_one, .use_tcp = true, .attempts = 1 };
    const over_tls: Config = .{ .servers = &servers_tls, .attempts = 1 };
    const cases = [_]struct { config: Config, reason: Reason }{
        .{ .config = plain, .reason = .connect },
        .{ .config = plain, .reason = .local },
        .{ .config = over_tls, .reason = .connect },
        .{ .config = over_tls, .reason = .handshake },
        .{ .config = over_tls, .reason = .local },
    };
    for (cases) |case| {
        var connecting: Harness = .{ .config = case.config };
        try connecting.start("example.com.", .a, seed);
        try testing.expect(connecting.poll() == .connect_tcp);
        connecting.lookup.on_tcp_failed(case.reason, connecting.now_ns);
        try expect_failure(&connecting, core.Error.AllServersFailed, from(0, .{ .reason = case.reason }));
    }
    // Up, before the query went and after it: whatever failed, the reason is `closed`.
    for ([_]Config{ plain, over_tls }) |config| {
        for ([_]bool{ false, true }) |sent| {
            var up: Harness = .{ .config = config };
            try up.start("example.com.", .a, seed);
            try testing.expect(up.poll() == .connect_tcp);
            up.lookup.on_tcp_connected(up.now_ns);
            if (sent) _ = up.send_over_tcp();
            up.lookup.on_tcp_failed(.closed, up.now_ns);
            try expect_failure(&up, core.Error.AllServersFailed, from(0, .{ .reason = .closed }));
        }
    }
}

test "a reason fits its call and the state of the lookup, and no other" {
    var plain: Harness = .{ .config = .{ .servers = &fixtures.servers_one, .use_tcp = true } };
    try plain.start("example.com.", .a, seed);
    try testing.expect(plain.poll() == .connect_tcp);
    const before = [_]bool{ true, false, true, false, false, false };
    for (std.enums.values(Reason), before) |reason, fits| {
        try testing.expectEqual(fits, fits_stream(&plain.lookup, reason));
    }
    plain.lookup.on_tcp_connected(plain.now_ns);
    for (std.enums.values(Reason)) |reason| {
        try testing.expectEqual(reason == .closed, fits_stream(&plain.lookup, reason));
    }
    var over_tls: Harness = .{ .config = .{ .servers = &servers_tls } };
    try over_tls.start("example.com.", .a, seed);
    try testing.expect(over_tls.poll() == .connect_tcp);
    try testing.expect(fits_stream(&over_tls.lookup, .handshake));
    // Over DoQ no connect and no HTTP status, and over DoH each reason.
    const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    const quic: core.Tls = servers_tls[0].tls.?;
    var over_https: Harness = .{ .config = .{ .servers = &.{.{ .endpoint = servers_tls[0].endpoint, .https = https }} } };
    try over_https.start("example.com.", .a, seed);
    var over_quic: Harness = .{ .config = .{ .servers = &.{.{ .endpoint = servers_tls[0].endpoint, .quic = quic }} } };
    try over_quic.start("example.com.", .a, seed);
    for (std.enums.values(Reason)) |reason| {
        try testing.expect(fits_request(&over_https.lookup, reason));
        try testing.expectEqual(reason != .connect and reason != .status, fits_request(&over_quic.lookup, reason));
    }
}

test "the last server failure is the cause, and a silent server after it leaves it standing" {
    var harness: Harness = .{ .config = .{ .servers = &fixtures.servers_three, .attempts = 1, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.server_failure);
    try ask(&harness, .{ .rcode = .refused });
    // The third server says nothing. Silence is no cause, and it clears none (§16 decision 25).
    _ = harness.send();
    const last = run_out(&harness).failed;
    try testing.expectEqual(core.Error.AllServersFailed, last.err);
    try testing.expectEqual(from(1, .{ .rcode = .refused }), last.cause);
}

test "the cause names the server that gave it, after a later pass moved the lookup to another server" {
    // The second server fails the first pass, and each try of the second pass runs out. The
    // lookup ends on the first server, and the cause names the second (§16 decision 51).
    var harness: Harness = .{ .config = .{ .servers = &fixtures.servers_two, .attempts = 2, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expect(run_out(&harness) == .send_udp);
    harness.lookup.on_sent(harness.now_ns);
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, harness.lookup.server()));
    _ = harness.send();
    try testing.expect(run_out(&harness) == .send_udp);
    harness.lookup.on_sent(harness.now_ns);
    const failure = run_out(&harness).failed;
    try testing.expectEqual(core.Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(u8, 0), failure.server_index);
    try testing.expectEqual(from(1, .{ .rcode = .server_failure }), failure.cause);
}

test "the cause names the server in the configuration, and not its place in the lookup's order" {
    // The first server failed an earlier lookup, so this one asks the second first (docs/design.md
    // §19 step 12). That server fails it, and the cause names it as `Config.servers` does.
    var harness: Harness = .{ .config = .{ .servers = &fixtures.servers_two, .attempts = 1, .failover_retry_chance = 0 } };
    try harness.start("example.com.", .a, seed);
    harness.servers.record_failure(0, 0);
    _ = harness.send();
    try testing.expectEqual(@as(u8, 1), harness.lookup.server_slot());
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, harness.lookup.server()));
    _ = harness.send();
    try testing.expectEqual(from(1, .{ .rcode = .server_failure }), run_out(&harness).failed.cause);
}

test "a stream that fails after an rcode replaces it, and an rcode after a stream replaces that" {
    const config: Config = .{ .servers = &fixtures.servers_two, .attempts = 1, .failover_retry_chance = 0 };
    var rcode_first: Harness = .{ .config = config };
    try rcode_first.start("example.com.", .a, seed);
    try ask(&rcode_first, fixtures.server_failure);
    // The second server's answer is truncated, and its connection fails.
    try ask(&rcode_first, fixtures.truncated);
    try testing.expect(rcode_first.poll() == .connect_tcp);
    rcode_first.lookup.on_tcp_failed(.connect, rcode_first.now_ns);
    try expect_failure(&rcode_first, core.Error.AllServersFailed, from(1, .{ .reason = .connect }));

    var stream_first: Harness = .{ .config = config };
    try stream_first.start("example.com.", .a, seed);
    try ask(&stream_first, fixtures.truncated);
    try testing.expect(stream_first.poll() == .connect_tcp);
    stream_first.lookup.on_tcp_connected(stream_first.now_ns);
    _ = stream_first.send_over_tcp();
    stream_first.lookup.on_tcp_failed(.closed, stream_first.now_ns);
    try ask(&stream_first, fixtures.server_failure);
    try expect_failure(&stream_first, core.Error.AllServersFailed, from(1, .{ .rcode = .server_failure }));
}

test "a lookup that no server failed carries no cause" {
    const config: Config = .{ .servers = &fixtures.servers_two, .attempts = 1, .failover_retry_chance = 0 };
    // Every try ran out: Timeout.
    var silent: Harness = .{ .config = config };
    try silent.start("example.com.", .a, seed);
    _ = silent.send();
    try testing.expect(run_out(&silent) == .send_udp);
    silent.lookup.on_sent(silent.now_ns);
    try testing.expectEqual(@as(?Cause, null), run_out(&silent).failed.cause);
    // Every send failed: the loop or the local stack refused it, and no server said a word.
    var unsent: Harness = .{ .config = config };
    try unsent.start("example.com.", .a, seed);
    for (0..config.servers.len) |_| {
        try testing.expect(unsent.poll() == .send_udp);
        unsent.lookup.on_send_failed(unsent.now_ns);
    }
    try expect_failure(&unsent, core.Error.Timeout, null);
    // A name that does not exist, a cancel, and no server at all.
    var missing: Harness = .{ .config = config };
    try missing.start("example.com.", .a, seed);
    try ask(&missing, fixtures.name_error);
    try expect_failure(&missing, core.Error.NameNotFound, null);
    var cancelled: Harness = .{ .config = config };
    try cancelled.start("example.com.", .a, seed);
    _ = cancelled.send();
    cancelled.lookup.cancel();
    try expect_failure(&cancelled, core.Error.Canceled, null);
    var serverless: Harness = .{ .config = .{ .servers = &.{} } };
    try serverless.start("example.com.", .a, seed);
    try expect_failure(&serverless, core.Error.NoServers, null);
}

test "a retry is no cause: FORMERR with EDNS0, a first BADCOOKIE and TC=1, then silence, is Timeout" {
    const retries = [_]fixtures.Reply{ fixtures.format_error, fixtures.bad_cookie_fresh, fixtures.truncated };
    for (retries) |reply| {
        var harness: Harness = .{ .config = one_try };
        try harness.start("example.com.", .a, seed);
        try ask(&harness, reply);
        try testing.expectEqual(@as(?Cause, null), harness.lookup.cause.get());
        // Asked again, over UDP or over the stream, and the server says nothing.
        if (harness.poll() == .connect_tcp) harness.lookup.on_tcp_connected(harness.now_ns) else harness.lookup.on_sent(harness.now_ns);
        const last = run_out(&harness);
        if (last == .failed) {
            try testing.expectEqual(core.Error.Timeout, last.failed.err);
            try testing.expectEqual(@as(?Cause, null), last.failed.cause);
        } else {
            try testing.expect(last == .send_tcp);
            harness.lookup.on_sent(harness.now_ns);
            try testing.expectEqual(@as(?Cause, null), run_out(&harness).failed.cause);
        }
    }
}

test "an error but AllServersFailed carries the last server failure too" {
    // The first server fails, and the second says the name does not exist (RFC 1035 §4.1.1).
    const config: Config = .{ .servers = &fixtures.servers_two, .failover_retry_chance = 0 };
    var missing: Harness = .{ .config = config };
    try missing.start("example.com.", .a, seed);
    try ask(&missing, fixtures.server_failure);
    try ask(&missing, fixtures.name_error);
    try expect_failure(&missing, core.Error.NameNotFound, from(0, .{ .rcode = .server_failure }));
    // The first server's connection fails, and the caller gives up.
    var cancelled: Harness = .{ .config = .{ .servers = &fixtures.servers_two, .use_tcp = true, .failover_retry_chance = 0 } };
    try cancelled.start("example.com.", .a, seed);
    try testing.expect(cancelled.poll() == .connect_tcp);
    cancelled.lookup.on_tcp_failed(.connect, cancelled.now_ns);
    cancelled.lookup.cancel();
    try expect_failure(&cancelled, core.Error.Canceled, from(0, .{ .reason = .connect }));
}

test "a server error taken as the answer under check_response off is the error, and no cause" {
    var harness: Harness = .{ .config = .{ .servers = &fixtures.servers_one, .check_response = false } };
    try harness.start("example.com.", .a, seed);
    try ask(&harness, fixtures.server_failure);
    try expect_failure(&harness, core.Error.ServerFailure, null);
}

test "a negative that the memory recalls has no cause" {
    // The memory keeps the negative and its TTL alone, and no server was asked (docs/design.md
    // §20).
    var harness: Harness = .{ .config = one_try };
    try harness.start("example.com.", .a, seed);
    recall.failure(&harness.lookup, core.Error.NameNotFound, fixtures.cached_ttl_seconds);
    try expect_failure(&harness, core.Error.NameNotFound, null);
}

test "the size of a failure is pinned, and an answer outweighs it" {
    // 8 octets until the cause came on 2026-10-17, and 12 until the security of a negative came
    // on 2026-10-31. An `Action` holds the larger `Answer`, so it kept its size (docs/design.md
    // §16 decision 45, §25).
    try testing.expectEqual(@as(usize, 16), @sizeOf(Failure));
    try testing.expect(@sizeOf(Failure) < @sizeOf(lookup_module.Answer));
    // The lookup holds a cause in three octets, where a `?Cause` takes four (§16 decision 51).
    try testing.expectEqual(@as(usize, 3), @sizeOf(Held));
    try testing.expectEqual(@as(usize, 4), @sizeOf(?Cause));
}
