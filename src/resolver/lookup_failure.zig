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
    /// The INFO-CODE (RFC 8914 §2) of the last response the lookup took whose rcode was not
    /// NOERROR and that carried an extended error option, or null when none did. It says why, as
    /// a validating server's SERVFAIL for bogus data does, and it changes nothing a lookup does
    /// (RFC 8914 §3; docs/design.md §16 decision 64).
    extended_error: ?u16,
    /// For `NoData` and `NameNotFound` after a CNAME, the chain's end that has no data, or null when
    /// no CNAME was followed (docs/design.md §5, The chain a lookup keeps).
    canonical_name: ?*const core.Name = null,
    /// The CNAME links that reached `canonical_name`, in the lookup's own storage, as
    /// `Answer.aliases` holds them.
    aliases: *const core.Aliases = &core.Aliases.none,

    /// The failure without its chain, for a caller that keeps it past the lookup's `release`:
    /// the chain points into the lookup's slot, which the release frees. `AddressLookup` and
    /// `NameLookup` report the end of their own walk, and no lookup's chain.
    pub fn detached(self: Failure) Failure {
        var kept = self;
        kept.canonical_name = null;
        kept.aliases = &core.Aliases.none;
        assert(kept.aliases.count == 0);
        return kept;
    }
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
        /// A message the validator called bogus (docs/design.md §25, step 11).
        bogus,
        /// The walk for a message's keys: every server of one of its questions failed.
        keys,
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
    what: union(enum) { none, rcode: wire.Rcode, reason: Reason, bogus, keys },

    pub const none: Held = .{ .server_index = 0, .what = .none };

    /// `what` from the server at `server_index`.
    pub fn of(server_index: u8, what: Cause.What) Held {
        return switch (what) {
            .rcode => |rcode| .{ .server_index = server_index, .what = .{ .rcode = rcode } },
            .reason => |reason| .{ .server_index = server_index, .what = .{ .reason = reason } },
            .bogus => .{ .server_index = server_index, .what = .bogus },
            .keys => .{ .server_index = server_index, .what = .keys },
        };
    }

    pub fn get(held: Held) ?Cause {
        // `none` names no server.
        assert(held.what != .none or held.server_index == 0);
        return switch (held.what) {
            .none => null,
            .rcode => |rcode| .{ .server_index = held.server_index, .what = .{ .rcode = rcode } },
            .reason => |reason| .{ .server_index = held.server_index, .what = .{ .reason = reason } },
            .bogus => .{ .server_index = held.server_index, .what = .bogus },
            .keys => .{ .server_index = held.server_index, .what = .keys },
        };
    }
};

/// Keeps `what` as the cause, from the server the lookup is on (docs/design.md §5, The cause of a
/// failure).
pub fn keep(self: *Lookup, what: Cause.What) void {
    keep_at(self, self.server_slot(), what);
}

/// As `keep`, for the configured server `slot`, which an earlier try went to and which the lookup
/// need not be on now (docs/design.md §5, Tries kept open).
pub fn keep_at(self: *Lookup, slot: u8, what: Cause.What) void {
    assert(!self.is_settled());
    assert(slot < self.config.servers.len);
    self.cause = Held.of(slot, what);
    assert(self.cause.server_index < self.config.servers.len);
}

/// `Lookup.failure_of`: what `.failed` carries.
pub fn failure_of(self: *const Lookup) Failure {
    assert(self.state == .failed);
    assert_rests(self);
    const negative = self.failure == core.Error.NameNotFound or self.failure == core.Error.NoData;
    return .{
        .err = self.failure,
        // A lookup with no server to have been on reports the first.
        .server_index = if (self.config.server_count() == 0) 0 else self.server_slot(),
        .attempts_made = self.round,
        .negative_ttl_seconds = if (negative) self.negative_ttl_seconds else 0,
        .cause = self.cause.get(),
        .security = if (negative) security.of(self) else .unchecked,
        .extended_error = if (self.has_extended_error) self.extended_error else null,
        .canonical_name = if (negative and self.flags.aliased) &self.current else null,
        .aliases = if (negative) &self.aliases else &core.Aliases.none,
    };
}

fn assert_rests(self: *const Lookup) void {
    // `AllServersFailed` rests on a server that failed the lookup, and `Timeout` on none. A cause
    // names a server of the configuration. A failure that the memory recalled made no pass and
    // has no cause (docs/design.md §17 question 89); one that went out ends after its last pass.
    const passes_end = self.failure == core.Error.AllServersFailed or self.failure == core.Error.Timeout;
    assert(!passes_end or self.round == 0 or self.round == self.config.attempts);
    assert(self.failure != core.Error.AllServersFailed or self.cause.what != .none or self.round == 0);
    assert(self.failure != core.Error.Timeout or self.cause.what == .none);
    // `Bogus` rests on a bogus message, or a walk that proved one, or the memory: then it sent
    // nothing, and has no order and no cause (docs/design.md §25, steps 11 to 13).
    assert(self.failure != core.Error.Bogus or self.cause.what == .bogus or (!self.flags.ordered and self.cause.what == .none));
    assert(self.cause.server_index < self.config.servers.len or self.cause.what == .none);
}

/// Keeps the code of `message`'s first extended error option, when it carries one that holds its
/// code. Called for a response whose rcode is not NOERROR, which the checks of §7 let through.
/// An option too short for its code is passed over: a receiver "MUST be able to accept EDE codes
/// and EXTRA-TEXT in all messages", and the code changes no processing (RFC 8914 §3).
pub fn note_extended_error(self: *Lookup, message: []const u8) void {
    assert(self.state == .awaiting_udp or self.state == .awaiting_tcp);
    const record = (wire.response_opt.find(message, &self.current) catch return) orelse return;
    const extended = (wire.edns_options.extended_error(record.rdata) catch return) orelse return;
    self.extended_error = extended.info_code;
    self.has_extended_error = true;
    assert(self.extended_error == extended.info_code);
}
