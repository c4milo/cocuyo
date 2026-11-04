//! A validating lookup (docs/design.md §25, Stage B: what the lookup does with it, and step 11).
//! The table hands a lookup a `Validator`, and the lookup asks it of each message it acts on. A
//! secure message moves the lookup as it would unvalidated, an insecure one too, a bogus one moves
//! the server alone, and one whose keys are wanted waits in `awaiting_keys` until the table's walk
//! ends. Split from `lookup.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Kind = core.Kind;
const Validation = core.Validation;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const limits = @import("limits.zig");
const bound = @import("lookup_bound.zig");
const failure_module = @import("lookup_failure.zig");

/// What a lookup asks of a validator: the `dnssec` module's, over a key store, or a test's. It
/// reads a message that passed the checks of docs/design.md §7, for the name and the type the
/// lookup asks at that moment.
pub const Validator = struct {
    context: *anyopaque,
    validate: *const fn (context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation,
};

/// Stage B's conjunction: what every message the lookup acted on was. Once lowered it stays low.
pub const Checked = enum(u2) {
    /// The lookup has no validator.
    not_validating,
    secure,
    insecure,
    /// A question for RRSIG, which cannot be secure (§25 item 15).
    unchecked,

    /// What an end reports while the lookup validates.
    pub fn security(self: Checked) core.Security {
        return switch (self) {
            .not_validating => unreachable,
            .secure => .secure,
            .insecure => .insecure,
            .unchecked => .unchecked,
        };
    }
};

pub fn validating(self: *const Lookup) bool {
    assert((self.servers.validator == null) == (self.conjunctions.checked == .not_validating));
    return self.servers.validator != null;
}

/// A message to act on as its rcode and its records say. A secure message bounds what the lookup
/// ends with by `ttl_seconds` (§25 item 7), and says which of the two it must be.
pub const Act = struct { ttl_seconds: u32 = std.math.maxInt(u32), ending: ?core.validation.Ending = null };

/// What the lookup does with a message it acts on.
pub const Step = union(enum) {
    act: Act,
    /// Act on it as a negative, whatever the rcode said: the proof decides (RFC 9824 §8).
    negative: struct { name_error: bool, ttl_seconds: u32 },
    /// The message was bogus, or its keys are wanted: the validator's verdict moved the lookup.
    moved,
};

/// Asks the validator of a message the lookup acts on, whose rcode is `rcode`, and moves the
/// lookup when the verdict says the message is not to be acted on. `heard` is the response's
/// `heard`, which the lookup calls once for each message it accepts.
pub fn weigh(self: *Lookup, message: []const u8, rcode: wire.Rcode, heard: Heard, now_ns: u64) Step {
    assert(self.state == .awaiting_udp or self.state == .awaiting_tcp);
    const validator = self.servers.validator orelse return .{ .act = .{} };
    // A walk's answers go to the walk, which reads them under the keys it holds (walk rule 9).
    if (self.conjunctions.for_walk) return .{ .act = .{} };
    // An RRSIG is never signed (RFC 4035 §2.2): such a question ends `unchecked`.
    if (self.question.kind == .rrsig) {
        self.conjunctions.checked = .unchecked;
        return .{ .act = .{} };
    }
    const verdict = validator.validate(validator.context, &self.current, self.question.kind, message, now_ns);
    switch (verdict) {
        .secure => |secure| return secured(self, secure, rcode, heard, now_ns),
        .insecure, .unchecked => {
            if (self.conjunctions.checked == .secure) self.conjunctions.checked = .insecure;
            return .{ .act = .{} };
        },
        .bogus => {
            rejected(self, heard, now_ns);
            return .moved;
        },
        .keys_wanted => {
            wait_for_keys(self, heard, now_ns);
            return .moved;
        },
    }
}

/// The response's `heard`: what an answer the lookup takes says of its server.
pub const Heard = struct {
    context: *const anyopaque,
    call: *const fn (context: *const anyopaque, lookup: *Lookup, cause: ?failure_module.Cause.What, now_ns: u64) void,

    fn of(self: Heard, lookup: *Lookup, cause: ?failure_module.Cause.What, now_ns: u64) void {
        self.call(self.context, lookup, cause, now_ns);
    }
};

/// A secure message, under its rcode: NXDOMAIN must carry a proof of a negative, and a proof of a
/// negative makes a negative of any rcode (RFC 9824 §8). An answer or a chain under NOERROR is
/// acted on, and the collection must agree with the ending.
fn secured(self: *Lookup, secure: core.validation.Secure, rcode: wire.Rcode, heard: Heard, now_ns: u64) Step {
    switch (secure.ending) {
        .name_error => return .{ .negative = .{ .name_error = true, .ttl_seconds = secure.ttl_seconds } },
        .no_data => return .{ .negative = .{ .name_error = false, .ttl_seconds = secure.ttl_seconds } },
        .answer, .alias => if (rcode == .name_error) {
            rejected(self, heard, now_ns);
            return .moved;
        },
    }
    return .{ .act = .{ .ttl_seconds = secure.ttl_seconds, .ending = secure.ending } };
}

/// A bogus message moves nothing but the server: over UDP the same server is asked over TCP, as
/// TC=1 asks it, and over a stream, DoH or DoQ the next server is. Each keeps `bogus` as the
/// cause when the server is passed (docs/design.md §25, step 11).
pub fn rejected(self: *Lookup, heard: Heard, now_ns: u64) void {
    assert(self.state == .awaiting_udp or self.state == .awaiting_tcp);
    // A bogus message of an earlier try closes that try alone, and is its server's failure: the
    // lookup waits on its current try (docs/design.md §5, Tries kept open; `earlierChecked`).
    if (self.hearing_earlier) return heard.of(self, .bogus, now_ns);
    const over_stream = self.state == .awaiting_tcp or self.config.sends_requests();
    if (over_stream or bound.spent(self, .stream)) {
        heard.of(self, .bogus, now_ns);
        self.next_server(now_ns);
    } else {
        heard.of(self, null, now_ns);
        self.state = .tcp_needed;
    }
    // The try the bogus message answered is over. A later pass may wait on another try it kept
    // open on a stream, whose wait began now (docs/design.md §5, Tries kept open).
    assert((self.state != .awaiting_udp and self.state != .awaiting_tcp) or self.waited_from_ns == now_ns);
}

/// The message's keys are wanted: the lookup waits for the table's walk, `key_asks_max` times for
/// a name, and past that the message reads as bogus.
fn wait_for_keys(self: *Lookup, heard: Heard, now_ns: u64) void {
    if (self.conjunctions.key_asks >= limits.key_asks_max) return rejected(self, heard, now_ns);
    heard.of(self, null, now_ns);
    self.conjunctions.key_asks += 1;
    self.state = .awaiting_keys;
    assert(self.conjunctions.key_asks <= limits.key_asks_max);
}

/// The walk ended with the keys held, or with an insecure delegation: the same server is asked
/// again, over the transport the lookup starts on, as a retry asks it (RFC 9520 §3.1).
pub fn on_keys_ready(self: *Lookup, now_ns: u64) void {
    self.see(now_ns);
    assert(self.state == .awaiting_keys);
    if (bound.spent(self, bound.fresh(self))) self.next_server(now_ns) else self.restart(now_ns);
    assert(self.state != .awaiting_keys);
}

/// The walk failed, and the lookup ends with its failure. A walk's question that went unanswered
/// ends it `Timeout` only while no server failed it, so `Timeout` keeps its promise that every try
/// went unanswered (§16 decision 25).
pub fn on_keys_failed(self: *Lookup, walked: core.validation.Walked, now_ns: u64) void {
    self.see(now_ns);
    assert(self.state == .awaiting_keys);
    switch (walked) {
        .bogus => {
            failure_module.keep(self, .bogus);
            self.fail(core.Error.Bogus);
        },
        .failed => {
            failure_module.keep(self, .keys);
            self.fail(core.Error.AllServersFailed);
        },
        .timeout => self.fail(if (self.cause.what == .none) core.Error.Timeout else core.Error.AllServersFailed),
    }
    assert(self.is_settled());
}
