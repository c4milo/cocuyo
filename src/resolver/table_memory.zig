//! The cache the table asks, as two functions the caller supplies (docs/design.md §20).
//!
//! `resolver` reads `core` and `wire` and never `cache` (§3), and this is how a cache sits under
//! every lookup with that still true: the table names no cache, it names a `Memory`, and
//! `cocuyo.remembered_by` is what fills one in from a `Cache`. A consumer whose cache is its own
//! fills one the same way.
//!
//! A lookup asks once, at its first poll, before a query is built: a hit ends it there, so the
//! poll returns `.done` or `.failed` and nothing goes out. An end is written back once, whichever
//! poll produced it, because a lookup that has ended and waits for `release` answers every poll
//! with its end again (§11).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Error = core.Error;
const Question = core.Question;
const lookup_module = @import("lookup.zig");
const security = @import("lookup_security.zig");
const recall_module = @import("lookup_recall.zig");
const Action = lookup_module.Action;
const Lookup = lookup_module.Lookup;
const validate_module = @import("lookup_validate.zig");
const slots_module = @import("table_slots.zig");
const Slot = slots_module.Slot;

/// The two negative answers RFC 2308 §5 lets a resolver remember. Nothing else is: not a timeout,
/// not a refusal, not a message that did not parse.
pub const Negative = enum { name_not_found, no_data };

/// What the table is handed back, and what it writes. The answers point into the caller's own
/// storage and are read before the call returns.
///
/// `ttl_seconds` on `answered` is what is left of the answer's life, not what it was given: a
/// recalled answer reports the time it has now, the way a caller of the cache would read it. The
/// life it was given is `answers.ttl_seconds`, and the difference is the time the answers spent
/// in the memory: every TTL they hold, each record's own included, loses it when the lookup ends
/// (RFC 1035 §6.1.3). A memory that caps a life keeps the capped one there, as `Cache` does. One
/// that reports more than `answers.ttl_seconds` has no known time spent: nothing is lowered, and
/// the answer reports `ttl_seconds`.
pub const Remembered = union(enum) {
    /// `canonical_name` is the end of the CNAME chain that reached the answers, or null when
    /// none did (§17 question 13).
    answered: struct {
        answers: *const wire.Answers,
        ttl_seconds: u32,
        canonical_name: ?*const core.Name,
        /// What the lookup that found the answers knew of where they came from (docs/design.md
        /// §25, Stage A rule 5).
        security: core.Security,
    },
    negative: struct { outcome: Negative, ttl_seconds: u32, security: core.Security },
    /// A resolution failure, one that `resolution_failure` counts: no server gave a useful
    /// response (RFC 9520 §2). The memory sets its time, and a recall ends the lookup with it
    /// (docs/design.md §16 decision 61).
    failed: Error,
};

/// A cache above the table. `context` is the caller's and the table hands it back untouched.
pub const Memory = struct {
    context: *anyopaque,
    recall: *const fn (context: *anyopaque, question: *const Question, now_ns: u64) ?Remembered,
    remember: *const fn (
        context: *anyopaque,
        question: *const Question,
        end: Remembered,
        now_ns: u64,
    ) void,
};

/// Asks the memory, once per lookup and before its first query. A hit ends the lookup where it
/// stands, and a lookup ended this way never writes back what it was handed. A lookup that has
/// already ended, cancelled or with no server to ask, is not asked about: it has its end.
pub fn recall_into(memory: ?Memory, slot: *Slot, now_ns: u64) void {
    if (slot.asked_memory) return;
    slot.asked_memory = true;
    if (slot.lookup.is_settled()) return;
    const source = memory orelse return;
    const found = source.recall(source.context, &slot.lookup.question, now_ns) orelse return;
    if (!takes(&slot.lookup, &found)) return;
    switch (found) {
        .answered => |answered| recall_module.answer(
            &slot.lookup,
            answered.answers,
            answered.ttl_seconds,
            answered.canonical_name,
            answered.security,
        ),
        .negative => |negative| recall_module.failure(&slot.lookup, error_of(negative.outcome), negative.ttl_seconds, negative.security),
        .failed => |err| recall_module.failed(&slot.lookup, err),
    }
    assert(slot.lookup.is_settled());
    slot.remembered = true;
}

/// Whether a lookup takes what the memory found (docs/design.md §25, step 13). A validating lookup
/// takes only an end a validating lookup wrote: `secure` or `insecure`, or `unchecked` for an
/// RRSIG, which is never signed. One that validates nothing takes every end but `Bogus`, which it
/// could not reach itself. Any other entry is a miss, and the lookup's end replaces it.
fn takes(lookup: *const Lookup, found: *const Remembered) bool {
    const security_of: core.Security = switch (found.*) {
        .answered => |answered| answered.security,
        .negative => |negative| negative.security,
        .failed => |err| return err != Error.Bogus or validate_module.validating(lookup),
    };
    if (!validate_module.validating(lookup)) return true;
    return switch (security_of) {
        .secure, .insecure => true,
        .unchecked => lookup.question.kind == .rrsig,
        .authenticated => false,
    };
}

/// Writes a lookup's end back, once. An action that is not an end is not one. A failure is
/// remembered when it is one of RFC 2308's two negatives or a resolution failure of RFC 9520 §2,
/// and not at all otherwise.
pub fn remember_end(memory: ?Memory, slot: *Slot, action: Action, now_ns: u64) void {
    switch (action) {
        .done, .failed => {},
        else => return,
    }
    if (slot.remembered) return;
    slot.remembered = true;
    const source = memory orelse return;
    const end: Remembered = switch (action) {
        .done => .{ .answered = .{
            .answers = &slot.lookup.answers,
            .ttl_seconds = slot.lookup.answers.ttl_seconds,
            .canonical_name = if (slot.lookup.flags.aliased) &slot.lookup.current else null,
            .security = security.of(&slot.lookup),
        } },
        .failed => |failure| failure_end(&failure) orelse return,
        else => unreachable,
    };
    source.remember(source.context, &slot.lookup.question, end, now_ns);
}

/// What a failed lookup's end is remembered as, or null when it is not remembered.
fn failure_end(failure: *const lookup_module.Failure) ?Remembered {
    if (negative_of(failure.err)) |outcome| {
        return .{ .negative = .{ .outcome = outcome, .ttl_seconds = failure.negative_ttl_seconds, .security = failure.security } };
    }
    // "Resolvers MUST implement a cache for resolution failures" (RFC 9520 §3.2).
    if (resolution_failure(failure.err)) return .{ .failed = failure.err };
    return null;
}

/// Whether a lookup that ended in `err` ended in a resolution failure: no server gave a useful
/// response (RFC 9520 §2). It is `cache.resolution_failure`, which this module cannot read
/// (docs/design.md §3). A test in `src/cocuyo.zig` holds the two equal (§16 decision 61).
pub fn resolution_failure(err: Error) bool {
    return switch (err) {
        // A time-out, and a server that failed (RFC 9520 §2.1, §2.2, §2.3, §2.7).
        Error.Timeout, Error.AllServersFailed => true,
        // The server errors that `check_response` off takes as the end (RFC 9520 §2.1, §2.2).
        Error.ServerFailure, Error.Refused, Error.NotImplemented, Error.FormatError => true,
        // The chain bound is how a lookup sees an alias loop (RFC 9520 §2.5).
        Error.ChainTooLong => true,
        // "Resolvers MUST cache DNSSEC validation failures" (RFC 9520 §3.4).
        Error.Bogus => true,
        // No RFC states a rule here: these are no resolution failure by cocuyo's choice
        // (docs/design.md §16 decision 60). The two negatives are useful responses.
        else => false,
    };
}

fn error_of(outcome: Negative) Error {
    return switch (outcome) {
        .name_not_found => Error.NameNotFound,
        .no_data => Error.NoData,
    };
}

fn negative_of(err: Error) ?Negative {
    return switch (err) {
        Error.NameNotFound => .name_not_found,
        Error.NoData => .no_data,
        else => null,
    };
}

// Tests. The table's own tests drive a memory end to end; these pin the two mappings, which are
// the RFC 2308 §5 rule about what may be remembered at all.

const testing = std.testing;

test "only the two negatives of RFC 2308 are remembered, and each maps back" {
    try testing.expectEqual(@as(?Negative, .name_not_found), negative_of(Error.NameNotFound));
    try testing.expectEqual(@as(?Negative, .no_data), negative_of(Error.NoData));
    try testing.expectEqual(@as(?Negative, null), negative_of(Error.Timeout));
    try testing.expectEqual(@as(?Negative, null), negative_of(Error.ServerFailure));
    try testing.expectEqual(@as(?Negative, null), negative_of(Error.Canceled));
    // YXDOMAIN ends a lookup with this, and no RFC gives it a TTL (docs/design.md §16 decision 57).
    try testing.expectEqual(@as(?Negative, null), negative_of(Error.NameTooLong));
    try testing.expectEqual(@as(?Negative, null), negative_of(Error.MalformedMessage));
    try testing.expectEqual(Error.NameNotFound, error_of(.name_not_found));
    try testing.expectEqual(Error.NoData, error_of(.no_data));
}

// Tests of the table with a memory under it. The memory here is a stub: a real `Cache` cannot
// appear in this module, which never imports one (§3), and `src/cocuyo.zig` is where the two
// meet and where the composition is tested.

const fixtures = @import("fixtures.zig");
const Table = fixtures.Table;
const ready_module = @import("table_ready.zig");

/// A memory that hands back whatever a test put in it and counts what it was asked and told.
/// The walks' tests use it too. Test-only.
pub const Stub = struct {
    held: ?Remembered = null,
    recalls: u32 = 0,
    writes: u32 = 0,
    written: ?Remembered = null,

    pub fn memory(self: *Stub) Memory {
        return .{ .context = self, .recall = recall, .remember = remember };
    }

    fn recall(context: *anyopaque, question: *const Question, now_ns: u64) ?Remembered {
        _ = question;
        _ = now_ns;
        const self: *Stub = @ptrCast(@alignCast(context));
        self.recalls += 1;
        return self.held;
    }

    fn remember(context: *anyopaque, question: *const Question, end: Remembered, now_ns: u64) void {
        _ = question;
        _ = now_ns;
        const self: *Stub = @ptrCast(@alignCast(context));
        self.writes += 1;
        self.written = end;
    }
};

test {
    _ = @import("table_memory_test.zig");
}
