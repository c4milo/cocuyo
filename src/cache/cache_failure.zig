//! The cache of resolution failures (RFC 9520 §3.2, docs/design.md §16 decision 60): which errors
//! are one, and how long each is kept. `Cache.put_failure` keeps the entry, in a slot of the
//! table the caller sized, under the key of every other entry.
//!
//! This file and the decision are the record RFC 9520 §3.2 asks for: "Developers should document
//! their implementation choices". The first failure of a name is kept for the caller's minimum,
//! and each failure after the entry expired doubles the time, to five minutes. An expired entry
//! keeps its slot and its count until an answer replaces it or the hand evicts it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Error = core.Error;
const limits = @import("limits.zig");
const constants = @import("constants.zig");

/// The resolution failures, one for each error a lookup ends with when no server gave a useful
/// response (RFC 9520 §2). Four bits, so that a slot keeps it and its count in one octet.
pub const Failure = enum(u4) {
    timeout,
    all_servers_failed,
    server_failure,
    refused,
    not_implemented,
    format_error,
    chain_too_long,
};

/// What a `failed` slot keeps: its failure, and how often its time was doubled. `next_doublings`
/// stops the count at 9 from the least minimum, so four bits hold it.
pub const Kept = packed struct(u8) {
    failure: Failure = .timeout,
    doublings: u4 = 0,
};

/// The failure a lookup that ended in `err` ended in, or null when the end is no resolution
/// failure. NXDOMAIN and NODATA are useful responses, and `put_negative` keeps them. A cancelled
/// lookup and one with no server asked no server, so neither is a server's failure.
pub fn failure_of(err: Error) ?Failure {
    return switch (err) {
        // A time-out, and a server that failed (RFC 9520 §2.1, §2.2, §2.3, §2.7).
        Error.Timeout => .timeout,
        Error.AllServersFailed => .all_servers_failed,
        // The server errors that `check_response` off takes as the end (RFC 9520 §2.1, §2.2).
        Error.ServerFailure => .server_failure,
        Error.Refused => .refused,
        Error.NotImplemented => .not_implemented,
        Error.FormatError => .format_error,
        // The chain bound is how a lookup sees an alias loop (RFC 9520 §2.5).
        Error.ChainTooLong => .chain_too_long,
        // No RFC states a rule here: these are no resolution failure by cocuyo's choice
        // (docs/design.md §16 decision 60). A server that says YXDOMAIN (`NameTooLong`) answered.
        // `Canceled` and `NoServers` asked no server. A codec error moves the lookup on.
        else => null,
    };
}

/// The error a hit on a `failed` entry hands back: the one the lookup ended in.
pub fn error_of(failure: Failure) Error {
    return switch (failure) {
        .timeout => Error.Timeout,
        .all_servers_failed => Error.AllServersFailed,
        .server_failure => Error.ServerFailure,
        .refused => Error.Refused,
        .not_implemented => Error.NotImplemented,
        .format_error => Error.FormatError,
        .chain_too_long => Error.ChainTooLong,
    };
}

/// Whether a lookup that ended in `err` ended in a resolution failure, which
/// `Cache.put_failure` keeps (docs/design.md §16 decision 60).
pub fn resolution_failure(err: Error) bool {
    return failure_of(err) != null;
}

/// Whether a cache takes `seconds` as `failure_seconds_min`: 1 s to 300 s (RFC 9520 §3.2). A
/// time read at run time is input, so its reader asks this and refuses a bad one itself;
/// `Cache.put_failure` asserts the same bound.
pub fn failure_seconds_min_valid(seconds: u32) bool {
    // At least 1 s, and never more than 5 minutes (RFC 9520 §3.2).
    return seconds >= limits.failure_seconds_least and seconds <= limits.failure_seconds_max;
}

/// The time a failure is kept after `doublings` doublings of `seconds_min`: the exponential
/// backoff RFC 9520 §3.2 asks for, which stops at its 5 minutes.
pub fn seconds_for(seconds_min: u32, doublings: u4) u32 {
    assert(failure_seconds_min_valid(seconds_min));
    const doubled = @as(u64, seconds_min) << @intCast(doublings);
    // "resolution failures MUST NOT be cached for longer than 5 minutes" (RFC 9520 §3.2).
    const seconds: u32 = @intCast(@min(doubled, limits.failure_seconds_max));
    assert(seconds >= seconds_min);
    return seconds;
}

/// The count of doublings for the next failure after an entry with `doublings` expired. It stops
/// once the time is at the most: from 1 s that is 9, 512 s past the 300, so it fits in a `u4`.
pub fn next_doublings(seconds_min: u32, doublings: u4) u4 {
    if (seconds_for(seconds_min, doublings) >= limits.failure_seconds_max) return doublings;
    assert(doublings < std.math.maxInt(u4));
    return doublings + 1;
}

// Tests.

const testing = std.testing;
const cache = @import("cache.zig");
const Outcome = cache.Outcome;
const fixtures = @import("fixtures.zig");
const ask = fixtures.question;
const second = fixtures.second;

/// Enough slots that no test here fills the table.
const slot_count: usize = 4;

/// The seconds a failure entry of `text` has left at `now_ns`, or null when there is none.
fn failure_left(table: *cache.Cache, text: []const u8, now_ns: u64) ?u32 {
    const hit = table.get(&ask(text), now_ns) orelse return null;
    if (hit.outcome != .failed) return null;
    return hit.ttl_seconds;
}

test "the resolution failures are the errors where no server gave a useful response" {
    const kept = [_]Error{
        Error.Timeout,      Error.AllServersFailed, Error.ServerFailure,
        Error.Refused,      Error.NotImplemented,   Error.FormatError,
        Error.ChainTooLong,
    };
    for (kept) |err| try testing.expect(resolution_failure(err));
    const refused = [_]Error{
        Error.NameNotFound,    Error.NoData,    Error.NameTooLong,
        Error.Canceled,        Error.NoServers, Error.MalformedMessage,
        Error.UnqueryableType,
    };
    for (refused) |err| try testing.expect(!resolution_failure(err));
    // Each failure maps back to the error it was kept from.
    for (kept) |err| try testing.expectEqual(err, error_of(failure_of(err).?));
}

test "a failure time of 1 s to 300 s is valid, and 0 s and 301 s are not" {
    try testing.expect(!failure_seconds_min_valid(0));
    try testing.expect(failure_seconds_min_valid(1));
    try testing.expect(failure_seconds_min_valid(300));
    try testing.expect(!failure_seconds_min_valid(301));
    try testing.expectEqual(@as(u32, 5), constants.failure_seconds_min_default);
}

test "a hit on a failure entry says the error, and the time is the minimum" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    try testing.expectEqual(@as(u32, 5), table.failure_seconds_min);
    table.put_failure(&ask("down.example"), Error.AllServersFailed, 0);
    const hit = table.get(&ask("DOWN.example"), 0).?;
    try testing.expectEqual(Outcome.failed, hit.outcome);
    try testing.expectEqual(@as(?Error, Error.AllServersFailed), hit.failure);
    try testing.expectEqual(@as(u32, 5), hit.ttl_seconds);
    try testing.expectEqual(@as(usize, 0), hit.answers.count);
    // A hit on an answer says no error.
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("up.example"), &answers, null, .unchecked, 0);
    try testing.expectEqual(@as(?Error, null), table.get(&ask("up.example"), 0).?.failure);
    // At its expiry the entry is a miss, and the caller asks again.
    try testing.expect(table.get(&ask("down.example"), 5 * second) == null);
}

test "an error that is no resolution failure is not kept" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    for ([_]Error{ Error.Canceled, Error.NoServers, Error.NameTooLong, Error.NameNotFound }) |err| {
        table.put_failure(&ask("x.example"), err, 0);
    }
    try testing.expectEqual(@as(usize, 0), table.len());
}

test "the caller's minimum is the first time" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    table.failure_seconds_min = 1;
    table.put_failure(&ask("down.example"), Error.Timeout, 0);
    try testing.expectEqual(@as(?u32, 1), failure_left(&table, "down.example", 0));
    try testing.expect(table.get(&ask("down.example"), second) == null);
}

test "each failure after the entry expired doubles the time, to 300 s" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const expected = [_]u32{ 5, 10, 20, 40, 80, 160, 300, 300 };
    var now_ns: u64 = 0;
    for (expected) |seconds| {
        try testing.expect(table.get(&ask("down.example"), now_ns) == null);
        table.put_failure(&ask("down.example"), Error.Timeout, now_ns);
        try testing.expectEqual(@as(?u32, seconds), failure_left(&table, "down.example", now_ns));
        now_ns += @as(u64, seconds) * second;
    }
    try testing.expectEqual(@as(usize, 1), table.len());
}

test "a failure while the entry lives changes nothing" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    table.put_failure(&ask("down.example"), Error.Timeout, 0);
    // A lookup that started before the entry ends after it.
    table.put_failure(&ask("down.example"), Error.AllServersFailed, 2 * second);
    const hit = table.get(&ask("down.example"), 2 * second).?;
    try testing.expectEqual(@as(u32, 3), hit.ttl_seconds);
    try testing.expectEqual(@as(?Error, Error.Timeout), hit.failure);
    // So the next failure after the expiry is the second, at 10 s, not the third.
    table.put_failure(&ask("down.example"), Error.Timeout, 5 * second);
    try testing.expectEqual(@as(?u32, 10), failure_left(&table, "down.example", 5 * second));
}

test "a failure does not replace a live answer or a live negative" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("up.example"), &answers, null, .unchecked, 0);
    table.put_negative(&ask("gone.example"), .name_not_found, 30, .unchecked, 0);
    table.put_failure(&ask("up.example"), Error.Timeout, second);
    table.put_failure(&ask("gone.example"), Error.Timeout, second);
    try testing.expectEqual(Outcome.answered, table.get(&ask("up.example"), second).?.outcome);
    try testing.expectEqual(Outcome.name_not_found, table.get(&ask("gone.example"), second).?.outcome);
    // Expired, the answer is replaced by a first failure.
    table.put_failure(&ask("up.example"), Error.Timeout, 300 * second);
    try testing.expectEqual(@as(?u32, 5), failure_left(&table, "up.example", 300 * second));
}

/// The times of the backoff tests: the first failure's expiry, the second's time, and when the
/// end for the name comes, inside the second failure's 10 s.
const first_expiry_ns: u64 = constants.failure_seconds_min_default * second;
const second_seconds: u32 = 10;
const end_seconds: u64 = 15;
const end_ns: u64 = end_seconds * second;
/// The TTL of an answer that `put` keeps.
const kept_ttl_seconds: u32 = 300;

/// Two failures of `text`, then `end` for the name, while the second lives.
fn backoff_then(table: *cache.Cache, text: []const u8, end: *const fn (*cache.Cache, []const u8) void) !void {
    table.put_failure(&ask(text), Error.Timeout, 0);
    table.put_failure(&ask(text), Error.Timeout, first_expiry_ns);
    try testing.expectEqual(@as(?u32, second_seconds), failure_left(table, text, first_expiry_ns));
    end(table, text);
}

fn answer_in_backoff(table: *cache.Cache, text: []const u8) void {
    const answers = fixtures.answers_v4(1, 1);
    table.put(&ask(text), &answers, null, .unchecked, end_ns);
}

fn zero_answer_in_backoff(table: *cache.Cache, text: []const u8) void {
    const answers = fixtures.answers_v4(1, 0);
    table.put(&ask(text), &answers, null, .unchecked, end_ns);
}

fn truncated_answer_in_backoff(table: *cache.Cache, text: []const u8) void {
    var answers = fixtures.answers_v4(1, kept_ttl_seconds);
    answers.truncated = true;
    table.put(&ask(text), &answers, null, .unchecked, end_ns);
}

fn negative_in_backoff(table: *cache.Cache, text: []const u8) void {
    table.put_negative(&ask(text), .no_data, 1, .unchecked, end_ns);
}

fn zero_negative_in_backoff(table: *cache.Cache, text: []const u8) void {
    table.put_negative(&ask(text), .name_not_found, 0, .unchecked, end_ns);
}

test "an answer or a negative for the name ends the backoff, kept or not" {
    const ends = [_]*const fn (*cache.Cache, []const u8) void{
        answer_in_backoff, zero_answer_in_backoff, truncated_answer_in_backoff, negative_in_backoff, zero_negative_in_backoff,
    };
    for (ends) |end| {
        var fixture: fixtures.Fixture(slot_count) = .{};
        var table = fixture.init();
        try backoff_then(&table, "down.example", end);
        // The next failure, after whatever the end left expired, is a first one again.
        table.put_failure(&ask("down.example"), Error.Timeout, 20 * second);
        try testing.expectEqual(@as(?u32, 5), failure_left(&table, "down.example", 20 * second));
    }
}

test "a refused answer leaves a live answer of the name in place" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = fixture.init();
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("up.example"), &answers, null, .unchecked, 0);
    const zero = fixtures.answers_v4(1, 0);
    table.put(&ask("up.example"), &zero, null, .unchecked, second);
    // Only a failure entry goes: the live answer stays.
    try testing.expectEqual(Outcome.answered, table.get(&ask("up.example"), second).?.outcome);
}

test "the TTL cap caps a failure too" {
    var fixture: fixtures.Fixture(slot_count) = .{};
    var table = cache.Cache.init(&fixture.slots, &fixture.keys, fixtures.seed, 2);
    table.put_failure(&ask("down.example"), Error.Timeout, 0);
    try testing.expectEqual(@as(?u32, 2), failure_left(&table, "down.example", 0));
}

test "the hand takes an expired failure entry on sight, and its count goes with it" {
    var fixture: fixtures.Fixture(2) = .{};
    var table = fixture.init();
    table.put_failure(&ask("down.example"), Error.Timeout, 0);
    try testing.expect(table.get(&ask("down.example"), 0) != null);
    const answers = fixtures.answers_v4(1, 300);
    table.put(&ask("a.example"), &answers, null, .unchecked, 0);
    // Full, at 5 s: the failure entry expired, visited or not, and goes first.
    table.put(&ask("b.example"), &answers, null, .unchecked, 5 * second);
    try testing.expect(table.get(&ask("a.example"), 5 * second) != null);
    table.put_failure(&ask("down.example"), Error.Timeout, 5 * second);
    try testing.expectEqual(@as(?u32, 5), failure_left(&table, "down.example", 5 * second));
}

test "the backoff stops at its most from any valid minimum" {
    var seconds_min: u32 = limits.failure_seconds_least;
    while (seconds_min <= limits.failure_seconds_max) : (seconds_min += 1) {
        var doublings: u4 = 0;
        var steps: usize = 0;
        while (seconds_for(seconds_min, doublings) < limits.failure_seconds_max) : (steps += 1) {
            try testing.expect(steps < @bitSizeOf(u32));
            doublings = next_doublings(seconds_min, doublings);
        }
        try testing.expectEqual(doublings, next_doublings(seconds_min, doublings));
    }
}
