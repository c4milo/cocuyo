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
const Action = lookup_module.Action;
const slots_module = @import("table_slots.zig");
const Slot = slots_module.Slot;

/// The two negative answers RFC 2308 §5 lets a resolver remember. Nothing else is: not a timeout,
/// not a refusal, not a message that did not parse.
pub const Negative = enum { name_not_found, no_data };

/// What the table is handed back, and what it writes. The answers point into the caller's own
/// storage and are read before the call returns.
///
/// `ttl_seconds` on `answered` is what is left of the answer's life, not what it was given: a
/// recalled answer reports the time it has now, the way a caller of the cache would read it.
pub const Remembered = union(enum) {
    answered: struct { answers: *const wire.Answers, ttl_seconds: u32 },
    negative: struct { outcome: Negative, ttl_seconds: u32 },
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
/// stands, and a lookup ended this way never writes back what it was handed.
pub fn recall_into(memory: ?Memory, slot: *Slot, now_ns: u64) void {
    if (slot.asked_memory) return;
    slot.asked_memory = true;
    const source = memory orelse return;
    const found = source.recall(source.context, &slot.lookup.question, now_ns) orelse return;
    switch (found) {
        .answered => |answered| slot.lookup.recall_answer(answered.answers, answered.ttl_seconds),
        .negative => |negative| slot.lookup.recall_failure(error_of(negative.outcome), negative.ttl_seconds),
    }
    assert(slot.lookup.is_settled());
    slot.remembered = true;
}

/// Writes a lookup's end back, once. An action that is not an end is not one, and a failure that
/// is neither of RFC 2308's two negatives is not remembered at all.
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
        } },
        .failed => |failure| .{ .negative = .{
            .outcome = negative_of(failure.err) orelse return,
            .ttl_seconds = failure.negative_ttl_seconds,
        } },
        else => unreachable,
    };
    source.remember(source.context, &slot.lookup.question, end, now_ns);
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
const Stub = struct {
    held: ?Remembered = null,
    recalls: u32 = 0,
    writes: u32 = 0,
    written: ?Remembered = null,

    fn memory(self: *Stub) Memory {
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

/// Drives one lookup to its answer and returns the answers it holds, so a test has a real
/// `wire.Answers` to put in the stub.
fn answered_once(rig: *Table) !wire.Answers {
    const handle = try rig.start("example.com.");
    const sent = rig.poll().?;
    rig.resolver.on_sent(sent.handle, rig.now_ns);
    try testing.expectEqual(lookup_module.Verdict.accepted, rig.answer(handle));
    const end = rig.poll().?;
    try testing.expect(end.action == .done);
    const answers = rig.resolver.lookup_of(handle).answers;
    rig.resolver.release(handle);
    return answers;
}

test "a question the memory holds is answered at its first poll, and nothing is sent" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const answers = try answered_once(&rig);
    var stub: Stub = .{ .held = .{ .answered = .{ .answers = &answers, .ttl_seconds = 42 } } };
    rig.resolver.remember_with(stub.memory());

    const handle = try rig.start("example.com.");
    const event = rig.poll().?;
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    try testing.expect(event.action == .done);
    // The life it has left, not the life it was given.
    try testing.expectEqual(@as(u32, 42), event.action.done.ttl_seconds);
    // Read back from the memory, so it is not written to it again.
    try testing.expectEqual(@as(u32, 0), stub.writes);
    try testing.expectEqual(core.Kind.a, event.action.done.kind);
    try testing.expectEqual(@as(?*const core.Name, null), event.action.done.canonical_name);

    // Offered again, as a table that has not been told the answer was read does: the memory is
    // asked once per lookup, and asking a lookup that has already ended would be asking a
    // question whose answer it is holding.
    ready_module.offer(&rig.resolver, handle.index);
    const twice = rig.poll().?;
    try testing.expect(twice.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.recalls);
    rig.resolver.release(handle);
}

test "a negative the memory holds comes back as that failure, with what is left of it" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{ .held = .{ .negative = .{ .outcome = .name_not_found, .ttl_seconds = 7 } } };
    rig.resolver.remember_with(stub.memory());

    const handle = try rig.start("example.com.");
    const event = rig.poll().?;
    try testing.expect(event.action == .failed);
    try testing.expectEqual(Error.NameNotFound, event.action.failed.err);
    try testing.expectEqual(@as(u32, 7), event.action.failed.negative_ttl_seconds);
    try testing.expectEqual(@as(u32, 0), stub.writes);
    rig.resolver.release(handle);
}

test "an end is written back once, however many polls produce it" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.remember_with(stub.memory());

    const handle = try rig.start("example.com.");
    const sent = rig.poll().?;
    rig.resolver.on_sent(sent.handle, rig.now_ns);
    try testing.expectEqual(lookup_module.Verdict.accepted, rig.answer(handle));
    const end = rig.poll().?;
    try testing.expect(end.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.writes);
    try testing.expect(stub.written.? == .answered);

    // Offered again, as a table that has not been told the answer was read does.
    ready_module.offer(&rig.resolver, handle.index);
    const again = rig.poll().?;
    try testing.expect(again.action == .done);
    try testing.expectEqual(@as(u32, 1), stub.writes);
    rig.resolver.release(handle);
}

test "a failure that is not one of RFC 2308's two negatives is not written back" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    var stub: Stub = .{};
    rig.resolver.remember_with(stub.memory());

    const handle = try rig.start("example.com.");
    rig.resolver.cancel(handle);
    const event = rig.poll().?;
    try testing.expect(event.action == .failed);
    try testing.expectEqual(Error.Canceled, event.action.failed.err);
    try testing.expectEqual(@as(u32, 0), stub.writes);
    rig.resolver.release(handle);
}
