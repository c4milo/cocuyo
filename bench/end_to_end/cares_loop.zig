//! c-ares's side of the comparison: one channel with its event thread, which is how c-ares
//! recommends being driven since 1.26, and `ares_query_dnsrec` for one A lookup at a time, the
//! callback starting the next until `total` have ended. Two threads start lookups — the main
//! thread the first batch, c-ares's event thread every one after — so everything they share is
//! atomic, and a slot changes hands only by compare-and-exchange.
const std = @import("std");
const assert = std.debug.assert;
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const c = @cImport(@cInclude("ares.h"));

pub const Outcome = struct { elapsed_ns: u64, failures: u32 };

/// Who is starting lookups on a slot. A slot has one query out at a time, and its answer starts
/// the next; the answer can come inside `ares_query_dnsrec`, on the same thread, or on c-ares's
/// thread while the holder is still at work. Either way exactly one more start must follow it.
const Owner = enum(u8) {
    /// Nobody holds the slot: the next `start_next` takes it.
    idle,
    /// A `start_next` holds it and is issuing.
    issuing,
    /// It is held, and an answer came meanwhile: the holder owes one more start.
    owed,
};

/// How many times `take` looks. The only other hand on a slot is its holder, and the holder lets
/// go at most once while `take` looks, so the second look always settles it.
const take_rounds = 2;

/// One lookup in flight: when it started, the name it asked, which c-ares copies at start, and
/// who is starting lookups on it.
const Slot = struct {
    started_ns: u64 = 0,
    text: [constants.name_bytes]u8 = undefined,
    owner: std.atomic.Value(Owner) = .init(.idle),
};

const State = struct {
    channel: ?*c.ares_channel_t,
    total: u32,
    started: std.atomic.Value(u32) = .init(0),
    done: std.atomic.Value(u32) = .init(0),
    failures: std.atomic.Value(u32) = .init(0),
    latencies: []u64,
    slots: [constants.in_flight_max]Slot = @splat(.{}),
};

var state: State = undefined;
/// Set once a row is over, before the channel is destroyed. Destroying a channel fails the
/// queries still on it, and each failure reaches `on_answer`, which would otherwise start
/// another lookup on the channel being torn down.
var stopping: std.atomic.Value(bool) = .init(false);

pub fn run(port: u16, in_flight: u32, total: u32, latencies: []u64) !Outcome {
    assert(in_flight >= 1 and in_flight <= constants.in_flight_max);
    assert(latencies.len >= total);
    if (c.ares_library_init(c.ARES_LIB_INIT_ALL) != c.ARES_SUCCESS) return error.CaresInitFailed;
    defer c.ares_library_cleanup();
    var lookups = "b".*;
    var options: c.ares_options = std.mem.zeroes(c.ares_options);
    options.evsys = c.ARES_EVSYS_DEFAULT;
    options.lookups = &lookups;
    var channel: ?*c.ares_channel_t = null;
    if (c.ares_init_options(&channel, &options, c.ARES_OPT_EVENT_THREAD | c.ARES_OPT_LOOKUPS) != c.ARES_SUCCESS) return error.CaresInitFailed;
    defer c.ares_destroy(channel);
    var csv: [constants.name_bytes]u8 = undefined;
    const servers = try std.fmt.bufPrintZ(&csv, "127.0.0.1:{d}", .{port});
    if (c.ares_set_servers_ports_csv(channel, servers.ptr) != c.ARES_SUCCESS) return error.CaresInitFailed;

    state = .{ .channel = channel, .total = total, .latencies = latencies };
    stopping.store(false, .release);
    // Registered after the destroy above, so it runs before it: no lookup starts on a channel
    // that is going away.
    defer stopping.store(true, .release);
    const begin = harness.now_ns();
    var index: u32 = 0;
    while (index < in_flight and index < total) : (index += 1) start_next(&state.slots[index]);
    if (c.ares_queue_wait_empty(channel, constants.cares_wait_ms_max) != c.ARES_SUCCESS) {
        // A row that gives up says what it knew, because "the queue never emptied" has two very
        // different causes and they are told apart here. `done == total` means every lookup was
        // answered and the queue still held something, which is c-ares's own bookkeeping.
        // `done < total` means a lookup this driver started never came back, and the count says
        // how many.
        std.debug.print(
            "c-ares stalled: {d} of {d} answered, {d} claimed, {d} in flight asked for\n",
            .{ state.done.load(.monotonic), total, state.started.load(.monotonic), in_flight },
        );
        return error.CaresStalled;
    }
    // Every lookup the row asked for is answered, or the rate below is over a count nobody made.
    assert(state.done.load(.monotonic) == total);
    return .{ .elapsed_ns = harness.now_ns() - begin, .failures = state.failures.load(.monotonic) };
}

/// Starts lookups on `slot` until none is left to claim, or until one is out and unanswered.
///
/// Called for the first batch and from every answer. A call that finds the slot held does not
/// issue: it leaves word that one more start is owed, and the holder issues it. That is what
/// stops recursion when c-ares answers inside `ares_query_dnsrec` — at 20,000 lookups a call per
/// answer overflowed the stack — and what stops an answer that lands while the holder is letting
/// go from being lost, which two plain flags did not.
fn start_next(slot: *Slot) void {
    if (!take(slot)) return;
    while (!stopping.load(.acquire)) {
        const index = claim() orelse break;
        issue(slot, index);
        if (!settle(slot)) return;
    }
    // Nothing left to claim, or the row is over, and no query of this slot is out.
    slot.owner.store(.idle, .release);
}

/// Takes the slot, or, when it is held, tells the holder a start is owed.
fn take(slot: *Slot) bool {
    for (0..take_rounds) |_| {
        const seen = slot.owner.cmpxchgStrong(.idle, .issuing, .acq_rel, .acquire) orelse return true;
        // One query out per slot, so one answer per holding: a second owed start cannot arise.
        assert(seen != .owed);
        if (slot.owner.cmpxchgStrong(.issuing, .owed, .acq_rel, .acquire) == null) return false;
        // The holder let go between the two looks, so the slot is idle and the next look takes it.
    }
    unreachable;
}

/// After a query goes out: true when its answer has already come and the holder must issue
/// again, false when the slot was let go and the answer, when it comes, takes it.
fn settle(slot: *Slot) bool {
    if (let_go(slot)) return false;
    // It could not be let go, so a start is owed: the answer has already come, and issuing for
    // it is the holder's.
    const taken = slot.owner.cmpxchgStrong(.owed, .issuing, .acq_rel, .acquire);
    assert(taken == null);
    return true;
}

/// Lets the slot go unless a start is owed on it. An answer that lands while the holder leaves
/// must still be issued for, and a plain store here would erase the word it left.
fn let_go(slot: *Slot) bool {
    return slot.owner.cmpxchgStrong(.issuing, .idle, .acq_rel, .acquire) == null;
}

/// The next lookup's index, or null once `total` have been claimed. Two threads claim: the first
/// batch goes out from the main thread and every lookup after it from a callback on c-ares's,
/// which runs while that batch is still going.
fn claim() ?u32 {
    const index = state.started.fetchAdd(1, .monotonic);
    return if (index < state.total) index else null;
}

/// One query out, under c-ares's own lock either way.
fn issue(slot: *Slot, index: u32) void {
    // Not `catch unreachable`: when this failed it said nothing about why, and the name it was
    // asked to write always fits. A panic that carries the index is what a rerun needs.
    const name = std.fmt.bufPrintZ(&slot.text, "h{d}.example.", .{index}) catch {
        std.debug.panic("the name for lookup {d} did not fit {d} octets", .{ index, constants.name_bytes });
    };
    slot.started_ns = harness.now_ns();
    const status = c.ares_query_dnsrec(state.channel, name.ptr, c.ARES_CLASS_IN, c.ARES_REC_TYPE_A, &on_answer, slot, null);
    assert(status == c.ARES_SUCCESS);
}

fn on_answer(arg: ?*anyopaque, status: c.ares_status_t, timeouts: usize, record: ?*const c.ares_dns_record_t) callconv(.c) void {
    _ = timeouts;
    const slot: *Slot = @ptrCast(@alignCast(arg.?));
    const now = harness.now_ns();
    const answered = status == c.ARES_SUCCESS and c.ares_dns_record_rr_cnt(record, c.ARES_SECTION_ANSWER) != 0;
    const at = state.done.fetchAdd(1, .monotonic);
    assert(at < state.total);
    state.latencies[at] = now - slot.started_ns;
    if (!answered) _ = state.failures.fetchAdd(1, .monotonic);
    start_next(slot);
}

// Tests. The loop against the responder is in `end_to_end.zig`; these pin the handoff, whose
// interleavings no run can be made to produce on demand — c-ares answers inline, or on its own
// thread mid-release, when it happens to and not when a test asks. So each step is driven from
// the state an interleaving would leave behind.

const testing = std.testing;

/// Puts the row state where no claim succeeds and none is counted but the one a test makes.
fn empty_row() void {
    stopping.store(false, .release);
    state.total = 0;
    state.started.store(0, .release);
}

test "a start that happens inside a start makes no query of its own, and is owed" {
    empty_row();
    var slot: Slot = .{ .owner = .init(.issuing) };
    start_next(&slot);
    try testing.expectEqual(Owner.owed, slot.owner.load(.acquire));
    // Not even a claim: the holder issues what is owed, not this call.
    try testing.expectEqual(@as(u32, 0), state.started.load(.acquire));
}

test "an answer that lands while the holder lets go keeps the slot held" {
    var slot: Slot = .{ .owner = .init(.owed) };
    // The holder tries to leave with a start owed: it must not, and the word must survive.
    try testing.expect(!let_go(&slot));
    try testing.expectEqual(Owner.owed, slot.owner.load(.acquire));
    slot.owner.store(.issuing, .release);
    try testing.expect(let_go(&slot));
    try testing.expectEqual(Owner.idle, slot.owner.load(.acquire));
}

test "settling issues again when the answer came, and lets go when it has not" {
    var answered: Slot = .{ .owner = .init(.owed) };
    try testing.expect(settle(&answered));
    try testing.expectEqual(Owner.issuing, answered.owner.load(.acquire));
    var waiting: Slot = .{ .owner = .init(.issuing) };
    try testing.expect(!settle(&waiting));
    try testing.expectEqual(Owner.idle, waiting.owner.load(.acquire));
}

test "an idle slot is taken, and a held one is marked owed" {
    var idle: Slot = .{};
    try testing.expect(take(&idle));
    try testing.expectEqual(Owner.issuing, idle.owner.load(.acquire));
    try testing.expect(!take(&idle));
    try testing.expectEqual(Owner.owed, idle.owner.load(.acquire));
}

test "no lookup starts once the row is over" {
    empty_row();
    stopping.store(true, .release);
    defer stopping.store(false, .release);
    // A channel being destroyed fails what is on it, and each failure reaches the callback,
    // which must not answer a teardown with another query. Not even a claim is made, and the
    // slot is left as it was found.
    var slot: Slot = .{};
    start_next(&slot);
    try testing.expectEqual(@as(u32, 0), state.started.load(.acquire));
    try testing.expectEqual(Owner.idle, slot.owner.load(.acquire));
}
