//! c-ares's side of the comparison: one channel with its event thread, which is how c-ares
//! recommends being driven since 1.26, and `ares_query_dnsrec` for one A lookup at a time, the
//! callback starting the next until `total` have ended. The callbacks run on c-ares's thread
//! under its channel lock, so the state below is touched by one thread at a time and read by the
//! main thread only once the queue is empty.
const std = @import("std");
const assert = std.debug.assert;
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const c = @cImport(@cInclude("ares.h"));

pub const Outcome = struct { elapsed_ns: u64, failures: u32 };

/// One lookup in flight: when it started, the name it asked, which c-ares copies at start, and
/// the two flags that keep a start from nesting inside a start.
const Slot = struct {
    started_ns: u64 = 0,
    text: [constants.name_bytes]u8 = undefined,
    /// A query is being submitted on this slot right now. Atomic because two threads read it:
    /// the first batch goes out from the main thread, and c-ares may answer on its event thread
    /// before `ares_query_dnsrec` has returned here.
    issuing: std.atomic.Value(bool) = .init(false),
    /// Its answer came while that submission was still in progress.
    answered_inline: std.atomic.Value(bool) = .init(false),
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
    const begin = harness.now_ns();
    var index: u32 = 0;
    while (index < in_flight and index < total) : (index += 1) start_next(&state.slots[index]);
    if (c.ares_queue_wait_empty(channel, constants.cares_wait_ms_max) != c.ARES_SUCCESS) return error.CaresStalled;
    return .{ .elapsed_ns = harness.now_ns() - begin, .failures = state.failures.load(.monotonic) };
}

/// Starts lookups on `slot` until one of them does not answer inside the call that made it.
///
/// c-ares may answer before `ares_query_dnsrec` returns: `ares_send_nolock` calls the callback
/// itself when the answer is already there. The callback starts the next lookup, so calling this
/// again from inside it is recursion with a frame per lookup, and at 20,000 it overflowed the
/// stack. A start that happens inside a start now only says so, and the loop here makes the next
/// one. The claims bound the loop: there are `total` of them and no more.
fn start_next(slot: *Slot) void {
    if (slot.issuing.load(.acquire)) {
        slot.answered_inline.store(true, .release);
        return;
    }
    slot.issuing.store(true, .release);
    defer slot.issuing.store(false, .release);
    while (claim()) |index| {
        slot.answered_inline.store(false, .release);
        issue(slot, index);
        if (!slot.answered_inline.load(.acquire)) return;
    }
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

// Tests. The loop against the responder is in `end_to_end.zig`; this pins the guard that keeps a
// start from nesting inside a start, which no run can be made to exercise on demand — c-ares
// answers inline when it happens to, not when a test asks.

const testing = std.testing;

test "a start that happens inside a start makes no query of its own" {
    var slot: Slot = .{ .issuing = .init(true) };
    start_next(&slot);
    try testing.expect(slot.answered_inline.load(.acquire));
    // Still the outer start's to finish: the loop there makes the next query, not this call.
    try testing.expect(slot.issuing.load(.acquire));
}
