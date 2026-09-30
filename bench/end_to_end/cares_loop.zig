//! c-ares's side of the comparison: one channel with its event thread, which is how c-ares
//! recommends being driven since 1.26, and `ares_query_dnsrec` for each A lookup, sent from this
//! thread when the schedule says it is due. The callback runs on c-ares's thread, or inside
//! `ares_query_dnsrec` when c-ares answers at once, and only records: no lookup starts from it.
//! So the two threads share the count of lookups done, the failures, and each lookup's latency,
//! which only the callback writes and only this thread reads once the row is over.
const std = @import("std");
const assert = std.debug.assert;
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const schedule_module = @import("schedule.zig");
const kernel = @import("kernel.zig");
const Schedule = schedule_module.Schedule;
const Outcome = schedule_module.Outcome;
const Record = schedule_module.Record;
const c = @cImport(@cInclude("ares.h"));

const State = struct {
    schedule: Schedule,
    begin_ns: u64,
    total: u32,
    record: Record,
    done: std.atomic.Value(u32) = .init(0),
    failures: std.atomic.Value(u32) = .init(0),
};

/// Written before the row's first query, and read by the callback after c-ares's lock, which the
/// query and the callback both take, has ordered it.
var state: State = undefined;

pub fn run(port: u16, schedule: Schedule, total: u32, record: Record) !Outcome {
    assert(schedule.in_flight >= 1 and schedule.in_flight <= constants.in_flight_max);
    assert(record.holds(total));
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

    const kernel_before = kernel.read();
    state = .{ .schedule = schedule, .begin_ns = harness.now_ns(), .total = total, .record = record };
    var in_flight_peak: u32 = 0;
    for (0..total) |at| {
        const index: u32 = @intCast(at);
        const deadline = harness.now_ns() + @as(u64, constants.cares_wait_ms_max) * constants.ns_per_ms;
        wait_for_room(index, deadline) catch |err| {
            std.debug.print("c-ares stalled: {d} of {d} answered, {d} sent\n", .{ state.done.load(.acquire), total, index });
            return err;
        };
        const now = wait_until_due(index);
        issue(channel, index, now);
        in_flight_peak = @max(in_flight_peak, index + 1 - state.done.load(.acquire));
    }
    if (c.ares_queue_wait_empty(channel, constants.cares_wait_ms_max) != c.ARES_SUCCESS) {
        // Every lookup was sent, so a queue that never empties is a lookup c-ares never ended;
        // the count says how many.
        std.debug.print("c-ares stalled: {d} of {d} answered\n", .{ state.done.load(.acquire), total });
        return error.CaresStalled;
    }
    // Every lookup the row sent has ended, or the rate below is over a count nobody made. The
    // acquire also orders every latency the callback wrote before the caller reads it.
    const done = state.done.load(.acquire);
    assert(done == total);
    return .{
        .elapsed_ns = harness.now_ns() - state.begin_ns,
        .failures = state.failures.load(.acquire),
        .in_flight_peak = in_flight_peak,
        .kernel = kernel.since(kernel_before, kernel.read()),
    };
}

/// Waits while the schedule's most are out. c-ares has been seen to hold a query and never end
/// it (docs/design.md §11), so the wait ends at `deadline_ns` like the queue's, and the row gives
/// up. It spins: this thread has nothing else to do, and a sleep would add its own lateness.
fn wait_for_room(index: u32, deadline_ns: u64) error{CaresStalled}!void {
    while (index - state.done.load(.acquire) >= state.schedule.in_flight) {
        if (harness.now_ns() >= deadline_ns) return error.CaresStalled;
        std.atomic.spinLoopHint();
    }
}

/// Sleeps until lookup `index` is due, and returns the clock when it is.
fn wait_until_due(index: u32) u64 {
    const due = state.schedule.due_ns(state.begin_ns, index);
    var now = harness.now_ns();
    while (now < due) {
        const wait = due - now;
        const request: std.c.timespec = .{
            .sec = @intCast(wait / constants.ns_per_s),
            .nsec = @intCast(wait % constants.ns_per_s),
        };
        _ = std.c.nanosleep(&request, null);
        now = harness.now_ns();
    }
    return now;
}

/// One query out, under c-ares's own lock. Its index rides in the callback's argument, one above
/// the index so that the first lookup's is not null.
fn issue(channel: ?*c.ares_channel_t, index: u32, now: u64) void {
    var text: [constants.name_bytes]u8 = undefined;
    // Not `catch unreachable`: when this failed it said nothing about why, and the name it was
    // asked to write always fits. A panic that carries the index is what a rerun needs.
    const name = std.fmt.bufPrintZ(&text, "h{d}.example.", .{index}) catch {
        std.debug.panic("the name for lookup {d} did not fit {d} octets", .{ index, constants.name_bytes });
    };
    state.record.late[index] = now - state.schedule.due_ns(state.begin_ns, index);
    // c-ares copies the name, so the buffer need outlive only the call.
    const argument: ?*anyopaque = @ptrFromInt(@as(usize, index) + 1);
    const status = c.ares_query_dnsrec(channel, name.ptr, c.ARES_CLASS_IN, c.ARES_REC_TYPE_A, &on_answer, argument, null);
    assert(status == c.ARES_SUCCESS);
}

fn on_answer(arg: ?*anyopaque, status: c.ares_status_t, timeouts: usize, record: ?*const c.ares_dns_record_t) callconv(.c) void {
    _ = timeouts;
    const now = harness.now_ns();
    const index: u32 = @intCast(@intFromPtr(arg.?) - 1);
    assert(index < state.total);
    const answered = status == c.ARES_SUCCESS and c.ares_dns_record_rr_cnt(record, c.ARES_SECTION_ANSWER) != 0;
    state.record.latencies[index] = now - state.schedule.due_ns(state.begin_ns, index);
    if (!answered) _ = state.failures.fetchAdd(1, .monotonic);
    const at = state.done.fetchAdd(1, .release);
    assert(at < state.total);
}

const testing = std.testing;

test "a lookup waits for room while the most are out, and the row gives up at the deadline" {
    state = .{ .schedule = .{ .period_ns = 0, .in_flight = 1 }, .begin_ns = 0, .total = 2, .record = undefined };
    // Nothing out: there is room at once, whatever the deadline.
    try wait_for_room(0, 0);
    // One out and none ended: no room, and a deadline already passed ends the wait.
    try testing.expectError(error.CaresStalled, wait_for_room(1, harness.now_ns()));
}
