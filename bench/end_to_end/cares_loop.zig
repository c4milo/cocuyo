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

/// One lookup in flight: when it started, and the name it asked, which c-ares copies at start.
const Slot = struct {
    started_ns: u64 = 0,
    text: [constants.name_bytes]u8 = undefined,
};

const State = struct {
    channel: ?*c.ares_channel_t,
    total: u32,
    started: u32 = 0,
    done: u32 = 0,
    failures: u32 = 0,
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
    if (c.ares_queue_wait_empty(channel, -1) != c.ARES_SUCCESS) return error.CaresWaitFailed;
    return .{ .elapsed_ns = harness.now_ns() - begin, .failures = state.failures };
}

/// Starts the next lookup in `slot`. Called from `run` for the first batch and from the callback
/// for every one after, under c-ares's lock either way.
fn start_next(slot: *Slot) void {
    const name = std.fmt.bufPrintZ(&slot.text, "h{d}.example.", .{state.started}) catch unreachable;
    slot.started_ns = harness.now_ns();
    state.started += 1;
    const status = c.ares_query_dnsrec(state.channel, name.ptr, c.ARES_CLASS_IN, c.ARES_REC_TYPE_A, &on_answer, slot, null);
    assert(status == c.ARES_SUCCESS);
}

fn on_answer(arg: ?*anyopaque, status: c.ares_status_t, timeouts: usize, record: ?*const c.ares_dns_record_t) callconv(.c) void {
    _ = timeouts;
    const slot: *Slot = @ptrCast(@alignCast(arg.?));
    const now = harness.now_ns();
    state.latencies[state.done] = now - slot.started_ns;
    state.done += 1;
    if (status != c.ARES_SUCCESS or c.ares_dns_record_rr_cnt(record, c.ARES_SECTION_ANSWER) == 0) state.failures += 1;
    if (state.started < state.total) start_next(slot);
}
