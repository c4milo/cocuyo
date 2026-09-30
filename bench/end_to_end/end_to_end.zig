//! The end-to-end comparison of docs/design.md §19 step 15: both stacks against one in-process
//! responder, each row a load offered on a schedule, on the machine and the day §11 names. Run by
//! `zig build bench-cares` after the table of `bench/cares.zig`.
//!
//! What is compared. cocuyo is the engine of §19 step 13 over rotor's loop in this thread,
//! ReleaseSafe with its assertions on; c-ares is the installed build with its event thread, which
//! gives it a thread of its own and every core it wants. Both ask one A question per lookup, of
//! distinct absolute names, so neither's cache answers, and both are answered by the same
//! responder, a process of its own, through the same loopback. The responder and the kernel are in
//! every latency, and they are the same for both. Before the first row, `warm_up_lookups` go unmeasured, so
//! neither stack pays for the process's warm-up in its numbers.
//!
//! What a row says. Each lookup is sent when `schedule.zig` says it is due, whether or not the
//! stack has answered, and its latency runs from then to its result. The row gives the load it
//! offered and the lookups a second it got; the median, the 99th and the 99.9th percentile and the
//! slowest latency; how late the 99th percentile of lookups went out, which is the driver's part
//! of the latency and not the stack's; the most that were out at once; the failures; and the
//! system calls and context switches of the stack's process per lookup (`kernel.zig`).
const std = @import("std");
const assert = std.debug.assert;
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const responder_module = @import("responder.zig");
const schedule_module = @import("schedule.zig");
const kernel = @import("kernel.zig");
const rotor_loop = @import("rotor_loop.zig");
const cares_loop = @import("cares_loop.zig");
const Schedule = schedule_module.Schedule;
const Outcome = schedule_module.Outcome;
const Record = schedule_module.Record;

var latencies: [constants.lookups_total]u64 = undefined;
var late: [constants.lookups_total]u64 = undefined;
const record: Record = .{ .latencies = &latencies, .late = &late };

pub fn run() void {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    responder.start() catch |err| {
        std.debug.print("end to end: the responder could not start: {t}\n", .{err});
        return;
    };
    defer responder.stop();
    // Unmeasured: the responder and the cores come up to speed here, not in a row.
    _ = rotor_loop.run(responder.port, Schedule.of_rate(constants.rates[0]), constants.warm_up_lookups, record) catch |err| {
        std.debug.print("warm-up: {t}\n", .{err});
        return;
    };
    std.debug.print("\nend to end, {d} lookups of distinct names a row, each sent when due with at most {d} out, one responder process on the loopback, after {d} to warm up; latencies in microseconds, and the stack's system calls and context switches per lookup\n\n", .{ constants.lookups_total, constants.in_flight_max, constants.warm_up_lookups });
    std.debug.print("{s:<8} {s:>9} {s:>10} {s:>8} {s:>8} {s:>8} {s:>8} {s:>9} {s:>8} {s:>9} {s:>9} {s:>9}\n", .{ "stack", "offered/s", "lookups/s", "median", "p99", "p99.9", "max", "late p99", "most out", "failures", "syscalls", "switches" });
    for (constants.rates) |rate| {
        const schedule = Schedule.of_rate(rate);
        const ours = rotor_loop.run(responder.port, schedule, constants.lookups_total, record) catch |err| {
            std.debug.print("cocuyo: {t}\n", .{err});
            continue;
        };
        report("cocuyo", rate, ours, constants.lookups_total);
        const answered_before = responder.answered();
        const theirs = cares_loop.run(responder.port, schedule, constants.lookups_total, record) catch |err| {
            // With the driver's own count of what it sent, this says which side lost a stalled
            // query: a responder that answered every one sent means c-ares had the reply and did
            // not take it, and one short means c-ares never sent the query.
            std.debug.print("c-ares: {t}, the responder answered {d} of this row's queries\n", .{
                err,
                responder.answered() - answered_before,
            });
            continue;
        };
        report("c-ares", rate, theirs, constants.lookups_total);
    }
}

/// One row: the load offered, lookups per second over the wall time, the latencies, how late the
/// 99th percentile of lookups went out, the most out at once, the failures, and the kernel's
/// counts per lookup. Sorts both arrays, which the next row overwrites anyway.
fn report(stack: []const u8, rate: u32, outcome: Outcome, total: u32) void {
    assert(outcome.elapsed_ns > 0);
    const measured = latencies[0..total];
    const lateness = late[0..total];
    std.mem.sort(u64, measured, {}, std.sort.asc(u64));
    std.mem.sort(u64, lateness, {}, std.sort.asc(u64));
    const per_second = @as(u64, total) * constants.ns_per_s / outcome.elapsed_ns;
    std.debug.print("{s:<8} {d:>9} {d:>10} {d:>8} {d:>8} {d:>8} {d:>8} {d:>9} {d:>8} {d:>9} ", .{
        stack,
        rate,
        per_second,
        at_permille(measured, constants.permille_median) / constants.ns_per_us,
        at_permille(measured, constants.permille_p99) / constants.ns_per_us,
        at_permille(measured, constants.permille_p999) / constants.ns_per_us,
        measured[measured.len - 1] / constants.ns_per_us,
        at_permille(lateness, constants.permille_p99) / constants.ns_per_us,
        outcome.in_flight_peak,
        outcome.failures,
    });
    if (outcome.kernel.syscalls) |syscalls| print_per_lookup(syscalls, total) else std.debug.print("{s:>9} ", .{"-"});
    print_per_lookup(outcome.kernel.switches, total);
    std.debug.print("\n", .{});
}

/// `count` over `total` lookups, with two decimals, right-aligned in nine columns.
fn print_per_lookup(count: u64, total: u32) void {
    const hundredths = per_lookup_hundredths(count, total);
    std.debug.print("{d:>6}.{d:0>2} ", .{ hundredths / constants.hundredths, hundredths % constants.hundredths });
}

/// `count` over `total` lookups, in hundredths, rounded down.
fn per_lookup_hundredths(count: u64, total: u32) u64 {
    assert(total > 0);
    return count * constants.hundredths / total;
}

/// The value `permille` thousandths of the way up a sorted array: the median at 500. The slowest
/// is the last value, which no permille below a thousand reaches.
fn at_permille(sorted: []const u64, permille: u32) u64 {
    assert(sorted.len > 0);
    assert(permille < constants.permille);
    return sorted[sorted.len * permille / constants.permille];
}

// Tests. They run under `zig build bench-cares` and `zig build test-cares`, since they link
// c-ares, and they open sockets on the loopback, which the gate must not need.

const testing = std.testing;
const cocuyo = @import("cocuyo");
const wire = @import("wire");
const udp = @import("udp.zig");

test {
    // The schedule's arithmetic, the kernel's counters and the c-ares side's wait for room, which
    // the runs below do not reach.
    _ = schedule_module;
    _ = kernel;
    _ = cares_loop;
}

test "the responder answers a query cocuyo builds with one A record for the name it asked" {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    const socket = try udp.open(0);
    defer udp.close(socket);
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const len = wire.query.write(&.{ .id = 0x1234, .name = try cocuyo.Name.from_text("h1.example."), .kind = .a }, &query);
    const to = udp.loopback(responder.port);
    try udp.send(socket, query[0..len], &to);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    var from: udp.Address = undefined;
    const bytes = udp.receive(socket, &reply, &from) orelse return error.NoReply;
    const header = try wire.header.parse(bytes);
    try testing.expectEqual(@as(u16, 0x1234), header.id);
    try testing.expectEqual(@as(u16, 1), header.ancount);
    try testing.expectEqualSlices(u8, &constants.answer_v4, bytes[bytes.len - constants.answer_v4.len ..]);
}

test "the responder answers from a process of its own, so the kernel's counts here hold none of its calls" {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    const socket = try udp.open(0);
    defer udp.close(socket);
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    const len = wire.query.write(&.{ .id = 0x1234, .name = try cocuyo.Name.from_text("h1.example."), .kind = .a }, &query);
    const to = udp.loopback(responder.port);
    var reply: [constants.datagram_bytes_max]u8 = undefined;
    var from: udp.Address = undefined;
    const before = kernel.read();
    for (0..constants.test_exchanges) |_| {
        try udp.send(socket, query[0..len], &to);
        _ = udp.receive(socket, &reply, &from) orelse return error.NoReply;
    }
    const counts = kernel.since(before, kernel.read());
    // This process makes two calls an exchange, a send and a receive. A responder counted with
    // it would add its own receive and send, four an exchange. Linux counts no system calls.
    if (counts.syscalls) |syscalls| try testing.expect(syscalls < 3 * constants.test_exchanges);
    try testing.expectEqual(@as(u64, constants.test_exchanges), responder.answered());
}

var test_latencies: [constants.test_total]u64 = undefined;
var test_late: [constants.test_total]u64 = undefined;
const test_record: Record = .{ .latencies = &test_latencies, .late = &test_late };

/// A row of the tests' own: one lookup a millisecond, a few out at most.
const test_schedule: Schedule = .{ .period_ns = constants.test_period_ns, .in_flight = constants.test_in_flight };

/// Every lookup due at once, and one out at a time: each waits for all those before it.
const queued_schedule: Schedule = .{ .period_ns = 0, .in_flight = 1 };

/// Runs the tests' row through `run` and requires it kept to the schedule.
fn expect_on_schedule(comptime run_row: anytype) !void {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    const outcome = try run_row(responder.port, test_schedule, constants.test_total, test_record);
    try testing.expectEqual(@as(u32, 0), outcome.failures);
    // No lookup goes out before it is due, so the row lasts at least until the last one is.
    const last_due = test_schedule.due_ns(0, constants.test_total - 1);
    try testing.expect(outcome.elapsed_ns >= last_due);
    // Nor does the driver wait past a due time. Each lookup is answered well within its period,
    // so between two there is nothing in flight, and a loop that waited for an event there would
    // wait out `tick_wait_ns_max` before the next went out.
    try testing.expect(outcome.elapsed_ns < last_due + constants.latency_ns_max);
    for (test_latencies) |latency| try testing.expect(latency > 0 and latency < constants.latency_ns_max);
}

/// Runs every lookup due at once, one out at a time, through `run`, and requires the latency of
/// the last to count its wait. Measured from when it went out, it would read like the first.
fn expect_queue_in_latency(comptime run_row: anytype) !void {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    const outcome = try run_row(responder.port, queued_schedule, constants.test_total, test_record);
    try testing.expectEqual(@as(u32, 0), outcome.failures);
    try testing.expectEqual(@as(u32, 1), outcome.in_flight_peak);
    // The last lookup was due when the row began and ended with it, and it went out only once
    // the others had ended, so both its latency and its lateness are most of the row.
    const last = constants.test_total - 1;
    try testing.expect(test_latencies[last] * 2 > outcome.elapsed_ns);
    try testing.expect(test_late[last] * 2 > outcome.elapsed_ns);
    try testing.expect(test_late[last] < test_latencies[last]);
}

test "cocuyo resolves every name through the engine over rotor, each when it is due" {
    try expect_on_schedule(rotor_loop.run);
}

test "c-ares resolves every name through its event thread, each when it is due" {
    try expect_on_schedule(cares_loop.run);
}

test "cocuyo's latencies count the wait of a lookup that was due and had no room" {
    try expect_queue_in_latency(rotor_loop.run);
}

test "c-ares's latencies count the wait of a lookup that was due and had no room" {
    try expect_queue_in_latency(cares_loop.run);
}

test "a count per lookup keeps two decimals" {
    try testing.expectEqual(@as(u64, 497), per_lookup_hundredths(99_400, 20_000));
    try testing.expectEqual(@as(u64, 0), per_lookup_hundredths(1, 20_000));
    try testing.expectEqual(@as(u64, 1818), per_lookup_hundredths(181_800, 10_000));
}

test "a permille reads that far up the sorted latencies, and never the slowest" {
    var sorted: [constants.permille]u64 = undefined;
    for (&sorted, 0..) |*value, index| value.* = index;
    try testing.expectEqual(@as(u64, 500), at_permille(&sorted, constants.permille_median));
    try testing.expectEqual(@as(u64, 990), at_permille(&sorted, constants.permille_p99));
    try testing.expectEqual(@as(u64, 999), at_permille(&sorted, constants.permille_p999));
    // A row of 20,000 puts the 99.9th percentile twenty from the slowest.
    var row: [constants.lookups_total]u64 = undefined;
    for (&row, 0..) |*value, index| value.* = index;
    try testing.expectEqual(@as(u64, 19_980), at_permille(&row, constants.permille_p999));
}
