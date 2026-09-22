//! The end-to-end comparison of docs/design.md §19 step 15: both stacks against one in-process
//! responder, lookups per second and latency at a number in flight, on the machine and the day
//! §11 names. Run by `zig build bench-cares` after the table of `bench/cares.zig`.
//!
//! What is compared. cocuyo is the engine of §19 step 13 over rotor's loop in this thread,
//! ReleaseSafe with its assertions on; c-ares is the installed build with its event thread, which
//! gives it a thread of its own and every core it wants. Both ask one A question per lookup, of
//! distinct absolute names, so neither's cache answers, and both are answered by the same
//! responder thread through the same loopback. The responder and the kernel are in every number,
//! and they are the same for both.
const std = @import("std");
const assert = std.debug.assert;
const harness = @import("../harness.zig");
const constants = @import("constants.zig");
const responder_module = @import("responder.zig");
const rotor_loop = @import("rotor_loop.zig");
const cares_loop = @import("cares_loop.zig");

var latencies: [constants.lookups_total]u64 = undefined;

pub fn run() void {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    responder.start() catch |err| {
        std.debug.print("end to end: the responder could not start: {t}\n", .{err});
        return;
    };
    defer responder.stop();
    std.debug.print("\nend to end, {d} lookups of distinct names, one responder thread on the loopback\n\n", .{constants.lookups_total});
    std.debug.print("{s:<8} {s:>10} {s:>12} {s:>12} {s:>12} {s:>9}\n", .{ "stack", "in flight", "lookups/s", "median us", "p99 us", "failures" });
    for (constants.in_flight_counts) |in_flight| {
        const ours = rotor_loop.run(responder.port, in_flight, constants.lookups_total, &latencies) catch |err| {
            std.debug.print("cocuyo: {t}\n", .{err});
            continue;
        };
        report("cocuyo", in_flight, ours.elapsed_ns, ours.failures, latencies[0..constants.lookups_total]);
        const theirs = cares_loop.run(responder.port, in_flight, constants.lookups_total, &latencies) catch |err| {
            std.debug.print("c-ares: {t}\n", .{err});
            continue;
        };
        report("c-ares", in_flight, theirs.elapsed_ns, theirs.failures, latencies[0..constants.lookups_total]);
    }
}

/// One row: lookups per second over the wall time, and the median and 99th percentile latency
/// in microseconds. Sorts the latencies, which the next run overwrites anyway.
fn report(stack: []const u8, in_flight: u32, elapsed_ns: u64, failures: u32, measured: []u64) void {
    assert(elapsed_ns > 0);
    std.mem.sort(u64, measured, {}, std.sort.asc(u64));
    const per_second = @as(u64, measured.len) * constants.ns_per_s / elapsed_ns;
    const median = measured[measured.len / 2] / constants.ns_per_us;
    const p99 = measured[measured.len * constants.percentile / constants.percent] / constants.ns_per_us;
    std.debug.print("{s:<8} {d:>10} {d:>12} {d:>12} {d:>12} {d:>9}\n", .{ stack, in_flight, per_second, median, p99, failures });
}

// Tests. They run under `zig build bench-cares` and `zig build test-cares`, since they link
// c-ares, and they open sockets on the loopback, which the gate must not need.

const testing = std.testing;
const cocuyo = @import("cocuyo");
const wire = @import("wire");
const udp = @import("udp.zig");

test {
    // The two drivers' own tests, which the runs below do not reach.
    _ = cares_loop;
    _ = rotor_loop;
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

test "cocuyo resolves every name through the engine over rotor against the responder" {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    var measured: [constants.test_total]u64 = undefined;
    const outcome = try rotor_loop.run(responder.port, constants.test_in_flight, constants.test_total, &measured);
    try testing.expectEqual(@as(u32, 0), outcome.failures);
    try testing.expect(outcome.elapsed_ns > 0);
    for (measured) |latency| try testing.expect(latency > 0 and latency < constants.latency_ns_max);
}

test "one lookup at a time is answered without waiting out a tick" {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    var measured: [constants.test_total_one]u64 = undefined;
    const outcome = try rotor_loop.run(responder.port, 1, constants.test_total_one, &measured);
    try testing.expectEqual(@as(u32, 0), outcome.failures);
    // The wall time, not the latencies: a lookup's latency is read when its result is taken,
    // which is before the driver waits, so a wait that follows every result shows here alone.
    try testing.expect(outcome.elapsed_ns < constants.test_total_one * constants.latency_ns_max);
    for (measured) |latency| try testing.expect(latency > 0 and latency < constants.latency_ns_max);
}

test "c-ares resolves every name through its event thread against the responder" {
    var responder: responder_module.Responder = .{ .socket = undefined, .port = 0 };
    try responder.start();
    defer responder.stop();
    var measured: [constants.test_total]u64 = undefined;
    const outcome = try cares_loop.run(responder.port, constants.test_in_flight, constants.test_total, &measured);
    try testing.expectEqual(@as(u32, 0), outcome.failures);
    try testing.expect(outcome.elapsed_ns > 0);
    for (measured) |latency| try testing.expect(latency > 0 and latency < constants.latency_ns_max);
}
