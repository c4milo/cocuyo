//! What a row costs the kernel in this process: its system calls and context switches, read when
//! the row begins and when it ends (pepegrillo's method, step 2: count what a unit costs the
//! kernel). The responder runs in a process of its own (`responder.zig`), so none of its calls is
//! counted here, and every thread of the stack is: c-ares's event thread as well as this one.
//!
//! macOS counts both for the whole task, in the events flavour of `task_info`. Its `getrusage`
//! counts every context switch as involuntary, so a wakeup is not told apart from a preemption
//! there. Linux counts context switches in `getrusage`, and system calls only for a tracer, which
//! stops the process at every call and changes what it counts; so a row on Linux counts none.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const c = std.c;

pub const Counts = struct {
    /// System calls, or null where the kernel counts none for the process.
    syscalls: ?u64,
    /// Context switches, of every thread of the process.
    switches: u64,
};

/// The counters as they stand. Only `since` gives them a meaning.
pub const Reading = switch (builtin.os.tag) {
    .macos => task_events_info,
    .linux => c.rusage,
    else => @compileError("the end-to-end comparison runs on macOS and Linux"),
};

pub fn read() Reading {
    return switch (builtin.os.tag) {
        .macos => read_task(),
        .linux => read_usage(),
        else => unreachable,
    };
}

/// What the kernel counted between `before` and `after`.
pub fn since(before: Reading, after: Reading) Counts {
    return switch (builtin.os.tag) {
        .macos => .{
            .syscalls = @as(u64, wrapped(before.syscalls_unix, after.syscalls_unix)) +
                wrapped(before.syscalls_mach, after.syscalls_mach),
            .switches = wrapped(before.csw, after.csw),
        },
        .linux => .{
            .syscalls = null,
            .switches = grown(before.nvcsw, after.nvcsw) + grown(before.nivcsw, after.nivcsw),
        },
        else => unreachable,
    };
}

/// `task_events_info` and its flavour, as `<mach/task_info.h>` declares them. The counters are
/// `integer_t`, 32 bits, and a process that runs long enough wraps them.
const task_events_info = extern struct {
    faults: i32,
    pageins: i32,
    cow_faults: i32,
    messages_sent: i32,
    messages_received: i32,
    syscalls_mach: i32,
    syscalls_unix: i32,
    csw: i32,
};
const task_events_info_flavor: c.task_flavor_t = 2;

fn read_task() task_events_info {
    var info: task_events_info = undefined;
    var count: c.mach_msg_type_number_t = @sizeOf(task_events_info) / @sizeOf(c.natural_t);
    const status = c.task_info(c.mach_task_self(), task_events_info_flavor, @ptrCast(&info), &count);
    assert(status == 0);
    assert(count == @sizeOf(task_events_info) / @sizeOf(c.natural_t));
    return info;
}

fn read_usage() c.rusage {
    var usage: c.rusage = undefined;
    assert(c.getrusage(c.rusage.SELF, &usage) == 0);
    return usage;
}

/// How far a 32-bit counter went from `before` to `after`, across a wrap.
fn wrapped(before: i32, after: i32) u32 {
    return @as(u32, @bitCast(after)) -% @as(u32, @bitCast(before));
}

/// How far a counter that never wraps went from `before` to `after`.
fn grown(before: isize, after: isize) u64 {
    assert(after >= before);
    return @intCast(after - before);
}

const testing = std.testing;

test "a 32-bit counter's growth reads right across a wrap" {
    try testing.expectEqual(@as(u32, 5), wrapped(10, 15));
    try testing.expectEqual(@as(u32, 3), wrapped(std.math.maxInt(i32) - 1, std.math.minInt(i32) + 1));
    try testing.expectEqual(@as(u32, 2), wrapped(-1, 1));
}

test "the kernel counts the system calls and switches this process makes" {
    const before = read();
    // A sleep is a system call, and it gives the processor up, which is a context switch.
    const request: c.timespec = .{ .sec = 0, .nsec = std.time.ns_per_ms };
    const sleeps = 10;
    for (0..sleeps) |_| _ = c.nanosleep(&request, null);
    const counts = since(before, read());
    try testing.expect(counts.switches >= sleeps);
    if (counts.syscalls) |syscalls| try testing.expect(syscalls >= sleeps);
    try testing.expectEqual(builtin.os.tag == .linux, counts.syscalls == null);
}
