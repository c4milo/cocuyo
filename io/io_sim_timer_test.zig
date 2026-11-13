//! The engine's one timer on the twin: it follows the table's soonest deadline, a deadline that
//! moves cancels it before the next is armed, an event of another component leaves it as it is,
//! and one that fires early is armed again (docs/design.md §19 step 13; §26, one operation for each
//! place). Split from `io_sim_test.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const Resolver = sim_test.Resolver;
const question = sim_test.question;
const tick_for = sim_test.tick_for;
const fixtures = @import("fixtures.zig");

test "the timer follows the table's soonest deadline" {
    var rig: Rig = .{};
    try rig.init(5, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(&question("example.com."), rig.loop.now());
    // A queued send is not a sent one: the wait, and the timer, start when it completes.
    try testing.expect(rig.engine.timer_handle == null);
    _ = try rig.step(0);
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(rig.engine.resolver.next_deadline_ns(), rig.engine.timer_due_ns);
    const result = try rig.until_result();
    try testing.expectEqual(cocuyo.Error.Timeout, result.outcome.failure.err);
    try testing.expectEqual(@as(u64, 4_000_000_000), rig.loop.now());
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a timer the deadline moved away from ends before the next timer is armed" {
    // The timer is one place, so one timer is in flight at most (docs/design.md §26, one
    // operation for each place). A deadline that moves cancels the timer, and the next timer is
    // armed at the cancelled one's end, which can arrive late (rotor decision 5, rule 2). The
    // table's deadline is a bound that moves only when it comes (§11), so the test moves the
    // deadline that the timer was armed for.
    var rig: Rig = .{};
    try rig.init(9, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(&question("first.example."), rig.loop.now());
    _ = try rig.step(0);
    const replaced = rig.engine.timer_id.?;
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    rig.engine.timer_due_ns = null;
    rig.engine.drive(rig.loop.now());
    // The timer is cancelled, and no other is armed while it is in flight.
    try testing.expectEqual(replaced, rig.engine.timer_id.?);
    try testing.expect(rig.engine.timer_handle == null);
    try testing.expect(rig.engine.operations.holds(replaced));
    try testing.expectEqual(@as(?u64, null), rig.engine.timer_due_ns);
    rig.engine.drive(rig.loop.now());
    try testing.expectEqual(replaced, rig.engine.timer_id.?);
    // The cancelled timer's end arrives, and the next timer is armed for the deadline.
    try testing.expectEqual(@as(u32, 1), try rig.step(0));
    try testing.expect(!rig.engine.operations.holds(replaced));
    const current = rig.engine.timer_id.?;
    try testing.expect(current != replaced);
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    // The next timer fires at the deadline.
    try testing.expectEqual(cocuyo.Error.Timeout, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "an event another component submitted is handed back untouched" {
    // A consumer's loop carries its own operations beside the resolver's, told apart by the tag
    // in the high bits of `user_data` (docs/design.md §24). This one is the resolver's own
    // current timer in every bit but the tag: taken for the resolver's, it would end that timer.
    var rig: Rig = .{};
    try rig.init(11, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    const started = try rig.engine.start(&question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    const armed = rig.engine.timer_handle;
    try testing.expect(armed != null);
    const own = Resolver.user_data(rig.engine.timer_id.?);
    const other_tag: u64 = Resolver.tag +% 1;
    const below_tag: u64 = (@as(u64, 1) << io.constants.tag_shift) - 1;
    const foreign: rotor.Event = .{ .user_data = (other_tag << io.constants.tag_shift) | (own & below_tag), .result = 0, .flags = .{} };
    try testing.expect(!rig.engine.apply(foreign, rig.loop.now()));
    try testing.expectEqual(armed, rig.engine.timer_handle);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    try testing.expectEqual(@as(usize, 1), rig.engine.in_flight());

    rig.engine.cancel(started, rig.loop.now());
    try testing.expectEqual(cocuyo.Error.Canceled, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a timer that fires before the caller's clock reaches the deadline is armed again" {
    var rig: Rig = .{};
    try rig.init(10, .{ .{ .down = true }, .{ .down = true } }, .{ .servers = &.{}, .timeout_ns = 2_000_000_000, .attempts = 1 });
    _ = try rig.engine.start(&question("example.com."), rig.loop.now());
    _ = try rig.step(0);
    try testing.expectEqual(@as(u32, 1), try tick_for(&rig.loop, &rig.events, fixtures.wait_ns));
    try testing.expectEqual(@as(u64, 2_000_000_000), rig.loop.now());
    // The caller's clock is a nanosecond short of the deadline the loop's has reached: nothing
    // times out yet, and the timer must be armed again rather than left for dead.
    try testing.expect(rig.engine.apply(rig.events[0], rig.loop.now() - 1));
    try testing.expectEqual(@as(usize, 1), rig.engine.in_flight());
    try testing.expect(rig.engine.timer_handle != null);
    try testing.expectEqual(@as(?u64, 2_000_000_000), rig.engine.timer_due_ns);
    try testing.expectEqual(cocuyo.Error.Timeout, (try rig.until_result()).outcome.failure.err);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}
