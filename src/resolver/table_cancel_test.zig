//! What a cancel does to a lookup in the table: settles one still waiting, and leaves the end of one
//! that has already ended to be taken (docs/design.md §4). Split from `table.zig` by the
//! file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const fixtures = @import("fixtures.zig");
const table_module = @import("table.zig");
const Event = table_module.Event;
const Verdict = @import("lookup.zig").Verdict;

const servers = fixtures.servers_two;
const Table = fixtures.Table;

test "cancelling settles a lookup and the caller sees it once" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    table.resolver.cancel(handle);
    const event = table.poll().?;
    try testing.expectEqual(core.Error.Canceled, event.action.failed.err);
    table.resolver.release(handle);
    try testing.expectEqual(@as(usize, 0), table.resolver.in_flight());
}

test "a cancel after a lookup has ended leaves its end to be taken" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    const send = table.poll().?;
    table.resolver.on_sent(send.handle, table.now_ns);
    try testing.expectEqual(Verdict.accepted, table.answer(handle));
    // The answer is in and not yet taken: the cancel comes too late and changes nothing.
    table.resolver.cancel(handle);
    try testing.expect(table.poll().?.action == .done);
    try testing.expectEqual(@as(?Event, null), table.poll());
    table.resolver.release(handle);
}
