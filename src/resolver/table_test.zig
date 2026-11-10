//! The table's own tests: it starts lookups, hands each datagram to the lookup it belongs to, and
//! frees their slots (docs/design.md §4 and §11). Split from `table.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const fixtures = @import("fixtures.zig");
const table_module = @import("table.zig");
const Event = table_module.Event;
const Handle = table_module.Handle;
const Verdict = @import("lookup.zig").Verdict;

const servers = fixtures.servers_two;
const Table = fixtures.Table;
const slot_count = fixtures.slot_count;
const key_count = fixtures.key_count;

test "keys_for gives the least power of two that holds the floor of keys for each slot" {
    const limits = @import("limits.zig");
    const lookup_slots_max = @import("core").limits.lookup_slots_max;
    for ([_]usize{ 1, 2, 3, 4, 5, 64, 100, lookup_slots_max }) |slots| {
        const keys = table_module.Resolver.keys_for(slots);
        try testing.expect(std.math.isPowerOfTwo(keys));
        try testing.expect(keys >= slots * limits.keys_per_slot_min);
        // The least one: half of it is under the floor.
        try testing.expect(keys / 2 < slots * limits.keys_per_slot_min);
    }
    // What `init` asserts of a table's keys, for the keys the fixtures hold.
    try testing.expectEqual(key_count, table_module.Resolver.keys_for(slot_count));
}

test "a table starts lookups, answers them, and frees their slots" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    try testing.expectEqual(@as(usize, 1), table.resolver.in_flight());

    const event = table.poll().?;
    try testing.expectEqual(handle, event.handle);
    try testing.expect(event.action == .send_udp);
    table.resolver.on_sent(handle, table.now_ns);

    try testing.expectEqual(Verdict.accepted, table.answer(handle));
    const done = table.poll().?;
    try testing.expectEqual(@as(usize, 1), done.action.done.addresses.len);
    table.resolver.release(handle);
    try testing.expectEqual(@as(usize, 0), table.resolver.in_flight());
    try testing.expectEqual(@as(?Event, null), table.poll());
}

test "a full table refuses another lookup until a slot is freed" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    var handles: [slot_count]Handle = undefined;
    for (&handles) |*handle| handle.* = try table.start("example.com.");
    try testing.expectEqual(@as(usize, slot_count), table.resolver.in_flight());
    try testing.expectError(error.NoSlot, table.start("example.com."));
    table.resolver.release(handles[2]);
    _ = try table.start("other.example.");
}

test "a datagram reaches the lookup whose transaction it carries" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    while (table.poll()) |event| {
        table.resolver.on_sent(event.handle, table.now_ns);
    }
    try testing.expectEqual(Verdict.accepted, table.answer(second));
    try testing.expect(table.resolver.lookup_of(second).state == .done);
    try testing.expect(table.resolver.lookup_of(first).state == .awaiting_udp);

    // And the other way round, which is the case that matters: `second` sits first in the chain
    // and ignores this datagram, so a walk that stopped there would drop `first`'s answer.
    try testing.expectEqual(Verdict.accepted, table.answer(first));
    try testing.expect(table.resolver.lookup_of(first).state == .done);
}

test "a datagram with one lookup's id and another's question is refused by both" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    while (table.poll()) |event| {
        table.resolver.on_sent(event.handle, table.now_ns);
    }
    try testing.expectEqual(Verdict.ignored, table.crosstalk(first, second));
    try testing.expect(table.resolver.lookup_of(first).state == .awaiting_udp);
    try testing.expect(table.resolver.lookup_of(second).state == .awaiting_udp);
    // The real answer still lands afterwards.
    try testing.expectEqual(Verdict.accepted, table.answer(first));
}

test "a lookup that drew a new transaction is still reachable" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    _ = table.poll();
    const lookup = table.resolver.lookup_of(handle);
    table.resolver.on_sent(handle, table.now_ns);
    const first_id = lookup.transaction.id;

    // The wait runs out, which draws a new transaction for the next server.
    table.now_ns = lookup.deadline_ns;
    _ = table.poll();
    try testing.expect(lookup.transaction.id != first_id or
        lookup.transaction.case_seed != 0);
    table.resolver.on_sent(handle, table.now_ns);
    try testing.expectEqual(Verdict.accepted, table.answer(handle));
}

test "the poll rotates, so one lookup cannot starve another" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    const one = table.poll().?;
    const two = table.poll().?;
    try testing.expect(one.handle.index != two.handle.index);
    try testing.expect(one.handle.index == first.index or one.handle.index == second.index);
}

test "a released slot comes back with a new generation" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("example.com.");
    table.resolver.release(first);
    const second = try table.start("example.com.");
    try testing.expectEqual(first.index, second.index);
    try testing.expect(first.generation != second.generation);
}

test "a datagram for a released slot is ignored rather than delivered" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    _ = table.poll();
    const lookup = table.resolver.lookup_of(handle);
    table.resolver.on_sent(handle, table.now_ns);
    const message = table.build(lookup, fixtures.answer_a);
    table.resolver.release(handle);
    table.now_ns += 1;
    try testing.expectEqual(
        Verdict.ignored,
        table.resolver.on_datagram(message, servers[0].endpoint, table.now_ns),
    );
}

test "every slot and key is usable, and the key table survives churn" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    // Start and release every slot several times over, which fills the key table with tombstones
    // and would break a probe that stopped at the first one.
    var round: usize = 0;
    while (round < key_count) : (round += 1) {
        var handles: [slot_count]Handle = undefined;
        for (&handles) |*handle| handle.* = try table.start("example.com.");
        while (table.poll()) |event| {
            table.resolver.on_sent(event.handle, table.now_ns);
        }
        for (handles) |handle| {
            try testing.expectEqual(Verdict.accepted, table.answer(handle));
            table.resolver.release(handle);
        }
    }
    try testing.expectEqual(@as(usize, 0), table.resolver.in_flight());
}

test "a cut datagram reaches the lookup whose transaction it carries, which then asks over TCP" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    while (table.poll()) |event| table.resolver.on_sent(event.handle, table.now_ns);
    const lookup = table.resolver.lookup_of(second);
    const whole = table.build(lookup, fixtures.answer_a);
    try testing.expectEqual(Verdict.accepted, table.resolver.on_datagram_cut(whole[0 .. whole.len - 1], lookup.server(), table.now_ns));
    // The table follows the lookup that moved: its next poll asks for the stream (docs/design.md §7).
    const event = table.poll().?;
    try testing.expectEqual(second, event.handle);
    try testing.expect(event.action == .connect_tcp);
    try testing.expect(table.resolver.lookup_of(first).state == .awaiting_udp);
}
