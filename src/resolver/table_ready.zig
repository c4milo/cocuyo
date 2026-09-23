//! The ready list and the deadline bound of a table (docs/design.md §11, §16 decision 20): which
//! lookups have something to do, and the soonest instant any of them is waiting for.
//!
//! The list is threaded through the caller's own slots, two links and a flag in each, so it costs
//! no memory of its own and a slot leaves it in a step from wherever it sits. A poll takes from
//! the head instead of walking the table, which is what keeps one event's cost independent of how
//! many lookups are in flight. Free functions over the table, split out of `table.zig` so each is
//! scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const slots_module = @import("table_slots.zig");
const table_module = @import("table.zig");
const Resolver = table_module.Resolver;

/// Offers every lookup whose wait has run out, and finds the soonest deadline again. The
/// bound is a compare, so a poll that arrives before it costs one; the table is walked only
/// when a deadline has actually passed.
pub fn wake_expired(self: *Resolver, now_ns: u64) void {
    const soonest = self.soonest_ns orelse return;
    if (now_ns < soonest) return;
    self.soonest_ns = null;
    for (self.slots.items, 0..) |*slot, index| {
        if (!slot.occupied) continue;
        if (!slot.lookup.is_waiting()) continue;
        if (slot.lookup.deadline_ns <= now_ns) {
            offer(self, @intCast(index));
        } else {
            note_deadline(self, slot.lookup.deadline_ns);
        }
    }
}

/// Puts a slot on the ready list, at the back, unless it is on it already.
pub fn offer(self: *Resolver, index: u16) void {
    const slot = &self.slots.items[index];
    assert(slot.occupied);
    if (slot.ready) return;
    slot.ready = true;
    slot.next_ready = slots_module.slot_none;
    slot.prev_ready = self.ready_tail;
    if (self.ready_tail == slots_module.slot_none) {
        self.ready_head = index;
    } else {
        self.slots.items[self.ready_tail].next_ready = index;
    }
    self.ready_tail = index;
}

/// Takes the lookup that has waited longest for its turn, or null when none has.
pub fn take_ready(self: *Resolver) ?u16 {
    const index = self.ready_head;
    if (index == slots_module.slot_none) return null;
    withdraw(self, index);
    return index;
}

/// Takes a slot off the ready list, from wherever it sits.
pub fn withdraw(self: *Resolver, index: u16) void {
    const slot = &self.slots.items[index];
    if (!slot.ready) return;
    if (slot.prev_ready == slots_module.slot_none) {
        self.ready_head = slot.next_ready;
    } else {
        self.slots.items[slot.prev_ready].next_ready = slot.next_ready;
    }
    if (slot.next_ready == slots_module.slot_none) {
        self.ready_tail = slot.prev_ready;
    } else {
        self.slots.items[slot.next_ready].prev_ready = slot.prev_ready;
    }
    slot.ready = false;
    slot.next_ready = slots_module.slot_none;
    slot.prev_ready = slots_module.slot_none;
}

/// What an event leaves behind: a lookup with something to do goes on the ready list, and a
/// lookup that is waiting takes its deadline into the bound.
pub fn settle(self: *Resolver, index: u16) void {
    const slot = &self.slots.items[index];
    assert(slot.occupied);
    if (slot.lookup.is_waiting()) {
        note_deadline(self, slot.lookup.deadline_ns);
    } else {
        offer(self, index);
    }
}

pub fn note_deadline(self: *Resolver, deadline_ns: u64) void {
    if (self.soonest_ns == null or deadline_ns < self.soonest_ns.?) {
        self.soonest_ns = deadline_ns;
    }
}

// Tests.

const testing = std.testing;
const core = @import("core");
const fixtures = @import("fixtures.zig");
const Table = fixtures.Table;
const Event = table_module.Event;
const Verdict = @import("lookup.zig").Verdict;
const servers = fixtures.servers_two;

test "a lookup is offered once for each thing it has to do" {
    // The ready list of §11: what the caller has been told is not repeated, so one event costs
    // the same whether one lookup is in flight or a thousand.
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    try testing.expect(table.poll().?.action == .send_udp);
    try testing.expectEqual(@as(?Event, null), table.poll());
    table.resolver.on_sent(handle, table.now_ns);
    try testing.expectEqual(@as(?Event, null), table.poll());
    try testing.expectEqual(Verdict.accepted, table.answer(handle));
    try testing.expect(table.poll().?.action == .done);
    try testing.expectEqual(@as(?Event, null), table.poll());
    table.resolver.release(handle);
}

test "a lookup offered twice is on the list once" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    // `start` put it on the list; putting it on again must not link it twice, or the list runs
    // through the same slot for ever and the caller is told the same thing twice.
    offer(&table.resolver, handle.index);
    try testing.expect(table.poll().?.action == .send_udp);
    try testing.expectEqual(@as(?Event, null), table.poll());
    table.resolver.release(handle);
    try testing.expectEqual(@as(usize, 0), table.resolver.in_flight());
}

test "a wait that runs out offers the lookup again" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    try testing.expect(table.poll().?.action == .send_udp);
    table.resolver.on_sent(handle, table.now_ns);
    try testing.expectEqual(@as(?Event, null), table.poll());
    // Nothing has answered and the wait is over: the lookup asks to send again.
    table.now_ns = table.resolver.lookup_of(handle).deadline_ns;
    try testing.expect(table.poll().?.action == .send_udp);
    table.resolver.release(handle);
}

test "a released slot is off the ready list, and the table offers the others" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    table.resolver.release(first);
    const event = table.poll().?;
    try testing.expectEqual(second.index, event.handle.index);
    try testing.expectEqual(@as(?Event, null), table.poll());
    table.resolver.release(second);
    try testing.expectEqual(@as(usize, 0), table.resolver.in_flight());
}

test "the deadline offered is never later than the soonest, and is found again when it fires" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    _ = table.poll();
    table.resolver.on_sent(first, table.now_ns);
    _ = table.poll();
    // The second is sent later, so it waits for a later instant than the first.
    table.now_ns += 10;
    table.resolver.on_sent(second, table.now_ns);
    const early = table.resolver.lookup_of(first).deadline_ns;
    const late = table.resolver.lookup_of(second).deadline_ns;
    try testing.expectEqual(@as(?u64, early), table.resolver.next_deadline_ns());

    // The lookup that held the bound answers, so the bound is early rather than wrong. The poll
    // that its timer causes finds the soonest again.
    try testing.expectEqual(Verdict.accepted, table.answer(first));
    try testing.expectEqual(@as(?u64, early), table.resolver.next_deadline_ns());
    table.now_ns = early;
    _ = table.poll();
    try testing.expectEqual(@as(?u64, late), table.resolver.next_deadline_ns());
    table.resolver.release(first);
    table.resolver.release(second);
}

test "a poll that asks for a connection puts its deadline in the bound" {
    // Every query over TCP: the first poll asks for a connection and leaves the lookup waiting
    // for it. A bound that missed that wait left the caller no timer to arm, and a connect that
    // never completed was never given up on.
    var table: Table = .{ .config = .{ .servers = &servers, .use_tcp = true } };
    table.open();
    const handle = try table.start("example.com.");
    try testing.expect(table.poll().?.action == .connect_tcp);
    const deadline = table.resolver.lookup_of(handle).deadline_ns;
    try testing.expectEqual(@as(?u64, deadline), table.resolver.next_deadline_ns());
    table.now_ns = deadline;
    try testing.expect(table.poll().?.action == .connect_tcp);
    try testing.expectEqual(@as(u8, 1), table.resolver.lookup_of(handle).server_index);
    table.resolver.release(handle);
}
