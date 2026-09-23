//! `Resolver`: a bounded table of lookups and the code that decides which lookup an inbound
//! datagram belongs to (docs/design.md §4 and §11).
//!
//! This layer exists for one reason: that decision is security-critical. A caller with one socket
//! and many questions in flight has to answer "whose is this?" before it can check anything, and
//! a caller that writes it itself writes the matching rules of §7 again. So the table answers it
//! once, and answers it by asking each candidate lookup to check the datagram against its own
//! transaction — a lookup handed someone else's datagram ignores it without touching its state.
//!
//! The table also owns every event entry point. A caller that reached past it to tell a lookup its
//! query went out would arm a deadline the table never learns about, and the timer the table hands
//! out would be wrong (the mutation T9 of docs/mutations.md found exactly that).
//!
//! The caller owns the slots and the key table, sizes them, and frees a slot when it has read the
//! answer. cocuyo allocates nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Endpoint = core.Endpoint;
const Question = core.Question;
const constants = @import("constants.zig");
const entropy_module = @import("entropy.zig");
const servers_module = @import("servers.zig");
const keys_module = @import("table_keys.zig");
const slots_module = @import("table_slots.zig");
const ready_module = @import("table_ready.zig");
const memory_module = @import("table_memory.zig");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Action = lookup_module.Action;
const Verdict = lookup_module.Verdict;

pub const MatchKey = keys_module.MatchKey;
pub const Handle = slots_module.Handle;
pub const Slot = slots_module.Slot;

/// What a poll found for one lookup.
pub const Event = struct {
    handle: Handle,
    action: Action,
};

pub const Resolver = struct {
    slots: slots_module.Slots,
    keys: []MatchKey,
    config: *const Config,
    /// The per-server state every lookup of the table shares: cookies now, failover next
    /// (docs/design.md §19 steps 10 and 12).
    servers: servers_module.Servers,
    entropy: entropy_module.Entropy,
    /// The lookups with something to do, oldest first: the ready list of docs/design.md §11,
    /// threaded through the slots. A poll takes from the head rather than walking the table, so
    /// what one event costs does not grow with the lookups in flight.
    ready_head: u16,
    ready_tail: u16,
    /// A lower bound on the soonest deadline in the table, or null when nothing is waiting. A
    /// bound and not the minimum: a deadline that moves earlier lowers it, and one that moves
    /// later or goes away leaves it, so the caller's timer can fire early and never late. The
    /// exact minimum is found again when it fires, which is the one scan of the table
    /// (docs/design.md §11).
    soonest_ns: ?u64,
    /// The cache under every lookup, or null when the caller keeps none (docs/design.md §20).
    /// The table names no cache: it names two functions, which `cocuyo.remembered_by` fills in
    /// from a `Cache` and a consumer with a cache of its own fills the same way.
    memory: ?memory_module.Memory,

    /// `keys.len` must be a power of two and at least `keys_per_slot_min` times `slots.len`: the
    /// probe relies on the mask, and the load factor keeps the probe short.
    pub fn init(slots: []Slot, keys: []MatchKey, config: *const Config, seed: u64) Resolver {
        config.assert_valid();
        assert(keys.len >= slots.len * constants.keys_per_slot_min);
        assert(std.math.isPowerOfTwo(keys.len));
        for (keys) |*key| key.* = .{};
        return .{
            .slots = slots_module.Slots.init(slots),
            .keys = keys,
            .config = config,
            .servers = servers_module.Servers.init(config, seed),
            .entropy = entropy_module.Entropy.init(seed),
            .ready_head = slots_module.slot_none,
            .ready_tail = slots_module.slot_none,
            .soonest_ns = null,
            .memory = null,
        };
    }

    /// Puts a cache under every lookup this table starts (docs/design.md §20). Set before the
    /// first lookup: a table with lookups already in flight would remember some and not others.
    pub fn remember_with(self: *Resolver, memory: memory_module.Memory) void {
        assert(self.in_flight() == 0);
        self.memory = memory;
    }

    /// Starts a lookup. Its seed is drawn from the table's own generator, so one seed at the top
    /// gives the whole table a reproducible stream (docs/design.md §7).
    pub fn start(self: *Resolver, question: Question) error{NoSlot}!Handle {
        const index = self.slots.acquire() orelse return error.NoSlot;
        const slot = &self.slots.items[index];
        slot.lookup.init_in_place(self.config, &self.servers, question, self.entropy.next());
        slot.keyed_id = slot.lookup.transaction.id;
        keys_module.insert(self.keys, slot.keyed_id, index);
        ready_module.offer(self, index);
        return self.slots.handle_of(index);
    }

    /// The next thing for the caller to do, for any lookup, or null when there is nothing to
    /// do now. The caller then sleeps until `next_deadline_ns`.
    ///
    /// Each lookup is offered once for each thing it has to do, and offered again when an event
    /// gives it something new: a send whose completion has not arrived, or an answer the caller
    /// has been handed and not yet freed, is not offered twice. That is what keeps one event's
    /// cost independent of the lookups in flight (docs/design.md §11 and §16 decision 20), and
    /// it is why a caller must act on what it is given rather than poll again to be reminded.
    pub fn poll(self: *Resolver, now_ns: u64, out: []u8) ?Event {
        assert(out.len >= core.constants.query_bytes_max);
        ready_module.wake_expired(self, now_ns);
        var taken: usize = 0;
        while (taken < self.slots.items.len) : (taken += 1) {
            const index = ready_module.take_ready(self) orelse return null;
            const slot = &self.slots.items[index];
            assert(slot.occupied);
            memory_module.recall_into(self.memory, slot, now_ns);
            const action = slot.lookup.poll(now_ns, out);
            self.rekey(index);
            if (action == .wait) {
                ready_module.note_deadline(self, action.wait);
                continue;
            }
            memory_module.remember_end(self.memory, slot, action, now_ns);
            return .{ .handle = self.slots.handle_of(index), .action = action };
        }
        return null;
    }

    /// The soonest instant any lookup is waiting for, or null when none is. A caller arms one
    /// timer for the whole table rather than one per lookup.
    /// The instant the caller's one timer is armed for: a bound on the soonest deadline, never
    /// later than it. A lookup that stops waiting leaves the bound where it was, so the timer can
    /// fire with nothing expired; the poll that follows finds the soonest again and the caller
    /// arms it anew. Firing early costs a wakeup, and never firing would cost an answer.
    pub fn next_deadline_ns(self: *const Resolver) ?u64 {
        return self.soonest_ns;
    }

    /// Hands a datagram to the lookup it belongs to, if any.
    ///
    /// The id chooses the candidates and the lookups do the deciding: each candidate runs every
    /// check of §7 against its own transaction, so a datagram carrying one lookup's id and
    /// another's question is ignored by both.
    pub fn on_datagram(
        self: *Resolver,
        message: []const u8,
        from: Endpoint,
        now_ns: u64,
    ) Verdict {
        const header = wire.header.parse(message) catch return .ignored;
        var candidates = keys_module.Candidates.init(self.keys, header.id);
        while (candidates.next()) |slot| {
            if (self.deliver(slot, message, from, now_ns) == .accepted) return .accepted;
        }
        return .ignored;
    }

    /// The caller sent what a poll asked for.
    pub fn on_sent(self: *Resolver, handle: Handle, now_ns: u64) void {
        self.event(handle, now_ns, Lookup.on_sent);
    }

    /// The send failed.
    pub fn on_send_failed(self: *Resolver, handle: Handle, now_ns: u64) void {
        self.event(handle, now_ns, Lookup.on_send_failed);
    }

    pub fn on_tcp_connected(self: *Resolver, handle: Handle, now_ns: u64) void {
        self.event(handle, now_ns, Lookup.on_tcp_connected);
    }

    pub fn on_tcp_failed(self: *Resolver, handle: Handle, now_ns: u64) void {
        self.event(handle, now_ns, Lookup.on_tcp_failed);
    }

    /// Settles a lookup as cancelled. The caller still sees one `.failed` for it, and then frees
    /// the slot with `release`. A lookup that has already ended keeps its end: the answer or the
    /// failure stands and is offered once, as it would have been, so every caller may cancel
    /// whatever it holds without first asking whether its end has come.
    pub fn cancel(self: *Resolver, handle: Handle) void {
        const slot = self.slot_of(handle);
        if (slot.lookup.is_settled()) return;
        slot.lookup.cancel();
        ready_module.settle(self, handle.index);
    }

    /// Frees a slot. Every slice the lookup handed out — the addresses of an answer, the names —
    /// points into the slot and is invalid from here.
    pub fn release(self: *Resolver, handle: Handle) void {
        const slot = self.slot_of(handle);
        keys_module.remove(self.keys, slot.keyed_id, handle.index);
        ready_module.withdraw(self, handle.index);
        self.slots.release(handle.index);
    }

    /// How many lookups are in flight.
    pub fn in_flight(self: *const Resolver) usize {
        return self.slots.occupied_count();
    }

    /// The lookup a handle names, for a caller that wants to read its state. Every event goes
    /// through the table's own entry points, so that the deadline cache follows it.
    pub fn lookup_of(self: *Resolver, handle: Handle) *Lookup {
        return &self.slot_of(handle).lookup;
    }

    /// One event on one lookup: forward it, follow any new transaction, and put the lookup back
    /// where it belongs, because every one of these can give it something to do or a new instant
    /// to wait for.
    fn event(
        self: *Resolver,
        handle: Handle,
        now_ns: u64,
        comptime apply: fn (*Lookup, u64) void,
    ) void {
        const slot = self.slot_of(handle);
        apply(&slot.lookup, now_ns);
        self.rekey(handle.index);
        ready_module.settle(self, handle.index);
    }

    fn slot_of(self: *Resolver, handle: Handle) *Slot {
        return self.slots.get(handle);
    }

    fn deliver(
        self: *Resolver,
        index: u16,
        message: []const u8,
        from: Endpoint,
        now_ns: u64,
    ) Verdict {
        assert(index < self.slots.items.len);
        const slot = &self.slots.items[index];
        // A key naming a free slot is a broken table rather than a stray datagram: `release`
        // tombstones the key it held, so nothing can reach a free slot's lookup, which is
        // `undefined` until something takes it.
        assert(slot.occupied);
        const verdict = slot.lookup.on_response(message, from, now_ns);
        if (verdict == .accepted) {
            self.rekey(index);
            ready_module.settle(self, index);
        }
        return verdict;
    }

    /// Follows a lookup that drew a new transaction.
    fn rekey(self: *Resolver, index: u16) void {
        const slot = &self.slots.items[index];
        assert(slot.occupied);
        const current = slot.lookup.transaction.id;
        if (current == slot.keyed_id) return;
        keys_module.remove(self.keys, slot.keyed_id, index);
        keys_module.insert(self.keys, current, index);
        slot.keyed_id = current;
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const Name = core.Name;

const servers = fixtures.servers_two;
const Table = fixtures.Table;
const slot_count = fixtures.slot_count;
const key_count = fixtures.key_count;
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

test "the table reports one deadline for every lookup waiting" {
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    try testing.expectEqual(@as(?u64, null), table.resolver.next_deadline_ns());
    _ = table.poll();
    table.resolver.on_sent(first, 10);
    _ = table.poll();
    table.resolver.on_sent(second, 20);
    const soonest = table.resolver.next_deadline_ns().?;
    try testing.expectEqual(table.resolver.lookup_of(first).deadline_ns, soonest);
    try testing.expect(soonest < table.resolver.lookup_of(second).deadline_ns);
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

test "two lookups sharing a transaction id are both offered the datagram" {
    // An id is sixteen bits drawn from a generator, so a collision between two live lookups is
    // unlikely rather than impossible. A table that stopped at the first candidate would drop the
    // answer whenever it happened, which is a bug that shows up once in thousands of lookups.
    var table: Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const first = try table.start("one.example.");
    const second = try table.start("two.example.");
    while (table.poll()) |event| table.resolver.on_sent(event.handle, table.now_ns);

    const shared = table.resolver.lookup_of(second).transaction.id;
    table.resolver.lookup_of(first).transaction.id = shared;
    // The collision is made by hand, so it is keyed by hand: a lookup that draws a new
    // transaction is re-keyed by the entry point that moved it, and nothing has moved this one.
    table.resolver.rekey(first.index);
    try testing.expectEqual(@as(?Event, null), table.poll());
    try testing.expectEqual(Verdict.accepted, table.answer(second));
    try testing.expect(table.resolver.lookup_of(second).state == .done);
    try testing.expect(table.resolver.lookup_of(first).state == .awaiting_udp);

    // And the other way round, which is the case that matters: `second` sits first in the chain
    // and ignores this datagram, so a walk that stopped there would drop `first`'s answer.
    try testing.expectEqual(Verdict.accepted, table.answer(first));
    try testing.expect(table.resolver.lookup_of(first).state == .done);
}

test "a deadline armed after the cache was filled is not missed" {
    // A lookup on its second pass waits twice as long as a fresh one, so a table that did not
    // drop its cached deadline when the fresh lookup was sent would hand the caller a timer
    // running past the fresh lookup's timeout.
    // One server, so the first wait that expires starts a second pass, which waits twice as long
    // (docs/design.md §5). With two servers the retry only moves along the list and the two waits
    // would be the same length.
    var table: Table = .{ .config = .{ .servers = &fixtures.servers_one } };
    table.open();
    const slow = try table.start("slow.example.");
    _ = table.poll();
    table.resolver.on_sent(slow, table.now_ns);
    // Let the first wait expire, which sends the same lookup to the next server on a longer wait.
    table.now_ns = table.resolver.lookup_of(slow).deadline_ns;
    _ = table.poll();
    table.resolver.on_sent(slow, table.now_ns);
    const slow_deadline = table.resolver.lookup_of(slow).deadline_ns;
    try testing.expectEqual(slow_deadline, table.resolver.next_deadline_ns().?);

    const fresh = try table.start("fresh.example.");
    _ = table.poll();
    table.resolver.on_sent(fresh, table.now_ns);
    const fresh_deadline = table.resolver.lookup_of(fresh).deadline_ns;
    try testing.expect(fresh_deadline < slow_deadline);
    try testing.expectEqual(fresh_deadline, table.resolver.next_deadline_ns().?);
}
