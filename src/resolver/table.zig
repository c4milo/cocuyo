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
const limits = @import("limits.zig");
const entropy_module = @import("entropy.zig");
const servers_module = @import("servers.zig");
const keys_module = @import("table_keys.zig");
const slots_module = @import("table_slots.zig");
const ready_module = @import("table_ready.zig");
const memory_module = @import("table_memory.zig");
const walks_module = @import("table_walks.zig");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Action = lookup_module.Action;
const Verdict = lookup_module.Verdict;

pub const MatchKey = keys_module.MatchKey;
pub const Handle = slots_module.Handle;
pub const Slot = slots_module.Slot;
pub const Trust = walks_module.Trust;

/// What a poll found for one lookup.
pub const Event = struct {
    handle: Handle,
    action: Action,
};

pub const Resolver = struct {
    slots: slots_module.Slots,
    keys: []MatchKey,
    config: *const Config,
    /// The per-server state every lookup of the table shares: the cookies and the failover
    /// counters (docs/design.md §19 steps 10 and 12).
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
    /// The walks for keys under every lookup, or null when the table validates nothing
    /// (docs/design.md §25, step 12).
    walks: ?walks_module.Walks,

    /// `keys.len` must be a power of two and at least `keys_per_slot_min` times `slots.len`: the
    /// probe relies on the mask, and the load factor keeps the probe short.
    pub fn init(slots: []Slot, keys: []MatchKey, config: *const Config, seed: u64) Resolver {
        config.assert_valid();
        assert(keys.len >= slots.len * limits.keys_per_slot_min);
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
            .walks = null,
        };
    }

    /// Puts a cache under every lookup this table starts (docs/design.md §20). Set before the
    /// first lookup: a table with lookups already in flight would remember some and not others.
    pub fn use_memory(self: *Resolver, memory: memory_module.Memory) void {
        assert(self.in_flight() == 0);
        self.memory = memory;
    }

    /// Validates every lookup this table starts, and fetches the keys they want with walks under
    /// it (docs/design.md §25). Set before the first lookup, as the cache is. The table must not
    /// move from here on.
    pub fn use_trust(self: *Resolver, trust: Trust) void {
        walks_module.use_trust(self, trust);
    }

    /// Starts a lookup. Its seed is drawn from the table's own generator, so one seed at the top
    /// gives the whole table a reproducible stream (docs/design.md §7). A validating table keeps
    /// `trust_slots_min` slots for the walks' questions, and refuses the consumer those.
    pub fn start(self: *Resolver, question: Question) error{NoSlot}!Handle {
        if (!walks_module.consumer_may(self)) return error.NoSlot;
        const index = self.slots.acquire() orelse return error.NoSlot;
        slots_module.occupy(self, index, question);
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
        assert(out.len >= core.limits.query_bytes_max);
        ready_module.wake_expired(self, now_ns);
        walks_module.ask_questions(self);
        var taken: usize = 0;
        while (taken < self.slots.items.len) : (taken += 1) {
            const index = ready_module.take_ready(self) orelse return null;
            const slot = &self.slots.items[index];
            assert(slot.occupied);
            memory_module.recall_into(self.memory, slot, now_ns);
            const action = slot.lookup.poll(now_ns, out);
            if (walks_module.walked(self, index, action, now_ns)) return .{ .handle = self.slots.handle_of(index), .action = .walked };
            self.rekey(index);
            // A poll can start a wait as well as report one: `connect_tcp` leaves the lookup
            // waiting for its connection, and the bound must hold that deadline too, or the
            // caller's timer never fires for it.
            if (slot.lookup.is_waiting()) ready_module.note_deadline(self, slot.lookup.deadline_ns);
            if (action == .wait) continue;
            memory_module.remember_end(self.memory, slot, action, now_ns);
            return .{ .handle = self.slots.handle_of(index), .action = action };
        }
        return null;
    }

    /// The instant the caller's one timer is armed for, or null when no lookup is waiting: one
    /// timer for the whole table rather than one per lookup. It is a bound on the soonest
    /// deadline, never later than it. A lookup that stops waiting leaves the bound where it was,
    /// so the timer can fire with nothing expired; the poll that follows finds the soonest again
    /// and the caller arms it anew. Firing early costs a wakeup, and never firing would cost an
    /// answer.
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
        return self.offer_datagram(message, from, now_ns, Lookup.on_response);
    }

    /// Hands a datagram that the kernel cut to the lookup it belongs to, if any: one longer than
    /// the caller's buffer, whose end is gone (docs/design.md §7, A datagram that the buffer cut).
    /// The candidates are the ones `on_datagram` asks, and each reads it as `Lookup.on_datagram_cut`.
    pub fn on_datagram_cut(self: *Resolver, message: []const u8, from: Endpoint, now_ns: u64) Verdict {
        return self.offer_datagram(message, from, now_ns, Lookup.on_datagram_cut);
    }

    fn offer_datagram(
        self: *Resolver,
        message: []const u8,
        from: Endpoint,
        now_ns: u64,
        comptime respond: fn (*Lookup, []const u8, Endpoint, u64) Verdict,
    ) Verdict {
        const header = wire.header.parse(message) catch return .ignored;
        var candidates = keys_module.Candidates.init(self.keys, header.id);
        while (candidates.next()) |slot| {
            if (self.deliver(slot, message, from, now_ns, respond) == .accepted) return .accepted;
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

    /// The connection to the configured server `configured` failed, for `reason` (docs/design.md
    /// §5, The cause of a failure). A lookup that is on another server now closes the tries it
    /// kept open on that connection (§5, Tries kept open).
    pub fn on_tcp_failed(self: *Resolver, handle: Handle, configured: u8, reason: lookup_module.Reason, now_ns: u64) void {
        self.slot_of(handle).lookup.on_tcp_failed(configured, reason, now_ns);
        self.follow(handle.index);
    }

    /// Hands the answer to a request over DoH or DoQ to the lookup whose query it answers, with
    /// the transaction `send_request` named and the `Age` (docs/design.md §22, §23). HTTP or
    /// QUIC paired it with its query, so it comes by handle and not through the key table.
    pub fn on_request_answer(
        self: *Resolver,
        handle: Handle,
        transaction: u16,
        message: []const u8,
        age_seconds: u32,
        now_ns: u64,
    ) Verdict {
        const verdict = self.slot_of(handle).lookup.on_request_answer(transaction, message, age_seconds, now_ns);
        if (verdict == .accepted) self.followed(handle.index, message, now_ns);
        return verdict;
    }

    /// A request over DoH or DoQ ended without an answer, for `reason` (docs/design.md §22, §23).
    pub fn on_request_failed(self: *Resolver, handle: Handle, transaction: u16, reason: lookup_module.Reason, now_ns: u64) void {
        self.slot_of(handle).lookup.on_request_failed(transaction, reason, now_ns);
        self.follow(handle.index);
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
        // A walk's lookup is freed once a poll handed `walked` for it.
        if (self.slot_of(handle).lookup.conjunctions.for_walk) walks_module.release(self, handle.index);
        self.free(handle.index);
    }

    fn free(self: *Resolver, index: u16) void {
        const slot = &self.slots.items[index];
        keys_module.remove(self.keys, slot.keyed_id, index);
        for (slot.keyed_tries[0..slot.keyed_tries_count]) |id| keys_module.remove(self.keys, id, index);
        slot.keyed_tries_count = 0;
        ready_module.withdraw(self, index);
        self.slots.release(index);
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
        apply(&self.slot_of(handle).lookup, now_ns);
        self.follow(handle.index);
    }

    /// Follows a lookup that accepted `message`: the walks first, which may free its slot.
    fn followed(self: *Resolver, index: u16, message: []const u8, now_ns: u64) void {
        // A table that validates nothing pays this one test (docs/performance.md).
        if (self.walks != null) walks_module.after_message(self, index, message, now_ns);
        self.follow(index);
    }

    /// Follows a lookup an event moved: its new transaction, and where it belongs now. It, `rekey`
    /// and `table_ready.settle` are inline: once the walks called it too, the compiler made calls
    /// of the three, which cost each accepted datagram 21 instructions (docs/performance.md).
    pub inline fn follow(self: *Resolver, index: u16) void {
        self.rekey(index);
        ready_module.settle(self, index);
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
        comptime respond: fn (*Lookup, []const u8, Endpoint, u64) Verdict,
    ) Verdict {
        assert(index < self.slots.items.len);
        const slot = &self.slots.items[index];
        // A key naming a free slot is a broken table rather than a stray datagram: `release`
        // tombstones the key it held, so nothing can reach a free slot's lookup, which is
        // `undefined` until something takes it.
        assert(slot.occupied);
        const verdict = respond(&slot.lookup, message, from, now_ns);
        if (verdict == .accepted) self.followed(index, message, now_ns);
        return verdict;
    }

    /// Follows a lookup that drew a new transaction, or whose open tries changed.
    inline fn rekey(self: *Resolver, index: u16) void {
        const slot = &self.slots.items[index];
        assert(slot.occupied);
        if (slot.lookup.tries.epoch != slot.keyed_epoch) self.rekey_tries(index);
        const current = slot.lookup.transaction.id;
        if (current == slot.keyed_id) return;
        keys_module.remove(self.keys, slot.keyed_id, index);
        keys_module.insert(self.keys, current, index);
        slot.keyed_id = current;
    }

    /// Keys the ids of the tries a lookup keeps open, in place of those keyed before, so that an
    /// answer to one of them reaches the lookup (docs/design.md §5, Tries kept open). Out of line:
    /// most events change no try.
    noinline fn rekey_tries(self: *Resolver, index: u16) void {
        @branchHint(.cold);
        const slot = &self.slots.items[index];
        for (slot.keyed_tries[0..slot.keyed_tries_count]) |id| keys_module.remove(self.keys, id, index);
        const tries = slot.lookup.tries.slice();
        for (tries, 0..) |kept, at| {
            keys_module.insert(self.keys, kept.id, index);
            slot.keyed_tries[at] = kept.id;
        }
        slot.keyed_tries_count = @intCast(tries.len);
        slot.keyed_epoch = slot.lookup.tries.epoch;
        assert(slot.keyed_tries_count <= limits.tries_open_max);
    }
};

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const Table = fixtures.Table;

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

test {
    _ = @import("table_test.zig");
}
