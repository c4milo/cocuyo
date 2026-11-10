//! The walks for keys under a validating table (docs/design.md §25, step 12). The table asks each
//! walk's question as a lookup of its own, in a free slot or in one of the `trust_slots_min`
//! slots only such a lookup may take, and hands its answer to the walk. The consumer never sees
//! such a lookup end: a poll hands the driver `walked`, and the driver frees the slot (step 15).
//! When a walk ends, each lookup that waits on it is asked again or fails.
//! `spec/tla/keys/Keys.tla` is the model. Split from `table.zig` by the file-length rule.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Kind = core.Kind;
const Name = core.Name;
const Validation = core.Validation;
const validation = core.validation;
const limits = @import("limits.zig");
const slots_module = @import("table_slots.zig");
const walk_none = slots_module.walk_none;
const Resolver = @import("table.zig").Resolver;
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const Action = lookup_module.Action;
const validate_module = @import("lookup_validate.zig");

/// What a validating table asks of the walks for keys: `cocuyo.validated_by`'s, over the `dnssec`
/// module's walker and key store, or a test's.
pub const Trust = struct {
    context: *anyopaque,
    /// Reads a message that passed §7's checks, for the name and the type being asked.
    validate: *const fn (context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation,
    /// Joins the walk for the name a `keys_wanted` names, or null when every walk is busy.
    join: *const fn (context: *anyopaque, target: *const Name, now_ns: u64) ?u8,
    /// A walk's next question, which the table now asks, or null.
    next_question: *const fn (context: *anyopaque) ?validation.Asked,
    /// The message that ended a walk's question, which passed §7's checks.
    answered: *const fn (context: *anyopaque, walk: u8, message: []const u8, now_ns: u64) void,
    /// A walk's question ended with no message: its time ran out, or every server failed it.
    question_failed: *const fn (context: *anyopaque, walk: u8, failure: validation.Walked) void,
    /// How a walk ended, or null while it runs.
    end: *const fn (context: *anyopaque, walk: u8) ?validation.End,
    /// Frees an ended walk.
    release: *const fn (context: *anyopaque, walk: u8) void,
};

/// What a validating table keeps for the walks.
pub const Walks = struct {
    trust: Trust,
    /// What every lookup of the table asks of a message. Its context is the table, so a
    /// `keys_wanted` joins a walk on its way to the lookup.
    validator: validate_module.Validator,
    /// The walk the last `keys_wanted` joined, which the table writes into the lookup's slot.
    joined: u8 = walk_none,
    /// The slots whose lookups ask a walk's question.
    asking_slots: u16 = 0,
};

/// Validates every lookup the table starts from here on. The table must stay where it is from
/// here on: its lookups' validator names it.
pub fn use_trust(self: *Resolver, trust: Trust) void {
    assert(self.in_flight() == 0);
    assert(self.slots.items.len > limits.trust_slots_min);
    self.walks = .{ .trust = trust, .validator = .{ .context = self, .validate = validate } };
    self.servers.use_validator(self.config, &self.walks.?.validator);
}

/// A `keys_wanted` joins its walk. A target that finds every walk busy waits for none, and the
/// message reads as bogus (docs/design.md §25, step 12).
fn validate(context: *anyopaque, asked: *const Name, kind: Kind, message: []const u8, now_ns: u64) Validation {
    const self: *Resolver = @ptrCast(@alignCast(context));
    const walks = &self.walks.?;
    const verdict = walks.trust.validate(walks.trust.context, asked, kind, message, now_ns);
    if (verdict != .keys_wanted) return verdict;
    walks.joined = walks.trust.join(walks.trust.context, &verdict.keys_wanted, now_ns) orelse return .{ .bogus = .signature };
    return verdict;
}

/// Whether the consumer may take a free slot: after it does, the free slots and the slots the
/// walks hold still make `trust_slots_min` (`ConsumerMay` in the model).
pub fn consumer_may(self: *const Resolver) bool {
    const walks = if (self.walks) |*walks| walks else return true;
    const held = @min(walks.asking_slots, limits.trust_slots_min);
    return self.slots.free_at_least(limits.trust_slots_min - held + 1);
}

/// Asks each walk's next question, at a poll, in a free slot, while one is free. Any free slot
/// serves, a reserved one too.
pub fn ask_questions(self: *Resolver) void {
    const walks = if (self.walks) |*walks| walks else return;
    assert(walks.validator.context == @as(*anyopaque, self));
    for (0..self.slots.items.len) |_| {
        if (!self.slots.free_at_least(1)) return;
        const asked = walks.trust.next_question(walks.trust.context) orelse return;
        assert(asked.walk != walk_none);
        assert(asked.question.absolute);
        const index = self.slots.acquire().?;
        const slot = &self.slots.items[index];
        // A walk reads a message, so the memory is not asked for its lookup, and its end never
        // reaches a poll that would write one.
        slot.asked_memory = true;
        slot.walk = asked.walk;
        slots_module.occupy(self, index, asked.question);
        slot.lookup.conjunctions.for_walk = true;
        walks.asking_slots += 1;
    }
}

/// Whether a poll hands `walked` for the slot: a walk's lookup that ended (§17 question 100). One
/// that the poll itself ended, as its time ran out, every server failed or a cancel came, has
/// not told its walk yet, and does so now. Its end never reaches the memory.
pub fn walked(self: *Resolver, index: u16, action: Action, now_ns: u64) bool {
    const slot = &self.slots.items[index];
    if (!slot.lookup.conjunctions.for_walk) return false;
    if (action != .done and action != .failed) return false;
    assert(slot.lookup.is_settled());
    if (slot.walk != walk_none) {
        const walk = slot.walk;
        const walks = &self.walks.?;
        assert(action == .failed);
        walks.trust.question_failed(walks.trust.context, walk, walked_with(slot.lookup.failure));
        slot.walk = walk_none;
        hand_end(self, walk, now_ns);
    }
    return true;
}

/// The driver frees a walk's slot that a poll handed `walked` for. Until now it counted among the
/// slots the walks hold.
pub fn release(self: *Resolver, index: u16) void {
    const walks = &self.walks.?;
    const slot = &self.slots.items[index];
    assert(slot.lookup.is_settled());
    assert(slot.walk == walk_none);
    assert(walks.asking_slots >= 1);
    walks.asking_slots -= 1;
}

/// What the table does once a lookup accepted `message`. A walk's lookup that ended on it hands the
/// walk the message, or its failure, and its slot waits for a poll to hand `walked`. A lookup the
/// message left waiting for keys keeps the walk it joined in its slot. The table follows the lookup
/// next. Never inline: a table that validates nothing never calls it, and it
/// keeps the path of each accepted datagram short.
pub noinline fn after_message(self: *Resolver, index: u16, message: []const u8, now_ns: u64) void {
    const walks = if (self.walks) |*walks| walks else return;
    const slot = &self.slots.items[index];
    if (slot.lookup.conjunctions.for_walk) {
        if (!slot.lookup.is_settled()) return;
        const walk = slot.walk;
        assert(walk != walk_none);
        if (acted(&slot.lookup)) {
            walks.trust.answered(walks.trust.context, walk, message, now_ns);
        } else {
            walks.trust.question_failed(walks.trust.context, walk, walked_with(slot.lookup.failure));
        }
        slot.walk = walk_none;
        hand_end(self, walk, now_ns);
        return;
    }
    if (slot.lookup.state == .awaiting_keys and slot.walk == walk_none) {
        assert(walks.joined != walk_none);
        slot.walk = walks.joined;
        walks.joined = walk_none;
        // A walk can end as it is joined: under no anchor, or with the store already holding.
        hand_end(self, slot.walk, now_ns);
    }
}

/// Whether a walk's lookup ended on a message it read: an answer, or one of the two negatives.
fn acted(lookup: *const Lookup) bool {
    if (lookup.state == .done) return true;
    return lookup.failure == core.Error.NameNotFound or lookup.failure == core.Error.NoData;
}

/// A walk's question that ended with no message fails the walk with that failure (walk rule 11).
fn walked_with(err: core.Error) validation.Walked {
    return if (err == core.Error.Timeout) .timeout else .failed;
}

/// A walk that ended hands `on_keys_ready` or `on_keys_failed` to each lookup that waits on it, and
/// to no other, and is freed. One scan of the table, once for each walk's end.
fn hand_end(self: *Resolver, walk: u8, now_ns: u64) void {
    const walks = &self.walks.?;
    const end = walks.trust.end(walks.trust.context, walk) orelse return;
    for (self.slots.items, 0..) |*slot, index| {
        if (!slot.occupied or slot.walk != walk or slot.lookup.state != .awaiting_keys) continue;
        assert(!slot.lookup.conjunctions.for_walk);
        slot.walk = walk_none;
        switch (end) {
            .ready => validate_module.on_keys_ready(&slot.lookup, now_ns),
            .failed => |failure| validate_module.on_keys_failed(&slot.lookup, failure, now_ns),
        }
        self.follow(@intCast(index));
    }
    walks.trust.release(walks.trust.context, walk);
}
