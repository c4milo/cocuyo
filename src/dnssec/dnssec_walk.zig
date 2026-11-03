//! The walks for keys: each fetches the DS and DNSKEY sets that a message's validation lacks,
//! one question at a time, and leaves them in the key store (docs/design.md §25, Stage B: where
//! the keys come from, and step 12). A walk asks nothing itself: the table takes its question,
//! asks it as a lookup of its own, and hands the answer back. `spec/lean/Spec/KeyWalk.lean` is
//! the model of one walk.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Kind = core.Kind;
const Name = core.Name;
const Question = core.Question;
const Walked = core.validation.Walked;
const dnssec = @import("dnssec.zig");
const Verifier = dnssec.Verifier;
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const proof = @import("dnssec_nsec3_proof.zig");
const message_reader = @import("dnssec_message.zig");
const store_module = @import("dnssec_store.zig");
const Store = store_module.Store;
const store_keys = @import("dnssec_store_keys.zig");
const validate = @import("dnssec_validate.zig");
const Validator = validate.Validator;
const Scratch = @import("dnssec_scratch.zig").Scratch;

pub const Phase = enum(u8) {
    free,
    /// The walk has a question the table has not taken.
    asking,
    /// The table asks the walk's question.
    asked,
    /// The store holds the target's keys, or an insecure delegation at or above it (rule 8).
    ready,
    failed,
};

pub const End = core.validation.End;

/// One walk. The zone it stands in and the name it asks of are ancestors of its target, so each
/// is a count of the target's labels.
pub const Walk = struct {
    target: Name = Name.empty,
    zone_labels: u8 = 0,
    probe_labels: u8 = 0,
    asking: Kind = .ds,
    questions: u8 = 0,
    /// Whether the walk began again once, after its own answer wanted keys the store lost.
    restarted: bool = false,
    phase: Phase = .free,
    failure: Walked = .bogus,
};

pub const Walker = struct {
    store: *Store,
    verifier: Verifier,
    hasher: proof.Hasher,
    /// The key store's memory for one validation at a time (§17 question 108).
    scratch: *Scratch,
    walks: [limits.walks_max]Walk = @splat(.{}),

    pub fn validator(self: *const Walker) Validator {
        return .{ .store = self.store, .verifier = self.verifier, .hasher = self.hasher, .scratch = self.scratch };
    }

    /// The walk for `target`: the one that runs for it, else a new one. Null when every walk is
    /// busy, and the lookup reads its message as bogus (step 12). One walk serves every lookup
    /// that waits for its target (rule 10).
    pub fn join(self: *Walker, target: *const Name, now_ns: u64) ?u8 {
        assert(target.len >= 1);
        for (&self.walks, 0..) |*walk, index| {
            if (walk.phase != .free and walk.target.equal(target)) return @intCast(index);
        }
        for (&self.walks, 0..) |*walk, index| {
            if (walk.phase != .free) continue;
            walk.* = .{ .target = target.*, .phase = .asking };
            self.begin(walk, now_ns);
            assert(walk.phase != .free);
            return @intCast(index);
        }
        return null;
    }

    /// The question of a walk that has one the table has not taken, which the table now asks.
    pub fn question(self: *Walker, index: u8) ?Question {
        const walk = &self.walks[index];
        if (walk.phase != .asking) return null;
        walk.phase = .asked;
        assert(walk.asking == .ds or walk.asking == .dnskey);
        return .{ .name = core.canonical.ancestor(&walk.target, walk.probe_labels), .kind = walk.asking, .absolute = true };
    }

    /// The question of the first walk that has one the table has not taken, which the table now
    /// asks (§25 step 12).
    pub fn next_question(self: *Walker) ?core.validation.Asked {
        for (0..self.walks.len) |index| {
            const walk: u8 = @intCast(index);
            if (self.question(walk)) |asked| return .{ .walk = walk, .question = asked };
        }
        return null;
    }

    /// The end of a walk, or null while it runs.
    pub fn end(self: *const Walker, index: u8) ?End {
        const walk = &self.walks[index];
        assert(walk.phase != .free);
        return switch (walk.phase) {
            .ready => .ready,
            .failed => .{ .failed = walk.failure },
            else => null,
        };
    }

    /// Frees an ended walk, once the table handed its end to every lookup that waits on it.
    pub fn release(self: *Walker, index: u8) void {
        const walk = &self.walks[index];
        assert(walk.phase == .ready or walk.phase == .failed);
        walk.* = .{};
    }

    /// The question went unanswered, or every server failed it: the walk fails with that failure,
    /// and not as bogus (rule 11).
    pub fn question_failed(self: *Walker, index: u8, failure: Walked) void {
        const walk = &self.walks[index];
        assert(walk.phase == .asked);
        assert(failure != .bogus);
        fail(walk, failure);
    }

    /// The answer to the walk's question, a response that passed docs/design.md §7's checks. The
    /// validator reads it under the keys the store holds (rule 9), and the walk moves on.
    pub fn answered(self: *Walker, index: u8, bytes: []const u8, now_ns: u64) void {
        const walk = &self.walks[index];
        assert(walk.phase == .asked);
        walk.phase = .asking;
        walk.questions += 1;
        // "the resolver MUST bound the work it puts into answering any particular query" (RFC
        // 4035 §5.4): rule 10.
        if (walk.questions > limits.chain_questions_max) return fail(walk, .bogus);
        // Another walk entered the zone first: its keys stand, and nothing of this answer is kept
        // in their place (rule 12).
        if (self.holds(&walk.target, walk.probe_labels, .keys, now_ns)) {
            walk.zone_labels = walk.probe_labels;
            return self.next(walk, now_ns);
        }
        const probe = core.canonical.ancestor(&walk.target, walk.probe_labels);
        if (walk.asking == .ds) self.ds_answered(walk, &probe, bytes, now_ns) else self.keys_answered(walk, &probe, bytes, now_ns);
        assert(walk.questions <= limits.chain_questions_max);
    }

    /// Rules 4 to 7: a DS set, a delegation with none, a name that is no delegation, or a name
    /// that does not exist.
    fn ds_answered(self: *Walker, walk: *Walk, probe: *const Name, bytes: []const u8, now_ns: u64) void {
        const checker = self.validator();
        switch (checker.validate(probe, .ds, bytes, now_ns)) {
            .secure => |secure| switch (secure.ending) {
                .answer => {
                    if (!self.keep_ds(probe, bytes, secure.ttl_seconds, now_ns)) return fail(walk, .bogus);
                    walk.asking = .dnskey;
                },
                .no_data => {
                    if (checker.delegated(probe, bytes, now_ns)) return self.insecure(walk, probe, secure.ttl_seconds, now_ns);
                    // The name exists and is no delegation: the next label, in the same zone.
                    next_label(walk);
                },
                .name_error, .alias => fail(walk, .bogus),
            },
            // An Opt-Out span, or a store that already speaks for the name. A negative answer's
            // TTL is its SOA's (RFC 2308 §5).
            .insecure => self.insecure(walk, probe, wire.response.negative_ttl_seconds(bytes, probe) catch 0, now_ns),
            .keys_wanted => self.restart(walk, now_ns),
            // A signed answer that proves nothing at the probe, as NSD's DS answer at an empty
            // non-terminal under Opt-Out, which leaves out the record RFC 5155 §7.2.4 requires
            // (rule 6). Nothing of it is kept, and the next answer is validated under the same keys.
            .bogus => |reason| if (reason == .proof) next_label(walk) else fail(walk, .bogus),
            .unchecked => fail(walk, .bogus),
        }
    }

    /// Rule 6: the next label, in the same zone. At the target, data with no signature sits inside
    /// a signed zone (rule 8).
    fn next_label(walk: *Walk) void {
        assert(walk.asking == .ds);
        if (walk.probe_labels >= walk.target.label_count()) return fail(walk, .bogus);
        walk.probe_labels += 1;
        assert(walk.probe_labels <= walk.target.label_count());
    }

    /// Rule 4: the DNSKEY set enters when a key in it matches the anchor or the held DS set.
    fn keys_answered(self: *Walker, walk: *Walk, probe: *const Name, bytes: []const u8, now_ns: u64) void {
        const admission = store_keys.admit(self.store, self.verifier, self.scratch, probe, bytes, now_ns) catch return fail(walk, .bogus);
        switch (admission) {
            .admitted => {
                walk.zone_labels = walk.probe_labels;
                self.next(walk, now_ns);
            },
            .insecure => self.next(walk, now_ns),
            .bogus => fail(walk, .bogus),
            .ds_wanted => self.restart(walk, now_ns),
        }
    }

    /// Rule 5: everything at or under `probe` is insecure, and the walk ends. An entry of no TTL
    /// expires at once, and the walk asks again, within rule 10's bound.
    fn insecure(self: *Walker, walk: *Walk, probe: *const Name, ttl_seconds: u32, now_ns: u64) void {
        const kept = self.store.put(probe, .insecure, &.{}, expires(ttl_seconds, now_ns));
        assert(kept);
        self.next(walk, now_ns);
    }

    /// Keeps the DS set at `probe` that the validator called secure.
    fn keep_ds(self: *Walker, probe: *const Name, bytes: []const u8, ttl_seconds: u32, now_ns: u64) bool {
        const message = &self.scratch.message;
        const fits = message.read(bytes, probe) catch return false;
        if (!fits) return false;
        const set = message.rrset(.answer, .ds, probe) catch return false;
        assert(set.count() >= 1);
        if (set.count() > limits.ds_records_max) return false;
        const records = &self.scratch.kept;
        for (0..set.count()) |index| records[index] = set.record(index).rdata;
        return self.store.put(probe, .ds, records[0..set.count()], expires(ttl_seconds, now_ns));
    }

    /// A walk's own answer never waits for keys: when it would, the walk begins again from the
    /// deepest zone the store holds, once (step 12). The questions it asked still count.
    fn restart(self: *Walker, walk: *Walk, now_ns: u64) void {
        if (walk.restarted) return fail(walk, .bogus);
        walk.restarted = true;
        self.begin(walk, now_ns);
    }

    /// Rule 2: the walk stands in the deepest zone whose keys the store holds, or enters the
    /// deepest anchor above the target by asking its DNSKEY set.
    fn begin(self: *Walker, walk: *Walk, now_ns: u64) void {
        const labels = walk.target.label_count();
        for (0..@as(usize, labels) + 1) |up| {
            const count: u8 = @intCast(labels - up);
            if (!self.holds(&walk.target, count, .keys, now_ns)) continue;
            walk.zone_labels = count;
            return self.next(walk, now_ns);
        }
        const anchor = self.deepest_anchor(&walk.target) orelse {
            // Under no anchor the name is insecure, and the validator asks for no walk.
            walk.phase = .ready;
            return;
        };
        walk.zone_labels = anchor;
        walk.probe_labels = anchor;
        walk.asking = .dnskey;
        walk.phase = .asking;
    }

    /// The walk's next question once it stands in a zone (rules 3 and 8).
    fn next(self: *Walker, walk: *Walk, now_ns: u64) void {
        const labels = walk.target.label_count();
        if (self.reached(walk, now_ns)) {
            walk.phase = .ready;
            return;
        }
        // A walk for data with no signature reached the name asked inside a signed zone.
        if (walk.zone_labels >= labels) return fail(walk, .bogus);
        walk.probe_labels = walk.zone_labels + 1;
        walk.asking = if (self.holds(&walk.target, walk.probe_labels, .ds, now_ns)) .dnskey else .ds;
        walk.phase = .asking;
        assert(walk.probe_labels <= labels);
    }

    /// Rule 8: the store holds the target's keys, or an insecure delegation at or above it.
    fn reached(self: *const Walker, walk: *const Walk, now_ns: u64) bool {
        const labels = walk.target.label_count();
        if (self.holds(&walk.target, labels, .keys, now_ns)) return true;
        for (0..@as(usize, labels) + 1) |count| {
            if (self.holds(&walk.target, @intCast(count), .insecure, now_ns)) return true;
        }
        return false;
    }

    /// Whether the store holds `known` for the ancestor of `target` with `count` labels.
    fn holds(self: *const Walker, target: *const Name, count: u8, known: store_module.Known, now_ns: u64) bool {
        const ancestor = core.canonical.ancestor(target, count);
        const entry = self.store.find(&ancestor, now_ns) orelse return false;
        return entry.known == known;
    }

    /// The labels of the deepest anchor at or above `target`, RFC 6840 Appendix C.1's policy.
    fn deepest_anchor(self: *const Walker, target: *const Name) ?u8 {
        var best: ?u8 = null;
        for (self.store.anchors) |*anchor| {
            const labels = anchor.zone.label_count();
            if (core.canonical.shared_labels(&anchor.zone, target) != labels) continue;
            if (best == null or best.? < labels) best = labels;
        }
        return best;
    }
};

fn fail(walk: *Walk, failure: Walked) void {
    walk.phase = .failed;
    walk.failure = failure;
}

fn expires(ttl_seconds: u32, now_ns: u64) u64 {
    return now_ns + @as(u64, ttl_seconds) * constants.ns_per_second;
}
