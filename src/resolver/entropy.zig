//! Where a lookup's unpredictability comes from: one `u64` the caller supplies, stepped by
//! `core.mix` (docs/design.md §7).
//!
//! Three fields per transaction, and a transaction is one query: a new id, a new source-port hint
//! and a new case pattern. A CNAME re-query is a new transaction and draws all three again, which
//! is what stops a chain from reusing one id across several questions.
//!
//! **The seed must come from a CSPRNG.** cocuyo cannot check that and does not pretend to: the mix
//! spreads the seed deterministically, which is what makes a lookup replayable from it, and the
//! strength of the spoofing defences is exactly the strength of the seed. A seed read from the
//! clock makes every field guessable.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

/// The three values one query needs.
pub const Transaction = struct {
    /// The transaction id the query carries and the response must echo (RFC 1035 §4.1.1).
    id: u16,
    /// A port in the Dynamic range for the caller to bind, if it binds one per query
    /// (RFC 6335 §6, RFC 5452 §9.2).
    port_hint: u16,
    /// The pattern the qname's letters are cased with, and the pattern the response's question
    /// section must come back with (RFC 5452 §9.2).
    case_seed: u64,
    /// Which of its lookup's transactions this is, counted from zero: what a DoH answer names,
    /// since HTTP and not the id pairs it with its request (docs/design.md §22). The lookup
    /// numbers it, and `lookup_https.zig` shows the count never wraps. It sits in what would
    /// be padding.
    number: u16 = 0,
};

/// How many ports the Dynamic range holds.
const port_span = core.constants.port_ephemeral_max - core.constants.port_ephemeral_min + 1;

pub const Entropy = struct {
    word: u64,

    pub fn init(seed: u64) Entropy {
        return .{ .word = seed };
    }

    /// The next word. Every draw goes through here, so a lookup's whole stream is a function of
    /// its seed and the number of draws before it.
    pub fn next(self: *Entropy) u64 {
        self.word = core.mix.next(self.word);
        return self.word;
    }

    /// The three values for one query.
    pub fn transaction(self: *Entropy) Transaction {
        const transaction_values: Transaction = .{
            .id = @truncate(self.next()),
            .port_hint = port_from(self.next()),
            .case_seed = self.next(),
        };
        assert(transaction_values.port_hint >= core.constants.port_ephemeral_min);
        assert(transaction_values.port_hint <= core.constants.port_ephemeral_max);
        return transaction_values;
    }

    /// Which server to start the first pass at, when a configuration asks for rotation. A process
    /// running many lookups against one list would otherwise aim all of them at the first server.
    pub fn server_start(self: *Entropy, server_count: usize) u8 {
        assert(server_count >= 1);
        assert(server_count <= core.constants.servers_max);
        return @intCast(self.next() % server_count);
    }
};

fn port_from(word: u64) u16 {
    return @intCast(core.constants.port_ephemeral_min + word % port_span);
}

// Tests.

const testing = std.testing;

test "a seed gives one stream, and two seeds give two" {
    var first = Entropy.init(1);
    var second = Entropy.init(1);
    var other = Entropy.init(2);
    try testing.expectEqual(first.transaction().id, second.transaction().id);
    try testing.expect(first.next() != other.next());
}

test "a transaction draws three fresh values, and the next draws three more" {
    var entropy = Entropy.init(0x1234_5678_9abc_def0);
    const first = entropy.transaction();
    const second = entropy.transaction();
    try testing.expect(first.id != second.id or first.case_seed != second.case_seed);
    try testing.expect(first.case_seed != second.case_seed);
    try testing.expect(first.port_hint != 0);
}

test "every port hint lands in the Dynamic range" {
    var entropy = Entropy.init(0);
    var draws: usize = 0;
    while (draws < 1024) : (draws += 1) {
        const port = entropy.transaction().port_hint;
        try testing.expect(port >= core.constants.port_ephemeral_min);
        try testing.expect(port <= core.constants.port_ephemeral_max);
    }
}

test "the port hints spread over the range rather than clustering" {
    // A hint drawn by masking rather than by the range's own width would leave most of the range
    // unreachable. Sixteen buckets, and every one of them is reached.
    const bucket_count = 16;
    var seen: [bucket_count]bool = @splat(false);
    var entropy = Entropy.init(7);
    var draws: usize = 0;
    while (draws < 1024) : (draws += 1) {
        const offset: usize = entropy.transaction().port_hint - core.constants.port_ephemeral_min;
        seen[offset * bucket_count / port_span] = true;
    }
    for (seen) |reached| try testing.expect(reached);
}

test "rotation picks a server inside the list" {
    var entropy = Entropy.init(3);
    var draws: usize = 0;
    var seen_first = false;
    var seen_last = false;
    while (draws < 256) : (draws += 1) {
        const index = entropy.server_start(3);
        try testing.expect(index < 3);
        if (index == 0) seen_first = true;
        if (index == 2) seen_last = true;
    }
    try testing.expect(seen_first and seen_last);
}
