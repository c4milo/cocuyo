//! A validating table over the twin's signed server, with several lookups at once and their replies
//! handed back in an order a seed chooses (c4milo/cocuyo#61). Their walks share the root's keys and
//! `example`'s. Each lookup must end as it ends when it runs alone, in every order: no order of
//! replies changes a verdict (docs/design.md §25, walk rule 12).
//!
//! Each seed runs three orders: the replies alone, then one lookup cancelled at a step the seed
//! picks, then every entry of the key store expired at a step the seed picks, as a TTL that runs
//! out or a full store does. `zig build test` runs a fixed range of seeds, and `zig build orders`
//! runs a range as long as the caller likes (`tools/orders.zig`).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const resolver = @import("resolver");
const dnssec = @import("dnssec");
const Kind = core.Kind;
const Question = core.Question;
const server = @import("sim_server.zig");
const signed = @import("sim_signed.zig");
const limits = @import("limits.zig");
const fixtures = @import("fixtures.zig");
const KeyStore = dnssec.keys.KeyStore;

const Asked = struct { text: []const u8, kind: Kind };

/// The names asked at once: a secure answer, an insecure one, a secure name error and a secure
/// no data, each a walk of its own through `example`.
const names = [_]Asked{
    .{ .text = "www.signed.example.", .kind = .a },
    .{ .text = "www.plain.example.", .kind = .a },
    .{ .text = "nope.signed.example.", .kind = .a },
    .{ .text = "www.signed.example.", .kind = .mx },
};

/// The table's slots: one for each name, one for each walk's question, and the slot kept for the
/// walks.
const slot_count: usize = names.len + dnssec.limits.walks_max + resolver.limits.trust_slots_min;
/// The match keys the table asks for its slots, as the power of two it requires.
const key_count: usize = std.math.ceilPowerOfTwoAssert(usize, slot_count * resolver.limits.keys_per_slot_min);
/// The store's entries: the four zones of the tree, with room to spare.
const entries_count: usize = 8;
/// Replies held at once: one for each slot, since each slot has one query out at most.
const held_max: usize = slot_count;
/// The orders `zig build test` runs, seeds 0 to 63.
pub const gate_count: u64 = 64;
/// The table's seed: any value, since a verdict does not depend on the ids.
const table_seed: u64 = 0x5eed;

const servers = [_]core.Server{.{ .endpoint = .{ .address = core.Address.from_v4(fixtures.server_octets) } }};

/// What an order does beside the replies it hands back.
pub const Twist = enum { none, cancel, expire };

/// A seed and a twist whose order changed what a lookup ended with.
pub const Broke = struct { seed: u64, twist: Twist, what: []const u8 };

/// What a lookup ended with, as far as an order must not change it.
const Verdict = struct {
    err: ?core.Error,
    security: core.Security,
    address: ?core.Address,

    fn of(action: resolver.Action) Verdict {
        return switch (action) {
            .done => |done| .{ .err = null, .security = done.security, .address = if (done.addresses.len > 0) done.addresses[0] else null },
            .failed => |failed| .{ .err = failed.err, .security = failed.security, .address = null },
            else => unreachable,
        };
    }

    fn equal(self: Verdict, other: Verdict) bool {
        if (!same_error(self.err, other.err) or self.security != other.security) return false;
        const address = self.address orelse return other.address == null;
        return other.address != null and address.equal(&other.address.?);
    }
};

/// Compares the payloads and not the optionals. Zig 0.16.0's own x86_64 backend, which builds
/// Debug on x86_64 Linux, gets `==` wrong when it compares two `?core.Error` values: it gives false
/// for two equal values (c4milo/cocuyo#62). LLVM compiles it right.
fn same_error(left: ?core.Error, right: ?core.Error) bool {
    const left_err = left orelse return right == null;
    const right_err = right orelse return false;
    return left_err == right_err;
}

/// A reply the server wrote, which the rig holds until the seed hands it back.
const Held = struct {
    bytes: [limits.datagram_bytes_max]u8 = undefined,
    len: usize = 0,
};

/// A table that validates under a key store anchored at the root's DS, over one signed server.
/// Started in place: the table and the store name the arrays beside them.
const Rig = struct {
    config: core.Config = .{ .servers = &servers },
    slots: [slot_count]resolver.Slot = @splat(.{}),
    keys: [key_count]resolver.MatchKey = @splat(.{}),
    table: resolver.Resolver = undefined,
    entries: [entries_count]KeyStore.Entry = undefined,
    anchor_rdata: dnssec.fixtures.DsRdata = signed.root_anchor(),
    anchors: [1]dnssec.keys.Anchor = undefined,
    sums: dnssec.fixtures.Sums = .{},
    hashes: dnssec.fixtures.Hashes = .{},
    store: KeyStore = undefined,
    script: server.Script = .{ .signed = .{ .on = true } },
    out: [core.limits.query_bytes_max]u8 = undefined,
    held: [held_max]Held = undefined,
    held_count: usize = 0,
    handles: [names.len]resolver.Handle = undefined,
    verdicts: [names.len]?Verdict = @splat(null),
    now_ns: u64 = 0,
    draw: u64 = 0,

    fn open(self: *Rig) void {
        self.anchors = .{.{ .zone = core.Name.root, .kind = .ds, .rdata = &self.anchor_rdata }};
        self.table = resolver.Resolver.init(&self.slots, &self.keys, &self.config, table_seed);
        self.store.init(&self.entries, &self.anchors, self.sums.verifier(), self.hashes.hasher(), signed.now_seconds, 0);
        self.table.validate_with(signed.trust(&self.store));
    }

    /// Starts each of `asked`, then hands the replies back in the order `seed` chooses, until
    /// each lookup ends. The twist comes before the reply its step names, and to the lookup the
    /// seed picks. Returns the lookup cancelled, if any.
    fn run(self: *Rig, asked: []const Asked, seed: u64, how: Twist) !?usize {
        assert(asked.len <= names.len);
        for (asked, 0..) |name, index| self.handles[index] = try self.table.start(try Question.from_text(name.text, name.kind));
        var order = resolver.Entropy.init(seed);
        const twist_step = order.next() % limits.order_twist_steps_max;
        const cancelled: ?usize = if (how == .cancel) @intCast(order.next() % asked.len) else null;
        for (0..limits.order_steps_max) |step| {
            try self.send_all(asked.len);
            if (self.ended(asked.len)) return cancelled;
            if (self.held_count == 0) return error.Stalled;
            if (step == twist_step) self.apply(how, cancelled);
            // The seed picks which held reply comes back next.
            const pick: usize = @intCast(order.next() % self.held_count);
            const reply = self.held[pick];
            self.held[pick] = self.held[self.held_count - 1];
            self.held_count -= 1;
            self.now_ns += 1;
            _ = self.table.on_datagram(reply.bytes[0..reply.len], servers[0].endpoint, self.now_ns);
        }
        return error.Stalled;
    }

    fn apply(self: *Rig, how: Twist, cancelled: ?usize) void {
        switch (how) {
            .none => {},
            .cancel => self.table.cancel(self.handles[cancelled.?]),
            // Every entry expires now, as each TTL ran out (§25, walk rule 2, and step 12).
            .expire => for (self.store.store.entries) |*entry| {
                if (entry.known != .free) entry.expires_ns = @min(entry.expires_ns, self.now_ns);
            },
        }
    }

    /// Takes every event the table has: each query's reply is written and held, and each end is
    /// kept.
    fn send_all(self: *Rig, count: usize) !void {
        for (0..limits.order_steps_max) |_| {
            self.now_ns += 1;
            const event = self.table.poll(self.now_ns, &self.out) orelse return;
            switch (event.action) {
                .send_udp => |send| self.hold(event.handle, send.message_bytes, false),
                .connect_tcp => self.table.on_tcp_connected(event.handle, self.now_ns),
                .send_tcp => |send| self.hold(event.handle, send.message_bytes[core.constants.tcp_prefix_bytes..], true),
                .done, .failed => {
                    const index = std.mem.indexOfScalar(resolver.Handle, self.handles[0..count], event.handle) orelse
                        return error.Unexpected;
                    if (self.verdicts[index] != null) return error.Unexpected;
                    self.verdicts[index] = Verdict.of(event.action);
                },
                // The driver frees a walk's lookup that ended (docs/design.md §17 question 100).
                .walked => self.table.release(event.handle),
                .wait, .send_request => return error.Unexpected,
            }
        }
        return error.Stalled;
    }

    fn hold(self: *Rig, handle: resolver.Handle, query: []const u8, over_tcp: bool) void {
        assert(self.held_count < held_max);
        self.table.on_sent(handle, self.now_ns);
        self.draw += 1;
        const held = &self.held[self.held_count];
        held.len = server.respond(&self.script, &fixtures.server_address, query, over_tcp, self.draw, &held.bytes).?.len;
        self.held_count += 1;
    }

    fn ended(self: *const Rig, count: usize) bool {
        for (self.verdicts[0..count]) |verdict| if (verdict == null) return false;
        return true;
    }
};

/// What each name ends with when it runs alone.
pub const Alone = [names.len]Verdict;

pub fn alone() !Alone {
    var verdicts: Alone = undefined;
    for (names, &verdicts) |name, *verdict| {
        var rig: Rig = .{};
        rig.open();
        _ = try rig.run(&.{name}, 0, .none);
        verdict.* = rig.verdicts[0].?;
    }
    return verdicts;
}

/// Runs the order of `seed` under `twist`, and says what broke, or null when each lookup ended as
/// it ends alone. A lookup cancelled before its end comes ends `Canceled` instead.
pub fn check(expected: *const Alone, seed: u64, twist: Twist) ?[]const u8 {
    var rig: Rig = .{};
    rig.open();
    const cancelled = rig.run(&names, seed, twist) catch return "a lookup did not end";
    for (expected, rig.verdicts, 0..) |want, got, index| {
        const verdict = got.?;
        if (verdict.equal(want)) continue;
        if (cancelled == index and same_error(verdict.err, core.Error.Canceled)) continue;
        return if (cancelled == index) "a cancelled lookup ended as neither itself nor Canceled" else "a verdict changed";
    }
    return null;
}

/// Runs `count` seeds from `first`, each under every twist, and returns the first that broke.
pub fn gate(expected: *const Alone, first: u64, count: u64) ?Broke {
    for (0..count) |offset| {
        const seed = first + offset;
        for (std.enums.values(Twist)) |twist| {
            if (check(expected, seed, twist)) |what| return .{ .seed = seed, .twist = twist, .what = what };
        }
    }
    return null;
}

// Tests.

const testing = std.testing;

test "lookups whose walks share zones end as each ends alone, in every order of replies" {
    const expected = try alone();
    try testing.expectEqual(core.Security.secure, expected[0].security);
    try testing.expectEqual(core.Security.insecure, expected[1].security);
    try testing.expectEqual(core.Error.NameNotFound, expected[2].err.?);
    try testing.expectEqual(core.Error.NoData, expected[3].err.?);
    if (gate(&expected, 0, gate_count)) |broke| {
        std.debug.print("seed {d}, {t}: {s}\n", .{ broke.seed, broke.twist, broke.what });
        return error.TestUnexpectedResult;
    }
}

test "two errors are the same when both are none, or both are the same error" {
    const values = [_]?core.Error{ null, core.Error.NoData, core.Error.Canceled };
    for (values, 0..) |left, left_index| for (values, 0..) |right, right_index| {
        try testing.expectEqual(left_index == right_index, same_error(left, right));
    };
}

test "a cancelled lookup ends Canceled, and the others as each ends alone" {
    const expected = try alone();
    var cancelled_count: usize = 0;
    for (0..gate_count) |seed| {
        var rig: Rig = .{};
        rig.open();
        const cancelled = (try rig.run(&names, seed, .cancel)).?;
        if (same_error(rig.verdicts[cancelled].?.err, core.Error.Canceled)) cancelled_count += 1;
    }
    // Some seed cancels a lookup before its end comes, so the twist reaches the table.
    try testing.expect(cancelled_count > 0);
    try testing.expectEqual(@as(?[]const u8, null), check(&expected, 0, .cancel));
}
