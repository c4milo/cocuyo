//! The memory of the engine's cache, which is the caller's (docs/design.md §19 step 13, the
//! cache's memory; §16 decision 37): `init` and `reinit` are handed the slots and the key index,
//! or none. An engine handed memory answers a repeated question from it and sends nothing, one
//! handed none asks its servers again, and `reinit` takes the same memory, other memory or none.
//! The cap on a TTL is the configuration's. The rig is the one `io_sim_test.zig` builds.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const Rig = sim_test.Rig;
const question = sim_test.question;

const up = [fixtures.servers]rotor.server.Script{ .{}, .{} };
/// Servers whose answers carry a TTL past the default cap, so a cap shows in what a hit reports.
const long_lived = [fixtures.servers]rotor.server.Script{
    .{ .ttl_seconds = fixtures.long_ttl_seconds },
    .{ .ttl_seconds = fixtures.long_ttl_seconds },
};

/// What one lookup did: whether a query went out for it, and the TTL its answer reported.
const Asked = struct { sent: bool, ttl_seconds: u32 };

/// Asks `name` and takes its answer. A send lends its slot's buffer to the loop from its
/// submission (the stream's rule 6), and `start` drives the lookup's first poll, so a lookup
/// the cache answered has lent none when `start` returns, and one bound for a server has. An
/// answer from the cache is taken at once, before the loop turns: nothing was sent for it.
fn ask(rig: *Rig, name: []const u8) !Asked {
    const handle = try rig.engine.start(question(name), rig.loop.now());
    const sent = rig.engine.send_in_flight[handle.index];
    const result = if (sent) try rig.until_result() else rig.engine.take(rig.loop.now()) orelse return error.NoResult;
    try testing.expectEqual(handle, result.handle);
    const ttl_seconds = result.outcome.answer.ttl_seconds;
    _ = rig.engine.take(rig.loop.now());
    return .{ .sent = sent, .ttl_seconds = ttl_seconds };
}

/// `slot_count` slots of the rig's memory and the least key index they take, as a caller that
/// read the count at run time hands them over.
fn part_of(rig: *Rig, slot_count: usize) cocuyo.cache.Slices {
    return .{
        .slots = rig.cache_memory.slots[0..slot_count],
        .keys = rig.cache_memory.keys[0..cocuyo.cache.keys_for(slot_count)],
    };
}

test "an engine handed cache memory answers a repeated question from it, and sends nothing" {
    var rig: Rig = .{};
    try rig.init(31, up, .{ .servers = &.{} });
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    // The cache is over the memory the rig handed in, keyed by the seed of that call.
    const store = &rig.engine.cache.?;
    try testing.expectEqual(@as([*]cocuyo.cache.Slot, &rig.cache_memory.slots), store.slots.ptr);
    try testing.expectEqual(@as([*]cocuyo.cache.Key, &rig.cache_memory.keys), store.keys.ptr);
    try testing.expectEqual(@as(usize, Rig.cache_slots), store.slots.len);
    try testing.expectEqual(@as(u64, 31), store.seed);
    try testing.expectEqual(@as(usize, 1), store.len());
    try rig.deinit();
}

test "an engine handed no cache memory has no cache, and sends a repeated question again" {
    var rig: Rig = .{};
    // The engine's own memory held a cache before: an engine built with one, and closed.
    try rig.init(32, up, .{ .servers = &.{} });
    try testing.expect(rig.engine.cache != null);
    try rig.deinit();
    try rig.init_with(47, up, .{ .servers = &.{} }, null);
    try testing.expect(rig.engine.cache == null);
    try testing.expect(rig.engine.resolver.memory == null);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try rig.deinit();
}

test "a cache of two slots, a count read at run time, holds two names and the third evicts one" {
    var rig: Rig = .{};
    var slot_count: usize = fixtures.cache_two_slots;
    _ = &slot_count;
    try testing.expect(cocuyo.cache.slot_count_valid(slot_count));
    try rig.init_with(33, up, .{ .servers = &.{} }, part_of(&rig, slot_count));
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "b.example.")).sent);
    // Both are held, and the hit marks `a` as used.
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "c.example.")).sent);
    try testing.expectEqual(slot_count, rig.engine.cache.?.len());
    // The hand passed `a`, which was used, and took `b` (docs/design.md §18), so `b` is asked
    // of a server again.
    try testing.expect((try ask(&rig, "b.example.")).sent);
    try rig.deinit();
}

test "the least memory there is, one slot and two keys, is a cache of one answer" {
    var rig: Rig = .{};
    var least: cocuyo.cache.Storage(fixtures.cache_least_slots) = .{};
    try testing.expectEqual(@as(usize, fixtures.cache_least_keys), least.keys.len);
    try testing.expectEqual(least.keys.len, cocuyo.cache.keys_for(least.slots.len));
    try rig.init_with(34, up, .{ .servers = &.{} }, least.slices());
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "b.example.")).sent);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try rig.deinit();
}

test "reinit handed the memory the engine holds empties the cache, and keys it by the new seed" {
    var rig: Rig = .{};
    try rig.init(35, up, .{ .servers = &.{} });
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    // The seed of `init` again, which a caller never hands `reinit` (RFC 9018 §3): it keeps
    // every name where it landed, so an entry the reinit left behind would be found.
    try rig.engine.reinit(&rig.config, rig.cache_memory.slices(), 35, rig.loop.now());
    try testing.expectEqual(@as(usize, 0), rig.engine.cache.?.len());
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try rig.engine.reinit(&rig.config, rig.cache_memory.slices(), 36, rig.loop.now());
    try testing.expectEqual(@as(u64, 36), rig.engine.cache.?.seed);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try rig.deinit();
}

test "reinit handed other memory builds the cache over it, and leaves the old alone" {
    var rig: Rig = .{};
    try rig.init(37, up, .{ .servers = &.{} });
    try testing.expect((try ask(&rig, "a.example.")).sent);
    var other: cocuyo.cache.Storage(fixtures.cache_least_slots) = .{};
    try rig.engine.reinit(&rig.config, other.slices(), 38, rig.loop.now());
    // The old memory is the caller's again once `reinit` returns: written over, it must stay
    // as written, and nothing the engine does may depend on it.
    const old = std.mem.asBytes(&rig.cache_memory);
    @memset(old, fixtures.memory_mark);
    try testing.expectEqual(@as([*]cocuyo.cache.Slot, &other.slots), rig.engine.cache.?.slots.ptr);
    try testing.expectEqual(@as(usize, fixtures.cache_least_slots), rig.engine.cache.?.slots.len);
    // One slot now, where the old memory held a slot a lookup: the second name evicts the first.
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "b.example.")).sent);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(std.mem.allEqual(u8, old, fixtures.memory_mark));
    try rig.deinit();
}

test "a reinit that fails has taken the memory it was handed, and let go of what it held" {
    var rig: Rig = .{};
    try rig.init(48, up, .{ .servers = &.{} });
    try testing.expect((try ask(&rig, "a.example.")).sent);
    var other: cocuyo.cache.Storage(fixtures.cache_least_slots) = .{};
    // No descriptor is left, so the sockets of the new start cannot be opened.
    rig.loop.network().refuse_open = true;
    const failed = rig.engine.reinit(&rig.config, other.slices(), 49, rig.loop.now());
    try testing.expectError(error.SocketFailed, failed);
    rig.loop.network().refuse_open = false;
    // The table and the cache were built before the sockets were asked for, so the cache is
    // over the memory that call handed in, under its seed: the caller keeps that memory, and
    // the memory the engine held before is the caller's to write over (rule 5).
    try testing.expectEqual(@as([*]cocuyo.cache.Slot, &other.slots), rig.engine.cache.?.slots.ptr);
    try testing.expectEqual(@as([*]cocuyo.cache.Key, &other.keys), rig.engine.cache.?.keys.ptr);
    try testing.expectEqual(@as(u64, 49), rig.engine.cache.?.seed);
    const old = std.mem.asBytes(&rig.cache_memory);
    @memset(old, fixtures.memory_mark);
    // The next reinit is handed the memory the failed one took, and the engine answers again,
    // from one slot: the second name evicts the first.
    try rig.engine.reinit(&rig.config, other.slices(), 50, rig.loop.now());
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "b.example.")).sent);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(std.mem.allEqual(u8, old, fixtures.memory_mark));
    // Handed none, a reinit that fails has let go of the memory all the same, and the engine
    // it leaves is one its caller can still shut.
    rig.loop.network().refuse_open = true;
    try testing.expectError(error.SocketFailed, rig.engine.reinit(&rig.config, null, 51, rig.loop.now()));
    rig.loop.network().refuse_open = false;
    try testing.expect(rig.engine.cache == null);
    try testing.expect(rig.engine.resolver.memory == null);
    try rig.deinit();
}

test "reinit handed none turns the cache off, and handed memory again turns it on" {
    var rig: Rig = .{};
    try rig.init(39, up, .{ .servers = &.{} });
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try rig.engine.reinit(&rig.config, null, 40, rig.loop.now());
    try testing.expect(rig.engine.cache == null);
    try testing.expect(rig.engine.resolver.memory == null);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try rig.engine.reinit(&rig.config, rig.cache_memory.slices(), 41, rig.loop.now());
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expect(!(try ask(&rig, "a.example.")).sent);
    try rig.deinit();
}

test "the cache keeps an answer no longer than an hour, when the configuration names no cap" {
    var rig: Rig = .{};
    try rig.init(42, long_lived, .{ .servers = &.{} });
    // The answer that went out reports what the server said, and the cache keeps it an hour.
    const first = try ask(&rig, "a.example.");
    try testing.expect(first.sent);
    try testing.expectEqual(@as(u32, fixtures.long_ttl_seconds), first.ttl_seconds);
    const hit = try ask(&rig, "a.example.");
    try testing.expect(!hit.sent);
    try testing.expectEqual(@as(u32, fixtures.hour_seconds), hit.ttl_seconds);
    try testing.expectEqual(@as(u32, fixtures.hour_seconds), rig.engine.cache.?.ttl_seconds_max);
    try rig.deinit();
}

test "the cache keeps an answer no longer than the cap the configuration sets, under its TTL or over" {
    const caps = [_]u32{ fixtures.cap_under_seconds, fixtures.cap_over_seconds };
    for (caps, 0..) |cap, case| {
        var rig: Rig = .{};
        try rig.init(43 + case, long_lived, .{ .servers = &.{}, .cache_ttl_seconds_max = cap });
        try testing.expect((try ask(&rig, "a.example.")).sent);
        const hit = try ask(&rig, "a.example.");
        try testing.expect(!hit.sent);
        // A cap over the answer's TTL leaves it as the server gave it: a cap only lowers.
        try testing.expectEqual(@min(cap, fixtures.long_ttl_seconds), hit.ttl_seconds);
        try rig.deinit();
    }
}

test "reinit takes the cap of the configuration it is handed" {
    var rig: Rig = .{};
    try rig.init(45, long_lived, .{ .servers = &.{}, .cache_ttl_seconds_max = fixtures.cap_before_seconds });
    try testing.expect((try ask(&rig, "a.example.")).sent);
    try testing.expectEqual(@as(u32, fixtures.cap_before_seconds), (try ask(&rig, "a.example.")).ttl_seconds);
    var replacement = rig.config;
    replacement.cache_ttl_seconds_max = fixtures.cap_after_seconds;
    try rig.engine.reinit(&replacement, rig.cache_memory.slices(), 46, rig.loop.now());
    try testing.expect((try ask(&rig, "a.example.")).sent);
    const hit = try ask(&rig, "a.example.");
    try testing.expect(!hit.sent);
    try testing.expectEqual(@as(u32, fixtures.cap_after_seconds), hit.ttl_seconds);
    try rig.deinit();
}

test "the cache takes the failure minimum of the configuration, at init and at reinit" {
    var rig: Rig = .{};
    try rig.init(47, up, .{ .servers = &.{}, .cache_failure_seconds_min = cocuyo.limits.cache_failure_seconds_least });
    try testing.expectEqual(cocuyo.limits.cache_failure_seconds_least, rig.engine.cache.?.failure_seconds_min);
    var replacement = rig.config;
    replacement.cache_failure_seconds_min = cocuyo.limits.cache_failure_seconds_max;
    try rig.engine.reinit(&replacement, rig.cache_memory.slices(), 48, rig.loop.now());
    try testing.expectEqual(cocuyo.limits.cache_failure_seconds_max, rig.engine.cache.?.failure_seconds_min);
    try rig.deinit();
}
