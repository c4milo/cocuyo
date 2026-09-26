//! Two engines on two threads of one image, each on its own loop, resolving at once (docs/design.md
//! §24 step 6, a thread per core): on the twin, whose network is thread-local, so each thread's
//! scripted servers are its own. Both engines hold one `Config`, and each thread's servers answer
//! with a TTL of their own, so an answer that crossed threads, or a cache the two shared, would show.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;
const endpoint_of = sim_test.endpoint_of;

const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .cache_slots = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
});
const Rig = sim_test.RigOf(Resolver);

/// The names each thread resolves: the same on both, so a shared cache would answer one thread
/// with what the other's servers said.
const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example." };
const threads = 2;

/// One thread's run: its rig, its seed and its servers' TTL, and what it took.
const Run = struct {
    rig: Rig = .{},
    seed: u64,
    ttl_seconds: u32,
    config: *const cocuyo.Config,
    started: *std.atomic.Value(usize),
    answered: usize = 0,
    crossed: usize = 0,
    failed: ?anyerror = null,
};

fn run(state: *Run) void {
    resolve_all(state) catch |err| {
        state.failed = err;
    };
}

/// Waits for the other thread, so the two resolve at once, then resolves every name and counts
/// the answers that carry this thread's servers' TTL and those that do not.
fn resolve_all(state: *Run) !void {
    const script: rotor.server.Script = .{ .ttl_seconds = state.ttl_seconds };
    try state.rig.init_on(state.seed, .{ script, script }, state.config);
    _ = state.started.fetchAdd(1, .acq_rel);
    // Bounded by the other thread's start, which the test joins.
    while (state.started.load(.acquire) < threads) std.atomic.spinLoopHint();
    for (names) |name| _ = try state.rig.engine.start(question(name), state.rig.loop.now());
    for (names) |_| {
        const result = try state.rig.until_result();
        const answer = switch (result.outcome) {
            .answer => |held| held,
            .failure => return error.LookupFailed,
        };
        if (answer.ttl_seconds == state.ttl_seconds) state.answered += 1 else state.crossed += 1;
    }
    _ = state.rig.engine.take(state.rig.loop.now());
    try state.rig.deinit();
}

test "two engines on two threads, each on its own loop, resolve at once, and neither takes the other's answers" {
    const servers = [_]cocuyo.Server{
        .{ .endpoint = endpoint_of(rotor.Network.server_address(0)) },
        .{ .endpoint = endpoint_of(rotor.Network.server_address(1)) },
    };
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    var started = std.atomic.Value(usize).init(0);
    const runs = try testing.allocator.alloc(Run, threads);
    defer testing.allocator.free(runs);
    const ttls = [threads]u32{ 111, 222 };
    for (runs, ttls, 0..) |*state, ttl, index| {
        state.* = .{ .seed = 71 + index, .ttl_seconds = ttl, .config = &config, .started = &started };
    }
    var handles: [threads]std.Thread = undefined;
    for (&handles, runs) |*handle, *state| handle.* = try std.Thread.spawn(.{}, run, .{state});
    for (handles) |handle| handle.join();
    for (runs) |state| {
        try testing.expectEqual(@as(?anyerror, null), state.failed);
        try testing.expectEqual(names.len, state.answered);
        try testing.expectEqual(@as(usize, 0), state.crossed);
    }
}
