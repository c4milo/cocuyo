//! The cache over a real DNS log (docs/design.md §18):
//!
//!     zig build bench-log -- <dataset.csv>
//!
//! The log is Mendeley Data c4n7fckkz3, read by `log_csv.zig`. It is replayed through the real
//! cache, the SIEVE model that must match it, S3-FIFO, W-TinyLFU, expected hits and the optimal,
//! at the sizes the synthetic trace uses, in two ways. Every client together through one cache is
//! the workload of a recursive resolver. The busiest clients one by one, each with a cache of its
//! own, is closer to how cocuyo is deployed: inside one process on one host.
//!
//! The log carries no TTLs, so each name takes one from the synthetic trace's mixture, twice
//! over. Once by a hash of its text, which makes TTL and popularity unrelated; once by its rank,
//! as the synthetic trace does, so the most asked names take the shortest TTLs. How far the two
//! differ is how much the tables rest on the assumption.
const std = @import("std");
const assert = std.debug.assert;
const log_csv = @import("log_csv.zig");
const recording_module = @import("trace_recording.zig");
const cache_replay = @import("cache_replay.zig");
const optimal_module = @import("cache_optimal.zig");
const cache_trace = @import("cache_trace.zig");
const policy = @import("cache_policy/cache_policy.zig");
const s3fifo_policy = @import("cache_policy/cache_policy_s3fifo.zig");
const tinylfu_policy = @import("cache_policy/cache_policy_tinylfu.zig");
const expected_policy = @import("cache_policy/cache_policy_expected.zig");
const cares_policy = @import("cache_policy/cache_policy_cares.zig");
const Recording = recording_module.Recording;
const Outcome = recording_module.Outcome;
const Id = recording_module.Id;
const replay_model = recording_module.replay_model;

/// The most names a log may hold: the models are sized at compile time, and this is past the
/// 638,748 names of the Mendeley log.
const names_max = 1 << 20;
/// Digits in a name's question text, which covers `names_max`.
const name_digits = 7;
/// The busiest clients replayed one by one: past them, a client asks too little in a day for a
/// cache to say anything.
const clients_replayed = 100;
/// The affordable form of expected hits, as the synthetic tables run it.
const expected_draws = 16;
/// S3-FIFO as Algorithm 1 line 23 has it.
const s3fifo_line_23 = 1;
/// The cache's hash key, as the synthetic trace's.
const cache_seed = 0x5eed_c0c0;

pub const TtlRule = enum { hashed, by_rank };

var sieve_model: policy.Sieve(names_max) = undefined;
var s3fifo_model: s3fifo_policy.S3Fifo(names_max) = undefined;
var tinylfu_model: tinylfu_policy.WTinyLfu(names_max) = undefined;
var expected_model: expected_policy.ExpectedHits(names_max) = undefined;
var cares_model: cares_policy.Unbounded(names_max) = undefined;
var optimal: optimal_module.Optimal(names_max) = undefined;

/// One row of a table: every policy over one recording, or summed over several.
const Columns = struct {
    cache: Outcome = .{},
    sieve: Outcome = .{},
    s3fifo: Outcome = .{},
    tinylfu: Outcome = .{},
    expected: Outcome = .{},
    best: Outcome = .{},

    fn add(self: *Columns, other: Columns) void {
        inline for (std.meta.fields(Columns)) |field| @field(self, field.name).add(@field(other, field.name));
    }
};

fn replay_all(recording: *const Recording, slot_count: usize) Columns {
    var out: Columns = .{ .cache = cache_replay.replay(name_digits, recording, slot_count, cache_seed) };
    sieve_model.init(slot_count, .refresh_in_place, .hand);
    out.sieve = replay_model(&sieve_model, recording);
    s3fifo_model.init(slot_count, s3fifo_line_23, .refresh_in_place);
    out.s3fifo = replay_model(&s3fifo_model, recording);
    tinylfu_model.init(slot_count);
    out.tinylfu = replay_model(&tinylfu_model, recording);
    expected_model.init(slot_count, expected_draws, true, .reuse);
    out.expected = replay_model(&expected_model, recording);
    out.best = optimal.replay(recording, slot_count);
    return out;
}

/// Each name's life under `rule`, by name.
pub fn lives_of(gpa: std.mem.Allocator, log: *const log_csv.Log, rule: TtlRule) ![]u64 {
    const lives = try gpa.alloc(u64, log.name_count());
    switch (rule) {
        .hashed => for (lives, log.name_hashes.items) |*life, hash| {
            life.* = life_of_share(@intCast(hash % cache_trace.ttl_share_total));
        },
        .by_rank => {
            const ranked = try by_popularity(gpa, log);
            for (ranked, 0..) |name, rank| {
                lives[name] = life_of_share(@intCast(rank * cache_trace.ttl_share_total / ranked.len));
            }
        },
    }
    return lives;
}

fn life_of_share(bucket: u32) u64 {
    return @as(u64, cache_trace.ttl_for_share(bucket)) * std.time.ns_per_s;
}

/// The names, most asked first, and by index among names asked as often.
fn by_popularity(gpa: std.mem.Allocator, log: *const log_csv.Log) ![]Id {
    const counts = try gpa.alloc(u32, log.name_count());
    @memset(counts, 0);
    for (log.names.items) |name| counts[name] += 1;
    const ranked = try gpa.alloc(Id, log.name_count());
    for (ranked, 0..) |*name, index| name.* = @intCast(index);
    std.mem.sort(Id, ranked, counts, struct {
        fn before(context: []const u32, one: Id, other: Id) bool {
            if (context[one] != context[other]) return context[one] > context[other];
            return one < other;
        }
    }.before);
    return ranked;
}

/// Every question of the log, through one cache.
fn whole(gpa: std.mem.Allocator, log: *const log_csv.Log, lives: []u64) !Recording {
    const recording: Recording = .{
        .names = log.names.items,
        .times_ns = log.times_ns.items,
        .next = try gpa.alloc(u32, log.names.items.len),
        .lives_ns = lives,
    };
    recording.link(try gpa.alloc(u32, lives.len));
    return recording;
}

/// The `count` clients that asked most, busiest first.
fn busiest(gpa: std.mem.Allocator, log: *const log_csv.Log, count: usize) ![]u32 {
    const volumes = try gpa.alloc(u32, log.client_count());
    @memset(volumes, 0);
    for (log.clients.items) |client| volumes[client] += 1;
    const ranked = try gpa.alloc(u32, log.client_count());
    for (ranked, 0..) |*client, index| client.* = @intCast(index);
    std.mem.sort(u32, ranked, volumes, struct {
        fn before(context: []const u32, one: u32, other: u32) bool {
            if (context[one] != context[other]) return context[one] > context[other];
            return one < other;
        }
    }.before);
    return ranked[0..@min(count, ranked.len)];
}

/// One client's questions alone, its names renumbered from zero so a model sized for the whole
/// log holds them, each keeping the life it has in the whole log.
pub fn client_recording(gpa: std.mem.Allocator, log: *const log_csv.Log, lives: []const u64, client: u32) !Recording {
    var names: std.ArrayList(Id) = .empty;
    var times: std.ArrayList(u64) = .empty;
    var local_lives: std.ArrayList(u64) = .empty;
    var local: std.AutoHashMapUnmanaged(Id, Id) = .empty;
    for (log.names.items, log.times_ns.items, log.clients.items) |name, time, asker| {
        if (asker != client) continue;
        const entry = try local.getOrPut(gpa, name);
        if (!entry.found_existing) {
            entry.value_ptr.* = @intCast(local_lives.items.len);
            try local_lives.append(gpa, lives[name]);
        }
        try names.append(gpa, entry.value_ptr.*);
        try times.append(gpa, time);
    }
    const recording: Recording = .{
        .names = names.items,
        .times_ns = times.items,
        .next = try gpa.alloc(u32, names.items.len),
        .lives_ns = local_lives.items,
    };
    recording.link(try gpa.alloc(u32, local_lives.items.len));
    return recording;
}

fn print_header(title: []const u8) void {
    std.debug.print("\n{s}\n\n", .{title});
    std.debug.print("{s:>8} {s:>9} {s:>9} {s:>9} {s:>9} {s:>9} {s:>9}\n", .{ "slots", "cache", "sieve", "s3-fifo", "tinylfu", "expected", "optimal" });
}

fn print_row(slot_count: usize, row: Columns) void {
    std.debug.print("{d:>8} {d:>8.2}% {d:>8.2}% {d:>8.2}% {d:>8.2}% {d:>8.2}% {d:>8.2}%\n", .{
        slot_count,
        row.cache.rate_percent(),
        row.sieve.rate_percent(),
        row.s3fifo.rate_percent(),
        row.tinylfu.rate_percent(),
        row.expected.rate_percent(),
        row.best.rate_percent(),
    });
}

fn run_rule(gpa: std.mem.Allocator, log: *const log_csv.Log, rule: TtlRule, clients: []const u32) !void {
    const lives = try lives_of(gpa, log, rule);
    const recording = try whole(gpa, log, lives);
    print_header(if (rule == .hashed) "every client, one cache; TTLs by a hash of the name" else "every client, one cache; TTLs by rank, the most asked shortest");
    for (cache_trace.sizes) |slot_count| print_row(slot_count, replay_all(&recording, slot_count));
    cares_model.init();
    const cares = replay_model(&cares_model, &recording);
    std.debug.print("c-ares's rule, no bound: {d:.2}% hits, at most {d} entries live at once\n", .{ cares.rate_percent(), cares_model.entries_peak });

    const alone = try gpa.alloc(Recording, clients.len);
    for (alone, clients) |*one, client| one.* = try client_recording(gpa, log, lives, client);
    print_header("the busiest clients, each with a cache of its own, summed");
    for (cache_trace.sizes) |slot_count| {
        var sum: Columns = .{};
        for (alone) |*one| sum.add(replay_all(one, slot_count));
        print_row(slot_count, sum);
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(gpa);
    if (arguments.len != 2) {
        std.debug.print("usage: bench-log <dataset.csv>\n", .{});
        return error.Usage;
    }
    const log = try log_csv.load(init.io, gpa, arguments[1]);
    if (log.name_count() > names_max) return error.TooManyNames;
    const clients = try busiest(gpa, &log, clients_replayed);
    var asked: usize = 0;
    for (log.clients.items) |client| {
        if (std.mem.indexOfScalar(u32, clients, client) != null) asked += 1;
    }
    std.debug.print("{d} questions kept, {d} attack rows dropped, {d} names, {d} clients; the busiest {d} ask {d}\n", .{
        log.names.items.len, log.attack_rows, log.name_count(), log.client_count(), clients.len, asked,
    });
    for ([_]TtlRule{ .hashed, .by_rank }) |rule| try run_rule(gpa, &log, rule, clients);
}

// Tests.

const testing = std.testing;

fn small_log(gpa: std.mem.Allocator) !log_csv.Log {
    var log: log_csv.Log = .{};
    const rows = [_][]const u8{
        "c1,x,1000,False,popular.example",
        "c2,x,1001,False,popular.example",
        "c1,x,1002,False,rare.example",
        "c2,x,1003,False,popular.example",
        "c2,x,1004,False,other.example",
    };
    for (rows) |row| try log.add(gpa, try log_csv.parse_line(row));
    return log;
}

test "by rank, the most asked name takes the shortest life; by hash, each takes one of the mixture" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const log = try small_log(arena.allocator());
    const ranked = try lives_of(arena.allocator(), &log, .by_rank);
    try testing.expectEqual(@as(u64, cache_trace.ttl_seconds[0]) * std.time.ns_per_s, ranked[0]);
    try testing.expect(ranked[0] <= ranked[1] and ranked[0] <= ranked[2]);
    const hashed = try lives_of(arena.allocator(), &log, .hashed);
    for (hashed, log.name_hashes.items) |life, hash| {
        try testing.expectEqual(life_of_share(@intCast(hash % cache_trace.ttl_share_total)), life);
    }
}

test "one client's recording holds its questions alone, its names renumbered from zero" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const log = try small_log(arena.allocator());
    const lives = try lives_of(arena.allocator(), &log, .hashed);
    const alone = try client_recording(arena.allocator(), &log, lives, 1);
    try testing.expectEqualSlices(Id, &.{ 0, 0, 1 }, alone.names);
    try testing.expectEqualSlices(u64, &.{ 1 * std.time.ns_per_ms, 3 * std.time.ns_per_ms, 4 * std.time.ns_per_ms }, alone.times_ns);
    try testing.expectEqualSlices(u32, &.{ 1, recording_module.no_request, recording_module.no_request }, alone.next);
    try testing.expectEqualSlices(u64, &.{ lives[0], lives[2] }, alone.lives_ns);
    const clients = try busiest(arena.allocator(), &log, 1);
    try testing.expectEqualSlices(u32, &.{1}, clients);
}
