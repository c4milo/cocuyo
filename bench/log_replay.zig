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
/// A client stuck in a loop: one that asks a single name for nine questions in ten, a hundred
/// thousand times or more in the log. Every policy hits such a name nearly every time, so the
/// client would pad every table as though it were a workload. The Mendeley log has one, asking
/// `samba.local.local` 6.78 million times in a day, a fifth of all its questions.
const loop_questions_min = 100_000;
const loop_share_permille = 900;
const permille = 1000;

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
    var out: Columns = .{ .cache = cache_replay.replay(name_digits, recording, slot_count, cache_trace.trace_seed) };
    sieve_model.init(slot_count, .refresh_in_place, .hand);
    out.sieve = replay_model(&sieve_model, recording);
    s3fifo_model.init(slot_count, cache_trace.s3fifo_line_23, .refresh_in_place);
    out.s3fifo = replay_model(&s3fifo_model, recording);
    tinylfu_model.init(slot_count);
    out.tinylfu = replay_model(&tinylfu_model, recording);
    expected_model.init(slot_count, cache_trace.expected_draws, true, .reuse);
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
            const ranked = try ranked_by_count(gpa, log.names.items, log.name_count());
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

/// The values below `value_count` by how often `column` holds each, most often first and by value
/// among values held as often: the names by how often they are asked, or the clients by how much
/// they ask.
fn ranked_by_count(gpa: std.mem.Allocator, column: []const u32, value_count: usize) ![]u32 {
    const counts = try gpa.alloc(u32, value_count);
    @memset(counts, 0);
    for (column) |value| counts[value] += 1;
    const ranked = try gpa.alloc(u32, value_count);
    for (ranked, 0..) |*value, index| value.* = @intCast(index);
    std.mem.sort(u32, ranked, counts, struct {
        fn before(context: []const u32, one: u32, other: u32) bool {
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

/// Which clients are stuck in a loop, by client: at least `questions_min` questions, and one name
/// asked for `share_permille` in a thousand of them or more.
pub fn looping_clients(gpa: std.mem.Allocator, log: *const log_csv.Log, questions_min: usize, share_permille: usize) ![]bool {
    const volumes = try gpa.alloc(u64, log.client_count());
    @memset(volumes, 0);
    for (log.clients.items) |client| volumes[client] += 1;
    const looping = try gpa.alloc(bool, log.client_count());
    @memset(looping, false);
    // Counted only for the clients past the minimum, keyed by client and name together.
    var counts: std.AutoHashMapUnmanaged(u64, u64) = .empty;
    for (log.names.items, log.clients.items) |name, client| {
        if (volumes[client] < questions_min) continue;
        const entry = try counts.getOrPut(gpa, (@as(u64, client) << 32) | name);
        if (!entry.found_existing) entry.value_ptr.* = 0;
        entry.value_ptr.* += 1;
        if (entry.value_ptr.* * permille >= share_permille * volumes[client]) looping[client] = true;
    }
    return looping;
}

/// The log without the questions of the clients `excluded` marks. The names keep their indices.
pub fn without(gpa: std.mem.Allocator, log: *const log_csv.Log, excluded: []const bool) !log_csv.Log {
    var kept = log.*;
    kept.names = .empty;
    kept.times_ns = .empty;
    kept.clients = .empty;
    for (log.names.items, log.times_ns.items, log.clients.items) |name, time, client| {
        if (excluded[client]) continue;
        try kept.names.append(gpa, name);
        try kept.times_ns.append(gpa, time);
        try kept.clients.append(gpa, client);
    }
    return kept;
}

/// The `count` clients that asked most, busiest first.
fn busiest(gpa: std.mem.Allocator, log: *const log_csv.Log, count: usize) ![]u32 {
    const ranked = try ranked_by_count(gpa, log.clients.items, log.client_count());
    return ranked[0..@min(count, ranked.len)];
}

/// Where a client that is not among the ones replayed alone stands among them: nowhere.
const not_alone = std.math.maxInt(u32);

/// Some clients' questions, each client's alone with its names renumbered from zero so a model
/// sized for the whole log holds them. Only the lives differ from one TTL rule to the next, so the
/// log is read once for every client and every rule, and `set_lives` gives each rule its lives.
pub const Alone = struct {
    recordings: []Recording,
    /// Each recording's names as the whole log numbers them, by the recording's own number.
    names_in_log: []const []const Id,

    /// Each name of each recording takes the life it has in the whole log.
    pub fn set_lives(self: *const Alone, lives: []const u64) void {
        for (self.recordings, self.names_in_log) |*recording, names| {
            for (recording.lives_ns, names) |*life, name| life.* = lives[name];
        }
    }

    /// How many questions the clients ask between them.
    pub fn questions(self: *const Alone) usize {
        var total: usize = 0;
        for (self.recordings) |*recording| total += recording.names.len;
        return total;
    }
};

/// The questions of `clients`, each client's alone, in one pass over the log. The lives are left
/// for `Alone.set_lives`.
pub fn clients_alone(gpa: std.mem.Allocator, log: *const log_csv.Log, clients: []const u32) !Alone {
    const place = try gpa.alloc(u32, log.client_count());
    @memset(place, not_alone);
    for (clients, 0..) |client, index| place[client] = @intCast(index);
    const names = try gpa.alloc(std.ArrayList(Id), clients.len);
    const times = try gpa.alloc(std.ArrayList(u64), clients.len);
    const in_log = try gpa.alloc(std.ArrayList(Id), clients.len);
    const local = try gpa.alloc(std.AutoHashMapUnmanaged(Id, Id), clients.len);
    @memset(names, .empty);
    @memset(times, .empty);
    @memset(in_log, .empty);
    @memset(local, .empty);
    for (log.names.items, log.times_ns.items, log.clients.items) |name, time, client| {
        const at = place[client];
        if (at == not_alone) continue;
        const entry = try local[at].getOrPut(gpa, name);
        if (!entry.found_existing) {
            entry.value_ptr.* = @intCast(in_log[at].items.len);
            try in_log[at].append(gpa, name);
        }
        try names[at].append(gpa, entry.value_ptr.*);
        try times[at].append(gpa, time);
    }
    const recordings = try gpa.alloc(Recording, clients.len);
    const names_in_log = try gpa.alloc([]const Id, clients.len);
    for (recordings, names_in_log, names, times, in_log) |*recording, *numbering, asked, when, known| {
        recording.* = .{
            .names = asked.items,
            .times_ns = when.items,
            .next = try gpa.alloc(u32, asked.items.len),
            .lives_ns = try gpa.alloc(u64, known.items.len),
        };
        recording.link(try gpa.alloc(u32, known.items.len));
        numbering.* = known.items;
    }
    return .{ .recordings = recordings, .names_in_log = names_in_log };
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

fn run_rule(gpa: std.mem.Allocator, log: *const log_csv.Log, rule: TtlRule, alone: *const Alone) !void {
    const lives = try lives_of(gpa, log, rule);
    const recording = try whole(gpa, log, lives);
    print_header(if (rule == .hashed) "every client, one cache; TTLs by a hash of the name" else "every client, one cache; TTLs by rank, the most asked shortest");
    for (cache_trace.sizes) |slot_count| print_row(slot_count, replay_all(&recording, slot_count));
    cares_model.init();
    const cares = replay_model(&cares_model, &recording);
    std.debug.print("c-ares's rule, no bound: {d:.2}% hits, at most {d} entries live at once\n", .{ cares.rate_percent(), cares_model.entries_peak });

    alone.set_lives(lives);
    print_header("the busiest clients, each with a cache of its own, summed");
    for (cache_trace.sizes) |slot_count| {
        var sum: Columns = .{};
        for (alone.recordings) |*one| sum.add(replay_all(one, slot_count));
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
    const loaded = try log_csv.load(init.io, gpa, arguments[1]);
    if (loaded.name_count() > names_max) return error.TooManyNames;
    const looping = try looping_clients(gpa, &loaded, loop_questions_min, loop_share_permille);
    const log = try without(gpa, &loaded, looping);
    std.debug.print("{d} clients stuck in a loop set aside, with {d} questions\n", .{
        std.mem.count(bool, looping, &.{true}), loaded.names.items.len - log.names.items.len,
    });
    const clients = try busiest(gpa, &log, clients_replayed);
    const alone = try clients_alone(gpa, &log, clients);
    std.debug.print("{d} questions kept, {d} attack rows dropped, {d} names, {d} clients; the busiest {d} ask {d}\n", .{
        log.names.items.len, log.attack_rows, log.name_count(), log.client_count(), clients.len, alone.questions(),
    });
    for ([_]TtlRule{ .hashed, .by_rank }) |rule| try run_rule(gpa, &log, rule, &alone);
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
    const clients = try busiest(arena.allocator(), &log, 1);
    try testing.expectEqualSlices(u32, &.{1}, clients);
    const alone = try clients_alone(arena.allocator(), &log, clients);
    const one = alone.recordings[0];
    try testing.expectEqualSlices(Id, &.{ 0, 0, 1 }, one.names);
    try testing.expectEqualSlices(u64, &.{ 1 * std.time.ns_per_ms, 3 * std.time.ns_per_ms, 4 * std.time.ns_per_ms }, one.times_ns);
    try testing.expectEqualSlices(u32, &.{ 1, recording_module.no_request, recording_module.no_request }, one.next);
    try testing.expectEqual(@as(usize, 3), alone.questions());
    // The lives are set per rule, each name taking the one it has in the whole log.
    for ([_]TtlRule{ .hashed, .by_rank }) |rule| {
        const lives = try lives_of(arena.allocator(), &log, rule);
        alone.set_lives(lives);
        try testing.expectEqualSlices(u64, &.{ lives[0], lives[2] }, one.lives_ns);
    }
}

test "a client asking one name nine times in ten, often enough, is stuck in a loop" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var log: log_csv.Log = .{};
    // c1: x nine times, y once. c2: x five times, y five. c3: x nine times, under the minimum.
    const plan = [_]struct { client: []const u8, name: []const u8, times: usize }{
        .{ .client = "c1", .name = "x.example", .times = 9 },
        .{ .client = "c1", .name = "y.example", .times = 1 },
        .{ .client = "c2", .name = "x.example", .times = 5 },
        .{ .client = "c2", .name = "y.example", .times = 5 },
        .{ .client = "c3", .name = "x.example", .times = 9 },
    };
    for (plan) |step| {
        for (0..step.times) |_| try log.add(gpa, .{ .client = step.client, .time_ms = 1, .attack = false, .name = step.name });
    }
    const looping = try looping_clients(gpa, &log, 10, 900);
    try testing.expectEqualSlices(bool, &.{ true, false, false }, looping);
    const kept = try without(gpa, &log, looping);
    try testing.expectEqual(@as(usize, 19), kept.names.items.len);
    for (kept.clients.items) |client| try testing.expect(client != 0);
}
