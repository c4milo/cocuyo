//! The order a lookup asks its servers in (docs/design.md §19 step 12). c-ares asks the servers
//! with the fewest consecutive failures first and probes a failed one now and then with a copy
//! of the query; cocuyo sorts the same way and, one query in `failover_retry_chance`, once
//! `failover_retry_delay_ns` has passed, gives a failed server the first place with the real
//! query, at the price of one timeout when it is still down (§16 decision 17).
//!
//! The order is computed at the first poll, which is the first instant a lookup has, and holds
//! for the lookup: a server that fails during it is asked last by the next lookup, not this one.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Lookup = @import("lookup.zig").Lookup;

pub fn order_servers(self: *Lookup, now_ns: u64) void {
    assert(!self.flags.ordered);
    const count = self.config.server_count();
    assert(count <= core.constants.servers_max);
    for (self.order[0..count], 0..) |*slot, index| slot.* = @intCast(index);
    sort_by_failures(self, count);
    if (self.config.rotate) rotate_front_group(self, count);
    if (self.config.failover_retry_chance > 0) promote_retry(self, count, now_ns);
    self.flags.ordered = true;
}

/// Insertion sort, stable, so servers with the same count keep the configured order. Eight at
/// most, which is why it is this sort.
fn sort_by_failures(self: *Lookup, count: usize) void {
    var index: usize = 1;
    while (index < count) : (index += 1) {
        var at = index;
        while (at > 0 and failures_of(self, self.order[at]) < failures_of(self, self.order[at - 1])) : (at -= 1) {
            std.mem.swap(u8, &self.order[at], &self.order[at - 1]);
        }
    }
    assert(count == 0 or failures_of(self, self.order[0]) <= failures_of(self, self.order[count - 1]));
}

/// Rotation among the servers that share the fewest failures: the seed picks where the first
/// pass starts among them, and the walk goes on from there in order.
fn rotate_front_group(self: *Lookup, count: usize) void {
    const fewest = failures_of(self, self.order[0]);
    var group: usize = 1;
    while (group < count and failures_of(self, self.order[group]) == fewest) : (group += 1) {}
    assert(group <= count);
    if (group == 1) return;
    const start = self.entropy.server_start(group);
    std.mem.rotate(u8, self.order[0..group], start);
}

/// One query in `failover_retry_chance`, the first failed server whose delay has passed goes
/// first, so a server that recovered is found without waiting for a good one to fail.
fn promote_retry(self: *Lookup, count: usize, now_ns: u64) void {
    const chance = self.config.failover_retry_chance;
    assert(chance >= 1);
    if (self.entropy.next() % chance != 0) return;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const state = self.servers.state(self.order[index]);
        if (state.failures == 0) continue;
        if (now_ns < state.failed_at_ns + self.config.failover_retry_delay_ns) continue;
        std.mem.rotate(u8, self.order[0 .. index + 1], index);
        assert(self.servers.failures(self.order[0]) >= 1);
        return;
    }
}

fn failures_of(self: *const Lookup, slot: u8) u8 {
    return self.servers.failures(slot);
}

// Tests. The order is read straight off the lookup after one poll.

const testing = std.testing;
const Config = core.Config;
const Question = core.Question;
const Servers = @import("servers.zig").Servers;
const fixtures = @import("fixtures.zig");

const three = fixtures.servers_three;

fn ordered(config: *const Config, servers: *Servers, seed: u64, now_ns: u64) [core.constants.servers_max]u8 {
    var lookup = Lookup.init(config, servers, Question.from_text("example.com.", .a) catch unreachable, seed);
    var out: [core.constants.query_bytes_max]u8 = @splat(0);
    _ = lookup.poll(now_ns, &out);
    return lookup.order;
}

test "servers are asked in configured order until one fails, and a failed one goes last" {
    const config: Config = .{ .servers = &three, .failover_retry_chance = 0 };
    var servers = Servers.init(&config, 1);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, ordered(&config, &servers, 1, 0)[0..3]);
    servers.record_failure(1, 0);
    try testing.expectEqualSlices(u8, &.{ 0, 2, 1 }, ordered(&config, &servers, 1, 0)[0..3]);
    servers.record_failure(0, 0);
    servers.record_failure(0, 0);
    try testing.expectEqualSlices(u8, &.{ 2, 1, 0 }, ordered(&config, &servers, 1, 0)[0..3]);
    servers.record_success(0);
    try testing.expectEqualSlices(u8, &.{ 0, 2, 1 }, ordered(&config, &servers, 1, 0)[0..3]);
}

test "rotation moves among the servers with the fewest failures and never past them" {
    const config: Config = .{ .servers = &three, .rotate = true, .failover_retry_chance = 0 };
    var servers = Servers.init(&config, 1);
    servers.record_failure(2, 0);
    var seen: [3]bool = @splat(false);
    var seed: u64 = 0;
    while (seed < 32) : (seed += 1) {
        const order = ordered(&config, &servers, seed, 0);
        try testing.expect(order[0] != 2);
        try testing.expectEqual(@as(u8, 2), order[2]);
        seen[order[0]] = true;
    }
    try testing.expect(seen[0] and seen[1]);
}

test "a failed server is promoted once its delay has passed, one query in the chance" {
    const always: Config = .{ .servers = &three, .failover_retry_chance = 1, .failover_retry_delay_ns = 10 };
    var servers = Servers.init(&always, 1);
    servers.record_failure(0, 100);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 0 }, ordered(&always, &servers, 1, 105)[0..3]);
    try testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, ordered(&always, &servers, 1, 110)[0..3]);
    const never: Config = .{ .servers = &three, .failover_retry_chance = 0, .failover_retry_delay_ns = 10 };
    try testing.expectEqualSlices(u8, &.{ 1, 2, 0 }, ordered(&never, &servers, 1, 110)[0..3]);
}

test "with a chance of two, about half the lookups promote the failed server" {
    const half: Config = .{ .servers = &three, .failover_retry_chance = 2, .failover_retry_delay_ns = 0 };
    var servers = Servers.init(&half, 1);
    servers.record_failure(2, 0);
    var promoted: usize = 0;
    var seed: u64 = 0;
    while (seed < 64) : (seed += 1) {
        if (ordered(&half, &servers, seed, 1)[0] == 2) promoted += 1;
    }
    try testing.expect(promoted >= 16 and promoted <= 48);
}
