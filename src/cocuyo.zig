//! cocuyo: a DNS resolver library. It builds query bytes and parses response bytes, and owns no
//! socket, no file descriptor, no thread, no timer and no allocator. The caller does the sending
//! and the receiving; cocuyo says what to do next.
//!
//! This file is the public surface: each module of docs/design.md §2 is re-exported here, and the
//! names a consumer reaches for are flattened alongside them as each step of §15 lands them.
//!
//! It holds one piece of logic, and only because this is the one file that can: `remembered_by`
//! turns a `Cache` into the `Memory` the table asks, and `resolver` cannot reach `cache` (§3).
//! What may be remembered at all — RFC 2308 §5's two negatives and the resolution failures of
//! RFC 9520 §2 — is written there once rather than in every consumer (§20, §16 decision 61).
pub const core = @import("core");
pub const wire = @import("wire");
pub const resolver = @import("resolver");
pub const resolv_conf = @import("config");
pub const hosts = resolv_conf.hosts;
pub const spki_pin = resolv_conf.spki_pin;
pub const cache = @import("cache");

// The names a consumer reaches for, flattened. Everything else is behind the module it belongs to.
pub const Address = core.Address;
pub const Endpoint = core.Endpoint;
pub const Family = core.Family;
pub const Name = core.Name;
pub const Kind = core.Kind;
pub const Question = core.Question;
pub const Config = core.Config;
pub const Security = core.Security;
pub const AuthenticatedData = core.AuthenticatedData;
pub const Server = core.Server;
pub const Tls = core.Tls;
pub const Https = core.Https;
pub const Pin = core.Pin;
pub const Source = core.Source;
pub const Hosts = core.Hosts;
/// RFC 6724's destination address ordering over routes the consumer supplies (§19 step 15).
pub const Route = core.address_order.Route;
pub const order_addresses = core.address_order.order;
pub const Error = core.Error;
pub const constants = core.constants;
pub const limits = core.limits;

pub const Lookup = resolver.Lookup;
pub const Resolver = resolver.Resolver;
pub const Servers = resolver.Servers;
pub const Action = resolver.Action;
pub const Answer = resolver.Answer;
pub const Failure = resolver.Failure;
pub const Cause = resolver.Cause;
pub const Reason = resolver.Reason;
pub const Verdict = resolver.Verdict;
pub const Handle = resolver.Handle;
pub const Slot = resolver.Slot;
pub const MatchKey = resolver.MatchKey;
pub const Event = resolver.Event;
pub const AddressLookup = resolver.AddressLookup;
pub const AddressFlags = resolver.AddressFlags;
pub const AddressInfo = resolver.AddressInfo;
pub const AddressOutcome = resolver.AddressOutcome;
pub const NameLookup = resolver.NameLookup;
pub const NameInfo = resolver.NameInfo;
pub const NameOutcome = resolver.NameOutcome;

pub const Cache = cache.Cache;
pub const Hit = cache.Hit;
pub const Memory = resolver.Memory;
pub const Remembered = resolver.Remembered;

/// A `Memory` filled in from a `Cache`: what a consumer hands `Resolver.remember_with` to put
/// the cache under every lookup the table starts, composed ones included (docs/design.md §20).
///
/// This is the one place that says what may be remembered at all: an answer, the two
/// negatives of RFC 2308 §5 with the TTL the SOA gave, and a resolution failure of RFC 9520 §2,
/// which the cache keeps for a time of its own. `resolver` cannot reach `cache` (§3), and
/// this file can reach both, so the rule lives here rather than in every consumer.
pub fn remembered_by(store: *Cache) Memory {
    return .{ .context = store, .recall = recall_from_cache, .remember = remember_in_cache };
}

fn recall_from_cache(context: *anyopaque, question: *const Question, now_ns: u64) ?Remembered {
    const store: *Cache = @ptrCast(@alignCast(context));
    const hit = store.get(question, now_ns) orelse return null;
    return switch (hit.outcome) {
        .answered => .{ .answered = .{
            .answers = hit.answers,
            .ttl_seconds = hit.ttl_seconds,
            .canonical_name = hit.canonical_name,
        } },
        .name_not_found => .{ .negative = .{ .outcome = .name_not_found, .ttl_seconds = hit.ttl_seconds } },
        .no_data => .{ .negative = .{ .outcome = .no_data, .ttl_seconds = hit.ttl_seconds } },
        // A resolution failure: the table ends the lookup with it and sends no query
        // (RFC 9520 §3.2; docs/design.md §16 decision 61).
        .failed => .{ .failed = hit.failure.? },
    };
}

fn remember_in_cache(
    context: *anyopaque,
    question: *const Question,
    end: Remembered,
    now_ns: u64,
) void {
    const store: *Cache = @ptrCast(@alignCast(context));
    switch (end) {
        .answered => |answered| store.put(question, answered.answers, answered.canonical_name, now_ns),
        .negative => |negative| store.put_negative(question, switch (negative.outcome) {
            .name_not_found => .name_not_found,
            .no_data => .no_data,
        }, negative.ttl_seconds, now_ns),
        .failed => |err| {
            // The table writes the failures that the cache keeps, and no other (§16 decision 61).
            assert(cache.resolution_failure(err));
            store.put_failure(question, err, now_ns);
        },
    }
}

test "a failure the cache holds comes back as failed, with its error" {
    var rig: CacheRig = .{};
    rig.open();
    const question = try Question.from_text("down.example", .a);
    rig.store.put_failure(&question, Error.AllServersFailed, 0);
    const memory = remembered_by(&rig.store);
    try testing.expectEqual(Error.AllServersFailed, memory.recall(memory.context, &question, 0).?.failed);
}

test "a failure written through the memory is kept for the cache's minimum, and then expires" {
    var rig: CacheRig = .{};
    rig.open();
    const memory = remembered_by(&rig.store);
    const question = try Question.from_text("down.example", .a);
    memory.remember(memory.context, &question, .{ .failed = Error.Timeout }, 0);
    const hit = rig.store.get(&question, 0).?;
    try testing.expectEqual(cache.Outcome.failed, hit.outcome);
    try testing.expectEqual(Error.Timeout, hit.failure.?);
    try testing.expectEqual(rig.store.failure_seconds_min, hit.ttl_seconds);
    const past = @as(u64, rig.store.failure_seconds_min) * cache.constants.ns_per_s;
    try testing.expectEqual(@as(?Remembered, null), memory.recall(memory.context, &question, past));
}

test "the table writes as failed exactly the errors the cache keeps" {
    // `resolver` cannot read `cache` (docs/design.md §3), so each holds the list of resolution
    // failures (RFC 9520 §2). This file reads both, and holds them equal (§16 decision 61).
    inline for (@typeInfo(Error).error_set.?) |member| {
        const err = @field(Error, member.name);
        try testing.expectEqual(cache.resolution_failure(err), resolver.table_memory.resolution_failure(err));
    }
}

test "a failure in the cache ends a table's lookup at its first poll, and nothing is sent" {
    // "the resolver MUST NOT send any corresponding outgoing queries until after the cache
    // entries expire" (RFC 9520 §3.2).
    var rig: CacheRig = .{};
    rig.open();
    const question = try Question.from_text("down.example.", .a);
    rig.store.put_failure(&question, Error.AllServersFailed, 0);
    var slots: [1]Slot = @splat(.{});
    var keys: [resolver.limits.keys_per_slot_min]MatchKey = @splat(.{});
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }) } }};
    const config: Config = .{ .servers = &servers, .search = &.{} };
    var table = Resolver.init(&slots, &keys, &config, 0);
    table.remember_with(remembered_by(&rig.store));
    _ = try table.start(question);
    var out: [limits.query_bytes_max]u8 = @splat(0);
    const failure = table.poll(0, &out).?.action.failed;
    try testing.expectEqual(Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(?Cause, null), failure.cause);
    try testing.expectEqual(@as(u8, 0), failure.attempts_made);
}

/// The length a TCP length prefix describes (RFC 7766 §8). A caller reads two octets, calls this,
/// reads that many more, and hands them to `on_response`.
pub const message_len = wire.message_len;

test {
    _ = core;
    _ = wire;
    _ = resolver;
    _ = resolv_conf;
    _ = cache;
}

// Tests of the glue above: what a `Cache` hands the table, and what the table writes into it.
// The composition itself — a lookup that never goes out because the cache answered it — is driven
// on the deterministic twin by `zig build test-io`, which is where a cache, a table and a network
// are in one place.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const cache_slot_count: usize = 8;
const cache_key_count: usize = 16;
const remembered_ttl_seconds: u32 = 300;

/// A cache and the storage it is given, in one value a test puts on its stack.
const CacheRig = struct {
    slots: [cache_slot_count]cache.Slot = @splat(cache.Slot.empty),
    keys: [cache_key_count]cache.Key = @splat(.{}),
    store: Cache = undefined,

    fn open(self: *CacheRig) void {
        self.store = Cache.init(&self.slots, &self.keys, 0, cache.constants.ttl_seconds_max_default);
    }
};

/// One A record with the life given. The address is every octet set: these tests read the
/// outcome and the life, never the address.
fn one_address(life_seconds: u32) wire.Answers {
    return wire.fixtures.answers_address(Address.from_v4(@splat(1)), life_seconds);
}

test "an answer put through the memory comes back with what is left of its life" {
    var rig: CacheRig = .{};
    rig.open();
    const memory = remembered_by(&rig.store);
    const question = try Question.from_text("example.com.", .a);
    const answers = one_address(remembered_ttl_seconds);

    memory.remember(memory.context, &question, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = remembered_ttl_seconds,
        .canonical_name = null,
    } }, 0);

    const half = @as(u64, remembered_ttl_seconds / 2) * cache.constants.ns_per_s;
    const found = memory.recall(memory.context, &question, half).?;
    try testing.expect(found == .answered);
    try testing.expectEqual(@as(u32, remembered_ttl_seconds / 2), found.answered.ttl_seconds);
    try testing.expectEqual(@as(u8, 1), found.answered.answers.count);
}

test "each negative of RFC 2308 goes in and comes back as itself" {
    var rig: CacheRig = .{};
    rig.open();
    const memory = remembered_by(&rig.store);
    const missing = try Question.from_text("nothing.example.", .a);
    const empty = try Question.from_text("empty.example.", .a);

    memory.remember(memory.context, &missing, .{ .negative = .{
        .outcome = .name_not_found,
        .ttl_seconds = remembered_ttl_seconds,
    } }, 0);
    memory.remember(memory.context, &empty, .{ .negative = .{
        .outcome = .no_data,
        .ttl_seconds = remembered_ttl_seconds,
    } }, 0);

    const first = memory.recall(memory.context, &missing, 0).?;
    try testing.expectEqual(resolver.Negative.name_not_found, first.negative.outcome);
    const second = memory.recall(memory.context, &empty, 0).?;
    try testing.expectEqual(resolver.Negative.no_data, second.negative.outcome);
}

test "what the memory has nothing for, and what has expired, is a miss" {
    var rig: CacheRig = .{};
    rig.open();
    const memory = remembered_by(&rig.store);
    const question = try Question.from_text("example.com.", .a);
    try testing.expectEqual(@as(?Remembered, null), memory.recall(memory.context, &question, 0));

    const answers = one_address(remembered_ttl_seconds);
    memory.remember(memory.context, &question, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = remembered_ttl_seconds,
        .canonical_name = null,
    } }, 0);
    const past = (@as(u64, remembered_ttl_seconds) + 1) * cache.constants.ns_per_s;
    try testing.expectEqual(@as(?Remembered, null), memory.recall(memory.context, &question, past));
}

test "the chain's end goes through the memory and comes back as it went in" {
    var rig: CacheRig = .{};
    rig.open();
    const memory = remembered_by(&rig.store);
    const aliased = try Question.from_text("www.example.", .a);
    const plain = try Question.from_text("plain.example.", .a);
    const answers = one_address(remembered_ttl_seconds);
    const target = try Name.from_text("edge.cdn.example");

    memory.remember(memory.context, &aliased, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = remembered_ttl_seconds,
        .canonical_name = &target,
    } }, 0);
    memory.remember(memory.context, &plain, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = remembered_ttl_seconds,
        .canonical_name = null,
    } }, 0);

    try testing.expect(memory.recall(memory.context, &aliased, 0).?.answered.canonical_name.?.equal(&target));
    try testing.expectEqual(@as(?*const Name, null), memory.recall(memory.context, &plain, 0).?.answered.canonical_name);
}

/// A cap under the record's own TTL, so the life the cache gives an entry is not the record's.
const capped_ttl_seconds: u32 = 60;
/// How long the entry has been in the cache when the table asks for it.
const spent_seconds: u32 = 20;

test "a hit through the table hands each record back less the time it spent in the cache" {
    // The MX record says 300 seconds and the cache gives the entry 60. Twenty seconds on, the
    // record has lost twenty, counted from the 60 the entry was given and not from its own 300
    // (RFC 1035 §6.1.3, c4milo/cocuyo#39).
    var rig: CacheRig = .{};
    rig.store = Cache.init(&rig.slots, &rig.keys, 0, capped_ttl_seconds);
    const memory = remembered_by(&rig.store);
    const question = try Question.from_text("example.com.", .mx);
    var chain = question.name;
    var answers = wire.Answers.init(.mx);
    _ = try wire.response.collect(&wire.fixtures.answer_mx, &chain, .mx, 0, &answers);
    const stored_ttl_seconds = answers.records().at(0).ttl_seconds;
    try testing.expect(stored_ttl_seconds > capped_ttl_seconds);
    memory.remember(memory.context, &question, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = answers.ttl_seconds,
        .canonical_name = null,
    } }, 0);

    var slots: [1]Slot = @splat(.{});
    var keys: [resolver.limits.keys_per_slot_min]MatchKey = @splat(.{});
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }) } }};
    const config: Config = .{ .servers = &servers, .search = &.{} };
    var table = Resolver.init(&slots, &keys, &config, 0);
    table.remember_with(memory);
    _ = try table.start(question);
    var out: [limits.query_bytes_max]u8 = @splat(0);
    const done = table.poll(spent_seconds * cache.constants.ns_per_s, &out).?.action.done;
    try testing.expectEqual(@as(u32, capped_ttl_seconds - spent_seconds), done.ttl_seconds);
    try testing.expectEqual(stored_ttl_seconds - spent_seconds, done.records.?.at(0).ttl_seconds);
}
