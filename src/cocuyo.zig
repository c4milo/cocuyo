//! cocuyo: a DNS resolver library. It builds query bytes and parses response bytes, and owns no
//! socket, no file descriptor, no thread, no timer and no allocator. The caller does the sending
//! and the receiving; cocuyo says what to do next.
//!
//! This file is the public surface: each module of docs/design.md §2 is re-exported here, and the
//! names a consumer reaches for are flattened alongside them as each step of §15 lands them.
//!
//! It holds one piece of logic, and only because this is the one file that can: `remembered_by`
//! turns a `Cache` into the `Memory` the table asks, and `resolver` cannot reach `cache` (§3).
//! What may be remembered at all — RFC 2308 §5's two negatives and nothing else — is written
//! there once rather than in every consumer (§20).
pub const core = @import("core");
pub const wire = @import("wire");
pub const resolver = @import("resolver");
pub const resolv_conf = @import("config");
pub const hosts = resolv_conf.hosts;
pub const cache = @import("cache");

// The names a consumer reaches for, flattened. Everything else is behind the module it belongs to.
pub const Address = core.Address;
pub const Endpoint = core.Endpoint;
pub const Family = core.Family;
pub const Name = core.Name;
pub const Kind = core.Kind;
pub const Question = core.Question;
pub const Config = core.Config;
pub const Server = core.Server;
pub const Source = core.Source;
pub const Hosts = core.Hosts;
/// RFC 6724's destination address ordering over routes the consumer supplies (§19 step 15).
pub const Route = core.address_order.Route;
pub const order_addresses = core.address_order.order;
pub const Error = core.Error;
pub const constants = core.constants;

pub const Lookup = resolver.Lookup;
pub const Resolver = resolver.Resolver;
pub const Servers = resolver.Servers;
pub const Action = resolver.Action;
pub const Answer = resolver.Answer;
pub const Failure = resolver.Failure;
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
/// This is the one place that says what may be remembered at all: an answer, and the two
/// negatives of RFC 2308 §5 with the TTL the SOA gave. `resolver` cannot reach `cache` (§3), and
/// this file can reach both, so the rule lives here rather than in every consumer.
pub fn remembered_by(store: *Cache) Memory {
    return .{ .context = store, .recall = recall_from_cache, .remember = remember_in_cache };
}

fn recall_from_cache(context: *anyopaque, question: *const Question, now_ns: u64) ?Remembered {
    const store: *Cache = @ptrCast(@alignCast(context));
    const hit = store.get(question, now_ns) orelse return null;
    return switch (hit.outcome) {
        .answered => .{ .answered = .{ .answers = hit.answers, .ttl_seconds = hit.ttl_seconds } },
        .name_not_found => .{ .negative = .{ .outcome = .name_not_found, .ttl_seconds = hit.ttl_seconds } },
        .no_data => .{ .negative = .{ .outcome = .no_data, .ttl_seconds = hit.ttl_seconds } },
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
        .answered => |answered| store.put(question, answered.answers, now_ns),
        .negative => |negative| store.put_negative(question, switch (negative.outcome) {
            .name_not_found => .name_not_found,
            .no_data => .no_data,
        }, negative.ttl_seconds, now_ns),
    }
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
const testing = std.testing;

const cache_slot_count = 8;
const cache_key_count = 16;
const remembered_ttl_seconds = 300;

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
/// outcome and the life, never the address, and a corpus of octets belongs in a `fixtures.zig`,
/// which the module whose root is this file has nowhere to put.
fn one_address(life_seconds: u32) wire.Answers {
    var out = wire.Answers.init(.a);
    out.items.addresses[0] = Address.from_v4(@splat(1));
    out.count = 1;
    out.ttl_seconds = life_seconds;
    return out;
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
    } }, 0);
    const past = (@as(u64, remembered_ttl_seconds) + 1) * cache.constants.ns_per_s;
    try testing.expectEqual(@as(?Remembered, null), memory.recall(memory.context, &question, past));
}
