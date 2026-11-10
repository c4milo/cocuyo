//! cocuyo: a DNS resolver library. It builds query bytes and parses response bytes, and owns no
//! socket, no file descriptor, no thread, no timer and no allocator. The caller does the sending
//! and the receiving; cocuyo says what to do next.
//!
//! This file is the public surface of docs/design.md §20, "The surface, since 2026-11-09". A name
//! is here when a consumer must write it, and each name has one path. The central types are flat,
//! and each namespace below holds one job. The modules of §2 are not public, nor is any file that
//! splits a type apart, nor the test data. `zig build consumer-check` requires a consumer to fail
//! when it reaches for a path that left.
//!
//! It holds two pieces of logic, and only because this is the one file that can: `remembered_by`
//! turns a `Cache` into the `Memory` the table asks, and `resolver` cannot reach `cache` (§3).
//! What may be remembered at all — RFC 2308 §5's two negatives and the resolution failures of
//! RFC 9520 §2 — is written there once rather than in every consumer (§20, §16 decision 61).
//! `validated_by` turns a `KeyStore` into the `Trust` the table asks, as `resolver` cannot reach
//! `dnssec` (§25, step 12).

// The modules of §2. None is public: the names below are what a consumer reaches of them.
const core = @import("core");
const wire = @import("wire");
const resolver = @import("resolver");
const config_module = @import("config");
const cache_module = @import("cache");
const dnssec = @import("dnssec");

// Names and questions.
pub const Name = core.Name;
pub const Question = core.Question;
pub const Kind = core.Kind;
pub const Address = core.Address;
pub const Endpoint = core.Endpoint;
pub const Family = core.Family;

// Configuration.
pub const Config = core.Config;
pub const Server = core.Server;
pub const Tls = core.Tls;
pub const Https = core.Https;
pub const Pin = core.Pin;
// The time of day.
pub const Timestamp = core.Timestamp;

// The table.
pub const Resolver = resolver.Resolver;
pub const Slot = resolver.Slot;
pub const MatchKey = resolver.MatchKey;
pub const Handle = resolver.Handle;
pub const Event = resolver.Event;
pub const Action = resolver.Action;
pub const Answer = resolver.Answer;
pub const Failure = resolver.Failure;
pub const Cause = resolver.Cause;
pub const Reason = resolver.Reason;
pub const Error = core.Error;

// One lookup.
pub const Lookup = resolver.Lookup;
pub const Servers = resolver.Servers;

// The `getaddrinfo` shape.
pub const AddressLookup = resolver.AddressLookup;
pub const AddressFlags = resolver.AddressFlags;
pub const NameLookup = resolver.NameLookup;
pub const Hosts = core.Hosts;

// The cache.
pub const Cache = cache_module.Cache;
pub const Memory = resolver.Memory;
pub const Remembered = resolver.Remembered;

// DNSSEC. What a validating consumer names of it: its key store and its anchors (docs/design.md
// §25, step 12). Nothing else of `dnssec` is public.
pub const KeyStore = dnssec.keys.KeyStore;
pub const Anchor = dnssec.keys.Anchor;

// Records.
pub const Rcode = wire.Rcode;
pub const Kept = wire.Kept;
/// The length a TCP length prefix describes (RFC 7766 §8). A caller reads two octets, calls this,
/// reads that many more, and hands them to `on_response`.
pub const message_len = wire.message_len;

/// A `Config` from the text of `resolv.conf`.
pub const resolv_conf = struct {
    pub const parse = config_module.parse;
    pub const Storage = config_module.Storage;
};

/// A `Hosts` from the text of a hosts file.
pub const hosts = struct {
    pub const parse = config_module.hosts.parse;
    pub const Storage = config_module.hosts.Storage;
};

/// A `Pin` from its base64 text (RFC 7858 §4.2).
pub const spki_pin = struct {
    pub const from_base64 = config_module.spki_pin.from_base64;
    pub const Error = config_module.spki_pin.Error;
};

/// The anchors from text: DS and DNSKEY records in zone-file form (docs/design.md §25 step 15).
pub const trust_anchors = struct {
    pub const parse = dnssec.anchors.parse;
    pub const Error = dnssec.anchors.Error;
    /// The anchors a key store takes, and a text holds, at most (§17 question 105).
    pub const anchors_max = dnssec.limits.anchors_max;
};

/// The readers of record data, one for each type a lookup keeps as rdata.
pub const rdata = struct {
    pub const name = wire.rdata.name;
    pub const string = wire.rdata.string;
    pub const Txt = wire.rdata.Txt;
    pub const Hinfo = wire.rdata.Hinfo;
    pub const Mx = wire.rdata.Mx;
    pub const Srv = wire.rdata.Srv;
    pub const Soa = wire.rdata.Soa;
    pub const Naptr = wire.rdata.Naptr;
    pub const Sig = wire.rdata.Sig;
    pub const Rrsig = wire.rdata.Rrsig;
    pub const Ds = wire.rdata.Ds;
    pub const Dnskey = wire.rdata.Dnskey;
    pub const Nsec = wire.rdata.Nsec;
    pub const Nsec3 = wire.rdata.Nsec3;
    pub const Nsec3Param = wire.rdata.Nsec3Param;
    pub const TypeBitmaps = wire.rdata.TypeBitmaps;
    pub const Svcb = wire.rdata.Svcb;
    pub const SvcbParam = wire.rdata.SvcbParam;
    pub const Tlsa = wire.rdata.Tlsa;
    pub const Uri = wire.rdata.Uri;
    pub const Caa = wire.rdata.Caa;
    pub const Option = wire.rdata.Option;
    pub const Options = wire.rdata.Options;
};

/// The limits a consumer sizes its memory with. Each is the module's own, under the same name.
pub const limits = struct {
    /// A name in presentation form, which escapes: four bytes per wire byte at worst, `\255`.
    pub const name_text_bytes_max = core.limits.name_text_bytes_max;
    /// The largest query cocuyo builds: the header, a maximal qname, qtype and qclass, an OPT
    /// record carrying the largest COOKIE option and a Padding option, padded to a whole block, and
    /// the TCP length prefix. 12 + 255 + 4 + 55 + 4 is 330, padded to 384, and 2 more
    /// (docs/design.md §21).
    pub const query_bytes_max = core.limits.query_bytes_max;
    /// The rdata buffer of one lookup: one UDP payload of `udp_payload_bytes_default` with room for
    /// the names written out in full on the way in, each of which can grow from a two-octet
    /// pointer to `name_bytes_max`. A TCP answer that does not fit sets `truncated`
    /// (docs/design.md §19).
    pub const rdata_bytes_max = core.limits.rdata_bytes_max;
    /// The most servers a configuration may name. glibc's MAXNS is 3; 8 leaves room and still
    /// bounds every loop over the list.
    pub const servers_max = core.limits.servers_max;
    /// The pins one TLS server may carry: a primary pin and the backup RFC 7858 §4.2 asks to deploy
    /// with it, each with room to rotate. It is also chapulin's own bound (docs/design.md §21).
    pub const spki_pins_max = core.limits.spki_pins_max;
};

/// The protocol sizes and the defaults a consumer sizes its memory with. Each is the module's own,
/// under the same name.
pub const constants = struct {
    /// The DNS header: id, flags, and four section counts, two octets each (RFC 1035 §4.1.1).
    pub const header_bytes = core.constants.header_bytes;
    /// The question section's fixed part after the qname: qtype and qclass, two octets each
    /// (RFC 1035 §4.1.2).
    pub const question_fixed_bytes = core.constants.question_fixed_bytes;
    /// The UDP payload size cocuyo advertises in OPT by default. 1232 is the widely recommended
    /// value that keeps a response inside the smallest IPv6 MTU without fragmenting; recalled, not
    /// measured.
    pub const udp_payload_bytes_default = core.constants.udp_payload_bytes_default;
    /// The port a DNS server listens on (RFC 1035 §4.2.1).
    pub const port_dns_default = core.constants.port_dns_default;
    /// An IPv4 address, in octets: the "32 bit Internet address" an A record carries
    /// (RFC 1035 §3.4.1).
    pub const address_v4_bytes = core.constants.address_v4_bytes;
    /// An IPv6 address, in octets (RFC 3596 §2.2 gives the AAAA rdata this length).
    pub const address_v6_bytes = core.constants.address_v6_bytes;
    /// The entries a consumer's `KeyStore` takes by default: each one zone's keys, its DS set, or
    /// an insecure delegation (docs/design.md §25, §17 question 121). The consumer sizes the store.
    /// Chosen, not measured: a run of a few names fills far fewer.
    pub const key_store_zones_default = core.constants.key_store_zones_default;
    // The defaults of a `Config` that are numbers, for a caller that passes each field
    // (docs/design.md §20, Every field). `src/core/constants.zig` gives the reason for each.
    pub const ndots_default = core.constants.ndots_default;
    pub const attempts_default = core.constants.attempts_default;
    pub const timeout_ns_default = core.constants.timeout_ns_default;
    pub const timeout_ns_max_default = core.constants.timeout_ns_max_default;
    pub const failover_retry_chance_default = core.constants.failover_retry_chance_default;
    pub const failover_retry_delay_ns_default = core.constants.failover_retry_delay_ns_default;
    pub const cache_ttl_seconds_max_default = core.constants.cache_ttl_seconds_max_default;
    pub const cache_failure_seconds_min_default = core.constants.cache_failure_seconds_min_default;
};

/// What the table asks of a validator, and what `validated_by` fills in. Not public: a consumer
/// hands it on and never names it.
const Trust = resolver.Trust;
const Security = core.Security;

/// A `Trust` filled in from a key store: what a consumer hands `Resolver.use_trust` to
/// validate every lookup the table starts, composed ones included (docs/design.md §25, step 12).
/// `resolver` cannot reach `dnssec`, and this file can reach both.
pub fn validated_by(store: *KeyStore) Trust {
    const calls = dnssec.keys.calls;
    return .{
        .context = store.context(),
        .validate = calls.validate,
        .join = calls.join,
        .next_question = calls.next_question,
        .answered = calls.answered,
        .question_failed = calls.question_failed,
        .end = calls.end,
        .release = calls.release,
    };
}

/// A `Memory` filled in from a `Cache`: what a consumer hands `Resolver.use_memory` to put
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
            .aliases = hit.aliases,
            .security = hit.security,
        } },
        .name_not_found, .no_data => .{ .negative = .{
            .outcome = if (hit.outcome == .no_data) .no_data else .name_not_found,
            .ttl_seconds = hit.ttl_seconds,
            .security = hit.security,
            .canonical_name = hit.canonical_name,
            .aliases = hit.aliases,
        } },
        // A resolution failure: the table ends the lookup with it and sends no query
        // (RFC 9520 §3.2; docs/design.md §16 decision 61).
        .failed => .{ .failed = hit.failure.? },
    };
}

/// The chain a cache keeps of an end: its end and its links, or none when no CNAME reached it.
fn chain_of(canonical: ?*const core.Name, aliases: *const core.Aliases) ?cache_module.Chain {
    const end = canonical orelse return null;
    return .{ .end = end, .aliases = aliases };
}

fn remember_in_cache(
    context: *anyopaque,
    question: *const Question,
    end: Remembered,
    now_ns: u64,
) void {
    const store: *Cache = @ptrCast(@alignCast(context));
    switch (end) {
        .answered => |answered| store.put(question, answered.answers, chain_of(answered.canonical_name, answered.aliases), answered.security, now_ns),
        .negative => |negative| store.put_negative(question, switch (negative.outcome) {
            .name_not_found => .name_not_found,
            .no_data => .no_data,
        }, negative.ttl_seconds, chain_of(negative.canonical_name, negative.aliases), negative.security, now_ns),
        .failed => |err| {
            // The table writes the failures that the cache keeps, and no other (§16 decision 61).
            assert(cache_module.resolution_failure(err));
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
    try testing.expectEqual(cache_module.Outcome.failed, hit.outcome);
    try testing.expectEqual(Error.Timeout, hit.failure.?);
    try testing.expectEqual(rig.store.failure_seconds_min, hit.ttl_seconds);
    const past = @as(u64, rig.store.failure_seconds_min) * cache_module.constants.ns_per_s;
    try testing.expectEqual(@as(?Remembered, null), memory.recall(memory.context, &question, past));
}

test "the table writes as failed exactly the errors the cache keeps" {
    // `resolver` cannot read `cache` (docs/design.md §3), so each holds the list of resolution
    // failures (RFC 9520 §2). This file reads both, and holds them equal (§16 decision 61).
    inline for (@typeInfo(Error).error_set.?) |member| {
        const err = @field(Error, member.name);
        try testing.expectEqual(cache_module.resolution_failure(err), resolver.table_memory.resolution_failure(err));
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
    var keys: [Resolver.keys_for(1)]MatchKey = @splat(.{});
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }) } }};
    const config: Config = .{ .servers = &servers, .search = &.{} };
    var table = Resolver.init(&slots, &keys, &config, 0);
    table.use_memory(remembered_by(&rig.store));
    _ = try table.start(&question);
    var out: [limits.query_bytes_max]u8 = @splat(0);
    const failure = table.poll(0, &out).?.action.failed;
    try testing.expectEqual(Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(?Cause, null), failure.cause);
    try testing.expectEqual(@as(u8, 0), failure.attempts_made);
}

test {
    _ = core;
    _ = wire;
    _ = resolver;
    _ = config_module;
    _ = cache_module;
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
    slots: [cache_slot_count]Cache.Slot = @splat(Cache.Slot.empty),
    keys: [cache_key_count]Cache.Key = @splat(.{}),
    store: Cache = undefined,

    fn open(self: *CacheRig) void {
        self.store = Cache.init(&self.slots, &self.keys, 0, cache_module.constants.ttl_seconds_max_default);
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
        .security = .authenticated,
    } }, 0);

    const half = @as(u64, remembered_ttl_seconds / 2) * cache_module.constants.ns_per_s;
    const found = memory.recall(memory.context, &question, half).?;
    try testing.expect(found == .answered);
    try testing.expectEqual(@as(u32, remembered_ttl_seconds / 2), found.answered.ttl_seconds);
    try testing.expectEqual(@as(u8, 1), found.answered.answers.count);
    // The status goes in and comes back with the answer (docs/design.md §25, Stage A rule 5).
    try testing.expectEqual(Security.authenticated, found.answered.security);
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
        .security = .authenticated,
    } }, 0);
    memory.remember(memory.context, &empty, .{ .negative = .{
        .outcome = .no_data,
        .ttl_seconds = remembered_ttl_seconds,
        .security = .unchecked,
    } }, 0);

    const first = memory.recall(memory.context, &missing, 0).?;
    try testing.expectEqual(resolver.Negative.name_not_found, first.negative.outcome);
    try testing.expectEqual(Security.authenticated, first.negative.security);
    const second = memory.recall(memory.context, &empty, 0).?;
    try testing.expectEqual(resolver.Negative.no_data, second.negative.outcome);
    try testing.expectEqual(Security.unchecked, second.negative.security);
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
        .security = .unchecked,
    } }, 0);
    const past = (@as(u64, remembered_ttl_seconds) + 1) * cache_module.constants.ns_per_s;
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
        .security = .unchecked,
    } }, 0);
    memory.remember(memory.context, &plain, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = remembered_ttl_seconds,
        .canonical_name = null,
        .security = .unchecked,
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
    _ = try wire.response.collect(&wire.fixtures.answer_mx, &chain, .mx, 0, null, &answers);
    const stored_ttl_seconds = answers.records().at(0).ttl_seconds;
    try testing.expect(stored_ttl_seconds > capped_ttl_seconds);
    memory.remember(memory.context, &question, .{ .answered = .{
        .answers = &answers,
        .ttl_seconds = answers.ttl_seconds,
        .canonical_name = null,
        .security = .unchecked,
    } }, 0);

    var slots: [1]Slot = @splat(.{});
    var keys: [Resolver.keys_for(1)]MatchKey = @splat(.{});
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }) } }};
    const config: Config = .{ .servers = &servers, .search = &.{} };
    var table = Resolver.init(&slots, &keys, &config, 0);
    table.use_memory(memory);
    _ = try table.start(&question);
    var out: [limits.query_bytes_max]u8 = @splat(0);
    const done = table.poll(spent_seconds * cache_module.constants.ns_per_s, &out).?.action.done;
    try testing.expectEqual(@as(u32, capped_ttl_seconds - spent_seconds), done.ttl_seconds);
    try testing.expectEqual(stored_ttl_seconds - spent_seconds, done.records.?.at(0).ttl_seconds);
}
