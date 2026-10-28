//! The walk of an `AddressLookup` (docs/design.md §19 step 14): the sources of `Config.lookups`
//! in order, the hosts table, and the search candidates asked one at a time with a lookup per
//! family, then the join. Free functions over the lookup, split out of `address_lookup.zig` so
//! each is scored on its own.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Address = core.Address;
const Family = core.Family;
const Kind = core.Kind;
const Name = core.Name;
const Question = core.Question;
const address_order = core.address_order;
const policy = @import("lookup_policy.zig");
const lookup_module = @import("lookup.zig");
const Answer = lookup_module.Answer;
const Failure = lookup_module.Failure;
const address_lookup = @import("address_lookup.zig");
const AddressLookup = address_lookup.AddressLookup;
const Pending = address_lookup.Pending;

// The sources.

/// The first source, and the walk from there.
pub fn begin(self: *AddressLookup) error{NoSlot}!void {
    assert(self.source_index == 0);
    try next_source(self);
}

/// Tries the sources from `source_index` on, and ends the walk with nothing when they run out.
fn next_source(self: *AddressLookup) error{NoSlot}!void {
    const sources = self.resolver.config.lookups;
    assert(sources.len <= core.limits.lookup_sources_max);
    for (sources[self.source_index..]) |source| {
        self.source_index += 1;
        const found = switch (source) {
            .file => consult_file(self),
            .dns => try start_dns(self),
        };
        if (found) return;
    }
    end_negative(self);
}

/// The hosts table, when there is one and it holds the name in a family asked for; `v4_mapped`
/// widens that to both, the way it does on the wire.
fn consult_file(self: *AddressLookup) bool {
    const hosts = self.hosts orelse return false;
    var found: [core.limits.address_lookup_addresses_max]Address = undefined;
    const count = hosts.find(&self.question.name, if (mapping(self)) null else self.family, &found);
    if (count == 0) return false;
    for (found[0..count]) |address| keep(self, address);
    // A table that fills the room may hold more: said the way an answer says it.
    if (count == found.len) self.truncated = true;
    select_families(self);
    order_kept(self);
    if (self.flags.canonical_name) {
        if (hosts.canonical(&self.question.name)) |official| set_canonical(self, &official);
    }
    self.ended = .answered;
    assert(self.address_count >= 1);
    return true;
}

fn start_dns(self: *AddressLookup) error{NoSlot}!bool {
    self.candidate_index = 0;
    return try start_candidate(self);
}

// The candidates.

/// Starts the lookups of the candidate at `candidate_index`, or of the next one that can be
/// encoded; false when the candidates are exhausted.
fn start_candidate(self: *AddressLookup) error{NoSlot}!bool {
    while (self.candidate_index <= core.limits.candidates_max) : (self.candidate_index += 1) {
        switch (policy.candidate(self.resolver.config, &self.question, self.candidate_index)) {
            .name => |name| {
                try start_pair(self, &name);
                return true;
            },
            .skip => continue,
            .exhausted => return false,
        }
    }
    return false;
}

/// One absolute lookup per family asked, about the same name, so the two never drift apart on
/// the search list. A slot short of the pair frees the first again, so a failed start leaves
/// nothing behind.
fn start_pair(self: *AddressLookup, name: *const Name) error{NoSlot}!void {
    self.a = .{ .kind = .a };
    self.aaaa = .{ .kind = .aaaa };
    if (asks_a(self)) self.a = try start_one(self, name, .a);
    if (asks_aaaa(self)) {
        self.aaaa = start_one(self, name, .aaaa) catch |err| {
            if (self.a.handle) |handle| self.resolver.release(handle);
            self.a = .{ .kind = .a };
            return err;
        };
    }
    assert(self.in_flight() >= 1);
}

fn start_one(self: *AddressLookup, name: *const Name, kind: Kind) error{NoSlot}!Pending {
    const question: Question = .{ .name = name.*, .kind = kind, .absolute = true };
    const handle = try self.resolver.start(question);
    return .{ .kind = kind, .handle = handle, .ended = false };
}

fn asks_a(self: *const AddressLookup) bool {
    return self.family == null or self.family == .ipv4 or mapping(self);
}

fn asks_aaaa(self: *const AddressLookup) bool {
    return self.family == null or self.family == .ipv6;
}

/// Whether `A` addresses come back mapped: `v4_mapped` with family `.ipv6`, and not otherwise
/// (`getaddrinfo(3)`).
fn mapping(self: *const AddressLookup) bool {
    return self.family == .ipv6 and self.flags.v4_mapped;
}

/// The name of the candidate whose lookups are in flight or just ended.
fn candidate_name(self: *const AddressLookup) Name {
    return switch (policy.candidate(self.resolver.config, &self.question, self.candidate_index)) {
        .name => |name| name,
        .skip, .exhausted => unreachable,
    };
}

// What the lookups say.

pub fn take_answer(self: *AddressLookup, pending: *Pending, answer: *const Answer) void {
    pending.answered = true;
    for (answer.addresses) |address| keep(self, address);
    if (answer.truncated) self.truncated = true;
    self.ttl_seconds = if (self.a.answered and self.aaaa.answered) @min(self.ttl_seconds, answer.ttl_seconds) else answer.ttl_seconds;
    if (self.flags.canonical_name and !self.has_canonical) {
        if (answer.canonical_name) |name| set_canonical(self, name);
    }
}

pub fn take_failure(self: *AddressLookup, pending: *Pending, failure: Failure) void {
    pending.failure = failure;
    // A cancel is nobody's failure: the walk's own, or the consumer's, which ends the walk as
    // `Canceled` whatever else was seen. Once the consumer cancelled, a `Canceled` end that carries
    // a cause is the last failure, so the walk hands that cause on, as `NameLookup` does
    // (docs/design.md §19 step 14). The walk's own cancel keeps no failure, so that a negative end
    // keeps the negative TTL of the lookup that said it.
    const handed_on = self.cancelled and failure.cause != null;
    if (failure.err != core.Error.Canceled or handed_on) self.last_failure = failure;
    if (failure.err == core.Error.NoData) self.saw_no_data = true;
    // A name that does not exist (RFC 1035 §4.1.1) has no record of the other type either, so
    // the other lookup has nothing left to learn.
    if (failure.err == core.Error.NameNotFound) {
        cancel_pending(self, other_of(self, pending));
    }
}

fn other_of(self: *AddressLookup, pending: *const Pending) *Pending {
    return if (pending.kind == .a) &self.aaaa else &self.a;
}

/// Releases both slots of a pair that has ended. Together, and only then: a slot released at
/// its own lookup's end could be taken by another of the consumer's lookups before the other
/// end came in, and the next pair would find one slot for two lookups.
pub fn release_pair(self: *AddressLookup) void {
    assert(self.a.ended and self.aaaa.ended);
    for ([_]*Pending{ &self.a, &self.aaaa }) |pending| {
        const handle = pending.handle orelse continue;
        self.resolver.release(handle);
        pending.handle = null;
    }
}

/// Cancels a lookup still in flight; its `Canceled` end comes through `on_event` like any end.
pub fn cancel_pending(self: *AddressLookup, pending: *Pending) void {
    if (pending.ended) return;
    const handle = pending.handle orelse return;
    self.resolver.cancel(handle);
}

// The end of a candidate.

/// Both lookups of the candidate ended: an answer ends the walk, a name that does not exist
/// moves to the next candidate, and so does nothing but NODATA; any other failure ends the walk
/// with it, that lookup's `Failure` whole, its cause included (docs/design.md §19 step 14). The
/// order matters: the `Canceled` of a lookup the walk cancelled itself is only ever beside a
/// `NameNotFound`, which decides first.
pub fn end_candidate(self: *AddressLookup) void {
    assert(self.a.ended and self.aaaa.ended);
    if (self.cancelled) return end_failed(self, core.Error.Canceled);
    if (self.a.answered or self.aaaa.answered) return finish_answered(self);
    if (said_not_found(&self.a) or said_not_found(&self.aaaa)) return next_candidate(self);
    if (hard_failure(self)) |failure| return end_failed_with(self, failure);
    next_candidate(self);
}

fn said_not_found(pending: *const Pending) bool {
    const failure = pending.failure orelse return false;
    return failure.err == core.Error.NameNotFound;
}

/// A failure that is not negative, from either lookup: the A lookup's first.
fn hard_failure(self: *const AddressLookup) ?Failure {
    return hard_failure_of(&self.a) orelse hard_failure_of(&self.aaaa);
}

fn hard_failure_of(pending: *const Pending) ?Failure {
    const failure = pending.failure orelse return null;
    if (failure.err == core.Error.NameNotFound or failure.err == core.Error.NoData) return null;
    return failure;
}

fn next_candidate(self: *AddressLookup) void {
    self.candidate_index += 1;
    // Both slots of the last pair were released just before this, together, so the next pair
    // cannot want for one: nothing runs between that release and the start that follows it.
    const started = start_candidate(self) catch unreachable;
    if (started) return;
    next_source(self) catch unreachable;
}

fn finish_answered(self: *AddressLookup) void {
    self.partial = if (hard_failure(self)) |failure| failure.err else null;
    select_families(self);
    order_kept(self);
    if (self.flags.canonical_name and !self.has_canonical) set_canonical(self, &candidate_name(self));
    self.ended = .answered;
    assert(self.address_count >= 1);
}

/// The walk ended with nothing: `NoData` if any candidate answered NODATA, else `NameNotFound`
/// (docs/design.md §5), on the fields of the last failure seen.
fn end_negative(self: *AddressLookup) void {
    end_failed(self, if (self.saw_no_data) core.Error.NoData else core.Error.NameNotFound);
}

pub fn end_failed(self: *AddressLookup, err: core.Error) void {
    var failure: Failure = self.last_failure orelse .{ .err = err, .server_index = 0, .attempts_made = 0, .negative_ttl_seconds = 0, .cause = null };
    failure.err = err;
    end_failed_with(self, failure);
}

/// The walk ends with `failure`, a lookup's own, or one an end of the walk built.
fn end_failed_with(self: *AddressLookup, failure: Failure) void {
    // `AllServersFailed` rests on a server that failed a lookup (docs/design.md §5).
    // A failure that the memory recalled has no cause, and made no pass (§17 question 89).
    assert(failure.err != core.Error.AllServersFailed or failure.cause != null or failure.attempts_made == 0);
    self.ended = .{ .failed = failure };
}

// The join.

/// A name that was an address: answered as it is, mapped when `v4_mapped` asks for IPv6 and the
/// address is IPv4, and `NoData` when it is not of the family asked, since there is no address of
/// that family under that name.
pub fn answer_numeric(self: *AddressLookup, address: Address) void {
    const wanted = self.family orelse address.family;
    if (address.family == wanted) {
        keep(self, address);
    } else if (address.family == .ipv4 and mapping(self)) {
        keep(self, address.v4_mapped());
    } else {
        return end_failed(self, core.Error.NoData);
    }
    self.ended = .answered;
    assert(self.address_count == 1);
}

fn keep(self: *AddressLookup, address: Address) void {
    if (self.address_count == self.addresses.len) {
        self.truncated = true;
        return;
    }
    self.addresses[self.address_count] = address;
    self.address_count += 1;
    assert(self.address_count <= self.addresses.len);
}

/// The addresses kept so far, in the order they came, with `getaddrinfo(3)`'s family rule
/// applied: under `v4_mapped`, an IPv4 address comes mapped, and only when no IPv6 came or `all`
/// asks for both.
fn select_families(self: *AddressLookup) void {
    var found: [core.limits.address_lookup_addresses_max]Address = undefined;
    const count = self.address_count;
    @memcpy(found[0..count], self.addresses[0..count]);
    self.address_count = 0;
    var has_v6 = false;
    for (found[0..count]) |address| {
        if (address.family == .ipv6) has_v6 = true;
    }
    for (found[0..count]) |address| {
        if (address.family == .ipv6 or !mapping(self)) {
            keep(self, address);
        } else if (!has_v6 or self.flags.all) {
            keep(self, address.v4_mapped());
        }
    }
    assert(self.address_count <= count);
}

/// RFC 6724 §6 over what was kept, with no routes, unless `no_sort` asks for the order received.
fn order_kept(self: *AddressLookup) void {
    if (self.flags.no_sort) return;
    address_order.order(self.addresses[0..self.address_count], null);
}

fn set_canonical(self: *AddressLookup, name: *const Name) void {
    self.canonical = name.*;
    self.has_canonical = true;
}

// Tests. The rig is `address_lookup_test.zig`'s.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const lookup_test = @import("address_lookup_test.zig");
const table_memory = @import("table_memory.zig");

/// One more A record than a lookup keeps, each with an address of its own.
const records_past_bound = records: {
    const one = fixtures.record_a;
    var bytes: [(core.limits.addresses_max + 1) * one.len]u8 = undefined;
    for (0..core.limits.addresses_max + 1) |index| {
        bytes[index * one.len ..][0..one.len].* = one;
        bytes[(index + 1) * one.len - 1] = index + 1;
    }
    break :records bytes;
};

test "a lookup that kept part of its answer makes the walk's answer say so too" {
    // A round-robin name past `addresses_max` in one family: the lookup keeps the first ones and
    // says more exist, and the walk must say it as well, or its caller takes the part for the
    // whole.
    var rig: lookup_test.Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "many.example.", .ipv4, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, .{ .records = &records_past_bound, .ancount = core.limits.addresses_max + 1 });
    try rig.drive();
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, core.limits.addresses_max), info.addresses.len);
    try testing.expect(info.truncated);
}

test "a walk that ends on a hard failure carries that lookup's failure whole, its cause included" {
    // The A lookup's servers fail it, and the AAAA lookup's end comes after: NODATA, or silence.
    // The walk ends with the A lookup's failure (rule 5), not with the fields of the last lookup
    // that failed (docs/design.md §19 step 14, §5 The cause of a failure).
    const config: core.Config = .{ .servers = &fixtures.servers_one, .search = &.{}, .attempts = 1 };
    for ([_]bool{ false, true }) |silent| {
        var rig: lookup_test.Rig = .{ .table = .{ .config = config } };
        try rig.open();
        try rig.start(null, "host.example.", null, .{});
        try rig.drive();
        try rig.reply(rig.lookup.a.handle, fixtures.server_failure);
        try rig.drive();
        if (silent) rig.table.now_ns += fixtures.address_timeout_jump_ns else try rig.reply(rig.lookup.aaaa.handle, fixtures.no_data);
        try rig.drive();
        const failure = rig.lookup.outcome().?.failed;
        try testing.expectEqual(core.Error.AllServersFailed, failure.err);
        try testing.expectEqual(@as(?lookup_module.Cause, .{ .server_index = 0, .what = .{ .rcode = .server_failure } }), failure.cause);
        try testing.expectEqual(@as(u32, 0), failure.negative_ttl_seconds);
    }
}

test "a cancel hands on the cause that a lookup's own Canceled end carries" {
    // The A lookup's first server fails it, and the consumer cancels the walk while the second
    // server has the query. Both ends are `Canceled`, and the A lookup's carries the cause, as a
    // `NameLookup` hands it on (docs/design.md §5, The cause of a failure; §16 decision 51).
    const config: core.Config = .{ .servers = &fixtures.servers_two, .search = &.{}, .attempts = 1, .failover_retry_chance = 0 };
    var rig: lookup_test.Rig = .{ .table = .{ .config = config } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.server_failure);
    try rig.drive();
    try testing.expectEqual(@as(?address_lookup.AddressOutcome, null), rig.lookup.outcome());
    rig.lookup.cancel();
    try rig.drive();
    const failure = rig.lookup.outcome().?.failed;
    try testing.expectEqual(core.Error.Canceled, failure.err);
    try testing.expectEqual(@as(?lookup_module.Cause, .{ .server_index = 0, .what = .{ .rcode = .server_failure } }), failure.cause);
    // The lookup was on the second server when the cancel came.
    try testing.expectEqual(@as(u8, 1), failure.server_index);
}

test "a cancel after one family failed hands on that failure, when the other's Canceled end has no cause" {
    // The A lookup's server fails it, and the AAAA lookup still waits when the consumer cancels.
    // Its `Canceled` end carries no cause, so the walk keeps the A lookup's (§19 step 14, rule 7).
    var rig: lookup_test.Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .attempts = 1 } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.server_failure);
    try rig.drive();
    rig.lookup.cancel();
    try rig.drive();
    const failure = rig.lookup.outcome().?.failed;
    try testing.expectEqual(core.Error.Canceled, failure.err);
    try testing.expectEqual(@as(?lookup_module.Cause, .{ .server_index = 0, .what = .{ .rcode = .server_failure } }), failure.cause);
}

test "the walk's own cancel keeps no failure, so a negative end is on the lookup that said it" {
    // The AAAA lookup's first server fails it, and the A lookup's says that the name does not
    // exist. The walk cancels the AAAA lookup itself (rule 4). Its `Canceled` end carries a cause,
    // and the walk ends `NameNotFound` on the A lookup's failure all the same, whose negative TTL
    // is the one to keep (RFC 2308 §5).
    const config: core.Config = .{ .servers = &fixtures.servers_two, .search = &.{}, .attempts = 1, .failover_retry_chance = 0 };
    var rig: lookup_test.Rig = .{ .table = .{ .config = config } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.aaaa.handle, fixtures.server_failure);
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.name_error_soa);
    try rig.drive();
    const failure = rig.lookup.outcome().?.failed;
    try testing.expectEqual(core.Error.NameNotFound, failure.err);
    // The A lookup's own fields: the first server, and no cause.
    try testing.expectEqual(@as(u8, 0), failure.server_index);
    try testing.expectEqual(@as(?lookup_module.Cause, null), failure.cause);
}

test "a failure the memory recalls ends the walk with that error, and no cause" {
    // The memory keeps no cause, so a recalled `AllServersFailed` has none, and no pass was made
    // (docs/design.md §16 decision 61, §17 question 89).
    var rig: lookup_test.Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    var stub: table_memory.Stub = .{ .held = .{ .failed = core.Error.AllServersFailed } };
    rig.table.resolver.remember_with(stub.memory());
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    const failure = rig.lookup.outcome().?.failed;
    try testing.expectEqual(core.Error.AllServersFailed, failure.err);
    try testing.expectEqual(@as(?lookup_module.Cause, null), failure.cause);
    try testing.expectEqual(@as(u8, 0), failure.attempts_made);
}
