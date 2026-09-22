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
    assert(sources.len <= core.constants.lookup_sources_max);
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
    var found: [core.constants.address_lookup_addresses_max]Address = undefined;
    const count = hosts.find(&self.question.name, if (mapping(self)) null else self.family, &found);
    if (count == 0) return false;
    for (found[0..count]) |address| keep(self, address);
    // A table that fills the room may hold more: said the way an answer says it.
    if (count == found.len) self.truncated = true;
    select_families(self);
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
    while (self.candidate_index <= core.constants.candidates_max) : (self.candidate_index += 1) {
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
    pending.err = failure.err;
    // A cancel is nobody's failure: the walk's own, or the consumer's, which ends the walk as
    // `Canceled` whatever else was seen.
    if (failure.err != core.Error.Canceled) self.last_failure = failure;
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

/// Cancels a lookup still in flight; its `Canceled` end comes through `on_event` like any end.
pub fn cancel_pending(self: *AddressLookup, pending: *Pending) void {
    if (pending.ended) return;
    const handle = pending.handle orelse return;
    self.resolver.cancel(handle);
}

// The end of a candidate.

/// Both lookups of the candidate ended: an answer ends the walk, a name that does not exist
/// moves to the next candidate, and so does nothing but NODATA; any other failure ends the walk
/// with it. The order matters: the `Canceled` of a lookup the walk cancelled itself is only ever
/// beside a `NameNotFound`, which decides first.
pub fn end_candidate(self: *AddressLookup) void {
    assert(self.a.ended and self.aaaa.ended);
    if (self.cancelled) return end_failed(self, core.Error.Canceled);
    if (self.a.answered or self.aaaa.answered) return finish_answered(self);
    if (said_not_found(&self.a) or said_not_found(&self.aaaa)) return next_candidate(self);
    if (hard_error(self)) |err| return end_failed(self, err);
    next_candidate(self);
}

fn said_not_found(pending: *const Pending) bool {
    const err = pending.err orelse return false;
    return err == core.Error.NameNotFound;
}

/// A failure that is not negative, from either lookup.
fn hard_error(self: *const AddressLookup) ?core.Error {
    return hard_error_of(&self.a) orelse hard_error_of(&self.aaaa);
}

fn hard_error_of(pending: *const Pending) ?core.Error {
    const err = pending.err orelse return null;
    if (err == core.Error.NameNotFound or err == core.Error.NoData) return null;
    return err;
}

fn next_candidate(self: *AddressLookup) void {
    self.candidate_index += 1;
    // Both slots of the last pair were released before this, so the next pair cannot want for
    // one: nothing runs between a release and the start that follows it.
    const started = start_candidate(self) catch unreachable;
    if (started) return;
    next_source(self) catch unreachable;
}

fn finish_answered(self: *AddressLookup) void {
    self.partial = hard_error(self);
    select_families(self);
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
    var failure: Failure = self.last_failure orelse .{ .err = err, .server_index = 0, .attempts_made = 0, .negative_ttl_seconds = 0 };
    failure.err = err;
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

/// The addresses kept so far, in the order `getaddrinfo(3)` gives them: IPv6 first, then IPv4,
/// which under `v4_mapped` come mapped, and only when no IPv6 came or `all` asks for both.
fn select_families(self: *AddressLookup) void {
    var found: [core.constants.address_lookup_addresses_max]Address = undefined;
    const count = self.address_count;
    @memcpy(found[0..count], self.addresses[0..count]);
    self.address_count = 0;
    for (found[0..count]) |address| {
        if (address.family == .ipv6) keep(self, address);
    }
    const has_v6 = self.address_count > 0;
    for (found[0..count]) |address| {
        if (address.family != .ipv4) continue;
        if (!mapping(self)) {
            keep(self, address);
        } else if (!has_v6 or self.flags.all) {
            keep(self, address.v4_mapped());
        }
    }
    assert(self.address_count <= count);
}

fn set_canonical(self: *AddressLookup, name: *const Name) void {
    self.canonical = name.*;
    self.has_canonical = true;
}
