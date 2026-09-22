//! The `getaddrinfo` shape (docs/design.md §19 step 14, §16 decision 18): a numeric host, the
//! hosts table, then the `A` and `AAAA` lookups of one search candidate at a time, joined into
//! one answer. It is a composition above the table: it starts ordinary lookups through
//! `Resolver` and reads what they return, and nothing about `Lookup` or `Resolver` changes for
//! it. The walk itself is in `address_lookup_walk.zig`.
//!
//! What the consumer does: `init`; hand every `.done` and `.failed` event of `Resolver.poll` to
//! `on_event`, which says whether the handle was one of this lookup's and, when it was, has
//! released the slot; and read `outcome`, null until the walk is over. The consumer keeps the
//! association from handle to `AddressLookup` the way it keeps handles today.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Address = core.Address;
const Family = core.Family;
const Hosts = core.Hosts;
const Kind = core.Kind;
const Name = core.Name;
const Question = core.Question;
const table_module = @import("table.zig");
const Resolver = table_module.Resolver;
const Event = table_module.Event;
const Handle = table_module.Handle;
const Failure = @import("lookup.zig").Failure;
const walk = @import("address_lookup_walk.zig");

/// The flags of `getaddrinfo(3)` that c-ares implements (`ares.h`, `ARES_AI_*`), by what they
/// mean.
pub const AddressFlags = packed struct {
    /// `AI_CANONNAME`: `canonical_name` is the chain's end, the candidate's own name when there
    /// was no chain, or the hosts entry's official name. A numeric host has none.
    canonical_name: bool = false,
    /// `AI_NUMERICHOST`: the name must be an address, and no file and no query are consulted.
    numeric_host: bool = false,
    /// `AI_V4MAPPED`: with family `.ipv6`, the `A` addresses as `::ffff:a.b.c.d` when no `AAAA`
    /// came; ignored with any other family, as the manual says.
    v4_mapped: bool = false,
    /// `AI_ALL`: with `v4_mapped`, the `AAAA` addresses and the mapped `A` ones both.
    all: bool = false,
    /// `ARES_AI_NOSORT`: the addresses in the order received rather than §19 step 15's, which
    /// lands with that step; until then the order is `AAAA` then `A` either way.
    no_sort: bool = false,
};

pub const AddressInfo = struct {
    /// Into the lookup's own storage: valid for its lifetime.
    addresses: []const Address,
    canonical_name: ?*const Name,
    /// The smallest TTL over the answers used; zero for a numeric host or the hosts table.
    ttl_seconds: u32,
    truncated: bool,
    /// One family answered and the other failed with this; null when both ended as asked.
    partial: ?core.Error,
};

pub const AddressOutcome = union(enum) { answered: AddressInfo, failed: Failure };

/// One of the two lookups a candidate has. Not started is ended: a family that is not asked
/// never holds the walk up.
pub const Pending = struct {
    /// Which family's lookup this is, so the other is found by name and not by address.
    kind: Kind = .a,
    handle: ?Handle = null,
    ended: bool = true,
    answered: bool = false,
    /// What its failure said, `Canceled` included.
    err: ?core.Error = null,
};

pub const AddressLookup = struct {
    resolver: *Resolver,
    hosts: ?*const Hosts,
    /// The name as given, with whether it was absolute; the kind is unused.
    question: Question,
    family: ?Family,
    flags: AddressFlags,
    /// Where the walk stands: the next source of `Config.lookups`, and the candidate within
    /// `.dns`.
    source_index: u8,
    candidate_index: u8,
    a: Pending,
    aaaa: Pending,
    /// Whether any candidate answered NODATA, which ends an empty walk with `NoData` rather than
    /// `NameNotFound` (docs/design.md §5).
    saw_no_data: bool,
    /// Whether the consumer cancelled, so the lookups' `Canceled` ends are the outcome.
    cancelled: bool,
    /// The last failure a lookup reported, whose fields an end of the walk borrows.
    last_failure: ?Failure,
    /// How the walk ended, or null while it runs.
    ended: ?End,
    // The answer being built.
    addresses: [core.constants.address_lookup_addresses_max]Address,
    address_count: u8,
    canonical: Name,
    has_canonical: bool,
    ttl_seconds: u32,
    truncated: bool,
    partial: ?core.Error,

    pub const End = union(enum) { answered, failed: Failure };

    pub const InitError = error{NoSlot} || core.Error;

    /// Starts the walk. A name that is an address is answered here; with `numeric_host`, any
    /// other name fails here with `NameNotFound`, which is `EAI_NONAME`. `family` null asks both
    /// families, as `AF_UNSPEC` does.
    pub fn init(
        resolver: *Resolver,
        hosts: ?*const Hosts,
        name: []const u8,
        family: ?Family,
        flags: AddressFlags,
    ) InitError!AddressLookup {
        var self: AddressLookup = .{
            .resolver = resolver,
            .hosts = hosts,
            .question = undefined,
            .family = family,
            .flags = flags,
            .source_index = 0,
            .candidate_index = 0,
            .a = .{ .kind = .a },
            .aaaa = .{ .kind = .aaaa },
            .saw_no_data = false,
            .cancelled = false,
            .last_failure = null,
            .ended = null,
            .addresses = undefined,
            .address_count = 0,
            .canonical = Name.root,
            .has_canonical = false,
            .ttl_seconds = 0,
            .truncated = false,
            .partial = null,
        };
        if (Address.from_text(name)) |address| {
            self.question = Question.from_text(".", .a) catch unreachable;
            walk.answer_numeric(&self, address);
            return self;
        }
        self.question = try Question.from_text(name, .a);
        if (flags.numeric_host) {
            walk.end_failed(&self, core.Error.NameNotFound);
            return self;
        }
        try walk.begin(&self);
        assert(self.ended != null or self.in_flight() >= 1);
        return self;
    }

    /// A `.done` or `.failed` event of the resolver. True when the handle was one of this
    /// lookup's, and then its slot is released here: the consumer releases only what this
    /// refused. Any other action for one of its handles is the consumer's I/O to do, and handing
    /// it here is a programmer error.
    pub fn on_event(self: *AddressLookup, event: Event) bool {
        const pending = self.pending_of(event.handle) orelse return false;
        assert(!pending.ended);
        switch (event.action) {
            .done => |answer| walk.take_answer(self, pending, &answer),
            .failed => |failure| walk.take_failure(self, pending, failure),
            else => unreachable,
        }
        self.resolver.release(event.handle);
        pending.handle = null;
        pending.ended = true;
        if (self.a.ended and self.aaaa.ended) walk.end_candidate(self);
        assert(self.ended != null or self.in_flight() >= 1);
        return true;
    }

    /// Null until the walk is over. The slices point into this lookup.
    pub fn outcome(self: *const AddressLookup) ?AddressOutcome {
        const end = self.ended orelse return null;
        return switch (end) {
            .answered => .{ .answered = .{
                .addresses = self.addresses[0..self.address_count],
                .canonical_name = if (self.has_canonical) &self.canonical else null,
                .ttl_seconds = self.ttl_seconds,
                .truncated = self.truncated,
                .partial = self.partial,
            } },
            .failed => |failure| .{ .failed = failure },
        };
    }

    /// Cancels what is in flight. The outcome is `Canceled` once their ends have come through
    /// `on_event`, so a consumer keeps routing them here; a walk that is over is left as it is.
    pub fn cancel(self: *AddressLookup) void {
        if (self.ended != null) return;
        self.cancelled = true;
        walk.cancel_pending(self, &self.a);
        walk.cancel_pending(self, &self.aaaa);
        assert(self.in_flight() >= 1);
    }

    /// How many of its lookups hold a slot.
    pub fn in_flight(self: *const AddressLookup) usize {
        var count: usize = 0;
        if (!self.a.ended) count += 1;
        if (!self.aaaa.ended) count += 1;
        return count;
    }

    fn pending_of(self: *AddressLookup, handle: Handle) ?*Pending {
        if (self.a.handle) |mine| {
            if (handle_equal(mine, handle)) return &self.a;
        }
        if (self.aaaa.handle) |mine| {
            if (handle_equal(mine, handle)) return &self.aaaa;
        }
        return null;
    }
};

fn handle_equal(a: Handle, b: Handle) bool {
    return @as(u32, @bitCast(a)) == @as(u32, @bitCast(b));
}

test {
    _ = walk;
}
