//! The reverse of `AddressLookup`: an address in, the name that answers for it out. This is
//! `ares_gethostbyaddr` and the name half of `ares_getnameinfo`; the service half is out, because
//! `/etc/services` belongs to the consumer (docs/design.md §19 step 14, §17 question 12).
//!
//! It is the same composition as `AddressLookup`, and much smaller: the hosts table and DNS in
//! the order `Config.lookups` gives, and one `PTR` question, whose name is built from the address
//! and is absolute, so there is no search list to walk.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Address = core.Address;
const Hosts = core.Hosts;
const Name = core.Name;
const Question = core.Question;
const table_module = @import("table.zig");
const Resolver = table_module.Resolver;
const Event = table_module.Event;
const Handle = table_module.Handle;
const Failure = @import("lookup.zig").Failure;

pub const NameInfo = struct {
    /// Into this lookup's own storage: valid for its lifetime.
    name: *const Name,
    /// The TTL of the `PTR` record, or zero when the hosts table answered.
    ttl_seconds: u32,
    /// Whether the hosts table answered, which is what `Config.lookups` decides the order of.
    from_hosts: bool,
};

pub const NameOutcome = union(enum) { answered: NameInfo, failed: Failure };

pub const NameLookup = struct {
    resolver: *Resolver,
    hosts: ?*const Hosts,
    address: Address,
    /// The `PTR` lookup, while one is in flight.
    handle: ?Handle,
    /// Where the walk stands in `Config.lookups`.
    source_index: u8,
    name: Name,
    ttl_seconds: u32,
    from_hosts: bool,
    /// How the walk ended, or null while it runs. The name it answers with is a field of this
    /// lookup, so the outcome is built when it is asked for rather than kept: a pointer into a
    /// value that is still being returned would name the copy nobody keeps.
    ended: ?End,
    /// Whether the caller cancelled, so the lookup's end, whatever it was, is `Canceled`.
    cancelled: bool,
    /// Whether the lookup said `NoData`, which ends a walk out of sources as `NoData` rather than
    /// `NameNotFound` (docs/design.md §5).
    saw_no_data: bool,

    pub const End = union(enum) { answered, failed: Failure };
    pub const InitError = error{NoSlot} || core.Error;

    /// Starts the walk. The hosts table answers here when it is first in the order and holds the
    /// address; otherwise a `PTR` lookup goes out and its result comes through `on_event`.
    pub fn init(resolver: *Resolver, hosts: ?*const Hosts, address: *const Address) InitError!NameLookup {
        var self: NameLookup = .{
            .resolver = resolver,
            .hosts = hosts,
            .address = address.*,
            .handle = null,
            .source_index = 0,
            .name = Name.root,
            .ttl_seconds = 0,
            .from_hosts = false,
            .ended = null,
            .cancelled = false,
            .saw_no_data = false,
        };
        try next_source(&self);
        assert(self.ended != null or self.handle != null);
        return self;
    }

    /// A `.done` or `.failed` event of the resolver. True when the handle was this lookup's, and
    /// then its slot is released here.
    pub fn on_event(self: *NameLookup, event: Event) bool {
        const mine = self.handle orelse return false;
        if (mine != event.handle) return false;
        switch (event.action) {
            .done => |answer| if (self.cancelled) end_failed(self, core.Error.Canceled) else take_answer(self, &answer),
            .failed => |failure| take_failure(self, failure),
            else => unreachable,
        }
        self.resolver.release(event.handle);
        self.handle = null;
        return true;
    }

    /// Null until the walk is over. The name points into this lookup.
    pub fn outcome(self: *const NameLookup) ?NameOutcome {
        const end = self.ended orelse return null;
        return switch (end) {
            .answered => .{ .answered = .{
                .name = &self.name,
                .ttl_seconds = self.ttl_seconds,
                .from_hosts = self.from_hosts,
            } },
            .failed => |failure| .{ .failed = failure },
        };
    }

    /// Cancels the lookup in flight. The outcome is `Canceled` once its end comes through
    /// `on_event`, so a caller keeps routing events here.
    pub fn cancel(self: *NameLookup) void {
        if (self.ended != null) return;
        self.cancelled = true;
        const handle = self.handle orelse return;
        self.resolver.cancel(handle);
    }
};

/// Tries the sources from `source_index` on, and ends the walk with nothing when they run out.
fn next_source(self: *NameLookup) NameLookup.InitError!void {
    const sources = self.resolver.config.lookups;
    assert(sources.len <= core.constants.lookup_sources_max);
    for (sources[self.source_index..]) |source| {
        self.source_index += 1;
        const found = switch (source) {
            .file => consult_file(self),
            .dns => try start_query(self),
        };
        if (found) return;
    }
    end_failed(self, if (self.saw_no_data) core.Error.NoData else core.Error.NameNotFound);
}

/// The hosts table, when there is one and it names the address.
fn consult_file(self: *NameLookup) bool {
    const hosts = self.hosts orelse return false;
    const name = hosts.reverse(&self.address) orelse return false;
    self.name = name;
    self.from_hosts = true;
    self.ttl_seconds = 0;
    self.ended = .answered;
    return true;
}

/// One `PTR` question, whose name the address builds and which is absolute.
fn start_query(self: *NameLookup) NameLookup.InitError!bool {
    const question = try Question.from_address(&self.address);
    self.handle = try self.resolver.start(question);
    return true;
}

fn take_answer(self: *NameLookup, answer: *const @import("lookup.zig").Answer) void {
    // A reverse lookup keeps one name (`ptr_names_max`, docs/design.md §17.2), and a lookup that
    // is done has one: a response with no record of the type asked for is NODATA, which the
    // state machine fails rather than finishes (§5).
    assert(answer.names.len >= 1);
    self.name = answer.names[0];
    self.ttl_seconds = answer.ttl_seconds;
    self.from_hosts = false;
    self.ended = .answered;
}

fn take_failure(self: *NameLookup, failure: Failure) void {
    // A cancel is the caller's word and ends the walk, even when the lookup failed on its own
    // before the cancel reached it.
    if (failure.err == core.Error.Canceled) return end_failed_with(self, failure);
    if (self.cancelled) return end_failed(self, core.Error.Canceled);
    // A name that does not exist, or has no `PTR`, lets the next source try; any other failure
    // says nothing about the name and ends the walk with it (docs/design.md §19 step 14).
    const negative = failure.err == core.Error.NameNotFound or failure.err == core.Error.NoData;
    if (!negative) return end_failed_with(self, failure);
    if (failure.err == core.Error.NoData) self.saw_no_data = true;
    next_source(self) catch return end_failed_with(self, failure);
    if (self.ended == null and self.handle == null) end_failed_with(self, failure);
}

fn end_failed(self: *NameLookup, err: core.Error) void {
    end_failed_with(self, .{ .err = err, .server_index = 0, .attempts_made = 0, .negative_ttl_seconds = 0 });
}

fn end_failed_with(self: *NameLookup, failure: Failure) void {
    self.ended = .{ .failed = failure };
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");
const Table = fixtures.Table;
const Verdict = @import("lookup.zig").Verdict;
const Source = core.Source;

/// A hosts table built by hand, the parser being in `config`.
const HostsFixture = struct {
    storage: core.hosts.Storage = .{},
    entry_count: usize = 0,
    names_used: usize = 0,

    fn add(self: *HostsFixture, address: Address, text: []const u8) !void {
        const name = try Name.from_text(text);
        @memcpy(self.storage.names[self.names_used..][0..name.len], name.wire());
        var entry: core.hosts.Entry = .{ .address = address, .names = undefined, .name_count = 1 };
        entry.names[0] = .{ .offset = @intCast(self.names_used), .len = name.len };
        self.names_used += name.len;
        self.storage.entries[self.entry_count] = entry;
        self.entry_count += 1;
    }

    fn table(self: *const HostsFixture) Hosts {
        return .{
            .entries = self.storage.entries[0..self.entry_count],
            .names = self.storage.names[0..self.names_used],
        };
    }
};

/// Drives the table until nothing more is to be done, handing every end to the lookup.
fn drive(rig: *Table, lookup: *NameLookup) !void {
    var polls: usize = 0;
    while (polls < fixtures.address_polls_max) : (polls += 1) {
        const event = rig.poll() orelse return;
        switch (event.action) {
            .send_udp => rig.resolver.on_sent(event.handle, rig.now_ns),
            .done, .failed => try testing.expect(lookup.on_event(event)),
            else => return error.UnexpectedAction,
        }
    }
    return error.TooManyPolls;
}

test "the hosts table answers a reverse lookup first, and costs no slot" {
    var hosts_fixture: HostsFixture = .{};
    try hosts_fixture.add(Address.from_v4(.{ 192, 0, 2, 10 }), "db.example");
    const hosts = hosts_fixture.table();
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 10 });
    var lookup = try NameLookup.init(&rig.resolver, &hosts, &address);
    const info = lookup.outcome().?.answered;
    try testing.expect(info.name.equal(&try Name.from_text("db.example")));
    try testing.expect(info.from_hosts);
    try testing.expectEqual(@as(u32, 0), info.ttl_seconds);
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}

test "an address the table does not name is asked about as a PTR question" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    var lookup = try NameLookup.init(&rig.resolver, null, &address);
    const asked = rig.resolver.lookup_of(lookup.handle.?);
    try testing.expectEqual(core.Kind.ptr, asked.question.kind);
    try testing.expect(asked.question.name.equal(&try Name.from_text("1.2.0.192.in-addr.arpa.")));

    const event = rig.poll().?;
    rig.resolver.on_sent(event.handle, rig.now_ns);
    const message = rig.build(rig.resolver.lookup_of(lookup.handle.?), fixtures.answer_ptr);
    rig.now_ns += 1;
    try testing.expectEqual(Verdict.accepted, rig.resolver.on_datagram(message, asked.server(), rig.now_ns));
    try drive(&rig, &lookup);
    const info = lookup.outcome().?.answered;
    try testing.expect(info.name.equal(&try Name.from_text("host.example.net")));
    try testing.expect(!info.from_hosts);
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}

test "with DNS first, the table answers only when the query found nothing" {
    var hosts_fixture: HostsFixture = .{};
    try hosts_fixture.add(Address.from_v4(.{ 192, 0, 2, 1 }), "db.example");
    const hosts = hosts_fixture.table();
    const order = [_]Source{ .dns, .file };
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .lookups = &order } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    var lookup = try NameLookup.init(&rig.resolver, &hosts, &address);
    try testing.expect(lookup.handle != null);
    const event = rig.poll().?;
    rig.resolver.on_sent(event.handle, rig.now_ns);
    const message = rig.build(rig.resolver.lookup_of(lookup.handle.?), fixtures.name_error);
    rig.now_ns += 1;
    _ = rig.resolver.on_datagram(message, rig.resolver.lookup_of(lookup.handle.?).server(), rig.now_ns);
    try drive(&rig, &lookup);
    const info = lookup.outcome().?.answered;
    try testing.expect(info.from_hosts);
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}

test "an address nothing answers for ends as NameNotFound, and a cancel ends as Canceled" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    var lookup = try NameLookup.init(&rig.resolver, null, &address);
    const event = rig.poll().?;
    rig.resolver.on_sent(event.handle, rig.now_ns);
    const message = rig.build(rig.resolver.lookup_of(lookup.handle.?), fixtures.name_error);
    rig.now_ns += 1;
    _ = rig.resolver.on_datagram(message, rig.resolver.lookup_of(lookup.handle.?).server(), rig.now_ns);
    try drive(&rig, &lookup);
    try testing.expectEqual(core.Error.NameNotFound, lookup.outcome().?.failed.err);

    var second = try NameLookup.init(&rig.resolver, null, &address);
    second.cancel();
    try drive(&rig, &second);
    try testing.expectEqual(core.Error.Canceled, second.outcome().?.failed.err);
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}

test "a server that fails ends the reverse walk with its failure, and NODATA ends it NoData" {
    // Only a name that does not exist, or has no PTR, lets the next source try; a failure that
    // says nothing about the name is the walk's end (docs/design.md §19 step 14).
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .attempts = 1 } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    const cases = [_]struct { reply: fixtures.Reply, err: core.Error }{
        .{ .reply = fixtures.server_failure, .err = core.Error.AllServersFailed },
        .{ .reply = fixtures.no_data, .err = core.Error.NoData },
    };
    for (cases) |case| {
        var lookup = try NameLookup.init(&rig.resolver, null, &address);
        const event = rig.poll().?;
        rig.resolver.on_sent(event.handle, rig.now_ns);
        const asked = rig.resolver.lookup_of(lookup.handle.?);
        const message = rig.build(asked, case.reply);
        rig.now_ns += 1;
        _ = rig.resolver.on_datagram(message, asked.server(), rig.now_ns);
        try drive(&rig, &lookup);
        try testing.expectEqual(case.err, lookup.outcome().?.failed.err);
    }
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}

test "a cancel after the answer came, before it was routed, still ends as Canceled" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    var lookup = try NameLookup.init(&rig.resolver, null, &address);
    const event = rig.poll().?;
    rig.resolver.on_sent(event.handle, rig.now_ns);
    const message = rig.build(rig.resolver.lookup_of(lookup.handle.?), fixtures.answer_ptr);
    rig.now_ns += 1;
    _ = rig.resolver.on_datagram(message, rig.resolver.lookup_of(lookup.handle.?).server(), rig.now_ns);
    lookup.cancel();
    try drive(&rig, &lookup);
    try testing.expectEqual(core.Error.Canceled, lookup.outcome().?.failed.err);
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}

test "an end that is another lookup's is refused and left for its owner" {
    var rig: Table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } };
    rig.open();
    const address = Address.from_v4(.{ 192, 0, 2, 1 });
    var first = try NameLookup.init(&rig.resolver, null, &address);
    var second = try NameLookup.init(&rig.resolver, null, &address);
    second.cancel();
    var polls: usize = 0;
    while (second.outcome() == null and polls < fixtures.address_polls_max) : (polls += 1) {
        const event = rig.poll() orelse break;
        switch (event.action) {
            .send_udp => rig.resolver.on_sent(event.handle, rig.now_ns),
            .done, .failed => {
                try testing.expect(!first.on_event(event));
                try testing.expect(second.on_event(event));
            },
            else => return error.UnexpectedAction,
        }
    }
    try testing.expectEqual(core.Error.Canceled, second.outcome().?.failed.err);
    try testing.expectEqual(@as(?NameOutcome, null), first.outcome());
    first.cancel();
    try drive(&rig, &first);
    try testing.expectEqual(@as(usize, 0), rig.resolver.in_flight());
}
