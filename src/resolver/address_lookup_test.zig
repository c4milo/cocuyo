//! The `getaddrinfo` shape on the fake server (docs/design.md §19 step 14's gate): the lockstep
//! walk, the name that does not exist ending a candidate early, `NoData` against `NameNotFound`,
//! `v4_mapped` and `all`, the canonical name, the sources' order, a numeric host, and the two
//! slots a walk holds at most.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Address = core.Address;
const Family = core.Family;
const Name = core.Name;
const Source = core.Source;
const fixtures = @import("fixtures.zig");
const address_lookup = @import("address_lookup.zig");
const AddressLookup = address_lookup.AddressLookup;
const AddressFlags = address_lookup.AddressFlags;
const Handle = @import("table.zig").Handle;
const Verdict = @import("lookup.zig").Verdict;

/// A table on the fake server with one address lookup on it.
const Rig = struct {
    table: fixtures.Table,
    lookup: AddressLookup = undefined,
    search: [fixtures.address_search_entries]Name = undefined,

    fn open(rig: *Rig) !void {
        rig.search[0] = try Name.from_text("a.example");
        rig.search[1] = try Name.from_text("b.example");
        rig.table.config.search = &rig.search;
        rig.table.open();
    }

    fn start(rig: *Rig, hosts: ?*const core.Hosts, name: []const u8, family: ?Family, flags: AddressFlags) !void {
        rig.lookup = try AddressLookup.init(&rig.table.resolver, hosts, name, family, flags);
    }

    /// Polls until every lookup waits: a send is acknowledged, an end is handed to the address
    /// lookup, and the walk never holds more than its two slots.
    fn drive(rig: *Rig) !void {
        var polls: usize = 0;
        while (polls < fixtures.address_polls_max) : (polls += 1) {
            const event = rig.table.poll() orelse return;
            switch (event.action) {
                .send_udp => rig.table.resolver.on_sent(event.handle, rig.table.now_ns),
                .done, .failed => try testing.expect(rig.lookup.on_event(event)),
                else => return error.UnexpectedAction,
            }
            try testing.expect(rig.table.resolver.in_flight() <= fixtures.address_slots_per_walk);
        }
        return error.TooManyPolls;
    }

    /// Answers one of the walk's lookups the way its server would.
    fn reply(rig: *Rig, handle: ?Handle, message: fixtures.Reply) !void {
        const lookup = rig.table.resolver.lookup_of(handle orelse return error.NotInFlight);
        const bytes = rig.table.build(lookup, message);
        rig.table.now_ns += 1;
        try testing.expectEqual(Verdict.accepted, rig.table.resolver.on_datagram(bytes, lookup.server(), rig.table.now_ns));
    }

    /// The name one of the walk's lookups is asking about.
    fn asking(rig: *Rig, handle: ?Handle, text: []const u8) !void {
        const lookup = rig.table.resolver.lookup_of(handle orelse return error.NotInFlight);
        try testing.expect(lookup.question.absolute);
        try testing.expect(lookup.question.name.equal(&try Name.from_text(text)));
    }
};

fn expect_address(info: address_lookup.AddressInfo, index: usize, text: []const u8) !void {
    try testing.expect(index < info.addresses.len);
    try testing.expect(info.addresses[index].equal(&Address.from_text(text).?));
}

test "the two families ask the same candidate, and move together when both say no" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host", null, .{});
    try rig.drive();
    try rig.asking(rig.lookup.a.handle, "host.a.example");
    try rig.asking(rig.lookup.aaaa.handle, "host.a.example");
    try rig.reply(rig.lookup.a.handle, fixtures.no_data);
    try rig.reply(rig.lookup.aaaa.handle, fixtures.no_data);
    try rig.drive();
    try rig.asking(rig.lookup.a.handle, "host.b.example");
    try rig.asking(rig.lookup.aaaa.handle, "host.b.example");
    try rig.reply(rig.lookup.aaaa.handle, fixtures.no_data);
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.drive();
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 1), info.addresses.len);
    try expect_address(info, 0, "192.0.2.1");
    try testing.expectEqual(@as(?*const Name, null), info.canonical_name);
    try testing.expectEqual(@as(?core.Error, null), info.partial);
    try testing.expectEqual(@as(usize, 0), rig.table.resolver.in_flight());
}

test "a name that does not exist ends the candidate at once: the other family is cancelled" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.name_error);
    // One poll hands the A's end over; the AAAA is settled by it, before anything else runs.
    const sibling = rig.lookup.aaaa.handle.?;
    const event = rig.table.poll().?;
    try testing.expect(event.action == .failed);
    try testing.expect(rig.lookup.on_event(event));
    try testing.expect(rig.table.resolver.lookup_of(sibling).is_settled());
    try rig.drive();
    try rig.asking(rig.lookup.a.handle, "host.b.example");
    try rig.asking(rig.lookup.aaaa.handle, "host.b.example");
    try testing.expectEqual(@as(?address_lookup.AddressOutcome, null), rig.lookup.outcome());
    try rig.reply(rig.lookup.aaaa.handle, fixtures.name_error);
    try rig.drive();
    // The bare name is the last candidate, since `host` has fewer dots than `ndots`.
    try rig.asking(rig.lookup.a.handle, "host");
    try rig.reply(rig.lookup.a.handle, fixtures.name_error);
    try rig.drive();
    try testing.expectEqual(core.Error.NameNotFound, rig.lookup.outcome().?.failed.err);
    try testing.expectEqual(@as(usize, 0), rig.table.resolver.in_flight());
}

test "a walk that finds nothing is NameNotFound, or NoData when any candidate had the name" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.no_data);
    try rig.reply(rig.lookup.aaaa.handle, fixtures.no_data);
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.name_error);
    try rig.drive();
    try rig.asking(rig.lookup.aaaa.handle, "host");
    try rig.reply(rig.lookup.aaaa.handle, fixtures.name_error);
    try rig.drive();
    try testing.expectEqual(core.Error.NoData, rig.lookup.outcome().?.failed.err);
}

test "a hard failure on one family ends the walk with it when the other has no answer" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .attempts = 1 } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.aaaa.handle, fixtures.no_data);
    rig.table.now_ns += fixtures.address_timeout_jump_ns;
    try rig.drive();
    try testing.expectEqual(core.Error.Timeout, rig.lookup.outcome().?.failed.err);
}

test "one family answered and the other timed out is an answer that says so" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .attempts = 1 } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    rig.table.now_ns += fixtures.address_timeout_jump_ns;
    try rig.drive();
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 1), info.addresses.len);
    try testing.expectEqual(core.Error.Timeout, info.partial.?);
}

test "no_sort keeps the order received, whichever family came first" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{ .no_sort = true });
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.reply(rig.lookup.aaaa.handle, fixtures.answer_aaaa);
    try rig.drive();
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 2), info.addresses.len);
    try expect_address(info, 0, "192.0.2.1");
    try expect_address(info, 1, "2001:db8::1");
}

test "both families answered come back IPv6 first, with the smaller TTL" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{ .v4_mapped = true });
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.reply(rig.lookup.aaaa.handle, fixtures.answer_aaaa);
    try rig.drive();
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 2), info.addresses.len);
    try expect_address(info, 0, "2001:db8::1");
    // `v4_mapped` without family `.ipv6` is ignored: the IPv4 address comes as it is.
    try expect_address(info, 1, "192.0.2.1");
    try testing.expectEqual(@as(u32, 60), info.ttl_seconds);
}

test "v4_mapped with family ipv6 maps the A addresses when no AAAA came, and with all, always" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host.example.", .ipv6, .{ .v4_mapped = true });
    try rig.drive();
    try rig.reply(rig.lookup.aaaa.handle, fixtures.no_data);
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.drive();
    const mapped = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 1), mapped.addresses.len);
    try expect_address(mapped, 0, "::ffff:192.0.2.1");

    try rig.start(null, "other.example.", .ipv6, .{ .v4_mapped = true, .all = true });
    try rig.drive();
    try rig.reply(rig.lookup.aaaa.handle, fixtures.answer_aaaa);
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.drive();
    const both = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 2), both.addresses.len);
    try expect_address(both, 0, "2001:db8::1");
    try expect_address(both, 1, "::ffff:192.0.2.1");

    // Without `all`, an AAAA answer leaves the A one out.
    try rig.start(null, "third.example.", .ipv6, .{ .v4_mapped = true });
    try rig.drive();
    try rig.reply(rig.lookup.aaaa.handle, fixtures.answer_aaaa);
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.drive();
    const v6_only = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 1), v6_only.addresses.len);
    try expect_address(v6_only, 0, "2001:db8::1");
}

test "family ipv6 without v4_mapped asks AAAA alone, and an A answer is not sought" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host.example.", .ipv6, .{});
    try rig.drive();
    try testing.expectEqual(@as(?Handle, null), rig.lookup.a.handle);
    try testing.expectEqual(@as(usize, 1), rig.table.resolver.in_flight());
    try rig.reply(rig.lookup.aaaa.handle, fixtures.answer_aaaa);
    try rig.drive();
    try expect_address(rig.lookup.outcome().?.answered, 0, "2001:db8::1");
}

test "the canonical name is the chain's end, or the candidate's own name without a chain" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host", .ipv4, .{ .canonical_name = true });
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.cname_then_a);
    try rig.drive();
    const chained = rig.lookup.outcome().?.answered;
    try testing.expect(chained.canonical_name.?.equal(&try Name.from_text("host.example.net")));

    try rig.start(null, "host", .ipv4, .{ .canonical_name = true });
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.drive();
    const plain = rig.lookup.outcome().?.answered;
    try testing.expect(plain.canonical_name.?.equal(&try Name.from_text("host.a.example")));
}

test "the hosts table answers first in the default order, with its official name, and no slot" {
    var fixture: HostsFixture = .{};
    try fixture.add(Address.from_v4(.{ 192, 0, 2, 10 }), &.{ "db.example", "db" });
    const hosts = fixture.table();
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(&hosts, "db", null, .{ .canonical_name = true });
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 1), info.addresses.len);
    try expect_address(info, 0, "192.0.2.10");
    try testing.expect(info.canonical_name.?.equal(&try Name.from_text("db.example")));
    try testing.expectEqual(@as(u32, 0), info.ttl_seconds);
    try testing.expectEqual(@as(usize, 0), rig.table.resolver.in_flight());
}

test "with DNS first in the order, the table answers only when the walk found nothing" {
    var fixture: HostsFixture = .{};
    try fixture.add(Address.from_v4(.{ 192, 0, 2, 10 }), &.{"db"});
    const hosts = fixture.table();
    const order = [_]Source{ .dns, .file };
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{}, .lookups = &order } } };
    try rig.open();
    try rig.start(&hosts, "db.", null, .{});
    try rig.drive();
    try testing.expectEqual(@as(?address_lookup.AddressOutcome, null), rig.lookup.outcome());
    try rig.reply(rig.lookup.a.handle, fixtures.name_error);
    try rig.drive();
    try expect_address(rig.lookup.outcome().?.answered, 0, "192.0.2.10");
}

test "a family the table lacks falls through to DNS, unless v4_mapped widens the ask" {
    var fixture: HostsFixture = .{};
    try fixture.add(Address.from_v4(.{ 192, 0, 2, 10 }), &.{"db"});
    const hosts = fixture.table();
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(&hosts, "db.", .ipv6, .{});
    try rig.drive();
    try testing.expectEqual(@as(usize, 1), rig.table.resolver.in_flight());
    rig.lookup.cancel();
    try rig.drive();
    try testing.expectEqual(core.Error.Canceled, rig.lookup.outcome().?.failed.err);

    try rig.start(&hosts, "db.", .ipv6, .{ .v4_mapped = true });
    try expect_address(rig.lookup.outcome().?.answered, 0, "::ffff:192.0.2.10");
}

test "a cancel after one family answered is Canceled all the same, not half an answer" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try rig.reply(rig.lookup.a.handle, fixtures.answer_a);
    try rig.drive();
    try testing.expectEqual(@as(?address_lookup.AddressOutcome, null), rig.lookup.outcome());
    rig.lookup.cancel();
    try rig.drive();
    try testing.expectEqual(core.Error.Canceled, rig.lookup.outcome().?.failed.err);
    try testing.expectEqual(@as(usize, 0), rig.table.resolver.in_flight());
}

test "a numeric host is answered at once, mapped or refused by family, and numeric_host insists" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "192.0.2.1", null, .{});
    try expect_address(rig.lookup.outcome().?.answered, 0, "192.0.2.1");
    try testing.expectEqual(@as(usize, 0), rig.table.resolver.in_flight());
    try rig.start(null, "192.0.2.1", .ipv6, .{ .v4_mapped = true });
    try expect_address(rig.lookup.outcome().?.answered, 0, "::ffff:192.0.2.1");
    try rig.start(null, "192.0.2.1", .ipv6, .{});
    try testing.expectEqual(core.Error.NoData, rig.lookup.outcome().?.failed.err);
    try rig.start(null, "2001:db8::1", null, .{ .numeric_host = true });
    try expect_address(rig.lookup.outcome().?.answered, 0, "2001:db8::1");
    try rig.start(null, "host.example.", null, .{ .numeric_host = true });
    try testing.expectEqual(core.Error.NameNotFound, rig.lookup.outcome().?.failed.err);
}

test "a table that fills the room is an answer marked truncated, since more may exist" {
    var fixture: HostsFixture = .{};
    var octet: u8 = 0;
    while (octet < core.constants.address_lookup_addresses_max + 1) : (octet += 1) {
        try fixture.add(Address.from_v4(.{ 10, 0, 0, octet }), &.{"many"});
    }
    const hosts = fixture.table();
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(&hosts, "many", null, .{});
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, core.constants.address_lookup_addresses_max), info.addresses.len);
    try testing.expect(info.truncated);
}

test "the size of an address lookup is pinned" {
    // docs/design.md §9: the number there is this one.
    try testing.expectEqual(@as(usize, 1152), @sizeOf(AddressLookup));
}

test "a table with one slot short of the pair refuses the start and leaves nothing behind" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    var filler: [fixtures.slot_count - 1]Handle = undefined;
    for (&filler) |*handle| handle.* = try rig.table.start("filler.example.");
    try testing.expectError(error.NoSlot, AddressLookup.init(&rig.table.resolver, null, "host.example.", null, .{}));
    try testing.expectEqual(@as(usize, filler.len), rig.table.resolver.in_flight());
}

/// A hosts table built by hand, the parser being in `config`.
const HostsFixture = struct {
    storage: core.hosts.Storage = .{},
    entry_count: usize = 0,
    names_used: usize = 0,

    fn add(self: *HostsFixture, address: Address, names: []const []const u8) !void {
        var entry: core.hosts.Entry = .{ .address = address, .names = undefined, .name_count = 0 };
        for (names) |text| {
            const name = try Name.from_text(text);
            @memcpy(self.storage.names[self.names_used..][0..name.len], name.wire());
            entry.names[entry.name_count] = .{ .offset = @intCast(self.names_used), .len = name.len };
            entry.name_count += 1;
            self.names_used += name.len;
        }
        self.storage.entries[self.entry_count] = entry;
        self.entry_count += 1;
    }

    fn table(self: *const HostsFixture) core.Hosts {
        return .{
            .entries = self.storage.entries[0..self.entry_count],
            .names = self.storage.names[0..self.names_used],
        };
    }
};
