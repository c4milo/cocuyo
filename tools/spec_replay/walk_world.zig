//! The `getaddrinfo` walks of `resolver` over a real table, driven by the events of the walks'
//! transcript (spec/Spec/AddressWalk.lean), and their state written the way the model writes its
//! own (`stateLine`), so the two can be compared line by line.
//!
//! Each of the walk's lookups is answered through the table by a message its server would send:
//! an answer of the family asked, NXDOMAIN, NODATA, or SERVFAIL from the one server there is, a
//! failure that says nothing about the name. An end is handed to the walk when the transcript
//! says, straight from the lookup, since the order the consumer polls in is what the model
//! leaves free.
//!
//! This is developer tooling. It is never linked into the library.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const resolver = @import("resolver");
const fixtures = @import("fixtures.zig");
const AddressLookup = resolver.AddressLookup;
const NameLookup = resolver.NameLookup;
const Pending = resolver.address_lookup.Pending;

/// The slots the largest table the transcript names has.
pub const slots_max = 3;
const keys_count = std.math.ceilPowerOfTwoAssert(usize, slots_max * resolver.constants.keys_per_slot_min);

/// The seed of the table; the model abstracts its entropy away.
const seed = 0xadd7_e55e;

/// The name the forward walk asks about, relative so the search list walks, and the address the
/// reverse walk asks about. The hosts table holds both, in both families.
const asked_name = "host";
const search_texts = [_][]const u8{ "a.test", "b.test" };
const address_v4 = core.Address.from_v4(.{ 192, 0, 2, 1 });

/// The longest state line.
pub const text_bytes_max = 128;

pub const Error = error{ Malformed, Refused, NotInFlight };

pub const Walk = enum { address, name };

/// What an event changes: the table, the walk and the consumer's other lookups, kept whole so a
/// depth-first transcript can go back to any line's parent.
pub const Live = struct {
    slots: [slots_max]resolver.Slot,
    keys: [keys_count]resolver.MatchKey,
    table: resolver.Resolver,
    address: AddressLookup,
    name: NameLookup,
    others: [slots_max]resolver.Handle,
    others_count: usize,
    now_ns: u64,
};

/// What a transcript's section fixes, and the storage the table and the hosts table point into.
pub const World = struct {
    walk: Walk = .address,
    server: [1]core.Server = undefined,
    search: [search_texts.len]core.Name = undefined,
    lookups: [2]core.Source = undefined,
    config: core.Config = undefined,
    storage: core.hosts.Storage = .{},
    hosts: core.Hosts = undefined,
    has_hosts: bool = false,
    family: ?core.Family = null,
    slot_count: usize = 0,
    live: Live = undefined,
    out: [core.constants.query_bytes_max]u8 = undefined,
    reply: [core.constants.udp_payload_bytes_default]u8 = undefined,

    /// Sets the section up: the sources in order, whether the hosts table holds the name, and
    /// for the forward walk the candidates, the family and the table's size.
    pub fn configure(world: *World, walk: Walk, sources: []const u8, hosts_has: bool, candidates: usize, family: ?core.Family, slot_count: usize) Error!void {
        world.walk = walk;
        var count: usize = 0;
        var parts = std.mem.splitScalar(u8, sources, ',');
        while (parts.next()) |part| : (count += 1) {
            if (count == world.lookups.len) return error.Malformed;
            world.lookups[count] = if (std.mem.eql(u8, part, "dns")) .dns else if (std.mem.eql(u8, part, "file")) .file else return error.Malformed;
        }
        if (candidates < 1 or candidates > search_texts.len + 1) return error.Malformed;
        if (slot_count < 2 or slot_count > slots_max) return error.Malformed;
        for (search_texts[0 .. candidates - 1], 0..) |entry, index| world.search[index] = core.Name.from_text(entry) catch unreachable;
        world.server = .{.{ .endpoint = .{ .address = core.Address.from_v4(.{ 192, 0, 2, 53 }) } }};
        world.config = .{
            .servers = &world.server,
            .search = world.search[0 .. candidates - 1],
            .ndots = 1,
            .attempts = 1,
            .lookups = world.lookups[0..count],
        };
        world.has_hosts = hosts_has;
        if (hosts_has) world.fill_hosts();
        world.family = family;
        world.slot_count = slot_count;
    }

    /// A hosts table naming `host` at an address of each family.
    fn fill_hosts(world: *World) void {
        const name = core.Name.from_text(asked_name) catch unreachable;
        @memcpy(world.storage.names[0..name.len], name.wire());
        const addresses = [_]core.Address{ address_v4, core.Address.from_text("2001:db8::1").? };
        for (addresses, 0..) |address, index| {
            var entry: core.hosts.Entry = .{ .address = address, .names = undefined, .name_count = 1 };
            entry.names[0] = .{ .offset = 0, .len = name.len };
            world.storage.entries[index] = entry;
        }
        world.hosts = .{ .entries = world.storage.entries[0..addresses.len], .names = world.storage.names[0..name.len] };
    }

    /// The table, and the walk started on it.
    pub fn begin(world: *World) Error!void {
        const live = &world.live;
        live.slots = @splat(.{});
        live.table = resolver.Resolver.init(live.slots[0..world.slot_count], &live.keys, &world.config, seed);
        live.others_count = 0;
        live.now_ns = 1;
        const hosts: ?*const core.Hosts = if (world.has_hosts) &world.hosts else null;
        switch (world.walk) {
            .address => live.address = AddressLookup.init(&live.table, hosts, asked_name, world.family, .{}) catch return error.Refused,
            .name => live.name = NameLookup.init(&live.table, hosts, &address_v4) catch return error.Refused,
        }
        world.acknowledge();
    }

    /// Every lookup of the walk that is ready to send is told its query went out, so an answer
    /// can be accepted; the walk starts lookups inside `init` and `on_event`.
    fn acknowledge(world: *World) void {
        var handles: [2]?resolver.Handle = .{ null, null };
        switch (world.walk) {
            .address => handles = .{ world.live.address.a.handle, world.live.address.aaaa.handle },
            .name => handles[0] = world.live.name.handle,
        }
        for (handles) |held| {
            const handle = held orelse continue;
            if (world.live.table.lookup_of(handle).state == .query_ready) world.live.table.on_sent(handle, world.live.now_ns);
        }
    }

    /// One event of the transcript.
    pub fn apply(world: *World, token: []const u8) Error!void {
        var parts = std.mem.splitScalar(u8, token, ':');
        const name = parts.first();
        world.live.now_ns += 1;
        if (std.mem.eql(u8, name, "cancel")) {
            world.cancel();
        } else if (std.mem.eql(u8, name, "steal")) {
            try world.steal();
        } else if (std.mem.eql(u8, name, "give_back")) {
            try world.give_back();
        } else {
            try world.end_event(name, &parts);
        }
        world.acknowledge();
    }

    fn cancel(world: *World) void {
        switch (world.walk) {
            .address => world.live.address.cancel(),
            .name => world.live.name.cancel(),
        }
    }

    /// Another consumer starts a lookup in a free slot.
    fn steal(world: *World) Error!void {
        var buffer: [32]u8 = undefined;
        const other = std.fmt.bufPrint(&buffer, "o{d}.other.", .{world.live.others_count}) catch unreachable;
        const question = core.Question.from_text(other, .a) catch unreachable;
        world.live.others[world.live.others_count] = world.live.table.start(question) catch return error.Refused;
        world.live.others_count += 1;
    }

    /// Another consumer releases the slot it took last.
    fn give_back(world: *World) Error!void {
        if (world.live.others_count == 0) return error.Malformed;
        world.live.others_count -= 1;
        world.live.table.release(world.live.others[world.live.others_count]);
    }

    /// An end arrives in the table, or is handed to the walk.
    fn end_event(world: *World, name: []const u8, parts: *std.mem.SplitIterator(u8, .scalar)) Error!void {
        const handle = try world.handle_of(parts);
        if (std.mem.eql(u8, name, "arrive")) return world.arrive(handle, parts.next() orelse return error.Malformed);
        if (std.mem.eql(u8, name, "deliver")) return world.deliver(handle);
        return error.Malformed;
    }

    fn handle_of(world: *World, parts: *std.mem.SplitIterator(u8, .scalar)) Error!resolver.Handle {
        switch (world.walk) {
            .name => return world.live.name.handle orelse error.NotInFlight,
            .address => {
                const family = parts.next() orelse return error.Malformed;
                const pending = if (std.mem.eql(u8, family, "a")) &world.live.address.a else &world.live.address.aaaa;
                return pending.handle orelse error.NotInFlight;
            },
        }
    }

    /// The lookup's server answers it.
    fn arrive(world: *World, handle: resolver.Handle, result: []const u8) Error!void {
        const reply: fixtures.Reply = if (std.mem.eql(u8, result, "answer"))
            .answer
        else if (std.mem.eql(u8, result, "name_not_found"))
            .nxdomain
        else if (std.mem.eql(u8, result, "no_data"))
            .nodata
        else if (std.mem.eql(u8, result, "hard")) .servfail else return error.Malformed;
        const lookup = world.live.table.lookup_of(handle);
        const message = fixtures.build(lookup, reply, &world.reply);
        if (world.live.table.on_datagram(message, lookup.server(), world.live.now_ns) != .accepted) return error.Refused;
    }

    /// The consumer hands the lookup's end to the walk.
    fn deliver(world: *World, handle: resolver.Handle) Error!void {
        const lookup = world.live.table.lookup_of(handle);
        if (!lookup.is_settled()) return error.NotInFlight;
        const event: resolver.Event = .{ .handle = handle, .action = lookup.poll(world.live.now_ns, &world.out) };
        const taken = switch (world.walk) {
            .address => world.live.address.on_event(event),
            .name => world.live.name.on_event(event),
        };
        if (!taken) return error.Refused;
    }

    /// The walk's state as the model writes one.
    pub fn text(world: *World, out: *[text_bytes_max]u8) []const u8 {
        var line = std.Io.Writer.fixed(out);
        switch (world.walk) {
            .address => world.address_text(&line),
            .name => world.reverse_text(&line),
        }
        return line.buffered();
    }

    fn address_text(world: *World, line: *std.Io.Writer) void {
        const walk = &world.live.address;
        put(line, "s{d} c{d} a:", .{ walk.source_index, walk.candidate_index });
        world.pending_text(line, &walk.a);
        put(line, " q:", .{});
        world.pending_text(line, &walk.aaaa);
        put(line, " {c}{c} e:", .{ flag(walk.saw_no_data, 'N'), flag(walk.cancelled, 'C') });
        end_text(line, walk.ended, walk.partial);
        put(line, " o{d}", .{world.live.others_count});
    }

    fn pending_text(world: *World, line: *std.Io.Writer, pending: *const Pending) void {
        const handle = pending.handle orelse return put(line, "-", .{});
        if (pending.ended) {
            const result = if (pending.answered) "answer" else result_of(pending.err.?);
            return put(line, "done/{s}", .{result});
        }
        world.lookup_text(line, handle);
    }

    /// A lookup in flight, or settled with its end not yet handed over.
    fn lookup_text(world: *World, line: *std.Io.Writer, handle: resolver.Handle) void {
        const lookup = world.live.table.lookup_of(handle);
        switch (lookup.state) {
            .done => put(line, "arr/answer", .{}),
            .failed => put(line, "arr/{s}", .{result_of(lookup.failure)}),
            else => put(line, "run", .{}),
        }
    }

    fn reverse_text(world: *World, line: *std.Io.Writer) void {
        const walk = &world.live.name;
        put(line, "s{d} p:", .{walk.source_index});
        if (walk.handle) |handle| world.lookup_text(line, handle) else put(line, "-", .{});
        put(line, " {c}{c} e:", .{ flag(walk.saw_no_data, 'N'), flag(walk.cancelled, 'C') });
        end_text(line, walk.ended, null);
    }
};

/// How a walk ended, or `-` while it runs.
fn end_text(line: *std.Io.Writer, ended: anytype, partial: ?core.Error) void {
    const end = ended orelse return put(line, "-", .{});
    switch (end) {
        .answered => put(line, "answered/{s}", .{if (partial) |err| result_of(err) else "-"}),
        .failed => |failure| put(line, "failed/{s}", .{result_of(failure.err)}),
    }
}

fn put(line: *std.Io.Writer, comptime format: []const u8, arguments: anytype) void {
    line.print(format, arguments) catch unreachable;
}

fn flag(set: bool, letter: u8) u8 {
    return if (set) letter else '-';
}

/// A failure as the model names it: the two negatives, a cancel, and every other failure hard.
fn result_of(err: core.Error) []const u8 {
    return switch (err) {
        error.NameNotFound => "name_not_found",
        error.NoData => "no_data",
        error.Canceled => "canceled",
        else => "hard",
    };
}
