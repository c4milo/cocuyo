//! The hosts table: what a hosts file holds once `config.hosts.parse` has read it, and the three
//! questions asked of it. An entry is an address, up to `hosts_names_per_entry_max` references
//! into one arena of wire names, and a count, all in the caller's `Storage`: cocuyo reads no
//! file and allocates nothing. `AddressLookup` consults the table before a query goes out, in the
//! order `Config.lookups` gives (docs/design.md §19 steps 11 and 14).
//!
//! The type lives here and its parser in `config`, the split `Config` has: `resolver` reaches
//! `core` and never `config` (§2).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const address_module = @import("address.zig");
const Address = address_module.Address;
const Family = address_module.Family;
const Name = @import("name.zig").Name;

/// A wire name inside `Storage.names`.
pub const NameRef = struct { offset: u16, len: u8 };

pub const Entry = struct {
    address: Address,
    /// The official name first, then the aliases, in the line's order.
    names: [constants.hosts_names_per_entry_max]NameRef,
    name_count: u8,
};

pub const Storage = struct {
    entries: [constants.hosts_entries_max]Entry = undefined,
    names: [constants.hosts_names_bytes_max]u8 = undefined,
};

pub const Hosts = struct {
    entries: []const Entry,
    names: []const u8,

    pub const empty: Hosts = .{ .entries = &.{}, .names = &.{} };

    /// The addresses every entry naming `name` holds, of `family` or of either, written into
    /// `out` in the file's order; how many were written.
    pub fn find(self: *const Hosts, name: *const Name, family: ?Family, out: []Address) usize {
        var count: usize = 0;
        for (self.entries) |*entry| {
            if (count == out.len) break;
            if (family) |wanted| {
                if (entry.address.family != wanted) continue;
            }
            if (!self.names_include(entry, name)) continue;
            out[count] = entry.address;
            count += 1;
        }
        assert(count <= out.len);
        return count;
    }

    /// The official name of the first entry naming `name`: the first field of its line.
    pub fn canonical(self: *const Hosts, name: *const Name) ?Name {
        for (self.entries) |*entry| {
            if (self.names_include(entry, name)) return self.name_of(entry.names[0]);
        }
        return null;
    }

    /// The official name of the first entry with `address`.
    pub fn reverse(self: *const Hosts, address: *const Address) ?Name {
        for (self.entries) |*entry| {
            if (entry.address.equal(address)) return self.name_of(entry.names[0]);
        }
        return null;
    }

    fn names_include(self: *const Hosts, entry: *const Entry, name: *const Name) bool {
        assert(entry.name_count >= 1);
        for (entry.names[0..entry.name_count]) |ref| {
            if (wire_equal(self.names[ref.offset..][0..ref.len], name.wire())) return true;
        }
        return false;
    }

    fn name_of(self: *const Hosts, ref: NameRef) Name {
        assert(ref.len >= 1);
        var name: Name = Name.empty;
        @memcpy(name.bytes[0..ref.len], self.names[ref.offset..][0..ref.len]);
        name.len = ref.len;
        return name;
    }
};

/// Two wire names, compared with the case of their letters folded (RFC 1035 §2.3.3, as RFC 4343
/// clarifies it). The length octets are below the letters and fold to themselves.
fn wire_equal(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |mine, theirs| {
        if (std.ascii.toLower(mine) != std.ascii.toLower(theirs)) return false;
    }
    return true;
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

/// A table built by hand, since the parser lives in `config`: the entries in the order given, the
/// first name of each its official one.
const Fixture = struct {
    storage: Storage = .{},
    entry_count: usize = 0,
    names_used: usize = 0,

    fn add(self: *Fixture, address: Address, names: []const []const u8) !void {
        var entry: Entry = .{ .address = address, .names = undefined, .name_count = 0 };
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

    fn table(self: *const Fixture) Hosts {
        return .{
            .entries = self.storage.entries[0..self.entry_count],
            .names = self.storage.names[0..self.names_used],
        };
    }
};

fn typical(fixture: *Fixture) !void {
    try fixture.add(fixtures.localhost_v4, &.{"localhost"});
    try fixture.add(fixtures.localhost_v6, &.{"localhost"});
    try fixture.add(fixtures.db_v4, &.{ "db.example", "db" });
    try fixture.add(fixtures.db_v6, &.{"db.example"});
}

test "find gives every entry naming the name, of one family or either, in the table's order" {
    var fixture: Fixture = .{};
    try typical(&fixture);
    const hosts = fixture.table();
    var out: [4]Address = undefined;
    const localhost = try Name.from_text("localhost");
    try testing.expectEqual(@as(usize, 2), hosts.find(&localhost, null, &out));
    try testing.expectEqual(Family.ipv4, out[0].family);
    try testing.expectEqual(Family.ipv6, out[1].family);
    try testing.expectEqual(@as(usize, 1), hosts.find(&localhost, .ipv6, &out));
    try testing.expectEqual(Family.ipv6, out[0].family);
    try testing.expectEqual(@as(usize, 0), hosts.find(&try Name.from_text("nothing.example"), null, &out));
}

test "an alias finds the entry, its official name is the canonical one, and case does not matter" {
    var fixture: Fixture = .{};
    try typical(&fixture);
    const hosts = fixture.table();
    var out: [4]Address = undefined;
    const alias = try Name.from_text("DB");
    try testing.expectEqual(@as(usize, 1), hosts.find(&alias, null, &out));
    try testing.expect(out[0].equal(&fixtures.db_v4));
    const canonical = hosts.canonical(&alias).?;
    try testing.expect(canonical.equal(&try Name.from_text("db.example")));
    const official = try Name.from_text("db.example");
    try testing.expectEqual(@as(usize, 2), hosts.find(&official, null, &out));
    try testing.expectEqual(@as(?Name, null), hosts.canonical(&try Name.from_text("nothing.example")));
}

test "a reverse lookup gives the official name of the first entry with the address" {
    var fixture: Fixture = .{};
    try typical(&fixture);
    const hosts = fixture.table();
    try testing.expect(hosts.reverse(&fixtures.db_v4).?.equal(&try Name.from_text("db.example")));
    try testing.expectEqual(@as(?Name, null), hosts.reverse(&fixtures.unlisted_v4));
}

test "the room the caller gives bounds a find, and the empty table finds nothing" {
    var fixture: Fixture = .{};
    try typical(&fixture);
    const hosts = fixture.table();
    var one: [1]Address = undefined;
    const localhost = try Name.from_text("localhost");
    try testing.expectEqual(@as(usize, 1), hosts.find(&localhost, null, &one));
    try testing.expectEqual(@as(usize, 0), Hosts.empty.find(&localhost, null, &one));
    try testing.expectEqual(@as(?Name, null), Hosts.empty.canonical(&localhost));
    try testing.expectEqual(@as(?Name, null), Hosts.empty.reverse(&one[0]));
}
