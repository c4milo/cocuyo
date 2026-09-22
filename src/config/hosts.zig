//! The hosts file: one address, an official name and its aliases per line, `#` starting a
//! comment, fields separated by blanks and tabs (`hosts(5)`). No RFC states the format; the
//! manual page is the source, and this file says so (CLAUDE.md non-negotiable 8).
//!
//! `parse` takes the file's bytes and fills the caller's `Storage`: cocuyo reads no file. The
//! names are kept in wire form in one arena of the storage, so an entry is an address, up to
//! `hosts_names_per_entry_max` references into that arena, and a count; the engine consults the
//! result before a query goes out, in the order `Config.lookups` gives (docs/design.md §19
//! step 11).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Address = core.Address;
const Family = core.Family;
const Name = core.Name;
const constants = @import("constants.zig");
const address_text = @import("address_text.zig");

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

/// Reads `bytes` into `storage` and returns the entries it describes. Lines past
/// `hosts_lines_max`, entries past `hosts_entries_max`, names on a line past
/// `hosts_names_per_entry_max` and names past the arena are dropped; a line whose address or
/// every name will not parse is skipped, as every stub skips it.
pub fn parse(bytes: []const u8, storage: *Storage) Hosts {
    var builder: Builder = .{ .storage = storage };
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var read: usize = 0;
    while (read < constants.hosts_lines_max) : (read += 1) {
        const line = lines.next() orelse break;
        builder.line(line);
    }
    assert(builder.entry_count <= constants.hosts_entries_max);
    return .{
        .entries = storage.entries[0..builder.entry_count],
        .names = storage.names[0..builder.names_used],
    };
}

const Builder = struct {
    storage: *Storage,
    entry_count: usize = 0,
    names_used: usize = 0,

    fn line(self: *Builder, text: []const u8) void {
        // Everything from the comment character on is not read (`hosts(5)`).
        const end = std.mem.indexOfScalar(u8, text, constants.hosts_comment_start) orelse text.len;
        var tokens = std.mem.tokenizeAny(u8, text[0..end], constants.token_separators);
        const address_token = tokens.next() orelse return;
        if (self.entry_count == constants.hosts_entries_max) return;
        const address = address_text.parse(address_token) orelse return;
        var entry: Entry = .{ .address = address, .names = undefined, .name_count = 0 };
        var read: usize = 0;
        while (read <= constants.hosts_names_per_entry_max) : (read += 1) {
            const token = tokens.next() orelse break;
            if (entry.name_count == constants.hosts_names_per_entry_max) break;
            const ref = self.intern(token) orelse continue;
            entry.names[entry.name_count] = ref;
            entry.name_count += 1;
        }
        // An official name is required (`hosts(5)`): an address alone names nothing.
        if (entry.name_count == 0) return;
        self.storage.entries[self.entry_count] = entry;
        self.entry_count += 1;
        assert(self.entry_count <= constants.hosts_entries_max);
    }

    /// Writes `text` into the arena as a wire name; null when it is not a name, or when the
    /// arena is full.
    fn intern(self: *Builder, text: []const u8) ?NameRef {
        const name = Name.from_text(text) catch return null;
        if (self.names_used + name.len > constants.hosts_names_bytes_max) return null;
        const offset = self.names_used;
        @memcpy(self.storage.names[offset..][0..name.len], name.wire());
        self.names_used += name.len;
        assert(self.names_used <= constants.hosts_names_bytes_max);
        return .{ .offset = @intCast(offset), .len = name.len };
    }
};

// Tests.

const testing = std.testing;

const typical =
    \\# Host Database
    \\127.0.0.1       localhost
    \\::1             localhost
    \\192.0.2.10      db.example db   # the database, aliased
    \\
    \\2001:db8::10    db.example
    \\not-an-address  nothing.example
    \\192.0.2.11
    \\192.0.2.12      a..b  good.example
    \\
;

fn parse_text(text: []const u8, storage: *Storage) Hosts {
    return parse(text, storage);
}

test "a typical file gives its entries, comments and bad lines skipped" {
    var storage: Storage = .{};
    const hosts = parse_text(typical, &storage);
    try testing.expectEqual(@as(usize, 5), hosts.entries.len);
    var out: [4]Address = undefined;
    const localhost = try Name.from_text("localhost");
    try testing.expectEqual(@as(usize, 2), hosts.find(&localhost, null, &out));
    try testing.expectEqual(core.Family.ipv4, out[0].family);
    try testing.expectEqual(core.Family.ipv6, out[1].family);
    try testing.expectEqual(@as(usize, 1), hosts.find(&localhost, .ipv6, &out));
    // A word in a comment is not a name.
    try testing.expectEqual(@as(usize, 0), hosts.find(&try Name.from_text("aliased"), null, &out));
}

test "an alias finds the entry, its official name is the canonical one, and case does not matter" {
    var storage: Storage = .{};
    const hosts = parse_text(typical, &storage);
    var out: [4]Address = undefined;
    const alias = try Name.from_text("DB");
    try testing.expectEqual(@as(usize, 1), hosts.find(&alias, null, &out));
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 10 }, out[0].slice());
    const canonical = hosts.canonical(&alias).?;
    try testing.expect(canonical.equal(&try Name.from_text("db.example")));
    const official = try Name.from_text("db.example");
    try testing.expectEqual(@as(usize, 2), hosts.find(&official, null, &out));
    try testing.expectEqual(@as(?Name, null), hosts.canonical(&try Name.from_text("nothing.example")));
}

test "a reverse lookup gives the official name of the first entry with the address" {
    var storage: Storage = .{};
    const hosts = parse_text(typical, &storage);
    const address = Address.from_v4(.{ 192, 0, 2, 10 });
    try testing.expect(hosts.reverse(&address).?.equal(&try Name.from_text("db.example")));
    const other = Address.from_v4(.{ 192, 0, 2, 99 });
    try testing.expectEqual(@as(?Name, null), hosts.reverse(&other));
}

test "a name that will not parse is skipped and the good one beside it kept" {
    var storage: Storage = .{};
    const hosts = parse_text(typical, &storage);
    const good = try Name.from_text("good.example");
    var out: [1]Address = undefined;
    try testing.expectEqual(@as(usize, 1), hosts.find(&good, null, &out));
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 12 }, out[0].slice());
}

test "the room the caller gives bounds a find, and the empty table finds nothing" {
    var storage: Storage = .{};
    const hosts = parse_text(typical, &storage);
    var one: [1]Address = undefined;
    const localhost = try Name.from_text("localhost");
    try testing.expectEqual(@as(usize, 1), hosts.find(&localhost, null, &one));
    try testing.expectEqual(@as(usize, 0), Hosts.empty.find(&localhost, null, &one));
    try testing.expectEqual(@as(?Name, null), Hosts.empty.canonical(&localhost));
}

test "names past the limit on one line, and entries past the limit, are dropped" {
    var storage: Storage = .{};
    const many_names = "192.0.2.1 n0 n1 n2 n3 n4 n5 n6 n7 n8 n9\n";
    const hosts = parse_text(many_names, &storage);
    try testing.expectEqual(@as(u8, constants.hosts_names_per_entry_max), hosts.entries[0].name_count);
    var out: [1]Address = undefined;
    try testing.expectEqual(@as(usize, 0), hosts.find(&try Name.from_text("n9"), null, &out));

    const line = "192.0.2.2 host\n";
    const too_many = line ** (constants.hosts_entries_max + 3);
    const bounded = parse_text(too_many, &storage);
    try testing.expectEqual(@as(usize, constants.hosts_entries_max), bounded.entries.len);
}

test "a name that does not fit the arena is dropped, and the line with it when it was the only one" {
    var storage: Storage = .{};
    var builder: Builder = .{ .storage = &storage, .names_used = constants.hosts_names_bytes_max - 3 };
    try testing.expectEqual(@as(?NameRef, null), builder.intern("abcd"));
    builder.line("192.0.2.3 abcd");
    try testing.expectEqual(@as(usize, 0), builder.entry_count);
    const short = builder.intern("a").?;
    try testing.expectEqual(@as(u8, 3), short.len);
}
