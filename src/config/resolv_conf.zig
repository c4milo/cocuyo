//! The `resolv.conf` parser (docs/design.md §10).
//!
//! It takes bytes rather than a path, because the caller reads the file: cocuyo owns no I/O
//! (CLAUDE.md non-negotiable 1). And it produces a `core.Config`, which is a `core` type, so the
//! state machine depends on the values and never on the file format — `zig build graph-check`
//! shows the compiler refusing a module of the resolver's shape an import of this one.
//!
//! `resolv.conf` has no RFC. What it recognises is what `resolv.conf(5)` documents on Linux and on
//! macOS, and the behaviour for everything else is what every stub resolver does: skip the line.
//! A configuration file with one line cocuyo does not understand must not stop a program from
//! resolving, so `parse` cannot fail.
//!
//! What it does **not** do is read the file, find it, or follow the platform's own configuration.
//! On macOS `/etc/resolv.conf` is a partial, legacy view of the system's DNS configuration, and
//! §14 says plainly what a caller does and does not see by reading it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const Address = core.Address;
const Config = core.Config;
const Endpoint = core.Endpoint;
const Name = core.Name;
pub const constants = @import("constants.zig");
pub const address_text = @import("address_text.zig");
pub const options = @import("resolv_conf_options.zig");

/// The memory a parse fills. The `Config` it returns holds slices into this, so it must outlive
/// every lookup that reads it. cocuyo allocates nothing.
pub const Storage = struct {
    servers: [core.constants.servers_max]Endpoint = @splat(.{
        .address = .{ .family = .ipv4, .octets = @splat(0) },
    }),
    search: [core.constants.search_max]Name = @splat(Name.root),
};

/// Reads `bytes` into `storage` and returns the configuration it describes. Lines past
/// `lines_max`, servers past `servers_max` and search entries past `search_max` are dropped, which
/// the returned slice lengths say.
pub fn parse(bytes: []const u8, storage: *Storage) Config {
    var builder: Builder = .{ .storage = storage };
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var read: usize = 0;
    while (read < constants.lines_max) : (read += 1) {
        const line = lines.next() orelse break;
        builder.line(line);
    }
    assert(read <= constants.lines_max);
    return builder.finish();
}

const Builder = struct {
    storage: *Storage,
    server_count: u8 = 0,
    search_count: u8 = 0,
    ndots: u8 = core.constants.ndots_default,
    timeout_ns: u64 = core.constants.timeout_ns_default,
    attempts: u8 = core.constants.attempts_default,
    rotate: bool = false,

    const Tokens = std.mem.TokenIterator(u8, .any);

    fn line(self: *Builder, text: []const u8) void {
        var tokens = std.mem.tokenizeAny(u8, text, constants.token_separators);
        const keyword = tokens.next() orelse return;
        if (std.mem.indexOfScalar(u8, constants.comment_starts, keyword[0]) != null) return;
        if (std.mem.eql(u8, keyword, constants.keyword_nameserver)) {
            self.nameserver(&tokens);
        } else if (std.mem.eql(u8, keyword, constants.keyword_search)) {
            self.search(&tokens);
        } else if (std.mem.eql(u8, keyword, constants.keyword_domain)) {
            self.domain(&tokens);
        } else if (std.mem.eql(u8, keyword, constants.keyword_options)) {
            self.option_line(&tokens);
        }
        // `sortlist` and anything else is skipped: cocuyo does not order addresses, and a keyword
        // it does not know is a line for something else.
    }

    /// `nameserver ADDRESS`. A line with no address, a malformed one, or one past the limit is
    /// dropped.
    fn nameserver(self: *Builder, tokens: *Tokens) void {
        const text = tokens.next() orelse return;
        if (self.server_count == core.constants.servers_max) return;
        const address = address_text.parse(text) orelse return;
        self.storage.servers[self.server_count] = .{ .address = address };
        self.server_count += 1;
        assert(self.server_count <= core.constants.servers_max);
    }

    /// `search ONE TWO ...`. The last `search` or `domain` line in a file wins, so this replaces
    /// whatever came before rather than adding to it.
    fn search(self: *Builder, tokens: *Tokens) void {
        self.search_count = 0;
        var read: usize = 0;
        while (read <= core.constants.search_max) : (read += 1) {
            const text = tokens.next() orelse break;
            if (self.search_count == core.constants.search_max) break;
            const name = Name.from_text(text) catch continue;
            self.storage.search[self.search_count] = name;
            self.search_count += 1;
        }
        assert(self.search_count <= core.constants.search_max);
    }

    /// `domain NAME`: a search list of one.
    fn domain(self: *Builder, tokens: *Tokens) void {
        const text = tokens.next() orelse return;
        const name = Name.from_text(text) catch return;
        self.storage.search[0] = name;
        self.search_count = 1;
    }

    /// `options ONE TWO ...`, each token independent of the others.
    fn option_line(self: *Builder, tokens: *Tokens) void {
        var read: usize = 0;
        while (read < constants.options_max) : (read += 1) {
            const text = tokens.next() orelse break;
            const option = options.parse(text) orelse continue;
            switch (option) {
                .ndots => |ndots| self.ndots = ndots,
                .timeout_ns => |timeout_ns| self.timeout_ns = timeout_ns,
                .attempts => |attempts| self.attempts = attempts,
                .rotate => self.rotate = true,
            }
        }
    }

    fn finish(self: *Builder) Config {
        if (self.server_count == 0) {
            // A file with no nameserver means the local one, which is what every stub does.
            self.storage.servers[0] = .{
                .address = Address.from_v4(constants.nameserver_default),
            };
            self.server_count = 1;
        }
        assert(self.server_count >= 1);
        const config: Config = .{
            .servers = self.storage.servers[0..self.server_count],
            .search = self.storage.search[0..self.search_count],
            .ndots = self.ndots,
            .attempts = self.attempts,
            .timeout_ns = self.timeout_ns,
            .rotate = self.rotate,
        };
        // Whatever the file said, the configuration handed back is one a lookup can run on.
        config.assert_valid();
        return config;
    }
};

// Tests.

const testing = std.testing;

fn parse_text(text: []const u8, storage: *Storage) Config {
    return parse(text, storage);
}

test "a plain file gives its servers in order" {
    var storage: Storage = .{};
    const config = parse_text(
        \\nameserver 192.0.2.53
        \\nameserver 2001:db8::53
        \\
    , &storage);
    try testing.expectEqual(@as(usize, 2), config.servers.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 53 }, config.servers[0].address.slice());
    try testing.expectEqual(core.Family.ipv6, config.servers[1].address.family);
    try testing.expectEqual(@as(u16, 53), config.servers[0].port);
}

test "an empty file means the local nameserver" {
    var storage: Storage = .{};
    const config = parse_text("", &storage);
    try testing.expectEqual(@as(usize, 1), config.servers.len);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, config.servers[0].address.slice());
    try testing.expectEqual(@as(usize, 0), config.search.len);
    try testing.expectEqual(core.constants.ndots_default, config.ndots);
    try testing.expectEqual(core.constants.attempts_default, config.attempts);
    try testing.expectEqual(core.constants.timeout_ns_default, config.timeout_ns);
    try testing.expect(!config.rotate);
}

test "a search line becomes the search list, in order" {
    var storage: Storage = .{};
    const config = parse_text("search one.example two.example three.example\n", &storage);
    try testing.expectEqual(@as(usize, 3), config.search.len);
    try testing.expect(config.search[0].equal(&try Name.from_text("one.example")));
    try testing.expect(config.search[2].equal(&try Name.from_text("three.example")));
}

test "the last search or domain line wins" {
    var storage: Storage = .{};
    const config = parse_text(
        \\search one.example two.example
        \\domain last.example
        \\
    , &storage);
    try testing.expectEqual(@as(usize, 1), config.search.len);
    try testing.expect(config.search[0].equal(&try Name.from_text("last.example")));

    const other = parse_text(
        \\domain first.example
        \\search one.example two.example
        \\
    , &storage);
    try testing.expectEqual(@as(usize, 2), other.search.len);
    try testing.expect(other.search[0].equal(&try Name.from_text("one.example")));
}

test "options are read, and the ones cocuyo does not know are skipped" {
    var storage: Storage = .{};
    // The options cocuyo does not know sit between the ones it does, on purpose: with them last,
    // a parser that stopped at the first unknown option would pass this test (mutation C10).
    const config = parse_text(
        "options edns0 ndots:3 single-request timeout:2 inet6 attempts:4 no-tld-query rotate\n",
        &storage,
    );
    try testing.expectEqual(@as(u8, 3), config.ndots);
    try testing.expectEqual(@as(u64, 2_000_000_000), config.timeout_ns);
    try testing.expectEqual(@as(u8, 4), config.attempts);
    try testing.expect(config.rotate);
}

test "comments and blank lines are skipped" {
    var storage: Storage = .{};
    const config = parse_text(
        \\# generated by something
        \\; another comment
        \\
        \\nameserver 192.0.2.53
        \\
    , &storage);
    try testing.expectEqual(@as(usize, 1), config.servers.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 53 }, config.servers[0].address.slice());
}

test "a line cocuyo does not understand costs nothing" {
    var storage: Storage = .{};
    const config = parse_text(
        \\sortlist 192.0.2.0/24
        \\lookup file bind
        \\nameserver 192.0.2.53
        \\nameserver not-an-address
        \\nameserver
        \\nameserver 192.0.2.54
        \\
    , &storage);
    try testing.expectEqual(@as(usize, 2), config.servers.len);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 54 }, config.servers[1].address.slice());
}

test "tabs and extra spaces separate tokens like one space" {
    var storage: Storage = .{};
    const config = parse_text("nameserver\t \t192.0.2.53   \nsearch\tone.example\n", &storage);
    try testing.expectEqual(@as(usize, 1), config.servers.len);
    try testing.expectEqual(@as(usize, 1), config.search.len);
}

test "a file with carriage returns parses" {
    var storage: Storage = .{};
    const config = parse_text("nameserver 192.0.2.53\r\nsearch one.example\r\n", &storage);
    try testing.expectEqual(@as(usize, 1), config.servers.len);
    try testing.expect(config.search[0].equal(&try Name.from_text("one.example")));
}

test "more servers than the limit are dropped, and the configuration says so" {
    var storage: Storage = .{};
    const line = "nameserver 192.0.2.1\n";
    const text = line ** (core.constants.servers_max + 3);
    const config = parse_text(text, &storage);
    try testing.expectEqual(@as(usize, core.constants.servers_max), config.servers.len);
}

test "more search entries than the limit are dropped" {
    var storage: Storage = .{};
    const config = parse_text("search a.example b.example c.example d.example e.example" ++
        " f.example g.example h.example\n", &storage);
    try testing.expectEqual(@as(usize, core.constants.search_max), config.search.len);
}

test "a file longer than the line bound stops there" {
    var storage: Storage = .{};
    const filler = "# comment\n" ** (constants.lines_max + 10);
    const config = parse_text(filler ++ "nameserver 192.0.2.53\n", &storage);
    // The nameserver line is past the bound, so the default stands.
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, config.servers[0].address.slice());
}

test "the configuration a parse returns is one the state machine accepts" {
    var storage: Storage = .{};
    const config = parse_text(
        \\nameserver 192.0.2.53
        \\search one.example
        \\options ndots:2 timeout:1 attempts:3
        \\
    , &storage);
    config.assert_valid();
    try testing.expectEqual(@as(u64, 1_000_000_000), config.timeout_ns);
}

test "a malformed search entry is skipped and the rest are kept" {
    var storage: Storage = .{};
    const config = parse_text("search one.example a..b two.example\n", &storage);
    try testing.expectEqual(@as(usize, 2), config.search.len);
    try testing.expect(config.search[1].equal(&try Name.from_text("two.example")));
}
