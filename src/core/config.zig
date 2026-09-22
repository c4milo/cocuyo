//! `Config`: the servers to ask, the search list to try, and the retry policy. It lives in `core`
//! rather than beside the `resolv.conf` parser, which is what lets the state machine take a server
//! list and a search list from whoever produced them and never depend on a file format
//! (docs/design.md §16 decision 7).
//!
//! The slices are the caller's and must outlive every lookup that reads them. cocuyo copies no
//! server list, because cocuyo allocates nothing.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const Endpoint = @import("address.zig").Endpoint;
const Name = @import("name.zig").Name;

pub const Config = struct {
    /// The servers to ask, in the order they are asked. At least one, at most
    /// `constants.servers_max`.
    servers: []const Endpoint,
    /// The search list, in the order it is tried. May be empty.
    search: []const Name = &.{},
    /// The dot count that decides whether the name or the search list is tried first.
    ndots: u8 = constants.ndots_default,
    /// Passes over the server list before a lookup gives up.
    attempts: u8 = constants.attempts_default,
    /// The wait for one server on the first pass. It doubles per pass, capped at
    /// `constants.timeout_ns_max`.
    timeout_ns: u64 = constants.timeout_ns_default,
    /// The UDP payload size cocuyo advertises in OPT, which is also the smallest receive buffer
    /// the caller may use.
    udp_payload_bytes: u16 = constants.udp_payload_bytes_default,
    /// Whether to randomise the case of the qname and require it back unchanged. On by default;
    /// turn it off only for a server that mangles case (docs/design.md §7).
    mix_case: bool = true,
    /// Whether to start the first pass at a server the seed chooses rather than at the first.
    rotate: bool = false,

    /// Every rule a configuration must satisfy. A configuration is the caller's to build, so a
    /// broken one is a programmer error and asserts rather than returning (CLAUDE.md
    /// non-negotiable 3).
    pub fn assert_valid(self: *const Config) void {
        assert(self.servers.len >= 1);
        assert(self.servers.len <= constants.servers_max);
        assert(self.search.len <= constants.search_max);
        assert(self.attempts >= 1);
        assert(self.attempts <= constants.attempts_max);
        assert(self.timeout_ns >= 1);
        assert(self.timeout_ns <= constants.timeout_ns_max);
        assert(self.udp_payload_bytes >= constants.udp_payload_bytes_min);
        assert(self.udp_payload_bytes <= constants.message_bytes_max);
    }
};

// Tests.

const testing = std.testing;
const Address = @import("address.zig").Address;

test "the defaults are the resolv.conf defaults and are valid" {
    const servers = [_]Endpoint{.{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) }};
    const config: Config = .{ .servers = &servers };
    config.assert_valid();
    try testing.expectEqual(@as(u8, 1), config.ndots);
    try testing.expectEqual(@as(u8, 2), config.attempts);
    try testing.expectEqual(@as(u64, 5_000_000_000), config.timeout_ns);
    try testing.expectEqual(@as(u16, 1232), config.udp_payload_bytes);
    try testing.expect(config.mix_case);
    try testing.expect(!config.rotate);
    try testing.expectEqual(@as(usize, 0), config.search.len);
}

test "a search list at the limit is valid" {
    const servers = [_]Endpoint{.{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) }};
    const search: [constants.search_max]Name = @splat(Name.root);
    const config: Config = .{ .servers = &servers, .search = &search };
    config.assert_valid();
    try testing.expectEqual(@as(usize, constants.search_max), config.search.len);
}
