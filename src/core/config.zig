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
const Address = @import("address.zig").Address;
const Endpoint = @import("address.zig").Endpoint;
const Name = @import("name.zig").Name;

/// One server: where a query goes over UDP, and the port a TCP connection uses when it differs,
/// which c-ares configures apart (docs/design.md §19 step 11). Zero means the same port.
pub const Server = struct {
    endpoint: Endpoint,
    tcp_port: u16 = 0,

    pub fn tcp_endpoint(self: *const Server) Endpoint {
        var endpoint = self.endpoint;
        if (self.tcp_port != 0) endpoint.port = self.tcp_port;
        return endpoint;
    }
};

/// Where a name is looked up: the hosts file, or DNS. `Config.lookups` orders them, which is
/// c-ares's `lookups` option, `fb` by default (§19 step 11); the engine reads the order.
pub const Source = enum { file, dns };

pub const default_lookups = [_]Source{ .file, .dns };

pub const Config = struct {
    /// The servers to ask, in the order they are asked. At most `constants.servers_max`; none
    /// when a `resolv.conf` named none and the caller asked for no default, in which case every
    /// lookup fails at once with `NoServers`.
    servers: []const Server,
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
    /// The cap on the doubling wait between passes: c-ares's `maxtimeout`. At most the
    /// constant of the same name.
    timeout_ns_max: u64 = constants.timeout_ns_max,
    /// Every query over TCP: `use-vc` in a `resolv.conf`, `ARES_FLAG_USEVC` in c-ares.
    use_tcp: bool = false,
    /// A truncated UDP answer is taken as it is rather than asked again over TCP
    /// (`ARES_FLAG_IGNTC`).
    ignore_truncation: bool = false,
    /// The RD bit of every query (RFC 1035 §4.1.1); `ARES_FLAG_NORECURSE` clears it.
    recursion_desired: bool = true,
    /// Whether SERVFAIL, REFUSED and NOTIMP move the lookup to the next server. Off, each ends
    /// the lookup with its own error, which is `ARES_FLAG_NOCHECKRESP`.
    check_response: bool = true,
    /// Only the first server is asked (`ARES_FLAG_PRIMARY`).
    primary: bool = false,
    /// Where the engine looks a name up, in order: the hosts file, then DNS, by default.
    lookups: []const Source = &default_lookups,
    /// One query in this many gives a server that failed, and whose delay has passed, the first
    /// place again (§19 step 12); zero never does.
    failover_retry_chance: u8 = constants.failover_retry_chance_default,
    /// The local address the engine binds its sockets to, when the caller has one to name
    /// (c-ares `ARES_OPT_LOCAL_IP4` and `LOCAL_IP6`). Null is the unspecified address, which is
    /// what a host with one route wants. A server of another family is bound unspecified, since
    /// an address of the wrong family cannot name a local endpoint for it. Binding to a device
    /// by name is out: rotor opens sockets and names no device (docs/design.md §19 step 13).
    local_address: ?Address = null,
    /// What the engine asks the kernel for on each socket it opens, which is c-ares's
    /// `socket_receive_buffer_size` and `socket_send_buffer_size`. Zero, the default, leaves the
    /// kernel's own size alone. What a kernel grants is rarely what it was asked for, and it is
    /// free to refuse: a socket that will not take the size is used with the size it has, since
    /// a buffer smaller than the caller wanted loses datagrams and no buffer at all loses every
    /// one (docs/design.md §19 step 13).
    socket_receive_bytes: u32 = 0,
    socket_send_bytes: u32 = 0,
    /// How many queries one source port carries before the engine opens another, which is
    /// c-ares `udp_max_queries`. Zero, the default there and here, keeps the port for the life
    /// of the engine; the port is entropy against a spoof either way (RFC 5452 §9.2).
    udp_queries_per_port: u32 = 0,
    /// How long a failed server stays last before it may be tried first again.
    failover_retry_delay_ns: u64 = constants.failover_retry_delay_ns_default,

    /// Every rule a configuration must satisfy. A configuration is the caller's to build, so a
    /// broken one is a programmer error and asserts rather than returning (CLAUDE.md
    /// non-negotiable 3).
    pub fn assert_valid(self: *const Config) void {
        assert(self.servers.len <= constants.servers_max);
        assert(self.search.len <= constants.search_max);
        assert(self.attempts >= 1);
        assert(self.attempts <= constants.attempts_max);
        assert(self.timeout_ns >= 1);
        assert(self.timeout_ns <= self.timeout_ns_max);
        assert(self.timeout_ns_max <= constants.timeout_ns_max);
        assert(self.udp_payload_bytes >= constants.udp_payload_bytes_min);
        assert(self.udp_payload_bytes <= constants.message_bytes_max);
        assert(self.lookups.len <= constants.lookup_sources_max);
    }

    /// How many servers a lookup may ask: with `primary`, the first is the only one.
    pub fn server_count(self: *const Config) usize {
        if (self.primary and self.servers.len >= 1) return 1;
        return self.servers.len;
    }
};

// Tests.

const testing = std.testing;
test "the defaults are the resolv.conf defaults and are valid" {
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) } }};
    const config: Config = .{ .servers = &servers };
    config.assert_valid();
    try testing.expectEqual(@as(u8, 1), config.ndots);
    try testing.expect(config.recursion_desired);
    try testing.expect(config.check_response);
    try testing.expect(!config.use_tcp and !config.ignore_truncation and !config.primary);
    try testing.expectEqual(constants.timeout_ns_max, config.timeout_ns_max);
    try testing.expectEqualSlices(Source, &default_lookups, config.lookups);
    try testing.expectEqual(@as(u8, 2), config.attempts);
    try testing.expectEqual(@as(u64, 5_000_000_000), config.timeout_ns);
    try testing.expectEqual(@as(u16, 1232), config.udp_payload_bytes);
    try testing.expect(config.mix_case);
    try testing.expect(!config.rotate);
    try testing.expectEqual(@as(usize, 0), config.search.len);
}

test "a search list at the limit is valid" {
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) } }};
    const search: [constants.search_max]Name = @splat(Name.root);
    const config: Config = .{ .servers = &servers, .search = &search };
    config.assert_valid();
    try testing.expectEqual(@as(usize, constants.search_max), config.search.len);
}

test "a TCP port of its own replaces the UDP port for a connection, and zero keeps it" {
    const endpoint: Endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }), .port = 53 };
    const same: Server = .{ .endpoint = endpoint };
    try testing.expectEqual(@as(u16, 53), same.tcp_endpoint().port);
    const other: Server = .{ .endpoint = endpoint, .tcp_port = 5353 };
    try testing.expectEqual(@as(u16, 5353), other.tcp_endpoint().port);
    try testing.expect(other.tcp_endpoint().address.equal(&endpoint.address));
}

test "primary asks one server, and a configuration may name none" {
    const servers = [_]Server{
        .{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }) } },
        .{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 54 }) } },
    };
    const config: Config = .{ .servers = &servers, .primary = true };
    try testing.expectEqual(@as(usize, 1), config.server_count());
    const both: Config = .{ .servers = &servers };
    try testing.expectEqual(@as(usize, 2), both.server_count());
    const none: Config = .{ .servers = &.{} };
    none.assert_valid();
    try testing.expectEqual(@as(usize, 0), none.server_count());
}
