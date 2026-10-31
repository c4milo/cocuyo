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
const limits = @import("limits.zig");
const Address = @import("address.zig").Address;
const Endpoint = @import("address.zig").Endpoint;
const Name = @import("name.zig").Name;

/// An SPKI pin: the SHA-256 of a DER SubjectPublicKeyInfo (RFC 7858 §4.2).
pub const Pin = [constants.spki_pin_bytes]u8;

/// What a query to a DNS-over-TLS server needs (docs/design.md §21): how the server is known, by
/// its name, its SPKI pins, or both, and the port, 853 unless client and server agreed on
/// another (RFC 7858 §3.1).
pub const Tls = struct {
    /// The name the server's certificate must carry, the authentication domain name of RFC 8310
    /// §7.1. It is a DNS name: the certificate check reads a DNS-ID and nothing else. Null with
    /// pins alone, RFC 8310 §6.3's "SPKI + IP": the server is known by its key.
    name: ?Name = null,
    /// The SPKI pin set (RFC 7858 §4.2). With a name as well, the chain is validated against the
    /// name and a key on it must hash to one of the pins: both must pass (RFC 8310 §6.4). With pins
    /// alone, the server's raw public key, or its leaf certificate's key, must: the rest of the
    /// chain, its dates and its names are not read, and a pin on an intermediate or a root key
    /// matches nothing (chapulin's decision 65). The slice is the caller's, as `Config.servers`
    /// is.
    pins: []const Pin = &.{},
    port: u16 = constants.port_dns_tls_default,
    /// Whether a handshake must end on the post-quantum hybrid X25519MLKEM768 (RFC 10024 §4). The
    /// session then offers it alone, and a server that selects another group fails the handshake
    /// (docs/design.md §21, TLS rule 10). Off, the hello offers the hybrid and two classic groups.
    require_post_quantum: bool = false,

    /// Whether the server can be authenticated at all: a strict client connects only to a
    /// server it can authenticate (RFC 8310 §5), by a name, by pins, or by both.
    pub fn valid(self: *const Tls) bool {
        return (self.name != null or self.pins.len >= 1) and self.pins.len <= limits.spki_pins_max;
    }
};

/// What a query to a DNS-over-HTTPS server needs (docs/design.md §22): the URI template the
/// driver expands with the `dns` variable, or POSTs to (RFC 8484 §3, §4.1). cocuyo never reads
/// it: a URI is HTTP's. The slice is the caller's, as `Config.servers` is.
pub const Https = struct {
    template: []const u8,
    /// Whether the channel's handshakes must end on X25519MLKEM768, as `Tls.require_post_quantum`
    /// says for a TLS server (docs/design.md §21, TLS rule 10).
    require_post_quantum: bool = false,
};

/// How a configuration's servers are spoken to: every one the same way (docs/design.md §22,
/// §23).
pub const Transport = enum { cleartext, tls, https, quic };

/// One server: where a query goes over UDP, and the port a TCP connection uses when it differs,
/// which c-ares configures apart (docs/design.md §19 step 11). Zero means the same port. A
/// server that speaks TLS takes its connections on its TLS port instead.
pub const Server = struct {
    endpoint: Endpoint,
    tcp_port: u16 = 0,
    /// The TLS every query to this server goes over, or null for none. A configuration has TLS
    /// on every server or on none, which `Config.assert_valid` holds.
    tls: ?Tls = null,
    /// The HTTPS every query to this server goes over, or null for none (docs/design.md §22).
    https: ?Https = null,
    /// The QUIC every query to this server goes over, or null for none (docs/design.md §23).
    /// It is known as a TLS server is (RFC 9250 §5.1), and its port is UDP's.
    quic: ?Tls = null,

    /// How this server is spoken to: over TLS, HTTPS or QUIC, one of them at most, or in the
    /// clear.
    pub fn transport(self: *const Server) Transport {
        assert(self.kinds() <= 1);
        if (self.tls != null) return .tls;
        if (self.https != null) return .https;
        if (self.quic != null) return .quic;
        return .cleartext;
    }

    /// How many encrypted transports the server names: one at most is valid.
    fn kinds(self: *const Server) u8 {
        return @as(u8, @intFromBool(self.tls != null)) + @intFromBool(self.https != null) +
            @intFromBool(self.quic != null);
    }

    /// Where a stream to this server connects. A TLS server's is its TLS port, and never its
    /// cleartext one: a client that asked for TLS does not send a query in the clear (RFC 8310
    /// §5.1).
    pub fn tcp_endpoint(self: *const Server) Endpoint {
        var endpoint = self.endpoint;
        if (self.tls) |tls| {
            endpoint.port = tls.port;
        } else if (self.tcp_port != 0) {
            endpoint.port = self.tcp_port;
        }
        return endpoint;
    }
};

/// Where a name is looked up: the hosts file, or DNS. `Config.lookups` orders them, which is
/// c-ares's `lookups` option, `fb` by default (§19 step 11); the engine reads the order.
pub const Source = enum { file, dns };

pub const default_lookups = [_]Source{ .file, .dns };

pub const Config = struct {
    /// The servers to ask, in the order they are asked. At most `limits.servers_max`; none
    /// when a `resolv.conf` named none and the caller asked for no default, in which case every
    /// lookup fails at once with `NoServers`.
    servers: []const Server,
    /// The search list, in the order it is tried. May be empty.
    search: []const Name = &.{},
    /// The dot count that decides whether the name or the search list is tried first.
    ndots: u8 = constants.ndots_default,
    /// Passes over the server list before a lookup gives up.
    attempts: u8 = constants.attempts_default,
    /// The wait for a server until it has 3 samples of its latency; from then on its wait is
    /// five times its measured average (docs/design.md §5). Either is clamped to at least
    /// `limits.timeout_ns_min` and at most `timeout_ns_max`, and doubles per pass. 2 seconds
    /// by default, c-ares's `ARES_OPT_TIMEOUTMS`. It may be no more than `timeout_ns_max`, whose
    /// default is 5 seconds, so a configuration that sets it higher raises `timeout_ns_max` as
    /// far; before 2026-10-09 the default cap was 30 seconds and this needed no such care.
    timeout_ns: u64 = constants.timeout_ns_default,
    /// The UDP payload size cocuyo advertises in OPT, which is also the smallest receive buffer
    /// the caller may use. The engine receives into buffers of its own. Its `init` and `reinit`
    /// refuse a size above what one of them holds, `cocuyo_rotor.limits.udp_payload_bytes_max`
    /// (docs/design.md §19 step 13, the datagram's rule 7).
    udp_payload_bytes: u16 = constants.udp_payload_bytes_default,
    /// Whether to randomise the case of the qname (DNS-0x20) and require it back unchanged. On by
    /// default. A server that answers a mixed name in lowercase is asked in lowercase from then
    /// on, until its `Servers` table is built again, and every other server keeps 0x20; the
    /// response that showed it is ignored, so that lookup waits out its deadline, which counts as
    /// a latency sample as long as the wait. A server that changes the case any other way cannot
    /// be told from an echo of another query: every try at it runs out, and its wait rises to
    /// `timeout_ns_max`, so it still needs this off. Off, no query mixes the case (docs/design.md
    /// §5, What the rule costs, and §7, A server that changes the case).
    mix_case: bool = true,
    /// Whether to start the first pass at a server the seed chooses rather than at the first.
    rotate: bool = false,
    /// The cap on every wait, measured or doubled per pass: c-ares's `maxtimeout`. 5 seconds by
    /// default, and at most the constant of the same name, 30. At least `timeout_ns`, which
    /// `assert_valid` requires. A cap below `limits.timeout_ns_min` wins over that floor
    /// (docs/design.md §5).
    timeout_ns_max: u64 = constants.timeout_ns_max_default,
    /// Every query over TCP: `use-vc` in a `resolv.conf`, `ARES_FLAG_USEVC` in c-ares.
    use_tcp: bool = false,
    /// A truncated UDP answer is taken as it is rather than asked again over TCP
    /// (`ARES_FLAG_IGNTC`), and marked `truncated`, since records may be missing from it.
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
    /// The cap on every TTL the engine's cache keeps, in seconds: c-ares's `qcache_max_ttl`
    /// (`ARES_OPT_QUERY_CACHE`), and an hour by default as it is there. The engine hands it to
    /// the cache it builds, at `init` and at each `reinit`, and no lookup reads it; a caller
    /// that builds a `Cache` of its own hands `Cache.init` this or a cap of its own. At least
    /// 1: an engine is given no cache by handing it no memory, never by a cap of zero. At most
    /// `limits.cache_ttl_seconds_max`, seven days, the cap RFC 8767 §4 recommends. No line
    /// of a `resolv.conf` sets it (docs/design.md §16 decision 37, §19 step 13).
    cache_ttl_seconds_max: u32 = constants.cache_ttl_seconds_max_default,
    /// The first time a cache keeps a resolution failure of a name, in seconds: 5 s by default,
    /// and 1 s to 300 s, as RFC 9520 §3.2 asks. Each later failure after the entry expired
    /// doubles the time, to 300 s. The engine hands it to the cache it builds, at `init` and at
    /// each `reinit`; a caller that builds a `Cache` of its own sets `Cache.failure_seconds_min`
    /// from it. No line of a `resolv.conf` sets it (docs/design.md §16 decision 60).
    cache_failure_seconds_min: u32 = constants.cache_failure_seconds_min_default,

    /// Every rule a configuration must satisfy. A configuration is the caller's to build, so a
    /// broken one is a programmer error and asserts rather than returning (CLAUDE.md
    /// non-negotiable 3).
    pub fn assert_valid(self: *const Config) void {
        assert(self.servers.len <= limits.servers_max);
        assert(self.search.len <= limits.search_max);
        assert(self.attempts >= 1);
        assert(self.attempts <= limits.attempts_max);
        assert(self.timeout_ns >= 1);
        assert(self.timeout_ns <= self.timeout_ns_max);
        assert(self.timeout_ns_max <= limits.timeout_ns_max);
        assert(self.udp_payload_bytes >= limits.udp_payload_bytes_min);
        assert(self.udp_payload_bytes <= limits.message_bytes_max);
        assert(self.lookups.len <= limits.lookup_sources_max);
        // A cap of zero would lower every TTL to zero, and a record with a TTL of zero "should
        // not be cached" (RFC 1035 §3.2.1, as `Cache.put` cites it): handing an engine no memory
        // is what turns its cache off (docs/design.md §19 step 13).
        assert(self.cache_ttl_seconds_max >= 1);
        // "Values SHOULD be capped on the order of days to weeks, with a recommended cap of
        // 604,800 seconds (7 days)" (RFC 8767 §4): no configuration caps later than that.
        assert(self.cache_ttl_seconds_max <= limits.cache_ttl_seconds_max);
        // "at least 1 second", and "not longer than 5 minutes" (RFC 9520 §3.2).
        assert(self.cache_failure_seconds_min >= limits.cache_failure_seconds_least);
        assert(self.cache_failure_seconds_min <= limits.cache_failure_seconds_max);
        assert(servers_agree(self.servers));
        // Every query on a stream means TCP, and a DoH or DoQ server takes each query as an
        // request of its own (docs/design.md §22, §23).
        assert(!(self.use_tcp and self.sends_requests()));
        for (self.servers) |server| {
            if (server.tls) |tls| assert(tls.valid());
            if (server.quic) |quic| {
                assert(quic.valid());
                // "DoQ connections MUST NOT use UDP port 53" (RFC 9250 §4.1.1).
                assert(quic.port != constants.port_dns_default);
            }
        }
    }

    /// How every server of the configuration is spoken to.
    pub fn transport(self: *const Config) Transport {
        if (self.servers.len == 0) return .cleartext;
        return self.servers[0].transport();
    }

    /// Whether the servers are DNS-over-TLS servers. Every one is or none is.
    pub fn uses_tls(self: *const Config) bool {
        return self.transport() == .tls;
    }

    /// Whether the servers are DNS-over-HTTPS servers (docs/design.md §22).
    pub fn uses_https(self: *const Config) bool {
        return self.transport() == .https;
    }

    /// Whether the servers are DNS-over-QUIC servers (docs/design.md §23).
    pub fn uses_quic(self: *const Config) bool {
        return self.transport() == .quic;
    }

    /// Whether each query is a request of its own, over DoH or DoQ: HTTP or QUIC pairs it with
    /// its answer, and not its ID (docs/design.md §22, §23).
    pub fn sends_requests(self: *const Config) bool {
        return switch (self.transport()) {
            .https, .quic => true,
            .cleartext, .tls => false,
        };
    }

    /// Whether a query goes encrypted, which is when it is padded (RFC 7830 §6).
    pub fn encrypted(self: *const Config) bool {
        return self.transport() != .cleartext;
    }

    /// Whether every query goes on a stream: `use_tcp` says so, or the servers speak TLS, which
    /// has no datagram form here.
    pub fn streams_only(self: *const Config) bool {
        return self.use_tcp or self.uses_tls();
    }

    /// How many servers a lookup may ask: with `primary`, the first is the only one.
    pub fn server_count(self: *const Config) usize {
        if (self.primary and self.servers.len >= 1) return 1;
        return self.servers.len;
    }
};

/// Whether every server is spoken to one way: in the clear, or over TLS, HTTPS or QUIC. A list
/// that mixed them would let a lookup fail over from an encrypted server to a cleartext one:
/// under RFC 8310's strict profile a server that cannot be reached encrypted is a hard failure
/// (§5), and a query never falls back during its resolution (§5.1). DoH and DoQ are held to the
/// same (docs/design.md §22, §23; RFC 9250 §5.1). A server that names two transports is refused.
pub fn servers_agree(servers: []const Server) bool {
    for (servers) |server| {
        if (server.kinds() > 1) return false;
        if (server.transport() != servers[0].transport()) return false;
    }
    return true;
}

// Tests.

const testing = std.testing;
test "the defaults are the resolv.conf defaults, c-ares's waits, and are valid" {
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) } }};
    const config: Config = .{ .servers = &servers };
    config.assert_valid();
    try testing.expectEqual(@as(u8, 1), config.ndots);
    try testing.expect(config.recursion_desired);
    try testing.expect(config.check_response);
    try testing.expect(!config.use_tcp and !config.ignore_truncation and !config.primary);
    try testing.expectEqual(@as(u64, 5_000_000_000), config.timeout_ns_max);
    try testing.expectEqualSlices(Source, &default_lookups, config.lookups);
    try testing.expectEqual(@as(u8, 2), config.attempts);
    try testing.expectEqual(@as(u64, 2_000_000_000), config.timeout_ns);
    try testing.expectEqual(@as(u16, 1232), config.udp_payload_bytes);
    try testing.expect(config.mix_case);
    try testing.expect(!config.rotate);
    try testing.expectEqual(@as(usize, 0), config.search.len);
}

test "the cache's TTL cap is c-ares's hour by default, and a cap of a second to seven days is valid" {
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) } }};
    const config: Config = .{ .servers = &servers };
    try testing.expectEqual(@as(u32, 3600), config.cache_ttl_seconds_max);
    // The least cap keeps an answer a second, and the most keeps one seven days, "a recommended
    // cap of 604,800 seconds (7 days)" (RFC 8767 §4).
    try testing.expectEqual(@as(u32, 604_800), limits.cache_ttl_seconds_max);
    for ([_]u32{ 1, 300, limits.cache_ttl_seconds_max }) |cap| {
        const capped: Config = .{ .servers = &servers, .cache_ttl_seconds_max = cap };
        capped.assert_valid();
        try testing.expectEqual(cap, capped.cache_ttl_seconds_max);
    }
}

test "the first time a failure is kept is 5 s by default, and a time of 1 s to 300 s is valid" {
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) } }};
    const config: Config = .{ .servers = &servers };
    try testing.expectEqual(@as(u32, 5), config.cache_failure_seconds_min);
    // "at least 1 second", and "not longer than 5 minutes" (RFC 9520 §3.2).
    try testing.expectEqual(@as(u32, 1), limits.cache_failure_seconds_least);
    try testing.expectEqual(@as(u32, 300), limits.cache_failure_seconds_max);
    for ([_]u32{ limits.cache_failure_seconds_least, 30, limits.cache_failure_seconds_max }) |seconds| {
        const kept: Config = .{ .servers = &servers, .cache_failure_seconds_min = seconds };
        kept.assert_valid();
        try testing.expectEqual(seconds, kept.cache_failure_seconds_min);
    }
}

test "a TLS or HTTPS server does not require the post-quantum hybrid unless it says so" {
    // docs/design.md §21, TLS rule 10: off by default, the hello offers the hybrid and two
    // classic groups, so a server without the hybrid still answers.
    const tls: Tls = .{ .name = try Name.from_text("dns.example.") };
    const https: Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    try testing.expect(!tls.require_post_quantum);
    try testing.expect(!https.require_post_quantum);
}

test "a search list at the limit is valid" {
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 127, 0, 0, 1 }) } }};
    const search: [limits.search_max]Name = @splat(Name.root);
    const config: Config = .{ .servers = &servers, .search = &search };
    config.assert_valid();
    try testing.expectEqual(@as(usize, limits.search_max), config.search.len);
}

test "a TCP port of its own replaces the UDP port for a connection, and zero keeps it" {
    const endpoint: Endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }), .port = 53 };
    const same: Server = .{ .endpoint = endpoint };
    try testing.expectEqual(@as(u16, 53), same.tcp_endpoint().port);
    const other: Server = .{ .endpoint = endpoint, .tcp_port = 5353 };
    try testing.expectEqual(@as(u16, 5353), other.tcp_endpoint().port);
    try testing.expect(other.tcp_endpoint().address.equal(&endpoint.address));
}

test "servers speak TLS all together or not at all, and TLS sends every query on a stream" {
    const address = Address.from_v4(.{ 192, 0, 2, 53 });
    const tls: Tls = .{ .name = try Name.from_text("dns.example.") };
    const encrypted = [_]Server{ .{ .endpoint = .{ .address = address }, .tls = tls }, .{ .endpoint = .{ .address = address }, .tls = tls } };
    const mixed = [_]Server{ .{ .endpoint = .{ .address = address }, .tls = tls }, .{ .endpoint = .{ .address = address } } };
    const cleartext = [_]Server{ .{ .endpoint = .{ .address = address } }, .{ .endpoint = .{ .address = address } } };
    try testing.expect(servers_agree(&encrypted));
    try testing.expect(servers_agree(&cleartext));
    try testing.expect(!servers_agree(&mixed));
    const reversed = [_]Server{ cleartext[0], encrypted[0] };
    try testing.expect(!servers_agree(&reversed));
    const config: Config = .{ .servers = &encrypted };
    config.assert_valid();
    try testing.expect(config.uses_tls() and config.streams_only());
    try testing.expectEqual(@as(u16, 853), encrypted[0].tcp_endpoint().port);
    const ported: Server = .{ .endpoint = .{ .address = address }, .tcp_port = 5353, .tls = .{ .name = tls.name, .port = 8853 } };
    try testing.expectEqual(@as(u16, 8853), ported.tcp_endpoint().port);
    const plain: Config = .{ .servers = &cleartext };
    try testing.expect(!plain.uses_tls() and !plain.streams_only());
    const none: Config = .{ .servers = &.{} };
    try testing.expect(!none.uses_tls());
}

test "a TLS server is known by its name, its pins, or both, and by no more pins than the bound" {
    const name = try Name.from_text("dns.example.");
    const pins: [limits.spki_pins_max + 1]Pin = @splat(@splat(0xab));
    const by_name: Tls = .{ .name = name };
    const by_pins: Tls = .{ .pins = pins[0..1] };
    const by_both: Tls = .{ .name = name, .pins = pins[0..limits.spki_pins_max] };
    try testing.expect(by_name.valid() and by_pins.valid() and by_both.valid());
    const by_nothing: Tls = .{};
    const too_many: Tls = .{ .name = name, .pins = &pins };
    try testing.expect(!by_nothing.valid());
    try testing.expect(!too_many.valid());
    const servers = [_]Server{.{ .endpoint = .{ .address = Address.from_v4(.{ 192, 0, 2, 53 }) }, .tls = by_pins }};
    const config: Config = .{ .servers = &servers };
    config.assert_valid();
}

test "servers speak HTTPS all together, never beside TLS or the clear, and never both at once" {
    const address = Address.from_v4(.{ 192, 0, 2, 53 });
    const https: Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    const tls: Tls = .{ .name = try Name.from_text("dns.example.") };
    const over_https = [_]Server{ .{ .endpoint = .{ .address = address }, .https = https }, .{ .endpoint = .{ .address = address }, .https = https } };
    try testing.expect(servers_agree(&over_https));
    const config: Config = .{ .servers = &over_https };
    config.assert_valid();
    try testing.expect(config.uses_https() and !config.uses_tls() and config.encrypted());
    try testing.expect(!config.streams_only());
    const beside_tls = [_]Server{ .{ .endpoint = .{ .address = address }, .https = https }, .{ .endpoint = .{ .address = address }, .tls = tls } };
    const beside_clear = [_]Server{ .{ .endpoint = .{ .address = address } }, .{ .endpoint = .{ .address = address }, .https = https } };
    const both = [_]Server{.{ .endpoint = .{ .address = address }, .tls = tls, .https = https }};
    try testing.expect(!servers_agree(&beside_tls));
    try testing.expect(!servers_agree(&beside_clear));
    try testing.expect(!servers_agree(&both));
}

test "servers speak QUIC all together, known as a TLS server is, and never beside another kind" {
    const address = Address.from_v4(.{ 192, 0, 2, 53 });
    const quic: Tls = .{ .name = try Name.from_text("dns.example.") };
    const over_quic = [_]Server{ .{ .endpoint = .{ .address = address }, .quic = quic }, .{ .endpoint = .{ .address = address }, .quic = quic } };
    try testing.expect(servers_agree(&over_quic));
    const config: Config = .{ .servers = &over_quic };
    config.assert_valid();
    try testing.expect(config.uses_quic() and config.sends_requests() and config.encrypted());
    try testing.expect(!config.uses_https() and !config.uses_tls() and !config.streams_only());
    // Port 853 unless agreed otherwise (RFC 9250 §4.1.1), and no server known by nothing.
    try testing.expectEqual(constants.port_dns_tls_default, quic.port);
    try testing.expect(!(Tls{}).valid());
    const https: Https = .{ .template = "https://dns.example/dns-query{?dns}" };
    const beside_https = [_]Server{ .{ .endpoint = .{ .address = address }, .quic = quic }, .{ .endpoint = .{ .address = address }, .https = https } };
    const beside_clear = [_]Server{ .{ .endpoint = .{ .address = address }, .quic = quic }, .{ .endpoint = .{ .address = address } } };
    const both = [_]Server{.{ .endpoint = .{ .address = address }, .tls = quic, .quic = quic }};
    try testing.expect(!servers_agree(&beside_https));
    try testing.expect(!servers_agree(&beside_clear));
    try testing.expect(!servers_agree(&both));
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
