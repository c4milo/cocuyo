//! Per-server state that outlives one lookup: the DNS cookies of RFC 7873 (docs/design.md §19
//! step 10), and the failover counters of step 12 to come. A configuration is shared and
//! constant and a lookup is one question, so this is a third thing, owned by the caller —
//! `Resolver` holds one for its table — and handed to every lookup by pointer.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const Config = core.Config;
const Endpoint = core.Endpoint;

pub const ServerState = struct {
    /// The client cookie for this server, fixed for the life of the table (RFC 7873 §4.1).
    cookie_client: [core.constants.cookie_client_bytes]u8,
    /// The server cookie it last answered with, `cookie_server_len` octets of it; zero until
    /// one is learned (RFC 7873 §5.3).
    cookie_server: [core.constants.cookie_server_bytes_max]u8,
    cookie_server_len: u8,
};

pub const Servers = struct {
    states: [core.constants.servers_max]ServerState,
    count: u8,

    /// One state per configured server, in the configuration's order, each with its client
    /// cookie derived from `seed` and the server's endpoint.
    pub fn init(config: *const Config, seed: u64) Servers {
        config.assert_valid();
        var servers: Servers = .{ .states = undefined, .count = @intCast(config.servers.len) };
        for (config.servers, 0..) |*server, index| {
            servers.states[index] = .{
                .cookie_client = client_cookie(seed, &server.endpoint),
                .cookie_server = @splat(0),
                .cookie_server_len = 0,
            };
        }
        assert(servers.count <= core.constants.servers_max);
        return servers;
    }

    pub fn state(self: *const Servers, index: usize) *const ServerState {
        assert(index < self.count);
        return &self.states[index];
    }

    /// What a query to server `index` carries: the client cookie, and the server cookie once
    /// learned (RFC 7873 §5.1).
    pub fn cookie(self: *const Servers, index: usize) wire.Cookie {
        const entry = self.state(index);
        return .{
            .client = entry.cookie_client,
            .server = entry.cookie_server,
            .server_len = entry.cookie_server_len,
        };
    }

    /// Whether a response from server `index` must carry a COOKIE option: it must once the
    /// server has answered with a cookie (RFC 7873 §5.3, "expecting").
    pub fn expecting(self: *const Servers, index: usize) bool {
        return self.state(index).cookie_server_len > 0;
    }

    /// Caches the server cookie a response carried (RFC 7873 §5.3). The caller has checked the
    /// client cookie beside it; the length was checked when the option was read.
    pub fn learn(self: *Servers, index: usize, server_cookie: []const u8) void {
        assert(index < self.count);
        assert(server_cookie.len >= core.constants.cookie_server_bytes_min);
        assert(server_cookie.len <= core.constants.cookie_server_bytes_max);
        const entry = &self.states[index];
        @memcpy(entry.cookie_server[0..server_cookie.len], server_cookie);
        entry.cookie_server_len = @intCast(server_cookie.len);
    }
};

/// The client cookie for one server: "a pseudorandom function of the Client IP address, the
/// Server IP address, and a secret quantity known only to the client" (RFC 7873 §4.1). The
/// secret is the caller's seed and the server's address and port are mixed in; the client's own
/// address is not known before a socket is bound and is left out, which docs/design.md §19
/// step 10 records with what it gives up. The mix is `core.mix`, with §7's caveat: it spreads a
/// seed rather than hiding it, and the defence is against a peer who sees no cookie at all.
fn client_cookie(seed: u64, endpoint: *const Endpoint) [core.constants.cookie_client_bytes]u8 {
    var word = core.mix.next(seed ^ endpoint.port);
    word = core.mix.next(word ^ @intFromEnum(endpoint.address.family));
    // The sixteen address octets, a word at a time.
    var offset: usize = 0;
    while (offset < endpoint.address.octets.len) : (offset += @sizeOf(u64)) {
        const chunk = std.mem.readInt(u64, endpoint.address.octets[offset..][0..@sizeOf(u64)], .little);
        word = core.mix.next(word ^ chunk);
    }
    assert(offset == endpoint.address.octets.len);
    var bytes: [core.constants.cookie_client_bytes]u8 = undefined;
    std.mem.writeInt(u64, &bytes, word, .little);
    return bytes;
}

// Tests.

const testing = std.testing;
const fixtures = @import("fixtures.zig");

test "each server gets its own client cookie, the same one for the same seed" {
    const config: Config = .{ .servers = &fixtures.servers_two };
    const first = Servers.init(&config, 1);
    const again = Servers.init(&config, 1);
    const other_seed = Servers.init(&config, 2);
    try testing.expectEqualSlices(u8, &first.state(0).cookie_client, &again.state(0).cookie_client);
    try testing.expect(!std.mem.eql(u8, &first.state(0).cookie_client, &first.state(1).cookie_client));
    try testing.expect(!std.mem.eql(u8, &first.state(0).cookie_client, &other_seed.state(0).cookie_client));
    try testing.expectEqual(@as(u8, 2), first.count);
}

test "a learned server cookie is what the next query carries, and nothing is expected before" {
    const config: Config = .{ .servers = &fixtures.servers_two };
    var servers = Servers.init(&config, 1);
    try testing.expect(!servers.expecting(0));
    try testing.expectEqual(@as(u8, 0), servers.cookie(0).server_len);
    const learned = [_]u8{0xc0} ++ [_]u8{0xcc} ** 15;
    servers.learn(0, &learned);
    try testing.expect(servers.expecting(0));
    try testing.expect(!servers.expecting(1));
    const cookie = servers.cookie(0);
    try testing.expectEqual(@as(u8, 16), cookie.server_len);
    try testing.expectEqualSlices(u8, &learned, cookie.server[0..16]);
    try testing.expectEqualSlices(u8, &servers.state(0).cookie_client, &cookie.client);
}
