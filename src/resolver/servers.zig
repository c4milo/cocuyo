//! Per-server state that outlives one lookup: the DNS cookies of RFC 7873 and RFC 9018
//! (docs/design.md §19 step 10), and the failover counters of step 12. A configuration is shared
//! and constant and a lookup is one question, so this is a third thing, owned by the caller —
//! `Resolver` holds one for its table — and handed to every lookup by pointer.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const Config = core.Config;
const Endpoint = core.Endpoint;

pub const ServerState = struct {
    /// The client cookie that drew `cookie_server`: the pair every query to this server carries
    /// once `cookie_server_len` is above zero, as the client "should store the Client Cookie
    /// alongside the Server Cookie it registered for that server" (RFC 9018 §3). It means nothing
    /// while no server cookie is known: a query then carries a client cookie of its own
    /// transaction (docs/design.md §19 step 10).
    cookie_client: [core.constants.cookie_client_bytes]u8,
    /// The server cookie it last answered with, `cookie_server_len` octets of it; zero until
    /// one is learned (RFC 7873 §5.3).
    cookie_server: [core.constants.cookie_server_bytes_max]u8,
    cookie_server_len: u8,
    /// Until this instant a query to this server carries no COOKIE option: it answered a client
    /// cookie without one and has given no server cookie (RFC 9018 §3). Zero when it has not.
    cookie_silent_until_ns: u64,
    /// Consecutive failures: timeouts, failed sends, failed connections and requests, and
    /// answers that mark the server's failure, SERVFAIL among them. Any other answer a lookup
    /// accepts resets it, and a response it ignores leaves it (docs/design.md §19 step 12).
    failures: u8,
    /// When the last of them happened.
    failed_at_ns: u64,
};

/// The COOKIE option a query carries (docs/design.md §19 step 10).
pub const CookieForm = enum(u8) {
    /// None: the query has no OPT record, goes over DoH or DoQ, or goes to a server in its
    /// silence.
    none,
    /// A client cookie of the lookup's own transaction, never sent before (RFC 9018 §8.1).
    fresh,
    /// The server's pair: its server cookie and the client cookie that drew it (RFC 7873 §5.1).
    paired,
};

pub const Servers = struct {
    states: [core.constants.servers_max]ServerState,
    count: u8,
    /// The caller's seed, mixed into every fresh client cookie with the transaction's own draw:
    /// a table built anew with a new seed draws its cookies from a new secret too.
    secret: u64,

    /// One state per configured server, in the configuration's order, with no server cookie and
    /// no silence.
    pub fn init(config: *const Config, seed: u64) Servers {
        config.assert_valid();
        var servers: Servers = .{ .states = undefined, .count = @intCast(config.servers.len), .secret = seed };
        for (0..config.servers.len) |index| {
            servers.states[index] = .{
                .cookie_client = @splat(0),
                .cookie_server = @splat(0),
                .cookie_server_len = 0,
                .cookie_silent_until_ns = 0,
                .failures = 0,
                .failed_at_ns = 0,
            };
        }
        assert(servers.count <= core.constants.servers_max);
        return servers;
    }

    pub fn state(self: *const Servers, index: usize) *const ServerState {
        assert(index < self.count);
        return &self.states[index];
    }

    /// The COOKIE option a query with an OPT record carries to server `index` at `now_ns`: the
    /// pair once the server has given a server cookie (RFC 7873 §5.1), none through its silence,
    /// and a fresh client cookie otherwise (RFC 9018 §3).
    pub fn cookie_form(self: *const Servers, index: usize, now_ns: u64) CookieForm {
        const entry = self.state(index);
        // A server that gave a cookie has cookies, whatever answered without one before.
        if (entry.cookie_server_len > 0) return .paired;
        // "it is recommended that the client does not send a Client Cookie to that server for a
        // certain period (for example, five minutes)" (RFC 9018 §3).
        if (now_ns < entry.cookie_silent_until_ns) return .none;
        return .fresh;
    }

    /// The pair a query to server `index` carries once it has given a server cookie: the client
    /// cookie that drew it, and the server cookie (RFC 7873 §5.1, RFC 9018 §3).
    pub fn cookie(self: *const Servers, index: usize) wire.Cookie {
        const entry = self.state(index);
        assert(entry.cookie_server_len >= core.constants.cookie_server_bytes_min);
        return .{
            .client = entry.cookie_client,
            .server = entry.cookie_server,
            .server_len = entry.cookie_server_len,
        };
    }

    /// A fresh client cookie for a query to `endpoint`, made from the transaction's `draw`: a
    /// new transaction makes a new one, and so does a move to a stream, which keeps its
    /// transaction (docs/design.md §19 step 10).
    pub fn fresh_cookie(
        self: *const Servers,
        draw: u64,
        endpoint: *const Endpoint,
        stream: bool,
    ) [core.constants.cookie_client_bytes]u8 {
        return client_cookie(self.secret ^ draw, endpoint, stream);
    }

    /// Whether a response from server `index` must carry a COOKIE option: it must once the
    /// server has answered with a cookie (RFC 7873 §5.3, "expecting").
    pub fn expecting(self: *const Servers, index: usize) bool {
        return self.state(index).cookie_server_len > 0;
    }

    /// One more failure, at `now_ns`: silence, a refusal, or an answer that marks the server's
    /// failure. Saturates: a server down for a week is as down as one down for a day.
    pub fn record_failure(self: *Servers, index: usize, now_ns: u64) void {
        assert(index < self.count);
        const entry = &self.states[index];
        entry.failures +|= 1;
        entry.failed_at_ns = now_ns;
        assert(entry.failures >= 1);
    }

    /// An answer that marks no failure of the server's: the server is up.
    pub fn record_success(self: *Servers, index: usize) void {
        assert(index < self.count);
        self.states[index].failures = 0;
    }

    pub fn failures(self: *const Servers, index: usize) u8 {
        return self.state(index).failures;
    }

    /// Keeps the pair a response carried: the client cookie the lookup sent, which the response
    /// echoed, and the server cookie beside it, cached "even if the response is an error
    /// response" (RFC 7873 §5.3). A server that gave one has cookies, and `cookie_form` puts its
    /// pair before any silence. The caller has checked the client cookie; the length was checked
    /// when the option was read.
    pub fn learn(
        self: *Servers,
        index: usize,
        client: *const [core.constants.cookie_client_bytes]u8,
        server_cookie: []const u8,
    ) void {
        assert(index < self.count);
        assert(server_cookie.len >= core.constants.cookie_server_bytes_min);
        assert(server_cookie.len <= core.constants.cookie_server_bytes_max);
        const entry = &self.states[index];
        entry.cookie_client = client.*;
        @memcpy(entry.cookie_server[0..server_cookie.len], server_cookie);
        entry.cookie_server_len = @intCast(server_cookie.len);
        assert(self.expecting(index));
    }

    /// Server `index`, which has given no server cookie, answered a client cookie without a
    /// COOKIE option at `now_ns`: it does not support cookies, and "the client MUST NOT send the
    /// same Client Cookie to that same server again" (RFC 9018 §3). It is sent none for
    /// `cookie_silence_ns`.
    pub fn silence(self: *Servers, index: usize, now_ns: u64) void {
        assert(index < self.count);
        assert(!self.expecting(index));
        const entry = &self.states[index];
        entry.cookie_silent_until_ns = now_ns +| constants.cookie_silence_ns;
        assert(entry.cookie_silent_until_ns > now_ns);
    }
};

/// A client cookie: "Client-Cookie = 64 bits of entropy" (RFC 9018 §3), the draw, with the address
/// and port the query goes to mixed in, since "a client MUST use a different Client Cookie for each
/// different Server IP address", and whether it goes over a stream. The mix is `core.mix`, with
/// §7's caveat: it spreads a seed rather than hiding it, and the defence is against a peer who sees
/// no cookie at all.
fn client_cookie(
    draw: u64,
    endpoint: *const Endpoint,
    stream: bool,
) [core.constants.cookie_client_bytes]u8 {
    var word = core.mix.next(draw ^ endpoint.port);
    word = core.mix.next(word ^ @intFromEnum(endpoint.address.family));
    word = core.mix.next(word ^ @intFromBool(stream));
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

/// A server cookie of the length RFC 9018 §4 fixes.
const learned = fixtures.server_cookie;

test "a fresh cookie differs per draw, per server, per transport and per seed, and repeats for none" {
    const config: Config = .{ .servers = &fixtures.servers_two };
    const servers = Servers.init(&config, 1);
    const other_seed = Servers.init(&config, 2);
    const first = &fixtures.servers_two[0].endpoint;
    const second = &fixtures.servers_two[1].endpoint;
    const cookie = servers.fresh_cookie(7, first, false);
    try testing.expectEqualSlices(u8, &cookie, &servers.fresh_cookie(7, first, false));
    try testing.expect(!std.mem.eql(u8, &cookie, &servers.fresh_cookie(8, first, false)));
    try testing.expect(!std.mem.eql(u8, &cookie, &servers.fresh_cookie(7, second, false)));
    try testing.expect(!std.mem.eql(u8, &cookie, &servers.fresh_cookie(7, first, true)));
    try testing.expect(!std.mem.eql(u8, &cookie, &other_seed.fresh_cookie(7, first, false)));
    try testing.expectEqual(@as(u8, 2), servers.count);
}

test "a server is sent a fresh cookie, then its pair once it gave a server cookie" {
    const config: Config = .{ .servers = &fixtures.servers_two };
    var servers = Servers.init(&config, 1);
    try testing.expect(!servers.expecting(0));
    try testing.expectEqual(CookieForm.fresh, servers.cookie_form(0, 0));
    const client = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    servers.learn(0, &client, &learned);
    try testing.expect(servers.expecting(0));
    try testing.expect(!servers.expecting(1));
    try testing.expectEqual(CookieForm.paired, servers.cookie_form(0, 0));
    try testing.expectEqual(CookieForm.fresh, servers.cookie_form(1, 0));
    const pair = servers.cookie(0);
    try testing.expectEqual(@as(u8, 16), pair.server_len);
    try testing.expectEqualSlices(u8, &learned, pair.server[0..16]);
    try testing.expectEqualSlices(u8, &client, &pair.client);
}

test "a server without cookies is sent none for five minutes, then a fresh one" {
    const config: Config = .{ .servers = &fixtures.servers_two };
    var servers = Servers.init(&config, 1);
    const at_ns = 1_000;
    servers.silence(0, at_ns);
    try testing.expectEqual(CookieForm.none, servers.cookie_form(0, at_ns));
    try testing.expectEqual(CookieForm.none, servers.cookie_form(0, at_ns + constants.cookie_silence_ns - 1));
    try testing.expectEqual(CookieForm.fresh, servers.cookie_form(0, at_ns + constants.cookie_silence_ns));
    try testing.expectEqual(CookieForm.fresh, servers.cookie_form(1, at_ns));
    // A server cookie learned through the silence ends it.
    servers.silence(1, at_ns);
    servers.learn(1, &@as([core.constants.cookie_client_bytes]u8, @splat(9)), &learned);
    try testing.expectEqual(CookieForm.paired, servers.cookie_form(1, at_ns));
}

test "failures count up until an answer resets them, and the instant is the last one's" {
    const config: Config = .{ .servers = &fixtures.servers_two };
    var servers = Servers.init(&config, 1);
    try testing.expectEqual(@as(u8, 0), servers.failures(0));
    servers.record_failure(0, 10);
    servers.record_failure(0, 20);
    try testing.expectEqual(@as(u8, 2), servers.failures(0));
    try testing.expectEqual(@as(u64, 20), servers.state(0).failed_at_ns);
    try testing.expectEqual(@as(u8, 0), servers.failures(1));
    servers.record_success(0);
    try testing.expectEqual(@as(u8, 0), servers.failures(0));
}
