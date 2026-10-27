//! The queries one lookup sends each server for one name, and the walk over the servers that this
//! count bounds (docs/design.md §5, retry policy; §16 decision 58). "A resolver MUST NOT retry a
//! given query to a server address over a given DNS transport more than twice (i.e., three queries
//! in total)" (RFC 9520 §3.1). `Config.attempts` counts the passes over the server list, and
//! FORMERR and BADCOOKIE each add a retry inside a pass. So without this count, one server could
//! get more than three queries of one name over one transport.
//!
//! The lookup counts the queries that it sent, at `on_sent`, for each position in its order and for
//! each transport. A send that failed did not reach the server, so it does not count. A new name,
//! the next search candidate or a CNAME's target, starts each count again at zero. A server with
//! no query left is passed over, and a retry that the bound forbids moves the lookup to the next
//! server. A pass over a server records no failure and no sample of it: the lookup sent it
//! nothing. A FORMERR or a BADCOOKIE whose retry the bound forbids fails the server with its rcode
//! (docs/design.md §5, §19 step 12). TC=1 at the bound records the sample of its reply, and keeps
//! no cause.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const lookup_module = @import("lookup.zig");
const Lookup = lookup_module.Lookup;
const limits = @import("limits.zig");

/// How a query goes to its server: as a datagram, over UDP or as a DoH or DoQ request, or on a
/// stream, over TCP or TLS. Each is one DNS transport of RFC 9520 §3.1.
pub const Transport = enum(u1) { datagram, stream };

/// One count of queries: zero to `queries_per_transport_max`.
const Count = u2;
const transport_count = std.enums.values(Transport).len;
const Bits = std.meta.Int(.unsigned, core.limits.servers_max * transport_count * @bitSizeOf(Count));
const Shift = std.math.Log2Int(Bits);

comptime {
    assert(limits.queries_per_transport_max <= std.math.maxInt(Count));
}

/// The queries sent for the current name: a `Count` for each position in the order and each
/// transport, packed into one word, so that the lookup grows by four octets and not by sixteen.
pub const Sends = struct {
    bits: Bits = 0,

    fn shift(position: u8, transport: Transport) Shift {
        assert(position < core.limits.servers_max);
        const index = @as(usize, position) * transport_count + @intFromEnum(transport);
        return @intCast(index * @bitSizeOf(Count));
    }

    /// The queries sent to the server at `position` over `transport`.
    pub fn count(self: Sends, position: u8, transport: Transport) usize {
        const sent: Count = @truncate(self.bits >> shift(position, transport));
        assert(sent <= limits.queries_per_transport_max);
        return sent;
    }

    /// One more query sent. The checks before each send hold the count under the bound, so a
    /// count at the bound here is a programmer error (RFC 9520 §3.1).
    pub fn add(self: *Sends, position: u8, transport: Transport) void {
        const before = self.count(position, transport);
        assert(before < limits.queries_per_transport_max);
        self.bits += @as(Bits, 1) << shift(position, transport);
        assert(self.count(position, transport) == before + 1);
    }
};

/// The transport a query goes over when the lookup starts on a server: a stream when every query
/// goes on one, under `use_tcp` or to a TLS server (§19 step 11, §21), and a datagram otherwise.
pub fn fresh(self: *const Lookup) Transport {
    return if (self.config.streams_only()) .stream else .datagram;
}

/// Whether the current server has had its queries for the current name over `transport`, so that
/// the lookup may not ask it again over that transport (RFC 9520 §3.1).
pub fn spent(self: *const Lookup, transport: Transport) bool {
    assert(self.server_index < self.config.server_count());
    return self.sends.count(self.server_index, transport) >= limits.queries_per_transport_max;
}

/// The query went out: one more for its server over its transport.
pub fn count_sent(self: *Lookup) void {
    assert(self.state == .query_ready or self.state == .tcp_ready);
    const transport: Transport = if (self.state == .query_ready) .datagram else .stream;
    self.sends.add(self.server_index, transport);
}

/// The same server, over a stream: after TC=1, or a datagram that the buffer cut (RFC 7766 §5).
/// When the server has had its queries for the name on a stream, the lookup moves to the next
/// server instead (RFC 9520 §3.1). The reply is no failure of the server, so it keeps no cause.
pub fn to_stream(self: *Lookup, now_ns: u64) void {
    assert(self.state == .awaiting_udp);
    if (spent(self, .stream)) {
        self.next_server(now_ns);
    } else {
        self.state = .tcp_needed;
    }
    assert(self.state != .awaiting_udp);
}

/// The next server, then the next pass, then the end (docs/design.md §5, retry policy). A server
/// that has had its queries for the name over the transport the lookup starts on is passed over,
/// and the walk goes on to the next (RFC 9520 §3.1). When no server is left, the lookup ends as
/// the last pass ends.
pub fn next_server(self: *Lookup, now_ns: u64) void {
    assert(!self.is_settled());
    self.flags.cookie_retried = false;
    self.flags.edns_enabled = true;
    const positions_max = core.limits.servers_max * core.limits.attempts_max;
    for (0..positions_max) |_| {
        self.server_index += 1;
        if (self.server_index == self.config.server_count()) {
            self.server_index = 0;
            self.round += 1;
        }
        if (self.round == self.config.attempts) {
            // A server that failed the lookup left a cause; silence leaves none (§16 decision 25).
            self.fail(if (self.cause.what != .none)
                core.Error.AllServersFailed
            else
                core.Error.Timeout);
            return;
        }
        if (!spent(self, fresh(self))) break;
    } else unreachable;
    assert(self.round < self.config.attempts);
    assert(!spent(self, fresh(self)));
    self.restart(now_ns);
}
