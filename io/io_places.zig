//! The places of an engine's operations (docs/design.md §26, one operation for each place). A
//! place holds one operation in flight at most, from its submit to its final event, in a slot of
//! the engine's table that is its own. So the count of places bounds the operations in flight,
//! and the table never fills.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const Origin = @import("io_operations.zig").Origin;
const Kind = @import("io.zig").Kind;

/// A connection's places, in their order: its connect, its receive and its send of the session's
/// records.
const ConnectionPlace = enum(u32) { connect, receive, records_send };

/// A channel's places, in their order: its QUIC link's receive and send, then its TCP link's
/// connect, receive and send.
const ChannelPlace = enum(u32) { quic_receive, quic_send, tcp_connect, tcp_receive, tcp_send };

comptime {
    assert(@typeInfo(ConnectionPlace).@"enum".fields.len == limits.loop_operations_per_connection_max);
    assert(@typeInfo(ChannelPlace).@"enum".fields.len == limits.loop_operations_per_channel_max);
}

/// The places of an engine of `lookups` lookups, `connections` TCP connections, and a QUIC
/// connection or a channel for each of `quic_servers` and `doh_servers` servers.
pub fn Places(comptime lookups: u32, comptime connections: u32, comptime quic_servers: u32, comptime doh_servers: u32) type {
    return struct {
        // The limits are `usize`. Written as `u32`, they keep each place a `u32` (docs/design.md
        // §16 decision 40).
        const receives_per_server: u32 = limits.udp_receives_per_server_max;
        const per_connection: u32 = limits.loop_operations_per_connection_max;
        const per_quic_connection: u32 = limits.loop_operations_per_quic_connection_max;
        const per_channel: u32 = limits.loop_operations_per_channel_max;

        /// A lookup's send, of a datagram or of a query on a stream. Its buffer is lent until
        /// the send's final event, so a lookup has one send in flight (the stream's rule 6).
        const sends_at: u32 = 0;
        /// Each server's two receives: its current socket's and its draining socket's.
        const receives_at: u32 = sends_at + lookups;
        const timer_at: u32 = receives_at + receives_per_server * cocuyo.limits.servers_max;
        /// A connection's connect, its receive and its send of the session's records.
        const connections_at: u32 = timer_at + 1;
        /// A QUIC connection's receive and its send.
        const quic_at: u32 = connections_at + per_connection * connections;
        /// A channel's QUIC link's receive and send, and its TCP link's connect, receive and send.
        const channels_at: u32 = quic_at + per_quic_connection * quic_servers;

        /// The count of places, which is the most operations in flight.
        pub const count: u32 = channels_at + per_channel * doh_servers;

        /// The place of the operation for `origin`.
        pub fn of(origin: Origin) u32 {
            const place = switch (origin.kind) {
                .udp_send, .tcp_send => sends_at + lookup_of(origin.index),
                .udp_receive => receives_at + receives_per_server * server_of(origin.index) + lane_of(origin.index),
                .timer => timer_at,
                .tcp_connect, .tcp_receive, .tls_send => connections_at + per_connection * connection_of(origin.index) + connection_place(origin.kind),
                .quic_receive, .quic_send => quic_at + per_quic_connection * quic_server_of(origin.index) + @intFromBool(origin.kind == .quic_send),
                .doh_connect, .doh_send, .doh_receive => channels_at + channel_place(origin),
            };
            assert(place < count);
            return place;
        }

        fn lookup_of(index: u64) u32 {
            assert(index < lookups);
            return @intCast(index);
        }

        fn server_of(index: u64) u32 {
            const server: u32 = @intCast(index & constants.udp_server_mask);
            assert(server < cocuyo.limits.servers_max);
            return server;
        }

        fn lane_of(index: u64) u32 {
            const lane = index >> constants.udp_lane_shift;
            assert(lane < receives_per_server);
            return @intCast(lane);
        }

        fn connection_of(index: u64) u32 {
            const at: u32 = @intCast(index & constants.tcp_slot_mask);
            assert(at < connections);
            return at;
        }

        fn connection_place(kind: Kind) u32 {
            const place: ConnectionPlace = switch (kind) {
                .tcp_connect => .connect,
                .tcp_receive => .receive,
                .tls_send => .records_send,
                else => unreachable,
            };
            return @intFromEnum(place);
        }

        fn quic_server_of(index: u64) u32 {
            const server: u32 = @intCast(index & constants.quic_server_mask);
            assert(server < quic_servers);
            return server;
        }

        /// A link's index is its server's, doubled, and one for TCP.
        fn channel_place(origin: Origin) u32 {
            const link: u32 = @intCast(origin.index & constants.quic_server_mask);
            const server = link >> 1;
            assert(server < doh_servers);
            const stream = link & 1 == 1;
            const place: ChannelPlace = switch (origin.kind) {
                .doh_receive => if (stream) .tcp_receive else .quic_receive,
                .doh_send => if (stream) .tcp_send else .quic_send,
                .doh_connect => connect: {
                    // Only the TCP link connects: the QUIC link's socket opens bound.
                    assert(stream);
                    break :connect .tcp_connect;
                },
                else => unreachable,
            };
            return per_channel * server + @intFromEnum(place);
        }
    };
}

const testing = std.testing;

test "each place has its own slot, and the count of places is the last slot and one" {
    const Of = Places(2, 1, 1, 1);
    var seen: [Of.count]bool = @splat(false);
    const origins = [_]Origin{
        .{ .kind = .udp_send, .index = 0 },
        .{ .kind = .tcp_send, .index = 1 },
        .{ .kind = .udp_receive, .index = 0 },
        .{ .kind = .udp_receive, .index = 1 << constants.udp_lane_shift },
        .{ .kind = .udp_receive, .index = cocuyo.limits.servers_max - 1 },
        .{ .kind = .udp_receive, .index = (1 << constants.udp_lane_shift) | (cocuyo.limits.servers_max - 1) },
        .{ .kind = .timer, .index = 0 },
        .{ .kind = .tcp_connect, .index = 7 << constants.tcp_incarnation_shift },
        .{ .kind = .tcp_receive, .index = 0 },
        .{ .kind = .tls_send, .index = 0 },
        .{ .kind = .quic_receive, .index = 3 << constants.quic_incarnation_shift },
        .{ .kind = .quic_send, .index = 0 },
        .{ .kind = .doh_receive, .index = 0 },
        .{ .kind = .doh_send, .index = 0 },
        .{ .kind = .doh_connect, .index = 1 },
        .{ .kind = .doh_receive, .index = 1 },
        .{ .kind = .doh_send, .index = 1 },
    };
    for (origins) |origin| {
        const place = Of.of(origin);
        try testing.expect(!seen[place]);
        seen[place] = true;
    }
    // A lookup's send is one place, whichever transport carries it: a lookup lends its buffer to
    // one send at a time.
    try testing.expectEqual(Of.of(.{ .kind = .udp_send, .index = 1 }), Of.of(.{ .kind = .tcp_send, .index = 1 }));
    try testing.expectEqual(Of.count - 1, Of.of(.{ .kind = .doh_send, .index = 1 }));
}
