//! The engine's UDP side: one socket per configured server, bound to an ephemeral port the seed
//! chooses (RFC 5452 §9.2), with one multishot receive each into the engine's datagram group,
//! which is the example's shape with a socket per server (docs/design.md §19 step 13).
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const Kind = @import("io.zig").Kind;

pub const Socket = struct {
    open: bool = false,
    descriptor: rotor.Descriptor = 0,
    receive: rotor.Handle = rotor.Handle.none,
};

pub const Sockets = struct {
    items: [cocuyo.constants.servers_max]Socket,
    count: u8,

    /// Opens a socket per server and starts its receive. A port already in use is not a reason
    /// to fail: the kernel picks another.
    pub fn open(self: *Sockets, loop: *rotor.Loop, config: *const cocuyo.Config, seed: u64, tag: u16) error{ SocketFailed, ReceiveFailed }!void {
        self.items = @splat(.{});
        self.count = @intCast(config.servers.len);
        var word = seed;
        for (config.servers, 0..) |*server, index| {
            word = cocuyo.core.mix.next(word);
            const family = server.endpoint.address.family;
            const descriptor = open_bound(family, port_from(word)) catch open_bound(family, 0) catch return error.SocketFailed;
            self.items[index] = .{ .open = true, .descriptor = descriptor };
            try self.receive_again(loop, @intCast(index), tag);
        }
    }

    fn open_bound(family: cocuyo.Family, port: u16) !rotor.Descriptor {
        const bind_to = switch (family) {
            .ipv4 => rotor.Address.ipv4(@splat(0), port),
            .ipv6 => rotor.Address.ipv6(@splat(0), port, 0),
        };
        return rotor.sync.open_datagram(rotor_family(family), &bind_to, .{});
    }

    /// Arms the multishot receive of server `index`'s socket, which every datagram from that
    /// server arrives on.
    pub fn receive_again(self: *Sockets, loop: *rotor.Loop, index: u8, tag: u16) error{ReceiveFailed}!void {
        assert(index < self.count);
        const socket = &self.items[index];
        assert(socket.open);
        const operation: rotor.Operation = .{
            .user_data = user_data(tag, .udp_receive, index),
            .kind = .{ .receive_from = .{ .socket = socket.descriptor, .group = constants.group_id } },
        };
        var handles: [1]rotor.Handle = undefined;
        if (loop.submit(&.{operation}, &handles) != 1) return error.ReceiveFailed;
        socket.receive = handles[0];
    }

    pub fn descriptor_of(self: *const Sockets, index: u8) rotor.Descriptor {
        assert(index < self.count);
        assert(self.items[index].open);
        return self.items[index].descriptor;
    }

    pub fn cancel(self: *Sockets, loop: *rotor.Loop) void {
        for (self.items[0..self.count]) |*socket| {
            if (!socket.open) continue;
            loop.cancel(socket.receive);
            socket.receive = rotor.Handle.none;
        }
    }

    pub fn close(self: *Sockets) void {
        for (self.items[0..self.count]) |*socket| {
            if (!socket.open) continue;
            rotor.sync.close_now(socket.descriptor);
            socket.open = false;
        }
    }
};

fn user_data(tag: u16, kind: Kind, index: usize) u64 {
    return (@as(u64, tag) << constants.tag_shift) | (@as(u64, @intFromEnum(kind)) << constants.kind_shift) | index;
}

/// A port in the Dynamic range from one word of the seed (RFC 6335 §6).
fn port_from(word: u64) u16 {
    const span = cocuyo.constants.port_ephemeral_max - cocuyo.constants.port_ephemeral_min + 1;
    return @intCast(cocuyo.constants.port_ephemeral_min + word % span);
}

fn rotor_family(family: cocuyo.Family) rotor.Address.Family {
    return switch (family) {
        .ipv4 => .ipv4,
        .ipv6 => .ipv6,
    };
}

/// The datagram group every socket receives into: the caller's memory, provided once.
pub fn Group(comptime buffers: u16) type {
    return struct {
        const Self = @This();
        const group: rotor.datagram.GroupOptions = .{};

        memory: [rotor.buffers.group_bytes(buffers, constants.buffer_bytes)]u8 align(rotor.buffers.group_alignment),

        pub fn provide(self: *Self, loop: *rotor.Loop) error{ReceiveFailed}!void {
            loop.provide_datagram_buffers(constants.group_id, &self.memory, buffers, constants.buffer_bytes, group) catch
                return error.ReceiveFailed;
        }

        comptime {
            if (rotor.datagram.payload_capacity(constants.buffer_bytes, group) < cocuyo.constants.udp_payload_bytes_default) {
                @compileError("a group buffer cannot hold the payload cocuyo advertises");
            }
        }
    };
}

/// Where a datagram goes: cocuyo's endpoint as rotor addresses it.
pub fn outbound_to(endpoint: cocuyo.Endpoint) rotor.datagram.Outbound {
    return .{
        .peer = address_of(endpoint),
        .local = undefined,
        .segment_bytes = 0,
        .ecn = .not_ect,
        .flags = .{ .peer = true },
    };
}

pub fn address_of(endpoint: cocuyo.Endpoint) rotor.Address {
    const octets = endpoint.address.slice();
    return switch (endpoint.address.family) {
        .ipv4 => .ipv4(octets[0..cocuyo.constants.address_v4_bytes].*, endpoint.port),
        .ipv6 => .ipv6(octets[0..cocuyo.constants.address_v6_bytes].*, endpoint.port, 0),
    };
}

/// Where a datagram came from, which the table checks against the server the query went to
/// (docs/design.md §7 check 3).
pub fn endpoint_of(address: rotor.Address) cocuyo.Endpoint {
    return switch (address.family) {
        .ipv4 => .{
            .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*),
            .port = address.port,
        },
        .ipv6 => .{ .address = cocuyo.Address.from_v6(address.bytes), .port = address.port },
    };
}

// Tests.

const testing = std.testing;

test "a port from a word is in the Dynamic range, and an endpoint round-trips through rotor's address" {
    var word: u64 = 0;
    while (word < 64) : (word += 1) {
        const port = port_from(cocuyo.core.mix.next(word));
        try testing.expect(port >= cocuyo.constants.port_ephemeral_min);
    }
    const endpoint: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_v4(.{ 192, 0, 2, 53 }), .port = 53 };
    try testing.expect(endpoint_of(address_of(endpoint)).equal(&endpoint));
    const six: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_v6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1}), .port = 53 };
    try testing.expect(endpoint_of(address_of(six)).equal(&six));
}
