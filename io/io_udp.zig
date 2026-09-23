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
    /// Whether its receive is armed. False when the loop refused the last arming, which the next
    /// drive asks for again (docs/design.md §19 step 13, the datagram's rule 1).
    receiving: bool = false,
    /// Queries sent from this port, for `Config.udp_queries_per_port`.
    sent: u32 = 0,
    /// Which receive this socket has armed, out of the table's count. The end of a receive a
    /// replaced socket left behind carries another, and there is nothing to do about it.
    armed_generation: u32 = 0,
    /// Whether the port has carried its share and waits for its lookups to end before another
    /// is opened. A port is never taken from a query that is still waiting for its answer.
    retiring: bool = false,
};

pub const Sockets = struct {
    items: [cocuyo.constants.servers_max]Socket,
    count: u8,
    /// Where the next port comes from: the seed's stream, so a run is a run.
    word: u64 = 0,
    /// Names every receive this table has ever armed, apart. It outlives the sockets, because
    /// what it tells apart is a receive from a socket that is gone (`reinit`, a port replaced).
    /// Thirty-two bits, so a receive left behind cannot come back to a count that wrapped.
    next_generation: u32 = 0,

    /// Opens a socket per server and starts its receive. A port already in use is not a reason
    /// to fail: the kernel picks another.
    pub fn open(self: *Sockets, loop: *rotor.Loop, config: *const cocuyo.Config, seed: u64, tag: u16) error{ SocketFailed, ReceiveFailed }!void {
        // The generation counter is not reset: it tells a receive from one a socket that is
        // gone left behind, and `reinit` is exactly when there are some.
        self.items = @splat(.{});
        self.count = @intCast(config.servers.len);
        self.word = seed;
        for (config.servers, 0..) |*server, index| {
            try self.open_one(loop, config, @intCast(index), server.endpoint.address.family, tag);
        }
    }

    /// Opens server `index`'s socket on a port the seed chooses and arms its receive.
    fn open_one(
        self: *Sockets,
        loop: *rotor.Loop,
        config: *const cocuyo.Config,
        index: u8,
        family: cocuyo.Family,
        tag: u16,
    ) error{ SocketFailed, ReceiveFailed }!void {
        self.word = cocuyo.core.mix.next(self.word);
        const local = local_for(config, family);
        const descriptor = open_bound(family, port_from(self.word), local) catch
            open_bound(family, 0, local) catch return error.SocketFailed;
        size_buffers(descriptor, config);
        self.items[index] = .{ .open = true, .descriptor = descriptor };
        try self.receive_again(loop, index, tag);
    }

    /// Where a socket of `family` binds: the caller's local address when it named one of that
    /// family, and the unspecified address otherwise.
    fn local_for(config: *const cocuyo.Config, family: cocuyo.Family) ?cocuyo.Address {
        const local = config.local_address orelse return null;
        return if (local.family == family) local else null;
    }

    fn open_bound(family: cocuyo.Family, port: u16, local: ?cocuyo.Address) !rotor.Descriptor {
        const octets = if (local) |address| address.octets else @as([cocuyo.constants.address_v6_bytes]u8, @splat(0));
        const bind_to = switch (family) {
            .ipv4 => rotor.Address.ipv4(octets[0..cocuyo.constants.address_v4_bytes].*, port),
            .ipv6 => rotor.Address.ipv6(octets, port, 0),
        };
        return rotor.sync.open_datagram(rotor_family(family), &bind_to, .{});
    }

    /// One more query has gone out from server `index`'s port. True when the port has carried
    /// its share and should be replaced once nothing is waiting on it.
    pub fn count_sent(self: *Sockets, index: u8, per_port: u32) bool {
        assert(index < self.count);
        const socket = &self.items[index];
        socket.sent +|= 1;
        if (per_port == 0 or socket.sent < per_port) return false;
        socket.retiring = true;
        return true;
    }

    /// Replaces a retiring port with a new one, once nothing is waiting on it (c-ares
    /// `udp_max_queries`). The receive on the old socket is cancelled and the socket closed, so
    /// nothing arrives on it afterwards. When the new one cannot be opened the server has no
    /// socket until `tend` opens one (the datagram's rule 4).
    pub fn rotate(
        self: *Sockets,
        loop: *rotor.Loop,
        config: *const cocuyo.Config,
        index: u8,
        tag: u16,
    ) error{ SocketFailed, ReceiveFailed }!void {
        assert(index < self.count);
        const socket = &self.items[index];
        assert(socket.retiring);
        const family = config.servers[index].endpoint.address.family;
        loop.cancel(socket.receive);
        rotor.sync.close_now(socket.descriptor);
        self.items[index] = .{};
        try self.open_one(loop, config, index, family, tag);
    }

    /// Before the first `open`, when nothing is in flight and the struct holds whatever the
    /// caller's memory held.
    pub fn reset_generation(self: *Sockets) void {
        self.next_generation = 0;
    }

    pub fn is_retiring(self: *const Sockets, index: u8) bool {
        assert(index < self.count);
        return self.items[index].retiring;
    }

    pub fn is_open(self: *const Sockets, index: u8) bool {
        assert(index < self.count);
        return self.items[index].open;
    }

    /// What a drive does last for server `index`: a socket opened when it has none, and its
    /// receive armed when it has none. What the moment refuses is asked for again at the next
    /// drive (the datagram's rules 1 and 4).
    pub fn tend(self: *Sockets, loop: *rotor.Loop, config: *const cocuyo.Config, index: u8, tag: u16) void {
        assert(index < self.count);
        const socket = &self.items[index];
        if (!socket.open) {
            self.open_one(loop, config, index, config.servers[index].endpoint.address.family, tag) catch {};
        } else if (!socket.receiving) {
            self.receive_again(loop, index, tag) catch {};
        }
    }

    /// Arms the multishot receive of server `index`'s socket, which every datagram from that
    /// server arrives on.
    pub fn receive_again(self: *Sockets, loop: *rotor.Loop, index: u8, tag: u16) error{ReceiveFailed}!void {
        assert(index < self.count);
        const socket = &self.items[index];
        assert(socket.open);
        self.next_generation +%= 1;
        socket.armed_generation = self.next_generation;
        const operation: rotor.Operation = .receive_from(
            user_data(tag, .udp_receive, receive_index(index, socket.armed_generation)),
            socket.descriptor,
            constants.group_id,
        );
        var handles: [1]rotor.Handle = undefined;
        if (loop.submit(&.{operation}, &handles) != 1) {
            socket.receiving = false;
            return error.ReceiveFailed;
        }
        socket.receive = handles[0];
        socket.receiving = true;
    }

    /// The `user_data` index of a receive: the server it is on, and which receive on it.
    fn receive_index(index: u8, generation: u32) usize {
        return @as(usize, index) | (@as(usize, generation) << constants.receive_generation_shift);
    }

    /// Whether a receive event names the receive this server has armed now. An event from one
    /// the socket left behind names a generation that has moved on, and there is nothing to do
    /// about it: the socket it belonged to is closed.
    pub fn is_current(self: *const Sockets, index: usize) ?u8 {
        const server: u8 = @intCast(index & constants.receive_index_mask);
        if (server >= self.count) return null;
        const generation: u32 = @truncate(index >> constants.receive_generation_shift);
        if (self.items[server].armed_generation != generation) return null;
        return server;
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

        const needed = rotor.buffers.group_bytes(buffers, constants.buffer_bytes);
        const alignment = rotor.buffers.group_alignment;

        /// One alignment more than the group needs, and no alignment claimed for it: the window
        /// is found at run time instead.
        ///
        /// rotor asks for 64 KiB, and no platform gave it. The object file keeps the promise
        /// (`__bss` at `align 2^16` on arm64 macOS), and the loader then slides the image by the
        /// page, 16 KiB there, so the engine landed at 0x102be8000, 32 KiB into a 64 KiB boundary;
        /// on x86_64-linux it landed at 0x1332d50, not even page-aligned, and
        /// `IORING_REGISTER_PBUF_RING` refused it with `EINVAL`. A type that claims the alignment
        /// is worse than one that does not: in ReleaseSafe the optimizer believes the claim and
        /// folds the arithmetic that would find the window, and the program reaches `unreachable`
        /// from a premise that was false. Debug computes on the real address, which is why only
        /// ReleaseSafe failed.
        memory: [needed + alignment]u8,

        /// The aligned window, which is what rotor is given.
        pub fn ring(self: *Self) []align(alignment) u8 {
            const from = @intFromPtr(&self.memory);
            const at = std.mem.alignForward(usize, from, alignment);
            assert(at - from < alignment);
            return @alignCast(self.memory[at - from ..][0..needed]);
        }

        comptime {
            // The claim this struct must never make again, pinned: nothing here is aligned beyond
            // what a page guarantees, so the optimizer has no false premise to fold.
            assert(@alignOf(Self) <= constants.storage_alignment_max);
        }

        pub fn provide(self: *Self, loop: *rotor.Loop) error{ReceiveFailed}!void {
            const memory = ring(self);
            assert(@intFromPtr(memory.ptr) % alignment == 0);
            loop.provide_datagram_buffers(constants.group_id, memory, buffers, constants.buffer_bytes, group) catch
                return error.ReceiveFailed;
        }

        comptime {
            if (rotor.datagram.payload_capacity(constants.buffer_bytes, group) < cocuyo.constants.udp_payload_bytes_default) {
                @compileError("a group buffer cannot hold the payload cocuyo advertises");
            }
        }
    };
}

/// Asks the kernel for the buffer sizes the caller named, and lets the socket be whatever it
/// already is when the kernel will not: a buffer smaller than the caller wanted loses datagrams
/// under load, and a socket that was not opened loses every one (`Config.socket_receive_bytes`).
pub fn size_buffers(descriptor: rotor.Descriptor, config: *const cocuyo.Config) void {
    if (config.socket_receive_bytes != 0) {
        _ = rotor.sync.set_buffer_bytes(descriptor, .receive, config.socket_receive_bytes) catch {};
    }
    if (config.socket_send_bytes != 0) {
        _ = rotor.sync.set_buffer_bytes(descriptor, .send, config.socket_send_bytes) catch {};
    }
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
