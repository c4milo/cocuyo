//! The engine's UDP side: one socket per configured server, bound to an ephemeral port the seed
//! chooses (RFC 5452 §9.2), with one multishot receive each into the engine's datagram group,
//! which is the example's shape with a socket per server (docs/design.md §19 step 13). While a
//! replaced port drains, its server has a second socket beside it.
const std = @import("std");
const assert = std.debug.assert;
const cocuyo = @import("cocuyo");
const core = @import("core");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const limits = @import("limits.zig");
const operations = @import("io_operations.zig");
const OperationId = @import("io_interface.zig").OperationId;

pub const Socket = struct {
    open: bool = false,
    descriptor: rotor.Descriptor = 0,
    receive: rotor.Handle = rotor.Handle.none,
    /// Whether its receive is armed. False when the loop refused the last arming, which the next
    /// drive asks for again (docs/design.md §19 step 13, the datagram's rule 1).
    receiving: bool = false,
    /// The id of the receive this socket armed last. The end of a receive that a replaced socket
    /// left behind carries another id, and there is nothing to do about it.
    receive_id: ?OperationId = null,
    /// The lane of the receive this socket armed last: which of its server's two places it holds
    /// (docs/design.md §26, one operation for each place).
    lane: u1 = 0,
    /// Queries sent from this port, for `Config.udp_queries_per_port`.
    sent: u32 = 0,
    /// Which opening of a socket this is, out of the table's count: what a lookup's query
    /// remembers of the socket it left from, so a draining socket knows what it is still owed.
    epoch: u32 = 0,
    /// Whether the port has carried its share, and is replaced as soon as no older one drains.
    retiring: bool = false,
};

/// Which socket of a server an event or a query names.
pub const Which = enum { current, draining };

/// The socket a lookup's datagram left from: its server, and which opening of a socket.
pub const SentFrom = struct { server: u8, epoch: u32 };

pub const Sockets = struct {
    /// The socket every query to a server leaves from.
    items: [cocuyo.limits.servers_max]Socket,
    /// The socket a server's last port drains on, keeping its receive for the answers to the
    /// queries that left from it; closed when there is none (the datagram's rule 4).
    draining: [cocuyo.limits.servers_max]Socket,
    count: u8,
    /// Where the next port comes from: the seed's stream, so a run is a run.
    word: u64 = 0,
    /// Names every socket this table has opened, apart. It outlives the sockets, because what it
    /// tells apart is a query from a socket that is gone (`reinit`, a port replaced).
    next_epoch: u32 = 0,
    /// The datagram group every receive takes its buffers from, which the loop reserved for the
    /// engine (rotor decision 29).
    group: rotor.BufferGroup = undefined,

    /// Opens a socket per server of the engine's configuration and starts its receive. A port
    /// already in use is not a reason to fail: the kernel picks another.
    pub fn open(self: *Sockets, engine: anytype, seed: u64) error{ SocketFailed, ReceiveFailed }!void {
        assert(self == &engine.sockets);
        const config = engine.config;
        // The epoch counter is not reset: it tells a query from one that a socket that is gone
        // sent, and `reinit` is exactly when there are some.
        self.items = @splat(.{});
        self.draining = @splat(.{});
        // A TLS configuration opens no UDP socket: every query goes on a stream (docs/design.md
        // §21, TLS rule 9). Nor does a DoQ one: each query goes on a QUIC connection, whose
        // socket is its own (§24, request rule 1).
        self.count = if (config.encrypted()) 0 else @intCast(config.servers.len);
        self.word = seed;
        self.group = engine.group.id;
        for (config.servers[0..self.count], 0..) |*server, index| {
            self.items[index] = try self.open_port(config, server.endpoint.address.family);
            try self.arm(engine, &self.items[index], @intCast(index));
        }
    }

    /// A socket on a port the seed chooses, not yet receiving.
    fn open_port(self: *Sockets, config: *const cocuyo.Config, family: cocuyo.Family) error{SocketFailed}!Socket {
        self.word = core.mix.next(self.word);
        const local = local_for(config, family);
        const descriptor = open_bound(family, port_from(self.word), local) catch
            open_bound(family, 0, local) catch return error.SocketFailed;
        size_buffers(descriptor, config);
        self.next_epoch +%= 1;
        return .{ .open = true, .descriptor = descriptor, .epoch = self.next_epoch };
    }

    /// Where a socket of `family` binds: the caller's local address when it named one of that
    /// family, and the unspecified address otherwise.
    pub fn local_for(config: *const cocuyo.Config, family: cocuyo.Family) ?cocuyo.Address {
        const local = config.local_address orelse return null;
        return if (local.family == family) local else null;
    }

    pub fn open_bound(family: cocuyo.Family, port: u16, local: ?cocuyo.Address) !rotor.Descriptor {
        const octets = if (local) |address| address.octets else @as([cocuyo.constants.address_v6_bytes]u8, @splat(0));
        const bind_to = switch (family) {
            .ipv4 => rotor.Address.ipv4(octets[0..cocuyo.constants.address_v4_bytes].*, port),
            .ipv6 => rotor.Address.ipv6(octets, port, 0),
        };
        return rotor.sync.open_datagram(rotor_family(family), &bind_to, .{});
    }

    /// One more query has gone out from server `index`'s current port. True when the port has
    /// carried its share and is to be replaced.
    pub fn count_sent(self: *Sockets, index: u8, per_port: u32) bool {
        assert(index < self.count);
        const socket = &self.items[index];
        socket.sent +|= 1;
        if (per_port == 0 or socket.sent < per_port) return false;
        socket.retiring = true;
        return true;
    }

    /// Whether server `index`'s port has carried its share and is free to be replaced: no older
    /// one still drains, and no receive of an older socket is in flight. A server holds two
    /// receives at most, so the socket after this one needs a lane that no older socket's receive
    /// holds (docs/design.md §26, one operation for each place).
    pub fn is_due(self: *const Sockets, engine: anytype, index: u8) bool {
        assert(index < self.count);
        const current = &self.items[index];
        if (!current.retiring or self.draining[index].open) return false;
        for (0..limits.udp_receives_per_server_max) |lane| {
            if (current.receiving and current.lane == lane) continue;
            if (operations.busy(engine, receive_origin(index, @intCast(lane)))) return false;
        }
        return true;
    }

    /// Replaces server `index`'s port (c-ares `udp_max_queries`): a new socket takes every
    /// query from now on, and the old one drains, keeping its receive for the answers to its
    /// queries (the datagram's rule 4). The new socket is opened first, so when it cannot be the
    /// old one stays in use and the next drive tries again.
    pub fn rotate(self: *Sockets, engine: anytype, index: u8) error{SocketFailed}!void {
        assert(self.is_due(engine, index));
        const config = engine.config;
        const fresh = try self.open_port(config, config.servers[index].endpoint.address.family);
        self.draining[index] = self.items[index];
        self.items[index] = fresh;
        self.arm(engine, &self.items[index], index) catch {};
    }

    /// Closes server `index`'s draining socket: nothing is owed on it any more.
    pub fn close_draining(self: *Sockets, loop: *rotor.Loop, index: u8) void {
        assert(index < self.count);
        const socket = &self.draining[index];
        assert(socket.open);
        if (socket.receiving) loop.cancel(socket.receive);
        rotor.sync.close_now(socket.descriptor);
        socket.* = .{};
    }

    /// Before the first `open`, when nothing is in flight and the struct holds whatever the
    /// caller's memory held.
    pub fn reset_epoch(self: *Sockets) void {
        self.next_epoch = 0;
    }

    /// What a drive does last for server `index`: a receive armed on each of its sockets that
    /// has none. What the moment refuses is asked for again at the next drive (the datagram's
    /// rules 1 and 5).
    pub fn tend(self: *Sockets, engine: anytype, index: u8) void {
        assert(index < self.count);
        if (!self.items[index].receiving) self.arm(engine, &self.items[index], index) catch {};
        const draining = &self.draining[index];
        if (draining.open and !draining.receiving) self.arm(engine, draining, index) catch {};
    }

    /// Arms the multishot receive of one of server `index`'s sockets, which every datagram to
    /// that socket arrives on. Its origin names the server and a lane that no receive holds, and
    /// the socket keeps its id. With both lanes held, by the other socket's receive and by one
    /// that a closed socket left behind, it waits for the drive after that one's end (§26, one
    /// operation for each place).
    pub fn arm(self: *Sockets, engine: anytype, socket: *Socket, index: u8) error{ReceiveFailed}!void {
        assert(index < self.count);
        assert(socket.open);
        assert(!socket.receiving);
        const lane = for (0..limits.udp_receives_per_server_max) |lane| {
            const free: u1 = @intCast(lane);
            if (!operations.busy(engine, receive_origin(index, free))) break free;
        } else return;
        const operation: rotor.Operation = .receive_from(undefined, socket.descriptor, self.group);
        const submitted = operations.submit(engine, receive_origin(index, lane), operation) orelse
            return error.ReceiveFailed;
        socket.receive_id = submitted.id;
        socket.receive = submitted.handle;
        socket.receiving = true;
        socket.lane = lane;
    }

    /// The socket that the receive `id` with origin index `index` names, or null for a receive
    /// that a socket that is gone left behind: no socket of the server keeps its id.
    pub fn find(self: *Sockets, id: OperationId, index: usize) ?struct { server: u8, socket: *Socket, which: Which } {
        const server: u8 = @intCast(index & constants.udp_server_mask);
        if (server >= self.count) return null;
        if (self.items[server].receive_id == id) {
            return .{ .server = server, .socket = &self.items[server], .which = .current };
        }
        const draining = &self.draining[server];
        if (draining.open and draining.receive_id == id) {
            return .{ .server = server, .socket = draining, .which = .draining };
        }
        return null;
    }

    pub fn descriptor_of(self: *const Sockets, index: u8) rotor.Descriptor {
        assert(index < self.count);
        assert(self.items[index].open);
        return self.items[index].descriptor;
    }

    /// The opening every query to server `index` leaves from now.
    pub fn epoch_of(self: *const Sockets, index: u8) u32 {
        assert(index < self.count);
        return self.items[index].epoch;
    }

    pub fn cancel(self: *Sockets, loop: *rotor.Loop) void {
        for (self.items[0..self.count], self.draining[0..self.count]) |*current, *draining| {
            for ([_]*Socket{ current, draining }) |socket| {
                if (!socket.open) continue;
                loop.cancel(socket.receive);
                socket.receive = rotor.Handle.none;
            }
        }
    }

    pub fn close(self: *Sockets) void {
        for (self.items[0..self.count], self.draining[0..self.count]) |*current, *draining| {
            for ([_]*Socket{ current, draining }) |socket| {
                if (!socket.open) continue;
                rotor.sync.close_now(socket.descriptor);
                socket.open = false;
            }
        }
    }
};

/// The origin of a receive of server `server`'s, in lane `lane`.
pub fn receive_origin(server: u8, lane: u1) operations.Origin {
    return .{ .kind = .udp_receive, .index = (@as(u64, lane) << constants.udp_lane_shift) | server };
}

/// A port in the Dynamic range from one word of the seed (RFC 6335 §6).
fn port_from(word: u64) u16 {
    const span = core.limits.port_ephemeral_max - core.limits.port_ephemeral_min + 1;
    return @intCast(core.limits.port_ephemeral_min + word % span);
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
        /// The options that `limits.udp_payload_bytes_max` is read under. So the room it names
        /// is the room of these buffers (docs/design.md §19 step 13, the datagram's rule 7).
        const group = constants.group_options;

        const needed = rotor.buffers.group_bytes(buffers, limits.buffer_bytes_max);
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
        /// The id the loop reserved for the group at `provide` (rotor decision 29).
        id: rotor.BufferGroup,

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
            assert(@alignOf(Self) <= limits.storage_alignment_max);
        }

        /// Reserves the group's id on the loop and gives the loop its buffers. A loop whose every
        /// id another library holds gives none (rotor decision 29), and the engine then has no
        /// buffer to receive into.
        pub fn provide(self: *Self, loop: *rotor.Loop) error{ReceiveFailed}!void {
            const memory = ring(self);
            assert(@intFromPtr(memory.ptr) % alignment == 0);
            self.id = loop.reserve_buffer_group() catch return error.ReceiveFailed;
            loop.provide_datagram_buffers(self.id, memory, buffers, limits.buffer_bytes_max, group) catch
                return error.ReceiveFailed;
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

/// The family of socket a stream to `endpoint` opens.
pub fn family_of(endpoint: cocuyo.Endpoint) rotor.Address.Family {
    return switch (endpoint.address.family) {
        .ipv4 => .ipv4,
        .ipv6 => .ipv6,
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

test "the two ends of the Dynamic range are drawn, and the span wraps after the last" {
    // 49152 to 65535, both ends included (RFC 6335 §6).
    const ports: u64 = @as(u64, core.limits.port_ephemeral_max) - core.limits.port_ephemeral_min + 1;
    try testing.expectEqual(core.limits.port_ephemeral_min, port_from(0));
    try testing.expectEqual(core.limits.port_ephemeral_max, port_from(ports - 1));
    try testing.expectEqual(core.limits.port_ephemeral_min, port_from(ports));
}

test "a port from a word is in the Dynamic range, and an endpoint round-trips through rotor's address" {
    var word: u64 = 0;
    while (word < 64) : (word += 1) {
        const port = port_from(core.mix.next(word));
        try testing.expect(port >= core.limits.port_ephemeral_min);
    }
    const endpoint: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_v4(.{ 192, 0, 2, 53 }), .port = 53 };
    try testing.expect(endpoint_of(address_of(endpoint)).equal(&endpoint));
    const six: cocuyo.Endpoint = .{ .address = cocuyo.Address.from_v6([_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 11 ++ [_]u8{1}), .port = 53 };
    try testing.expect(endpoint_of(address_of(six)).equal(&six));
}
