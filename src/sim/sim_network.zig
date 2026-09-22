//! The virtual network under the twin's loop: sockets, the datagrams and stream bytes waiting to
//! be delivered, and the scripted servers they go to (docs/design.md §19 step 13). One per
//! process, as the kernel is one per process: rotor's `sync` calls take no loop, so the twin's
//! cannot either, and `Loop.init` resets it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const server = @import("sim_server.zig");
const Address = types.Address;
const Descriptor = types.Descriptor;

pub const SocketKind = enum { datagram, stream };

/// A multishot receive registered on a socket: the slot it belongs to and the group it reads
/// into. The twin delivers into groups alone, which is how the engine reads.
pub const Receiver = struct { slot: u32, user_data: u64, group: u16, multishot: bool };

pub const Socket = struct {
    open: bool = false,
    kind: SocketKind = .datagram,
    family: Address.Family = .ipv4,
    local: Address = Address.ipv4(constants.client_address, 0),
    /// A stream socket's connection once connected.
    connection: ?u8 = null,
    receiver: ?Receiver = null,
};

/// A datagram on its way to a socket.
pub const PendingDatagram = struct {
    live: bool = false,
    socket: Descriptor = 0,
    from: Address = Address.ipv4(constants.client_address, 0),
    due_ns: u64 = 0,
    len: u16 = 0,
    bytes: [constants.datagram_bytes_max]u8 = undefined,
};

/// A stream connection to a scripted server: what the client sent and has not finished a
/// frame of, and what the server answered that the client has not read.
pub const Connection = struct {
    open: bool = false,
    socket: Descriptor = 0,
    server: u8 = 0,
    peer: Address = Address.ipv4(constants.client_address, 0),
    partial: [core.constants.tcp_prefix_bytes + constants.datagram_bytes_max]u8 = undefined,
    partial_len: usize = 0,
    inbound: [constants.stream_bytes_max]u8 = undefined,
    inbound_len: usize = 0,
    /// When the bytes queued may be read: the last reply's delay.
    available_at_ns: u64 = 0,
};

pub const Network = struct {
    sockets: [constants.sockets_max]Socket = @splat(.{}),
    next_port: u16 = constants.client_port_first,
    scripts: [constants.servers_max]server.Script = @splat(.{}),
    server_count: u8 = 0,
    datagrams: [constants.datagrams_pending_max]PendingDatagram = @splat(.{}),
    connections: [constants.connections_max]Connection = @splat(.{}),

    pub fn reset(self: *Network) void {
        self.* = .{};
    }

    /// The address of scripted server `index`: the documentation range, one octet a server.
    pub fn server_address(index: u8) Address {
        assert(index < constants.servers_max);
        return Address.ipv4(constants.server_prefix ++ [_]u8{constants.server_octet_first + index}, constants.server_port);
    }

    /// Which scripted server an address names, or null for anywhere else: a datagram there is
    /// sent into the void, and a connection there is refused.
    pub fn server_of(self: *const Network, address: *const Address) ?u8 {
        if (address.family != .ipv4 or address.port != constants.server_port) return null;
        if (!std.mem.eql(u8, address.bytes[0..constants.server_prefix.len], &constants.server_prefix)) return null;
        const octet = address.bytes[constants.server_prefix.len];
        if (octet < constants.server_octet_first) return null;
        const index = octet - constants.server_octet_first;
        if (index >= self.server_count) return null;
        return @intCast(index);
    }

    pub fn socket(self: *Network, descriptor: Descriptor) *Socket {
        assert(descriptor >= 0);
        assert(descriptor < constants.sockets_max);
        const entry = &self.sockets[@intCast(descriptor)];
        assert(entry.open);
        return entry;
    }

    fn open(self: *Network, kind: SocketKind, family: Address.Family) SocketError!Descriptor {
        for (&self.sockets, 0..) |*entry, index| {
            if (entry.open) continue;
            entry.* = .{ .open = true, .kind = kind, .family = family };
            entry.local = Address.ipv4(constants.client_address, 0);
            return @intCast(index);
        }
        return error.DescriptorLimit;
    }

    pub fn assign_port_public(self: *Network) u16 {
        return self.assign_port();
    }

    fn assign_port(self: *Network) u16 {
        const port = self.next_port;
        self.next_port +%= 1;
        if (self.next_port == 0) self.next_port = constants.client_port_first;
        return port;
    }

    /// A datagram on its way: the slot it lands in, or null when the queue is full, which is a
    /// drop.
    pub fn queue_datagram(self: *Network) ?*PendingDatagram {
        for (&self.datagrams) |*entry| {
            if (!entry.live) {
                entry.live = true;
                return entry;
            }
        }
        return null;
    }

    pub fn open_connection(self: *Network, descriptor: Descriptor, server_index: u8) ?u8 {
        for (&self.connections, 0..) |*entry, index| {
            if (entry.open) continue;
            entry.* = .{ .open = true, .socket = descriptor, .server = server_index, .peer = server_address(server_index) };
            return @intCast(index);
        }
        return null;
    }

    pub fn connection(self: *Network, index: u8) *Connection {
        assert(index < constants.connections_max);
        assert(self.connections[index].open);
        return &self.connections[index];
    }

    pub fn close(self: *Network, descriptor: Descriptor) void {
        const entry = self.socket(descriptor);
        assert(entry.receiver == null);
        if (entry.connection) |index| self.connections[index].open = false;
        for (&self.datagrams) |*pending| {
            if (pending.live and pending.socket == descriptor) pending.live = false;
        }
        entry.* = .{};
    }
};

/// The one network of the process.
pub var network: Network = .{};

// The `sync` calls rotor's surface names, over the network above.

pub const SocketError = error{ AddressFamilyUnsupported, DescriptorLimit, SystemResources, Unexpected };
pub const ListenError = error{ AddressInUse, AddressNotAvailable, AccessDenied, Unexpected } || SocketError;
pub const AddressError = error{ NotSocket, Unexpected };
pub const OptionError = error{ NotSocket, Unexpected };

pub const DatagramOptions = struct {
    control: bool = true,
    dont_fragment: bool = true,
};

pub const ListenOptions = struct { backlog: u16 = 16, reuse_port: bool = false };

pub fn open_datagram(family: Address.Family, bind_to: ?*const Address, options: DatagramOptions) ListenError!Descriptor {
    _ = options;
    const descriptor = try network.open(.datagram, family);
    const entry = network.socket(descriptor);
    if (bind_to) |address| {
        assert(address.family == family);
        entry.local = address.*;
    }
    if (entry.local.port == 0) entry.local.port = network.assign_port();
    return descriptor;
}

pub fn open_socket(family: Address.Family) SocketError!Descriptor {
    return network.open(.stream, family);
}

pub fn close_now(descriptor: Descriptor) void {
    network.close(descriptor);
}

pub fn local_address(descriptor: Descriptor) AddressError!Address {
    return network.socket(descriptor).local;
}

pub fn set_no_delay(descriptor: Descriptor, enabled: bool) OptionError!void {
    _ = network.socket(descriptor);
    _ = enabled;
}

pub fn prepare_accepted(descriptor: Descriptor) OptionError!void {
    _ = network.socket(descriptor);
}

pub fn set_option(descriptor: Descriptor, level: i32, name: u32, enabled: bool) OptionError!void {
    _ = network.socket(descriptor);
    _ = level;
    _ = name;
    _ = enabled;
}

/// The twin listens for nobody: the engine is a client.
pub fn listen(address: *const Address, options: ListenOptions) ListenError!Descriptor {
    _ = address;
    _ = options;
    return error.Unexpected;
}

// Tests.

const testing = std.testing;

test "a datagram socket opens with a port of its own, and closes" {
    network.reset();
    const bound = try open_datagram(.ipv4, null, .{});
    const address = try local_address(bound);
    try testing.expectEqual(@as(u16, constants.client_port_first), address.port);
    const chosen = Address.ipv4(.{ 10, 0, 0, 1 }, 5000);
    const second = try open_datagram(.ipv4, &chosen, .{});
    try testing.expectEqual(@as(u16, 5000), (try local_address(second)).port);
    close_now(bound);
    close_now(second);
    try testing.expect(!network.sockets[0].open);
}

test "the scripted servers sit at the documentation range, in order" {
    network.reset();
    network.server_count = 2;
    try testing.expectEqual(@as(?u8, 0), network.server_of(&Network.server_address(0)));
    try testing.expectEqual(@as(?u8, 1), network.server_of(&Network.server_address(1)));
    try testing.expectEqual(@as(?u8, null), network.server_of(&Network.server_address(2)));
    try testing.expectEqual(@as(?u8, null), network.server_of(&Address.ipv4(.{ 10, 0, 0, 1 }, 53)));
    try testing.expectEqual(@as(?u8, null), network.server_of(&Address.ipv4(.{ 192, 0, 2, 53 }, 5353)));
}
