//! The virtual network under the twin's loop: sockets, the datagrams and stream bytes waiting to
//! be delivered, and the scripted servers they go to (docs/design.md §19 step 13). One per
//! thread: rotor's `sync` calls take no loop, so the twin's cannot either, and a thread's loop and
//! its `sync` calls reach the thread's own network. A thread per core shares nothing (§24), so a
//! twin on each thread is a kernel of its own, and `Loop.init` resets the thread's.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const types = @import("sim_types.zig");
const server = @import("sim_server.zig");
const tls_module = @import("sim_tls.zig");
const quic_module = @import("sim_quic.zig");
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
    /// What the kernel gave each of its buffers, or zero for whatever it starts with.
    receive_buffer_bytes: u32 = 0,
    send_buffer_bytes: u32 = 0,
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
    /// The server side of the twin's TLS, on a connection to the TLS port (sim_tls.zig).
    tls: ?tls_module.Peer = null,
};

/// The server side of one of the twin's QUIC connections: the client's socket it answers, and
/// the scripted server it is (sim_quic.zig).
pub const QuicPeer = struct {
    open: bool = false,
    socket: Descriptor = 0,
    server: u8 = 0,
    peer: quic_module.Peer = .{},
};

/// A server a test puts on a scripted server's QUIC port in place of the twin's QUIC
/// (docs/design.md §24, colibri over the twin): it is handed every datagram sent there, and woken
/// at its own deadline, and it answers with `Network.reply`. The twin is in `src/`, which depends
/// on nothing, so a test in `io/` brings colibri's server this way.
pub const Responder = struct {
    context: *anyopaque,
    hear: *const fn (context: *anyopaque, socket: Descriptor, bytes: []const u8, now_ns: u64) void,
    deadline: *const fn (context: *anyopaque) ?u64,
    expire: *const fn (context: *anyopaque, now_ns: u64) void,
};

pub const Network = struct {
    sockets: [constants.sockets_max]Socket = @splat(.{}),
    next_port: u16 = constants.client_port_first,
    scripts: [constants.servers_max]server.Script = @splat(.{}),
    server_count: u8 = 0,
    datagrams: [constants.datagrams_pending_max]PendingDatagram = @splat(.{}),
    connections: [constants.connections_max]Connection = @splat(.{}),
    quic_peers: [constants.connections_max]QuicPeer = @splat(.{}),
    /// A responder on each scripted server's QUIC port, or null for the twin's QUIC.
    responders: [constants.servers_max]?Responder = @splat(null),
    /// Whether every socket open fails, as it does when a process has no descriptor left: set
    /// by a caller driving the twin in manual mode (tools/spec_replay/).
    refuse_open: bool = false,

    pub fn reset(self: *Network) void {
        self.* = .{};
    }

    /// The address of scripted server `index`: the documentation range, one octet a server.
    pub fn server_address(index: u8) Address {
        assert(index < constants.servers_max);
        return Address.ipv4(constants.server_prefix ++ [_]u8{constants.server_octet_first + index}, constants.server_port);
    }

    /// Where scripted server `index` speaks QUIC from: its address, on its QUIC port.
    pub fn server_quic_address(index: u8) Address {
        var address = server_address(index);
        address.port = constants.server_quic_port;
        return address;
    }

    /// A datagram from server `index`'s QUIC port to `descriptor`, due at `due_ns`. False when the
    /// network holds as many as it can, or the datagram is longer than one holds: a drop.
    pub fn reply(self: *Network, descriptor: Descriptor, index: u8, bytes: []const u8, due_ns: u64) bool {
        const pending = self.queue_datagram() orelse return false;
        if (bytes.len > pending.bytes.len) {
            pending.live = false;
            return false;
        }
        pending.socket = descriptor;
        pending.from = server_quic_address(index);
        pending.due_ns = due_ns;
        pending.len = @intCast(bytes.len);
        @memcpy(pending.bytes[0..bytes.len], bytes);
        return true;
    }

    /// Which scripted server an address names, or null for anywhere else: a datagram there is
    /// sent into the void, and a connection there is refused.
    pub fn server_of(self: *const Network, address: *const Address) ?u8 {
        if (address.family != .ipv4) return null;
        const ports = [_]u16{ constants.server_port, constants.server_tcp_port, constants.server_tls_port };
        if (std.mem.indexOfScalar(u16, &ports, address.port) == null) return null;
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
        if (self.refuse_open) return error.DescriptorLimit;
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

    pub fn open_connection(self: *Network, descriptor: Descriptor, server_index: u8, tls: bool) ?u8 {
        for (&self.connections, 0..) |*entry, index| {
            if (entry.open) continue;
            entry.* = .{
                .open = true,
                .socket = descriptor,
                .server = server_index,
                .peer = server_address(server_index),
                .tls = if (tls) .{} else null,
            };
            return @intCast(index);
        }
        return null;
    }

    /// The server side of the QUIC connection from `descriptor` to server `server_index`, opened
    /// when the first datagram comes. Null when every one is taken, which drops the datagram.
    pub fn quic_peer(self: *Network, descriptor: Descriptor, server_index: u8) ?*QuicPeer {
        for (&self.quic_peers) |*entry| {
            if (entry.open and entry.socket == descriptor and entry.server == server_index) return entry;
        }
        for (&self.quic_peers) |*entry| {
            if (entry.open) continue;
            entry.* = .{ .open = true, .socket = descriptor, .server = server_index };
            return entry;
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
        for (&self.quic_peers) |*peer| {
            if (peer.open and peer.socket == descriptor) peer.open = false;
        }
        for (&self.datagrams) |*pending| {
            if (pending.live and pending.socket == descriptor) pending.live = false;
        }
        entry.* = .{};
    }
};

/// The network of this thread.
pub threadlocal var network: Network = .{};

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

/// Which of a socket's two kernel buffers `set_buffer_bytes` sizes.
pub const SocketBuffer = enum { receive, send };

/// The largest `bytes` the call carries, as rotor's is: not a size any kernel grants.
pub const socket_buffer_bytes_max: u32 = std.math.maxInt(i32);

pub const BufferError = OptionError || error{SizeRefused};

/// Asks for `bytes` of buffer and answers what was set, which is rarely the request: this grants
/// what it is asked for up to `socket_buffer_bytes_cap` and caps above it, which is the shape
/// rotor measured on macOS. The size is remembered so a test can read it back.
pub fn set_buffer_bytes(descriptor: Descriptor, which: SocketBuffer, bytes: u32) BufferError!u32 {
    assert(bytes >= 1);
    assert(bytes <= socket_buffer_bytes_max);
    const entry = network.socket(descriptor);
    if (bytes > constants.socket_buffer_bytes_refuse_above) return error.SizeRefused;
    const granted = @min(bytes, constants.socket_buffer_bytes_cap);
    switch (which) {
        .receive => entry.receive_buffer_bytes = granted,
        .send => entry.send_buffer_bytes = granted,
    }
    return granted;
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
    errdefer close_now(bound);
    const address = try local_address(bound);
    try testing.expectEqual(@as(u16, constants.client_port_first), address.port);
    const chosen = Address.ipv4(.{ 10, 0, 0, 1 }, 5000);
    const second = try open_datagram(.ipv4, &chosen, .{});
    errdefer close_now(second);
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
    // A server also accepts streams on a port of its own, so a `Server.tcp_port` is a thing a
    // test can set; any other port is nobody's.
    try testing.expectEqual(@as(?u8, 0), network.server_of(&Address.ipv4(.{ 192, 0, 2, 53 }, constants.server_tcp_port)));
    try testing.expectEqual(@as(?u8, null), network.server_of(&Address.ipv4(.{ 192, 0, 2, 53 }, 1053)));
}
