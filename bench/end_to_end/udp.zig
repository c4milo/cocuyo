//! The libc sockets the comparison drives: IPv4 datagram sockets on the loopback, an address
//! type for them, and the calls the responder makes. This is `bench/`, which may own a socket
//! (CLAUDE.md, Layout); nothing under `src/` does.
const std = @import("std");
const assert = std.debug.assert;
const c = std.c;
const constants = @import("constants.zig");

pub const Socket = c.fd_t;
pub const Address = c.sockaddr.in;

pub const Error = error{ SocketFailed, BindFailed, SendFailed };

/// An address on the loopback, at `port` in host order.
pub fn loopback(port: u16) Address {
    return .{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(constants.loopback_v4),
    };
}

/// A datagram socket bound to the loopback at `port`, or at one the kernel picks for zero, with
/// a receive queue deep enough for every lookup in flight to have a reply waiting.
pub fn open(port: u16) Error!Socket {
    const socket = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
    if (socket < 0) return error.SocketFailed;
    const bytes: c_int = constants.socket_buffer_bytes;
    _ = c.setsockopt(socket, c.SOL.SOCKET, c.SO.RCVBUF, &bytes, @sizeOf(c_int));
    _ = c.setsockopt(socket, c.SOL.SOCKET, c.SO.SNDBUF, &bytes, @sizeOf(c_int));
    const address = loopback(port);
    if (c.bind(socket, @ptrCast(&address), @sizeOf(Address)) != 0) {
        _ = c.close(socket);
        return error.BindFailed;
    }
    return socket;
}

/// The port the socket was bound to, in host order.
pub fn port_of(socket: Socket) u16 {
    var address: Address = undefined;
    var len: c.socklen_t = @sizeOf(Address);
    assert(c.getsockname(socket, @ptrCast(&address), &len) == 0);
    return std.mem.bigToNative(u16, address.port);
}

pub fn close(socket: Socket) void {
    _ = c.close(socket);
}

pub fn send(socket: Socket, bytes: []const u8, to: *const Address) Error!void {
    const sent = c.sendto(socket, bytes.ptr, bytes.len, 0, @ptrCast(to), @sizeOf(Address));
    if (sent < 0 or @as(usize, @intCast(sent)) != bytes.len) return error.SendFailed;
}

/// One datagram, blocking until it comes; where it came from is written to `from`.
pub fn receive(socket: Socket, buffer: []u8, from: *Address) ?[]u8 {
    var len: c.socklen_t = @sizeOf(Address);
    const got = c.recvfrom(socket, buffer.ptr, buffer.len, 0, @ptrCast(from), &len);
    if (got < 0) return null;
    return buffer[0..@intCast(got)];
}
