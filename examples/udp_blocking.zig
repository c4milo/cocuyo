//! One lookup over a UDP socket, so the shape of the API is visible in one file: cocuyo says what
//! to do, this does it, and tells cocuyo what happened.
//!
//!     zig build example-udp-blocking -- example.com
//!
//! What the caller owns here is everything cocuyo does not: the configuration file, the socket,
//! the clock and the seed. The I/O is Zig's own `std.Io`, which is the point of the split — the
//! same thirty lines of driving run over any other implementation of it, including a
//! completion-based loop, without cocuyo knowing which.
//!
//! Two of the four are worth reading twice.
//!
//! The clock is the monotonic one. cocuyo asserts that the instant it is given never goes
//! backwards, and a wall clock does exactly that when the machine's time is corrected.
//!
//! The seed comes from the host's CSPRNG. It is what the transaction id, the source-port hint and
//! the DNS-0x20 case pattern are drawn from, so a seed read from the clock would make all three
//! guessable (docs/design.md §7).
const std = @import("std");
const cocuyo = @import("cocuyo");
const net = std.Io.net;

/// The largest `resolv.conf` this example reads. A real one is a few hundred octets.
const resolv_conf_bytes_max = 4096;

/// Where the platform keeps the file. §14 of the design document says what this does and does not
/// see, which on macOS is less than the rest of the machine sees.
const resolv_conf_path = "/etc/resolv.conf";

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 2) {
        std.debug.print("usage: udp-blocking <name>\n", .{});
        std.process.exit(2);
    }

    // The caller reads the file; cocuyo parses bytes (CLAUDE.md non-negotiable 1). A file that is
    // not there is an empty one, which cocuyo reads as the local nameserver.
    var storage: cocuyo.resolv_conf.Storage = .{};
    const file_bytes = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        resolv_conf_path,
        arena,
        .limited(resolv_conf_bytes_max),
    ) catch "";
    const config = cocuyo.resolv_conf.parse(file_bytes, &storage);

    var seed_bytes: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&seed_bytes);
    try resolve(init.io, arguments[1], &config, std.mem.readInt(u64, &seed_bytes, .little));
}

/// The driving loop. Every branch is one thing cocuyo asked for.
fn resolve(io: std.Io, name: []const u8, config: *const cocuyo.Config, seed: u64) !void {
    // The per-server state a lookup shares with the others of its process: cookies live here.
    var servers = cocuyo.Servers.init(config, seed);
    var lookup = cocuyo.Lookup.init(config, &servers, try cocuyo.Question.from_text(name, .a), seed);
    const clock: Clock = .init(io);
    var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
    var reply: [cocuyo.constants.udp_payload_bytes_default]u8 = undefined;
    var socket: ?net.Socket = null;
    defer if (socket) |open_socket| open_socket.close(io);

    while (true) {
        switch (lookup.poll(clock.read(), &query)) {
            .send_udp => |send| {
                if (socket == null) socket = try open(io, send.server, send.local_port_hint);
                const server = address_of(send.server);
                try socket.?.send(io, &server, send.message_bytes);
                lookup.on_sent(clock.read());
            },
            .wait => |deadline_ns| try wait(io, &lookup, socket.?, &reply, clock, deadline_ns),
            .connect_tcp, .send_tcp => {
                // A truncated answer needs TCP: connect, write the length-prefixed query, read two
                // octets, call `cocuyo.message_len`, read that many, and hand them to
                // `on_response`. It is the same shape as below and is left to the caller; this
                // example stops here rather than pretending to be complete.
                std.debug.print("{s}: the answer needs TCP, which this example does not do\n", .{name});
                std.process.exit(1);
            },
            .done => |answer| return report(name, answer),
            .failed => |failure| {
                std.debug.print("{s}: {t}\n", .{ name, failure.err });
                std.process.exit(1);
            },
        }
    }
}

/// One datagram, or nothing when the wait ran out. Either way the next poll decides what happens:
/// another server, another pass, or the failure. A datagram that is not ours costs one parse and
/// changes nothing, so this hands over whatever arrives.
fn wait(
    io: std.Io,
    lookup: *cocuyo.Lookup,
    socket: net.Socket,
    reply: []u8,
    clock: Clock,
    deadline_ns: u64,
) !void {
    const remaining = deadline_ns -| clock.read();
    const message = socket.receiveTimeout(io, reply, .{
        // The wait is on the same monotonic clock the lookup is driven by.
        .duration = .{ .raw = .{ .nanoseconds = @intCast(remaining) }, .clock = .awake },
    }) catch |err| switch (err) {
        error.Timeout => return,
        else => return err,
    };
    _ = lookup.on_response(message.data, endpoint_of(message.from), clock.read());
}

/// The clock cocuyo is driven by: monotonic, so it never goes backwards, which is what the library
/// asserts about every instant it is given.
const Clock = struct {
    io: std.Io,
    start: std.Io.Timestamp,

    fn init(io: std.Io) Clock {
        return .{ .io = io, .start = .now(io, .awake) };
    }

    fn read(self: Clock) u64 {
        const elapsed = self.start.durationTo(.now(self.io, .awake));
        return @intCast(elapsed.nanoseconds);
    }
};

/// A socket of the server's family, bound to the port cocuyo suggested. The hint is entropy
/// against a spoof (RFC 5452 §9.2), and a port already in use is not a reason to fail: the kernel
/// picks another.
fn open(io: std.Io, server: cocuyo.Endpoint, port_hint: u16) !net.Socket {
    var hinted = unspecified(server, port_hint);
    return hinted.bind(io, .{ .mode = .dgram }) catch {
        var any = unspecified(server, 0);
        return any.bind(io, .{ .mode = .dgram });
    };
}

fn unspecified(server: cocuyo.Endpoint, port: u16) net.IpAddress {
    return switch (server.address.family) {
        .ipv4 => .{ .ip4 = .unspecified(port) },
        .ipv6 => .{ .ip6 = .unspecified(port) },
    };
}

fn address_of(endpoint: cocuyo.Endpoint) net.IpAddress {
    const octets = endpoint.address.slice();
    return switch (endpoint.address.family) {
        .ipv4 => .{ .ip4 = .{
            .bytes = octets[0..cocuyo.constants.address_v4_bytes].*,
            .port = endpoint.port,
        } },
        .ipv6 => .{ .ip6 = .{
            .bytes = octets[0..cocuyo.constants.address_v6_bytes].*,
            .port = endpoint.port,
        } },
    };
}

/// The source of a datagram, which cocuyo checks against the server the query went to
/// (docs/design.md §7 check 3). Handing over the wrong one would be handing over the check.
fn endpoint_of(address: net.IpAddress) cocuyo.Endpoint {
    return switch (address) {
        .ip4 => |ip4| .{ .address = cocuyo.Address.from_v4(ip4.bytes), .port = ip4.port },
        .ip6 => |ip6| .{ .address = cocuyo.Address.from_v6(ip6.bytes), .port = ip6.port },
    };
}

fn report(name: []const u8, answer: cocuyo.Answer) void {
    var text: [cocuyo.constants.name_text_bytes_max]u8 = undefined;
    if (answer.canonical_name) |canonical| {
        std.debug.print("{s} is {s}\n", .{ name, text[0..canonical.write_text(&text)] });
    }
    for (answer.addresses) |address| {
        const octets = address.slice();
        std.debug.print("{s} A {d}.{d}.{d}.{d} (ttl {d})\n", .{
            name,
            octets[0],
            octets[1],
            octets[2],
            octets[3],
            answer.ttl_seconds,
        });
    }
    if (answer.truncated) {
        std.debug.print("{s}: more addresses existed than there was room for\n", .{name});
    }
}
