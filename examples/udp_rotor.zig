//! One lookup over rotor's loop: the same library, driven by a completion-based event loop
//! instead of a blocking socket.
//!
//!     zig build example-udp-rotor -- example.com
//!
//! `examples/udp_blocking.zig` is the same lookup over `std.Io`. Reading them side by side is the
//! point of having both: the `switch` over what cocuyo asked for is the same shape in each, and
//! everything that differs is I/O the caller owns. cocuyo does not know which one it is driving.
//!
//! Three things a completion loop changes, and none of them is in cocuyo:
//!
//! 1. A send is queued, not performed. `submit` makes no syscall, and the send goes out on the
//!    next `tick`. So `on_sent` is called when the send's completion event arrives, which is what
//!    `on_sent` has always meant: the caller sent it.
//! 2. A receive is armed once and delivers many. One multishot `receive_from` covers every
//!    datagram of the lookup, retries included.
//! 3. The bytes arrive in a buffer the loop picked from a group, not in one the caller passed to
//!    a call. The caller reads them through the loop and gives the buffer back.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");

/// The largest `resolv.conf` this example reads.
const resolv_conf_bytes_max = 4096;
const resolv_conf_path = "/etc/resolv.conf";

/// The loop holds one send and one receive at a time, and `entries` is what the io_uring backend
/// sizes its submission ring by.
const loop_options: rotor.Loop.Options = .{ .operations = 4 };
const loop_memory_bytes = rotor.Loop.memory_bytes(loop_options);

/// The buffer group every datagram is delivered into. Each buffer holds rotor's own prefix and
/// then the datagram, so it is sized past the payload cocuyo advertises in EDNS0.
const group_id = 0;
const group_buffers = 4;
const group: rotor.datagram.GroupOptions = .{};
const buffer_bytes = 2048;

/// What each completion event says it belongs to.
const send_tag = 1;
const receive_tag = 2;

/// How many events one tick may hand back.
const events_max = 8;

comptime {
    const payload = rotor.datagram.payload_capacity(buffer_bytes, group);
    if (payload < cocuyo.constants.udp_payload_bytes_default) {
        @compileError("a group buffer cannot hold the payload cocuyo advertises");
    }
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 2) {
        std.debug.print("usage: udp-rotor <name>\n", .{});
        std.process.exit(2);
    }

    // The configuration file and the seed are read through `std.Io`: a file read once at startup
    // is not what an event loop is for, and rotor does not hand out entropy.
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

fn resolve(io: std.Io, name: []const u8, config: *const cocuyo.Config, seed: u64) !void {
    // The per-server state a lookup shares with the others of its process: cookies live here.
    var servers = cocuyo.Servers.init(config, seed);
    var lookup = cocuyo.Lookup.init(config, &servers, try cocuyo.Question.from_text(name, .a), seed);
    const clock: Clock = .init(io);

    var loop_memory: [loop_memory_bytes]u8 align(rotor.memory_alignment) = undefined;
    var group_memory: [rotor.buffers.group_bytes(group_buffers, buffer_bytes)]u8 align(rotor.buffers.group_alignment) = undefined;

    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    try loop.provide_datagram_buffers(group_id, &group_memory, group_buffers, buffer_bytes, group);

    // The port cocuyo suggests is entropy against a spoof (RFC 5452 §9.2). A port already in use
    // is not a reason to fail: the kernel picks another.
    const hint = lookup.transaction.port_hint;
    const socket = open(hint) catch try open(0);
    defer rotor.sync.close_now(socket);

    // One multishot receive covers the whole lookup: every retry's answer arrives on it.
    var handles: [1]rotor.Handle = undefined;
    if (loop.submit(&.{receive_from(socket)}, &handles) != 1) return error.LoopFull;
    defer end(&loop, handles[0]);

    var driver: Driver = .{ .loop = &loop, .socket = socket, .clock = clock };
    try driver.run(&lookup, name);
}

/// The loop's own state: what has been queued, and the outbound metadata the loop borrows until
/// a send completes (rotor decision 5, rule 3).
const Driver = struct {
    loop: *rotor.Loop,
    socket: rotor.Descriptor,
    clock: Clock,
    outbound: rotor.datagram.Outbound = undefined,
    sending: bool = false,

    fn run(self: *Driver, lookup: *cocuyo.Lookup, name: []const u8) !void {
        var query: [cocuyo.constants.query_bytes_max]u8 = undefined;
        var events: [events_max]rotor.Event = undefined;
        while (true) {
            const wait_ns = switch (lookup.poll(self.clock.read(), &query)) {
                .send_udp => |request| wait: {
                    // A queued send is not a sent one, so the lookup is told when its completion
                    // arrives and not here.
                    if (!self.sending) try self.queue_send(request);
                    break :wait 0;
                },
                .wait => |deadline_ns| deadline_ns -| self.clock.read(),
                // Cleartext servers alone: DoH and DoQ are colibri's to drive (§22, §23).
                .send_exchange => unreachable,
                .connect_tcp, .send_tcp => {
                    std.debug.print("{s}: the answer needs TCP, which this example does not do\n", .{name});
                    std.process.exit(1);
                },
                .done => |answer| return report(name, answer),
                .failed => |failure| {
                    std.debug.print("{s}: {t}\n", .{ name, failure.err });
                    std.process.exit(1);
                },
            };
            const count = try self.loop.tick(&events, wait_ns);
            for (events[0..count]) |event| self.apply(lookup, event);
        }
    }

    fn queue_send(self: *Driver, request: anytype) !void {
        self.outbound = .{
            .peer = address_of(request.server),
            .local = undefined,
            .segment_bytes = 0,
            .ecn = .not_ect,
            .flags = .{ .peer = true },
        };
        const operation: rotor.Operation = .{ .user_data = send_tag, .kind = .{ .send_to = .{
            .socket = self.socket,
            .buffer = .{ .bytes = request.message_bytes },
            .to = &self.outbound,
        } } };
        if (self.loop.submit(&.{operation}, &.{}) != 1) return error.LoopFull;
        self.sending = true;
    }

    /// One completion. A send that failed costs its server a turn, exactly as a failed `sendto`
    /// does in the blocking example.
    fn apply(self: *Driver, lookup: *cocuyo.Lookup, event: rotor.Event) void {
        const now_ns = self.clock.read();
        switch (event.user_data) {
            send_tag => {
                self.sending = false;
                if (event.outcome()) |_| lookup.on_sent(now_ns) else |_| {
                    lookup.on_send_failed(now_ns);
                }
            },
            receive_tag => self.receive(lookup, event, now_ns),
            else => {},
        }
    }

    /// The datagram the loop picked a buffer for. Read through the loop, handed to cocuyo, and
    /// the buffer given straight back: cocuyo copies what it keeps, so nothing here has to hold
    /// the bytes.
    fn receive(self: *Driver, lookup: *cocuyo.Lookup, event: rotor.Event, now_ns: u64) void {
        const bytes = event.outcome() catch return;
        if (bytes == 0) return;
        const delivery = self.loop.datagram(group_id, event);
        _ = lookup.on_response(delivery.bytes, endpoint_of(delivery.from.peer), now_ns);
        self.loop.give_back_buffer(group_id, event.flags.buffer_id);
    }
};

fn receive_from(socket: rotor.Descriptor) rotor.Operation {
    return .{ .user_data = receive_tag, .kind = .{ .receive_from = .{
        .socket = socket,
        .group = group_id,
    } } };
}

fn open(port: u16) !rotor.Descriptor {
    const bind_to = rotor.Address.ipv4(.{ 0, 0, 0, 0 }, port);
    return rotor.sync.open_datagram(.ipv4, &bind_to, .{});
}

/// Ends the multishot receive and empties the loop, which `deinit` requires (rotor decision 5,
/// rule 7).
fn end(loop: *rotor.Loop, handle: rotor.Handle) void {
    loop.cancel(handle);
    var events: [events_max]rotor.Event = undefined;
    loop.drain(&events) catch {};
}

/// The clock cocuyo is driven by: monotonic, so it never goes backwards. rotor times an operation
/// by a duration from the tick that submits it, and cocuyo wants an absolute instant, so the
/// clock stays the caller's.
const Clock = struct {
    io: std.Io,
    start: std.Io.Timestamp,

    fn init(io: std.Io) Clock {
        return .{ .io = io, .start = .now(io, .awake) };
    }

    fn read(self: Clock) u64 {
        return @intCast(self.start.durationTo(.now(self.io, .awake)).nanoseconds);
    }
};

fn address_of(endpoint: cocuyo.Endpoint) rotor.Address {
    const octets = endpoint.address.slice();
    return switch (endpoint.address.family) {
        .ipv4 => .ipv4(octets[0..cocuyo.constants.address_v4_bytes].*, endpoint.port),
        .ipv6 => .ipv6(octets[0..cocuyo.constants.address_v6_bytes].*, endpoint.port, 0),
    };
}

/// Where a datagram came from, which cocuyo checks against the server the query went to
/// (docs/design.md §7 check 3).
fn endpoint_of(address: rotor.Address) cocuyo.Endpoint {
    return switch (address.family) {
        .ipv4 => .{
            .address = cocuyo.Address.from_v4(address.bytes[0..cocuyo.constants.address_v4_bytes].*),
            .port = address.port,
        },
        .ipv6 => .{ .address = cocuyo.Address.from_v6(address.bytes), .port = address.port },
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
            name, octets[0], octets[1], octets[2], octets[3], answer.ttl_seconds,
        });
    }
}
