//! Two engines on two threads of one image, each on its own rotor loop, resolving at once
//! (docs/design.md §24 step 6, a thread per core):
//!
//!     zig build example-threads-rotor
//!
//! A responder thread on the loopback answers every query with one A record. Each engine thread
//! runs a loop and an engine of its own, seeded apart, and both engines hold one `Config`, which
//! is read and never written. The two start together, resolve the same names at once, and each
//! must take an answer for every lookup it started. Each hands its engine every event its loop
//! makes, and counts the ones the engine says are not its own: there must be none, since the
//! other engine's events are on the other loop.
//!
//! It exits 0 when both engines took every answer, and 1 when either did not.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");

const c = std.c;

const engines = 2;
/// The names each engine resolves: the same on both, which each engine's own cache answers
/// nothing of, since each resolves each name once.
const names = [_][]const u8{ "a.example.", "b.example.", "c.example.", "d.example." };

const Resolver = io.Resolver(.{ .lookups = names.len, .cache_slots = names.len });
const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
const events_max = 16;
/// How long the engines are given, in ticks of `tick_ns`, before the example gives up.
const tick_ns = 10_000_000;
const ticks_max = 500;

/// Each loop's memory, aligned as rotor asks: one aligned array, each loop's share rounded up to
/// the alignment so the second starts aligned too. An aligned field of a struct was the first try,
/// and Zig 0.16's own x86_64 backend placed the array 16 octets past the alignment.
const loop_memory_bytes = std.mem.alignForward(usize, rotor.Loop.memory_bytes(loop_options), rotor.memory_alignment);
var loop_memory: [engines][loop_memory_bytes]u8 align(rotor.memory_alignment) = undefined;
var resolvers: [engines]Resolver = undefined;

/// One engine thread: what it was given, and what it took.
const Engine = struct {
    index: usize,
    seed: u64,
    config: *const cocuyo.Config,
    clock: Clock,
    started: *std.atomic.Value(usize),
    answered: usize = 0,
    failed: usize = 0,
    foreign: usize = 0,
    err: ?anyerror = null,
};

pub fn main(init: std.process.Init) !void {
    var responder: Responder = .{};
    try responder.start();
    defer responder.stop();
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = cocuyo.Address.from_v4(loopback_v4), .port = responder.port } }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    const clock: Clock = .init(init.io);

    var started = std.atomic.Value(usize).init(0);
    var states: [engines]Engine = undefined;
    for (&states, 0..) |*state, index| {
        var seed: [@sizeOf(u64)]u8 = undefined;
        try init.io.randomSecure(&seed);
        state.* = .{ .index = index, .seed = std.mem.readInt(u64, &seed, .little), .config = &config, .clock = clock, .started = &started };
    }
    var threads: [engines]std.Thread = undefined;
    for (&threads, &states) |*thread, *state| thread.* = try std.Thread.spawn(.{}, run, .{state});
    for (threads) |thread| thread.join();

    var whole = true;
    for (states) |state| {
        std.debug.print("engine {d}: {d} of {d} answered, {d} failed, {d} events not its own", .{
            state.index, state.answered, names.len, state.failed, state.foreign,
        });
        if (state.err) |err| std.debug.print(", stopped by {t}", .{err});
        std.debug.print("\n", .{});
        whole = whole and state.err == null and state.answered == names.len and state.foreign == 0;
    }
    std.debug.print("the responder answered {d} queries\n", .{responder.answered.load(.acquire)});
    if (!whole) std.process.exit(1);
}

fn run(state: *Engine) void {
    resolve(state) catch |err| {
        state.err = err;
    };
}

/// Runs a loop and an engine of this thread's own until every lookup it started has a result.
fn resolve(state: *Engine) !void {
    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory[state.index], loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    const resolver = &resolvers[state.index];
    try resolver.init(&loop, state.config, state.seed, state.clock.read());
    defer {
        resolver.deinit();
        loop.drain(&events) catch {};
        resolver.close();
    }
    // Both engines start their lookups together, so the two loops run at once.
    _ = state.started.fetchAdd(1, .acq_rel);
    while (state.started.load(.acquire) < engines) std.atomic.spinLoopHint();
    for (names) |name| _ = try resolver.start(try cocuyo.Question.from_text(name, .a), state.clock.read());
    try drive(state, resolver, &loop, &events);
}

/// Ticks the loop, hands the engine every event it makes, and takes the results, until each
/// lookup has one or the ticks run out.
fn drive(state: *Engine, resolver: *Resolver, loop: *rotor.Loop, events: []rotor.Event) !void {
    var taken: usize = 0;
    for (0..ticks_max) |_| {
        while (resolver.take(state.clock.read())) |result| {
            taken += 1;
            if (result.outcome == .answer) state.answered += 1 else state.failed += 1;
        }
        if (taken == names.len) return;
        const count = try loop.tick(events, tick_ns);
        const now = state.clock.read();
        for (events[0..count]) |event| {
            if (!resolver.apply(event, now)) state.foreign += 1;
        }
    }
}

const loopback_v4 = [_]u8{ 127, 0, 0, 1 };
/// What the responder answers every query with: 192.0.2.1 (RFC 5737 §3), for a minute.
const answer_v4 = [_]u8{ 192, 0, 2, 1 };
const answer_ttl_seconds = 60;
/// The answer's owner, a pointer to the question's name at the header's end, its type A and its
/// class IN (RFC 1035 §4.1.3, §4.1.4), and its RDLENGTH of four.
const record_head = [_]u8{ 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01 };
const record_rdlength = [_]u8{ 0x00, 0x04 };
const datagram_bytes_max = cocuyo.constants.udp_payload_bytes_default;

/// A thread on a loopback datagram socket that answers every query with one A record, until a
/// datagram from itself stops it.
const Responder = struct {
    socket: c.fd_t = -1,
    port: u16 = 0,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = .init(false),
    answered: std.atomic.Value(u64) = .init(0),

    fn start(self: *Responder) !void {
        self.socket = c.socket(c.AF.INET, c.SOCK.DGRAM, 0);
        if (self.socket < 0) return error.SocketFailed;
        var address = loopback(0);
        if (c.bind(self.socket, @ptrCast(&address), @sizeOf(c.sockaddr.in)) != 0) return error.BindFailed;
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        if (c.getsockname(self.socket, @ptrCast(&address), &len) != 0) return error.BindFailed;
        self.port = std.mem.bigToNative(u16, address.port);
        self.thread = try std.Thread.spawn(.{}, serve, .{self});
    }

    fn stop(self: *Responder) void {
        self.stopping.store(true, .release);
        const to = loopback(self.port);
        _ = c.sendto(self.socket, "stop", "stop".len, 0, @ptrCast(&to), @sizeOf(c.sockaddr.in));
        if (self.thread) |thread| thread.join();
        _ = c.close(self.socket);
    }

    fn serve(self: *Responder) void {
        var query: [datagram_bytes_max]u8 = undefined;
        var reply: [datagram_bytes_max]u8 = undefined;
        var from: c.sockaddr.in = undefined;
        while (!self.stopping.load(.acquire)) {
            var len: c.socklen_t = @sizeOf(c.sockaddr.in);
            const got = c.recvfrom(self.socket, &query, query.len, 0, @ptrCast(&from), &len);
            if (got < 0) continue;
            const reply_len = build_reply(query[0..@intCast(got)], &reply) orelse continue;
            _ = c.sendto(self.socket, &reply, reply_len, 0, @ptrCast(&from), @sizeOf(c.sockaddr.in));
            _ = self.answered.fetchAdd(1, .monotonic);
        }
    }
};

fn loopback(port: u16) c.sockaddr.in {
    return .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(loopback_v4) };
}

/// The reply to `query`: its header with QR and RA set and one answer, its question as it came,
/// and the A record. Null for a datagram that is not a query.
fn build_reply(query: []const u8, reply: []u8) ?usize {
    const wire = cocuyo.wire;
    const header_bytes = cocuyo.constants.header_bytes;
    if (query.len < header_bytes) return null;
    const name_end = wire.name.skip(query, header_bytes) catch return null;
    const question_end = name_end + cocuyo.constants.question_fixed_bytes;
    if (question_end > query.len) return null;
    @memcpy(reply[0..question_end], query[0..question_end]);
    var header = wire.header.parse(query) catch return null;
    header.flags = (header.flags | wire.constants.flag_response | wire.constants.flag_recursion_available) &
        ~@as(u16, wire.constants.rcode_mask);
    header.ancount = 1;
    header.nscount = 0;
    header.arcount = 0;
    wire.header.write(&header, reply);
    var ttl: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &ttl, answer_ttl_seconds, .big);
    var at = question_end;
    for ([_][]const u8{ &record_head, &ttl, &record_rdlength, &answer_v4 }) |part| {
        @memcpy(reply[at..][0..part.len], part);
        at += part.len;
    }
    return at;
}

/// The clock cocuyo is driven by: monotonic, as `examples/udp_rotor.zig` reads it.
const Clock = struct {
    io: std.Io,
    start: std.Io.Timestamp,

    fn init(io_handle: std.Io) Clock {
        return .{ .io = io_handle, .start = .now(io_handle, .awake) };
    }

    fn read(self: Clock) u64 {
        return @intCast(self.start.durationTo(.now(self.io, .awake)).nanoseconds);
    }
};
