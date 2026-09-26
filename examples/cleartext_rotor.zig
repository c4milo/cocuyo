//! Lookups over plain DNS: the engine of docs/design.md §19 step 13 on rotor's loop, asking one
//! server over UDP (RFC 1035 §4.2.1), or over TCP alone (RFC 7766), as `Config.use_tcp` asks.
//!
//!     zig build example-cleartext-rotor -- <name>[,<name>...] <server address>[:<port>] [udp | tcp]
//!
//! for instance `example.com 9.9.9.9`, or `example.com/MX+example.com/TXT 127.0.0.1:8053 tcp`. A
//! server on a port other than 53 is named with it, an IPv6 one in brackets, as `[::1]:8053`
//! (`examples/server_text.zig`). A name asks for A, and `name/TYPE` for another type
//! (`examples/answer_text.zig`, which writes the answers out). Names after the first are resolved
//! in turn. Names joined by `+` are resolved at once: over UDP each query on a datagram
//! of its own, and over TCP each on the one connection (RFC 7766 §6.2.1.1).
//!
//! `examples/udp_rotor.zig` drives a `Lookup` by hand over the same loop; this drives the engine,
//! which owns the sockets, the timers and the connections for every lookup at once.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const answer_text = @import("answer_text.zig");
const server_text = @import("server_text.zig");

const Resolver = io.Resolver(.{ .lookups = at_once_max + 1, .cache_slots = at_once_max + 1 });

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;

/// How long a turn is given, in ticks of `tick_ns`, before the example gives up on it.
const tick_ns = 100_000_000;
const ticks_max = 200;
const events_max = 16;
/// The turns one run resolves.
const turns_max = 4;
/// The names one turn resolves at once.
const at_once_max = 4;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 3 or arguments.len > 4) {
        std.debug.print("usage: cleartext-rotor <name>[,<name>...] <server address>[:<port>] [udp | tcp]\n", .{});
        std.process.exit(2);
    }
    const at = try server_text.place_of(arguments[2]);
    const endpoint: cocuyo.Endpoint = .{ .address = at.address, .port = at.port orelse cocuyo.constants.port_dns_default };
    const use_tcp = arguments.len == 4 and std.mem.eql(u8, arguments[3], "tcp");
    if (arguments.len == 4 and !use_tcp and !std.mem.eql(u8, arguments[3], "udp")) return error.BadTransport;
    const servers = [_]cocuyo.Server{.{ .endpoint = endpoint }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{}, .use_tcp = use_tcp };

    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    const clock: Clock = .init(init.io);

    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, std.mem.readInt(u64, &engine_seed, .little), clock.read());
    defer {
        engine.deinit();
        loop.drain(&events) catch {};
        engine.close();
    }
    if (std.mem.count(u8, arguments[1], ",") >= turns_max) return error.TooManyTurns;
    var turns = std.mem.splitScalar(u8, arguments[1], ',');
    for (0..turns_max) |_| {
        const turn = turns.next() orelse return;
        try resolve(&loop, &events, clock, turn);
    }
}

/// One turn's names, `+` between two, started at once and driven until each has its result, which
/// is reported under its name. The example exits when one has none in `ticks_max` ticks.
fn resolve(loop: *rotor.Loop, events: []rotor.Event, clock: Clock, turn: []const u8) !void {
    if (std.mem.count(u8, turn, "+") >= at_once_max) return error.TooManyAtOnce;
    var named: [at_once_max + 1][]const u8 = undefined;
    var names = std.mem.splitScalar(u8, turn, '+');
    var started: usize = 0;
    for (0..at_once_max) |_| {
        const name = names.next() orelse break;
        const handle = try engine.start(try answer_text.question_of(name), clock.read());
        named[handle.index] = name;
        started += 1;
    }
    var taken: usize = 0;
    for (0..ticks_max) |_| {
        while (engine.take(clock.read())) |result| {
            try report(named[result.handle.index], result);
            taken += 1;
        }
        if (taken == started) return;
        try tick(loop, events, clock);
    }
    std.debug.print("{s}: {d} of {d} answered in {d} ticks\n", .{ turn, taken, started, ticks_max });
    std.process.exit(1);
}

fn tick(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    const count = try loop.tick(events, tick_ns);
    const now = clock.read();
    for (events[0..count]) |event| _ = engine.apply(event, now);
    engine.drive(now);
}

fn report(name: []const u8, result: Resolver.Result) !void {
    switch (result.outcome) {
        .answer => |answer| try answer_text.report(name, &answer),
        .failure => |failure| {
            std.debug.print("{s}: {t}\n", .{ name, failure.err });
            std.process.exit(1);
        },
    }
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
