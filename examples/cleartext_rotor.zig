//! Lookups over plain DNS: the engine of docs/design.md §19 step 13 on rotor's loop, asking one
//! server over UDP (RFC 1035 §4.2.1), or over TCP alone (RFC 7766), as `Config.use_tcp` asks.
//!
//!     zig build example-cleartext-rotor -- [dnssec <anchor file>] <name>[,<name>...] <server address>[:<port>] [udp | tcp]
//!
//! for instance `example.com 9.9.9.9`, or `example.com/MX+example.com/TXT 127.0.0.1:8053 tcp`. A
//! server on a port other than 53 is named with it, an IPv6 one in brackets, as `[::1]:8053`
//! (`examples/server_text.zig`). A name asks for A, and `name/TYPE` for another type
//! (`examples/answer_text.zig`, which writes the answers out). Names after the first are resolved
//! in turn. Names joined by `+` are resolved at once: over UDP each query on a datagram
//! of its own, and over TCP each on the one connection (RFC 7766 §6.2.1.1).
//!
//! With the word `dnssec` and a file of DS or DNSKEY records first, the example validates each
//! lookup from those anchors (`examples/trust_text.zig`, docs/design.md §25 step 15).
//!
//! `examples/udp_rotor.zig` drives a `Lookup` by hand over the same loop; this drives the engine,
//! which owns the sockets, the timers and the connections for every lookup at once.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const answer_text = @import("answer_text.zig");
const server_text = @import("server_text.zig");
const trust_text = @import("trust_text.zig");

const Resolver = io.Resolver(.{
    .lookups = at_once_max + 1,
    .tag = io.constants.tag_default,
    .group_buffers = io.constants.group_buffers_default,
    .tcp_connections = io.constants.tcp_connections_default,
    .tcp_group_buffers = io.constants.tcp_group_buffers_default,
    .requests = null,
    .tcp_message_bytes = io.limits.tcp_message_bytes_max,
    .tls = io.tls.None,
    .quic = io.quic.None,
    .doh = io.channel.None,
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(&loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;
/// The cache's memory, which is the caller's (docs/design.md §19 step 13): the size the README
/// recommends, 2.9 MiB. The engine builds its cache over it at `init`, and `null` in its place
/// would be an engine with no cache.
var cache_memory: cocuyo.Cache.Storage(io.constants.cache_slots_default) = undefined;
/// The key store under the word `dnssec`, and the memory it names.
var trust: trust_text.Trust = .{};

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
    const command = trust_text.read((try init.minimal.args.toSlice(arena))[1..]);
    const arguments = command.operands;
    if (arguments.len < 2 or arguments.len > 3) {
        std.debug.print("usage: cleartext-rotor [dnssec <anchor file>] <name>[,<name>...] <server address>[:<port>] [udp | tcp]\n", .{});
        std.process.exit(2);
    }
    const at = try server_text.place_of(arguments[1]);
    const endpoint: cocuyo.Endpoint = .{ .address = at.address, .port = at.port orelse cocuyo.constants.port_dns_default };
    const use_tcp = arguments.len == 3 and std.mem.eql(u8, arguments[2], "tcp");
    if (arguments.len == 3 and !use_tcp and !std.mem.eql(u8, arguments[2], "udp")) return error.BadTransport;
    const servers = [_]cocuyo.Server{.{ .endpoint = endpoint }};
    const config: cocuyo.Config = .{
        .servers = &servers,
        .search = &.{},
        .ndots = cocuyo.constants.ndots_default,
        .attempts = cocuyo.constants.attempts_default,
        .timeout_ns = cocuyo.constants.timeout_ns_default,
        .udp_payload_bytes = cocuyo.constants.udp_payload_bytes_default,
        .mix_case = true,
        .rotate = false,
        .timeout_ns_max = cocuyo.constants.timeout_ns_max_default,
        .use_tcp = use_tcp,
        .ignore_truncation = false,
        .recursion_desired = true,
        .check_response = true,
        .primary = false,
        .authenticated_data = .ignored,
        .lookups = &.{ .file, .dns },
        .failover_retry_chance = cocuyo.constants.failover_retry_chance_default,
        .local_address = null,
        .socket_receive_bytes = 0,
        .socket_send_bytes = 0,
        .udp_queries_per_port = 0,
        .failover_retry_delay_ns = cocuyo.constants.failover_retry_delay_ns_default,
        .cache_ttl_seconds_max = cocuyo.constants.cache_ttl_seconds_max_default,
        .cache_failure_seconds_min = cocuyo.constants.cache_failure_seconds_min_default,
    };

    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    const clock: Clock = .init(init.io);

    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, &loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, cache_memory.slices(), std.mem.readInt(u64, &engine_seed, .little), clock.read());
    defer {
        engine.deinit();
        loop.drain(&events) catch {};
        engine.close();
    }
    // Before any lookup, which the engine asserts.
    if (command.anchor_path) |path| engine.use_trust(try trust.open(init.io, arena, path, .{ .unix_seconds = unix_seconds(init.io), .monotonic_ns = clock.read() }));
    if (std.mem.count(u8, arguments[0], ",") >= turns_max) return error.TooManyTurns;
    var turns = std.mem.splitScalar(u8, arguments[0], ',');
    for (0..turns_max) |_| {
        const turn = turns.next() orelse break;
        try resolve(&loop, &events, clock, turn);
    }
    // Every result of every turn is written out first, and a failure among them ends the run.
    if (failed) std.process.exit(1);
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
        const handle = try engine.start(&try answer_text.question_of(name), clock.read());
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

/// Whether a lookup of the run failed. The run goes on to its last turn, and then exits 1.
var failed = false;

fn report(name: []const u8, result: Resolver.Result) !void {
    switch (result.outcome) {
        .answer => |answer| try answer_text.report(name, &answer),
        .failure => |failure| {
            answer_text.report_failure(name, &failure);
            failed = true;
        },
    }
}

/// The wall clock, for the dates of the signatures (docs/design.md §25, Time).
fn unix_seconds(io_handle: std.Io) u64 {
    return @intCast(@divFloor(std.Io.Timestamp.now(io_handle, .real).nanoseconds, std.time.ns_per_s));
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
