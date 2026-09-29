//! Lookups over DoH: the engine of docs/design.md §19 step 13 on rotor's loop, carrying each query
//! through colibri's channel (`cocuyo_doh`), which comes up on HTTP/3 over QUIC, or on HTTP/2 or
//! HTTP/1.1 over TCP when QUIC is not answered in time (§24, decision 33), with chapulin's TLS in
//! colibri's `tls`, strict as HTTPS is (RFC 9110 §4.3.4).
//!
//!     zig build example-doh-rotor -- \
//!         <name>[,<name>...] <server address> <URI template> <root certificate>...
//!
//! for instance `example.com 1.1.1.1 https://cloudflare-dns.com/dns-query{?dns} ssl-com-ecc.der`.
//! Each root is a DER certificate the server's chain is expected to end at
//! (`examples/root_text.zig`), and the leaf must carry the template's host. The server's port is
//! the template's, 443 when it names none (RFC 9110 §4.2.2), on UDP for QUIC and on TCP.
//!
//! A name asks for A, and `name/TYPE` for another type, as `example.com/MX`
//! (`examples/answer_text.zig`, which writes the answers out). Names after the first are resolved
//! in turn, each once a ticket is kept and the channel has closed idle, so each opens a connection
//! that resumes with the ticket (§24, rule 23). Names joined by `+`, as `a.example+b.example`, are
//! resolved at once, each an exchange of its own. After each turn the example says how its
//! connection handshook, and which version of HTTP it came up on.
//!
//! What cocuyo does not read, the caller hands in (§24): the wall clock for the certificate's
//! dates, and octets from a CSPRNG for the handshake's keys and the QUIC connection IDs.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const cocuyo_doh = @import("cocuyo_doh");
const tls = @import("tls");
const answer_text = @import("answer_text.zig");
const server_text = @import("server_text.zig");
const root_text = @import("root_text.zig");

const Resolver = io.Resolver(.{
    .lookups = at_once_max + 1,
    .cache_slots = at_once_max + 1,
    .tcp_connections = 0,
    .doh = cocuyo_doh.Channel(.{ .answers = at_once_max }),
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;

/// The roots one run may trust: chapulin's bound on its anchors, as colibri's configuration holds
/// them.
const anchors_max = tls.record.ClientConfig.anchors_max;
/// The largest root certificate the example reads.
const certificate_bytes_max = 8192;
/// How long a lookup is given, in ticks of `tick_ns`, before the example gives up on it.
const tick_ns = 100_000_000;
const ticks_max = 200;
/// How long the example waits between two names for a ticket and the idle close: past the
/// engine's idle wait of ten seconds (`quic_idle_ns_default`), and QUIC's closing period after it.
const close_ticks_max = 300;
const events_max = 16;
/// The names one run resolves.
const names_max = 4;
/// The names one turn resolves at once, each an exchange of its own.
const at_once_max = 4;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 4) {
        std.debug.print("usage: doh-rotor <name>[,<name>...] <server address> <URI template> <root certificate>...\n", .{});
        std.process.exit(2);
    }
    const at = try server_text.place_of(arguments[2]);
    if (at.port != null) return error.PortInTemplate;
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = at.address }, .https = .{ .template = arguments[3] } }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };

    var anchors: [anchors_max]tls.Anchor = undefined;
    const roots = arguments[4..];
    if (roots.len > anchors_max) return error.TooManyRoots;
    for (roots, 0..) |path, index| {
        const der = try std.Io.Dir.cwd().readFileAlloc(init.io, path, arena, .limited(certificate_bytes_max));
        anchors[index] = try root_text.anchor_of(tls.Anchor, der);
    }

    var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    try init.io.randomSecure(&seed);
    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    const clock: Clock = .init(init.io);
    const unix_seconds: u64 = @intCast(@divFloor(std.Io.Timestamp.now(init.io, .real).nanoseconds, std.time.ns_per_s));

    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, std.mem.readInt(u64, &engine_seed, .little), clock.read());
    engine.use_doh(.init(anchors[0..roots.len], seed, unix_seconds, clock.read()));
    defer {
        engine.deinit();
        loop.drain(&events) catch {};
        engine.close();
    }
    if (std.mem.count(u8, arguments[1], ",") >= names_max) return error.TooManyNames;
    var turns = std.mem.splitScalar(u8, arguments[1], ',');
    for (0..names_max) |position| {
        const turn = turns.next() orelse return;
        if (position > 0) try wait_for_close(&loop, &events, clock);
        try resolve(&loop, &events, clock, turn);
        report_connection(turn);
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

/// Ticks until a ticket is kept and the channel has closed idle, so the next lookup opens a
/// connection that resumes. Says which did not happen when one does not.
fn wait_for_close(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    for (0..close_ticks_max) |_| {
        if (ticket_kept() and closed()) return;
        try tick(loop, events, clock);
    }
    if (!ticket_kept()) std.debug.print("in {d} ticks no ticket was kept\n", .{close_ticks_max});
    if (!closed()) std.debug.print("in {d} ticks the channel did not close\n", .{close_ticks_max});
}

fn tick(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    const count = try loop.tick(events, tick_ns);
    const now = clock.read();
    for (events[0..count]) |event| _ = engine.apply(event, now);
    engine.drive(now);
}

fn ticket_kept() bool {
    for (engine.doh.tickets[0]) |ticket| {
        if (ticket != null) return true;
    }
    return false;
}

fn closed() bool {
    return engine.doh.slots[0].state == .closed;
}

/// How the channel's connection handshook: resumed with its ticket, as chapulin's session says; in
/// full, the ticket it offered declined; or in full with no ticket. Then the version of HTTP it came
/// up on. With none up, the answer came from the cache.
fn report_connection(turn: []const u8) void {
    const connected = engine.doh.slots[0].channel.connected() orelse {
        std.debug.print("{s}: handshake not seen: no connection is up\n", .{turn});
        return;
    };
    const how = if (connected.resumed) "resumed" else if (connected.offered) "in full, its ticket declined" else "in full";
    std.debug.print("{s}: handshake {s}\n", .{ turn, how });
    std.debug.print("{s}: over {s}\n", .{ turn, @tagName(connected.protocol) });
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
