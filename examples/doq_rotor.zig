//! Lookups over DNS over QUIC: the engine of docs/design.md §19 step 13 on rotor's loop, carrying
//! each query on a stream of colibri's QUIC (`cocuyo_quic`), with chapulin's QUIC session in
//! colibri's `tls` as its TLS (`io/io_chapulin_quic.zig`), strict as RFC 9250 §5.1 and RFC 8310 §5
//! ask. DoH goes through colibri's channel, in `examples/doh_rotor.zig`.
//!
//!     zig build example-doq-rotor -- \
//!         <name>[,<name>...] <server address> <authentication name | pin-sha256:<pin>,...> <root certificate>...
//!
//! for instance `example.com 94.140.14.14 dns.adguard-dns.com usertrust-ecc.der`. Each root is a DER
//! certificate the server's chain is expected to end at (`examples/root_text.zig`). The leaf must
//! carry the authentication name. A server known by its key alone takes pins in place of the name,
//! and no root. A server on a port other than UDP's 853 (RFC 9250 §4.1.1) is named with it, as
//! `127.0.0.1:8853` or `[::1]:8853` (`examples/server_text.zig`).
//!
//! A name asks for A, and `name/TYPE` for another type, as `example.com/MX`
//! (`examples/answer_text.zig`, which writes the answers out). Names after the first are resolved
//! in turn, each once the server's ticket is kept and the connection before has closed idle, so
//! each opens a connection that resumes with the ticket (§24, request rule 10). Names joined by `+`, as `a.example+b.example`, are resolved at once, on
//! one connection, each on a stream of its own. After each turn the example says how its
//! handshake went.
//!
//! What cocuyo does not read, the caller hands in (§24): the wall clock for the certificate's
//! dates, and octets from a CSPRNG for the handshake's keys and the connection IDs.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const cocuyo_quic = @import("cocuyo_quic");
const chapulin = @import("chapulin_quic");
const answer_text = @import("answer_text.zig");
const server_text = @import("server_text.zig");
const root_text = @import("root_text.zig");

const Quic = cocuyo_quic.Connection(.{ .Session = chapulin.Session, .streams = at_once_max });
const Resolver = io.Resolver(.{
    .lookups = at_once_max + 1,
    .cache_slots = at_once_max + 1,
    .tcp_connections = 0,
    .quic = Quic,
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;

/// The roots one run may trust: chapulin's bound on its anchors, as colibri's configuration holds
/// them.
const anchors_max = chapulin.Session.anchors_max;
/// The largest root certificate the example reads.
const certificate_bytes_max = 8192;
/// How long a lookup is given, in ticks of `tick_ns`, before the example gives up on it.
const tick_ns = 100_000_000;
const ticks_max = 200;
/// How long the example waits between two names for the ticket and the idle close: past the
/// engine's idle wait of ten seconds (`quic_idle_ns_default`).
const close_ticks_max = 200;
const events_max = 16;
/// The names one run resolves.
const names_max = 4;
/// The names one turn resolves at once, each on a stream of its own.
const at_once_max = 4;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 4) {
        std.debug.print("usage: doq-rotor <name>[,<name>...] <server address> <authentication name | pin-sha256:<pin>,...> <root certificate>...\n", .{});
        std.process.exit(2);
    }
    const at = try server_text.place_of(arguments[2]);
    var pins: [cocuyo.constants.spki_pins_max]cocuyo.Pin = undefined;
    var quic = try known_by(arguments[3], &pins);
    if (at.port) |port| quic.port = port;
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = at.address }, .quic = quic }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };

    var anchors: [anchors_max]chapulin.Session.Anchor = undefined;
    const roots = arguments[4..];
    if (roots.len > anchors_max) return error.TooManyRoots;
    for (roots, 0..) |path, index| {
        const der = try std.Io.Dir.cwd().readFileAlloc(init.io, path, arena, .limited(certificate_bytes_max));
        anchors[index] = try root_text.anchor_of(chapulin.Session.Anchor, der);
    }

    var seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    try init.io.randomSecure(&seed);
    var id_seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    try init.io.randomSecure(&id_seed);
    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    const clock: Clock = .init(init.io);
    const unix_seconds: u64 = @intCast(@divFloor(std.Io.Timestamp.now(init.io, .real).nanoseconds, std.time.ns_per_s));

    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, std.mem.readInt(u64, &engine_seed, .little), clock.read());
    engine.use_quic(.{
        .session = .init(anchors[0..roots.len], seed, unix_seconds, clock.read()),
        .stream = std.Random.ChaCha.init(id_seed),
    });
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
        std.debug.print("{s}: handshake {s}\n", .{ turn, handshake() });
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

/// Ticks until the server's ticket is kept and every connection has closed idle, so the next
/// lookup opens a connection that resumes. Says which did not happen when one does not.
fn wait_for_close(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    for (0..close_ticks_max) |_| {
        if (engine.quic.tickets[0] != null and all_closed()) return;
        try tick(loop, events, clock);
    }
    if (engine.quic.tickets[0] == null) std.debug.print("in {d} ticks no ticket was kept\n", .{close_ticks_max});
    if (!all_closed()) std.debug.print("in {d} ticks the connection did not close\n", .{close_ticks_max});
}

fn tick(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    const count = try loop.tick(events, tick_ns);
    const now = clock.read();
    for (events[0..count]) |event| _ = engine.apply(event, now);
    engine.drive(now);
}

fn all_closed() bool {
    for (engine.quic.connections) |connection| {
        if (connection.state != .closed) return false;
    }
    return true;
}

/// How the connection that is up handshook: resumed with its ticket, as chapulin's session says;
/// in full within the same connection, the ticket it offered declined; or in full with no ticket.
/// With none up, the answer came from the cache or the connection has closed since.
fn handshake() []const u8 {
    for (&engine.quic.connections) |*connection| {
        if (connection.state != .up) continue;
        const session = &connection.transport.session;
        if (session.resumed()) return "resumed";
        if (session.offered) return "in full, its ticket declined";
        return "in full";
    }
    return "not seen: no connection is up";
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

/// How a server is known, from its argument: by its name, or by its key alone, RFC 8310 §6.3's
/// "SPKI + IP", as `pin-sha256:<base64>[,<base64>...]`, each pin the base64 of the SHA-256 of a
/// SubjectPublicKeyInfo (RFC 7858 §4.2), which chapulin matches against the leaf's key.
fn known_by(text: []const u8, pins: *[cocuyo.constants.spki_pins_max]cocuyo.Pin) !cocuyo.Tls {
    const prefix = "pin-sha256:";
    if (!std.mem.startsWith(u8, text, prefix)) return .{ .name = try cocuyo.Name.from_text(text) };
    var each = std.mem.splitScalar(u8, text[prefix.len..], ',');
    var count: usize = 0;
    // Bounded by the pins a server may have, and one more to say there were too many.
    for (0..pins.len + 1) |_| {
        const pin = each.next() orelse break;
        if (count == pins.len) return error.TooManyPins;
        pins[count] = try cocuyo.spki_pin.from_base64(pin);
        count += 1;
    }
    return .{ .pins = pins[0..count] };
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
