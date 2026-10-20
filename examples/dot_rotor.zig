//! Lookups over DNS over TLS: the engine of docs/design.md §19 step 13 on rotor's loop, with
//! chapulin's session in colibri's `tls` behind the session interface of §21 (`io/io_chapulin.zig`),
//! strict as RFC 8310 §5 asks.
//!
//!     zig build example-dot-rotor -- \
//!         <name>[,<name>...] <server address> <authentication name | pin-sha256:<pin>,...> <root certificate>...
//!
//! for instance `dns.google 8.8.8.8 dns.google gts-root-r1.der gts-root-r4.der`: Google shows a
//! chain under either root, by the frontend a connection reaches. Each root is a DER certificate a
//! chain of the server's is expected to end at; its subject Name and its SubjectPublicKeyInfo are
//! the trust anchor chapulin checks the chain against, and the name is what the leaf must carry. A
//! server known by its key alone takes pins in place of the name, and no root. A server on a port
//! other than 853 (RFC 7858 §3.1) is named with it, as `127.0.0.1:8853` or `[::1]:8853`
//! (`examples/server_text.zig`).
//!
//! A name asks for A, and `name/TYPE` for another type, as `example.com/MX`
//! (`examples/answer_text.zig`, which writes the answers out). Names after the first are resolved
//! in turn, each once the server's ticket is kept and the connection before has closed idle, so
//! each opens a connection that resumes with the ticket (§21, TLS rule 8). Names joined by `+`,
//! as `a.example+b.example`, are resolved at once, each query on the one connection (RFC 7766
//! §6.2.1.1). After each turn the example says how its handshake went.
//!
//! What cocuyo does not read, the caller hands in (§21):
//!
//! - the wall clock, for the certificate's dates;
//! - 32 octets from a CSPRNG, for the handshake's keys;
//! - what it states of its CPU.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const chapulin = @import("chapulin");
const answer_text = @import("answer_text.zig");
const server_text = @import("server_text.zig");
const root_text = @import("root_text.zig");

const Resolver = io.Resolver(.{
    .lookups = at_once_max + 1,
    .tcp_connections = cocuyo.constants.servers_max,
    .tls = chapulin.Session,
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Resolver = undefined;
/// The cache's memory, which is the caller's (docs/design.md §19 step 13): the size the README
/// recommends, 2.9 MiB. The engine builds its cache over it at `init`, and `null` in its place
/// would be an engine with no cache.
var cache_memory: cocuyo.cache.Storage(io.constants.cache_slots_default) = undefined;

/// The roots one run may trust: chapulin's bound on its anchors, as colibri's configuration holds
/// them.
const anchors_max = chapulin.Session.anchors_max;
/// What the example states of the CPU: nothing, as a consumer does that cannot state its thread's
/// timing mode (docs/design.md §16 decision 48). Each hello then offers
/// TLS_CHACHA20_POLY1305_SHA256 alone. The probe colibri names is stdx's, which cocuyo does not
/// depend on, and the example sets no timing mode (§17 question 58).
const cpu_not_stated: chapulin.Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known }, .timing = .not_stated };
/// The largest root certificate the example reads.
const certificate_bytes_max = 8192;
/// How long a lookup is given, in ticks of `tick_ns`, before the example gives up on it.
const tick_ns = 100_000_000;
const ticks_max = 200;
/// How long the example waits between two names for the ticket and the idle close: past the
/// engine's idle wait of ten seconds (`tcp_idle_ns_default`).
const close_ticks_max = 200;
const events_max = 16;
/// The turns one run resolves.
const names_max = 4;
/// The names one turn resolves at once, each query on the one connection.
const at_once_max = 4;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 4) {
        std.debug.print("usage: dot-rotor <name>[,<name>...] <server address> <authentication name | pin-sha256:<pin>,...> <root certificate>...\n", .{});
        std.process.exit(2);
    }
    const at = try server_text.place_of(arguments[2]);
    var pins: [cocuyo.constants.spki_pins_max]cocuyo.Pin = undefined;
    var tls = try known_by(arguments[3], &pins);
    if (at.port) |port| tls.port = port;
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = at.address }, .tls = tls }};
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
    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    const clock: Clock = .init(init.io);
    const unix_seconds: u64 = @intCast(@divFloor(std.Io.Timestamp.now(init.io, .real).nanoseconds, std.time.ns_per_s));

    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();
    var events: [events_max]rotor.Event = undefined;
    try engine.init(&loop, &config, cache_memory.slices(), std.mem.readInt(u64, &engine_seed, .little), clock.read());
    // The engine has no context of its own, and a lookup started before this call would stop the
    // program at an assertion (docs/design.md §16 decision 39).
    engine.use_tls(.init(anchors[0..roots.len], cpu_not_stated, seed, unix_seconds, clock.read()));
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
        if (engine.tls_tickets[0] != null and all_closed()) return;
        try tick(loop, events, clock);
    }
    if (engine.tls_tickets[0] == null) std.debug.print("in {d} ticks no ticket was kept\n", .{close_ticks_max});
    if (!all_closed()) std.debug.print("in {d} ticks the connection did not close\n", .{close_ticks_max});
}

fn tick(loop: *rotor.Loop, events: []rotor.Event, clock: Clock) !void {
    const count = try loop.tick(events, tick_ns);
    const now = clock.read();
    for (events[0..count]) |event| _ = engine.apply(event, now);
    engine.drive(now);
}

fn all_closed() bool {
    for (engine.connections) |connection| {
        if (connection.state != .closed) return false;
    }
    return true;
}

/// How the connection that is up handshook: resumed with its ticket, as chapulin's session says;
/// in full within the same connection, the ticket it offered declined; or in full with no ticket,
/// which is also how the engine opens a connection again after a resumed handshake failed. With
/// none up, the answer came from the cache or the connection has closed since.
fn handshake() []const u8 {
    for (engine.connections) |connection| {
        if (connection.state != .up) continue;
        if (connection.tls.session.resumed()) return "resumed";
        if (connection.tls.ticket != null) return "in full, its ticket declined";
        return "in full";
    }
    return "not seen: no connection is up";
}

fn report(name: []const u8, result: Resolver.Result) !void {
    switch (result.outcome) {
        .answer => |answer| try answer_text.report(name, &answer),
        .failure => |failure| {
            answer_text.report_failure(name, &failure);
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
