//! One lookup over DNS over TLS: the engine of docs/design.md §19 step 13 on rotor's loop, with
//! chapulin's session behind the seam of §21 (`io/io_chapulin.zig`), strict as RFC 8310 §5 asks.
//!
//!     zig build example-dot-rotor -Dchapulin=<checkout> -- \
//!         <name> <server address> <authentication name> <root certificate>...
//!
//! for instance `dns.google 8.8.8.8 dns.google gts-root-r1.der`. Each root is a DER certificate
//! the server's chain is expected to end at; its subject Name and its SubjectPublicKeyInfo are the
//! trust anchor chapulin checks the chain against, and the name is what the leaf must carry.
//!
//! What cocuyo does not read, the caller hands in (§21): the wall clock for the certificate's
//! dates, and 32 octets from a CSPRNG for the handshake's keys.
const std = @import("std");
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io");
const chapulin = @import("chapulin");

const Engine = io.Engine(.{
    .lookups = 2,
    .cache_slots = 2,
    .tcp_connections = cocuyo.constants.servers_max,
    .tls = chapulin.Session,
});

const loop_options: rotor.Loop.Options = .{ .operations = Engine.loop_operations };
var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var engine: Engine = undefined;

/// The roots one run may trust: chapulin's bound on its anchors.
const anchors_max = chapulin.c.CH_WEBPKI_ANCHOR_MAX;
/// The largest root certificate the example reads.
const certificate_bytes_max = 8192;
/// How long a lookup is given, in ticks of `tick_ns`, before the example gives up on it.
const tick_ns = 100_000_000;
const ticks_max = 200;
const events_max = 16;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len < 5) {
        std.debug.print("usage: dot-rotor <name> <server address> <authentication name> <root certificate>...\n", .{});
        std.process.exit(2);
    }
    const address = cocuyo.Address.from_text(arguments[2]) orelse return error.BadAddress;
    const tls: cocuyo.Tls = .{ .name = try cocuyo.Name.from_text(arguments[3]) };
    const servers = [_]cocuyo.Server{.{ .endpoint = .{ .address = address }, .tls = tls }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };

    var anchors: [anchors_max]chapulin.c.ch_trust_anchor = undefined;
    const roots = arguments[4..];
    if (roots.len > anchors_max) return error.TooManyRoots;
    for (roots, 0..) |path, index| {
        const der = try std.Io.Dir.cwd().readFileAlloc(init.io, path, arena, .limited(certificate_bytes_max));
        anchors[index] = try anchor_of(der);
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
    engine.use_tls(.init(anchors[0..roots.len], seed, unix_seconds, clock.read()));
    defer {
        engine.deinit();
        loop.drain(&events) catch {};
        engine.close();
    }
    _ = try engine.start(try cocuyo.Question.from_text(arguments[1], .a), clock.read());
    var ticks: usize = 0;
    while (ticks < ticks_max) : (ticks += 1) {
        if (engine.take(clock.read())) |result| return report(arguments[1], result);
        const count = try loop.tick(&events, tick_ns);
        const now = clock.read();
        for (events[0..count]) |event| _ = engine.apply(event, now);
    }
    std.debug.print("{s}: no answer in {d} ticks\n", .{ arguments[1], ticks_max });
    std.process.exit(1);
}

fn report(name: []const u8, result: Engine.Result) void {
    switch (result.outcome) {
        .answer => |answer| {
            for (answer.addresses) |address| {
                const octets = address.slice();
                std.debug.print("{s} A {d}.{d}.{d}.{d} (ttl {d})\n", .{
                    name, octets[0], octets[1], octets[2], octets[3], answer.ttl_seconds,
                });
            }
        },
        .failure => |failure| {
            std.debug.print("{s}: {t}\n", .{ name, failure.err });
            std.process.exit(1);
        },
    }
}

/// A root certificate's subject Name and SubjectPublicKeyInfo, each a whole DER TLV, which is
/// what chapulin's anchor carries (its webpki_cfg.h). The walk reads RFC 5280 §4.1's fields in
/// order: the version, the serial, the signature, the issuer, the validity, the subject, the key.
fn anchor_of(der: []const u8) !chapulin.c.ch_trust_anchor {
    const certificate = try tlv(der);
    var fields = (try tlv(certificate.contents)).contents;
    var field = try tlv(fields);
    // The version is the one field with a context tag, [0], and it is optional.
    if (field.tag == 0xa0) {
        fields = fields[field.whole.len..];
        field = try tlv(fields);
    }
    // The serial, the signature, the issuer and the validity come before the subject.
    for (0..4) |_| {
        fields = fields[field.whole.len..];
        field = try tlv(fields);
    }
    const subject = field.whole;
    fields = fields[field.whole.len..];
    const key = (try tlv(fields)).whole;
    return .{ .name = subject.ptr, .name_len = subject.len, .spki = key.ptr, .spki_len = key.len };
}

const Tlv = struct { tag: u8, whole: []const u8, contents: []const u8 };

/// One DER TLV at the start of `bytes`, with a length of one, two or three octets (X.690 §8.1.3).
fn tlv(bytes: []const u8) !Tlv {
    if (bytes.len < 2) return error.BadCertificate;
    const first = bytes[1];
    var header: usize = 2;
    var length: usize = first;
    if (first & 0x80 != 0) {
        const octets = first & 0x7f;
        if (octets == 0 or octets > 3 or bytes.len < 2 + octets) return error.BadCertificate;
        length = 0;
        for (bytes[2..][0..octets]) |octet| length = (length << 8) | octet;
        header += octets;
    }
    if (bytes.len < header + length) return error.BadCertificate;
    return .{ .tag = bytes[0], .whole = bytes[0 .. header + length], .contents = bytes[header..][0..length] };
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
