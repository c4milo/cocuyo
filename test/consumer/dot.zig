//! What a consumer that speaks DoT writes (docs/design.md §21, §16 decision 38 as amended for §17
//! question 64). Its resolver of `cocuyo_rotor` names the session over chapulin, `Session` of the
//! module `chapulin`, and runs on a loop of the consumer's own. Its build binds its rotor into
//! `cocuyo_rotor`, which is the session's `io`, and colibri's `tls` and `tls_provider` into
//! `chapulin`.
//!
//! `zig build consumer-check` builds this and does not run it. It shows that a consumer can name
//! the session that the package registers, and that the image links. The session's own tests and
//! the live check of DoT show the rest.
const std = @import("std");
const rotor = @import("rotor");
const cocuyo = @import("cocuyo");
const dns = @import("cocuyo_rotor");
const chapulin = @import("chapulin");

/// The lookups the resolver holds at once: one, small on purpose, as the table is.
const lookups = 1;
/// The connections to the server: one, as `lookups` is small.
const tcp_connections = 1;
const Resolver = dns.Resolver(.{ .lookups = lookups, .tcp_connections = tcp_connections, .tls = chapulin.Session });

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
const events_max = 16;
const now_ns = 1;
/// The wall clock at `now_ns`, which a program for a network reads from its clock.
const unix_seconds = 1;
/// What the program states of its CPU: nothing, which each program can state truthfully
/// (docs/design.md §16 decision 48).
const cpu: chapulin.Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known }, .timing = .not_stated };

var loop_memory: [rotor.Loop.memory_bytes(loop_options)]u8 align(rotor.memory_alignment) = undefined;
var resolver: Resolver = undefined;

pub fn main(init: std.process.Init) !void {
    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, loop_options);
    defer loop.deinit();

    // A server known by its name. The program trusts no root and names no pin. It is built, and
    // never run against a network.
    const servers = [_]cocuyo.Server{.{
        .endpoint = .{ .address = cocuyo.Address.from_v4(.{ 127, 0, 0, 1 }) },
        .tls = .{ .name = try cocuyo.Name.from_text("dns.example.") },
    }};
    const config: cocuyo.Config = .{ .servers = &servers, .search = &.{} };
    // Every seed comes from the CSPRNG, each drawn for one use alone.
    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    var session_seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    try init.io.randomSecure(&session_seed);

    try resolver.init(&loop, &config, null, std.mem.readInt(u64, &engine_seed, .little), now_ns);
    defer resolver.deinit();
    resolver.use_tls(.init(&.{}, cpu, session_seed, unix_seconds, now_ns));
    _ = try resolver.start(try cocuyo.Question.from_text("example.com.", .a), now_ns);

    var events: [events_max]rotor.Event = undefined;
    const count = try loop.tick(&events, 0);
    for (events[0..count]) |event| _ = resolver.apply(event, now_ns);
    resolver.drive(now_ns);
    if (resolver.take(now_ns)) |result| std.debug.print("{any}\n", .{result.handle});
}
