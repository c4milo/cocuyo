//! What a consumer that speaks DoT writes (docs/design.md §21, §16 decision 38 as amended for §17
//! question 64). Its resolver of `cocuyo_rotor` names the session over chapulin, `Session` of the
//! module `chapulin`, and runs on a loop of the consumer's own. Its build binds its rotor into
//! `cocuyo_rotor`, which is the session's `io`, and colibri's one module into `chapulin`. The
//! program makes the sessions' context with its own stdx.
//!
//! `zig build consumer-check` builds this and does not run it. It shows that a consumer can name
//! the session that the package registers, and that the image links. The session's own tests and
//! the live check of DoT show the rest.
const std = @import("std");
const rotor = @import("rotor");
const cocuyo = @import("cocuyo");
const dns = @import("cocuyo_rotor");
const chapulin = @import("chapulin");
const stdx = @import("stdx");

/// The lookups the resolver holds at once: one, small on purpose, as the table is.
const lookups = 1;
/// The connections to the server: one, as `lookups` is small.
const tcp_connections = 1;
const Resolver = dns.Resolver(.{
    .lookups = lookups,
    .tag = dns.constants.tag_default,
    .group_buffers = dns.constants.group_buffers_default,
    .tcp_connections = tcp_connections,
    .tcp_group_buffers = dns.constants.tcp_group_buffers_default,
    .requests = null,
    .tcp_message_bytes = dns.limits.tcp_message_bytes_max,
    .tls = chapulin.Session,
    .quic = dns.quic.None,
    .doh = dns.channel.None,
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
const events_max = 16;
const now_ns = 1;
/// The wall clock at `now_ns`, which a program for a network reads from its clock.
const unix_seconds = 1;
/// The source of the sessions' keys: `io.randomSecure`, which halts the program when it fails, so
/// no session runs on octets the system did not give.
const SecureRandom = struct {
    io: std.Io,

    fn fill(pointer: *anyopaque, octets: []u8) void {
        const self: *SecureRandom = @ptrCast(@alignCast(pointer));
        self.io.randomSecure(octets) catch |err| std.debug.panic("no entropy: {t}", .{err});
    }

    fn random(self: *SecureRandom) std.Random {
        return .{ .ptr = self, .fillFn = fill };
    }
};

var loop_memory: [rotor.Loop.memory_bytes(&loop_options)]u8 align(rotor.memory_alignment) = undefined;
var resolver: Resolver = undefined;

pub fn main(init: std.process.Init) !void {
    var loop: rotor.Loop = undefined;
    try loop.init(&loop_memory, &loop_options);
    defer loop.deinit();

    // A server known by its name. The program trusts no root and names no pin. It is built, and
    // never run against a network.
    const servers = [_]cocuyo.Server{.{
        .endpoint = .{ .address = cocuyo.Address.from_v4(.{ 127, 0, 0, 1 }) },
        .tls = .{ .name = try cocuyo.Name.parse("dns.example.") },
    }};
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
        .use_tcp = false,
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
    // Every seed comes from the CSPRNG, each drawn for one use alone.
    var engine_seed: [@sizeOf(u64)]u8 = undefined;
    try init.io.randomSecure(&engine_seed);
    // The context of every session: no instruction, which each program can state truthfully, and
    // the system's source (docs/design.md §16 decision 48, colibri decision 175).
    var secure: SecureRandom = .{ .io = init.io };
    const crypto = stdx.crypto.init(.none(), secure.random());

    try resolver.init(&loop, &config, null, std.mem.readInt(u64, &engine_seed, .little), now_ns);
    defer resolver.deinit();
    resolver.use_tls(.init(&.{}, crypto, .{ .unix_seconds = unix_seconds, .monotonic_ns = now_ns }));
    _ = try resolver.start(&try cocuyo.Question.parse("example.com.", .a), now_ns);

    var events: [events_max]rotor.Event = undefined;
    const count = try loop.tick(&events, 0);
    for (events[0..count]) |event| _ = resolver.apply(event, now_ns);
    resolver.drive(now_ns);
    if (resolver.take(now_ns)) |result| std.debug.print("{any}\n", .{result.handle});
}
