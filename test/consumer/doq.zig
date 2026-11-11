//! What a consumer that speaks DoQ writes (docs/design.md §24, the session a connection names).
//! Its connection of `cocuyo_quic` names the session over chapulin, `chapulin_quic`, and cocuyo's
//! resolver runs that connection on a loop of the consumer's own. Its build binds colibri's `quic`
//! into `cocuyo_quic`, and colibri's `quic` and `tls` into `chapulin_quic`.
//!
//! `zig build consumer-check` builds this and does not run it. It shows that a consumer can name
//! the session that the package registers, and that the image links. The session's own tests and
//! the live check of DoQ show the rest.
const std = @import("std");
const rotor = @import("rotor");
const cocuyo = @import("cocuyo");
const dns = @import("cocuyo_rotor");
const cocuyo_quic = @import("cocuyo_quic");
const chapulin = @import("chapulin_quic");

/// The lookups one connection carries at once: one, small on purpose, as the table is.
const streams = 1;
const Quic = cocuyo_quic.Connection(.{
    .Session = chapulin.Session,
    .streams = streams,
    .receive_bytes = cocuyo_quic.constants.receive_bytes_default,
});
const Resolver = dns.Resolver(.{
    .lookups = streams + 1,
    .tag = dns.constants.tag_default,
    .group_buffers = dns.constants.group_buffers_default,
    .tcp_connections = 0,
    .tcp_group_buffers = dns.constants.tcp_group_buffers_default,
    .requests = null,
    .tcp_message_bytes = dns.limits.tcp_message_bytes_max,
    .tls = dns.tls.None,
    .quic = Quic,
    .doh = dns.channel.None,
});

const loop_options: rotor.Loop.Options = .{ .operations = Resolver.loop_operations };
const events_max = 16;
const now_ns = 1;
/// The wall clock at `now_ns`, which a program for a network reads from its clock.
const unix_seconds = 1;
/// What the program states of its CPU: nothing, which each program can state truthfully
/// (docs/design.md §16 decision 48).
const cpu: chapulin.Session.Cpu = .{ .probe = .{ .aes_clmul = .not_known, .dit = .not_known, .sha256 = .not_known, .sha512 = .not_known, .sha3 = .not_known, .ssse3 = .not_known, .sse4_1 = .not_known, .avx2 = .not_known, .vaes = .not_known }, .timing = .not_stated };

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
        .quic = .{ .name = try cocuyo.Name.parse("dns.example.") },
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
    var session_seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    try init.io.randomSecure(&session_seed);
    var id_seed: [std.Random.ChaCha.secret_seed_length]u8 = undefined;
    try init.io.randomSecure(&id_seed);

    try resolver.init(&loop, &config, null, std.mem.readInt(u64, &engine_seed, .little), now_ns);
    defer resolver.deinit();
    resolver.use_quic(.{
        .session = .init(&.{}, cpu, session_seed, .{ .unix_seconds = unix_seconds, .monotonic_ns = now_ns }),
        .stream = std.Random.ChaCha.init(id_seed),
    });
    _ = try resolver.start(&try cocuyo.Question.parse("example.com.", .a), now_ns);

    var events: [events_max]rotor.Event = undefined;
    const count = try loop.tick(&events, 0);
    for (events[0..count]) |event| _ = resolver.apply(event, now_ns);
    resolver.drive(now_ns);
    if (resolver.take(now_ns)) |result| std.debug.print("{any}\n", .{result.handle});
}
