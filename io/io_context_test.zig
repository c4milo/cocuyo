//! The engine's contexts on the twin (docs/design.md §24, the context a session starts from; §16
//! decision 39). For each encrypted transport an engine has no context until its `use_` call, and
//! the context of another transport counts for nothing. A configuration of plain DNS needs none,
//! `reinit` keeps each context, a session started after it takes the kept one, and `init` leaves
//! none.
//!
//! `start` asserts what `has_context` says, and a test that tripped the assertion would stop the
//! whole run, so these tests ask the predicate. The engine speaks all three of the twin's types, so
//! one engine is asked about each.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");
const io = @import("io.zig");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const question = sim_test.question;

/// An engine that speaks each of the twin's encrypted transports, with a connection slot for each
/// server (docs/design.md §21, TLS rule 6).
const Resolver = io.Resolver(.{
    .lookups = fixtures.small_lookups,
    .group_buffers = fixtures.group_buffers,
    .tcp_connections = fixtures.servers,
    .tls = rotor.tls.Session,
    .quic = rotor.quic.Connection,
    .doh = rotor.channel.Channel,
});
const Rig = sim_test.RigOf(Resolver);

/// The twin's contexts, each a struct of no fields: a test's, named one transport at a time, where
/// the other rigs name theirs with `use_test_contexts`.
const test_tls: Resolver.Tls.Context = .{};
const test_quic: Resolver.Quic.Context = .{};
const test_doh: Resolver.Doh.Context = .{};

/// How a configuration's servers are spoken to.
const Spoken = enum { plain, dot, doq, doh };

/// A DoH server's template, on HTTPS's port (RFC 9110 §4.2.2).
const template = "https://dns.example/dns-query{?dns}";

/// The twin's two scripted servers, spoken to as `spoken` says.
fn servers_over(spoken: Spoken) ![fixtures.servers]cocuyo.Server {
    const name = try cocuyo.Name.parse("dns.example.");
    var servers: [fixtures.servers]cocuyo.Server = undefined;
    for (&servers, 0..) |*server, index| {
        server.* = .{ .endpoint = sim_test.endpoint_of(rotor.Network.server_address(@intCast(index))) };
        switch (spoken) {
            .plain => {},
            .dot => server.tls = .{ .name = name },
            .doq => server.quic = .{ .name = name },
            .doh => server.https = .{ .template = template },
        }
    }
    return servers;
}

/// A configuration of `servers`, under a timeout long enough for any of the twin's handshakes.
fn config_of(servers: []const cocuyo.Server) cocuyo.Config {
    return .{ .servers = servers, .timeout_ns = fixtures.stream_timeout_ns, .timeout_ns_max = fixtures.stream_timeout_ns, .failover_retry_chance = 0 };
}

/// One lookup started, answered by the first server, and its result taken. A started lookup has
/// passed `start`'s assertion, and its session took its context from the engine.
fn expect_answered(rig: *Rig, name: []const u8) !void {
    const handle = try rig.engine.start(&question(name), rig.loop.now());
    if (rig.engine.config.uses_https()) {
        // The twin's channel says what a test queues: the exchange's end, read at the next drive.
        rig.engine.doh.slots[0].channel.say(.{ .finished = .{ .index = handle.index, .answer = true } }, rig.loop.now());
        rig.engine.drive(rig.loop.now());
        _ = try rig.step(fixtures.channel_read_ns);
    }
    const result = try rig.until_result();
    try testing.expect(result.outcome == .answer);
    _ = rig.engine.take(rig.loop.now());
}

test "an engine over DoT has no context until use_tls names one, whatever the other transports have" {
    var servers = try servers_over(.dot);
    const config = config_of(&servers);
    var rig: Rig = .{};
    try rig.init_on(111, .{ .{}, .{} }, &config);
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_quic(test_quic);
    rig.engine.use_doh(test_doh);
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_tls(test_tls);
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "example.com.");
    try rig.deinit();
}

test "an engine over DoQ has no context until use_quic names one, whatever the other transports have" {
    var servers = try servers_over(.doq);
    const config = config_of(&servers);
    var rig: Rig = .{};
    try rig.init_on(112, .{ .{}, .{} }, &config);
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_tls(test_tls);
    rig.engine.use_doh(test_doh);
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_quic(test_quic);
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "example.com.");
    try rig.deinit();
}

test "an engine over DoH has no context until use_doh names one, whatever the other transports have" {
    var servers = try servers_over(.doh);
    const config = config_of(&servers);
    var rig: Rig = .{};
    try rig.init_on(113, .{ .{}, .{} }, &config);
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_tls(test_tls);
    rig.engine.use_quic(test_quic);
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_doh(test_doh);
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "example.com.");
    try rig.deinit();
}

test "a configuration of plain DNS needs no context, on an engine that speaks every transport" {
    var servers = try servers_over(.plain);
    const config = config_of(&servers);
    var rig: Rig = .{};
    try rig.init_on(114, .{ .{}, .{} }, &config);
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "example.com.");
    try rig.deinit();
}

test "reinit keeps the contexts: one set before it still counts, and one never set is still missing" {
    var dot = try servers_over(.dot);
    var doq = try servers_over(.doq);
    var doh = try servers_over(.doh);
    const over_dot = config_of(&dot);
    const over_doq = config_of(&doq);
    const over_doh = config_of(&doh);
    var rig: Rig = .{};
    const memory = rig.cache_memory.slices();
    try rig.init_on(115, .{ .{}, .{} }, &over_dot);
    rig.engine.use_tls(test_tls);
    try expect_answered(&rig, "one.example.");
    // A new configuration sets no context: DoQ's was never named.
    try rig.engine.reinit(&over_doq, memory, 116, rig.loop.now());
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_quic(test_quic);
    try expect_answered(&rig, "two.example.");
    // DoT's outlived the reinit that left its transport, and DoQ's the one that came back.
    try rig.engine.reinit(&over_dot, memory, 117, rig.loop.now());
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "three.example.");
    try rig.engine.reinit(&over_doq, memory, 118, rig.loop.now());
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "four.example.");
    try rig.engine.reinit(&over_doh, memory, 119, rig.loop.now());
    try testing.expect(!rig.engine.has_context());
    rig.engine.use_doh(test_doh);
    try expect_answered(&rig, "five.example.");
    // DoH's too: a channel opened after two more starts from the context named before them.
    try rig.engine.reinit(&over_dot, memory, 120, rig.loop.now());
    try rig.engine.reinit(&over_doh, memory, 121, rig.loop.now());
    try testing.expect(rig.engine.has_context());
    try expect_answered(&rig, "six.example.");
    try rig.deinit();
}

test "init leaves an engine with no context, whatever its memory held from the engine before" {
    for ([_]Spoken{ .dot, .doq, .doh }, 0..) |spoken, case| {
        var servers = try servers_over(spoken);
        const config = config_of(&servers);
        var rig: Rig = .{};
        try rig.init_on(122 + case, .{ .{}, .{} }, &config);
        rig.engine.use_tls(test_tls);
        rig.engine.use_quic(test_quic);
        rig.engine.use_doh(test_doh);
        try testing.expect(rig.engine.has_context());
        try rig.deinit();
        // The same memory, started again: the contexts are named again, or there are none.
        try rig.init_on(122 + case, .{ .{}, .{} }, &config);
        try testing.expect(!rig.engine.has_context());
        try rig.deinit();
    }
}
