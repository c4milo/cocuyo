//! The engine over DoH on the twin (docs/design.md §24, DoH over HTTP/3): a connection on `h3` to
//! the port and the name its template gives, an answer with its `Age`, and the responses that fail
//! their request. The twin's scripted servers answer a request on `h3` as a response, whose
//! status, `Age` and media type their scripts give; what only colibri's HTTP/3 can show is
//! colibri's, over the twin as well.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const rotor = @import("rotor");

const fixtures = @import("fixtures.zig");
const sim_test = @import("io_sim_test.zig");
const request_test = @import("io_request_test.zig");
const question = sim_test.question;
const Rig = request_test.Rig;
const peer_of = request_test.peer_of;

/// The twin's scripted servers take QUIC on 853, so the template names it.
const template = "https://dns.example:853/dns-query{?dns}";

/// A rig whose servers speak DoH as `scripts` say, each known by `templates`.
fn start(rig: *Rig, seed: u64, scripts: [fixtures.servers]rotor.server.Script, templates: [fixtures.servers][]const u8) !void {
    for (&rig.servers, templates) |*server, text| server.https = .{ .template = text };
    try rig.init(seed, scripts, .{ .servers = &.{}, .timeout_ns = fixtures.stream_timeout_ns, .failover_retry_chance = 0 });
}

test "a lookup over DoH handshakes on h3 to its template's port, and is answered" {
    var rig: Rig = .{};
    try start(&rig, 81, .{ .{}, .{} }, .{ template, template });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    const connection = &rig.engine.quic_connections[0];
    try testing.expect(connection.state == .up);
    try testing.expectEqual(@as(u16, 853), connection.port);
    const peer = peer_of(&rig, 0).?;
    try testing.expectEqualStrings("h3", peer.offered[0..peer.offered_len]);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a response's Age lowers its answer's TTLs" {
    // "if an RRset is received with a DNS TTL of 600, but the Age header field indicates that the
    // response has been cached for 250 seconds, the remaining lifetime of the RRset is 350
    // seconds" (RFC 8484 §5.1).
    var rig: Rig = .{};
    const aged: rotor.server.Script = .{ .ttl_seconds = 600, .quic = .{ .http = .{ .age_seconds = 250 } } };
    try start(&rig, 82, .{ aged, .{} }, .{ template, template });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(u32, 350), result.outcome.answer.ttl_seconds);
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

/// A lookup whose first server answers as `script` says: it fails the request, counts as that
/// server's failure, and the second server answers (RFC 8484 §4.2.1, decision 25).
fn expect_failed_over(seed: u64, script: rotor.server.Script, templates: [fixtures.servers][]const u8) !void {
    var rig: Rig = .{};
    try start(&rig, seed, .{ script, .{} }, templates);
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 1), rig.engine.resolver.servers.failures(0));
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(1));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a response that is not 2xx fails its request, and the next server answers" {
    // "HTTP responses with non-successful HTTP status codes do not contain replies to the original
    // DNS question" (RFC 8484 §4.2.1).
    try expect_failed_over(83, .{ .quic = .{ .http = .{ .status = 404 } } }, .{ template, template });
    try expect_failed_over(84, .{ .quic = .{ .http = .{ .status = 199 } } }, .{ template, template });
    try expect_failed_over(85, .{ .quic = .{ .http = .{ .status = 300 } } }, .{ template, template });
}

test "a 2xx response whose content is not a DNS message fails its request" {
    try expect_failed_over(86, .{ .quic = .{ .http = .{ .dns_message = false } } }, .{ template, template });
}

test "a DoH server that negotiates another protocol than h3 is refused" {
    try expect_failed_over(87, .{ .quic = .{ .other_protocol = true } }, .{ template, template });
}

test "a template the engine cannot read fails its server before a socket opens" {
    try expect_failed_over(88, .{}, .{ "http://dns.example:853/dns-query{?dns}", template });
}

test "a 2xx other than 200 carries an answer" {
    var rig: Rig = .{};
    try start(&rig, 89, .{ .{ .quic = .{ .http = .{ .status = 299 } } }, .{} }, .{ template, template });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    const result = try rig.until_result();
    try testing.expectEqual(@as(usize, 1), result.outcome.answer.addresses.len);
    try testing.expectEqual(@as(u8, 0), rig.engine.resolver.servers.failures(0));
    _ = rig.engine.take(rig.loop.now());
    try rig.deinit();
}

test "a template that names no port goes to 443" {
    var rig: Rig = .{};
    try start(&rig, 90, .{ .{}, .{} }, .{ "https://dns.example/dns-query{?dns}", template });
    _ = try rig.engine.start(question("example.com."), rig.loop.now());
    try testing.expectEqual(@as(u16, 443), rig.engine.quic_connections[0].port);
    rig.engine.cancel_all(rig.loop.now());
    _ = try rig.until_result();
    try rig.deinit();
}
