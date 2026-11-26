//! The templates `cocuyo_doh` takes at `start` (docs/design.md §24): one whose GET would not fit is
//! refused, and one whose GET at its longest fills the path buffer is answered. Split out of
//! `io_doh_channel_test.zig`, whose pair they run on.
const std = @import("std");
const testing = std.testing;
const cocuyo = @import("cocuyo");
const wire = @import("wire");
const doh_limits = @import("doh").limits;
const identity = @import("io_doh_channel_identity.zig");
const rig = @import("io_doh_channel_test.zig");
const Pair = rig.Pair;

test "a template whose GET would not fit is refused when the channel starts" {
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    pair.* = .{};
    pair.context = identity.test_context(&pair.stream, rig.round_ns);
    const long_path = "/" ++ "p" ** 1400 ++ "{?dns}";
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.parse(identity.server_name) };
    const long = .{ .authority = "dns.example:8443", .host = "dns.example", .port = rig.port, .path = long_path };
    try testing.expectError(error.Failed, pair.doh.start(.{
        .server = 0,
        .endpoint = pair.endpoint,
        .tls = &named,
        .https = long,
        .alternative = null,
        .context = &pair.context,
        .now_ns = pair.now_ns,
    }));
}

test "a template whose GET path at its longest fills the path buffer starts, and its longest GET is answered; one octet more is refused" {
    // At `start` the template is expanded with a `dns` value `dns_variable_bytes_max` long, and a
    // path past `doh_request_bytes_max` is refused (docs/design.md §24). Here the path at its
    // longest is a slash, `?x=`, the filler, `&dns=` and the value: 1536 octets. The authority is
    // the longest, a name of 253 octets and a port, and the query is the longest a `dns` value of
    // 512 octets carries, 384 octets in base64url (RFC 4648 §5).
    const query_part = "?x=";
    const value_part = "&dns=";
    const filler = doh_limits.doh_request_bytes_max - 1 - query_part.len - value_part.len - wire.limits.dns_variable_bytes_max;
    const longest = query_part ++ "p" ** filler ++ "{&dns}";
    const host = ("h" ** 63 ++ ".") ** 3 ++ "h" ** 61;
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    pair.* = .{ .endpoint = rig.endpoint };
    pair.context = identity.test_context(&pair.stream, rig.round_ns);
    try pair.server.init(.{}, identity.unix_seconds, pair.now_ns);
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.parse(identity.server_name) };
    const fits_slot = .{ .authority = host ++ ":8443", .host = host, .port = rig.port, .path = longest };
    try pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = fits_slot, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns });
    var longest_query: [wire.limits.dns_variable_bytes_max / 4 * 3]u8 = @splat(0);
    @memcpy(longest_query[0..rig.query.len], &rig.query);
    try testing.expect(pair.doh.request(0, &longest_query, pair.now_ns));
    const result = (try pair.run(.finished)).finished.result;
    if (result != .answer) return error.TestUnexpectedResult;
    const answer = result.answer;
    try testing.expectEqual(longest_query.len, answer.message.len);
    pair.doh.wipe();
    const over = .{ .authority = "dns.example:8443", .host = "dns.example", .port = rig.port, .path = query_part ++ "p" ** (filler + 1) ++ "{&dns}" };
    try testing.expectError(error.Failed, pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = over, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns }));
}

test "a template whose path starts with a slash and fills the path buffer starts, and its longest GET is answered; one octet more is refused" {
    // The slash is the template's own, so the expansion has the whole buffer: a slash, the
    // filler, `?dns=` and a value of 512 octets make 1536 (docs/design.md §24, §17 question 42).
    const value_part = "?dns=";
    const filler = doh_limits.doh_request_bytes_max - 1 - value_part.len - wire.limits.dns_variable_bytes_max;
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    pair.* = .{ .endpoint = rig.endpoint };
    pair.context = identity.test_context(&pair.stream, rig.round_ns);
    try pair.server.init(.{}, identity.unix_seconds, pair.now_ns);
    const named: cocuyo.Tls = .{ .name = try cocuyo.Name.parse(identity.server_name) };
    const fills = .{ .authority = "dns.example:8443", .host = "dns.example", .port = rig.port, .path = "/" ++ "p" ** filler ++ "{?dns}" };
    try pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = fills, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns });
    // The longest query a `dns` value of 512 octets carries goes out on that path, and colibri's
    // server answers it.
    var longest_query: [wire.limits.dns_variable_bytes_max / 4 * 3]u8 = @splat(0);
    @memcpy(longest_query[0..rig.query.len], &rig.query);
    try testing.expect(pair.doh.request(0, &longest_query, pair.now_ns));
    const result = (try pair.run(.finished)).finished.result;
    if (result != .answer) return error.TestUnexpectedResult;
    const answer = result.answer;
    try testing.expectEqual(longest_query.len, answer.message.len);
    pair.doh.wipe();
    const over = .{ .authority = "dns.example:8443", .host = "dns.example", .port = rig.port, .path = "/" ++ "p" ** (filler + 1) ++ "{?dns}" };
    try testing.expectError(error.Failed, pair.doh.start(.{ .server = 0, .endpoint = pair.endpoint, .tls = &named, .https = over, .alternative = null, .context = &pair.context, .now_ns = pair.now_ns }));
}
