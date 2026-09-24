//! A table over DoH servers (docs/design.md §22): a request handed out with its transaction, its
//! answer taken by handle, and an HTTP failure that moves the lookup on. Split from `table.zig`
//! by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const fixtures = @import("fixtures.zig");
const Verdict = @import("lookup.zig").Verdict;
const Event = @import("table.zig").Event;

const https: core.Https = .{ .template = "https://dns.example/dns-query{?dns}" };
const servers = [_]core.Server{
    .{ .endpoint = fixtures.servers_two[0].endpoint, .https = https },
    .{ .endpoint = fixtures.servers_two[1].endpoint, .https = https },
};

test "a table hands out a DoH request, and takes its answer by handle and transaction" {
    var table: fixtures.Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    const request = table.poll().?.action.send_https;
    table.resolver.on_sent(handle, table.now_ns);
    const lookup = table.resolver.lookup_of(handle);
    const message = table.build(lookup, fixtures.answer_a);
    // The same message as a datagram, from the server, is nobody's answer.
    try testing.expectEqual(Verdict.ignored, table.resolver.on_datagram(message, lookup.server(), table.now_ns));
    try testing.expectEqual(Verdict.ignored, table.resolver.on_https_answer(handle, request.transaction +% 1, message, 0, table.now_ns));
    try testing.expectEqual(Verdict.accepted, table.resolver.on_https_answer(handle, request.transaction, message, 0, table.now_ns));
    try testing.expectEqual(@as(usize, 1), table.poll().?.action.done.addresses.len);
}

test "an HTTP failure in a table offers the lookup's request to the next server" {
    var table: fixtures.Table = .{ .config = .{ .servers = &servers } };
    table.open();
    const handle = try table.start("example.com.");
    const first = table.poll().?.action.send_https;
    table.resolver.on_sent(handle, table.now_ns);
    try testing.expectEqual(@as(?Event, null), table.poll());
    table.resolver.on_https_failed(handle, first.transaction, table.now_ns);
    const second = table.poll().?.action.send_https;
    try testing.expect(second.server_index != first.server_index);
    try testing.expect(second.transaction != first.transaction);
}
