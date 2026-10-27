//! YXDOMAIN driven through the fake server: the lookup ends at once with `NameTooLong`, with no
//! next server and no next candidate, and the `getaddrinfo` walk keeps its rules
//! (docs/design.md §5, §16 decision 57, RFC 6672 §2.2). Split from `lookup_response.zig` by the
//! file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Endpoint = core.Endpoint;
const lookup_module = @import("lookup.zig");
const Verdict = lookup_module.Verdict;
const Cause = lookup_module.Cause;
const fixtures = @import("fixtures.zig");
const Rig = @import("address_lookup_test.zig").Rig;
const Handle = @import("table.zig").Handle;

const servers = fixtures.servers_two;
const seed = fixtures.seed;

/// YXDOMAIN, "Name Exists when it should not" (RFC 6895 §2.3), written as its number so that the
/// tests read the code the wire carries.
const rcode_yxdomain: u16 = 6;

/// Writes YXDOMAIN into the header of `message`, a NOERROR reply with no records.
fn with_yxdomain(message: []u8) ![]u8 {
    var header = try wire.header.parse(message);
    header.flags |= rcode_yxdomain;
    wire.header.write(&header, message);
    return message;
}

/// Hands the lookup a YXDOMAIN reply from `from`.
fn respond(harness: *fixtures.Harness, from: Endpoint) !Verdict {
    const built = harness.build(fixtures.no_data);
    const message = try with_yxdomain(harness.reply_buffer[0..built.len]);
    harness.now_ns += 1;
    return harness.lookup.on_response(message, from, harness.now_ns);
}

test "YXDOMAIN ends the lookup at once with NameTooLong, and asks no other server" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, try respond(&harness, servers[0].endpoint));
    const failure = harness.poll().failed;
    try testing.expectEqual(core.Error.NameTooLong, failure.err);
    try testing.expectEqual(@as(?Cause, null), failure.cause);
    // RFC 2308 §5 gives a TTL to NXDOMAIN and NODATA alone: nothing here may be kept.
    try testing.expectEqual(@as(u32, 0), failure.negative_ttl_seconds);
    try testing.expectEqual(@as(u8, 0), harness.lookup.server_index);
}

test "YXDOMAIN ends the search walk, and the next candidate is not asked" {
    const search = [_]Name{try Name.from_text("one.net")};
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers, .search = &search, .ndots = 1 } };
    try harness.start("example.com", .a, seed);
    _ = harness.send();
    try testing.expect(harness.lookup.current.equal(&try Name.from_text("example.com")));
    try testing.expectEqual(Verdict.accepted, try respond(&harness, servers[0].endpoint));
    try testing.expectEqual(core.Error.NameTooLong, harness.poll().failed.err);
    try testing.expectEqual(@as(u8, 0), harness.lookup.candidate_index);
}

test "YXDOMAIN counts its server up, and keeps the cause an earlier server gave" {
    var harness: fixtures.Harness = .{ .config = .{ .servers = &servers } };
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    try testing.expectEqual(Verdict.accepted, harness.respond(fixtures.server_failure, servers[0].endpoint));
    _ = harness.send();
    const second = harness.lookup.server();
    harness.servers.record_failure(harness.lookup.server_slot(), harness.now_ns);
    try testing.expectEqual(Verdict.accepted, try respond(&harness, second));
    try testing.expectEqual(@as(u8, 0), harness.servers.failures(harness.lookup.server_slot()));
    const failure = harness.poll().failed;
    try testing.expectEqual(core.Error.NameTooLong, failure.err);
    try testing.expectEqual(@as(?Cause, .{ .server_index = 0, .what = .{ .rcode = .server_failure } }), failure.cause);
}

test "over TCP, and with check_response off, YXDOMAIN ends the lookup the same way" {
    var stream: fixtures.Harness = .{ .config = .{ .servers = &servers, .use_tcp = true } };
    try stream.start("example.com.", .a, seed);
    const endpoint = stream.poll().connect_tcp;
    stream.lookup.on_tcp_connected(stream.now_ns);
    _ = stream.send_over_tcp();
    try testing.expectEqual(Verdict.accepted, try respond(&stream, endpoint));
    try testing.expectEqual(core.Error.NameTooLong, stream.poll().failed.err);

    var unchecked: fixtures.Harness = .{ .config = .{ .servers = &servers, .check_response = false } };
    try unchecked.start("example.com.", .a, seed);
    _ = unchecked.send();
    try testing.expectEqual(Verdict.accepted, try respond(&unchecked, servers[0].endpoint));
    try testing.expectEqual(core.Error.NameTooLong, unchecked.poll().failed.err);
}

/// Hands one of the walk's lookups a YXDOMAIN reply.
fn reply_yxdomain(rig: *Rig, handle: ?Handle) !void {
    const lookup = rig.table.resolver.lookup_of(handle orelse return error.NotInFlight);
    const built = rig.table.build(lookup, fixtures.no_data);
    const message = try with_yxdomain(rig.table.reply[0..built.len]);
    rig.table.now_ns += 1;
    try testing.expectEqual(Verdict.accepted, rig.table.resolver.on_datagram(message, lookup.server(), rig.table.now_ns));
}

test "YXDOMAIN on one family leaves the other, whose answer stands, and on both ends the walk" {
    var rig: Rig = .{ .table = .{ .config = .{ .servers = &fixtures.servers_one, .search = &.{} } } };
    try rig.open();
    try rig.start(null, "host.example.", null, .{});
    try rig.drive();
    try reply_yxdomain(&rig, rig.lookup.a.handle);
    try rig.drive();
    // Rule 4 cancels the other family for `NameNotFound` alone (§19 step 14).
    try rig.reply(rig.lookup.aaaa.handle, fixtures.answer_aaaa);
    try rig.drive();
    const info = rig.lookup.outcome().?.answered;
    try testing.expectEqual(@as(usize, 1), info.addresses.len);
    try testing.expectEqual(core.Error.NameTooLong, info.partial.?);

    try rig.start(null, "other.example.", null, .{});
    try rig.drive();
    try reply_yxdomain(&rig, rig.lookup.aaaa.handle);
    try reply_yxdomain(&rig, rig.lookup.a.handle);
    try rig.drive();
    try testing.expectEqual(core.Error.NameTooLong, rig.lookup.outcome().?.failed.err);
    try testing.expectEqual(@as(usize, 0), rig.table.resolver.in_flight());
}
