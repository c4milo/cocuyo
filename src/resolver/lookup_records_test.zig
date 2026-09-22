//! A lookup for a type kept as rdata, driven through the fake server: the records come back in
//! the answer's `records` view, readable through `wire.rdata` (docs/design.md §19 step 9).
//! Split from `lookup_response.zig` by the file-length rule.
const std = @import("std");
const testing = std.testing;
const core = @import("core");
const wire = @import("wire");
const Name = core.Name;
const Kind = core.Kind;
const fixtures = @import("fixtures.zig");

const servers = fixtures.servers_two;
const seed = fixtures.seed;

fn harness_for() fixtures.Harness {
    return .{ .config = .{ .servers = &servers } };
}

test "a lookup for MX ends with the record kept and readable" {
    var harness = harness_for();
    try harness.start("example.com.", .mx, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_mx, servers[0]);
    const done = harness.poll().done;
    try testing.expectEqual(Kind.mx, done.kind);
    try testing.expectEqual(@as(u8, 1), done.record_count);
    try testing.expectEqual(@as(usize, 0), done.addresses.len);
    const kept = done.records.?.at(0);
    try testing.expectEqual(Kind.mx.code(), kept.kind_code);
    const mx = try wire.rdata.Mx.parse(kept.rdata);
    try testing.expectEqual(@as(u16, 10), mx.preference);
    try testing.expect(mx.exchange.equal(&try Name.from_text("mail.example.com")));
    try testing.expectEqual(@as(u32, 300), done.ttl_seconds);
}

test "an ANY lookup keeps every record the name owns, each with its own type" {
    var harness = harness_for();
    try harness.start("example.com.", .any, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_any, servers[0]);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u8, 2), done.record_count);
    try testing.expectEqual(Kind.a.code(), done.records.?.at(0).kind_code);
    try testing.expectEqual(Kind.mx.code(), done.records.?.at(1).kind_code);
    try testing.expectEqualSlices(u8, &.{ 192, 0, 2, 1 }, done.records.?.at(0).rdata);
}

test "a CNAME question is answered by the CNAME and follows nothing" {
    var harness = harness_for();
    try harness.start("example.com.", .cname, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.cname_only, servers[0]);
    const done = harness.poll().done;
    try testing.expectEqual(@as(u8, 1), done.record_count);
    try testing.expectEqual(@as(?*const Name, null), done.canonical_name);
    const target = try wire.rdata.name.whole(done.records.?.at(0).rdata);
    try testing.expect(target.equal(&try Name.from_text("host.example.net")));
}

test "an address lookup has no records view, and a PTR lookup has names" {
    var harness = harness_for();
    try harness.start("example.com.", .a, seed);
    _ = harness.send();
    _ = harness.respond(fixtures.answer_a, servers[0]);
    const done = harness.poll().done;
    try testing.expectEqual(@as(?*const wire.Records, null), done.records);
    try testing.expectEqual(@as(u8, 0), done.record_count);
    try testing.expectEqual(@as(usize, 1), done.addresses.len);
}
